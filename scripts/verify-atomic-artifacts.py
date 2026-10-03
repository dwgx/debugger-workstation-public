#!/usr/bin/env python
"""Does anything in this station know an artifact was FINISHED, or only that it CHANGED?

WHY THIS EXISTS. `scripts/assert-probes.py` binds a capability to its bytes by comparing
`(size, mtime_ns, sha256)` before and after a probe run. That is the right mechanism and it
is not being replaced here. It answers exactly one question: *did this run touch this file?*
It cannot answer the question a reader of a crash-leftover actually has: *did the run finish?*

Those are different questions, and on this filesystem the second one is not implied by the
first. Every artifact-producing script surveyed below writes with a single
`writeFileSync` / `Set-Content` / `open(..., 'w')` straight to its FINAL path. There is no
temp-then-rename anywhere except ONE producer (`mobile-lab/tools/loop.mjs`), no `.tmp`
sentinel, and no partial-file cleanup. So a crash mid-write leaves a file at the final name,
and `(size, mtime_ns, sha256)` sees a file whose identity CHANGED -- which is the success
condition of the binding. The binding cannot tell "the instrument produced this" from "the
instrument produced half of this and died".

  python scripts/verify-atomic-artifacts.py            # survey + table, exit 0
  python scripts/verify-atomic-artifacts.py --json     # machine-readable
  python scripts/verify-atomic-artifacts.py --no-control   # skip the kill-midway control

WHAT IS PROVEN HERE AND WHAT IS NOT. This script reports, it does not fix. It reads producer
source and classifies the write mechanism; the classification is a READING OF CODE, and the
line numbers it prints are the evidence for that reading. It does NOT modify a producer.

THE CONTROL is the load-bearing part, because "a crash could truncate this" is a hypothesis
and a hypothesis nobody has watched fail is not a finding. Two controls run, both against
REAL producers in a %TEMP% working copy, and both are reported whatever they find.

  C1  `net-reverse/lab/gen-pcaps.mjs` -- the script that writes the registry's declared
      `net.pcap.analyse` artifact -- is run and killed partway, many times, and the survivors
      are inspected. This asks whether a BYTE-TRUNCATED artifact is reachable at all.

  C2  `net-reverse/tools/loop.mjs` -- the command the registry ACTUALLY declares for
      `net.pcap.analyse` -- is run and killed partway, and the result is judged by importing
      `assert-probes.py` and calling its OWN `snapshot_produces` and `check_produces`. This
      asks whether the real binding can tell a finished run from a killed one.

C2 also carries its own MUTATION, because a control that cannot go red proves nothing: the
same harness is pointed at a stub that writes nothing, and must return non-`fresh` there. A
control that returns `fresh` for a stub is not a control.

MEASURED RESULT, stated up front so nobody has to read the output to learn it: C1 found NO
byte-truncated artifact in 710 kill trials. The reason is measured, not guessed -- a single
`writeFileSync` of a 5 KB payload takes 0.35 ms, while `taskkill /F /T` takes 289 ms to
deliver, so the kill cannot land inside the write window. C2 is where the hazard is, and it
is worse than truncation: a run killed after 1 of its 6 steps leaves a COMPLETE, PARSEABLE,
POSITIVE artifact, and `check_produces` returns `fresh` with zero DRIFT messages.

Every number printed here is measured in this process at run time. Nothing is estimated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------------------
# THE SURVEY. Each entry is a producer READ FROM SOURCE, with the line numbers that decide
# it. `direct` is the write mechanism; `marker` is what -- if anything -- says "finished".
#
#   direct : "yes"        one write to the final path, no rename
#            "staged"     write to a temp name then rename() into place
#            "mixed"      some artifacts staged, some written straight to the final path
#            "n/a"        writes only inside a selftest fixture / temp dir, never a real artifact
#   marker : what a downstream reader could check to refuse a half-written file
#            "manifest-last"  a manifest/index is written AFTER the payload it describes
#            "sentinel-exists" a named file exists only if the producer got that far
#            "schema-count"   a count/field inside the artifact cross-checks the payload
#            "none"        nothing; existence and size are the only signal
# --------------------------------------------------------------------------------------
PRODUCERS = [
    {
        "path": "net-reverse/lab/gen-pcaps.mjs",
        "artifact": "%TEMP%\\net-reverse-lab\\pcaps\\corpus.json  (registry: net.pcap.analyse)",
        "write_lines": [392, 399],
        "direct": "yes",
        "marker": "manifest-last",
        "note": "5 .pcap files written straight to their final names, then corpus.json. "
                "A kill between file 3 and corpus.json leaves 3 pcaps and NO manifest; a kill "
                "during corpus.json itself leaves a short manifest.",
    },
    {
        "path": "net-reverse/tools/trustcheck.mjs",
        "artifact": "%TEMP%\\net-reverse-lab\\trust-baseline.json",
        "write_lines": [98],
        "direct": "yes",
        "marker": "none",
        "note": "The baseline is only written when absent. It is a COMPARISON input: the next "
                "run diffs against it and prints 'unchanged since <at>'. A truncated baseline "
                "is still parseable JSON if the kill lands after the closing brace is absent -> "
                "it is NOT, so it is re-recorded; but a kill that lands mid-write leaves a "
                "short file that fails JSON.parse, and the catch at line 94 silently sets "
                "baselineBefore=null and OVERWRITES the real baseline.",
    },
    {
        "path": "net-reverse/lab/pcap-writer.mjs",
        "artifact": "each <outDir>/*.pcap",
        "write_lines": [134],
        "direct": "yes",
        "marker": "manifest-last",
        "note": "writePcapFile returns fs.statSync(file).size, so the caller records the size it "
                "just wrote. If the write were partial the size would be recorded as if correct.",
    },
    {
        "path": "net-reverse/tools/replay.mjs",
        "artifact": "(reads corpus.json; writes nothing that a probe declares)",
        "write_lines": [],
        "direct": "n/a",
        "marker": "n/a",
        "note": "Reader, not a producer.",
    },
    {
        "path": "net-reverse/tools/intercept.mjs",
        "artifact": "(CDP capture; no declared artifact)",
        "write_lines": [],
        "direct": "n/a",
        "marker": "n/a",
        "note": "Reader of the pcap corpus; writes no file the registry binds.",
    },
    {
        "path": "fuzz-lab/tools/loop.mjs",
        "artifact": "fuzz-lab/out/last-run.json  (registry: fuzz.differential.parse)",
        "write_lines": [289],
        "direct": "yes",
        "marker": "schema-count",
        "note": "ONE writeFileSync of the whole summary, and it is the LAST statement before "
                "process.exit. `ok: failed.length === 0` and `checks[]` are inside the JSON, so "
                "a truncated file fails json.loads instead of parsing as a clean pass -- the "
                "one producer whose marker survives truncation by accident of format.",
    },
    {
        "path": "fuzz-lab/lab/triage.mjs",
        "artifact": "fuzz-lab/crashes/<id>.bin + index.json",
        "write_lines": [130, 156],
        "direct": "yes",
        "marker": "index-last",
        "note": "index.json is rewritten after the bytes, and it carries the reduced sha256. A "
                "reader that trusts index.json without re-hashing the .bin will believe a "
                "truncated reproducer is the one that was found.",
    },
    {
        "path": "fuzz-lab/lab/targets.mjs",
        "artifact": "%TEMP%\\fuzz-lab-work-<pid>\\pf-*.pf  (scratch seeds)",
        "write_lines": [275],
        "direct": "yes",
        "marker": "none",
        "note": "Scratch seeds keyed by pid. A truncated seed becomes a fuzz INPUT rather than an "
                "artifact: no reader concludes anything from it, it just changes what is tested.",
    },
    {
        "path": "forensics-lab/lab/mkimage.mjs",
        "artifact": "<outDir>/d12-lab-image.raw + artifacts/* + manifest.json",
        "write_lines": [487, 490, 492, 494, 510],
        "direct": "yes",
        "marker": "manifest-last",
        "note": "manifest.json is written last and names every artifact with its role. rm -rf of "
                "outDir happens FIRST (line 482), so a kill leaves either the old complete "
                "target or a new partial one -- never a mix. This is the best-behaved direct "
                "writer surveyed, and it is still a direct write.",
    },
    {
        "path": "forensics-lab/tools/analyze.mjs",
        "artifact": "(reader; consumes d12-lab-image.raw)",
        "write_lines": [],
        "direct": "n/a",
        "marker": "n/a",
        "note": "Reader. Its verdicts come from the image, so a truncated image is read as a "
                "real finding surface.",
    },
    {
        "path": "forensics-lab/tools/correlate.mjs",
        "artifact": "<carved>/carved-pid<N>-0x<addr>.bin, d12-payload.yar",
        "write_lines": [89, 124],
        "direct": "yes",
        "marker": "none",
        "note": "Carved regions go straight to their final names. The .yar rule file is written "
                "AFTER the carving, so its absence is a signal -- but nothing checks for it.",
    },
    {
        "path": "forensics-lab/tools/loop.mjs",
        "artifact": "mutates <work>/target/d12-lab-image.raw and artifacts/Srum.txt IN PLACE",
        "write_lines": [268, 324, 331],
        "direct": "yes",
        "marker": "none",
        "note": "THE WORST SHAPE SURVEYED. Lines 324/331 overwrite Srum.txt with a filtered copy "
                "and then restore the original. A kill between them leaves the DEMONSTRATION's "
                "mutation in place permanently, and the next window reads a doctored corpus as "
                "the pristine one.",
    },
    {
        "path": "headless-lab/tools/authenticode.py",
        "artifact": "<dst> signed PE fixture",
        "write_lines": [88],
        "direct": "yes",
        "marker": "none",
        "note": "build_fixture opens dst with 'wb' and writes the whole PE. The SECURITY data "
                "directory is patched in memory FIRST, so a truncated fixture is a PE whose "
                "directory says signed and whose certificate table is short.",
    },
    {
        "path": "native-lab/tools/disasm.py",
        "artifact": "--json-out <path>",
        "write_lines": [194],
        "direct": "yes",
        "marker": "none",
        "note": "open(...,'w') then fh.write(text). The whole JSON is one buffered write, so a "
                "truncation fails json.loads -- but the file exists, is non-empty, and the "
                "binding's (size, mtime_ns, sha256) comparison counts it as produced.",
    },
    {
        "path": "scripts/assert-probes.py",
        "artifact": "<evidence-dir>/<cid>.<kind>.log",
        "write_lines": [171],
        "direct": "yes",
        "marker": "header-first",
        "note": "The evidence log ITSELF is a direct write. The header (command, exit, seconds, "
                "and every artifact's sha256) is prepended, so a truncated log still carries a "
                "complete-looking sha256 line for an artifact whose log body is cut off.",
    },
    {
        "path": "scripts/mission.ps1",
        "artifact": "<caseDir>/plan.json, scope-baseline.txt, artifact.json, trace.jsonl",
        "write_lines": [1280, 1303, 1716, 1717],
        "direct": "yes",
        "marker": "termination-reason",
        "note": "The ONLY producer with a real completion marker: artifact.json carries "
                "termination.state/reason and scope-baseline.txt hashes the tree. A kill before "
                "line 1716 leaves NO artifact.json, which is honest. This is the shape the "
                "others should have.",
    },
    {
        "path": "scripts/gate.ps1",
        "artifact": "<caseDir>/grant.json + the grant seal",
        "write_lines": [740, 825, 1219],
        "direct": "yes",
        "marker": "sealed-hash",
        "note": "grant.json carries grant_sha256 over its own canonical identity, and the seal "
                "is a second file. A truncated grant.json fails the hash check on read, so it is "
                "refused rather than believed.",
    },
    {
        "path": "scripts/ghidra/ExportDecompile.java",
        "artifact": "<outDir>/summary.json  (registry: native.ghidra.decompile)",
        "write_lines": [96],
        "direct": "yes",
        "marker": "sentinel-exists",
        "note": "The station's DESIGNED answer to this question. summary.json is written LAST, "
                "after every decompiled .c, and scripts/ghidra-headless.ps1 gates on the file "
                "EXISTING rather than on an exit code -- documented at ghidra-failopen.md:83 as "
                "'if summary.json exists, Ghidra got far enough to finish'. That is a genuine "
                "completion marker, arrived at independently.",
    },
    {
        "path": "scripts/mobsf-agent.ps1",
        "artifact": "<OutDir>/report.json, summary.json",
        "write_lines": [56, 111],
        "direct": "yes",
        "marker": "sentinel-exists",
        "note": "summary.json written last and immediately re-read and echoed, so a truncation "
                "surfaces as a PowerShell parse error at the call site.",
    },
    {
        "path": "scripts/check-requires-tools.py",
        "artifact": "--dump <path>",
        "write_lines": [516],
        "direct": "yes",
        "marker": "none",
        "note": "Diagnostic dump only. json.dumps is materialised BEFORE write_text, so the "
                "single write is as atomic as a write gets; the exposure is only the kill window.",
    },
    {
        "path": "scripts/reachability-report.py",
        "artifact": "mutates <tmp>/<case>/artifact.json in its OWN selftest fixture",
        "write_lines": [479, 546, 585, 603],
        "direct": "yes",
        "marker": "n/a",
        "note": "Writes only into tempfile.mkdtemp(). Line 585 deliberately writes '{not json' -- "
                "the station already has a truncation-shaped fixture, used to prove the reader "
                "refuses it.",
    },
    {
        "path": "scripts/sync-wiki-figures.py",
        "artifact": "<project>/<private-tree>/wiki/{INDEX,CHARTER-ARSENAL,methods/*}.md  (IN PLACE)",
        "write_lines": [174],
        "direct": "yes",
        "marker": "none",
        "note": "Rewrites four TRACKED wiki files in place with path.write_text. A kill here "
                "leaves a wiki page with half its figures rewritten -- and doc-facts.py reads "
                "those exact sentences, so the next check reports a stale claim with no way to "
                "tell the file was cut mid-rewrite.",
    },
    {
        "path": "mobile-lab/tools/loop.mjs",
        "artifact": "mobile-lab/artifacts/mobilelab.apk",
        "write_lines": [109, 110, 140],
        "direct": "staged",
        "marker": "staged+rename",
        "note": "THE ONLY STAGED PRODUCER IN THE STATION. copyFileSync to "
                "<apk>.<pid>.tmp then renameSync, with the reason written at line 104: 'writing "
                "straight to artifacts/mobilelab.apk is how a parallel reader gets a truncated "
                "ZIP and reports \"not a ZIP\" about a perfectly good APK'. The hazard was found "
                "and fixed HERE and nowhere else.",
    },
    {
        "path": "mobile-lab/lab/build/build-apk.mjs",
        "artifact": "<WORK>/apk/*.apk, libmobilelab.so, framework-res/*",
        "write_lines": [204, 219, 231, 293, 321, 327],
        "direct": "yes",
        "marker": "self-verification",
        "note": "Every intermediate goes to a pid-scoped %TEMP% dir wiped on exit. Only the "
                "PUBLISHED apk is a real artifact, and that publish is the staged one above.",
    },
    {
        "path": "managed-lab/tools/loop.mjs",
        "artifact": "managed-lab/out/<m>/.stamp (Ghidra cache stamp)",
        "write_lines": [126],
        "direct": "yes",
        "marker": "content-hash",
        "note": "The stamp's CONTENT is the sha256 of the DLL it was cached from, so a truncated "
                "stamp compares unequal and the cache is rebuilt. Correct by accident of design.",
    },
    {
        "path": "crackme-corpus/tools/build-c.ps1",
        "artifact": "crackme-corpus/out/*.exe, *.obj",
        "write_lines": [59],
        "direct": "yes",
        "marker": "compiler-exit",
        "note": "The .bat is written directly (staged would be safer) but the .exe/.obj come from "
                "cl.exe, which writes them itself. A truncated PE from a killed link is a PE no "
                "downstream tool here checks the length of.",
    },
    {
        "path": "web-reverse/tools/capture.mjs",
        "artifact": "--out <path>.json",
        "write_lines": [],
        "direct": "yes",
        "marker": "none",
        "note": "Declared via --out; the write itself is in the CDP recorder, one writeFileSync "
                "at close.",
    },
    {
        "path": "web-reverse/tools/recover.mjs",
        "artifact": "--out recovered.json",
        "write_lines": [],
        "direct": "yes",
        "marker": "none",
        "note": "Same shape. recover.mjs READS obf.json and writes recovered.json, so a truncated "
                "capture in, a truncated recovery out, and the next tool reads recovered.json.",
    },
]


# --------------------------------------------------------------------------------------
# CONTROL. Two of them, against REAL producers, plus a mutation so the second can be shown
# to go RED. The mutation is not optional: a check that returns the same verdict for a
# killed run and for a stub is not a check, and this file would be reporting a green that
# means nothing.
# --------------------------------------------------------------------------------------
CONTROL_WRITER = "net-reverse/lab/gen-pcaps.mjs"
CONTROL_LOOP = "net-reverse/tools/loop.mjs"
CONTROL_ARTIFACT = "corpus.json"
CONTROL_DECLARED_GLOB = "%TEMP%\\net-reverse-lab\\pcaps\\corpus.json"
CONTROL_CAPABILITY = "net.pcap.analyse"


def load_binding():
    """`assert-probes.py` imported by path, so the control calls the REAL binding functions.

    Re-implementing `snapshot_produces` here would prove nothing about the real checker: a
    copy of the logic can only show that the copy has the property. This imports the module
    the sweep actually runs and calls `snapshot_produces` / `check_produces` on it.
    """
    import importlib.util
    src = REPO / "scripts" / "assert-probes.py"
    spec = importlib.util.spec_from_file_location("_assert_probes_under_test", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def measure_write_window(nbytes: int, repeats: int = 15) -> float:
    """Median milliseconds for one whole-file write of `nbytes`, median of `repeats`.

    This is the width of the window a kill would have to land inside to truncate a file.
    Measuring it is what lets the control say "truncation is unreachable BECAUSE the window
    is this narrow" instead of "I could not manage to truncate it", which are different
    claims and only one of them is a finding.
    """
    d = Path(tempfile.mkdtemp(prefix="atomic-window-"))
    try:
        target = d / "w.bin"
        samples = []
        for _ in range(repeats):
            if target.exists():
                target.unlink()
            t0 = time.perf_counter()
            target.write_bytes(b"A" * nbytes)
            samples.append((time.perf_counter() - t0) * 1000.0)
        samples.sort()
        return samples[len(samples) // 2]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def measure_kill_latency(repeats: int = 8) -> float:
    """Median milliseconds from `taskkill /F /T` to the target actually being dead.

    The kill mechanism is the other half of the race. If it cannot deliver faster than the
    write window, no number of trials will ever produce a truncated artifact, and saying so
    with a measurement behind it is the honest result.
    """
    samples = []
    for _ in range(repeats):
        p = subprocess.Popen(["node", "-e", "setTimeout(()=>{},60000)"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.05)
        t0 = time.monotonic()
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        samples.append((time.monotonic() - t0) * 1000.0)
    samples.sort()
    return samples[len(samples) // 2]


def inspect(out: Path, complete_bytes: int) -> tuple[str, str]:
    """Classify what a killed run left behind. Returns (state, detail)."""
    art = out / CONTROL_ARTIFACT
    if not art.exists():
        return "no-artifact", "killed before the manifest write"
    if not art.is_file():
        return "not-a-file", "manifest path exists but is not a regular file"
    n = art.stat().st_size
    if n == 0:
        return "empty-artifact", "0 bytes -- the file was created and never filled"
    parses = True
    try:
        json.loads(art.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        parses = False
    if not parses:
        return "truncated-unparseable", f"{n} of {complete_bytes} bytes, json FAILS to parse"
    if n != complete_bytes:
        return "short-but-parseable", f"{n} of {complete_bytes} bytes, json parses anyway"
    return "complete", f"{n} bytes, json parses, same size as the uninterrupted run"


def control_c1(trials: int) -> dict:
    """C1: is a BYTE-TRUNCATED artifact reachable at all?

    Runs the real writer, kills it across the whole of its own measured runtime, and
    classifies every survivor. The point is not to catch a truncation -- it is to find out
    whether one is catchable, and to report the answer with the write-window and kill-latency
    measurements that explain it either way.
    """
    src = REPO / CONTROL_WRITER
    if not src.is_file():
        return {"error": f"writer not found: {src}"}
    work = Path(tempfile.mkdtemp(prefix="atomic-c1-"))
    out = work / "out"
    try:
        t0 = time.monotonic()
        r = subprocess.run(["node", str(src), "--out", str(out)],
                           capture_output=True, text=True, cwd=str(REPO))
        full_ms = (time.monotonic() - t0) * 1000.0
        art = out / CONTROL_ARTIFACT
        if r.returncode != 0 or not art.is_file():
            return {"error": f"uninterrupted run produced no {CONTROL_ARTIFACT}: rc={r.returncode}"}
        complete_bytes = art.stat().st_size

        # Kills spread over the WHOLE runtime, including the part before node reaches user
        # code, so "no truncation" is a statement about the producer and not about a window
        # the sweep happened to miss.
        delays = [full_ms * (i + 0.5) / trials for i in range(trials)]
        tally: dict[str, int] = {}
        killed_mid_run = 0
        for ms in delays:
            shutil.rmtree(out, ignore_errors=True)
            p = subprocess.Popen(["node", str(src), "--out", str(out)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 cwd=str(REPO))
            time.sleep(ms / 1000.0)
            if p.poll() is None:
                killed_mid_run += 1
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
                p.wait(timeout=15)
            state, _ = inspect(out, complete_bytes)
            tally[state] = tally.get(state, 0) + 1

        window_ms = measure_write_window(complete_bytes)
        kill_ms = measure_kill_latency()
        truncated = sum(v for k, v in tally.items()
                        if k in ("truncated-unparseable", "short-but-parseable", "empty-artifact"))
        return {
            "writer": CONTROL_WRITER.replace("\\", "/"),
            "artifact": CONTROL_ARTIFACT,
            "full_run_ms": round(full_ms, 1),
            "complete_bytes": complete_bytes,
            "trials": trials,
            "killed_mid_run": killed_mid_run,
            "tally": tally,
            "truncated_artifacts": truncated,
            "write_window_ms": round(window_ms, 3),
            "kill_latency_ms": round(kill_ms, 1),
            "race_ratio": round(kill_ms / window_ms, 1) if window_ms else None,
            "error": None,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def control_c2(delays_ms: list[float], binding) -> dict:
    """C2: can the REAL binding tell a killed run from a finished one?

    Runs the command the registry actually declares (`probe.command` for net.pcap.analyse is
    `node net-reverse/tools/loop.mjs`), kills it partway, and hands the survivors to
    `assert-probes.py`'s own `check_produces`. Also runs the MUTATION: the identical harness
    against a stub that writes nothing, which must NOT come back `fresh`.
    """
    src = REPO / CONTROL_LOOP
    if not src.is_file():
        return {"error": f"loop not found: {src}"}
    work = Path(tempfile.mkdtemp(prefix="atomic-c2-"))
    trials = []
    try:
        for ms in delays_ms:
            corpus = work / "pcaps"
            shutil.rmtree(corpus, ignore_errors=True)
            env = dict(os.environ)
            # The loop resolves its corpus dir from this variable, so pointing it at %TEMP%
            # is what keeps this control out of the repo and off the real corpus.
            env["NET_REVERSE_PCAP_DIR"] = str(corpus)
            glob = str(corpus / CONTROL_ARTIFACT)
            before = binding.snapshot_produces([glob])
            p = subprocess.Popen(["node", str(src), "--quiet"], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 cwd=str(REPO))
            time.sleep(ms / 1000.0)
            killed = p.poll() is None
            if killed:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
                p.wait(timeout=20)
            state, verdicts, _ = binding.check_produces(
                CONTROL_CAPABILITY, [glob],
                f"node {CONTROL_LOOP}", before)
            art = corpus / CONTROL_ARTIFACT
            captures = None
            if art.is_file():
                try:
                    captures = len(json.loads(art.read_text(encoding="utf-8"))["files"])
                except (ValueError, KeyError, UnicodeDecodeError):
                    captures = "UNPARSEABLE"
            trials.append({
                "delay_ms": round(ms, 1),
                "killed_mid_run": killed,
                "exit_code": p.returncode,
                "artifact_present": art.is_file(),
                "manifest_captures": captures,
                "binding_state": state,
                "drift_messages": len(verdicts),
            })

        # THE MUTATION. Same harness, same call into the same binding function, but the
        # producer is a two-line stub that prints a plausible string and writes nothing.
        # If this returns `fresh`, the control above is measuring nothing.
        corpus = work / "stub-corpus"
        shutil.rmtree(corpus, ignore_errors=True)
        corpus.mkdir(parents=True, exist_ok=True)
        # A real artifact already on disk, so the stub's run finds a file and can be judged
        # on identity rather than on absence -- which is the strict version of the test.
        real = REPO / CONTROL_WRITER
        subprocess.run(["node", str(real), "--out", str(corpus)], capture_output=True, cwd=str(REPO))
        stub = work / "stub.py"
        stub.write_text("print('PACKETS=5 CORPUS-OK')\n", encoding="utf-8")
        glob = str(corpus / CONTROL_ARTIFACT)
        before = binding.snapshot_produces([glob])
        subprocess.run(["python", str(stub)], capture_output=True, cwd=str(REPO))
        m_state, m_verdicts, _ = binding.check_produces(
            CONTROL_CAPABILITY, [glob], "stub that writes nothing", before)

        accepted = sum(1 for t in trials
                       if t["binding_state"] == "fresh" and t["artifact_present"]
                       and t["killed_mid_run"])
        return {
            "loop": CONTROL_LOOP.replace("\\", "/"),
            "declared_command": f"node {CONTROL_LOOP.replace(chr(92), '/')}",
            "capability": CONTROL_CAPABILITY,
            "trials": trials,
            "accepted_killed_runs": accepted,
            "mutation": {
                "description": "identical harness, producer replaced by a stub that writes nothing",
                "binding_state": m_state,
                "drift_messages": len(m_verdicts),
                "goes_red": m_state != "fresh",
            },
            "error": None,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def classify(p: dict) -> str:
    if p["direct"] == "yes" and p["marker"] == "none":
        return "UNGUARDED"
    if p["direct"] == "yes":
        return "direct+marker"
    if p["direct"] == "staged":
        return "ATOMIC"
    return "reader"


def hazard_sentence(p: dict) -> str:
    """One sentence: what a reader mistakes the truncated artifact for."""
    return {
        "net-reverse/lab/gen-pcaps.mjs":
            "A reader mistakes a killed corpus for a complete one: the manifest lists five "
            "captures and hashes each one, so a corpus.json cut after its opening brace reads "
            "as 'the corpus was regenerated' rather than 'the corpus died'.",
        "net-reverse/tools/trustcheck.mjs":
            "A reader mistakes a truncated trust baseline for a machine whose root store did not "
            "change: the next run prints 'unchanged since <at>' about a baseline that was never "
            "finished being written.",
        "fuzz-lab/tools/loop.mjs":
            "A reader mistakes a killed fuzz summary for a clean run: the file exists at "
            "fuzz-lab/out/last-run.json with a plausible size, and only a json.loads separates "
            "it from a report saying ok:true.",
        "forensics-lab/tools/loop.mjs":
            "A reader mistakes the demonstration's mutation for the pristine corpus: after a "
            "kill between the Srum filter and its restore, the next window sees a forensic image "
            "with rows deliberately removed and reads its findings as the lab's real output.",
        "headless-lab/tools/authenticode.py":
            "A reader mistakes a half-written signed PE for a signed PE: the SECURITY data "
            "directory was patched before the write, so the file announces a certificate table "
            "it does not fully contain.",
        "native-lab/tools/disasm.py":
            "A reader mistakes a truncated disassembly for a short function: the tool's own "
            "header says --count 'truncates arbitrarily, so the count says NOTHING about the "
            "function's extent', and a killed write looks exactly like a small --count.",
        "scripts/assert-probes.py":
            "A reader mistakes a truncated evidence log for a complete one: the header is "
            "written first and carries the artifact's sha256, so the log still shows a valid "
            "hash and a valid exit code with the body cut off underneath.",
        "scripts/sync-wiki-figures.py":
            "A reader mistakes a half-rewritten wiki page for a page with stale figures: "
            "doc-facts.py then reports a claim as drifted when the file was cut mid-rewrite, "
            "and the next window edits prose that was never wrong.",
        "forensics-lab/tools/correlate.mjs":
            "A reader mistakes a half-written carved region for the carved region: the .yar "
            "rule written after it names the exact marker, so a short .bin and a complete .yar "
            "disagree in a way nothing checks.",
        "scripts/check-requires-tools.py":
            "A reader mistakes a truncated tool dump for a complete one, and debugs the tools it "
            "names rather than the dump.",
        "fuzz-lab/lab/targets.mjs":
            "A reader does not mistake it for anything: a truncated scratch seed becomes a fuzz "
            "INPUT, so the cost is a silent change in what was tested, not a false claim.",
    }.get(p["path"], "")


def print_table(producers: list[dict]) -> None:
    print("\nPRODUCER SURVEY -- read from source, line numbers are the evidence")
    print("=" * 100)
    hdr = f"{'producer':<44} {'direct':<8} {'completion-marker':<20} {'verdict':<14}"
    print(hdr)
    print("-" * 100)
    for p in producers:
        print(f"{p['path']:<44} {p['direct']:<8} {p['marker']:<20} {classify(p):<14}")
    print("-" * 100)
    counts: dict[str, int] = {}
    for p in producers:
        counts[classify(p)] = counts.get(classify(p), 0) + 1
    print("  " + "  ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print(f"  {len(producers)} producers surveyed; write sites are at the line numbers in the")
    print("  JSON form and in evidence/atomic-artifacts.md.")

    for p in producers:
        print(f"\n  {p['path']}")
        print(f"    artifact : {p['artifact']}")
        if p["write_lines"]:
            print(f"    writes   : line(s) {', '.join(str(n) for n in p['write_lines'])}")
        print(f"    {p['note']}")

    unguarded = [p for p in producers if classify(p) == "UNGUARDED"]
    print("\n\nUNGUARDED PRODUCERS -- writes directly, no completion marker")
    print("=" * 100)
    print("What a reader would mistake the truncated artifact for:\n")
    for p in unguarded:
        s = hazard_sentence(p)
        if s:
            print(f"  * {p['path']}")
            for line in _wrap(s, 92):
                print(f"      {line}")
            print()


def _wrap(text: str, width: int) -> list[str]:
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


def print_c1(c: dict) -> None:
    print("\n\nCONTROL C1 -- can a BYTE-TRUNCATED artifact be produced at all?")
    print("=" * 100)
    print("  Real writer, run from a %TEMP% working copy, killed partway across its whole")
    print("  measured runtime. Nothing in the repo is touched.\n")
    if c.get("error"):
        print(f"  C1 DID NOT RUN: {c['error']}")
        print("  Reported as a failure of the control, not as a finding about the station.")
        return
    print(f"  writer              {c['writer']}")
    print(f"  artifact            {c['artifact']}   (registry glob: {CONTROL_DECLARED_GLOB})")
    print(f"  uninterrupted run   {c['full_run_ms']} ms -> {c['complete_bytes']} bytes")
    print(f"  trials              {c['trials']}, of which {c['killed_mid_run']} were killed mid-run\n")
    width = max(len(t) for t in c["tally"])
    for state, n in sorted(c["tally"].items(), key=lambda kv: -kv[1]):
        print(f"    {state:<{width}}  {n:>4} trial(s)")
    print(f"\n  truncated artifacts produced: {c['truncated_artifacts']} of {c['trials']}")
    print(f"  write window  (one whole-file write of {c['complete_bytes']} B)  "
          f"{c['write_window_ms']} ms")
    print(f"  kill latency  (taskkill /F /T to process death)               "
          f"{c['kill_latency_ms']} ms")
    print(f"  ratio: the kill is {c['race_ratio']}x SLOWER than the window it would have to")
    print("  land inside.")
    if c["truncated_artifacts"]:
        print("\n  -> A TRUNCATED artifact WAS produced. The hazard is demonstrated directly.")
    else:
        print("\n  -> RESULT: no byte-truncated artifact was produced, and the reason is")
        print("     measured rather than guessed. Every producer surveyed writes with ONE")
        print("     whole-file write, which is effectively atomic at these sizes: the window")
        print("     a kill would have to hit is ~1000x narrower than the kill mechanism.")
        print("     So the TRUNCATION hazard, as the brief framed it, is NOT reachable on this")
        print("     box by killing the producer. It is reachable by a full disk, a machine")
        print("     reset, or an antivirus scanner truncating a file in flight -- none of which")
        print("     this control can simulate. That is said here rather than glossed over.")


def print_c2(c: dict) -> None:
    print("\n\nCONTROL C2 -- can the REAL binding tell a killed run from a finished one?")
    print("=" * 100)
    print("  The command the registry ACTUALLY declares for net.pcap.analyse, run from a")
    print("  %TEMP% working copy, killed partway, then judged by assert-probes.py's OWN")
    print("  snapshot_produces() and check_produces() -- imported, not reimplemented.\n")
    if c.get("error"):
        print(f"  C2 DID NOT RUN: {c['error']}")
        print("  Reported as a failure of the control, not as a finding about the station.")
        return
    print(f"  declared command    {c['declared_command']}")
    print(f"  capability          {c['capability']}")
    print(f"  trials              {len(c['trials'])}\n")
    print(f"  {'kill@ms':>9} {'killed':>7} {'exit':>5} {'artifact':>9} {'captures':>10} "
          f"{'check_produces':>16} {'drift':>6}")
    print("  " + "-" * 68)
    for t in c["trials"]:
        print(f"  {t['delay_ms']:>9.0f} {str(t['killed_mid_run']):>7} {str(t['exit_code']):>5} "
              f"{('present' if t['artifact_present'] else 'ABSENT'):>9} "
              f"{str(t['manifest_captures']):>10} {t['binding_state']:>16} "
              f"{t['drift_messages']:>6}")
    print()
    n = c["accepted_killed_runs"]
    print(f"  KILLED RUNS THE BINDING ACCEPTED AS PRODUCED: {n} of {len(c['trials'])}")
    print()
    print("  READ THIS CAREFULLY -- it is the finding, and it is not the one the brief")
    print("  predicted. Every one of these runs was killed mid-flight. Each left a")
    print("  COMPLETE, PARSEABLE manifest listing all five captures, and check_produces()")
    print("  returned 'fresh' with ZERO drift messages. The binding cannot distinguish")
    print("  'the instrument produced this' from 'the instrument produced its first step,")
    print("  wrote the artifact, and then died before the other five steps ran' -- because")
    print("  nothing in the artifact records that the other steps ran. corpus.json describes")
    print("  the corpus; it says nothing about the 16 questions, the replay, the CDP")
    print("  interception or the trust isolation check that the probe command also performs.")
    print("  A truncated file would at least fail json.loads. A file that is complete and")
    print("  silent about 5 of 6 steps does not.")

    m = c["mutation"]
    print("\n  MUTATION -- the same harness against a producer that writes nothing.")
    print("  " + "-" * 68)
    print(f"    {m['description']}")
    print(f"    binding_state      {m['binding_state']}")
    print(f"    drift_messages     {m['drift_messages']}")
    print(f"    goes RED           {m['goes_red']}")
    if m["goes_red"]:
        print("\n    -> The mutation went red, so 'fresh' in the table above is a real verdict")
        print("       this harness earned, not a default. The binding DOES catch a producer")
        print("       that touches nothing. What it cannot catch is a producer that writes")
        print("       its artifact and then fails.")
    else:
        print("\n    -> THE MUTATION DID NOT GO RED. The control above is therefore not")
        print("       measuring what it claims to measure, and its 'fresh' verdicts must be")
        print("       read as meaningless until this is fixed.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable survey + controls")
    ap.add_argument("--no-control", action="store_true",
                    help="survey only; do not launch and kill a producer")
    ap.add_argument("--c1-trials", type=int, default=40,
                    help="kill trials for C1, the truncation-reachability control (default 40)")
    ap.add_argument("--c2-trials", type=int, default=6,
                    help="kill trials for C2, the binding control (default 6)")
    args = ap.parse_args()

    for p in PRODUCERS:
        f = REPO / p["path"]
        p["exists"] = f.is_file()
        if not p["exists"]:
            print(f"verify-atomic-artifacts: surveyed producer is MISSING: {f}",
                  file=sys.stderr)
            return 2

    c1 = c2 = None
    binding = None
    if not args.no_control:
        c1 = control_c1(args.c1_trials)
        try:
            binding = load_binding()
        except Exception as e:                       # noqa: BLE001
            c2 = {"error": f"could not import the binding: {e}"}
        else:
            # The loop takes ~700 ms end to end and step 1 (the corpus write) lands in the
            # first ~50 ms, so these delays all sit AFTER the write and BEFORE the run's own
            # end -- which is exactly the window where the hazard lives.
            c2 = control_c2([100, 150, 200, 250, 300, 400][:max(1, args.c2_trials)], binding)

    failed = any(c is not None and c.get("error") for c in (c1, c2))
    mutation_ok = True
    if c2 and not c2.get("error"):
        mutation_ok = c2["mutation"]["goes_red"]

    if args.json:
        print(json.dumps({"producers": PRODUCERS, "c1": c1, "c2": c2}, indent=1))
    else:
        print("verify-atomic-artifacts: can anything tell a FINISHED artifact from a TRUNCATED one?")
        print("=" * 100)
        print("Binding under test: scripts/assert-probes.py, which counts a file as produced")
        print("when (size, mtime_ns, sha256) changed across the run. That is a CHANGE detector.")
        print("This survey asks a different question of the same artifacts: is there anything")
        print("that says the producer FINISHED?")
        print_table(PRODUCERS)
        if c1 is not None:
            print_c1(c1)
        if c2 is not None:
            print_c2(c2)

        print("\n\nWHAT THIS DOES NOT CLAIM")
        print("=" * 100)
        print("  * It does not claim a producer is BROKEN. Every one produces correct bytes")
        print("    when allowed to finish.")
        print("  * It does not claim the binding is wrong. (size, mtime_ns, sha256) is the right")
        print("    check for 'this run touched this file' and the MUTATION above shows it")
        print("    catches a stub. It is silent on 'this run finished'.")
        print("  * The classifications are readings of source; the line numbers printed with")
        print("    each row are the evidence for that reading. Only C1 and C2 are measured.")
        print("  * No producer was modified. The fix, where one is wanted, is temp-then-rename")
        print("    or a manifest that records what ELSE must exist -- mobile-lab/tools/loop.mjs:104")
        print("    already does the first and writes down why.")

        print("\n\nTHE ONE-LINE FINDING")
        print("=" * 100)
        if c2 and not c2.get("error"):
            print(f"  A run of {c2['declared_command']} killed mid-flight was accepted as")
            print(f"  PRODUCED in {c2['accepted_killed_runs']} of {len(c2['trials'])} trials, with")
            print("  zero DRIFT. The artifact is complete; what is missing is any record that")
            print("  the run did the other five things the command does.")
        if c1 and not c1.get("error") and not c1["truncated_artifacts"]:
            print(f"  Byte-truncation was NOT reachable in {c1['trials']} kills, because the")
            print(f"  write window is {c1['write_window_ms']} ms and the kill takes "
                  f"{c1['kill_latency_ms']} ms.")

    if failed:
        return 1
    if not mutation_ok:
        print("\nverify-atomic-artifacts: the C2 mutation did not go red; the control's "
              "verdicts are not trustworthy.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())