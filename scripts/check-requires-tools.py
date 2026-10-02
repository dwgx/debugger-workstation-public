#!/usr/bin/env python
"""Execute every `requires.tools[].probe` and check it against its declared `expect`.

WHY THIS EXISTS. Nothing in this project ever executed `requires.tools[].expect`. An audit
proved it by grep: the field appears only in R18, which reads `.name` for instrument identity and
never touches `expect`. So the field was decoration that read like a contract.

And it was not decoration about nothing. One entry declared:

    { "name": "tshark", "probe": "tshark --version", "expect": "TShark" }

which FAILS on this station -- `where tshark` finds nothing, because the station ships a PORTABLE
Wireshark at Network-HTTP/Wireshark/portable/App/Wireshark/tshark.exe (measured TShark 4.6.8).
Another declared `corpus.json written to %TEMP%\\net-reverse-lab\\pcaps`, which can never match:
%TEMP% is a CMD token the program does not expand, and it prints `label -> <path>\\corpus.json`.

Both sat there with the registry reporting CLEAN, and neither would ever have been noticed.

WHAT IT IS NOT. This is NOT `assert-probes.py`. That tool checks a capability's PROBE -- the run
that produces its evidence. This checks the PRECONDITION that says the tool is even present.
They fail in opposite directions and confusing them would be its own bug: a capability whose probe
cannot reproduce is a defect; a capability whose required tool is missing is an environment fact,
and the right answer is to say so rather than to fail the registry.

    python scripts/check-requires-tools.py            # all entries
    python scripts/check-requires-tools.py --verbose  # show each probe's real output

    python scripts/check-requires-tools.py --repeats 4      # 4 runs per probe, then diff them
    python scripts/check-requires-tools.py --dump probe-runs.json

VOLATILITY. `expect` is a STRING, and some strings move. The precedent is measured, not
hypothetical: `native.signature.certverify` recorded a 7-digit OpenSSL error prefix that came out
`182B0000:...` on one run and `ECB80000:...` on the next -- same host, same command, same binary.
The fix applied to that entry was manual: quote the stable parts, and say in prose that the
prefix is deliberately not recorded. A manual fix to one entry is not a control. The class stayed
open, and it stays open for the next entry written by anyone, including me.

So this script now does the thing the prose never did: it RUNS each probe more than once and
DIFFS the real outputs. Nothing here infers volatility from the shape of a word. A value is
volatile because it MEASURED different on a repeat of the same command, not because it looks like
a timestamp.

    VOLATILE              a span of the output measured DIFFERENT across runs and no declared
                          marker covers it. The expect asserts text that moves, so the entry
                          passed by luck and will fail on the next run that disagrees.
    VOLATILE-UNJUSTIFIED  a `{volatile:...}` marker whose region never moved. A volatility claim
                          nothing observed is decoration in a field that reads like a contract,
                          which is the exact shape this whole script exists to refuse.

THE VOCABULARY, and why it is the project's and not a second one. R25 lets a plan point at
`file:<path>` (and it MUST exist), `missing:<glob>` (and it MUST match nothing), or
`undecidable:<why>` (with a sentence). Every form is a TAG plus a PAYLOAD the machine checks, and
'nobody checked' has to be visible as a claim rather than hidden inside prose. This is the same
three-part idea aimed at a substring instead of a path:

    OpenSSL 3.5.2                              plain substring, semantics unchanged
    {volatile:error prefix differs per run}   the span MOVED, and was measured moving
    {undecidable:varies per boot not per run}  moves, but this host cannot stage the difference

Two forms, not three, because a substring has no 'this file exists' axis to be wrong about. The
obligation is the same in both directions: a MEASURED difference must be covered by a declared
marker, so the only remaining question left is whether the author can produce that difference on
demand. `{volatile:}` is held to it -- the region MUST move across the repeated runs.
`{undecidable:}` is the honest exit for volatility this host cannot stage on demand (an ASLR
address changes per boot, not per run; another account's %TEMP% is not reproducible at all). It
still carries a sentence, and it is still reported separately, so a reader can see which holes are
backed by measurement and which are a claim.

WHAT IT CANNOT CATCH. Stated here so nobody reads more into a green run than it says:
  * volatility on a period longer than the repeats. Four runs in the same second cannot see a
    value that changes on reboot, on a timer, or on the Nth run. `{undecidable:}` is where that
    is admitted, and the admission is taken on trust -- exactly as R25 trusts `undecidable:`.
  * host-portability. A path, a username, a version pin and a Windows install layout are stable
    on THIS box and wrong on another one. A same-host differential is blind to all four.
  * anything the probe never prints. If the volatile field does not reach stdout it cannot be in
    the expect either, so there is nothing here to flag.
  * whether an expectation is CORRECT. Only whether it can be relied on to give the same verdict
    tomorrow as it gave today.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# A probe that must never run here. Every one is a state=absent or state=blocked entry, so the
# tool does not exist by definition -- running the probe would be trying to verify something the
# registry already says is not present.
NEVER_RUN_IF_STATE = {"absent", "blocked"}

# `{volatile:<why>}` / `{undecidable:<why>}`, the two declared forms. `undecidable` is R25's own
# word for 'outside what this repository can check', kept so there is one vocabulary to learn.
MARKER_RE = re.compile(r"\{(?P<tag>[a-z][a-z0-9_-]*):(?P<why>[^{}]*)\}")
VOLATILE_TAGS = {"volatile", "undecidable"}
MIN_WHY = 12      # R25 uses the same floor for an undecidable reason. A short one is a shrug.


def as_powershell(cmd: str, tag: str = "cmd") -> tuple[str, str]:
    """Return (shell, line). Written to a .ps1 and run with -File, never re-quoted inline.

    `powershell -Command "<cmd>"` destroys any command containing a double quote, and a
    PowerShell marker sniff misses the rest. That mis-dispatch produced 21 false DRIFTs in
    assert-probes.py's first run. The text reaching the interpreter has to be byte-for-byte the
    text in the registry, so the file is the only arrangement in which 'verbatim' is true.
    """
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:48]
    # The pid is in the name because sibling agents run this script at the same time on one box,
    # and a shared temp filename would have two processes writing the interpreter's real input.
    script = Path(tempfile.gettempdir()) / f"_crt_{os.getpid()}_{safe}.ps1"
    script.write_text(cmd + "\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
    return f'powershell -NoProfile -ExecutionPolicy Bypass -File "{script}"', str(script)


def run_probe(shell: str, timeout: int) -> tuple[int, str]:
    """(exit code, combined stdout+stderr). Negative codes are this script's own faults."""
    try:
        p = subprocess.run(shell, shell=True, cwd=REPO, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, f"<timeout after {timeout}s>"
    except Exception as e:  # noqa: BLE001
        return -2, f"<could not run: {e}>"


# A run that never got to execute the probe. Measured on this box under load, not invented:
# PowerShell's own startup failed with `System.OutOfMemoryException` / a `ServicePointManager`
# type-initializer throw, and tshark aborted with a GLib `failed to allocate 16777248 bytes`.
# Both look exactly like a registry defect -- a different exit code, a different first line --
# and both are THIS SCRIPT'S PROBLEM, which is what TOOL-FAULT already means. Reporting them as
# VOLATILE would be a gate that cries wolf under load, and a wolf that cries wolf gets muted.
HOST_FAULT_RE = re.compile(
    r"the shell cannot be started|"
    r"System\.OutOfMemoryException|"
    r"type initializer for .* threw an exception|"
    r"GLib ERROR.*failed to allocate|"
    r"not enough (?:memory|storage)",
    re.IGNORECASE)

HOST_FAULT_EXITS = {4294901760, 3221226505, 3221225773, 3221225477}

def split_expect(expect: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Split an expect into its literal anchors and its `{tag:why}` markers."""
    literals, markers, pos = [], [], 0
    for m in MARKER_RE.finditer(expect):
        literals.append(expect[pos:m.start()])
        markers.append((m.group("tag"), m.group("why")))
        pos = m.end()
    literals.append(expect[pos:])
    return literals, markers


def anchor_regions(literals: list[str], blob: str) -> tuple[bool, list[tuple[int, int]], str]:
    """Find the literal anchors in order; return (all_found, one region per marker, failed one).

    The region for marker k is the output BETWEEN the end of literal k and the start of literal
    k+1 -- which is precisely the text the marker claims not to assert, and therefore precisely
    the text a measured difference is allowed to land in.
    """
    found: dict[int, tuple[int, int]] = {}
    pos = 0
    for i, lit in enumerate(literals):
        if not lit:
            continue
        j = blob.find(lit, pos)
        if j < 0:
            return False, [], repr(lit)
        found[i] = (j, j + len(lit))
        pos = j + len(lit)
    regions = []
    for k in range(1, len(literals)):
        s = found[k - 1][1] if (k - 1) in found else 0
        e = found[k][0] if k in found else len(blob)
        regions.append((s, max(s, e)))
    return True, regions, ""


def varying_spans(outputs: list[str]) -> list[tuple[int, int, str, str]]:
    """Spans of outputs[0] that a later run disagrees with, with the text on both sides.

    difflib rather than a position-wise zip: a run whose output is SHIFTED by an inserted
    timestamp must not mark everything after the shift as varying, because a stable substring
    that happens to follow the shift is still stable. Only spans that genuinely disagree count.
    """
    base = outputs[0]
    spans: list[tuple[int, int, str, str]] = []
    for other in outputs[1:]:
        sm = difflib.SequenceMatcher(None, base, other, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            i2 = max(i2, min(len(base), i1 + 1))
            spans.append((i1, i2, base[i1:i2], other[j1:j2]))
    merged: list[tuple[int, int, str, str]] = []
    for s, e, bt, ot in sorted(spans):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e), merged[-1][2], ot)
        else:
            merged.append((s, e, bt, ot))
    return merged


def overlaps(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


# Text that is a property of THIS MACHINE rather than of the tool. An expectation quoting it is
# correct here and wrong on the next box, which no same-host differential can detect -- it does
# not vary here, it varies somewhere this script has never run. Reported, never refused.
#
# Each pattern is anchored on something that has to be there for the reading to be right, so this
# is not a keyword list: 'C:\Users\...' is a path because it starts with a drive and contains a
# user directory, and `%TEMP%`/`$env:` are unexpanded CMD/PowerShell tokens wherever they appear.
HOST_SPECIFIC_PATTERNS = [
    (re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+"), "absolute path containing a user profile"),
    (re.compile(r"[A-Za-z]:\\Program Files", re.IGNORECASE), "absolute Program Files path"),
    (re.compile(r"%[A-Za-z_]+%|\$env:[A-Za-z_]+"), "unexpanded environment token"),
    (re.compile(r"\bMemory:\s*\d+\s*MB", re.IGNORECASE), "physical memory size"),
    (re.compile(r"\b0x[0-9a-fA-F]{8,}\b"), "long hex value (image base or address)"),
    (re.compile(r"\bsha256:[0-9a-f]{8,}"), "content hash prefix"),
]


def host_specific(literals: list[str]) -> str:
    """Name the host-bound spans an expectation quotes. A report, never a refusal."""
    hits = []
    for lit in literals:
        for rx, why in HOST_SPECIFIC_PATTERNS:
            m = rx.search(lit)
            if m:
                hits.append(f"{m.group(0)[:40]!r} ({why})")
    return "; ".join(dict.fromkeys(hits))



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--repeats", type=int, default=2,
                    help="runs per probe, then diffed. Floored at 2: with a single run there is "
                         "no diff, VOLATILE is unreachable, and the flag would be theatre.")
    ap.add_argument("--dump", help="write every raw run output and verdict to this JSON path")
    ap.add_argument("--registry", default=str(REG),
                    help="registry to check. Exists so a TEMP copy with planted fixtures can be "
                         "proven against without editing the real one.")
    ap.add_argument("--only", action="append", default=[], metavar="CAP_ID",
                    help="check only these capability ids (repeatable)")
    args = ap.parse_args()
    args.repeats = max(2, args.repeats)

    caps = json.load(open(args.registry, encoding="utf-8"))["capabilities"]
    if args.only:
        caps = [c for c in caps if c.get("id") in set(args.only)]
        if not caps:
            print(f"--only {args.only} matched no capability in {args.registry}")
            return 2
    rows: list[tuple[str, str, str, str]] = []   # (id, tool, verdict, detail)
    dump: list[dict] = []

    def emit(cid: str, name: str, verdict: str, detail: str = "", rec: dict | None = None) -> None:
        rows.append((cid, name, verdict, detail))
        if rec is not None:
            rec["verdict"] = verdict
            dump.append(rec)

    for c in caps:
        req = c.get("requires") or {}
        for t in req.get("tools") or []:
            name = t.get("name", "?")
            probe = (t.get("probe") or "").strip()
            expect = t.get("expect")
            # An entry may DECLARE itself unverifiable, which is honest and is not the same as
            # declaring a probe that cannot fail. MCP devices and browser surfaces have no CLI
            # invocation; giving them one would manufacture a check that passes without testing.
            if t.get("verify") is False:
                emit(c["id"], name, "UNDECLARED-UNVERIFIABLE",
                     str(t.get("verify_note") or "declared verify:false -- no CLI "
                                                "invocation can prove it"))
                continue
            if not probe:
                emit(c["id"], name, "NO-PROBE",
                     "declares a tool with no probe, so its presence is asserted and never checked")
                continue
            if c["state"] in NEVER_RUN_IF_STATE:
                emit(c["id"], name, "SKIP",
                     f"state={c['state']}: the registry already says this is not present, "
                     f"so running its probe would be checking a contradiction")
                continue

            # Run the SAME probe until there are `repeats` SUCCESSFUL runs, keeping every output.
            # One run cannot show volatility; it can only show a match, and a match is exactly
            # what a volatile expectation gives too. The repeat is the whole measurement.
            #
            # A run that never reached the probe is DISCARDED, not diffed and not reported as a
            # registry defect: this box runs several agents at once, and a starved PowerShell
            # fails at startup with an exit code no registry entry could ever have caused.
            #
            # THE DISCARD MUST NOT SHRINK N. Discarding is a filter, and a filter that quietly
            # hands back fewer samples than were asked for turns 'eight runs, two of them real'
            # into a verdict about eight. That is the vacuous diff this script refuses to accept
            # at N=1, arriving by the back door. So: keep collecting to a CEILING of 3N attempts,
            # and if N successes were not reached, say TOOL-FAULT with the discarded runs named.
            # Never 'stable', never 'no difference observed' -- those words require N samples.
            ceiling = args.repeats * 3
            runs: list[tuple[int, str]] = []
            host_faults: list[str] = []
            fault: tuple[int, str] | None = None
            attempts = 0
            while len(runs) < args.repeats and attempts < ceiling:
                attempts += 1
                shell, script = as_powershell(probe, f"{name}_{attempts}")
                try:
                    rc, blob = run_probe(shell, args.timeout)
                finally:
                    try:
                        os.unlink(script)
                    except OSError:
                        pass
                if rc < 0:
                    fault = (rc, blob)
                    break
                sig = HOST_FAULT_RE.search(blob)
                if sig or rc in HOST_FAULT_EXITS:
                    # Record WHICH signature and WHICH exit code, so a reader can disagree with
                    # the classification instead of taking it on faith. This is the one place
                    # the script trusts a pattern rather than a measurement, so it is also the
                    # one place the pattern is printed in full.
                    why = (f"matched signature {sig.group(0)[:70]!r}" if sig
                           else f"exit {rc} is in HOST_FAULT_EXITS")
                    host_faults.append(f"attempt{attempts} rc={rc}: {why}")
                    continue
                runs.append((rc, blob))
            if fault is None and len(runs) < args.repeats:
                fault = (-3, f"{len(host_faults)} of {attempts} attempts discarded: "
                             + " | ".join(host_faults[:6]))

            rec: dict = {"id": c["id"], "tool": name, "probe": probe, "expect": expect,
                         "repeats_requested": args.repeats, "attempts": attempts,
                         "attempt_ceiling": ceiling,
                         "runs_completed": len(runs),
                         "exits": sorted({r for r, _ in runs})}
            if host_faults:
                # Real runs exist, so the comparison is still meaningful; say what was dropped
                # rather than pretending the box was quiet.
                rec["host_faults"] = host_faults

            if fault is not None:
                frc, fblob = fault
                rec["fault"] = fblob.strip()[:200]
                if frc == -1:
                    emit(c["id"], name, "TOOL-FAULT",
                         f"probe timed out after {args.timeout}s -- this script's limit, "
                         f"not the registry's. A truncated run is not evidence.", rec)
                elif frc == -3:
                    emit(c["id"], name, "TOOL-FAULT",
                         f"reached only {len(runs)} usable run(s) of the {args.repeats} asked for, "
                         f"within a ceiling of {ceiling} attempts. THIS SCRIPT'S PROBLEM, not the "
                         f"registry's -- these runs failed BEFORE executing the probe, so they "
                         f"are not evidence that anything is or is not volatile. Refusing to "
                         f"answer is the honest result: a verdict here would rest on fewer "
                         f"samples than it claims. Discards: {fblob[:300]}", rec)
                else:
                    emit(c["id"], name, "TOOL-FAULT", fblob.strip()[:120], rec)
                continue

            rc, blob = runs[-1]
            rec["outputs"] = [b for _, b in runs]

            # The probe must SUCCEED. A non-zero exit with a matching string would let a broken
            # tool satisfy its own precondition, which is the shape this whole script exists to
            # refuse -- the same shape as assert-probes.py's stub finding.
            # A tool whose PRESENCE SIGNAL is a usage banner exits non-zero for having no
            # arguments. Ghidra's analyzeHeadless.bat prints its usage and exits -1 when invoked
            # bare, which is exactly what proves the batch file exists and responds. Calling that
            # BROKEN would make the gate unable to describe that case honestly, so a tool may
            # declare expect_exit and say which non-zero code is the one it means.
            want_rc = t.get("expect_exit", 0)
            if rc != want_rc:
                emit(c["id"], name, "BROKEN",
                     f"probe exited {rc} (declared expect_exit {want_rc}): "
                     f"{blob.strip()[:100]}", rec)
                continue
            if expect is None:
                emit(c["id"], name, "NO-EXPECT",
                     "probe succeeded but declares no expect, so success and failure look "
                     "identical", rec)
                continue

            # An exit code that is not REPRODUCIBLE is a landmine with no substring to hide in.
            # Host-fault exits are already gone by now, so what is left really did vary.
            distinct_rc = rec["exits"]
            if len(distinct_rc) > 1:
                emit(c["id"], name, "VOLATILE",
                     f"probe exited {distinct_rc} across {len(runs)} runs of the same command. "
                     f"expect_exit {want_rc} is one of those outcomes and not all of them, so "
                     f"this precondition passes or fails depending on when it is run.", rec)
                continue

            # `expect` is used in BOTH senses across this registry and both are legitimate:
            #   "exit 0"            a description of the expected EXIT CODE, and
            #   "TShark"            a literal substring the OUTPUT must contain.
            # Treating both as substrings made the first kind permanently unmeetable -- the
            # output of `python -c "import pefile"` is empty, so the substring "exit 0" can
            # never appear. Recognising the exit-code form is the honest resolution rather than
            # rewriting a dozen entries to match a convention half of them never used.
            literals, markers = split_expect(str(expect))
            unknown = [(tg, wy) for tg, wy in markers if tg not in VOLATILE_TAGS]
            if unknown:
                tg, wy = unknown[0]
                emit(c["id"], name, "MARKER-UNKNOWN",
                     f"expect carries {{{tg}:{wy}}} which is not a declared form. Use "
                     f"{{volatile:<why>}} or {{undecidable:<why>}} and nothing else -- a marker "
                     f"nobody defines is a claim with no reader.", rec)
                continue
            thin = [wy for _tg, wy in markers if len(wy.strip()) < MIN_WHY]
            if thin:
                emit(c["id"], name, "MARKER-NO-REASON",
                     f"expect marker with no reason: {thin[0]!r}. Saying a span moves is the easy "
                     f"half; saying WHY is the half a later reader needs.", rec)
                continue
            if not any(literals):
                emit(c["id"], name, "NO-ASSERTION",
                     "expect is nothing but markers, so it asserts nothing. Success and failure "
                     "look identical, which is the state this script was written to end.", rec)
                continue

            m = re.fullmatch(r"exit\s+(\d+)", str(expect).strip(), re.IGNORECASE)
            if m:
                want_rc = int(m.group(1))
                if rc != want_rc:
                    emit(c["id"], name, "UNMATCHED",
                         f"declared expect exit {want_rc}, real exit was {rc}", rec)
                else:
                    emit(c["id"], name, "OK", "", rec)
                continue

            first = runs[0][1]
            ok, regions, missing = anchor_regions(literals, first)
            if not ok:
                near = first.strip().replace("\n", " ")[:150]
                emit(c["id"], name, "UNMATCHED",
                     f"declared expect {str(expect)!r} does not occur in the real output: anchor "
                     f"{missing} is absent; {near!r}", rec)
                continue

            spans = varying_spans([b for _, b in runs])
            rec["varying_spans"] = [{"at": s, "len": e - s, "run1": bt, "other": ot}
                                   for s, e, bt, ot in spans]
            rec["marker_regions"] = [list(rg) for rg in regions]

            uncovered = [sp for sp in spans if not any(overlaps(sp, rg) for rg in regions)]
            if uncovered:
                sp = uncovered[0]
                emit(c["id"], name, "VOLATILE",
                     f"expect asserts text that MOVED across {len(runs)} runs of the same probe. "
                     f"Declared {str(expect)!r}; run 1 printed {sp[2]!r} at offset {sp[0]}, "
                     f"another run printed {sp[3]!r}. No {{volatile:}} or {{undecidable:}} marker "
                     f"covers it, so this entry passes by luck and fails on the next run that "
                     f"disagrees. Quote the stable part and wrap the moving part.", rec)
                continue

            stale = [(wy, k) for k, (tg, wy) in enumerate(markers)
                     if tg == "volatile"
                     and not any(overlaps(sp, regions[k]) for sp in spans)]
            if stale:
                wy, _k = stale[0]
                emit(c["id"], name, "VOLATILE-UNJUSTIFIED",
                     f"expect marks {{{wy}}} as volatile, and across {len(runs)} runs of the same "
                     f"probe that region never moved. A volatility claim nothing observed is "
                     f"decoration in a field that reads like a contract. If it really varies but "
                     f"this host cannot stage the difference, say {{undecidable:...}} and why.",
                     rec)
                continue

            note = "; ".join(
                f"{tg}:{wy} [{'measured moving' if any(overlaps(sp, regions[k]) for sp in spans)
                          else 'no difference observed'}]"
                for k, (tg, wy) in enumerate(markers))
            # A REPORTED note, never a verdict. Host-specific text cannot be detected from one
            # host by definition -- it does not vary here, it varies on a box that is not this
            # one -- so refusing it would refuse correct entries for a difference they cannot
            # exhibit. Naming it costs nothing and lets a reader judge the next host.
            hs = host_specific(literals)
            if hs:
                note = (note + "; " if note else "") + f"HOST-SPECIFIC, not refused: {hs}"
            emit(c["id"], name, "OK", note, rec)

    widths = (max(len(r[1]) for r in rows) if rows else 8,
              max(len(r[2]) for r in rows) if rows else 8)
    for cid, name, verdict, detail in rows:
        print(f"  {verdict:<{widths[1]}}  {name:<{widths[0]}}  {cid}")
        if detail and (args.verbose or verdict not in ("OK", "SKIP", "UNDECLARED-UNVERIFIABLE")):
            print(f"      {detail}")

    bad = [r for r in rows if r[2] in ("BROKEN", "UNMATCHED", "NO-PROBE", "NO-EXPECT",
                                       "VOLATILE", "VOLATILE-UNJUSTIFIED", "MARKER-UNKNOWN",
                                       "MARKER-NO-REASON", "NO-ASSERTION")]
    fault = [r for r in rows if r[2] == "TOOL-FAULT"]
    ok = [r for r in rows if r[2] == "OK"]
    skipped = [r for r in rows if r[2] == "SKIP"]
    print(f"\nrequires-tools: {len(rows)} declared tool probes across {len(caps)} capabilities "
          f"-- {len(ok)} ok, {len(bad)} wrong, {len(fault)} tool-fault, {len(skipped)} skipped. "
          f"Every executed probe was run {args.repeats}x and diffed against its first run.")

    if args.dump:
        Path(args.dump).write_text(json.dumps(dump, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"raw run outputs -> {args.dump}")

    if bad:
        print("\nA WRONG entry is a declaration nothing was checking. Nothing else in this project\n"
              "executes requires.tools[].expect, so these would otherwise have stayed invisible\n"
              "indefinitely -- and one of them already was: `tshark --version` cannot pass on this\n"
              "station, which ships a PORTABLE Wireshark that is not on PATH.\n"
              "VOLATILE means the entry passed this time and may not pass the next: the probe\n"
              "measured different output on this same host. Quote the stable part and wrap the\n"
              "moving part in {volatile:<why>}; if this host cannot stage the difference, wrap it\n"
              "in {undecidable:<why>} and say so.")
        return 1
    if fault:
        print("\nTOOL-FAULT is this script's problem, not the registry's. Fix the shell or raise\n"
              "--timeout before reading anything else in this output.")
    return 0


if __name__ == "__main__":
    sys.exit(main())