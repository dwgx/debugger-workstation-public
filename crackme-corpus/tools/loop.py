#!/usr/bin/env python3
"""crackme-corpus runner -- the single command for the whole corpus.

Builds every challenge, runs its solver, and checks the recovered answer
against the answer key. Exits 0 only when every challenge is solved AND
the negative control proves the comparison can fail.

This is the corpus's North Star artifact: without it, five solved
challenges are five anecdotes rather than one re-runnable capability.

  python tools/loop.py                 # build + solve everything
  python tools/loop.py --no-build      # skip the build step
  python tools/loop.py --only c03      # one challenge
  python tools/loop.py --list          # show the ramp, build nothing
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
STATION = os.path.dirname(ROOT)
GHIDRA = os.path.join(STATION, "scripts", "ghidra-headless.ps1")

# The answer key. Committed deliberately: this is a training corpus, and the
# point of a textbook is that the answers are published. The SOLVERS never
# read this file -- they recover the answers from the binaries, and the
# binaries themselves are the judge (each one prints ACCEPTED only for the
# real password). This file exists so the runner can assert.
CORPUS = [
    {
        "id": "c01",
        "dir": "c01-stringobf",
        "name": "c01-stringobf",
        "technique": "string-table obfuscation (byte rotation + XOR mask)",
        "difficulty": 1,
        "build": "c",
        "src": "src/c01_stringobf.c",
        "exe": "c01_stringobf.exe",
        "password": "C01-TABLE-XOR-9F2A",
        "flag": "FLAG{c01_string_table_xor}",
        "tools": "Ghidra headless -> radare2 -> binary judges",
        "teaches": "Never trust `strings | grep FLAG`; c01 ships a plaintext decoy flag. The real one is sealed in .rdata.",
    },
    {
        "id": "c02",
        "dir": "c02-cff-dispatch",
        "name": "c02-cff-dispatch",
        "technique": "control-flow flattening (dispatcher state machine)",
        "difficulty": 2,
        "build": "c",
        "src": "src/c02_cff.c",
        "exe": "c02_cff.exe",
        "password": "FL4T-STATE-7B",
        "flag": "FLAG{c02_flattened_state_machine}",
        "tools": "Ghidra graph walk -> jump-table constants -> binary judges",
        "teaches": "Reconstruct real control flow by walking the state graph. The password is compared as immediates, never as a contiguous string.",
    },
    {
        "id": "c03",
        "dir": "c03-antidebug",
        "name": "c03_antidebug",
        "technique": "anti-debug guard + rolling-XOR seal + FNV-1a integrity",
        "difficulty": 3,
        "build": "c",
        "src": "src/c03_antidebug.c",
        "exe": "c03_antidebug.exe",
        "password": "C03-ROLLING-KEY-7D",
        "flag": "FLAG{c03_rolling_key_behind_guard}",
        "tools": "Ghidra -> radare2 -> FNV-1a recheck -> binary judges",
        "teaches": "Anti-analysis on a sample you own: an integrity check plus a guarded unsealer. The FNV-1a target must be recomputed, not assumed.",
    },
    {
        "id": "c04",
        "dir": "c04-dotnet-obfuscation",
        "name": "c04-dotnet-obfuscation",
        "technique": "managed string encryption with a VM-style opcode table",
        "difficulty": 2,
        "build": "dotnet",
        "project": "src/c04.csproj",
        "dll": "c04.dll",
        "password": "C04-DOTNET-VM-3E91",
        "flag": "FLAG{c04_managed_vm_string_keys}",
        "tools": "ilspycmd decompile -> read the opcode table -> binary judges",
        "teaches": "Managed RE without a GUI. Neither the password nor the flag appears verbatim in the assembly.",
    },
    {
        "id": "c05",
        "dir": "c05-binary-format",
        "name": "c05-binary-format",
        "technique": "binary format / struct recovery (magic header + packed records)",
        "difficulty": 3,
        "build": "c",
        "src": "src/c05_blob.c",
        "exe": "c05_blob.exe",
        "password": "C05-2FE18F60",
        "flag": None,
        "tools": "Ghidra -> radare2 struct layout -> FNV-1a over live records",
        "teaches": "Recover a record layout from bytes, reject decoy records, and derive the key from the live data rather than from storage.",
    },
]


def run(argv, timeout=600, shell=False):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=shell)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def tail(text, n=3):
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return " | ".join(lines[-n:])[:150] if lines else ""


def ps(script, *args):
    return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, *args]


def build(ch):
    os.makedirs(OUT, exist_ok=True)
    if ch["build"] == "c":
        rc, out = run(ps(os.path.join(ROOT, "tools", "build-c.ps1"),
                         "-Source", os.path.join(ROOT, "challenges", ch["dir"], ch["src"]),
                         "-Id", ch["name"], "-OutDir", "out"))
    else:
        rc, out = run(["dotnet", "build",
                       os.path.join(ROOT, "challenges", ch["dir"], ch["project"]),
                       "-c", "Debug", "-o", os.path.join(OUT, ch["name"])], timeout=600)
    return rc == 0, tail(out, 1)


def ghidra(ch, binary=None, outdir=None):
    """Decompile one challenge's sample.

    `binary` and `outdir` are optional overrides, added 2026-11-01 so that
    crackme-corpus/tools/solve-one.py can decompile a CALLER-SUPPLIED binary with the same
    argv this loop uses. Default behaviour is unchanged: the corpus still resolves its own
    out-tree paths, so the loop's measurements are byte-identical to before.
    """
    target = ch["dll"] if ch["build"] == "dotnet" else ch["exe"]
    src = binary or (os.path.join(OUT, ch["name"], target) if ch["build"] == "dotnet" else os.path.join(OUT, target))
    outdir = outdir or os.path.join(OUT, f"{ch['name']}-ghidra" if ch["build"] == "c" else f"{ch['name']}-ilspy")
    if ch["build"] == "c":
        return run(ps(GHIDRA, "-Sample", src, "-OutDir", outdir), timeout=900)
    # managed path: ilspycmd is resolved separately (see ilspy() below)
    exe = ilspy()
    if not exe:
        return 127, "ilspycmd not found (dotnet tool list -g)"
    return run([*exe, "-o", outdir, src], timeout=600)


def solve(ch, binary=None, ghidra_out=None):
    """Solve one challenge.

    Same optional overrides as ghidra(): solve-one.py passes the caller's binary and the
    directory it just decompiled into. One argv builder, not two -- a second one would be
    the place the flags drift apart.
    """
    solver = os.path.join(ROOT, "challenges", ch["dir"], "solve.py")
    if ch["build"] == "dotnet":
        argv = [sys.executable, solver,
                "--dll", binary or os.path.join(OUT, ch["name"], ch["dll"]),
                "--ilspy-out", ghidra_out or os.path.join(OUT, f"{ch['name']}-ilspy"),
                "--expect-password", ch["password"], "--expect-flag", ch["flag"]]
    else:
        argv = [sys.executable, solver,
                "--exe", binary or os.path.join(OUT, ch["exe"]),
                "--ghidra-out", ghidra_out or os.path.join(OUT, f"{ch['name']}-ghidra"),
                "--expect-password", ch["password"]]
        if ch["flag"]:
            argv += ["--expect-flag", ch["flag"]]
    return run(argv, timeout=600)


def ilspy():
    """Resolve ilspycmd. It is a standalone exe under
    Static-Reversing\\ilspycmd\\ -- NOT beside the ILSpy GUI (that directory has
    no ilspycmd at all) and NOT a PATH tool; `dotnet tool list -g` is empty.
    Probe the known path first, then the dotnet shim, so a future move of the
    tool degrades to a clear error rather than a silent skip."""
    p = os.path.join(STATION, "Static-Reversing", "ilspycmd", "ilspycmd.exe")
    if os.path.exists(p):
        return [p]
    for probe in (["ilspycmd", "--version"], ["dotnet", "ilspycmd", "--version"]):
        rc, _ = run(probe, timeout=180)
        if rc == 0:
            return probe
    return None


def solve_negative(ch):
    """Same solver, wrong expected answer. MUST fail. A check that cannot fail
    proves nothing, so this runs on every invocation and gates the result."""
    solver = os.path.join(ROOT, "challenges", ch["dir"], "solve.py")
    bad = "WRONG-ON-PURPOSE-0000"
    if ch["build"] == "dotnet":
        argv = [sys.executable, solver,
                "--dll", os.path.join(OUT, ch["name"], ch["dll"]),
                "--ilspy-out", os.path.join(OUT, f"{ch['name']}-ilspy"),
                "--expect-password", bad, "--expect-flag", bad]
    else:
        argv = [sys.executable, solver,
                "--exe", os.path.join(OUT, ch["exe"]),
                "--ghidra-out", os.path.join(OUT, f"{ch['name']}-ghidra"),
                "--expect-password", bad]
        if ch["flag"]:
            argv += ["--expect-flag", bad]
    rc, _ = run(argv, timeout=600)
    return rc != 0, f"exit {rc} (want non-zero)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--no-ghidra", action="store_true")
    ap.add_argument("--only", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.list:
        print(f"{'id':5} {'diff':4} {'technique':52} build/solve")
        for c in CORPUS:
            print(f"{c['id']:5} {c['difficulty']:<4} {c['technique'][:52]:52} {c['tools']}")
        return 0

    sel = [c for c in CORPUS if not a.only or c["id"] == a.only]
    if not sel:
        print(f"no challenge matches --only {a.only}", file=sys.stderr)
        return 2

    steps, t0 = [], time.time()
    for ch in sel:
        if not a.no_build:
            ok, d = build(ch)
            steps.append({"label": f"build {ch['id']}", "pass": ok, "detail": d})
            if not ok:
                continue
        if not a.no_ghidra:
            rc, out = ghidra(ch)
            steps.append({"label": f"decompile {ch['id']}", "pass": rc == 0, "detail": tail(out, 1)})
            if rc != 0:
                continue
        rc, out = solve(ch)
        steps.append({"label": f"solve {ch['id']}", "pass": rc == 0, "detail": tail(out, 1)})
        ok, d = solve_negative(ch)
        steps.append({"label": f"negative control {ch['id']}", "pass": ok, "detail": d})

    print()
    print("=" * 78)
    print("crackme-corpus")
    print("=" * 78)
    for s in steps:
        mark = "PASS" if s["pass"] else "FAIL"
        print(f"  {mark}  {s['label']:<34} {s['detail']}")

    failed = [s for s in steps if not s["pass"]]
    n_neg = len([s for s in steps if s["label"].startswith("negative")])
    print()
    if failed:
        print(f"NOT CLOSED: {len(failed)} of {len(steps)} checks failed.")
    else:
        print(f"CORPUS CLOSED: {len(sel)} challenge(s), {len(steps)} checks, "
              f"{n_neg} negative controls, {time.time() - t0:.1f}s")
        print("Every challenge solved from its binary, and every solver was shown to reject a wrong answer.")
    if a.json:
        print("JSON " + json.dumps({"challenges": len(sel), "checks": len(steps),
                                    "pass": len(steps) - len(failed), "fail": len(failed)}))

    # Result to disk as well as stdout. assert-probes says an entry with no `probe.produces`
    # was "matched STRINGS only, and a stub which prints them satisfies it" -- and this loop
    # builds its own binaries, so it is the one place where a stub is easiest to imagine.
    # Added 2026-10-05; see scripts/probe_artifact.py.
    sys.path.insert(0, os.path.join(ROOT, "..", "scripts"))
    from probe_artifact import write_artifact
    write_artifact("crackme_corpus", {
        "ok": not failed,
        "challenges": len(sel),
        "negative_controls": n_neg,
        "checks": [{"ok": s["pass"], "name": s["label"]} for s in steps],
    }, out_dir="crackme-corpus/out")

    return 0 if not failed else 9


if __name__ == "__main__":
    sys.exit(main())
