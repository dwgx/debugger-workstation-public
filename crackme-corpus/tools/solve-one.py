#!/usr/bin/env python3
"""solve-one.py -- ONE self-built corpus binary in, the recovered answer out, as JSON.

WHY THIS EXISTS. `re.corpus.solve` consumes a `binary` path_ref and produces
`re.solve.answer`, but its only entry point was crackme-corpus/tools/loop.py, whose usage is
`--no-build | --only c03 | --list`: `--only` selects a CHALLENGE ID from the corpus ramp, not
a path a caller supplies. The entry's own not_callable.reason said exactly that, and it was
right: the loop builds its own binaries and never accepts one.

So this is the argv that consumes a caller's binary. It is a DISPATCHER, not a sixth solver:
it resolves which corpus challenge the binary belongs to, decompiles it with the SAME
`ghidra()` helper the loop uses, and runs the SAME per-challenge `solve.py` through the SAME
`solve()` argv builder (both now take an optional path override for exactly this caller).
Nothing about how a challenge is solved is re-implemented here.

WHY DISPATCH BY NAME, AND WHAT IT DOES NOT PROVE. The corpus answer key is keyed by challenge
id, and the only signal a bare path carries is its file name. A renamed copy of c01 is
therefore refused rather than guessed at, and a binary that is NOT from this corpus cannot be
solved by it at all -- these solvers read a specific obfuscation, and the entry's
does_not_prove already says a technique label does not transfer to a binary we did not build.
The judge is still the binary itself: the recovered password is fed back to the sample and it
must answer ACCEPTED, which is why exit 0 is not taken as the verdict on its own.

  python crackme-corpus/tools/solve-one.py --exe crackme-corpus/out/c01-stringobf.exe
  python crackme-corpus/tools/solve-one.py --exe <path> --keep-scratch

STDOUT IS ONE JSON OBJECT. mission.ps1 merges stdout and stderr before parsing, so the
progress narration of the underlying tools goes to stderr.

Exit: 0 solved and accepted by the binary, 1 refused (unknown sample / bad argv),
      2 could not run (decompile failed), 4 the solver ran but did not accept an answer.
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import loop as corpus  # noqa: E402  -- the corpus table and the two argv builders


def norm(name):
    """Hyphens and underscores name the same sample in this tree.

    MEASURED TRAP, and the corpus records it: tools/loop.py's c01 row says
    'c01_string_obf.exe' (underscores) while tools/build-c.ps1 writes '<id>.exe' with the id
    'c01-stringobf' (hyphens). Both files exist in out/ and only the hyphen one is built.
    Normalising means a caller who hands over the stale underscore file still resolves to the
    right challenge, and the decompile step then fails on its own merits if the bytes differ.
    """
    return name.lower().replace("_", "-")


def find_challenge(path, forced_id=None):
    base = norm(os.path.basename(path))
    for ch in corpus.CORPUS:
        if forced_id and ch["id"] != forced_id:
            continue
        for key in ("exe", "dll", "name"):
            if ch.get(key) and norm(ch[key]) == base:
                return ch
    return None


def parse_answer(text):
    """The solvers print `PASS <id> password='...' flag='...'` (c05 has no flag)."""
    pw = re.search(r"password=('([^']*)'|\"([^\"]*)\")", text)
    fl = re.search(r"flag=('([^']*)'|\"([^\"]*)\")", text)
    return (
        (pw.group(2) if pw and pw.group(2) is not None else (pw.group(3) if pw else None)),
        (fl.group(2) if fl and fl.group(2) is not None else (fl.group(3) if fl else None)),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, help="the binary to solve (a corpus sample)")
    ap.add_argument("--id", default=None, help="force a challenge id instead of dispatching by name")
    ap.add_argument("--ghidra-out", default=None, help="where to put the decompilation")
    ap.add_argument("--keep-scratch", action="store_true", help="do not delete the scratch dir")
    a = ap.parse_args()

    binary = os.path.abspath(a.exe)
    if not os.path.isfile(binary):
        return emit({"ok": False, "exit": 1, "error": "no such file: %s" % binary}, 1)

    ch = find_challenge(binary, a.id)
    if ch is None:
        return emit({
            "ok": False, "exit": 1,
            "error": "no corpus challenge matches %r" % os.path.basename(binary),
            "note": "Dispatch is by file name because that is the only signal a bare path "
                    "carries. Pass --id to force one of the ids below, or use a solver "
                    "directly if the sample is not from this corpus.",
            "known_ids": [c["id"] for c in corpus.CORPUS],
        }, 1)

    scratch = tempfile.mkdtemp(prefix="solve-one-%s-" % ch["id"])
    outdir = os.path.abspath(a.ghidra_out) if a.ghidra_out else os.path.join(
        scratch, ch["name"] + ("-ilspy" if ch["build"] == "dotnet" else "-ghidra"))
    os.makedirs(outdir, exist_ok=True)

    try:
        print("[decompile] %s -> %s" % (binary, outdir), file=sys.stderr)
        rc, out = corpus.ghidra(ch, binary=binary, outdir=outdir)
        if rc != 0:
            return emit({
                "ok": False, "exit": 2, "stage": "decompile", "id": ch["id"],
                "error": "decompiler exited %d" % rc,
                "detail": out.strip().splitlines()[-3:] if out.strip() else [],
            }, 2)

        print("[solve] challenges/%s/solve.py" % ch["dir"], file=sys.stderr)
        rc, out = corpus.solve(ch, binary=binary, ghidra_out=outdir)
        password, flag = parse_answer(out)
        accepted = rc == 0
        return emit({
            "ok": accepted,
            "exit": 0 if accepted else 4,
            "id": ch["id"],
            "technique": ch["technique"],
            "answer": password,
            "password": password,
            "flag": flag,
            "sample": binary,
            "decompiled_into": outdir,
            "solver_exit": rc,
            "verdict": "SOLVED-AND-ACCEPTED-BY-THE-BINARY" if accepted
                       else "NOT-ACCEPTED (the sample itself rejected the recovered answer)",
            "detail": [l for l in out.strip().splitlines() if l.strip()][-4:],
            "caveat": "A recovered answer means THIS sample accepted it. It does not mean the "
                      "technique transfers to a binary this corpus did not build.",
        }, 0 if accepted else 4)
    finally:
        if not a.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def emit(obj, code):
    sys.stdout.write(json.dumps(obj) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
