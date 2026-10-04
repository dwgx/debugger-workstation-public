#!/usr/bin/env python
"""Run a command, capture what it actually did, and write the record to disk.

WHY THIS EXISTS. Several registry entries declare a probe that is a bare invocation of an
external tool -- `frida -f ...`, `skillspector scan ...` -- rather than a script in this tree.
Those entries had no way to leave an artifact, so `assert-probes.py` verified them by matching
substrings in captured stdout and said so on every OK: *"NOT a claim that the instrument ran: a
stub which prints them satisfies it."*

The alternative was to rewrite each command as a purpose-built script. That is the wrong trade
for four entries: the command IS the thing under test, and wrapping it in a script that exists
only to wrap it adds a second thing that can be wrong.

So this wrapper is deliberately generic. It does not know what frida or skillspector are. It
records the command line, the exit code, the stdout, the stderr and the duration, and it does
that on EVERY exit path including a crash.

WHAT IT DELIBERATELY DOES NOT DO:

* It does not judge the output. A wrapper that decided whether a run succeeded would be a second
  verdict beside `assert-probes.py`'s, and two verdicts drift.
* It does not retry, normalise, or repair. It records.
* It does not swallow a failure. The child's exit code becomes this process's exit code, so
  adding the wrapper cannot turn a red into a green.

USAGE

    python scripts/probe_wrapper.py --tool dynamic.win.frida \\
        --out-dir dynamic-lab/out \\
        -- powershell -File scripts/frida-probe.ps1 ...

Everything after `--` is the command. Quoting is the caller's problem in exactly the way it is
for any other registry command.
"""

from __future__ import annotations

import argparse
import pathlib
import shlex
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from probe_artifact import write_artifact  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tool", required=True,
                    help="stable name; becomes the artifact filename")
    ap.add_argument("--out-dir", default="probe-artifacts",
                    help="repo-relative output directory (default: probe-artifacts)")
    ap.add_argument("--expect-exit", type=int, default=None,
                    help="documented expectation, recorded but NOT enforced here. Enforcing it "
                         "would make this a second verdict, and two verdicts drift.")
    ap.add_argument("--note", default=None, help="free text recorded in the artifact")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="the command to run, after a literal --")
    args = ap.parse_args()

    cmd = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not cmd:
        print("probe_wrapper: no command given. Usage: probe_wrapper.py --tool T --out-dir D -- CMD ...",
              file=sys.stderr)
        return 2

    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800,
                              cwd=str(REPO_ROOT))
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
        error = None
    except subprocess.TimeoutExpired as exc:
        rc, out, err = None, exc.stdout or "", exc.stderr or ""
        error = f"timeout after {exc.timeout}s -- the command was killed and this is a partial "
        error += "record, not a result"
    except FileNotFoundError as exc:
        rc, out, err, error = None, "", "", f"command not found: {exc}"

    elapsed = round(time.time() - started, 2)

    write_artifact(args.tool, {
        "ok": error is None and rc == 0,
        "wrapper": "scripts/probe_wrapper.py",
        "command": cmd if isinstance(cmd, list) else shlex.split(str(cmd)),
        "exit": rc,
        "duration_s": elapsed,
        "expect_exit_documented": args.expect_exit,
        "expect_exit_enforced_here": False,
        "note": args.note,
        "error": error,
        "stdout": out,
        "stderr": err,
        "caveat": (
            "THIS RECORDS A COMMAND'S BEHAVIOUR; IT DOES NOT JUDGE IT. `ok` means the process "
            "exited 0, nothing more. Whether the output is CORRECT is assert-probes.py's "
            "question, and duplicating that judgement here is how two verdicts start to drift. "
            "The full stdout and stderr are kept rather than a summary, because a summary is "
            "where a confident wrong answer hides."),
    }, out_dir=args.out_dir)

    # PASS THE CHILD'S OUTPUT THROUGH. Measured 2026-10-05: the first version captured stdout
    # and stderr into the artifact and printed neither, so the harness saw only the wrapper's own
    # ARTIFACT line and every recorded `expect` string went to DRIFT -- three entries reporting
    # a probe regression that had not happened. A wrapper that swallows the output it wraps is
    # worse than no wrapper: it presents as an instrument failure and it is the wrapper's.
    #
    # Written to OUR streams rather than re-raised from the captured strings, so the bytes a
    # caller sees are the bytes the child emitted. assert-probes merges stderr into stdout on
    # purpose (see its run()), which is why both are replayed verbatim.
    if out:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    if err:
        sys.stderr.write(err)
        if not err.endswith("\n"):
            sys.stderr.write("\n")
    sys.stdout.flush()
    sys.stderr.flush()

    # The child's exit code becomes ours, so adding this wrapper cannot turn a red into a green.
    return rc if isinstance(rc, int) else 1


if __name__ == "__main__":
    sys.exit(main())