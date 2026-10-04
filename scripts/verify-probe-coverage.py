#!/usr/bin/env python
"""Grade every capability's recorded probe by what it actually ASSERTS about a run.

THE QUESTION. `scripts/assert-probes.py` re-runs each capability's probe and compares strings. Its
own OK verdict says, in its own words:

    NOT a claim that the instrument ran: this entry declares no probe.produces, so this checker
    matched STRINGS only, and a stub which prints them satisfies it.

So for how many capabilities is that verdict hollow? A probe that prints its expected string and
exits 0 satisfies every comparison a strings-only checker makes. This script counts how many
capabilities leave that door open, and ranks them worst-first.

WHAT THIS DOES AND DOES NOT DO. It reads `manifests/capabilities.json` and PRINTS. It runs no
probe, executes no lab loop, and writes nothing back to the registry. It exits 0 whatever it
finds, because this is a MEASUREMENT and a red build would be a claim it cannot support -- the
honest answer is very likely "most of them are C or B" and that is a fact about the registry, not
a fault in the registry's syntax. It exits non-zero only when it cannot read the registry at all.

THE FOUR GRADES, AS SPECIFIED.
    A  expects an exit code AND an output substring AND a produced artifact
    B  expects an exit code AND an output substring
    C  expects an output substring only
    D  expects neither -- the probe exists but asserts nothing about the run

The ladder is monotone in what a stub has to reproduce: A's verdict dies if the instrument writes
no bytes, B's dies if the exit code is wrong, C's dies if the string is absent, D's cannot die at
all because it checks nothing.

FIFTH LABEL, E, AND WHY IT HAD TO BE ADDED. The four grades above are not total over the eight
possible (exit, substring, artifact) combinations: an entry that declares `expect_exit` and
`produces` but NO `expect` falls through all four. The brief's own negative test produces exactly
that cell -- deleting `expect` from an A-grade entry. Folding it into D would say such an entry
"expects neither", which is false: it expects an exit code. Folding it into C would say it expects
a substring, which is also false. So it is labelled E, counted separately, never silently merged,
and ranked next to C rather than next to D. A reader who disagrees can merge E into D by editing
one table in this file.

WHAT "evidence-bound" MEANS. The derivation doc-facts.py already owns: a capability is bound when
its probe names BOTH a `run_log` file and a `sha256` for it. Re-using that definition instead of
inventing a second one is the point -- counting `evidence_binding.status == "unverified"` instead
returns 3 rather than 2-of-23, because the status key also sits on a `planned` entry. This file
reuses the first derivation and says so in the output.

    python scripts/verify-probe-coverage.py
    python scripts/verify-probe-coverage.py --registry %TEMP%/copy.json    # for mutation tests
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# ----------------------------------------------------------------------- grade definitions
# Printed verbatim by main(). A grader that will not show its work is a grader nobody can argue
# with, and the whole purpose of this file is to be disagreed with.
GRADE_TEXT = """\
RANKING CRITERION -- weakest first. A weakness score, higher = worse, summed from named parts:

    base      D 400 | E 350 | C 300 | B 200 | A 100    (worst first)
              (E sits between C and D: it declares no output substring, which is the property
               this whole audit is about, but it does declare an exit code and/or an artifact,
               so it is closer to C than to D. Change the 350 if you disagree.)
    + 100     the harness NEVER EXECUTES this probe: it is in assert-probes.py's SKIP set, or
              its probe.command is empty or prose, so none of its recorded strings are compared
              by anything, ever
    +  50     no EXECUTABLE negative_control.command -- the control is a declared PLAN
    +  20     not evidence-bound (no run_log + sha256 pair, so `observed` rests on a summary line)
    +  10     state is not `observed`

Ties break on id, so the order is deterministic. Every part is printed in the ranked list, so any
single line of this rule can be checked against one capability."""

GRADES = {
    "A": "expects an exit code AND an output substring AND a produced artifact",
    "B": "expects an exit code AND an output substring",
    "C": "expects an output substring only",
    "D": "expects neither -- the probe exists but asserts nothing about the run",
    "E": "OUTSIDE the four-grade ladder: declares no output substring, but declares an exit code "
         "and/or an artifact. Reached by the brief's own negative test (delete `expect` from an "
         "A-grade entry). Counted and ranked separately rather than mislabelled C or D.",
}

BASE = {"A": 100, "B": 200, "E": 350, "C": 300, "D": 400}


# ------------------------------------------------------------------ the harness's own SKIP set
# Imported rather than retyped, because this file's #1 weakness signal is "the harness never runs
# this probe", and a second hand-typed copy of that list would drift from the first within a week
# and then be wrong in the exact direction that makes a table look better than the station is.
# Degrades to a prose-only test if assert-probes.py is unreadable, and says so in the output
# rather than quietly reporting a narrower definition.
HARNESS_SRC = REPO / "scripts" / "assert-probes.py"


def load_assert_probes():
    path = HARNESS_SRC
    if not path.is_file():
        return None, f"{path} not found"
    spec = importlib.util.spec_from_file_location("assert_probes_probe_coverage", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:                      # a broken sibling is reported, not raised
        return None, f"{type(exc).__name__}: {exc}"
    if not hasattr(mod, "SKIP") or not hasattr(mod, "prose"):
        return None, "loaded but exposes neither SKIP nor prose()"
    return mod, None


def truthy_declared(value) -> bool:
    """A key is DECLARED when it holds something a checker could act on."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple)):
        return any(str(v).strip() for v in value)
    return True


def grade_of(exit_declared: bool, expect_declared: bool, produces_declared: bool) -> str:
    if exit_declared and expect_declared and produces_declared:
        return "A"
    if exit_declared and expect_declared:
        return "B"
    if expect_declared:
        return "C"
    if exit_declared or produces_declared:
        return "E"
    return "D"


def measure(caps: list, harness) -> list[dict]:
    rows = []
    for cap in caps:
        cid = str(cap.get("id") or "<no id>")
        probe = cap.get("probe") or {}
        nc = cap.get("negative_control") or {}

        cmd = str(probe.get("command") or "").strip()
        prose = (not cmd)
        if not prose and harness is not None:
            try:
                prose = bool(harness.prose(cmd))
            except Exception:
                prose = False
        skipped = harness is not None and cid in getattr(harness, "SKIP", {})
        never_runs = bool(skipped or prose)

        exit_d = truthy_declared(probe.get("expect_exit")) or "expect_exit" in probe
        expect_d = truthy_declared(probe.get("expect"))
        produces_d = truthy_declared(probe.get("produces"))
        prepare_d = truthy_declared(probe.get("prepare"))

        nc_cmd = str(nc.get("command") or "").strip()
        nc_prose = (not nc_cmd)
        if not nc_prose and harness is not None:
            try:
                nc_prose = bool(harness.prose(nc_cmd))
            except Exception:
                nc_prose = False
        nc_declared = bool(cap.get("negative_control"))
        nc_executable = nc_declared and bool(nc_cmd) and not nc_prose

        run_log = str(probe.get("run_log") or "").strip()
        sha256 = str(probe.get("sha256") or "").strip()
        bound = bool(run_log and sha256)

        g = grade_of(exit_d, expect_d, produces_d)
        state = str(cap.get("state") or "-")

        weak = BASE[g]
        why = [f"grade {g}"]
        if never_runs:
            weak += 100
            cause = harness.SKIP.get(cid) if skipped else f"probe.command is {cmd[:24]!r}"
            why.append(f"harness never executes it ({cause}), so none of its recorded strings "
                       f"are compared by anything")
        else:
            why.append("the harness does execute it")
        if not nc_executable:
            weak += 50
            why.append("its negative control declares no runnable command (a plan)" if nc_declared
                       else "it declares no negative control at all")
        else:
            why.append("its negative control is a runnable command")
        if not bound:
            weak += 20
            why.append("not evidence-bound (no run_log + sha256 pair), so `observed` rests on a "
                       "summary line rather than a retained artifact")
        else:
            why.append("evidence-bound (run_log + sha256)")
        if state != "observed":
            weak += 10
            why.append(f"state is {state!r}, not 'observed'")
        else:
            why.append("state is 'observed'")

        rows.append({
            "id": cid, "state": state, "grade": g, "weak": weak,
            "expect": expect_d, "exit": exit_d, "produces": produces_d, "prepare": prepare_d,
            "nc": nc_declared, "nc_executable": nc_executable, "bound": bound,
            "run_log": run_log, "sha256": sha256,
            "produces_value": probe.get("produces"),
            "expect_value": probe.get("expect"),
            "never_runs": never_runs,
            "why": "; ".join(why),
        })
    return rows


def yn(b) -> str:
    return "yes" if b else " - "


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--registry", default=None, metavar="PATH",
                    help="read a COPY of the registry instead of manifests/capabilities.json "
                         "(for mutation tests; this script never writes to either)")
    args = ap.parse_args()
    reg = Path(args.registry) if args.registry else REG
    if not reg.is_absolute():
        reg = (Path.cwd() / reg)
    reg = reg.resolve()

    try:
        data = json.load(open(reg, encoding="utf-8"))
    except FileNotFoundError:
        print(f"probe-coverage: registry not found: {reg}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"probe-coverage: registry is not valid JSON: {reg} :: {exc}", file=sys.stderr)
        return 2

    caps = data.get("capabilities")
    if not isinstance(caps, list) or not caps:
        print(f"probe-coverage: {reg} has no capabilities[] list", file=sys.stderr)
        return 2

    harness, harness_err = load_assert_probes()

    print("=" * 100)
    print("PROBE COVERAGE -- what each capability's recorded probe actually ASSERTS about a run")
    print("=" * 100)
    print(f"registry : {reg}")
    print(f"entries  : {len(caps)}")
    # STATED AT THE TOP, not only at the bottom. This script exits 0 whatever the counts are, by
    # design: a D grade is a fact about what the registry declares, not a build failure. It ran
    # inside verify-all.ps1 for a long time with that fact printed only in the final paragraph,
    # which means a reader skimming twenty cyan `=== <name>` headers saw one more gate-shaped
    # line among them that could never go red. The step is already named "(report)"; this makes
    # the distinction survive being skimmed rather than only being read.
    print("THIS IS A REPORT, NOT A GATE. It exits 0 whatever the counts are. A grade is a fact "
          "about")
    print("what the registry DECLARES, not a build failure -- read it, do not gate on it.")
    print()
    if harness is None:
        print(f"harness  : assert-probes.py SKIP set UNAVAILABLE ({harness_err}); the 'never "
              f"executes' signal below is measured from probe.command only, which is a NARROWER "
              f"definition than the one printed in the ranking criterion")
    else:
        print(f"harness  : assert-probes.py SKIP set imported from {HARNESS_SRC} "
              f"({len(getattr(harness, 'SKIP', {}))} ids the checker never executes)")
    print()
    print(GRADE_TEXT)
    print()
    print("GRADE DEFINITIONS")
    for k in "ABCDE":
        print(f"  {k}  {GRADES[k]}")
    print()

    rows = measure(caps, harness)

    head = (f"{'id':<34} {'state':<9} {'expect':<7} {'exit':<6} {'produces':<9} {'prepare':<8} "
            f"{'negctrl':<8} {'evidence-bound':<15} grade")
    print(head)
    print("-" * len(head))
    for r in sorted(rows, key=lambda r: (-r["weak"], r["id"])):
        nc_txt = "yes" if r["nc_executable"] else ("plan" if r["nc"] else " - ")
        bound_txt = "yes (log+sha)" if r["bound"] else (
            "log only" if r["run_log"] else ("sha only" if r["sha256"] else "no"))
        print(f"{r['id']:<34} {r['state']:<9} {yn(r['expect']):<7} {yn(r['exit']):<6} "
              f"{yn(r['produces']):<9} {yn(r['prepare']):<8} {nc_txt:<8} {bound_txt:<15} "
              f"{r['grade']}")

    counts = {g: 0 for g in "ABCDE"}
    for r in rows:
        counts[r["grade"]] += 1
    print()
    print("COUNTS PER GRADE")
    for g in "ABCDE":
        print(f"  {g}  {counts[g]:>2}   {GRADES[g]}")
    print(f"  --  {len(rows):>2}   total")

    # The headline the brief actually asked for: how many entries get the strings-only verdict.
    hollow = [r for r in rows if not r["produces"]]
    print()
    print(f"HOLLOW VERDICTS: {len(hollow)} of {len(rows)} entries declare no probe.produces, so "
          f"assert-probes.py's OK text for them")
    print("  is the STRINGS-ONLY one -- satisfied by any process that prints the recorded string "
          "and exits")
    print(f"  {counts['A']}. A further {len([r for r in rows if r['never_runs']])} of those are "
          f"never executed by the harness at all, so for those the strings are not even "
          f"compared; their verdict rests on a hand-written summary line alone.")
    print(f"  {counts['D']} entries are grade D (the probe asserts nothing at all).")

    print()
    print("RANKED, WEAKEST FIRST (see the criterion printed above; every term is shown per row)")
    for i, r in enumerate(sorted(rows, key=lambda r: (-r["weak"], r["id"])), 1):
        print(f"  {i:>2}. [{r['weak']:>3}] {r['id']}")
        print(f"        {r['why']}")
        if r["produces"]:
            print(f"        probe.produces = {r['produces_value']!r}")
        if r["expect"]:
            print(f"        probe.expect    = {str(r['expect_value'])[:90]!r}")

    print()
    print("This is a measurement. Exit 0 is reported whatever the counts are; a D is a fact about "
          "what the")
    print("registry declares, not a build failure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
