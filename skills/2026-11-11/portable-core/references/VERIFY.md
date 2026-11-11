OWNER: SpecOptimizer | package/references/VERIFY.md
# VERIFY — the ONE acceptance check for this skill package

## What runs
`package/verify.py` is a thin wrapper; the real checks live in `package/tests/verify.py`
(READ-ONLY, stdlib only). Both resolve the workspace root from `__file__`, so the
working directory does not matter. `package/scripts/verify.py` is the same entry for
harnesses that only load `scripts/`.

## Command (from the workspace root)
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111" && python -X utf8 package/verify.py
```

## Measured output (as_of 2026-11-11, denominator 9 checks + 1 negative control)
```
as_of=2026-11-11 (denominator 9 checks + 1 negative control)
schema_files=10/10
fix_kb_rows official=8/6 community=5/4 total=13
all_fixes_have_verify=YES=True missing=0
red_gate_caveat=True vrc_ban=True no_credentials=True switcher=True owner=True
negative_control: FIX-KB row with empty verify_command -> checker_RED=YES | NO_FILE_WRITTEN
checks_run=9 checks_failed=0
VERDICT=PASS
```
Exit code 0. `schema_files` counts the 10 payload files the package promises; the
`official=8/6` and `community=5/4` lines are row counts against minimums 6 and 4.

## How to read RED
`VERDICT=FAIL` plus `failed=<names>` names the broken check, exit code 1. A RED is
never fixed by editing the checker: fix the artifact or record it as a blocker.
The negative control must stay RED-capable — if it prints `NO`, the checker is dead.

## Honesty
A PASS means "the package is internally consistent", NOT "all capabilities work".
`RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers and the strict
`0/27` in-package receipt count stand after a PASS.
