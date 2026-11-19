OWNER: Round2Entry (entry slice, 2026-11-12) | package/references/VERIFY.md
# VERIFY — the acceptance checks for this skill package

## What runs
`tests/package_contract.py` is the **single production validator**. `verify.py`,
`scripts/verify.py`, `tests/verify.py` and `tests/entry_checks.py` all call its
`validate()`; there is no second checker that can drift green. Both resolve the
package root from `__file__`, so the working directory does not matter.

`tests/verify.py` prints the 9 named honesty checks from 2026-11-11 and also gates
on the validator's structured failures, so a missing file can never hide behind a
green count. `tests/entry_checks.py` is the install contract: it runs every case on
a TEMP COPY of the package (the source is never modified).

## Required closure (structured, not traceback)
`REQUIRED_FILES` lists 19 files: `SKILL.md`, `AGENTS.md`, `SELF-DEPLOY.md`,
`SELF-REPAIR.md`, `LICENSE`, both READMEs, `verify.py`, `scripts/verify.py`, the
three `tests/*.py` validators, `references/{INSTALL,VERIFY,FIX-KB,PRIOR-WAVE}.md`,
`references/frozen/legacy-verify-2026-11-11.py.txt`, and both `FIX-KB/*.tsv`.
A missing or empty item prints `MISSING_REQUIRED=<path>` / `EMPTY_REQUIRED=<path>`
and exits 1 — a diagnosis, never a `FileNotFoundError` traceback.

## Install-contract cases (9)
1. `references/INSTALL.md` deleted → gate FAIL with `MISSING_REQUIRED=references/INSTALL.md`.
   The frozen 2026-11-11 verifier still exits 0 on the same copy: that is the dated
   proof of the old omission, kept as evidence — the live gate is not required to
   keep the bug.
2. install dir name ≠ frontmatter `name` → FAIL (`NAME_DIR_MISMATCH`).
3. a live absolute research path (`F:/GENESIS-ARCHIVE/...` — archived provenance,
   NOT a live command) inside an executable command → FAIL (`LIVE_ABS_PATH`).
4. the old publish SHA (`875cd108…` — archived provenance, NOT a live command)
   inside an executable command → FAIL (`OLD_SHA`).
5. `LICENSE` deleted → FAIL with `MISSING_REQUIRED=LICENSE` (both gates; the frozen
   legacy verifier passes, which is the old fake green).
6. a legal 14th FIX-KB row → PASS (row structure + unique id + minimums, no fixed total).
7. the same TSV content as LF instead of CRLF → PASS (EOL is text-equivalent).
8. the legacy fix re-applied (add `references/INSTALL.md` to the required set) → PASS.
9. a clean package → PASS.

## Command (from the clone root)
`repo_root` = the directory holding `skills/`.
```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
python -X utf8 skills/2026-11-11/portable-core/tests/entry_checks.py
```

## Measured output of `verify.py` (as_of 2026-11-12, 9 checks + 1 negative control)
```
as_of=2026-11-12 (denominator 9 checks + 1 negative control)
schema_files=19/19 missing=0 empty=0
fix_kb_rows official=8/6 community=5/4 total=13
fix_kb_eol official=CRLF community=CRLF duplicate_ids=0
all_fixes_have_verify=YES=True missing=0
red_gate_caveat=True vrc_ban=True no_credentials=True switcher=True owner=True
negative_control: FIX-KB row with empty verify_command -> checker_RED=YES legal_row_accepted=YES | NO_FILE_WRITTEN
checks_run=9 checks_failed=0 structured_failures=0
VERDICT=PASS
```
Exit code 0. `official=8/6` and `community=5/4` are row counts against minimums 6
and 4 — never against a fixed total. `tests/entry_checks.py` prints its own
denominator (7 package assertions + 9 cases + 1 negative control) and
`VERDICT=PASS`.

## EOL rule
Text files (`*.md`, `*.tsv`, `*.py`) are newline-normalised before comparison, so
an LF checkout and a CRLF checkout of the same content verify identically.
Evidence logs are the exception: they are stored and hashed as their true bytes.

## How to read RED
`VERDICT=FAIL` plus `failed=<names>` (and `failure=<CODE>` lines) names the broken
check, exit code 1. A RED is never fixed by editing the checker: fix the artifact or
record it as a blocker. The negative control must stay RED-capable — it feeds a bad
row through the production row validator, so a dead validator shows up as `NO`.

## Honesty
A PASS means "the package is internally consistent and installable under its
canonical name", NOT "all capabilities work". `RELEASE_GATE=RED`,
`COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers and the strict `0/27` in-package
receipt count stand after a PASS.
