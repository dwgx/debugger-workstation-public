OWNER: researcher-q6 | setukou-20261111/v5/slices/q6-audit/

# Q6 — independent multi-subagent audit of the 4 ACCEPTED slices (Q1/Q3/Q4/Q5)

`as_of 2026-11-11`. Q6 is a DIFFERENT actor re-running EACH accepted slice's ONE
`## Verify` from W and re-deriving every number from disk (no prose trust).
**Answer: no fake PASS / no duplicate counting / no denominator drift; ONE real
finding = Q3's `## Verify` regressed to `exit 1 VERDICT=FAIL` after the parent's
Q5 metric merge (contradiction X-001, reopened by parent). Q2 is NOT delivered —
explicit GAP, never audited.** `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`.

## Method (independent, bounded, read-only)
- `rerun_driver.py` re-ran the EXACT `## Verify` command of Q1/Q3/Q4/Q5 from W
  under a bounded 90s envelope, capturing stdout/stderr/exit/UTC into
  `receipts/<slice>-rerun.txt`. (v1 used `cmd /c` and produced a FALSE exit=0
  banner — caught and FIXED in v2 by executing argv directly; no slice was
  misjudged.)
- `measure.py` re-derived from disk: `SATURATION.tsv` status split, `results.tsv`,
  each `PROMOTIONS.tsv`, all Q5 receipts, research/Q<N> contracts, G-004 126.
- `AUDIT.tsv` = 40 rows (4 slices x A1–A10) + 3 explicit Q2 GAP rows.

## Measured (from the ONE ## Verify below, exit 0)
`slices_audited=4 checks_run=40 checks_failed=1 false_passes=0 denominator_drift=0
duplicate_claims=0 q2_gap_recorded=YES product_tree_writes=0 claims_total_frozen_ok=YES
VERDICT=GREEN`.

Denominator frozen: `claims_total=295 | real_verified=21 declared_unverified=108
owner_gated=151 missing=15 blockers=274`; `results_rows=2 metrics=[9,21]`
(baseline 9 + keep 21, both `claims_total=295`); `g004_unassigned=126`
(`TR:X36 TR:N32 TR:MB24 TR:MC21 TR:L11 TR:K2`) untouched.
`promotions: q3=0 q4=0 q5=12 all_SM=True q5_receipts_resolve=12/12`.
Re-run exits: `Q1=0 Q3=1 Q4=0 Q5=0`.

## Findings
- **X-001 (Q3 A3, FAIL / reopened)**: `q3-missing/verify.py:174` hard-codes
  `declared_rows == 120`; parent merged Q5's 12 `SM:*` promotions
  (`DECLARED_UNVERIFIED 120→108`), so the assertion now fails (`VERDICT=FAIL`,
  exit 1). Parent (Main IRC) CONFIRMED + recorded X-001 + reopened researcher-q3.
  This is a stale 口径 / post-merge regression, NOT a fake capability PASS. Q6 does
  NOT edit Q3's files, does NOT claim Q3 passed, does NOT wait for the fix.
- **Q1 A3 prose drift (not a failure)**: Q1 checker re-derives `21/274/108`
  (post-merge) but `COMPLETENESS.md` prose still says `9/286/120` (pre-merge);
  verdict `NOT_COMPLETE` unchanged. Recorded under A3 evidence.
- **No fake PASS anywhere**: no `--help`-as-pass; Q4 explicitly labels
  `20 backends wired` = config consistency NOT 20 usable backends; Q3/Q4
  `promotions=0` honest; Q5's 12 promotions each have a REAL receipt with
  exit+UTC+STDOUT + an in-memory tamper RED falsifier; Q1 NOT_COMPLETE.
- **No duplicate counting**: 12 Q5 promotion `claim_id`s all `SM:*` (owned
  prefix), 12 unique, `duplicate_claims=0`; `QA:G25` / `W3:CARD-01` already REAL
  were excluded to avoid double count; no claim simultaneously MISSING+REAL.
- **Q2 GAP**: `v5/slices/q2-scripts/` holds ONLY 2 SYNTHETIC fixtures +
  `syn-wiki/`; NO `verify.py`/`PROMOTIONS.tsv`/`REPORT.md`/receipts. Per the
  auto-deepresearch resume rule Q6 audits ONLY the 4 accepted slices and records
  Q2 non-delivery as an explicit GAP row (Q2 A3 = gap: re-run IMPOSSIBLE, not a
  fail). Q6 does NOT audit Q2's fixtures, does NOT write Q2 files.

## Boundaries
Read-only on product trees and on all other slices' files. Q6 writes ONLY
`v5/slices/q6-audit/` + `research/Q6/`. No `SATURATION.tsv`/`results.tsv` edit,
no Q2 files, no push, no repo action, no credential VALUE, no token output,
no online/third-party/HMC/untrusted-binary exec. `claims_total=295` frozen.

## Verify

ONE copy-pasteable W-relative command, run from W (no `W/` literal inside),
READ-ONLY, re-derives every printed number from disk, prints measured values +
`as_of` + denominator, and has an IN-MEMORY negative control (inject a fake
`PROMOTIONS` row with NO receipt into an in-memory copy; the checker MUST return
`VERDICT=FAIL`; NO file is written):

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
"C:/Program Files/Git/usr/bin/timeout.exe" 90 python -X utf8 -B setukou-20261111/v5/slices/q6-audit/verify.py
```

Observed run (2026-11-11, from W, exit 0): `slices_audited=4 checks_run=40
checks_failed=1 false_passes=0 denominator_drift=0 duplicate_claims=0
q2_gap_recorded=YES product_tree_writes=0 claims_total_frozen_ok=YES
rerun_receipts_ok=True exits={'Q1': '0', 'Q3': '1', 'Q4': '0', 'Q5': '0'}
research_contract_ok=True negative_control ... checker_verdict=FAIL valid=12/13
caught=YES | clean_path=GREEN | NO_FILE_WRITTEN VERDICT=GREEN`.
