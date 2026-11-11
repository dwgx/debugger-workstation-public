OWNER: researcher-q1 | setukou-20261111/v5/slices/q1-completeness/

# Q1 — is 「现在是不是全部都好了」 decidable from one re-runnable command?

`as_of 2026-11-11`. This slice answers Q1: merge the 295 claims, 28-row gap
matrix, v1–v4 sealed counts, corpus absorption rate and `RELEASE_GATE=RED`
into ONE copy-pasteable, disk-recomputed judgment. The honest answer is **NO**.

## What the checker does

`verify.py` is READ-ONLY. It recomputes every number from the bytes on disk
(no hard-coded counts) and prints each with `as_of` + denominator:

| number | source (disk) | current value |
|---|---|---|
| `claims_total` | `v5/SATURATION.tsv` data rows | 295 (frozen; cross-checked vs `v4/real-verify/REAL-VERIFY.tsv`) |
| `real_verified` | status `RUNNABLE_REAL_VERIFIED` | 9 |
| `blockers` | status `!= RUNNABLE_REAL_VERIFIED` | 286 (120 DECLARED_UNVERIFIED + 15 MISSING + 151 OWNER_GATED) |
| `RELEASE_GATE` | GREEN iff every claim REAL-verified | RED |
| `gap_rows / gap_yes / gap_no` | `v3/history-gap/GAP-MATRIX.tsv` | 28 / 8 / 20 |
| `absorved_rows / absorbed_yes / absorbed_no` | `v4/corpus-absorb/CORPUS-INDEX.tsv` | 320 / 7 / 313 |
| `v2_v3_v4_accepted_rows` | `ACCEPTED` cells in 3 ledgers | 16 (v2 5/5, v3 5/5, v4 6/6) |
| `external_actions_total/executed/unexecuted` | 36 `OWNER DECISION REQUIRED` markers | 36 / 0 / 36 |
| `push_executed` | 4 decision/state surfaces | NO |
| `live_porcelain_11_2_ok` | `git status --porcelain` (read-only) | True (11 / 2) |

The single completeness rule:

```
COMPLETE iff real_verified == claims_total AND blockers == 0
          AND gap_no == 0 AND absorbed_no == 0 AND RELEASE_GATE == GREEN
```

Everything else → `COMPLETENESS_VERDICT=NOT_COMPLETE`.

## Negative control (gate can go RED)

The checker injects a fake `real_verified=295` / `blockers=0` and STILL prints
`NOT_COMPLETE`, because `gap_no=20`, `absorbed_no=313` and `RELEASE_GATE=RED`
disagree. This proves a single inflated metric cannot flip the verdict — the
exact防-gaming property the autoresearch guard metric demands. A synthetic
all-green candidate is also exercised (`green_capable=True`), so both the RED
and GREEN paths run. `CHECKER_SELFTEST=OK` only if both controls hold.

## Why the sealed 6/6 ≠ global completion

v2 5/5, v3 5/5, v4 6/6 are **wave acceptances** (`completed != accepted`
resolved by parent re-running each `## Verify`). They certify the staged
artifacts are internally consistent, NOT that all 295 capabilities are
REAL-verified. `v4/ACCEPTANCE-V4.md:18` itself records the decisive
`RELEASE_GATE=RED`. `20 backends wired` is one config-consistency gate, not
20 installed/connectable backends (`v4/real-verify/VERIFY-REPORT.md:26`).

## Falsifier (what would make it YES)

Only this command's own output changing to `COMPLETENESS_VERDICT=COMPLETE`
— which requires ALL of: every one of the 295 claims carries a REAL receipt
(`RUNNABLE_REAL_VERIFIED`), all 28 gap rows reach `behaviour_gate_YES`, all
320 corpus rows reach `absorbed_into_behaviour_YES`, and the derived
`RELEASE_GATE` is GREEN. Prose, a new wave seal, or a config-wired count
cannot do it; only the disk bytes this checker reads.

## Boundaries

No new capability commands (Q2–Q5 own those), no edit to `v5/SATURATION.tsv`,
no product-tree write, no push, no credential/token output, no network, no
untrusted binary exec. Parent acceptance is non-delegable: parent opens these
files and re-runs the ONE `## Verify` below.

## Verify

ONE copy-pasteable W-relative command, run from W (no `W/` literal inside),
read-only, recomputes every number, prints measured values + `as_of` +
denominator + `COMPLETENESS_VERDICT`, negative + positive controls, exit 0:

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
"C:/Program Files/Git/usr/bin/timeout.exe" 120 python -X utf8 setukou-20261111/v5/slices/q1-completeness/verify.py
```

Measured run (2026-11-11, from W, exit 0): `claims_total=295 real_verified=9
blockers=286 RELEASE_GATE=RED gap_rows=28 gap_yes=8 gap_no=20
absorved_rows=320 absorbed_yes=7 absorbed_no=313 v2_v3_v4_accepted_rows=16
external_actions_total=36 external_actions_executed=0 push_executed=NO
live_porcelain_11_2_ok=True COMPLETENESS_VERDICT=NOT_COMPLETE
negative_control_red_capable=True green_capable=True CHECKER_SELFTEST=OK`.
