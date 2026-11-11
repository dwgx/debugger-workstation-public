OWNER: researcher-q2 | research/Q2/

# Q2 — 哪些能力可用自造 SYNTHETIC 靶场从 DECLARED_UNVERIFIED 变 RUNNABLE_REAL_VERIFIED？

6 of the 64 `TR:S-*` (scripts) claims can be honestly promoted via bounded REAL probes on our own scripts + SYNTHETIC fixtures; 58 cannot (7 frozen already-REAL, 51 honest non-promotions). [S2]

## Answer
Exactly 6 `TR:S-*` claims earn `RUNNABLE_REAL_VERIFIED`: `check-requires-tools.py`, `gate.ps1`, `mission.ps1`, `owner-attest.py`, `reachability-report.py`, `verify-tools-manifest.py`. Each has a REAL bounded `timeout.exe 45` command (cwd=W), a per-claim receipt with exit 0 + a literal success marker, and a negative-control receipt that fires RED (non-zero). [S3][S4][S5]

## Evidence (numbered, each tied to a source_id)
1. `tr_s_rows=64` (DECLARED 57 + REAL 7) recomputed from `v5/SATURATION.tsv` — the brief's `120` was the GLOBAL DECLARED count; parent's corrected `ROUND2-CONTRACT.md` and my disk recompute agree. `claims_total=295` frozen, never edited by this slice. [S1][S6]
2. Parent upper-bound reproduced on disk: `scripts/` 60 files (`.ps1 31 / .py 27 / .md 1 / .mjs 1`), `has_selftest=17`, `has_check=14`, `argparse/--help=25`, `neither=37`. So 120 (or even 64) rows CANNOT all be promoted; `--help` exit 0 alone is not a promotion. [S2]
3. Parent-verified real-probe key, reproduced by my calibration from cwd=W: `registry-verify.py --selftest` → exit 0 / 107 stdout lines; `assert-probes-selftest.py` → exit 2 (BROKEN gap) / `--selftest` argparse error exit 2. The non-zero exits are recorded HONESTLY and are NOT promoted. [S3][S7]
4. 6 promotion positives re-run under a product-tree SHA-256 before/after guard (`product_tree_writes: 0`, `equal: True`), all fresh exit 0, literal markers `1 ok` / `GATE SELFTEST OK` / `MISSION SELFTEST OK` / `SELFTEST 9/9 PASSED` / `REACHABILITY SELFTEST OK` / `passed`. [S4][S5]
5. SYNTHETIC fixtures <=8 KiB + sha256 sidecar (label `SYNTHETIC`): `syn-positive.json` → `check-requires-tools.py --registry` prints `1 ok` exit 0; `syn-negative.json` (expect `SYNTHETIC_NEVER_PRESENT` absent) → prints `UNMATCHED` exit 1. This is a positive AND expected-non-zero negative control through one of OUR OWN `--check`-style scripts. [S4][S8]
6. Six RED negative controls: `NEG-check-requires-tools.py` exit 1, `NEG-gate.ps1` exit 1, `NEG-mission.ps1` exit 2, `NEG-owner-attest.py` exit 2, `NEG-reachability-report.py` exit 2, `NEG-verify-tools-manifest.py` exit 1. A promotion without a receipt / with exit != 0 / with a ZERO negative control FAILs `verify.py`. [S5]
7. Honest non-promotions: `[FROZEN]` 7 (already REAL, V4 baseline), `[NONZERO]` 6, `[RAN0]` 4 (report-only, no RED receipt), `[NOENTRY]` 6 (dir/.md/no switch), `[GATED]` 35 (real IDA/Ghidra/dnSpy/MobSF/CheatEngine/MCP/network backends; `smoke-all.ps1 -Json` exit 124 under the 45s bound). `20 backends wired` = config consistency, NOT 20 usable backends. [S6][S7]
8. G-004: 126 further `TR:*` claims (`TR:X 36 / TR:N 32 / TR:MB 24 / TR:MC 21 / TR:L 11 / TR:K 2`) are UNASSIGNED to any Round-2 slice; frozen, untouched. [S1]

## Confidence
HIGH for the 6 promotions (real bounded command + exit 0 + literal marker + RED negative control + receipt + product-tree hash unchanged). HIGH for non-promotions (real non-zero exits recorded; `--help`/`--list`/report-only deliberately not promoted; 35 backend-gated scripts skipped). MEDIUM on the exact `[GATED]` classification of 35 scripts — it is a source-text boundary for capabilities needing a live backend/MCP/network, not a claim of usability (those stay OWNER_GATED / DECLARED). [S6][S7]

## What would falsify
- Any of the 6 `claim_TR_S-*.txt` receipts missing, exit != 0, or literal marker absent.
- Any `NEG-*.txt` negative control exiting 0 (not RED).
- `PRODUCT-TREE-INTEGRITY.txt` `equal: False` (product-tree write).
- `tr_s_rows != 64`, `has_selftest != 17`, `has_check != 14`, `claims_total != 295`.
- A `[FROZEN]` claim in `PROMOTIONS.tsv`, or re-running a promotion positive from W with a different exit.

## Real new subquestions / gaps
- 35 `[GATED]` `TR:S-*` scripts need a real backend/MCP/network decision (Q4 owns `TR:B-*`; these need a later OWNER_GATED review). No SYNTHETIC substitute proves a live IDA/Ghidra/dnSpy/MobSF/Cheat Engine backend usable.
- `sync-wiki-figures-selftest.py` and `verify-doc-facts-selftest.py` have planted green/red controls but BLOCK (exit 2, missing `<private-tree>\wiki`); a SYNTHETIC wiki skeleton + capabilities.json is a later-round靶场, not a defect.
- `smoke-all.ps1 -Json` exit 124 (45s bound) — a longer bounded run is a later question; recorded honestly, not suppressed.
- G-004: 126 unassigned `TR:*` claims remain frozen for a later round (parent). [S1]

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && python -X utf8 -B setukou-20261111/v5/slices/q2-scripts/verify.py
```
ONE `## Verify`: measures `tr_s_rows / scripts_probed / real_receipts / promotions / skipped_owner_gated / negative_controls_fired / synthetic_fixtures / sha256_match / product_tree_writes / claims_total_frozen_ok / VERDICT` from disk with `as_of` + denominator; negative control FAILs on a promotion with no receipt / non-zero exit / absent marker / non-RED negative control / FROZEN promotion.
