OWNER: researcher-q2 | v5/slices/q2-scripts/

# Q2 — SYNTHETIC 靶场真跑 (TR:S-* scripts)

Only 6 of the 64 `TR:S-*` claims can be honestly promoted from `DECLARED_UNVERIFIED` to `RUNNABLE_REAL_VERIFIED` without crossing a red line; the other 58 stay DECLARED / OWNER_GATED / FROZEN, with non-zero exits recorded honestly.

## Answer
6 promotions, each backed by a REAL bounded `C:/Program Files/Git/usr/bin/timeout.exe 45` command (cwd=W), a per-claim receipt (exit 0 + literal success marker), and a negative-control receipt that fires RED (non-zero exit). The 7 already-REAL claims are frozen; 51 others are not promoted.

## Evidence
1. `SCRIPT-PROBES.tsv` — one row per `TR:S-*` claim. `tr_s_rows=64` recomputed from `v5/SATURATION.tsv` (DECLARED 57 + REAL 7) — NOT the brief's wrong `120` (that is the GLOBAL DECLARED count; `ROUND2-CONTRACT.md` corrected by parent). `has_selftest=17 / has_check=14` reproduces `PARENT-Q2-UPPER-BOUND.md` (60 files / 17 / 14 / 37 neither / 31 `.ps1`). [SRC-SAT] [SRC-UB]
2. `receipts/` — 47 REAL receipts (command / cwd / started_utc / finished_utc / exit / stdout / stderr). 6 `claim_TR_S-*.txt` are the promotion positives (all exit 0). [SRC-REC]
3. Parent-verified real-probe key reproduced on disk: `registry-verify.py --selftest` exit 0 / 107 stdout lines [SRC-RV-PARENT]; `assert-probes-selftest.py` exit 2 (no-flag, BROKEN gap) and `--selftest` argparse error exit 2 — recorded HONESTLY in `SCRIPT-PROBES.tsv` as `[NONZERO]`, NEVER promoted. [SRC-APS]
4. 6 promotion positives re-run under a product-tree SHA-256 before/after guard: `PRODUCT-TREE-INTEGRITY.txt` shows `equal: True`, `product_tree_writes: 0`. All 6 fresh exits=0. [SRC-INTEG]
5. SYNTHETIC fixtures (<=8 KiB + sha256 sidecar, label `SYNTHETIC`): `fixtures/syn-positive.json` (expect present → `check-requires-tools.py --registry` prints `1 ok`, exit 0) and `fixtures/syn-negative.json` (expect `SYNTHETIC_NEVER_PRESENT` absent → prints `UNMATCHED`, exit 1). This is the positive + expected-non-zero negative control through one of OUR OWN `--check`-style scripts. [SRC-FX]
6. Negative controls that can go RED for every promotion: `NEG-check-requires-tools.py.txt` exit 1, `NEG-gate.ps1.txt` exit 1, `NEG-mission.ps1.txt` exit 2, `NEG-owner-attest.py.txt` exit 2, `NEG-reachability-report.py.txt` exit 2, `NEG-verify-tools-manifest.py.txt` exit 1. [SRC-NEG]
7. Honest non-promotions: `[FROZEN]` 7 (already REAL), `[NONZERO]` 6 (real non-zero exit, e.g. `assert-probes-selftest.py` exit 2, `sync-wiki-figures-selftest.py`/`verify-doc-facts-selftest.py` exit 2 missing private wiki, `verify-clone-freshness.py` exit 1, `sync-wiki-figures.py --check` exit 1, `verify-all.ps1 -Action Selftest` exit 2), `[RAN0]` 4 (report-only / no RED receipt), `[NOENTRY]` 6 (dirs / .md / no switch), `[GATED]` 35 (real RE/MCP/network backends, e.g. `agent-cli.ps1`, `ce-agent.ps1`, `dnspy-console.ps1`, `smoke-all.ps1` timed out 124). `--help` exit 0 alone is NEVER a promotion. `smoke-all.ps1 -Json` exit 124 (45s bound) recorded, not suppressed. [SRC-PROBES]
8. G-004 (parent): 126 further `TR:*` claims (`TR:X 36 / TR:N 32 / TR:MB 24 / TR:MC 21 / TR:L 11 / TR:K 2`) are UNASSIGNED to any Round-2 slice; they stay frozen and are NOT claimed, deleted, or reclassified here. `claims_total=295` frozen; `SATURATION.tsv` was NEVER edited by this slice. [SRC-CONTRACT]

## Confidence
HIGH for the 6 promotions (each has a real bounded command + exit 0 + literal marker + RED negative control + receipt; product-tree hash unchanged). HIGH for the non-promotions (real non-zero exits recorded; `--help`/`--list`/report-only deliberately not promoted; 35 backend-gated scripts skipped). MEDIUM on the exact `[GATED]` classification of 35 scripts (needs a real backend / MCP / network; classification is from source text, not a live connection — it is the honest OWNER_GATED boundary, not a claim of usability). `20 backends wired` = config consistency, NOT 20 usable backends.

## What would falsify
- Any of the 6 `claim_TR_S-*.txt` receipts missing / exit != 0 / literal marker absent.
- Any `NEG-*.txt` negative control exiting 0 (not RED).
- `PRODUCT-TREE-INTEGRITY.txt` `equal: False` (a probe wrote into a product tree).
- `tr_s_rows != 64`, `has_selftest != 17`, `has_check != 14`, or `claims_total != 295` (denominator drift).
- A `[FROZEN]` claim appearing in `PROMOTIONS.tsv`.
- Re-running any promotion positive from W and getting a different exit.

## Real new subquestions / gaps
- The 35 `[GATED]` scripts need a real backend/MCP/network decision (Q4 territory for `TR:B-*`; these are `TR:S-*`, so they need a later OWNER_GATED review) — no SYNTHETIC substitute exists for a live IDA/Ghidra/dnSpy/MobSF/Cheat Engine backend.
- `sync-wiki-figures-selftest.py` and `verify-doc-facts-selftest.py` have planted green/red controls but BLOCK (exit 2) because `<private-tree>\wiki` is absent; a SYNTHETIC wiki skeleton with the 4 wiki files + a capabilities.json could be built in a later round to exercise them (they currently refuse by design, not defect).
- `smoke-all.ps1 -Json` exceeded the 45s bound (exit 124); a longer bounded run is a later-round question, not a promotion here.
- G-004: 126 unassigned `TR:*` claims remain for a later round (parent).

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && python -X utf8 -B setukou-20261111/v5/slices/q2-scripts/verify.py
```
`verify.py` measures every number from disk with `as_of` + denominator, and has a negative control that FAILs (VERDICT=FAIL, exit 1) on a `PROMOTIONS.tsv` row whose receipt is missing, whose exit != 0, whose literal marker is absent, whose negative control did NOT go RED, or which promotes a FROZEN claim.
