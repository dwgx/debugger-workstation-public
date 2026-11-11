# WorkStation weapon-library — evidence + claims library (2026-11-11)

**This is an evidence/teaching package, NOT a claim that all capabilities work.**
Per-claim capability status is in [`SATURATION.tsv`](SATURATION.tsv), one row per
claim. Unverified does not mean usable.

- **Claims:** 295 total — `RUNNABLE_REAL_VERIFIED` 27, `DECLARED_UNVERIFIED` 102,
  `OWNER_GATED` 151, `MISSING` 15. Statuses are reproduced verbatim, not rewritten.
- **Release gate: RED.** `COMPLETENESS_VERDICT=NOT_COMPLETE`; 268 structural
  blockers. See [`RELEASE-GATE-STATUS.md`](RELEASE-GATE-STATUS.md). This package was
  published under an explicit Owner exemption (2026-11-11) for gate condition (a)
  and for the "generated but unusable" quality gate. The 268 unverified claims ship
  status-labelled, not promoted.
- **Evidence:** 8 accepted research questions (`research/Q1..Q8`), 8 verified
  work slices (`slices/q1..q8-*`) with receipts, metric ledger, audit and gate
  files, plus synthesis/ledger/checkpoint documents and a sanitized learning kit
  (`learning-kit/`, 17 files).

## What is NOT here

No raw corpora, no chat-export JSON files, no Hackerone KB source text, no `.jsonl`
transcripts, no `THINK/mandate.md`, no credential values, no account/token data,
no private-tree tracked content. Nothing in this package is a credential.

The only occurrences of the word "hackerone" in this package are read-only
product-tree names and repo-topology references in the ledgers — never KB content.

## How to read it

1. `SATURATION.tsv` — the authoritative claim table. Filter on `status`.
   Only `RUNNABLE_REAL_VERIFIED` rows carry a bounded real command + receipt.
2. `RELEASE-GATE-STATUS.md` — why the gate is RED and what the exemption covers.
3. `research/Q*/REPORT.md` + `sources.tsv` + `claims.tsv` — question-level evidence.
4. `slices/*/` — per-slice `verify.py`, `PROMOTIONS.tsv`, receipts, `METRIC-LEDGER`,
   `AUDIT.tsv`, `RELEASE-GATE.tsv`, `REPORT.md`, and SYNTHETIC fixtures with sha256
   sidecars. Re-run a slice verifier to reproduce its receipts.
5. `learning-kit/` — sanitized, self-contained teaching kit (licence note,
   QA gates, include/exclude manifests, receipt schema, two SYNTHETIC fixtures).
6. `checkpoints/round-0000..0006.json` — round-by-round state.

## Licences

Code/config/schema/validator/gate files → MIT. Documentation prose → CC BY-SA 4.0.
See [`learning-kit/LICENSE-NOTE.md`](learning-kit/LICENSE-NOTE.md). This package does
not alter the repository's root `LICENSE` / `LICENSE-docs`.

## Rollback

Every file here lives under `releases/2026-11-11-full-library/`. To revert the
publishing commit (append-only, no history rewrite):

```sh
git -C <clone-of-debugger-workstation-public> revert <pushed_sha> --no-edit
git -C <clone-of-debugger-workstation-public> push origin main
```

Rollback is written, rehearsed locally, and **not executed**; it requires a fresh
Owner decision. See [`ROLLBACK.md`](ROLLBACK.md).

## Integrity

`PACKAGE-MANIFEST.tsv` lists `path`, `sha256`, `bytes`, `status` for every file in
this package. Verify with:

```sh
python -X utf8 -c "import hashlib,pathlib,sys; ..."   # or any sha256sum -c style tool
```

`as_of 2026-11-11`.
