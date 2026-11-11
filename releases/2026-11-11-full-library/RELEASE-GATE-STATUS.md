# RELEASE-GATE-STATUS — RED / NOT_COMPLETE (Owner-exempted for this publication)

`as_of 2026-11-11`. Applies to `releases/2026-11-11-full-library/`.

## Verdict

| field | value |
|---|---|
| `RELEASE_GATE` (v4 REAL gate) | **RED** |
| `COMPLETENESS_VERDICT` | **NOT_COMPLETE** |
| structural blockers | **268** |
| claims total (frozen) | **295** |
| `RUNNABLE_REAL_VERIFIED` | **27** |
| `DECLARED_UNVERIFIED` | **102** |
| `OWNER_GATED` | **151** |
| `MISSING` | **15** |
| external actions executed | **0 / 36** |
| `push_executed` (before this release) | **NO** |

The gate is RED and the verdict is NOT_COMPLETE. Publishing this package does not
change either fact.

## Why RED — and what the Owner exempted

The v4 release gate requires 5 conditions. Condition (a) — every claim REAL-verified —
is **not met**: 268 claims remain unverified (102 declared, 151 owner-gated, 15 missing).
Those blockers are **structural**, not cosmetic: they need real commands, real receipts,
and tamper controls that do not exist yet.

On 2026-11-11 the Owner explicitly exempted this publication from:

- **condition (a)** — the all-claims-REAL requirement, and
- the **"generated but unusable" quality gate**,

and authorized shipping the full 295-claim table plus full evidence as a public
evidence package. The exemption covers *publication*, not *verification*: no claim's
status is upgraded, no receipt is invented, and no RED flag is turned GREEN.

## Per-claim status is preserved verbatim

`SATURATION.tsv` ships unmodified. Each of the 295 rows carries its own `status`,
`original_verdict`, `real_command`, `exit`, `receipt_path`, `note`, `round`,
`verified_by`. Only the 27 `RUNNABLE_REAL_VERIFIED` rows have a bounded real command
with a receipt and (where applicable) negative controls. The other 268 rows are
explicitly **not** verified and must be read as claims, not capabilities.

## What this package is / is not

- **Is:** a "claims + evidence" full library — every claim, every receipt, every
  audit trail, with honest status labels and the RED gate documented.
- **Is not:** a statement that all capabilities work, a GREEN release, a
  completeness certification, or a licence grant beyond the note in
  `learning-kit/LICENSE-NOTE.md`.

## Five-condition gate status at publication time

| # | condition | status |
|---|---|---|
| a | all claims REAL-verified | **RED — Owner-exempted 2026-11-11** |
| b | private trees unchanged | OK — `7dfabdb`/11 and `2c25f26`/2 porcelain entries, unchanged |
| c | pre-push diff clean (`origin/main...HEAD` empty) | OK — empty before the release commit |
| d | pre-push log clean (`origin/main..HEAD` empty) | OK — empty before the release commit |
| e | rollback written + locally rehearsed | OK — `ROLLBACK.md`, remote execution NOT performed |
