OWNER: SpecOptimizer | package/references/FIX-KB.md
# FIX-KB — how to read the fix knowledge base (pointer, not a copy)

The tables live at the skill root under `FIX-KB/` (two TSVs). This page is the
one-level pointer that `SKILL.md` is allowed to reference; the rows themselves are
owned by the fix-KB slice and are never duplicated here (no drift, no second copy).

| file | content | trust label |
|---|---|---|
| `FIX-KB/OFFICIAL.tsv` | fixes traced to vendor docs / the spec / a real exit code | `official-verified` |
| `FIX-KB/COMMUNITY.tsv` | community and prior-wave fixes, not independently reproduced | `community-unverified` |

## Columns (header row of both TSVs)
`id  symptom  cause  fix  verify_command  source  date  trust  status`

## Read order (self-diagnosis loop)
1. Print the failing state first (tool version, exit code, stdout tail). Never guess a cause.
2. Search `OFFICIAL.tsv` by symptom; only if there is no hit, search `COMMUNITY.tsv`.
3. A row is APPLICABLE only when `verify_command` is non-empty and `source` + `date` are present. Anything else is `[UNVERIFIED]` and must not be auto-applied.
4. Dry-run the fix, re-run the package verifier, and only then keep it. Rollback point: `SELF-REPAIR.md`.
5. High-risk rows (drivers / Npcap / Defender / samples): consequence + rollback written BEFORE acting; never silent-install.

## Invariants that no row may override
- No fix may turn `RELEASE_GATE=RED` into a claim of GREEN. `COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers and the strict `0/27` in-package receipt count stand after any repair.
- Never add credential values, raw corpora, `.jsonl`, or Hackerone KB source text as a "fix".
- `vrc-dcc` / `vrc-review` / `vrc-world` are HARD-BANNED (retired 2026-09-19): a proposed fix that restores them is rejected on sight.
