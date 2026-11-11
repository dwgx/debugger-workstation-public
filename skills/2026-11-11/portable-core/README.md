OWNER: parent (took over stalled PackageDesign slice) | package/README.md
# debuggerstation-selfdeploy — portable skill package

[English](README.md) · [简体中文](README.zh-CN.md)

A **reviewable LOCAL skill package** (NOT pushed, NOT installed into any product tree). Plain-language intro for an AI or human who is handed a debugger-station repo.

## What this is
One entry (`SKILL.md` → `SELF-DEPLOY.md`), one `tests/verify.py`, a `FIX-KB/` of official+community fixes, and a `SELF-REPAIR.md` loop. An AI can add it to its own harness, run tests, and self-diagnose tool/env failures.

## What this is NOT
- NOT `vrc-dcc` / `vrc-review` / `vrc-world` / VRC overlay (retired 2026-09-19, HARD BAN).
- NOT a claim that all capabilities work: `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, 295 claims / 27 REAL / 268 blockers, strict `0/27` in-package receipts.
- NOT credential values / raw corpora / `.jsonl` / THINK / Hackerone KB text / PRIVATE repo content.
- NOT a remote deploy: push / Pages / settings / visibility are `[NOT EXECUTED]`.

## 3-step AI handoff
1. Read `SKILL.md`, then `SELF-DEPLOY.md` (`[NOT EXECUTED]` banner).
2. Run ONE env self-check + ONE clone+verify; expect `PUSHED_SHA=875cd108… / VERDICT=PUBLISHED`.
3. Run `tests/verify.py`; on failure use `SELF-REPAIR.md` + `FIX-KB/*.tsv`, dry-run first, re-test, rollback if exit≠0.

## Status / licence
`RELEASE_GATE=RED` (295/27/268). Dual licence intended MIT(code)/CC BY-SA 4.0(docs); remote currently `NOASSERTION` — a known gap, not a licence grant. Prior-wave assets by pointer: `public-repo-best-handoff-20261111/assets/{repo-topology.svg,claim-status.svg,ai-entry.mmd}`, `deploy/AGENT-ENTRY.md`, `i18n/README*.md`.

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111" && python -X utf8 package/verify.py
```
