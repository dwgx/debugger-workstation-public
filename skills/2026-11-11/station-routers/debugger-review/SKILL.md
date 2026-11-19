---
name: debugger-review
description: Review a debugger-workstation task before closeout. Use to check artifacts, semantic test evidence, source identity, rollback and handoff after reverse engineering, bootstrap, tool changes or maintenance, with unverified claims made explicit.
license: MIT
compatibility: "A configured station repository and readable task evidence. Use Python 3.10+ or the documented PowerShell version only when a targeted verification needs them. Review does not install tools or drivers or modify the artifact under review."
metadata:
  version: "1"
  last-reviewed: "2026-11-19"
  spec: "agentskills.io/specification"
  owner: "repository maintainers | station-routers/debugger-review"
---
# debugger-review — evidence and artifact review

Resolve the station repository from the task or clone configuration; do not infer
it from an installed skill's location or the template author's machine. Paths
below are repository-relative. Read `AGENTS.md` (+ locale), current Owner scope
and `docs/CURRENT-CLOSEOUT.md` before judging. Current task decisions supersede
stale notes while approval, nonce/ledger and technical evidence gates remain.

Use `docs/CURRENT-CLI-PROFILE.md`, `docs/ROUTER_DESCRIPTORS.md` and
`docs/MISSION-SUCCESS-CONTRACTS.md` for the relevant execution path. Load only the
needed `.agent/` references: `atomic-artifacts.md`, `success-when.md`,
`exit-conventions.md`, `probe-coverage.md`, `clone-freshness.md`,
`tools-manifest.md` or `tool-blinds.md`. The 2026-10-16 `.agent/HANDOFF.md` is
historical context, not the current closeout authority.

Check both artifact and evidence:

1. Map each claim to an artifact or command/result with source version/hash and
   explicit `[UNVERIFIED]` gaps. Copy, package PASS, actual loader source and model
   use are separate claims; a skill's name alone does not identify its bytes.
2. For the changed behavior, inspect semantic output and a meaningful negative
   control. Preserve applicable old evidence; repeat tests only for a concrete gap.
3. Verify high-risk consequences, rollback and approval/nonce provenance. Never
   silently install drivers/Npcap, run untrusted host samples or widen user-global MCP.
4. Distinguish implemented, runtime-tested, independently accepted and published.
   Lead the report with the conclusion, remaining limits and one useful next action;
   persist a reusable lesson through `docs/AGENT_EVOLUTION.md` when warranted.

Do not modify the reviewed artifact during this pass. Never weaken a valid check
to obtain PASS; a suspected checker defect needs a reproducible counterexample
and independent review. The `vrc-dcc` / `vrc-review` / `vrc-world` family and
overlays remain retired (2026-09-19). Current Owner decisions do not bypass the
underlying approval or evidence mechanisms.
