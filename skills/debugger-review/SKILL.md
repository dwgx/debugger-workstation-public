---
name: debugger-review
description: 'Use after unpack/RE/boot/tool downloads, or when reviewing debugger work quality (评分/进化/收尾): check artifacts, evidence, exit conventions and handoff before claiming done.'
metadata:
  version: 1
  last-reviewed: 2026-10-28
---
SUPERSEDED by skills/2026-11-11/station-routers/debugger-review/SKILL.md (2026-11-11). Kept for history; the authoritative version is in the 2026-11-11 package.
# debugger-review (station review router)

Read-only review of a debugger work item. Authoritative artifacts:

- What "done" means: `.agent/success-when.md`
- Artifact/atomicity rules: `.agent/atomic-artifacts.md`
- Probe coverage: `.agent/probe-coverage.md`
- Exit conventions: `.agent/exit-conventions.md`
- Clones/tool freshness: `.agent/clone-freshness.md`, `.agent/tools-manifest.md`
- Blinds (known blind spots): `.agent/tool-blinds.md`
- Evolution / lessons: `docs/AGENT_EVOLUTION.md`
- Current handoff: `.agent/HANDOFF.md`

Checklist:
1. Every claim maps to a concrete artifact path or command output; `[UNVERIFIED]` is explicit.
2. Unpacked/tool-download steps are reproducible (manifest + version + hash), not just "it worked here".
3. High-risk actions (drivers/Npcap/samples) have a rollback and a written consequence note.
4. Exit/handoff updated; the next action is one line; board/digest reflects the true state.
5. Report: conclusion first, evidence second, no praise; list remaining unknowns.

Never modify the artifact under review during the review pass.
