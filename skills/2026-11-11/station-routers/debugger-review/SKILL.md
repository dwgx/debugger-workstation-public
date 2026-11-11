---
name: debugger-review
description: 'Use after unpack/RE/boot/tool downloads, or when reviewing debugger work quality (评分/进化/收尾) before claiming done: read-only review of artifacts, evidence, exit conventions and handoff at this station. Checks that every claim maps to a concrete artifact path or command output with [UNVERIFIED] marked explicitly, that unpack/tool-download steps are reproducible via manifest + version + hash, that high-risk driver/Npcap/sample actions carry a rollback and a written consequence note, that exit/handoff and the board/digest reflect the true state, and that the report leads with the conclusion. Keeps RED gates RED and the 2026-09-19 vrc-dcc/vrc-review/vrc-world ban intact. Keywords: review, 收尾, 评分, 进化, done criteria, evidence, artifact, atomicity, probe coverage, exit conventions, handoff, rollback, reproducibility, UNVERIFIED, debugger.'
license: MIT
compatibility: 'Requires Python 3.10+, git, and PowerShell 7 (pwsh) to run station scripts and re-check artifacts; optional GitHub CLI (gh) for read-only issue lookup. Review is read-only against the station tree D:/Software/Tool/WorkStation/debugger on Windows x64; it never installs tools, drivers or Npcap.'
metadata:
  version: "1"
  last-reviewed: "2026-11-11"
  spec: "agentskills.io/specification"
  owner: "RestoreWorkerB | D:/Software/Tool/WorkStation/debugger/skills/debugger-review/SKILL.md"
---
# debugger-review (station review router)

Read-only review of a debugger work item. Authoritative artifacts live in the station tree; read them before judging:

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

## Gates that must not be softened

- A RED gate stays RED: never edit a check to make it green; fix the work or report the failure with its command and stderr.
- `vrc-dcc` / `vrc-review` / `vrc-world` and their overlays are banned since 2026-09-19; a review never accepts them as restored work.
- Commits stay English; the contract changes in git, not chat (`docs/MAINTAIN.md`).
