---
name: debugger-workstation
description: Route reverse engineering, unpacking, binary/APK/pcap or memory triage, station bootstrap and session recovery through a configured debugger-workstation repository. Use when a task needs the station's tools, MCP router or mission evidence.
license: MIT
compatibility: "A configured station repository and the tools needed by the selected task. Python 3.10+ for Python scripts; use each station script's documented PowerShell version on Windows. Git is needed for Git provenance, not for every review or archive check."
metadata:
  version: "1"
  last-reviewed: "2026-11-19"
  spec: "agentskills.io/specification"
  owner: "repository maintainers | station-routers/debugger-workstation"
---
# debugger-workstation — station task router

Resolve the station repository from the current task or clone configuration: it
contains `AGENTS.md`, `manifests/` and `mcp/`. A copied skill directory is not the
station root. If that root is unknown, resolve it before running station commands.
All paths below are relative to that repository.

1. Read `AGENTS.md` (+ locale), local `OWNER.md` when present and
   `docs/CURRENT-CLOSEOUT.md`. Current Owner decisions define this task's scope;
   historical notes or personal authorizations do not expand or veto it.
2. For setup, use `README.md`, the selected manifests and questionnaire to resolve
   only unanswered choices. Use `scripts/bootstrap.ps1` dry-run before the
   authorized `-Apply`; download only the selected tools.
3. For a run, choose the current profile (`docs/CURRENT-CLI-PROFILE.md`), descriptors
   and mission contracts. `.agent/HANDOFF.md` (2026-10-16) and
   `.agent/RECOVERY-STATION.md` (2026-09-30) are historical recovery references.
4. Default to `debugger-router`; preserve user-global MCP and do not add a second
   IDA server when idalib already serves the task. Verify tool version/hash and
   semantic output, not just availability or an exit-0 probe.
5. Close material work with `skills/2026-11-11/station-routers/debugger-review/SKILL.md`.
   Report implementation, actual tests, acceptance and publication separately.

Keep root approval/nonce and evidence mechanisms. High-risk work needs stated
consequences and rollback; never silently install drivers/Npcap or run untrusted
samples on the host. The `vrc-dcc` / `vrc-review` / `vrc-world` family and overlays
remain retired (2026-09-19). Report an unrun step as `[UNVERIFIED]`. Never weaken a
valid check for PASS; a checker defect needs a counterexample and independent review.

When installing this router, keep one active canonical copy and verify the
harness's resolved source path and SHA-256 against reviewed bytes. The repository's
`skills/2026-11-11/portable-core/references/INSTALL.md` demonstrates this for OMP;
use this router's own canonical name and expected source path.
