---
name: debugger-workstation
description: 'Station-bound router for binary/APK/DLL/pcap/memory-dump reverse engineering in the WorkStation debugger tree: use it when unpacking, disassembling, triaging a memory dump or pcap, bootstrapping tools, or recovering a broken session at this station; not for readable source or live hosts. Routes the init handshake (AGENTS.md, OWNER.md, manifests, I18N questionnaire), high-risk drivers/Npcap/Defender/samples with consequences + rollback and never-silent-install, lazy MCP with debugger-router only and never a user-global mcp-all, tool downloads via bootstrap.ps1 dry-run then -Apply with manifest + version + hash, English commits, and the 2026-09-19 hard ban on the vrc-dcc/vrc-review/vrc-world family. Keywords: reverse engineering, RE, binary, APK, DLL, pcap, memory dump, IDA, idalib, Npcap, drivers, workstation, debugger-router, bootstrap, recovery, handshake.'
license: MIT
compatibility: 'Requires Python 3.10+, git, and PowerShell 7 (pwsh) for scripts/bootstrap.ps1 and download-tools.ps1; optional GitHub CLI (gh) for read-only issue lookup. IDA/id alib and Npcap are optional per task and are never installed silently. Runs against the station tree D:/Software/Tool/WorkStation/debugger on Windows x64.'
metadata:
  version: "1"
  last-reviewed: "2026-11-11"
  spec: "agentskills.io/specification"
  owner: "RestoreWorkerB | D:/Software/Tool/WorkStation/debugger/skills/debugger-workstation/SKILL.md"
---
# debugger-workstation (station router)

Authoritative files live in the station tree; this skill only routes. Read them before acting.

- Root contract: `<repo>/AGENTS.md` (+ locale variants).
- Init: read `README.md`, `AGENTS.md`, gitignored `OWNER.md`, `manifests/*.json`, `docs/I18N.md`; ask the language/handshake questionnaire, then plan.
- Recovery after a broken session: `.agent/RECOVERY-STATION.md`.
- High risk (drivers / Npcap / Defender / samples): state consequences + rollback, then follow intent; never silent-install drivers.
- MCP: default `debugger-router` only; never a user-global `mcp-all`; do not add a second IDA server if idalib exists.
- Tools: use `scripts/bootstrap.ps1` (dry-run → `-Apply`) and `download-tools.ps1 -Apply`.
- Git commits stay English; the contract changes in git, not chat (`docs/MAINTAIN.md`).
- Closeout for a material job is dual-axis — artifact axis + evidence axis — run against `skills/debugger-review`.

## Hard bans

- `vrc-dcc` / `vrc-review` / `vrc-world` and their overlays are banned since 2026-09-19 (`AGENTS.md` + retired note). Never restore them, never re-add a VRC overlay.
- Never install a driver, Npcap, or any kernel component silently; never run an untrusted sample on the host.
- Never widen MCP beyond `debugger-router` into the user-global config.

## Honesty gate

- A RED check is reported RED. Never edit a check to make it green; fix the work or report the failure with its command and stderr.
- Anything not actually run is marked `[UNVERIFIED]`.
