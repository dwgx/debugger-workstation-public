---
name: debugger-workstation
description: Use for binary/APK/DLL/pcap/memory-dump reverse engineering at this station; not for readable source or live hosts. Covers init handshake, high-risk drivers/Npcap/samples, lazy MCP, and tool download policy.
metadata:
  version: 1
  last-reviewed: 2026-10-28
---
# debugger-workstation (station router)

Authoritative files live in the station tree; this skill only routes.

- Root contract: `<repo>/AGENTS.md` (+ locale variants).
- Init: read `README.md`, `AGENTS.md`, gitignored `OWNER.md`, `manifests/*.json`, `docs/I18N.md`; ask the language/handshake questionnaire, then plan.
- Recovery after a broken session: `.agent/RECOVERY-STATION.md`.
- High risk (drivers / Npcap / Defender / samples): state consequences + rollback, then follow intent; never silent-install drivers.
- MCP: default `debugger-router` only; never a user-global `mcp-all`; do not add a second IDA server if idalib exists.
- Tools: use `scripts/bootstrap.ps1` (dry-run → `-Apply`) and `download-tools.ps1 -Apply`.
- Git commits stay English; the contract changes in git, not chat (`docs/MAINTAIN.md`).
