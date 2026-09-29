---
name: debugger-workstation
description: >-
  Reverse-engineering workstation (反编译, 逆向, decompile, unpack, Ghidra, IDA,
  x64dbg, JADX, Apktool, Il2CppDumper, AssetRipper, Frida, YARA, capa, FLOSS,
  PE, .NET). Auto-apply when the user wants to reverse a binary, unpack a
  game/APK/Unity IL2CPP, or the task is clearly RE — do not wait to be named.
  Read debugger AGENTS.md. Client MCP is debugger-router only. Drive CLI tools
  via SmartCLI. Never dump 19 backends into user-global MCP.
---

# debugger-workstation

Root: `D:\Software\Tool\WorkStation\debugger`

Read `AGENTS.md` there first, then gitignored `OWNER.md`. High-risk (Npcap, drivers, Defender, running malware on the host): brief the Owner, then follow intent. Do not silent-install drivers.

## Fire (pick one)

| Job | Read |
|---|---|
| Unknown sample | `debugger\skills\debugger-workstation\references\triage.md` |
| Need a binary path | `debugger\skills\debugger-workstation\references\arsenal.md` |
| MCP tool call | `debugger\skills\debugger-workstation\references\mcp-router.md` |
| Agent CLI (no GUI) | `debugger\skills\debugger-workstation\references\agent-cli.md` |
| Deep combo | `debugger\docs\EXPERT_PLAYBOOK.md` |

## Lazy MCP (required)

This station ships **one** client MCP: `debugger-router`. It starts a backend, runs the tool, exits.

- Catalog (not for the client): `MCP\.mcp.json`
- Client attach file: `D:\Software\Tool\WorkStation\mcp-clients\debugger-router.json`
- **Never** merge the 19 backends into `~\.cursor\mcp.json` / Claude user MCP / Codex user toml / Grok toml.
- IDA **idalib** is already on all four runtimes. Do not add a **second** IDA MCP. Router `ida` is `idalib-mcp --stdio`, not GUI `:13337`.
- Agent CLI first (no GUI stall): `debugger\scripts\agent-cli.ps1`. Table: `debugger\skills\debugger-workstation\references\agent-cli.md`.

## IDA on this PC

`Static-Reversing\IDA` → `D:\Software\Tool\Debugger\IDA Professional 9.2`. Do not download IDA.

## Tools

Pins on disk: `debugger\skills\debugger-workstation\references\arsenal.md`. Smoke: `debugger\scripts\smoke-tools.ps1` and `smoke-mcp.ps1`. Do not silent-install Npcap.

CLI + SmartCLI: `docs/SMARTCLI.md`. One PTY.

## After a job

Run `debugger-review`. Dual-axis score, then `notes/` / `Reports/`. Chat is not memory.
