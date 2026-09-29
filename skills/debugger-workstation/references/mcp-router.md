# debugger-router (the only client MCP)

Clients attach **one** server. The router starts a backend, runs one tool, exits.

- Client file: `D:\Software\Tool\WorkStation\mcp-clients\debugger-router.json`
- Catalog (router only, not for the client): `MCP\.mcp.json`
- Never copy the 19 backends into Claude / Codex / Cursor / Grok **user** config.

## Router tools

1. `list_backends` — names and categories, no process start.
2. `list_backend_tools` — start one backend, list its tools, close.
3. `call_backend_tool` — `backend`, `tool_name`, `arguments_json`, then close.

Always `list_backend_tools` before an unfamiliar backend. Do not invent tool names.

## Backends that need keys

`yaraflux`, `mobsf`, `virustotal`: do not call until `.env` exists. Do not commit `.env`.

## IDA

IDA MCP **is installed**. Two paths, one client (debugger-router):

- **idalib (default, headless):** `idalib-mcp.exe --stdio`. Global copy: `D:\Software\Developer\Python314\Scripts\idalib-mcp.exe`. Grok user config has it under `[mcp_servers.ida-pro-mcp]` but `disabled_mcp_servers` lists that name — **do not enable a second IDA in user-global**. Call via router backend `ida`.
- **GUI plugin (optional):** `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp.py` already present. Only needed when IDA is open and you want port 13337. Do not run `ida-pro-mcp --install claude,cursor`.

## If the router python is missing

`mcp\debugger-router\.venv\Scripts\python.exe` must exist. Headless smoke: `powershell -File scripts\smoke-mcp.ps1` (sevenzip / apktool / jadx / wireshark). Wireshark venv must pin `mcp>=0.9.0,<2.0.0` (mcp 2.x dropped `@Server.list_tools`).

JADX **decompile** for agents: `scripts\jadx-decompile.ps1 -InputPath <apk>` (CLI, no GUI). Plugin `Mobile-Android\jadx\plugins\jadx-ai-mcp-6.4.1.jar` is for live GUI MCP after the human opens `jadx-gui`. MCP `jadx` lists tools without the plugin; calls that need the HTTP plugin fail until GUI is up.

## CLI vs GUI vs router

Drive Ghidra / JADX / IDA / dnSpy from `scripts\agent-cli.ps1` first. Do not wait for a window.

- **Ghidra:** batch `scripts\ghidra-headless.ps1`. Interactive MCP needs HTTP `:8080` — either `-Http` (headless script) or the GUI plugin. `list_backend_tools ghidra` works without HTTP; decompile calls fail until `:8080` is up.
- **IDA:** batch `scripts\ida-cli.ps1` (`idat -A`). Interactive: router `ida` / idalib. GUI `:13337` optional.
- **JADX:** `scripts\jadx-decompile.ps1`. MCP HTTP plugin is GUI-only.
- **dnSpy:** `scripts\dnspy-console.ps1` or router `dnspy` (`DnSpyMcpServer.exe`, no window).
- **CE:** no headless CLI. `scripts\ce-agent.ps1` reports the named pipe. Else router `x64dbg`.
- **MobSF / VT:** `scripts\mobsf-agent.ps1` / `scripts\intel-agent.ps1` never stall on a missing key. Router backends still need `.env`.

GUI backends that still need a live session: x64dbg, CE (pipe), ReClass, ImHex. `yaraflux` / `mobsf` / `virustotal` need `.env` for the **router** path only.
