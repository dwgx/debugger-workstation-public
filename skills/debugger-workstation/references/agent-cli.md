# Agent CLI (no GUI stall)

Pattern: [HKUDS/CLI-Anything](https://github.com/HKUDS/CLI-Anything) (Click CLI + JSON + SKILL). That hub has **no** IDA/Ghidra/JADX harness — this station wraps them. JSON on stdout. Client MCP stays **debugger-router only**.

Dispatcher: `powershell -File scripts\agent-cli.ps1` (catalog). Per-tool scripts below.

| Tool | Agent CLI (no window) | GUI / live | Router backend |
|---|---|---|---|
| Ghidra | `scripts\ghidra-headless.ps1 -Sample <pe>` exports `decompiled\*.c` + `summary.json`. `-Http` starts GhidraMCP-compatible HTTP on `:8080` | `ghidraRun.bat` + GhidraMCP plugin | `ghidra` talks to `:8080` (headless `-Http` **or** GUI plugin) |
| IDA | `scripts\ida-cli.ps1 -Sample <pe>` via `idat -A` + Hex-Rays | `ida.exe` | `ida` = **idalib-mcp --stdio**. Do not enable a second IDA in user MCP. GUI plugin `:13337` is optional |
| JADX | `scripts\jadx-decompile.ps1 -InputPath <apk>` (`jadx.bat`) | `jadx-gui` + `plugins\jadx-ai-mcp-*.jar` | `jadx` lists without plugin; HTTP calls need GUI |
| dnSpy | `scripts\dnspy-console.ps1 -Sample <dll>` | `dnSpy.exe` | `dnspy` = `DnSpyMcpServer.exe` (ICSharpCode.Decompiler, **no window**) |
| CE | `scripts\ce-agent.ps1` JSON status. No headless scanner | CE window + `autorun\ce_mcp_bridge.lua` named pipe | `cheatengine` needs the pipe. Else **x64dbg** (48 tools) |
| MobSF | `scripts\mobsf-agent.ps1 -Sample <apk>` REST if `MOBSF_API_KEY`, else apktool static | Web UI not required | `mobsf` needs **local** MobSF API key (not VT). Do not commit `.env` |
| VT | `scripts\intel-agent.ps1 -Sample <file>` SHA256+DIE+capa. Hash lookup only if `VIRUSTOTAL_API_KEY` | n/a | `virustotal` needs the key. Never upload unless Owner names `-Upload` |

## Honest gaps

- CE has no useful `/?` CLI. Do not wait on a window. `-StartCe` is minimized GUI, not headless.
- VirusTotal cannot reputation-scan without a cloud key. Local substitute is DIE+capa+YARA.
- Full MobSF Django (`run.bat` / poetry) is optional. Local fallback is apktool manifest parse.
- Ghidra HTTP decompile of one function must finish within the Python bridge 5s timeout; bulk export has no that cap.
- IDA GUI graph / CE memory-scan UI / Ghidra listing cursor are live-session only. Batch export covers decompile, imports, exports, strings, xrefs.

## Do not

- Dump 19 backends into user-global MCP.
- Enable a second IDA server (idalib is already on the four runtimes).
- Pack IDA. Silent-install Npcap. Write `<project>` from this cwd.
