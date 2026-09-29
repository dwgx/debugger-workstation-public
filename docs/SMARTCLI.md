# SmartCLI + debugger-workstation

SmartCLI owns **one PTY**. Use it for interactive CLIs. Do not occupy it for Grok-delegate / headless `grok -p` runs.

## Prefer SmartCLI (TUI / REPL)

| Tool | Why | Example start |
|---|---|---|
| radare2 / rizin | Visual panels, seek, `VV` | `r2 -A sample.exe` |
| Ghidra headless | Batch decompile | `scripts\ghidra-headless.ps1 -Sample <pe>` |
| IDA `idat` | Batch Hex-Rays | `scripts\ida-cli.ps1 -Sample <pe>` |
| JADX CLI | Decompile wait | `scripts\jadx-decompile.ps1 -InputPath app.apk` |
| dnSpy.Console | .NET decompile | `scripts\dnspy-console.ps1 -Sample lib.dll` |
| Apktool | Decode/build | `java -jar apktool.jar d app.apk` |
| FLOSS / capa / YARA-X `yr` | Streaming analysis | `capa.exe sample` |
| ILSpy `ilspycmd` | Console decompile | `ilspycmd Assembly.dll -o out` |
| 7-Zip `7z` | List/extract archives | `7z l archive.7z` |
| tshark | Offline pcap | `tshark -r capture.pcap` |
| DIE `diec` | Detect-it-easy CLI if present | `diec.exe sample` |
| Volatility 3 | Memory plugin output | `vol.py -f mem.dmp windows.pslist` |
| objection | Frida REPL | `objection -g pkg explore` |
| UPX | Pack/unpack | `upx -t sample.exe` |

Flow: `smartcli.start` → `wait_ready` / `wait_regex` → `send_line` → `snapshot`. Close the session when the job ends.

## Do not put in SmartCLI

GUI-only: x64dbg, ImHex, PE-bear, Cheat Engine window, System Informer, Reqable, Wireshark GUI, AssetRipper GUI, `ida.exe` / `dnSpy.exe` / `ghidraRun.bat`. Agent decompile uses the CLI wrappers (ida-cli / ghidra-headless / dnspy-console / jadx-decompile), not those windows. CE: `scripts\ce-agent.ps1` then x64dbg MCP.

## MCP vs CLI

If a router backend exists (`jadx`, `apktool`, `radare2`, `ghidra`, `sevenzip`, `wireshark`), prefer **one** debugger-router call for a single tool action. Use SmartCLI when you need a **session** (REPL, pager, multi-step interactive).
