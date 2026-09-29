# Arsenal map (this clone)

Install root: `D:\Software\Tool\WorkStation\debugger`. Relative paths below. Pins match disk 2026-09-20, not always upstream latest.

| Lane | Tool | Entry |
|---|---|---|
| triage | DIE 3.21 | `Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe` |
| triage | capa 9.4.0 | `Static-Reversing\capa\capa.exe` |
| triage | FLOSS 3.1.1 | `Static-Reversing\FLOSS\floss.exe` |
| PE | Ghidra 12.1.3 | CLI `scripts\ghidra-headless.ps1`; GUI `ghidraRun.bat` |
| PE | IDA 9.2 | CLI `scripts\ida-cli.ps1` (`idat.exe`); junction `Static-Reversing\IDA` (do not pack) |
| PE | radare2 6.2.2 | `Static-Reversing\radare2\radare2-6.2.2-w64\bin\radare2.exe` |
| PE | PE-bear 0.7.2 | `Static-Reversing\PE-bear\PE-bear.exe` |
| PE | ImHex 1.38.1 | `Static-Reversing\ImHex\imhex-gui.exe` |
| rules | YARA-X 1.20.0 | `Static-Reversing\YARA-X\yr.exe` |
| .NET | ILSpy 11.0 | `Static-Reversing\ILSpy\ILSpy.exe` |
| .NET | ilspycmd | `Static-Reversing\ilspycmd\ilspycmd.exe` |
| .NET | dnSpyEx 6.6.0 | CLI `dnSpy.Console.exe` / `scripts\dnspy-console.ps1`; GUI `dnSpy.exe` |
| debug | x64dbg | `Debuggers\x64dbg\release\x64\x64dbg.exe` (agent debugger; 48 MCP tools) |
| debug | Cheat Engine 7.7 | GUI + pipe; `scripts\ce-agent.ps1` (no headless) |
| android | JADX 1.5.6 | CLI `scripts\jadx-decompile.ps1`; GUI `jadx-gui.bat` |
| android | Apktool 3.0.3 | `Mobile-Android\Apktool\apktool.jar` |
| unpack | 7-Zip 26.02 | `Unpackers-Game\7-Zip-full\7z.exe` |
| unpack | UPX 5.2.1 | `Unpackers-Game\upx\upx-5.2.1-win64\upx.exe` |
| unpack | UniExtract | `Unpackers-Game\UniExtract\UniExtract\UniExtract.exe` |
| game | AssetRipper 2.0.0 | `Unpackers-Game\AssetRipper\AssetRipper.GUI.Free.exe` |
| game | Il2CppDumper 6.7.46 | `Unpackers-Game\Il2CppDumper-net6-win-v6.7.46\Il2CppDumper.exe` |
| game | GoReSym | `Unpackers-Game\GoReSym\GoReSym.exe` |
| net | tshark 4.6.8 | `Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe` |
| host | System Informer | `System-Forensics\systeminformer\amd64\SystemInformer.exe` |

How to use: `docs/TOOLS_INDEX.md`. Combinations: `docs/EXPERT_PLAYBOOK.md`. CLI sessions: `docs/SMARTCLI.md`.

Smoke: `powershell -File scripts\smoke-tools.ps1` then `scripts\smoke-mcp.ps1`. CLI PASS 2026-09-20 (JADX 1.5.6, Apktool 3.0.3, radare2 6.2.2). MCP backends need their `.venv` (router starts them on demand).
