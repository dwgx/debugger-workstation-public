# Triage (unknown sample, first minutes)

Do not run the sample on the host — use the isolated VM.

Root: this clone (`local.json` `install_root`). Commands below are relative to it.

## 1. Classify

```
Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe -e <sample>
Static-Reversing\capa\capa.exe -q <sample>
powershell -File scripts\floss-agent.ps1 -Sample <sample>
```

FLOSS: default is `--only static` (~1.5s on a 576KB PE). `stack` / `tight` / `decoded` emulate and timed out at 45s on `7z.exe`. Pass `-Emulate` only when Owner names decoded strings.

| Signal | Next |
|---|---|
| entropy high / UPX / Themida | unpack first (`upx -d` or dynamic). Do not decompile the stub. |
| imports `mscoree.dll` | .NET → ILSpy / dnSpyEx |
| `.gopclntab` | Go → GoReSym |
| `_MEIPASS` | PyInstaller → pyinstxtractor-ng |
| `GameAssembly.dll` + `global-metadata.dat` | IL2CPP → Il2CppDumper |
| `.apk` / `classes.dex` | Android → JADX + Apktool |
| PE native, no packer | `scripts\ghidra-headless.ps1` or `scripts\ida-cli.ps1` (no GUI). radare2 REPL if needed |
| `.dll` / `mscoree` | `scripts\dnspy-console.ps1` or `ilspycmd` |
| `.apk` | `scripts\jadx-decompile.ps1` then `scripts\mobsf-agent.ps1` |
| reputation | `scripts\intel-agent.ps1` (no VT key required) |

## 2. Then one lane

Deep combinations: [`docs/EXPERT_PLAYBOOK.md`](../../../docs/EXPERT_PLAYBOOK.md). Paths: [`arsenal.md`](arsenal.md). MCP: [`mcp-router.md`](mcp-router.md).

GUI tools are not SmartCLI. CLI REPL (r2, objection, tshark) may use SmartCLI — one PTY, close when done.
