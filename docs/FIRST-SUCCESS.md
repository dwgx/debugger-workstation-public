# First success: one command, no external MCP backend

This is a **real, bounded product demonstration** for a new user or coding agent.
It creates a harmless one-packet DNS PCAP, runs the repository's PCAP parser,
and independently checks the frozen six-case plan. It does not download or
execute unknown binaries, need an API key, run a GUI, capture traffic, or
install a backend. Requires Python **3.12+** and a new output directory.

## Windows PowerShell quickstart

From a fresh public clone:

```powershell
git clone https://github.com/dwgx/debugger-workstation-public.git
Set-Location debugger-workstation-public
$proof = Join-Path $env:TEMP ('ws-first-success-' + [guid]::NewGuid().ToString('N'))
python -X utf8 -B scripts/first-success.py --output $proof
if ($LASTEXITCODE -ne 0) { throw "First-success demo failed; see $proof" }
Get-Content -LiteralPath (Join-Path $proof 'FIRST-SUCCESS.json')
```

Expected final CLI result: `"verdict": "PROFILE_PASS"`, both runner/verifier
exit codes zero, and a retained `FIRST-SUCCESS.json`. If a condition fails,
the command exits nonzero and preserves a failed evidence directory.

For a downloaded **source-release ZIP** with no Git checkout, supply the exact
40-hex commit identified by that release's `SOURCE-BUNDLE.json`. Example for
the separately versioned 2026-11-19 release (only if you are using that source):

```powershell
python -X utf8 -B scripts/first-success.py --output $proof --source-commit 51b1f535eb44d8bb2f985f1d198f33c9178f17ec
```

If your checkout has Git metadata, the program reads its actual HEAD; a
conflicting supplied commit is rejected. The HEAD is **provenance**, not proof
that a dirty checkout equals those Git bytes. Source hashes are frozen in the
plan; the controller records its own before/after file hashes.

## What the proof contains

`caller-freeze.json` stores the plan digest and the exact allowed argv.
`CONTROLLER-INTENT.json` is written **before** the runner. A controller guard
recalculates the plan digest and refuses any substituted command.
`runner.stdout.bin`, `runner.stderr.bin`, `verifier.stdout.bin` and
`verifier.stderr.bin` retain raw direct subprocess outputs.
`runs/attempts/<attempt-id>/terminal.json` is produced by the real bounded
runner; `FIRST-SUCCESS.json` records actual exit codes, source identity and
the verdict. The original runner captures its own execution artifacts,
semantic values, negative control and cleanup.

The six frozen checks are output integrity, expected execution exit, the PCAP
parser's `ok=true`, exactly one packet, exactly one DNS query and an
intentionally wrong two-packet claim that the verifier must reject.

**Important limitations:** this demonstrates only an *authored offline PCAP
parser invocation*. It is not live packet capture, Router/MCP-provider
acceptance, Skill auto-selection, general PE/APK decompilation, deployment of
all 20 backends, or a whole-workstation green release. The top-level Python
controller supervises direct subprocesses; the underlying selected runner
retains its own platform-specific cleanup limitations.

An existing output directory is rejected to prevent overwriting prior
evidence. Use a new directory for every retry. The script does not delete
prior attempts. Tests include a real PCAP execution plus command injection,
plan tampering, output collision and missing non-Git provenance cases.

## 简体中文

安装好 Python 3.12 及以上版本后，`git clone` 公开仓库，在仓库目录运行
`python -X utf8 -B scripts/first-success.py --output <新的外部目录>`。
它会产生自建 DNS PCAP、冻结计划、真实执行结果和独立验证报告。看到
`PROFILE_PASS` 才说明**这一个离线解析 demo**成功。

不用先安装 IDA、Ghidra、radare2、APKTool、OMP 或 MCP 服务。失败时保留
原始回执，不将 `isError`、非零退出、缺失结果或未执行功能改写成成功。
真实 MCP 靶场请参阅 [TOOL_LAB.md](TOOL_LAB.md)；20 个后端的具体覆盖见
[TOOL_LAB_COVERAGE.md](TOOL_LAB_COVERAGE.md)。
