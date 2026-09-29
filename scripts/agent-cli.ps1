#Requires -Version 5.1
<#
.SYNOPSIS
  CLI-Anything-style dispatcher for debugger-station. JSON stdout. No GUI.
  No args: catalog. First arg: ghidra|ida|jadx|dnspy|ce|mobsf|intel
#>
param(
    [Parameter(Position = 0)][string]$Tool = '',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

$catalog = @(
    @{ tool = 'ghidra'; script = 'ghidra-headless.ps1'; cli = 'analyzeHeadless + ExportDecompile.java'; gui = 'ghidraRun.bat + GhidraMCP plugin :8080'; mcp = 'router ghidra (HTTP 8080; start -Http or GUI plugin)' }
    @{ tool = 'ida'; script = 'ida-cli.ps1'; cli = 'idat -A -S export_decompiled.py'; gui = 'ida.exe'; mcp = 'router ida = idalib-mcp --stdio (do not add a second IDA MCP)' }
    @{ tool = 'jadx'; script = 'jadx-decompile.ps1'; cli = 'jadx.bat -d out'; gui = 'jadx-gui + jadx-ai-mcp plugin'; mcp = 'router jadx (list ok; HTTP plugin needs GUI)' }
    @{ tool = 'dnspy'; script = 'dnspy-console.ps1'; cli = 'dnSpy.Console.exe -o out'; gui = 'dnSpy.exe'; mcp = 'router dnspy = DnSpyMcpServer.exe (no window)' }
    @{ tool = 'ce'; script = 'ce-agent.ps1'; cli = 'none; JSON status + x64dbg fallback'; gui = 'cheatengine-x86_64.exe + autorun ce_mcp_bridge.lua'; mcp = 'router cheatengine needs named pipe; else x64dbg' }
    @{ tool = 'mobsf'; script = 'mobsf-agent.ps1'; cli = 'REST or apktool local-static'; gui = 'MobSF web UI not required'; mcp = 'router mobsf needs MOBSF_API_KEY (local, not VT)' }
    @{ tool = 'intel'; script = 'intel-agent.ps1'; cli = 'SHA256+DIE+capa; VT hash lookup if key'; gui = 'n/a'; mcp = 'router virustotal needs VIRUSTOTAL_API_KEY' }
    @{ tool = 'web-reverse'; script = 'web-reverse-lab.ps1'; cli = 'node tools/loop.mjs (CDP capture -> deobfuscate -> replay -> bot-detection report)'; gui = 'n/a (headless lab Chrome, disposable profile)'; mcp = 'none; raw CDP over the devtools websocket, zero npm deps' }
)

if (-not $Tool -or $Tool -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok      = $true
        tool    = 'catalog'
        pattern = 'CLI-Anything: Click-less PowerShell, JSON stdout, SKILL table. HKUDS/CLI-Anything has no IDA/Ghidra/JADX harness — this station wraps them.'
        clientMcp = 'debugger-router only'
        items   = $catalog
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

$map = @{
    ghidra = 'ghidra-headless.ps1'
    ida    = 'ida-cli.ps1'
    jadx   = 'jadx-decompile.ps1'
    dnspy  = 'dnspy-console.ps1'
    ce     = 'ce-agent.ps1'
    mobsf  = 'mobsf-agent.ps1'
    intel  = 'intel-agent.ps1'
    'web-reverse' = 'web-reverse-lab.ps1'
}
$key = $Tool.ToLowerInvariant()
if (-not $map.ContainsKey($key)) {
    @{ ok = $false; error = "unknown tool $Tool"; tools = @($map.Keys) } | ConvertTo-Json -Compress
    exit 2
}
$path = Join-Path $here $map[$key]
if (-not $Rest) { $Rest = @() }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path @Rest
exit $LASTEXITCODE
