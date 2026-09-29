#Requires -Version 5.1
<#
.SYNOPSIS
  Agent-callable JADX CLI decompile. No GUI. No MCP plugin required.
#>
param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [string]$OutDir = '',
    [string]$InstallRoot = ''
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$jadx = Join-Path $InstallRoot 'Mobile-Android\jadx\bin\jadx.bat'
if (-not (Test-Path -LiteralPath $jadx)) { throw "missing $jadx" }
if (-not (Test-Path -LiteralPath $InputPath)) { throw "missing input $InputPath" }
if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP ('jadx-out-' + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& cmd.exe /c "`"$jadx`" -d `"$OutDir`" --show-bad-code `"$InputPath`""
$code = $LASTEXITCODE
$java = @(Get-ChildItem -LiteralPath $OutDir -Filter '*.java' -Recurse -ErrorAction SilentlyContinue)
[ordered]@{
    ok       = ($code -eq 0)
    tool     = 'jadx'
    sample   = $InputPath
    outdir   = $OutDir
    javaFiles = $java.Count
    gui      = 'jadx-gui + plugins/jadx-ai-mcp-*.jar for live HTTP MCP'
} | ConvertTo-Json -Compress
exit $code
