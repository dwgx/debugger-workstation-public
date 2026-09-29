#Requires -Version 5.1
<#
.SYNOPSIS
  Agent dnSpy without GUI. Uses dnSpy.Console.exe (ICSharpCode.Decompiler).
  Live MCP: router backend dnspy (DnSpyMcpServer.exe) — also headless, no dnSpy window.
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [string]$OutDir = '',
    [string]$InstallRoot = '',
    [string]$Type = '',
    [int]$TimeoutMs = 120000
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$exe = Join-Path $InstallRoot 'Static-Reversing\dnSpyEx\dnSpy.Console.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "missing $exe" }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }
$Sample = (Resolve-Path -LiteralPath $Sample).Path
if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP ('dnspy-out-' + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if ($Type) {
    $argStr = "-t `"$Type`" --no-color `"$Sample`""
} else {
    $argStr = "-o `"$OutDir`" --no-color `"$Sample`""
}
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = $argStr
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
if (-not $p.WaitForExit($TimeoutMs)) {
    try { $p.Kill() } catch {}
    @{ ok = $false; tool = 'dnspy'; error = "TIMEOUT ${TimeoutMs}ms"; sample = $Sample } | ConvertTo-Json -Compress
    exit 1
}
$cs = @(Get-ChildItem -LiteralPath $OutDir -Filter '*.cs' -Recurse -ErrorAction SilentlyContinue)
@{
    ok      = $true
    tool    = 'dnspy'
    sample  = $Sample
    outdir  = $OutDir
    type    = $Type
    csFiles = $cs.Count
    mcp     = 'router backend dnspy (DnSpyMcpServer, no GUI)'
} | ConvertTo-Json -Compress
exit 0
