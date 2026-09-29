#Requires -Version 5.1
<#
.SYNOPSIS
  Agent IDA via idat (text/autonomous). No GUI. Hex-Rays when licensed.
  Interactive queries: debugger-router backend ida (idalib-mcp --stdio). Do not enable a second IDA MCP.
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [string]$OutDir = '',
    [string]$InstallRoot = '',
    [int]$MaxFunctions = 0,
    [switch]$NoAnalysis,
    [int]$TimeoutMs = 600000
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$idat = Join-Path $InstallRoot 'Static-Reversing\IDA\idat.exe'
if (-not (Test-Path -LiteralPath $idat)) {
    $idat = 'D:\Software\Tool\Debugger\IDA Professional 9.2\idat.exe'
}
if (-not (Test-Path -LiteralPath $idat)) { throw "missing idat.exe (do not download IDA)" }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }
$Sample = (Resolve-Path -LiteralPath $Sample).Path
if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP ('ida-out-' + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$script = Join-Path $PSScriptRoot 'ida\export_decompiled.py'
if (-not (Test-Path -LiteralPath $script)) { throw "missing $script" }

$work = Join-Path $env:TEMP ('ida-work-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$local = Join-Path $work ([IO.Path]::GetFileName($Sample))
Copy-Item -LiteralPath $Sample -Destination $local -Force
$idb = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($Sample) + '.i64')
$log = Join-Path $OutDir 'idat.log'
$maxArg = if ($MaxFunctions -gt 0) { " $MaxFunctions" } else { '' }
# -A no dialogs, -c new DB, -o work dir so we never write next to the sample.
# Start-Process ArgumentList re-splits on spaces; use ProcessStartInfo.Arguments.
$sArg = "$script $OutDir$maxArg"
$na = $(if ($NoAnalysis) { '-a ' } else { '' })
$argStr = "-A -c $na-L`"$log`" -o`"$idb`" -S`"$sArg`" `"$local`""
Write-Host "IDA $idat $argStr" -ForegroundColor DarkGray
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $idat
$psi.Arguments = $argStr
$psi.WorkingDirectory = $work
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
if (-not $p.WaitForExit($TimeoutMs)) {
    try { $p.Kill() } catch {}
    @{ ok = $false; tool = 'ida'; error = "TIMEOUT ${TimeoutMs}ms"; log = $log } | ConvertTo-Json -Compress
    exit 1
}
$summary = Join-Path $OutDir 'summary.json'
if (Test-Path -LiteralPath $summary) {
    Get-Content -LiteralPath $summary -Raw
    exit $p.ExitCode
}
@{
    ok     = ($p.ExitCode -eq 0)
    tool   = 'ida'
    exit   = $p.ExitCode
    outdir = $OutDir
    log    = $log
} | ConvertTo-Json -Compress
exit $p.ExitCode
