#Requires -Version 5.1
<#
.SYNOPSIS
  Agent-safe FLOSS. Static strings always. Emulation (stack/tight/decoded)
  is opt-in and hard-capped: those modes hung >45s on a 576KB PE (7z.exe).
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [switch]$Emulate,
    [int]$EmulateMs = 30000
)
$ErrorActionPreference = 'Stop'
$floss = Join-Path (Split-Path $PSScriptRoot) 'Static-Reversing\FLOSS\floss.exe'
if (-not (Test-Path -LiteralPath $floss)) { throw "missing $floss" }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }

Write-Host 'FLOSS --only static'
& $floss --only static -q -- $Sample
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not $Emulate) { exit 0 }

Write-Host "FLOSS emulate cap ${EmulateMs}ms"
$p = Start-Process -FilePath $floss -ArgumentList @('--no', 'static', '-q', '--', $Sample) -NoNewWindow -PassThru
if (-not $p.WaitForExit($EmulateMs)) {
    try { $p.Kill() } catch {}
    Write-Host 'FLOSS emulate TIMEOUT; static results above are complete'
    exit 0
}
exit $p.ExitCode
