#Requires -Version 5.1
<#
.SYNOPSIS
  Manifest-wide inventory and bounded CLI version checks. No GUI/driver/sample execution.
  Presence remains distinct from VERSION_VERIFIED; a matching banner with nonzero exit fails.
  Use -InventoryOnly for a report without starting tools. Python 3.10+ is required.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = '',
    [string]$Python = '',
    [string[]]$Tool = @(),
    [double]$Timeout = 20,
    [string]$Report = '',
    [switch]$InventoryOnly,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
if (-not $Python) {
    $command = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { $command = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $command) { Write-Error 'Python 3.10+ was not found; supply -Python.'; exit 2 }
    $Python = $command.Source
}
$probeArgs = @('-X', 'utf8', '-B', (Join-Path $PSScriptRoot 'smoke-tools.py'), '--timeout', $Timeout.ToString([Globalization.CultureInfo]::InvariantCulture))
if ($InstallRoot) { $probeArgs += @('--install-root', $InstallRoot) }
if (-not $InventoryOnly) { $probeArgs += '--probe' }
if ($Json) { $probeArgs += '--json' }
if ($Report) { $probeArgs += @('--report', $Report) }
foreach ($name in $Tool) { $probeArgs += @('--tool', $name) }
& $Python @probeArgs
exit $LASTEXITCODE
