#Requires -Version 5.1
<#
.SYNOPSIS
  Smoke debugger-router list_backends plus a few backends that do not need a GUI session.
#>
param([string]$InstallRoot = '')

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$py = Join-Path $InstallRoot 'mcp\debugger-router\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { throw "missing router venv: $py" }
$env:DEBUGGER_ROOT = $InstallRoot
& $py (Join-Path $PSScriptRoot 'smoke_mcp.py')
exit $LASTEXITCODE
