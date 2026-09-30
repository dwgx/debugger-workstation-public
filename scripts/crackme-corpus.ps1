#Requires -Version 5.1
<#
.SYNOPSIS
  crackme-corpus dispatcher for agent-cli.ps1. JSON stdout, human transcript on
  stderr, exit code from the runner.

.DESCRIPTION
  Wraps crackme-corpus\tools\loop.py so the corpus is reachable the same way as
  every other lab on this station:

      powershell -File scripts\crackme-corpus.ps1
      powershell -File scripts\crackme-corpus.ps1 --list
      powershell -File scripts\crackme-corpus.ps1 --only c03

  The runner is the capability. It builds every challenge, decompiles it, runs
  the solver, and re-runs each solver against a deliberately wrong answer to
  prove the comparison can fail. It exits 9 if anything is unsolved.

  Python is resolved from the station's developer tree first, then PATH.
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'

$root = Join-Path $PSScriptRoot '..\crackme-corpus'
$runner = Join-Path $root 'tools\loop.py'
if (-not (Test-Path -LiteralPath $runner)) {
    [ordered]@{ ok = $false; error = 'crackme-corpus runner not found'; expected = $runner } |
        ConvertTo-Json -Compress
    exit 2
}

$python = $null
foreach ($cand in @(
        'D:\Software\Developer\Python314\python.exe',
        'C:\Program Files\Python310\python.exe')) {
    if (Test-Path -LiteralPath $cand) { $python = $cand; break }
}
if (-not $python) {
    $probe = Get-Command python -ErrorAction SilentlyContinue
    if ($probe) { $python = $probe.Source }
}
if (-not $python) {
    [ordered]@{ ok = $false; error = 'python not found' } | ConvertTo-Json -Compress
    exit 2
}

if (-not $Rest) { $Rest = @() }

# The runner prints its PASS table to stdout and is also what a human reads, so
# let it through. Machine consumption uses --json.
& $python $runner @Rest
$code = $LASTEXITCODE

[ordered]@{
    ok      = ($code -eq 0)
    lab     = 'crackme-corpus'
    python  = $python
    exit    = $code
    summary = if ($code -eq 0) { 'CORPUS CLOSED: every challenge solved from its binary, every solver shown to reject a wrong answer' }
              else { "NOT CLOSED (exit $code) -- see the table above" }
} | ConvertTo-Json -Compress

exit $code
