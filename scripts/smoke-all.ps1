#Requires -Version 5.1
<#
.SYNOPSIS
  Full-station smoke — runs every capability probe the capability registry claims, in one
  read-only pass, and prints a single verdict.

.DESCRIPTION
  The table in `manifests/capabilities.json` is the contract; this is the shortcut that
  re-checks all of it at once. It runs each entry's `probe.command`, captures the lab's
  OWN summary line, and reports pass/fail per probe plus a JSON-SUMMARY.

  Written in PowerShell rather than bash after two failed attempts at a bash version.
  On this box `bash` resolves to C:\Windows\system32\bash.exe, which is WSL2: its root is
  a Linux filesystem and `D:` is not there at all. So a bash script could not see the
  repo, could not stat an interpreter, and reported 15/15 failures that had nothing to do
  with any lab. A smoke test that goes red for an environment reason is worse than no
  smoke test, because the red is indistinguishable from real breakage.

  It also addresses interpreters by absolute path rather than trusting PATH, because the
  PATH this process inherits is not guaranteed to resolve `node`, `python` or
  `powershell.exe` in a child context.

.PARAMETER Include
  Extra probe names to run, in addition to the default set.

.EXAMPLE
  powershell -File scripts\smoke-all.ps1
  powershell -File scripts\smoke-all.ps1 -Json

.NOTES
  Exit codes: 0 = every probe closed · 1 = at least one probe failed · 2 = the host is
  missing an interpreter, which is NOT a lab result and is reported as such.

  Read-only. Starts no service, starts no container, and touches no network target.
#>
[CmdletBinding()]
param([string[]]$Include = @(), [switch]$Json)

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Node = 'D:\Software\Developer\nodejs\node.exe'
$Py   = 'D:\Software\Developer\Python314\python.exe'
$PSExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

foreach ($b in @($Node, $Py, $PSExe)) {
    if (-not (Test-Path -LiteralPath $b)) {
        @{ ok = $false; error = "interpreter not found at $b -- host problem, not a lab result" } | ConvertTo-Json -Compress
        exit 2
    }
}

# name -> { file, args, expect }
$probes = [ordered]@{
    'registry-selftest'   = @{ file = $Py;  args = @('scripts/registry-verify.py', '--selftest'); expect = 'SELFTEST OK' }
    'registry-validate'   = @{ file = $Py;  args = @('scripts/registry-verify.py');               expect = 'REGISTRY CLEAN' }
    'ghidra-failopen'     = @{ file = $PSExe; args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts/ghidra-failopen-regress.ps1'); expect = 'LOOP CLOSED' }
    'web-reverse'         = @{ file = $Node; args = @('web-reverse/tools/loop.mjs');  expect = 'LOOP CLOSED' }
    'web-reverse-ast'     = @{ file = $Node; args = @('web-reverse/tools/loop2.mjs'); expect = 'LOOP CLOSED' }
    'crypto-lab'          = @{ file = $Node; args = @('crypto-lab/tools/loop.mjs');   expect = 'JSON-SUMMARY' }
    'net-reverse'         = @{ file = $Node; args = @('net-reverse/tools/loop.mjs'); expect = 'LANE CLOSED' }
    'net-trustcheck'      = @{ file = $Node; args = @('net-reverse/tools/trustcheck.mjs'); expect = 'ISOLATION HELD' }
    'crackme-corpus'      = @{ file = $Py;   args = @('crackme-corpus/tools/loop.py'); expect = 'CORPUS CLOSED' }
    'forensics-lab'       = @{ file = $Node; args = @('forensics-lab/tools/loop.mjs'); expect = 'LOOP CLOSED' }
    'managed-lab'         = @{ file = $Node; args = @('managed-lab/tools/loop.mjs');   expect = 'JSON-SUMMARY' }
    'mobile-lab'          = @{ file = $Node; args = @('mobile-lab/tools/loop.mjs');    expect = 'LOOP CLOSED' }
    'native-lab-ida'      = @{ file = $Node; args = @('native-lab/tools/loop.mjs');   expect = 'LOOP CLOSED' }
    'agent-contract'      = @{ file = $Py;   args = @('scripts/eval-agent-contract.py'); expect = 'PASS' }
    'backend-consistency' = @{ file = $Py;   args = @('scripts/check_backend_consistency.py'); expect = 'OK' }
}

if ($Include) {
    foreach ($n in $Include) {
        if (-not $probes.Contains($n)) { Write-Host "unknown probe: $n" -ForegroundColor Yellow }
    }
}

$results = @()
$pass = 0; $fail = 0

Write-Host ('=' * 78)
Write-Host ("full-station smoke  " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Write-Host ('=' * 78)

foreach ($name in $probes.Keys) {
    if ($Include.Count -and $name -notin $Include) { continue }
    $p = $probes[$name]
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = & $p.file @($p.args) 2>&1 | Out-String
    $rc = $LASTEXITCODE
    $sw.Stop()

    $summary = ($out -split "`n" |
                Select-String -Pattern 'JSON-SUMMARY|LOOP CLOSED|LANE CLOSED|ISOLATION HELD|CORPUS CLOSED|REGISTRY CLEAN|SELFTEST OK' |
                Select-Object -Last 1)
    $summaryText = if ($summary) { $summary.ToString().Trim() } else { '' }

    # Two independent things must hold: the process succeeded, AND the lab printed the
    # line it is supposed to print. Requiring only the exit code is the mistake that
    # made a Ghidra import failure look like a pass.
    $ok = ($rc -eq 0) -and ($summaryText -like "*$($p.expect)*")
    if ($ok) { $pass++ } else { $fail++ }

    $results += [ordered]@{
        ok       = $ok
        probe    = $name
        exit     = $rc
        seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        summary  = $summaryText
        tail     = if ($summaryText) { '' } else { (($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(90, (($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -replace '\s+', ' ').Trim().Length)) }
    }

    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("  {0}  {1,-22} {2,6}s  {3}" -f $tag, $name, [math]::Round($sw.Elapsed.TotalSeconds, 1), $summaryText)
}

Write-Host ''
Write-Host ('=' * 78)
Write-Host ("SMOKE SUMMARY  pass=$pass fail=$fail")
Write-Host ('=' * 78)
foreach ($r in $results) {
    if (-not $r.ok) { Write-Host ("  FAIL|$($r.probe)|exit=$($r.exit)|$($r.summary)$($r.tail)") -ForegroundColor Red }
}

$summaryObj = [ordered]@{ total = $pass + $fail; pass = $pass; fail = $fail }
Write-Host ''
Write-Host ('JSON-SUMMARY ' + ($summaryObj | ConvertTo-Json -Compress))
if ($Json) {
    [ordered]@{ ok = ($fail -eq 0); summary = $summaryObj; probes = $results } | ConvertTo-Json -Depth 6
}

if ($fail -gt 0) { exit 1 }
exit 0
