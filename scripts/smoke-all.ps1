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
    'gate-selftest'      = @{ file = $PSExe; args = @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/gate.ps1','-Action','Selftest'); expect = 'GATE SELFTEST OK' }
    'mission-selftest'   = @{ file = $PSExe; args = @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/mission.ps1','-Action','Selftest'); expect = 'MISSION SELFTEST OK' }
    'ghidra-failopen'     = @{ file = $PSExe; args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts/ghidra-failopen-regress.ps1'); expect = 'LOOP CLOSED' }
    'il2cpp-probe'       = @{ file = $PSExe; args = @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/il2cpp-probe.ps1'); expect = 'IL2CPP ABSENT' }
    'emulation-probe'    = @{ file = $PSExe; args = @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/emulation-probe.ps1'); expect = 'PCODE EMULATION BLOCKED' }
    'web-reverse'         = @{ file = $Node; args = @('web-reverse/tools/loop.mjs');  expect = 'LOOP CLOSED' }
    'web-reverse-ast'     = @{ file = $Node; args = @('web-reverse/tools/loop2.mjs'); expect = 'STATIC TOOLCHAIN PROVEN' }
    'crypto-lab'          = @{ file = $Node; args = @('crypto-lab/tools/loop.mjs');   expect = 'JSON-SUMMARY' }
    'net-reverse'         = @{ file = $Node; args = @('net-reverse/tools/loop.mjs'); expect = 'LANE CLOSED' }
    'net-trustcheck'      = @{ file = $Node; args = @('net-reverse/tools/trustcheck.mjs'); expect = 'ISOLATION HELD' }
    'crackme-corpus'      = @{ file = $Py;   args = @('crackme-corpus/tools/loop.py'); expect = 'CORPUS CLOSED' }
    'forensics-lab'       = @{ file = $Node; args = @('forensics-lab/tools/loop.mjs'); expect = 'LOOP CLOSED' }
    'managed-lab'         = @{ file = $Node; args = @('managed-lab/tools/loop.mjs');   expect = 'JSON-SUMMARY' }
    'mobile-lab'          = @{ file = $Node; args = @('mobile-lab/tools/loop.mjs');    expect = 'LOOP CLOSED' }
    'native-lab-ida'      = @{ file = $Node; args = @('native-lab/tools/loop.mjs');   expect = 'LOOP CLOSED' }
    'agent-contract'      = @{ file = $Py;   args = @('scripts/eval-agent-contract.py'); expect = 'eval-agent-contract: PASS' }
    'backend-consistency' = @{ file = $Py;   args = @('scripts/check_backend_consistency.py'); expect = 'consistency OK' }
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
    # Look for the verdict token on ANY line, and show the most specific one.
    #
    # Taking only the LAST matching line was a bug, and it reported four green labs
    # as red. `JSON-SUMMARY {...}` is printed after `LOOP CLOSED`, so selecting the last
    # hit meant a lab that had closed cleanly matched JSON-SUMMARY and failed the
    # expectation for its own verdict line. Four of fifteen probes went red while every
    # one of them had exited 0 with pass:N fail:0.
    #
    # The lesson is the same one the Ghidra fail-open taught, in a different costume: my
    # instrument was wrong, not the subject. A smoke test that reports red for healthy
    # labs is worse than no smoke test, because it trains the reader to ignore it.
    # The scan pattern is DERIVED from each probe's own `expect`, plus a few generic
    # verdict shapes.
    #
    # It used to be a hardcoded literal list, and that is the third time this harness has
    # produced a wrong verdict about its own probes: first by taking only the LAST match so
    # JSON-SUMMARY shadowed LOOP CLOSED, then two expectations that were simply wrong, and
    # now by adding two probes whose `expect` values were never in the scan list -- so the
    # harness reported "IL2CPP ABSENT" as a FAILURE while printing that exact string a few
    # lines above it.
    #
    # A checklist and the thing it is a checklist for must not be able to drift apart.
    $generic = @('JSON-SUMMARY', 'LOOP CLOSED', 'LANE CLOSED', 'ISOLATION HELD', 'CORPUS CLOSED',
                 'REGISTRY CLEAN', 'SELFTEST OK')
    $expectTokens = @($probes.Values | ForEach-Object { $_.expect } | Where-Object { $_ })
    $pattern = (@($generic) + @($expectTokens) | Where-Object { $_ } | Sort-Object -Unique) -join '|'
    $hits = $out -split "`n" | Select-String -Pattern $pattern
    $seen = @{}
    foreach ($h in $hits) { $seen[$h.ToString().Trim()] = $true }
    $allSummary = ($seen.Keys | Sort-Object) -join ' | '
    $matched = @($hits | Where-Object { $_.ToString() -like "*$($p.expect)*" }).Count -gt 0

    # Two independent things must hold: the process succeeded, AND the lab printed the
    # line it claims to print. Requiring only the exit code is the mistake that made a
    # Ghidra import failure look like a pass.
    $ok = ($rc -eq 0) -and $matched
    if ($ok) { $pass++ } else { $fail++ }

    $lastLine = (($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -replace '\s+', ' ').Trim()
    $tail = if ($lastLine.Length -gt 90) { $lastLine.Substring(0, 90) } else { $lastLine }

    $results += [ordered]@{
        ok       = $ok
        probe    = $name
        exit     = $rc
        seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        expected = $p.expect
        matched  = $matched
        summary  = $allSummary
        tail     = if ($ok) { '' } else { $tail }
    }

    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("  {0}  {1,-22} {2,6}s  {3}" -f $tag, $name, [math]::Round($sw.Elapsed.TotalSeconds, 1), $allSummary)
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
