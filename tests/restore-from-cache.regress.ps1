#requires -Version 5.1
<#
.SYNOPSIS
  Regression harness for cache restore freshness and staging ownership.

.DESCRIPTION
  Builds a fresh, unique install root per case, runs the script under test as a
  child of the current exact PowerShell executable, and asserts semantic observations.
  Point -ScriptPath at the OLD (preimage) copy to watch the leak cases FAIL;
  point it at the FIXED copy to watch them PASS. Same harness, same assertions.

  Sentinels are inert text bytes. Nothing is executed, no driver is installed,
  the harness writes only within -WorkDir. Candidate cleanup may remove only its
  own new staging directories. Archive fixtures are read-only; no fixture exe is run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [Parameter(Mandatory = $true)][string]$ArchivesDir
)

$ErrorActionPreference = 'Stop'
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
$ArchivesDir = (Resolve-Path -LiteralPath $ArchivesDir).Path
if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $ScriptPath) 'resolve-locale.ps1'))) {
    throw "resolve-locale.ps1 must sit next to the script under test: $ScriptPath"
}

if ($PSVersionTable.PSVersion.Major -ge 6) {
    $psExe = (Join-Path $PSHOME 'pwsh.exe')
    $shellName = 'pwsh'
} else {
    $psExe = Join-Path $PSHOME 'powershell.exe'
    $shellName = 'powershell-5.1'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runRoot = Join-Path $WorkDir ('regress-' + $stamp + '-' + (Get-Random))
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
Write-Output ('RUNROOT=' + $runRoot)
Write-Output ('SHELL=' + $shellName + ' ' + $PSVersionTable.PSVersion.ToString())
Write-Output ('TARGET=' + $ScriptPath)

$cases = New-Object System.Collections.Generic.List[object]

function Get-RelTree([string]$Base) {
    if (-not (Test-Path -LiteralPath $Base)) { return @('<absent>') }
    $items = @(Get-ChildItem -LiteralPath $Base -Recurse -Force -ErrorAction SilentlyContinue)
    if ($items.Count -eq 0) { return @('<empty>') }
    return @($items | ForEach-Object { $_.FullName.Substring($Base.Length + 1) } | Sort-Object)
}


function Get-Fingerprint([string]$Base) {
    if (-not (Test-Path -LiteralPath $Base)) { return '<absent>' }
    $rows = @(Get-ChildItem -LiteralPath $Base -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($Base.Length + 1)
        if ($_.PSIsContainer) { 'D:' + $rel }
        else { 'F:' + $rel + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    } | Sort-Object)
    return ($rows -join ';')
}
function Write-Inert([string]$Path, [string]$Text) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    [IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}
function Get-StagingDirs([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Directory -Force |
        Where-Object { $_.Name -like '_cache-unpack*' } | Select-Object -ExpandProperty Name | Sort-Object)
}

function Invoke-Restore {
    param([string]$Tag, [string]$Archive, [string]$InstallRoot, [switch]$Apply)
    $log = Join-Path $runRoot ($Tag + '.log')
    $argList = @('-NoProfile', '-NonInteractive', '-File', $ScriptPath,
                 '-ArchivePath', $Archive, '-InstallRoot', $InstallRoot)
    if ($Apply) { $argList += '-Apply' }
    # Child stderr must not escalate to a terminating NativeCommandError under EAP=Stop.
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $psExe @argList *> $log
    $ErrorActionPreference = $oldEap
    $code = $LASTEXITCODE
    $text = ''
    if (Test-Path -LiteralPath $log) { $text = [System.IO.File]::ReadAllText($log) }
    return @{ exit = $code; log = $text; logPath = $log }
}

function New-Case([string]$Name) {
    return @{
        name = $Name
        asserts = New-Object System.Collections.Generic.List[object]
        observations = New-Object System.Collections.Generic.List[object]
        logs = @{}
        exit = $null
        snapshots = @{}
    }
}
function Add-Assert($Case, [string]$Name, [bool]$Ok, [string]$Observed) {
    $Case.asserts.Add([pscustomobject]@{ name = $Name; pass = $Ok; observed = $Observed }) | Out-Null
}
function Add-Obs($Case, [string]$Name, [string]$Observed) {
    $Case.observations.Add([pscustomobject]@{ name = $Name; observed = $Observed }) | Out-Null
}
function Finish-Case($Case) {
    $failed = @($Case.asserts | Where-Object { -not $_.pass })
    $Case['verdict'] = $(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })
    $Case['failedAsserts'] = @($failed | ForEach-Object { $_.name })
    $cases.Add([pscustomobject]$Case) | Out-Null
    Write-Output ('CASE ' + $Case.name + ' -> ' + $Case.verdict)
}

$archA = Join-Path $ArchivesDir 'A.7z'
$archB = Join-Path $ArchivesDir 'B.7z'
$archC = Join-Path $ArchivesDir 'corruptC.7z'
$uniDirName = -join @([char]0x7A7A, [char]0x683C, ' ', [char]0x76EE, [char]0x5F55)
$uniFileName = -join @([char]0x6863, [char]0x6848, ' A.7z')
$archUni = Join-Path (Join-Path $ArchivesDir $uniDirName) $uniFileName

# ---------------------------------------------------------------- CASE 1: dry-run
$c = New-Case 'dry-run-no-side-effects'
$ir = Join-Path $runRoot 'install-dryrun'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
$before = (Get-RelTree $ir) -join ';'
$r = Invoke-Restore -Tag 'dryrun' -Archive $archA -InstallRoot $ir
$c.exit = $r.exit
$c.logs['dryrun'] = $r.logPath
$after = (Get-RelTree $ir) -join ';'
Add-Assert $c 'exit code is 0' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'stdout announces dry-run' ($r.log.Contains('dry-run')) ('found=' + $r.log.Contains('dry-run'))
Add-Assert $c 'stdout tells caller to re-run with -Apply' ($r.log.Contains('Re-run with -Apply to extract.')) ('found=' + $r.log.Contains('Re-run with -Apply to extract.'))
Add-Assert $c 'install root untouched by dry-run (no side effects)' ($after -eq $before) ('before=[' + $before + '] after=[' + $after + ']')
Finish-Case $c

# ------------------------------------------------------- CASE 2: single A baseline
$c = New-Case 'single-A-baseline'
$ir = Join-Path $runRoot 'install-singleA'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
$r = Invoke-Restore -Tag 'singleA' -Archive $archA -InstallRoot $ir -Apply
$c.exit = $r.exit
$c.logs['singleA'] = $r.logPath
$unpack = Join-Path $ir '_cache-unpack'
$snapUnpack = Get-RelTree $unpack
$snapCe = Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')
$snapStage = Get-RelTree (Join-Path $ir '_download-stage')
$c.snapshots['unpack'] = $snapUnpack; $c.snapshots['installCE'] = $snapCe; $c.snapshots['stage'] = $snapStage
Add-Assert $c 'exit code is 0' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'archive A installer selected (npcap)' ($r.log.Contains('Npcap installer copied')) ('found=' + $r.log.Contains('Npcap installer copied'))
Add-Assert $c 'npcap installer present in install tree' ((Get-RelTree (Join-Path $ir 'Network-HTTP\Npcap-installer')) -contains 'npcap-1.90-sentinelA.exe') 'installed output'
Add-Assert $c 'wireshark paf present in install tree' ((Get-RelTree (Join-Path $ir 'Network-HTTP\Wireshark')) -contains 'WiresharkPortable64_4.2.0-sentinelA.paf.exe') ('ok')
Add-Assert $c 'CE tree merged from archive A' ($snapCe -contains 'cheatengine-sentinelA.txt') ('CE tree: ' + ($snapCe -join ';'))
Add-Obs $c 'stage subtree after non-recursive Copy-Item (documentary)' ($snapStage -join ';')
Finish-Case $c

# ---------------------------------------------------- CASE 3: repeat A then B (CORE)
$c = New-Case 'repeat-A-then-B'
$ir = Join-Path $runRoot 'install-repeat'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
$runA = Invoke-Restore -Tag 'repeatA' -Archive $archA -InstallRoot $ir -Apply
$savedNpcap = Join-Path $ir 'Network-HTTP\Npcap-installer\npcap-1.90-sentinelA.exe'
$savedWireshark = Join-Path $ir 'Network-HTTP\Wireshark\WiresharkPortable64_4.2.0-sentinelA.paf.exe'
Add-Assert $c 'run A exits successfully before repeat test' ($runA.exit -eq 0) ('exit=' + $runA.exit)
Write-Inert $savedNpcap 'post-A user npcap marker'
Write-Inert $savedWireshark 'post-A user wireshark marker'
$runB = Invoke-Restore -Tag 'repeatB' -Archive $archB -InstallRoot $ir -Apply
$c.exit = $runB.exit
$c.logs['repeatA'] = $runA.logPath
$c.logs['repeatB'] = $runB.logPath
$unpack = Join-Path $ir '_cache-unpack'
$snapUnpackB = Get-RelTree $unpack
$snapCeB = Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')
$snapStageB = Get-RelTree (Join-Path $ir '_download-stage')
$c.snapshots['unpackAfterB'] = $snapUnpackB; $c.snapshots['installCEAfterB'] = $snapCeB; $c.snapshots['stageAfterB'] = $snapStageB
Add-Assert $c 'run A baseline: npcap installer selected' ($runA.log.Contains('Npcap installer copied')) ('found=' + $runA.log.Contains('Npcap installer copied'))
Add-Assert $c 'run B exit code is 0' ($runB.exit -eq 0) ('exit=' + $runB.exit)
Add-Assert $c 'run B does NOT re-select archive-A npcap installer (stale leak)' (-not $runB.log.Contains('Npcap installer copied')) ('message present=' + $runB.log.Contains('Npcap installer copied'))
Add-Assert $c 'run B unpack holds no archive-A npcap member' (-not ($snapUnpackB -contains 'npcap-1.90-sentinelA.exe')) ('unpack: ' + ($snapUnpackB -join ';'))
Add-Assert $c 'run B unpack holds no archive-A wireshark member' (-not ($snapUnpackB | Where-Object { $_ -like 'WiresharkPortable*' })) ('unpack: ' + ($snapUnpackB -join ';'))
Add-Assert $c 'run B does not overwrite a saved npcap installer from absent archive-A input' ([IO.File]::ReadAllText($savedNpcap) -eq 'post-A user npcap marker') 'saved installer marker'
Add-Assert $c 'run B does not overwrite a saved Wireshark installer from absent archive-A input' ([IO.File]::ReadAllText($savedWireshark) -eq 'post-A user wireshark marker') 'saved installer marker'
Add-Assert $c 'intentional merge preserved: archive-A CE file stays in install tree' ($snapCeB -contains 'cheatengine-sentinelA.txt') ('CE tree: ' + ($snapCeB -join ';'))
Add-Assert $c 'archive-B CE file merged into install tree' ($snapCeB -contains 'cheatengine-sentinelB.txt') ('CE tree: ' + ($snapCeB -join ';'))
Add-Assert $c 'intentional stage merge preserved: archive-A stage zip stays' ($snapStageB -contains 'sentinelA-tool.zip') ('stage: ' + ($snapStageB -join ';'))
Add-Assert $c 'archive-B stage zip merged into stage' ($snapStageB -contains 'sentinelB-tool.zip') ('stage: ' + ($snapStageB -join ';'))
Finish-Case $c

# ------------------------------------------------------ CASE 4: spaces/Unicode path
$c = New-Case 'archive-path-spaces-unicode'
$ir = Join-Path $runRoot 'install-unicode'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
$r = Invoke-Restore -Tag 'unicode' -Archive $archUni -InstallRoot $ir -Apply
$c.exit = $r.exit
$c.logs['unicode'] = $r.logPath
$snapUnpack = Get-RelTree (Join-Path $ir '_cache-unpack')
$c.snapshots['unpack'] = $snapUnpack
Add-Assert $c 'exit code is 0' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'extraction worked from spaces/Unicode archive path' ((Get-RelTree (Join-Path $ir 'Network-HTTP\Npcap-installer')) -contains 'npcap-1.90-sentinelA.exe') 'installed output'
Add-Assert $c 'npcap installer selected from Unicode-path archive' ($r.log.Contains('Npcap installer copied')) ('found=' + $r.log.Contains('Npcap installer copied'))
Finish-Case $c

# --------------------------------------------------- CASE 5: extraction failure -> B
$c = New-Case 'extraction-failure-then-B'
$ir = Join-Path $runRoot 'install-corrupt'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
$rC = Invoke-Restore -Tag 'corruptC' -Archive $archC -InstallRoot $ir -Apply
$c.logs['corruptC'] = $rC.logPath
$snapUnpackAfterC = Get-RelTree (Join-Path $ir '_cache-unpack')
$c.snapshots['unpackAfterFailedC'] = $snapUnpackAfterC
Add-Assert $c 'failed extraction exits non-zero' ($rC.exit -ne 0) ('exit=' + $rC.exit)
Add-Assert $c 'failure surfaces as 7z extract failed throw' ($rC.log.Contains('7z extract failed')) ('found=' + $rC.log.Contains('7z extract failed'))
Add-Obs $c 'unpack residue left by the failed extraction (documentary)' ($snapUnpackAfterC -join ';')
$runB = Invoke-Restore -Tag 'corruptThenB' -Archive $archB -InstallRoot $ir -Apply
$c.logs['corruptThenB'] = $runB.logPath
$c.exit = $runB.exit
$snapUnpackB = Get-RelTree (Join-Path $ir '_cache-unpack')
$snapCeB = Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')
$c.snapshots['unpackAfterB'] = $snapUnpackB; $c.snapshots['installCEAfterB'] = $snapCeB
Add-Assert $c 'recovery run B exit code is 0' ($runB.exit -eq 0) ('exit=' + $runB.exit)
Add-Assert $c 'run B does NOT select corrupt-C npcap installer (stale leak)' (-not $runB.log.Contains('Npcap installer copied')) ('message present=' + $runB.log.Contains('Npcap installer copied'))
Add-Assert $c 'run B CE tree has no corrupt-C residue (stale leak)' (-not ($snapCeB -contains 'cheatengine-sentinelC.txt')) ('CE tree: ' + ($snapCeB -join ';'))
Add-Assert $c 'run B unpack holds no corrupt-C npcap member' (-not ($snapUnpackB | Where-Object { $_ -like 'npcap-*sentinelC*' })) ('unpack: ' + ($snapUnpackB -join ';'))
Add-Assert $c 'archive-B CE file merged into install tree' ($snapCeB -contains 'cheatengine-sentinelB.txt') ('CE tree: ' + ($snapCeB -join ';'))
Finish-Case $c


# ----------------------------------------------- CASE 6: archive inside legacy stage
$c = New-Case 'archive-inside-legacy-stage'
$ir = Join-Path $runRoot 'install-input-in-legacy'
$legacy = Join-Path $ir '_cache-unpack'
New-Item -ItemType Directory -Force -Path $legacy | Out-Null
$inside = Join-Path $legacy 'only-input.7z'
Copy-Item -LiteralPath $archA -Destination $inside
Write-Inert (Join-Path $legacy 'owner-sentinel.txt') 'keep archive and old directory'
$before = Get-Fingerprint $legacy
$r = Invoke-Restore -Tag 'input-in-legacy' -Archive $inside -InstallRoot $ir -Apply
$c.exit = $r.exit; $c.logs['restore'] = $r.logPath
Add-Assert $c 'archive inside old staging directory restores successfully' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'the only input archive and all legacy files remain byte-identical' ((Get-Fingerprint $legacy) -eq $before) 'legacy fingerprint unchanged'
Add-Assert $c 'archive A payload reached its install destination' ((Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')) -contains 'cheatengine-sentinelA.txt') 'installed payload'
Finish-Case $c

# ---------------------------------------- CASE 7: do not adopt another caller's stage
$c = New-Case 'legacy-and-other-stage-preserved'
$ir = Join-Path $runRoot 'install-other-owner'
$legacy = Join-Path $ir '_cache-unpack'
$other = Join-Path $ir '_cache-unpack-other-owner'
Write-Inert (Join-Path $legacy 'keep-old.txt') 'legacy owner'
Write-Inert (Join-Path $legacy 'npcap-0.00-other-owner.exe') 'inert legacy installer'
Write-Inert (Join-Path $other 'keep-concurrent.txt') 'another invocation owns this'
$beforeLegacy = Get-Fingerprint $legacy
$beforeOther = Get-Fingerprint $other
$r = Invoke-Restore -Tag 'preserve-other-owner' -Archive $archB -InstallRoot $ir -Apply
$c.exit = $r.exit; $c.logs['restore'] = $r.logPath
Add-Assert $c 'restore B succeeds with pre-existing stage directories' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'legacy staging contents are not removed or modified' ((Get-Fingerprint $legacy) -eq $beforeLegacy) 'legacy fingerprint'
Add-Assert $c 'another staging directory and sentinel remain untouched' ((Get-Fingerprint $other) -eq $beforeOther) 'other-owner fingerprint'
Add-Assert $c 'legacy installer is not selected for archive B' (-not $r.log.Contains('Npcap installer copied')) 'no stale installer selection'
Add-Assert $c 'only the two pre-existing staging directories remain' (((Get-StagingDirs $ir) -join ';') -eq '_cache-unpack;_cache-unpack-other-owner') ((Get-StagingDirs $ir) -join ';')
Finish-Case $c

# ---------------------------------------------------- CASE 8: successful cleanup
$c = New-Case 'owned-stage-cleanup-success'
$ir = Join-Path $runRoot 'install-cleanup-success'
$r = Invoke-Restore -Tag 'cleanup-success' -Archive $archA -InstallRoot $ir -Apply
$c.exit = $r.exit; $c.logs['restore'] = $r.logPath
Add-Assert $c 'restore creates a previously absent install root and succeeds' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'successful extraction leaves no owned staging directories' (@(Get-StagingDirs $ir).Count -eq 0) ((Get-StagingDirs $ir) -join ';')
Add-Assert $c 'success cleanup preserves installed payload' ((Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')) -contains 'cheatengine-sentinelA.txt') 'installed payload'
Finish-Case $c

# ------------------------------------------------------- CASE 9: failed cleanup
$c = New-Case 'owned-stage-cleanup-failure'
$ir = Join-Path $runRoot 'install-cleanup-failure'
$r = Invoke-Restore -Tag 'cleanup-failure' -Archive $archC -InstallRoot $ir -Apply
$c.exit = $r.exit; $c.logs['restore'] = $r.logPath
Add-Assert $c 'CRC-corrupt archive fails extraction' ($r.exit -ne 0) ('exit=' + $r.exit)
Add-Assert $c 'failure reports the real 7z extraction error' ($r.log.Contains('7z extract failed')) 'extraction error surfaced'
Add-Assert $c 'failed extraction leaves no owned staging directories' (@(Get-StagingDirs $ir).Count -eq 0) ((Get-StagingDirs $ir) -join ';')
Add-Assert $c 'failed extraction did not begin payload installation' (-not (Test-Path -LiteralPath (Join-Path $ir 'Debuggers'))) 'no install copy'
Finish-Case $c

# ------------------------------------------- CASE 10: legacy junction remains owned
$c = New-Case 'legacy-stage-junction-preserved'
$ir = Join-Path $runRoot 'install-legacy-junction'
$legacy = Join-Path $ir '_cache-unpack'
$target = Join-Path $runRoot 'junction-target-owned-by-test'
New-Item -ItemType Directory -Force -Path $ir | Out-Null
Write-Inert (Join-Path $target 'target-owner.txt') 'junction target belongs to someone else'
New-Item -ItemType Junction -Path $legacy -Target $target | Out-Null
$before = Get-Fingerprint $target
$r = Invoke-Restore -Tag 'legacy-junction' -Archive $archB -InstallRoot $ir -Apply
$c.exit = $r.exit; $c.logs['restore'] = $r.logPath
$isLink = $false
if (Test-Path -LiteralPath $legacy) {
    $isLink = (((Get-Item -LiteralPath $legacy -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}
Add-Assert $c 'restore B succeeds with a legacy junction' ($r.exit -eq 0) ('exit=' + $r.exit)
Add-Assert $c 'legacy junction is not deleted or replaced with a directory' $isLink ('reparse=' + $isLink)
Add-Assert $c 'junction target is byte-identical after restore' ((Get-Fingerprint $target) -eq $before) 'target fingerprint'
Add-Assert $c 'archive B payload installed independently of the junction' ((Get-RelTree (Join-Path $ir 'Debuggers\Cheat Engine')) -contains 'cheatengine-sentinelB.txt') 'installed payload'
Finish-Case $c

# ------------------------------------------------------------------ report
$failedCases = @($cases | Where-Object { $_.verdict -eq 'FAIL' })
$summary = [pscustomobject]@{
    shell = $shellName
    psVersion = $PSVersionTable.PSVersion.ToString()
    target = $ScriptPath
    runRoot = $runRoot
    totalCases = $cases.Count
    expectedCases = 10
    denominatorComplete = ($cases.Count -eq 10)
    totalAssertions = @($cases | ForEach-Object { $_.asserts } | ForEach-Object { $_ }).Count
    sourceSha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    harnessSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    childPowerShell = $psExe
    failedCases = @($failedCases | ForEach-Object { $_.name })
    allPass = ($failedCases.Count -eq 0 -and $cases.Count -eq 10)
}
$results = [pscustomobject]@{ summary = $summary; cases = $cases }
$json = $results | ConvertTo-Json -Depth 8
$jsonPath = Join-Path $runRoot 'results.json'
[System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($true)))
Write-Output ('RESULTS=' + $jsonPath)
Write-Output ('VERDICT allPass=' + $summary.allPass + ' failedCases=[' + ($summary.failedCases -join ',') + ']')
if ($cases.Count -ne 10) { exit 10 }
if ($failedCases.Count -gt 0) { exit ([Math]::Min($failedCases.Count, 9)) }
exit 0
