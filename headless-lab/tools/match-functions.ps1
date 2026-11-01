<#
.SYNOPSIS
    Match functions between two Windows PE files by content hash, with no shared Ghidra project.

.DESCRIPTION
    WHY THIS EXISTS. The registry's only non-decompiler instrument on the native axis,
    native.crosscompare.ghidra, carries evidence_source 'binary-similarity' -- which is why it
    is the only registered route to genuine independence for native RE. It also has NO invoke
    block, because AutoVersionTrackingScript needs three arguments plus a GhidraValuesMap
    startup project holding both programs at once, and no registry field can express that
    precondition. The result was an instrument that was probeable but not callable, so the
    planner could not reach the one family that could actually corroborate.

    This wrapper removes the precondition instead of modelling it. Each binary is imported into
    its OWN throwaway Ghidra project, FunctionHashes.java emits one line per function
    (name, size, MD5-of-body truncated to 8 bytes), and the two tables are joined HERE on the
    hash. No shared project, no startup file, no session state.

    WHAT IT PROVES, and what it does not: identical function bodies hash identically. That is a
    content address, not a similarity score. It finds functions that are byte-for-byte the
    same, so it says NOTHING about a function that was merely recompiled, reordered or
    recompiled at a different optimisation level -- it will report those as different. Treat a
    miss as "not proven identical", never as "different code".

    Exit codes are the contract: 0 ran, 1 refused, 2 could not run. Exit 0 with an empty match
    set is a legitimate answer, not a failure, and is distinguished from a refusal by `ok`.

.EXAMPLE
    .\match-functions.ps1 -Source A.exe -Dest B.exe
    returns JSON: counts, match rate, and the matched pairs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Dest,
    # NOT defaulted in the param block. $PSScriptRoot is empty there when the script is run as
    # `powershell -File`, which is exactly how the registry invokes it, and Join-Path against
    # an empty string throws before a single line of real work happens. Measured, not assumed.
    [string]$Ghidra,
    [string]$ScriptPath,
    # Added 2026-11-01. Where the two throwaway projects are built. Default stays %TEMP%, so
    # every existing caller (including the probe) is byte-identical to before. The registry's
    # native.crosscompare.ghidra invoke passes `-WorkDir {scratch:fnmatch}`, which mission.ps1
    # creates inside the mission case dir -- that is what makes the entry's `write_scope:
    # case_dir` literally true instead of a description of a different code path.
    [string]$WorkDir,
    [switch]$KeepProjects
)

$ErrorActionPreference = 'Stop'
if (-not $Ghidra) { $Ghidra = Join-Path $PSScriptRoot '..\..\Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat' }
if (-not $ScriptPath) { $ScriptPath = Join-Path $PSScriptRoot '..\..\scripts\ghidra' }

function Refuse([int]$code, [string]$message) {
    [ordered]@{ ok = $false; exit = $code; error = $message } | ConvertTo-Json -Compress | Write-Output
    exit $code
}

foreach ($p in @($Source, $Dest)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Refuse 1 "no such file: $p" }
}
if (-not (Test-Path -LiteralPath $Ghidra -PathType Leaf)) { Refuse 2 "ghidra headless not found at $Ghidra" }

$work = if ($WorkDir) {
    # Caller-supplied: the orchestrator's own case directory. Still unique per run so two
    # concurrent rounds cannot collide, but it lives where the registry says this writes.
    Join-Path $WorkDir ("fnmatch-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
} else {
    Join-Path $env:TEMP ("fnmatch-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
}
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Get-FunctionHashes([string]$binary, [string]$tag) {
    # Ghidra writes a deprecation warning to stderr on a perfectly good run
    # ("PRE_COMMENT ... has been deprecated and marked for removal"). Under
    # $ErrorActionPreference='Stop' PowerShell promotes ANY native stderr line to a terminating
    # NativeCommandError, so the wrapper died on a warning and emitted no JSON at all.
    # Scoped to this call and restored immediately after, so a real failure elsewhere still
    # terminates. Measured: this is what the first working run actually did.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # Each binary gets its OWN project. This is the whole point: no shared project means no
    # startup file to express, and therefore no precondition the registry cannot carry.
    $proj = "p_$tag"
    & $Ghidra $work $proj -import $binary -postScript FunctionHashes.java $work `
        -scriptPath $ScriptPath -deleteProject *> $null
    $ErrorActionPreference = $prevEap
    $table = Get-ChildItem -LiteralPath $work -Filter 'hashes-*.txt' |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $table) { return $null }
    $map = @{}
    foreach ($line in Get-Content -LiteralPath $table.FullName) {
        if ($line.StartsWith('#') -or -not $line.Trim()) { continue }
        $f = $line -split "`t"
        if ($f.Count -ge 3) { $map[$f[2]] = [ordered]@{ name = $f[0]; size = [int]$f[1] } }
    }
    return $map
}

$sourcePath = (Resolve-Path -LiteralPath $Source).Path
$destPath = (Resolve-Path -LiteralPath $Dest).Path
$a = Get-FunctionHashes $sourcePath 'src'
$b = Get-FunctionHashes $destPath 'dst'

if (-not $KeepProjects) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }

if ($null -eq $a -or $null -eq $b) {
    Refuse 2 "Ghidra produced no function-hash table for at least one input"
}

$matched = @()
foreach ($h in $a.Keys) {
    if ($b.ContainsKey($h)) {
        $matched += [ordered]@{
            hash     = $h
            size     = $a[$h].size
            source   = $a[$h].name
            dest     = $b[$h].name
            renamed  = ($a[$h].name -ne $b[$h].name)
        }
    }
}

# `changed` -- the SAME hash join read the other way round, added 2026-11-01 so
# native.crosscompare.ghidra can bind native.diff.changed without a second instrument.
# It is a DIFF, not a similarity score: a source function whose body hash has no twin in
# dest is "no identical counterpart", which is the only thing content hashing can say. A
# function recompiled with one byte different lands here too, and that is why the label
# names the METHOD rather than the conclusion.
$changed = @()
foreach ($h in $a.Keys) {
    if (-not $b.ContainsKey($h)) {
        $changed += [ordered]@{ func = $a[$h].name; change = 'no-identical-counterpart-in-dest' }
    } elseif ($a[$h].name -ne $b[$h].name) {
        $changed += [ordered]@{ func = $a[$h].name; change = ('renamed-in-dest:' + $b[$h].name) }
    }
}
$changedTotal = $changed.Count
# Bounded on purpose: two unrelated binaries produce thousands of entries and the caller
# parses this on stdout. The TOTAL is reported either way, so a truncated list cannot read
# as a complete one.
if ($changed.Count -gt 200) { $changed = @($changed[0..199]) }

# Result written to disk as well as stdout, so the registry verdict rests on a FILE.
# assert-probes says an entry with no `probe.produces` was "matched STRINGS only, and a
# stub which prints them satisfies it". Added 2026-10-05; see scripts/probe_artifact.ps1,
# the PowerShell member of a family with the .py and .mjs writers.
. (Join-Path $PSScriptRoot '..\..\scripts\probe_artifact.ps1')

$result = [ordered]@{
    ok                = $true
    exit              = 0
    source            = $sourcePath
    dest              = $destPath
    source_functions  = $a.Count
    dest_functions    = $b.Count
    matched           = $matched.Count
    match_rate        = if ($a.Count) { [math]::Round(100.0 * $matched.Count / $a.Count, 1) } else { 0 }
    identical_inputs  = ($sourcePath -eq $destPath)
    pairs             = $matched
    changed           = $changed
    changed_total     = $changedTotal
    changed_truncated = ($changedTotal -gt $changed.Count)
    caveat            = 'CONTENT HASH, NOT SIMILARITY. Identical function bytes match. A function merely recompiled, reordered or re-optimised will NOT match. A miss means not-proven-identical, never different-code.'
}
$json = $result | ConvertTo-Json -Depth 5 -Compress
Write-Output $json
Write-ProbeArtifact -Tool 'match_functions' -OutDir 'probe-artifacts' -Payload $result | Out-Null
exit 0