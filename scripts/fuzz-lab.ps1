#Requires -Version 5.1
<#
.SYNOPSIS
  Fuzzing lab -- self-authored mutation fuzzer with a differential oracle, pointed at this
  repository's own parsers. Zero dependencies, no AFL, no install step: Node 24 only.

.DESCRIPTION
  Wraps `fuzz-lab/tools/*.mjs` with the station's CLI-Anything convention:
  JSON on stdout, transcript on stderr, exit code from the underlying tool.

  status    node readiness, the target inventory, the recorded crash index
  loop      the whole proof in one command: corpus -> campaign -> triage ->
            NEGATIVE CONTROL -> regressions. Exit 0 = the chain held.
  run       fuzz one target and print the outcome breakdown (needs -NodeArgs --target <id>)
  replay    re-derive a recorded crash from its recipe and re-run it
  crashes   list every recorded crash with its recipe and replay command

  `loop` is self-judging and is the only action that should be run casually. It executes
  one child process per input, so a full run is a few hundred spawns and takes tens of
  seconds; -NodeArgs '--budget N' trades runtime for coverage.

.EXAMPLE
  powershell -File scripts\fuzz-lab.ps1 loop
  powershell -File scripts\fuzz-lab.ps1 status
  powershell -File scripts\fuzz-lab.ps1 loop -NodeArgs '--budget 400 --run-id nightly'
  powershell -File scripts\fuzz-lab.ps1 crashes

.NOTES
  Exit codes: 0 = loop closed · 2 = unknown action · 5 = a recorded crash did not
  reproduce · 9 = a loop assertion failed (the table says which).

  THE ONE THAT MATTERS: exit 0 is not available to a run that found nothing. The negative
  control fails any run in which a deliberately fragile parser survived, because a fuzzer
  that cannot catch a parser with no bounds checks has not shown it can catch anything.

  STOP LINES. Self-authored targets only: every parser under test was written in this
  repository, and nothing is downloaded or executed. A finding is a parser in our own code
  misbehaving on our own synthetic input -- not a working exploit, and not a crash in
  anything we do not own.

  No hostile input in git. The reproducer bytes are gitignored (see fuzz-lab/.gitignore);
  the recipe is committed, and `replay` re-derives the bytes from it and checks the hash.
  This is a parser-robustness teaching lane, not a means of attacking anything.
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @(),
    # Tool flags go through here, not as bare --flags: PowerShell binds `--out` to
    # -OutVariable etc. before $Rest ever sees it. Same trap web-reverse-lab.ps1 documents.
    #   -NodeArgs '--budget 400 --run-id nightly'      (one string; -File safe)
    #   -NodeArgs @('--budget','400','--run-id','nightly')  (array; in-session)
    [string[]]$NodeArgs = @()
)
$ErrorActionPreference = 'Stop'
$Rest = @(@($Rest) + @($NodeArgs) | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ -ne '' })

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'fuzz-lab'
$ToolsDir = Join-Path $LabRoot 'tools'
$node = (Get-Command node -ErrorAction SilentlyContinue)

function Get-CrashIndex {
    $p = Join-Path $LabRoot 'crashes\index.json'
    if (Test-Path -LiteralPath $p) {
        try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { }
    }
    return $null
}

$inventory = @(
    @{ tool = 'corpus';   script = 'lab/corpus.mjs';  does = '27 seeds built from other labs generators; builds twice and compares hashes' }
    @{ tool = 'mutator';  script = 'lab/mutate.mjs';  does = '12 named strategies, seeded from the run id; the recipe is the inverse of the mutation' }
    @{ tool = 'pcap';     script = 'lab/pcap-reader.mjs'; target = $true; does = 'pcap reader written for this lab, plus a deliberately flawed twin' }
    @{ tool = 'jose';     script = 'lab/targets.mjs'; target = $true; does = 'crypto-lab jose.mjs + analyze.mjs (the 780-line deliverable)' }
    @{ tool = 'forensic'; script = 'lab/targets.mjs'; target = $true; does = 'forensics-lab parsePrefetch: the binary .pf record' }
    @{ tool = 'web';      script = 'lab/targets.mjs'; target = $true; does = 'web-reverse triage() + residuals(): the obfuscation fingerprint' }
    @{ tool = 'driver';   script = 'lab/driver.mjs';  does = 'one process per input, hard wall-clock and heap ceilings, five outcome classes' }
    @{ tool = 'triage';   script = 'lab/triage.mjs';  does = 'delta-debug minimisation + the gitignored crash store' }
    @{ tool = 'loop';     script = 'tools/loop.mjs';  does = 'all of the above in one self-judging command (exit 0 = loop closed)' }
    @{ tool = 'replay';   script = 'tools/replay.mjs'; does = 're-derive a crash from its recipe and re-run it' }
    @{ tool = 'regress';  script = 'tools/regressions.mjs'; does = 'the reduced cases that guard every fix' }
)

if ($Action -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok          = $true
        tool        = 'catalog'
        pattern     = 'CLI-Anything: Click-less PowerShell, JSON stdout, SKILL table.'
        clientMcp   = 'debugger-router only'
        node        = if ($node) { "$(& $node -v 2>&1)" } else { $null }
        nodeFound   = [bool]$node
        items       = $inventory
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

if (-not $node) {
    [ordered]@{ ok = $false; action = $Action; error = 'node not found on PATH (this lab needs Node >= 24 and nothing else)' } | ConvertTo-Json -Compress
    exit 2
}

$nodeVersion = (& $node -v) 2>&1
$crashes = Get-CrashIndex

switch ($Action.ToLowerInvariant()) {
    'status' {
        $ok = $true
        $warnings = @()
        if ("$nodeVersion" -notmatch '^v(2[4-9]|[3-9][0-9])') {
            $ok = $false
            $warnings += "node $nodeVersion is older than the v24 this lab is written against"
        }
        $crashList = if ($crashes) { @($crashes.crashes) } else { @() }
        [ordered]@{
            ok         = $ok
            tool       = 'fuzz-lab'
            node       = "$nodeVersion"
            labRoot    = $LabRoot
            workDir    = if ($env:FUZZ_LAB_DIR) { $env:FUZZ_LAB_DIR } else { (Join-Path $env:TEMP 'fuzz-lab') }
            targets    = @('pcap', 'jose', 'forensic-pf', 'web-triage')
            seeds      = 27
            ceilings   = [ordered]@{
                perInputMs = if ($env:FUZZ_INPUT_HARD_MS) { [int]$env:FUZZ_INPUT_HARD_MS } else { 4000 }
                heapMb     = if ($env:FUZZ_INPUT_HARD_MEM_MB) { [int]$env:FUZZ_INPUT_HARD_MEM_MB } else { 192 }
            }
            crashes    = $crashList.Count
            items      = $inventory
            warnings   = $warnings
            note       = 'self-authored targets only; reproducer bytes are gitignored, recipes are not; run `loop` for the whole proof'
        } | ConvertTo-Json -Compress -Depth 6
        if (-not $ok) { exit 2 }
        exit 0
    }
    'crashes' {
        $crashList = if ($crashes) { @($crashes.crashes) } else { @() }
        if ($crashList.Count -eq 0) {
            [ordered]@{ ok = $true; action = 'crashes'; count = 0; note = 'no crashes recorded; run action loop' } | ConvertTo-Json -Compress
            exit 0
        }
        foreach ($c in $crashList) {
            [Console]::Error.WriteLine("$($c.id)  $($c.outcome)  $($c.target)/$($c.variant)  $($c.reduced.length)B  sha256 $($c.reduced.sha256)")
            [Console]::Error.WriteLine("  $($c.detail)")
            [Console]::Error.WriteLine("  replay: node fuzz-lab/tools/replay.mjs $($c.target) $($c.variant) $($c.reduced.sha256.Substring(0,12))")
        }
        [ordered]@{
            ok      = $true
            action  = 'crashes'
            count   = $crashList.Count
            crashes = $crashList
        } | ConvertTo-Json -Compress -Depth 8
        exit 0
    }
    default {
        $map = @{
            loop   = 'tools\loop.mjs'
            run    = 'tools\loop.mjs'
            replay = 'tools\replay.mjs'
        }
        $key = $Action.ToLowerInvariant()
        if (-not $map.ContainsKey($key)) {
            [ordered]@{ ok = $false; action = $Action; error = "unknown action $Action"; actions = @('status', 'loop', 'run', 'replay', 'crashes', 'catalog') } | ConvertTo-Json -Compress
            exit 2
        }
        $scriptPath = Join-Path $LabRoot $map[$key]
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            [ordered]@{ ok = $false; action = $key; error = "missing $scriptPath" } | ConvertTo-Json -Compress
            exit 2
        }
        $out = & $node $scriptPath @Rest 2>&1 | Out-String
        $code = $LASTEXITCODE
        [Console]::Error.Write($out)
        $note = switch ($code) {
            0 { 'loop closed: corpus stable, every input executed under a hard ceiling, a real defect found and reproduced from its recipe, the flawed twin caught, every fix holding' }
            5 { 'a recorded crash did not reproduce - either the fix now holds (good) or the recipe drifted (a lab bug); read the stderr transcript' }
            9 { 'a loop assertion failed - the summary table names it. A green run is not available while any assertion is false.' }
            default { "tool exited $code - read the stderr transcript" }
        }
        [ordered]@{
            ok        = ($code -eq 0)
            action    = $key
            exitCode  = $code
            tool      = $map[$key]
            nodeArgs  = @($Rest)
            workDir   = if ($env:FUZZ_LAB_DIR) { $env:FUZZ_LAB_DIR } else { (Join-Path $env:TEMP 'fuzz-lab') }
            note      = $note
        } | ConvertTo-Json -Compress
        exit $code
    }
}
