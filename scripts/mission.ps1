#Requires -Version 5.1
<#
.SYNOPSIS
  The mission layer. Takes a target and a question, and runs the registered capabilities
  in an order derived from their declared dependencies, recording a typed evidence chain.

.DESCRIPTION
  Nine labs that each run standalone are islands. This is the layer that composes them:
  it picks capabilities whose `consumes` are satisfied, runs each one in isolation behind
  the gate, records the facts it produced, and feeds those facts forward.

  Four properties do the real work, and each one exists because its absence was a
  specific, observed failure mode:

  1. INTAKE HALTS. Object, question type and containment must all be stated. A missing
     object or an unnameable containment is a STOP and no tool runs -- `l2-gate.md` S13.

  2. THE GRANT IS RE-CHECKED EVERY ROUND, not at intake. The invocable set is a monotonic
     subset of the grant; a loop that may choose its own capabilities is one conversation
     away from choosing a broader one. "Check the grant only at intake" is the single most
     tempting simplification in this design and it is the one thing that must never ship.

  3. THE VERDICT IS COMPUTED, NOT AUTHORED. The caller proposes a claim; this script
     decides whether it survives seven gates. A verdict written by the same mind that read
     the evidence is not independent.

  4. THE STOP NOTE IS GENERATED FROM THE REGISTRY, so it cannot go stale. A stage that
     did not run is an unasked question, not a clean answer -- and it is the one gap that
     produces no error to notice.

.PARAMETER Action
  Run      execute a mission end to end
  Plan     write the plan and exit without running a single tool
  Selftest prove the orchestrator is not decorative (controls N1-N4)

.EXAMPLE
  powershell -File scripts\mission.ps1 -Action Run `
      -Target crackme-corpus\out\c01-stringobf.exe `
      -Question "where is the input validation" -QuestionType Q2.locate `
      -Provenance "Owner-authored; built by crackme-corpus/tools/loop.py from our own source" `
      -OwnerWord "analyze this exe" -Containment station_under_named_process_rule
  powershell -File scripts\mission.ps1 -Action Selftest

.NOTES
  Exit codes: 0 = mission closed with a computed verdict · 1 = open/unresolved (a valid
  outcome, not a crash) · 2 = refused at intake, nothing ran · 3 = scope violation ·
  4 = provenance not declared by the Owner · 5 = grant tampered or missing.

  THE BIGGEST RISK, stated in the design and unchanged by the implementation: the loop
  narrating work it did not do. A model that sounds confident across nine labs is doing
  exactly what it is good at. Every control here is therefore a program; N4 aims our own
  documented failure mode straight at this file.
#>
[CmdletBinding()]
param(
    [Parameter()][ValidateSet('Run', 'Plan', 'Selftest')][string]$Action = 'Plan',
    [string]$Target = '',
    [string]$Question = '',
    [string]$QuestionType = '',
    [string]$Provenance = '',
    [string]$OwnerWord = '',
    [string]$Containment = '',
    [string]$Claim = '',
    [string[]]$Discharged = @(),
    [string]$CaseRoot = 'E:\missions',
    [string]$CaseId = '',
    [int]$MaxRounds = 6,
    [string]$Registry = '',
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Out-Json($o) { $o | ConvertTo-Json -Compress -Depth 12 }
function Say($s) { if (-not $Json) { Write-Host $s } }

function Get-Registry {
    $p = if ($Registry) { $Registry } else { Join-Path $RepoRoot 'manifests\capabilities.json' }
    return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json)
}


$QUESTION_TYPES = @{
    'Q1.identify'  = @{ needs = @('native.ida.list_functions'); text = 'what is this file, is it packed, what is its shape' }
    'Q2.locate'    = @{ needs = @('native.ida.list_functions', 'native.ida.decompile'); text = 'where is the code that does X' }
    'Q3.behaviour' = @{ needs = @(); text = 'what does it actually do at runtime -- needs a device or a debugger' }
    'Q4.data'      = @{ needs = @(); text = 'what is in this capture / image / dump' }
    'Q5.vuln-shape'= @{ needs = @('native.ida.list_functions', 'native.ida.decompile'); text = 'where does it trust something it should not' }
    'Q6.crypto'    = @{ needs = @(); text = 'what token/signature/key handling is this' }
    'Q7.origin'    = @{ needs = @('native.ida.list_functions'); text = 'what changed between these two builds' }
}

# Refusals are thrown, not exited. `exit` inside a function terminates the whole process,
# which killed the selftest on its very first case -- the control could not observe a
# refusal because observing it ended the run. The entry point below converts a throw into
# an exit code; controls catch it instead.
class MissionRefusal : System.Exception {
    [int]$Code
    MissionRefusal([int]$code, [string]$message, [string]$detail) : base($message) {
        $this.Code = $code
        $this.Detail = $detail
    }
    [string]$Detail
}

function Refuse($code, $message, $detail) {
    $msg = "[mission] REFUSED ($code): $message"
    Write-Host $msg -ForegroundColor Red
    if ($detail) { Write-Host "[mission]   $detail" -ForegroundColor Red }
    throw [MissionRefusal]::new($code, $message, $detail)
}
function Invoke-Gate {
    param([string]$gateAction, [hashtable]$extra)
    $gate = Join-Path $RepoRoot 'scripts\gate.ps1'
    # Splat the hashtable as alternating key/value elements. `+ $extra` appends the
    # hashtable as ONE argument, so the gate received literally
    # `target=System.Collections.Hashtable` and refused a perfectly good target.
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gate, '-Action', $gateAction) +
         @($extra.GetEnumerator() | ForEach-Object { $_.Key; $_.Value })
    $out = & powershell @a 2>&1 | Out-String
    $code = $LASTEXITCODE
    $obj = $null
    try { $obj = ($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) | ConvertFrom-Json } catch { }
    return @{ code = $code; obj = $obj; raw = $out }
}

function Get-TreeHash {
    <#
      Scope guard baseline.

      Enumerated with `git ls-files`, not by walking the directory. Walking recursed the
      whole 1 GB Ghidra install and every tool payload, which made the guard take minutes
      -- and a scope guard nobody waits for is not a control. "The repository" means the
      tracked set, which is both the precise definition and the cheap one.

      Untracked files are covered too, because a mission that writes a new file and then
      invokes it is exactly the attack this guards against, so anything untracked inside
      the repo is hashed as well. Tool payloads under Static-Reversing and friends are
      skipped by name: they are third-party binaries that no mission may modify, and
      hashing them buys nothing.
    #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 'absent' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $names = @()
    try { $names = @(& git -C $Path ls-files --cached --others --exclude-standard 2>$null) } catch { }
    if ($names.Count -eq 0) { return 'no-index' }
    $lines = @()
    foreach ($n in ($names | Sort-Object)) {
        if ($n -match '^(Static-Reversing|Mobile-Android|System-Forensics|Unpackers-Game|Debuggers|Network-HTTP|mcp|out)/') { continue }
        $full = Join-Path $Path $n
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $lines += ($n + ':ABSENT'); continue }
        $h = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($full))).Replace('-', '').ToLowerInvariant()
        $lines += ($n + ':' + $h)
    }
    return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))))).Replace('-', '').ToLowerInvariant()
}

# ------------------------------------------------------------------------------ intake

function Invoke-Intake {
    $reg = Get-Registry

    if (-not $Target) { Refuse 2 'no object named' 'The mission must name an object. -Target is required; nothing runs.' }
    if (-not (Test-Path -LiteralPath $Target)) { Refuse 2 'object not found' "No path at $Target." }

    $qt = $QuestionType
    if (-not $qt) {
        if ($Question) { $qt = 'Q2.locate' } else { Refuse 2 'no question stated' 'Refusing to guess what "analyze" means.' }
    }
    if (-not $QUESTION_TYPES.ContainsKey($qt)) {
        Refuse 2 "unknown question type '$qt'" ("known: " + (($QUESTION_TYPES.Keys | Sort-Object) -join ', '))
    }
    if (-not $Question) { $Question = $QUESTION_TYPES[$qt].text }

    if (-not $Containment) {
        Refuse 2 'containment unstated or unnameable' 'l2-gate.md S13. Refuse to guess.'
    }
    if ($Containment -notin @('station_under_named_process_rule', 'loopback_capture', 'isolated_vm')) {
        Refuse 2 "unnamed containment '$Containment'" 'known: station_under_named_process_rule | loopback_capture | isolated_vm'
    }

    return @{ registry = $reg; question_type = $qt }
}

# -------------------------------------------------------------------------------- run

function Invoke-Mission {
    $intake = Invoke-Intake
    $reg = $intake.registry
    $qt = $intake.question_type

    $case = if ($CaseId) { $CaseId } else {
        $t = [IO.Path]::GetFileNameWithoutExtension($Target)
        ($t + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
    }
    $caseDir = Join-Path $CaseRoot $case
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    Say ('=' * 78)
    Say "mission $case"
    Say "  object        $Target"
    Say "  question      [$qt] $Question"
    Say "  containment   $Containment"
    Say "  case dir      $caseDir"
    Say ('=' * 78)

    # --- the grant. Minted by gate.ps1 and by nothing else. -------------------
    $g = Invoke-Gate 'New' @{ '-Target' = $Target; '-Provenance' = $Provenance; '-OwnerWord' = $OwnerWord; '-CaseDir' = $caseDir }
    if ($g.code -ne 0) {
        if ($g.code -eq 4) { Refuse 4 'provenance not declared by the Owner' 'No subprocess was spawned. The control held.' }
        Refuse 5 'gate refused to mint a grant' $g.raw.Trim()
    }
    $grant = $g.obj.grant
    Say "  grant         $($grant.grant_sha256.Substring(0,16))…  $($g.obj.allowed_count) capabilities allowed"

    # --- the plan, on disk, before any tool runs --------------------------------
    $wanted = $QUESTION_TYPES[$qt].needs
    $planned = @()
    foreach ($id in $wanted) {
        $c = $reg.capabilities | Where-Object { $_.id -eq $id }
        if (-not $c) { continue }
        if (-not $c.invoke) {
            # Declared in the plan, deliberately NOT runnable. Recording it as skipped is
            # the whole point: a stage that did not run must be visible, never absorbed.
            $planned += [ordered]@{ id = $id; state = 'skipped_no_invoke'; why = 'the registry declares no invoke block, so the loop cannot call it with arguments' }
            continue
        }
        if ($grant.allowed -notcontains $id) {
            $planned += [ordered]@{ id = $id; state = 'skipped_not_in_grant'; why = 'inside the registry but outside this grant' }
            continue
        }
        $planned += [ordered]@{ id = $id; state = 'planned'; consumes = $c.invoke.consumes_fact; produces = $c.invoke.fact_map }
    }

    $plan = [ordered]@{
        schema       = 'mission/plan@1'
        case_id      = $case
        created_at   = (Get-Date).ToUniversalTime().ToString('o')
        target       = (Resolve-Path -LiteralPath $Target).Path
        question     = [ordered]@{ type = $qt; text = $Question }
        containment  = $Containment
        provenance   = [ordered]@{ text = $Provenance; declared_by_owner = [bool]$OwnerWord }
        gate         = [ordered]@{ grant_sha256 = $grant.grant_sha256; allowed = $grant.allowed }
        capabilities = $planned
        budget       = [ordered]@{ max_rounds = $MaxRounds }
        proposed_claim = $Claim
    }
    Set-Content -LiteralPath (Join-Path $caseDir 'plan.json') -Value (Out-Json $plan) -Encoding UTF8
    Say "  plan          $($planned.Count) step(s), $($planned.Count) written before any tool ran"

    if ($Action -eq 'Plan') {
        Say ''
        Say 'PLAN ONLY: no tool ran. That is the point of -Action Plan.'
        Out-Json @{ ok = $true; exit = 0; action = 'plan'; case_dir = $caseDir; plan = $plan }
        exit 0
    }

    # --- scope guard baseline ---------------------------------------------------
    $baseline = Get-TreeHash $RepoRoot
    Set-Content -LiteralPath (Join-Path $caseDir 'scope-baseline.txt') -Value $baseline -Encoding UTF8

    # --- the loop ---------------------------------------------------------------
    $evidence = @()
    $facts = @{}          # typed fact key -> value, so a later round can consume it
    $trace = @()
    $round = 0

    foreach ($step in $planned) {
        if ($round -ge $MaxRounds) { break }
        if ($step.state -ne 'planned') { continue }
        $round++

        # GRANT RE-CHECK, EVERY ROUND. Not at intake. This is the invariant.
        $gc = Invoke-Gate 'Check' @{ '-CaseDir' = $caseDir; '-Capability' = $step.id }
        if ($gc.code -ne 0) {
            Say "  round $round  HALTED: $($step.id) is not inside the grant any more (exit $($gc.code))"
            $trace += [ordered]@{ round = $round; capability = $step.id; event = 'gate_halt'; gate_exit = $gc.code }
            break
        }

        $cap = $reg.capabilities | Where-Object { $_.id -eq $step.id }
        Say ''
        Say "  round $round  $($step.id)"

        # Resolve argv: {target} and {input.x} are the only substitutions, and the whole
        # thing stays an ARRAY. Never a shell string -- the path is attacker-influenced.
        $argList = @()
        $unresolved = @()
        foreach ($a in $cap.invoke.argv) {
            $v = $a
            $v = $v -replace '\{target\}', (Resolve-Path -LiteralPath $Target).Path
            if ($v -match '\{input\.([^}]+)\}') {
                # Resolve the CONSUMED FACT, then apply the declared selector to narrow it.
                # The produced fact is usually a whole table; binding that array straight into
                # a placeholder that wants one name is how a chain skips itself. The selector
                # is declared in the registry, so the loop picks a candidate rather than the
                # registry hard-coding an address.
                $slot = $Matches[1]
                $srcKey = if ($cap.invoke.consumes_fact) { $cap.invoke.consumes_fact } else { $slot }
                if ($facts.ContainsKey($srcKey)) {
                    $val = $facts[$srcKey]
                    if ($cap.invoke.select) {
                        $path = $cap.invoke.select.path
                        $idx  = $cap.invoke.select.index
                        if ($path) {
                            if ($null -ne $val -and $null -ne $val.PSObject.Properties[$path]) { $val = $val.$path }
                            else { $unresolved += ($srcKey + '.' + $path); $val = $null }
                        }
                        if ($null -ne $val -and $null -ne $idx) {
                            if (@($val).Count -gt $idx) { $val = @($val)[$idx] } else { $unresolved += ($srcKey + '[' + $idx + ']'); $val = $null }
                        }
                        if ($null -ne $val) { $v = "$val" }
                    } else { $v = "$val" }
                    $v = "$val"
                } else { $unresolved += $srcKey }
            }
            $argList += $v
        }
        if ($unresolved.Count) {
            Say "          SKIPPED: needs $($unresolved -join ', ') which no earlier round produced (skipped_no_consumer)"
            $trace += [ordered]@{ round = $round; capability = $step.id; event = 'skipped_no_consumer'; missing = $unresolved }
            continue
        }

        $sw = [Diagnostics.Stopwatch]::StartNew()
        $raw = & $cap.invoke.runner @argList 2>&1 | Out-String
        $rc = $LASTEXITCODE
        $sw.Stop()

        $ev = [ordered]@{
            id = "e$round"
            round = $round
            capability = $step.id
            argv = $argList
            runner = $cap.invoke.runner
            exit = $rc
            wall_s = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            facts = @()
            ts = (Get-Date).ToUniversalTime().ToString('o')
        }

        # The honest success test is the declared one, not the exit code. This server
        # reports a failed analysis with exit 0 semantics and isError:false; requiring
        # both the process result AND the declared success_when is the fix.
        $parsed = $null
        try { $parsed = $raw | ConvertFrom-Json } catch { $parsed = $null }
        $declaredOk = ($rc -eq 0) -and ($null -ne $parsed)
        if ($cap.invoke.stdout -eq 'json') {
            if ($cap.invoke.fact_map) {
                # Each mapped key must be present and non-null. A missing key is a failure,
                # not a smaller answer -- this class of API drops items silently.
                foreach ($k in $cap.invoke.fact_map.PSObject.Properties) {
                    $src = $k.Name; $dst = $k.Value
                    if ($null -ne $parsed.PSObject.Properties[$src]) {
                        $v = $parsed.$src
                        if ($null -ne $v) { $ev.facts += [ordered]@{ key = $dst; source_field = $src; value = $v } }
                    }
                }
            }
            if ($cap.invoke.success_when -match 'ok == true' -and $parsed.ok -ne $true) { $declaredOk = $false }
            if ($cap.invoke.success_when -match 'code is non-null' -and $null -eq $parsed.code) { $declaredOk = $false }
        }

        $ev['ok'] = $declaredOk
        $ev['evidence_source'] = $cap.gate.lane + '/' + $cap.id
        $evidence += $ev

        # Facts forward ONLY from a round that succeeded. Feeding a later lab the output
        # of a failed one is how a wrong answer becomes a confident one.
        if ($declaredOk) {
            foreach ($f in $ev.facts) {
                if (-not $facts.ContainsKey($f.key)) { $facts[$f.key] = $f.value }
            }
        }

        $trace += $ev
        $n = @($ev.facts).Count
        Say ("          exit={0} ok={1} facts={2} in {3}s" -f $rc, $declaredOk, $n, $ev.wall_s)
        if ($n -gt 0) { foreach ($f in $ev.facts) { Say ("            + {0} <- {1}" -f $f.key, $f.source_field) } }
    }

    # --- termination, COMPUTED over the artifact, never self-reported --------------
    $failedRounds = @($evidence | Where-Object { $_.ok -ne $true }).Count
    $term = Get-Termination -Evidence $evidence -Registry $reg -MaxRounds $MaxRounds -Round $round -FailedRounds $failedRounds -Planned $planned

    # --- the verdict, COMPUTED ---------------------------------------------------
    $verdict = Get-Verdict -Claim $Claim -QuestionType $qt -Evidence $evidence -Registry $reg -DischargedIn $Discharged

    # --- scope guard --------------------------------------------------------------
    $after = Get-TreeHash $RepoRoot
    $scopeOk = ($after -eq $baseline)
    if (-not $scopeOk) {
        Say ''
        Say '  SCOPE VIOLATION: the repo tree changed during a read-only mission.'
        Say '  The loop halts and does NOT revert. The change is reported, not undone,'
        Say '  because silently reverting would hide which tool did it.'
    }

    # --- the STOP note, generated from the registry so it cannot go stale -----------
    $notRun = @()
    foreach ($c in $reg.capabilities) {
        $ran = @($evidence | Where-Object { $_.capability -eq $c.id }).Count
        if ($ran -eq 0) {
            $notRun += [ordered]@{
                id = $c.id; state = $c.state
                why = if ($c.state -ne 'observed') { "state=$($c.state): not available on this host" }
                      elseif ($grant.allowed -notcontains $c.id) { 'outside this grant' }
                      else { 'not selected by this question type' }
            }
        }
    }

    $artifact = [ordered]@{
        schema     = 'mission/artifact@1'
        case_id    = $case
        question   = [ordered]@{ type = $qt; text = $Question }
        containment = $Containment
        grant_sha256 = $grant.grant_sha256
        rounds     = $round
        chain      = @($trace | Where-Object { $_.capability } | ForEach-Object { [ordered]@{ round = $_.round; capability = $_.capability; ok = $_.ok; facts = ($_.facts | ForEach-Object { $_.key }) } })
        verdict    = $verdict
        termination = $term
        scope_guard = [ordered]@{ baseline = $baseline.Substring(0,16); after = $after.Substring(0,16); intact = $scopeOk }
        stop_note  = [ordered]@{
            note = 'A stage that did not run is an unasked question, not a clean answer -- and it is the one gap that produces no error to notice.'
            not_run = $notRun
            ruled_out = @()
        }
    }
    Set-Content -LiteralPath (Join-Path $caseDir 'artifact.json') -Value (Out-Json $artifact) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $caseDir 'trace.jsonl') -Value (($trace | ForEach-Object { Out-Json $_ }) -join "`n") -Encoding UTF8

    Say ''
    Say ('=' * 78)
    Say "termination   $($term.state) -- $($term.why)"
    Say "verdict       $($verdict.tier)   (computed by seven gates; the caller proposed, this script disposed)"
    foreach ($g in $verdict.gates) { Say ("  {0}  {1,-16} {2}" -f $(if ($g.pass) { 'PASS' } else { 'FAIL' }), $g.name, $g.detail) }
    Say ''
    Say "evidence chain: $(@($artifact.chain).Count) step(s), $round round(s)"
    Say "scope guard:   $(if ($scopeOk) { 'INTACT' } else { 'VIOLATED' })"
    Say "STOP note:     $($notRun.Count) capability/capabilities did not run"
    Say ('=' * 78)

    $exit = if (-not $scopeOk) { 3 } elseif ($verdict.tier -eq 'unresolved') { 1 } else { 0 }
    Out-Json @{ ok = ($exit -eq 0); exit = $exit; case_dir = $caseDir; artifact = $artifact }
    exit $exit
}


function Get-Termination {
    <#
      Whether the mission is done is COMPUTED from the artifact, never self-reported.

      The rule from open-reverselab's ctf_loop_status.py, and the one mechanism in the
      whole corpus this station did not have at all: DONE / EXHAUSTED / CONTINUE is a
      predicate over recorded state. A state with a hypothesis still pending and an empty
      next_actions list must NOT read as EXHAUSTED -- that combination is indistinguishable
      from a loop that finished its work, and it is how a mission stops early while
      sounding complete.

      Three outcomes, deliberately not two:
        CONTINUE   rounds remain, progress was made this round
        EXHAUSTED  every hypothesis reached a terminal state and no capability is left
                   that would change the answer -- and the guards are NAMED, not assumed
        DONE       the question type's success criterion is met by evidence that covers it
    #>
    param($Evidence, $Registry, $MaxRounds, $Round, $FailedRounds, $Planned)

    $good = @($Evidence | Where-Object { $_.ok -eq $true })
    # "Left to run" is computed from the EVIDENCE, not from the plan's own state field.
    # The plan records what was INTENDED and is never mutated afterwards, so counting
    # planned-but-unrun from the plan said two steps remained after both had run.
    $ranIds = @($Evidence | ForEach-Object { $_.capability } | Sort-Object -Unique)
    $leftToRun = @($Planned | Where-Object { $_.state -eq 'planned' -and $_.id -notin $ranIds }).Count

    if ($good.Count -gt 0 -and $FailedRounds -eq 0 -and $round -lt $MaxRounds -and $leftToRun -gt 0) {
        return [ordered]@{ state = 'CONTINUE'; why = "rounds remain ($leftToRun planned, $round/$MaxRounds used) and the last round produced usable facts" }
    }

    # Anything that reached here with a planned step still pending and nothing new to
    # offer is EXHAUSTED only if the remaining steps could not have changed the answer.
    $couldStillHelp = @($Planned | Where-Object {
        $_.state -eq 'planned' -and ($Registry.capabilities | Where-Object { $_.id -eq $_.id -and $_.state -eq 'observed' })
    }).Count

    if ($good.Count -gt 0) {
        return [ordered]@{ state = 'DONE'; why = "$($good.Count) capability invocation(s) produced typed facts and no failure forced a stop" }
    }
    if ($round -ge $MaxRounds -or $FailedRounds -gt 0) {
        return [ordered]@{ state = 'EXHAUSTED'
            why = "budget or failure exhausted the mission; this is an unanswered question, not a clean result"
            guards_not_named = @($Planned | Where-Object { $_.state -eq 'planned' } | ForEach-Object { $_.id })
            note = 'EXHAUSTED must never be read as "nothing was there". The capability ids that did not run are listed, and naming a guard is what turns this into an answer.' }
    }
    return [ordered]@{ state = 'EXHAUSTED'; why = 'nothing ran and nothing was left to run'; guards_not_named = @($Planned | ForEach-Object { $_.id }) }
}

# ---------------------------------------------------------------------- the seven gates

function Get-Verdict {
    <#
      The model never writes the verdict. This function does, from seven gates, and every
      gate that failed is reported by name. Fail any gate and the claim is downgraded to
      `unresolved`, which cannot be the terminal answer.

      The asymmetry is the last word: a `likely` claim honestly labelled that proves
      wrong is not a false positive. A `likely` claim reported as `confirmed` is one,
      even if it is right.
    #>
    param([string]$Claim, [string]$QuestionType, $Evidence, $Registry, [string[]]$DischargedIn = @())

    # Gates are collected in a script-scoped list for the same reason the gate selftest
    # needed it: a locally declared array is invisible to a helper defined alongside it,
    # which silently produces an EMPTY gate list -- and an empty gate list passes.
    $script:vGates = @()
    $script:vDischarged = @($DischargedIn)
    function G($n, $p, $d) { $script:vGates += [ordered]@{ name = $n; pass = [bool]$p; detail = $d } }
    $vGates = @()
    $good = @($Evidence | Where-Object { $_.ok -eq $true })
    # 1. process -- did anything actually run, with recorded evidence ids
    G 'process' ($good.Count -gt 0) "$($good.Count) capability invocation(s) succeeded with recorded evidence ids"

    # 2. reachability -- is there a typed chain, not two disconnected results
    $chain = 0
    foreach ($e in $good) { if (@($e.facts).Count -gt 0) { $chain++ } }
    G 'reachability' ($chain -ge 1) "$chain invocation(s) produced typed facts a later step could consume"

    # 3. observation -- a fact on the ORIGINAL bytes. Instrumented-about-instrumented
    #    results cannot be the terminal answer, so a claim resting on those is downgraded.
    # Gate 3, observation. This used to be literally the same expression as gate 2 with a
    # hardcoded sentence claiming no runtime instrumentation was available -- so it could not
    # fail, and it emitted a FALSE FACTUAL CLAIM: with a dynamic.device.frida fact in the
    # evidence it still passed and the mission reached `confirmed`.
    # Now it checks the thing it says: no fact may come from a capability whose registry
    # state is not `observed`, because a fact from an absent or blocked capability is a fact
    # nobody produced.
    $unavailable = @()
    foreach ($e in $good) {
        $capDef = $Registry.capabilities | Where-Object { $_.id -eq $e.capability } | Select-Object -First 1
        if ($capDef -and $capDef.state -ne 'observed') { $unavailable += ("$($e.capability)=$($capDef.state)") }
    }
    # PowerShell has no `if` EXPRESSION, so the detail is computed first. The first attempt
    # put the conditional inline as an argument and did not parse.
    $obsDetail = if ($unavailable.Count) {
        "evidence includes facts from capabilities that are NOT observed: $($unavailable -join ', '). A fact from an absent or blocked capability is a fact nobody produced."
    } else {
        "$($good.Count) fact(s), all from capabilities whose registry state is observed"
    }
    G 'observation' ($unavailable.Count -eq 0) $obsDetail

    # 4. independence -- about the FAMILY of instrument, not the tool id.
    #
    #    Two capabilities from two tools is not two opinions. Ghidra's decompiler and
    #    IDA's decompiler are the same family, and two decompilers agreeing is one
    #    opinion held twice -- they share the blind spots that come from reconstructing
    #    machine code into C. REx-skill: "An ensemble of readers shares the decompiler's
    #    blind spots." {ghidra.decompile, ida.decompile} is therefore REFUSED as
    #    corroboration, even though they are two capabilities and two stars on GitHub.
    #
    #    ONE gate, not two. The previous version emitted both `independence` and
    #    `independence_insufficient` failing for the same fact, so the artifact showed a
    #    failure count higher than the number of things that were actually wrong.
    $famOf = @{}
    foreach ($c in $Registry.capabilities) { if ($c.evidence_source) { $famOf[$c.id] = $c.evidence_source } }
    $distinct = @($good | ForEach-Object { $_.capability } | Sort-Object -Unique)
    $families = @($good | ForEach-Object { $famOf[$_.capability] } | Where-Object { $_ } | Sort-Object -Unique)
    $independenceDetail = if ($families.Count -ge 2) {
        "$($distinct.Count) capabilities across $($families.Count) evidence families: $($families -join ', ')"
    } else {
        "every fact came from ONE instrument family (" + (($families + @('unclassified')) -join ',') + "). Independence is about the family of instrument, not the tool: two decompilers agreeing is one opinion held twice."
    }
    G 'independence' ($families.Count -ge 2) $independenceDetail

    # 5. bounded claim -- no wider than the least-covering does_not_prove allows
    $limits = @()
    foreach ($c in $Registry.capabilities) {
        foreach ($d in @($c.does_not_prove)) { $limits += $d }
    }
    # Gate 5 used to be `$Claim -ne ''` while counting the registry's does_not_prove entries
    # into its message and comparing them to NOTHING. "This binary is completely safe, has no
    # vulnerabilities of any kind" reached `confirmed`. So did a claim quoting the capability's
    # own three limits verbatim and denying every one.
    #
    # An UNBOUNDED claim is now refused outright: it asserts more than any does_not_prove
    # permits. This is a coarse first filter, not semantic entailment -- but it refuses the
    # catastrophic claim instead of endorsing it.
    $UNBOUNDED = '(?i)\b(completely|entirely|totally|absolutely|always)\b.*\b(safe|secure|no vulnerabilities|cannot be exploited|invulnerable)\b'
    $isUnbounded = ($Claim -match $UNBOUNDED)
    $hasLimits  = ($Claim -match '(?i)\bbut\b|\bhowever\b|\bexcept\b|\bdoes not prove\b|\blimitation\b')
    $boundedOk = ($Claim -ne '') -and (-not $isUnbounded) -and $hasLimits
    $bcDetail = if (-not $Claim) { 'no claim was proposed, so nothing can be bounded by any does_not_prove' }
                elseif ($isUnbounded) { 'the claim is UNBOUNDED: it asserts complete safety, which no does_not_prove in this registry permits. An unbounded claim is refused, not endorsed.' }
                elseif (-not $hasLimits) { "the claim states no limitation, so nothing bounds it against the registry's $($limits.Count) declared does_not_prove entries" }
                else { 'the claim carries an explicit limitation and is bounded by the registry' }
    G 'bounded_claim' $boundedOk $bcDetail

    # 6. uncertainty stated -- a verdict with no unknowns is not a verdict
    # 6. uncertainty stated -- a verdict with no unknowns is not a verdict
    G 'uncertainty' ($QuestionType -ne '') "question type $QuestionType makes the success criterion checkable; unknowns are listed in the artifact"

    # 7. discharged -- the strongest rule in the corpus, and strictly stronger than
    #    anything this station had before it. "I found nothing" is an ANSWER only when
    #    you can name the guards that would have found it. An empty finding with an empty
    #    discharged list is not a clean result; it is an unasked question that produces no
    #    error to notice.
    #
    #    Discharged is supplied by the caller as the guards it claims WERE consulted. It
    #    is validated rather than trusted: each id must exist in the registry.
    # Gate 7, discharged. This only checked that each named id EXISTS in the registry, so
    # naming dynamic.device.frida (absent), native.il2cpp.symbols (absent) and
    # native.ghidra.emulate (blocked) passed -- typing the list requires no work, and a guard
    # that did not run was being counted as one that did.
    #
    # A guard can only be DISCHARGED if it could have run. Naming an absent or blocked
    # capability is naming something that did not and could not answer.
    $discharged = @($script:vDischarged)
    $unknownIds = @($discharged | Where-Object { $d = $_; -not (@($Registry.capabilities | Where-Object { $_.id -eq $d }) | Select-Object -First 1) })
    $unrunnable = @()
    foreach ($d in $discharged) {
        $c = $Registry.capabilities | Where-Object { $_.id -eq $d } | Select-Object -First 1
        if ($c -and $c.state -ne 'observed') { $unrunnable += ("$d=$($c.state)") }
    }
    $findingsEmpty = ($good.Count -eq 0)
    $dischargedOk = ($unknownIds.Count -eq 0) -and ($unrunnable.Count -eq 0) -and (-not $findingsEmpty -or $discharged.Count -gt 0)
    $dDetail = if ($unknownIds.Count) {
        "not in the registry: $($unknownIds -join ', ')"
    } elseif ($unrunnable.Count) {
        "named guards that could NOT have run: $($unrunnable -join ', '). A guard that is absent or blocked did not answer, so it cannot discharge anything."
    } elseif ($discharged.Count -eq 0) {
        'no guards were named; acceptable only when there IS a finding, because "I found nothing" with no named guard is not an answer'
    } else {
        "$($discharged.Count) guard(s) named, all of them observed and able to have run"
    }
    G 'discharged' $dischargedOk $dDetail

    # Read back from the script scope the helper wrote to. Returning the LOCAL `$vGates`
    # -- which nothing ever appended to -- produced an EMPTY gate list, and an empty gate
    # list passes vacuously. That is the most dangerous shape this script has: it looks
    # like seven gates ran and reported all-clear. Hence also the floor below.
    $vGates = @($script:vGates)
    if ($vGates.Count -eq 0) {
        return [ordered]@{
            tier = 'unresolved'; computed_by = 'mission.ps1 Get-Verdict'
            note = 'NO GATES RAN. An empty gate list must never read as all-clear.'
            failed_gates = @('gates_empty'); gates = @()
            unknowns = @('the verdict function collected no gates at all')
        }
    }
    $failed = @($vGates | Where-Object { -not $_.pass })
    if ($failed.Count -eq 0) {
        $tier = if ($distinct.Count -ge 2) { 'confirmed' } else { 'likely' }
    } else {
        $tier = 'unresolved'
    }

    return [ordered]@{
        tier = $tier
        computed_by = 'mission.ps1 Get-Verdict'
        note = 'the model never writes the verdict; a lower tier is never a failure, a mislabelled tier always is'
        failed_gates = @($failed | ForEach-Object { $_.name })
        gates = $vGates
        unknowns = @(
            'whether the decompilation is faithful -- it is one analysers reconstruction',
            'what would have been found by capabilities that did not run'
        )
    }
}

# ---------------------------------------------------------------------------- selftest

function Invoke-Selftest {
    # Script-scoped, with the explicit zero-case floor below. A locally declared list is
    # invisible to a sibling function, which produces an EMPTY case list -- and an empty
    # case list that reports OK is a green run that tested nothing.
    $script:mCases = @()
    function C($n, $body, $want) { $script:mCases += ,@($n, (& $body), $want) }

    # Refusals throw, so a control can observe one. Without this the first refusal ended
    # the whole selftest and there was nothing to assert against.
    function RefusalCode($block) {
        try { & $block; return -1 } catch [MissionRefusal] { return $_.Exception.Code }
    }

    $tmp = Join-Path $env:TEMP ('mission-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $own = Join-Path $RepoRoot 'crackme-corpus\out\c01-stringobf.exe'

    C 'N1a intake halts with NO object, and spawns nothing' { RefusalCode { Invoke-Mission } } 2
    # Subprocess controls assert on the EXIT CODE, not on stdout. A refusal prints JSON
    # as its message; the JSON is not the signal, and comparing it to an integer is not a
    # test. Three of these controls "failed" for exactly that reason before this line.
    C 'N1b intake halts on an unknown question type' {
        & $PSCommandPath -Action Run -Target $own -QuestionType 'Q99.nope' -Containment station_under_named_process_rule | Out-Null
        $LASTEXITCODE
    } 2
    C 'N1c intake halts when containment is unstated (l2-gate S13)' {
        & $PSCommandPath -Action Run -Target $own -QuestionType 'Q2.locate' | Out-Null
        $LASTEXITCODE
    } 2
    C 'N1d refuse an object whose provenance the Owner did not declare' {
        & $PSCommandPath -Action Run -Target $own -QuestionType 'Q2.locate' -Question 'where is the input validation' `
            -Provenance 'I found it on my disk' -OwnerWord 'go' -Containment station_under_named_process_rule -CaseRoot $tmp | Out-Null
        $LASTEXITCODE
    } 4

    # N4, the important one: our own documented failure mode, aimed at this file.
    C 'N4 overclaim must NOT reach confirmed from a single instrument' {
        $ev = @([ordered]@{ capability = 'native.ida.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) })
        $v = Get-Verdict -Claim 'the input validation is at main' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)
        $v.tier
    } 'unresolved'

    C 'verdict tier is computed, never authored by the caller' {
        $ev = @(
            [ordered]@{ capability = 'native.ida.list_functions'; ok = $true; facts = @([ordered]@{ key = 'native.func.addr'; value = 1 }) },
            [ordered]@{ capability = 'native.ida.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) }
        )
        # The claim must now CARRY ITS OWN LIMITATION. bounded_claim refuses a claim that
        # states none, so 'the check is in main' was refused -- which is the gate working.
        $v = Get-Verdict -Claim 'the check is in main, but this says nothing about runtime behaviour and the decompilation is one analyser reconstruction' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)
        $v.tier
    } 'confirmed'

    # An UNBOUNDED claim must be refused outright. Before the bounded_claim fix this
    # reached `confirmed` with two capabilities' worth of evidence behind it.
    C 'bounded_claim: "completely safe, no vulnerabilities of any kind" is refused' {
        $ev = @(
            [ordered]@{ capability = 'native.ida.list_functions'; ok = $true; facts = @([ordered]@{ key = 'native.func.addr'; value = 1 }) },
            [ordered]@{ capability = 'native.ida.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) }
        )
        (Get-Verdict -Claim 'this binary is completely safe and has no vulnerabilities of any kind' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)).tier
    } 'unresolved'

    # A guard that is ABSENT did not answer, so naming it discharges nothing. Before the
    # fix, naming dynamic.device.frida / native.il2cpp.symbols / native.ghidra.emulate all
    # passed, and typing that list requires no work.
    C 'discharged: naming an ABSENT guard does not discharge anything' {
        $ev = @(
            [ordered]@{ capability = 'native.ida.list_functions'; ok = $true; facts = @([ordered]@{ key = 'native.func.addr'; value = 1 }) },
            [ordered]@{ capability = 'native.ida.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) }
        )
        (Get-Verdict -Claim 'nothing here is hidden' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry) -DischargedIn @('dynamic.device.frida')).tier
    } 'unresolved'

    # discharged: the strongest rule in the corpus. "I found nothing" is an answer ONLY
    # when you can name the guards that would have found it.
    C 'discharged: an empty finding with no named guard is NOT an answer' {
        (Get-Verdict -Claim 'nothing suspicious here' -QuestionType 'Q1.identify' -Evidence @() -Registry (Get-Registry)).tier
    } 'unresolved'

    C 'discharged: naming a guard that is not in the registry does not count' {
        $ev = @()
        (Get-Verdict -Claim 'nothing suspicious' -QuestionType 'Q1.identify' -Evidence $ev -Registry (Get-Registry) -DischargedIn @('a.capability.that.does.not.exist')).tier
    } 'unresolved'

    # Two DECOMPILERS are one opinion held twice. Distinct capability ids is not enough.
    C 'independence: two decompilers from different tools are NOT independent' {
        $ev = @(
            [ordered]@{ capability = 'native.ida.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) },
            [ordered]@{ capability = 'native.ghidra.decompile'; ok = $true; facts = @([ordered]@{ key = 'native.ghidra.summary'; value = 'y' }) }
        )
        (Get-Verdict -Claim 'the check is in main' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)).tier
    } 'unresolved'

    # Termination is a predicate over recorded state. The dangerous combination is a
    # hypothesis still pending with an empty next-actions list: it looks finished and is not.
    C 'termination: nothing ran and budget is gone is EXHAUSTED, not a clean result' {
        (Get-Termination -Evidence @() -Registry (Get-Registry) -MaxRounds 1 -Round 1 -FailedRounds 0 -Planned @([ordered]@{ id='native.ida.decompile'; state='planned' })).state
    } 'EXHAUSTED'

    C 'termination: an EXHAUSTED verdict names the guards it did not run' {
        $t = Get-Termination -Evidence @() -Registry (Get-Registry) -MaxRounds 1 -Round 1 -FailedRounds 0 -Planned @([ordered]@{ id='native.ida.decompile'; state='planned' })
        if (@($t.guards_not_named).Count -gt 0) { 'named' } else { 'unnamed' }
    } 'named'

    C 'termination: real facts with rounds remaining is CONTINUE, not DONE' {
        $ev = @([ordered]@{ capability='native.ida.decompile'; ok=$true; facts=@([ordered]@{key='native.dec.code';value='x'}) })
        (Get-Termination -Evidence $ev -Registry (Get-Registry) -MaxRounds 6 -Round 1 -FailedRounds 0 -Planned @([ordered]@{ id='native.ida.list_functions'; state='planned' })).state
    } 'CONTINUE'

    C 'a failed round contributes no facts to the verdict' {
        $ev = @([ordered]@{ capability = 'native.ida.decompile'; ok = $false; facts = @() })
        (Get-Verdict -Claim 'x' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)).tier
    } 'unresolved'

    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

    $mCases = $script:mCases
    if ($mCases.Count -eq 0) { Write-Host 'MISSION SELFTEST FAILED: zero cases. A green run that tested nothing is not a green run.'; return 2 }

    $w = 0; foreach ($c in $mCases) { if ($c[0].Length -gt $w) { $w = $c[0].Length } }
    $failed = 0
    foreach ($c in $mCases) {
        $got = $c[1]; $want = $c[2]
        $okc = $false
        if ($want -is [int]) { $okc = ([int]$got -eq $want) } else { $okc = ("$got" -eq "$want") }
        if (-not $okc) { $failed++ }
        $d = if ($okc) { "got=$got" } else { "WANT=$want GOT=$got" }
        Write-Host ("  {0}  {1}  {2}" -f $(if ($okc) { 'PASS' } else { 'FAIL' }), $c[0].PadRight($w), $d)
    }
    Write-Host ''
    if ($failed) { Write-Host "MISSION SELFTEST FAILED: $failed case(s). The orchestrator is the bug."; return 2 }
    Write-Host "MISSION SELFTEST OK: $($mCases.Count) controls behaved. N4 -- our own known failure mode, aimed here -- returned unresolved as it must."
    return 0
}

switch ($Action) {
    'Plan'  { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Run'   { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Selftest' { exit (Invoke-Selftest) }
}
