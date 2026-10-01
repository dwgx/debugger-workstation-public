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
  Ablate   rewrite each of the seven gates to `$true` in a temporary copy and prove the
           suite notices. A gate that can be deleted without turning the suite red is not
           a gate, it is a sentence in a comment. This is the control that keeps the
           other seven from rotting back into that.

.EXAMPLE
  powershell -File scripts\mission.ps1 -Action Run `
      -Target crackme-corpus\out\c01-stringobf.exe `
      -Question "where is the input validation" -QuestionType Q2.locate `
      -Provenance "Owner-authored; built by crackme-corpus/tools/loop.py from our own source" `
      -OwnerWord "analyze this exe" -Containment station_under_named_process_rule
  powershell -File scripts\mission.ps1 -Action Selftest
  powershell -File scripts\mission.ps1 -Action Ablate

.NOTES
  Exit codes: 0 = mission closed with a computed verdict · 1 = open/unresolved (a valid
  outcome, not a crash) · 2 = refused at intake, nothing ran · 3 = scope violation ·
  4 = provenance not declared by the Owner · 5 = grant tampered or missing ·
  6 = the caller tried to supply its own capability registry.

  THE BIGGEST RISK, stated in the design and unchanged by the implementation: the loop
  narrating work it did not do. A model that sounds confident across nine labs is doing
  exactly what it is good at. Every control here is therefore a program; N4 aims our own
  documented failure mode straight at this file.
#>
[CmdletBinding()]
param(
    [Parameter()][ValidateSet('Run', 'Plan', 'Selftest', 'Ablate')][string]$Action = 'Plan',
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
    <#
      The registry is NOT a caller-supplied input. Measured: `-Registry` fed
      Get-Verdict directly, so pointing it at a file whose capability `state` was
      flipped turned a BLOCKED capability into admissible evidence and gate 3,
      observation, passed on a fact no host could produce. Detecting a substituted
      file by content is a losing game -- the attacker edits the file too. The only
      defence that does not depend on the caller's honesty is to not accept one: the
      registry is the instrument's own calibration.
    #>
    if ($Registry) {
        Refuse 6 'caller-supplied registry refused' (
            "Refusing -Registry '$Registry'. The capability registry is the instrument's own calibration; " +
            'a caller that may substitute it can also declare a blocked capability observed, and every ' +
            'gate that reads `state` then reads the caller instead of the host.')
    }
    return (Get-Content -LiteralPath (Join-Path $RepoRoot 'manifests\capabilities.json') -Raw | ConvertFrom-Json)
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
    # -Containment is passed because gate.ps1 -Action New now REQUIRES it with no
    # default; without it the mint exits 3 and the whole -Action Run entry point is
    # dead. No new validation is needed here: Invoke-Intake already reduced $Containment
    # to exactly the three literals the gate accepts (mission.ps1, the `if ($Containment
    # -notin @(...))` check) before this line runs.
    $g = Invoke-Gate 'New' @{ '-Target' = $Target; '-Provenance' = $Provenance; '-OwnerWord' = $OwnerWord; '-CaseDir' = $caseDir; '-Containment' = $Containment }
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

    # What is still LEFT that could change the answer. Computed from the plan and the
    # registry TOGETHER: a planned step whose capability is not `observed` cannot answer,
    # so it is not a gap -- it is an absence the stop note already names. This used to be
    # computed into `$couldStillHelp` and then read by nothing.
    $couldStillHelp = @($Planned | Where-Object {
        $_.state -eq 'planned' -and ($Registry.capabilities | Where-Object { $_.id -eq $_.id -and $_.state -eq 'observed' })
    } | ForEach-Object { $_.id })

    # DONE is the strongest terminal state, so it carries the most conditions. Measured
    # before this fix: one good round PLUS one FAILED round still returned DONE while
    # printing "no failure forced a stop" -- a sentence about a condition never checked.
    # A mission that had a failure and reports DONE is reading its own gap as a verdict,
    # which is the exact error EXHAUSTED exists to prevent.
    if ($good.Count -gt 0 -and $FailedRounds -eq 0 -and $couldStillHelp.Count -eq 0 -and $leftToRun -eq 0) {
        return [ordered]@{ state = 'DONE'
            why = "$($good.Count) invocation(s) produced typed facts, no round failed, and no observed capability remained that could have changed the answer" }
    }
    if ($good.Count -gt 0 -and $FailedRounds -gt 0) {
        return [ordered]@{ state = 'EXHAUSTED'
            why = "$FailedRounds round(s) FAILED. A mission with a failure has not met its criterion, so it cannot be DONE; a partial result is not a clean one."
            failed_rounds = $FailedRounds
            guards_not_named = $couldStillHelp
            note = 'EXHAUSTED must never be read as "nothing was there". The capability ids that did not run are listed, and naming a guard is what turns this into an answer.' }
    }
    if ($good.Count -gt 0 -and ($couldStillHelp.Count -gt 0 -or $leftToRun -gt 0)) {
        return [ordered]@{ state = 'EXHAUSTED'
            why = "usable facts exist but $($couldStillHelp.Count) observed capability/capabilities were left unrun, so the answer is still open"
            guards_not_named = $couldStillHelp
            note = 'EXHAUSTED must never be read as "nothing was there". The capability ids that did not run are listed, and naming a guard is what turns this into an answer.' }
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

function Test-EvidenceIds {
    <#
      Every fact that reaches a gate must be TRACEABLE to one recorded round.

      The loop mints `id = "e$round"` and writes the same `round` onto the object
      (mission.ps1, the `$ev` literal in Invoke-Mission). Measured before this existed:
      NO gate read an id at all. A fabricated `"e7"` on a two-round mission and an
      empty string both reached `confirmed`, because the only things the verdict ever
      looked at were `ok` and `facts` -- both of which the caller writes by hand.

      Four conditions, all checkable without a new registry field:
        1. every entry has a non-empty id
        2. no id is used twice
        3. the id is well formed (`e<digits>`) and encodes the round the entry records
        4. the good ids are CONTIGUOUS from e1 -- a gap is a fabricated id, and a gap is
           the only shape a forgery takes when the forger cannot mint the record itself
    #>
    param($Evidence)
    $problems = @()
    $seen = @{}
    $n = 0
    foreach ($e in @($Evidence)) {
        $n++
        $id = "$($e.id)"
        if ([string]::IsNullOrWhiteSpace($id)) { $problems += "round $n ($($e.capability)) carries NO evidence id"; continue }
        if ($seen.ContainsKey($id)) { $problems += "evidence id '$id' is claimed by two rounds"; continue }
        if ($id -notmatch '^e(\d+)$') { $problems += "evidence id '$id' is not a round id (e<digits>)"; continue }
        $num = [int]$Matches[1]
        if ("$($e.round)" -ne '' -and [int]$e.round -ne $num) { $problems += "evidence id '$id' does not encode the round $($e.round) it records"; continue }
        $seen[$id] = $num
    }
    $good = @($Evidence | Where-Object { $_.ok -eq $true })
    $nums = @($good | ForEach-Object { if ("$($_.id)" -match '^e(\d+)$') { [int]$Matches[1] } } | Sort-Object)
    for ($i = 0; $i -lt $nums.Count; $i++) {
        if ($nums[$i] -ne ($i + 1)) { $problems += "good evidence ids are not contiguous from e1 (got $(($nums | ForEach-Object { 'e' + $_ }) -join ', ')): an id that resolves to no recorded round is a fabricated id"; break }
    }
    return $problems
}

function Get-RegistryFacts {
    <#
      The registry's typed graph, read once: what each capability PRODUCES and what each
      capability DECLARES IT CONSUMES. Both come from fields the registry already
      carries (`produces.facts[].key`, `invoke.fact_map`, `consumes.inputs[].from.field`,
      `invoke.consumes_fact`) -- no new schema, no sibling's files.
    #>
    param($Registry)
    $prod = @{}; $cons = @{}; $fam = @{}; $inst = @{}
    foreach ($c in @($Registry.capabilities)) {
        $pk = @()
        foreach ($f in @($c.produces.facts)) { if ($f.key) { $pk += $f.key } }
        if ($c.invoke -and $c.invoke.fact_map) { foreach ($p in $c.invoke.fact_map.PSObject.Properties) { $pk += $p.Value } }
        $ck = @()
        foreach ($i in @($c.consumes.inputs)) { if ($i.from -and $i.from.field) { $ck += $i.from.field } }
        if ($c.invoke -and $c.invoke.consumes_fact) { $ck += $c.invoke.consumes_fact }
        $prod[$c.id] = @($pk | Sort-Object -Unique)
        $cons[$c.id] = @($ck | Sort-Object -Unique)
        if ($c.evidence_source) { $fam[$c.id] = $c.evidence_source }

        # INSTRUMENT identity is a property of the CAPABILITY, never of a label that
        # happens to be spelled two ways. Measured: IDA Pro carries two `evidence_source`
        # values (`decompiler` on native.ida.decompile, `static-analysis` on
        # native.ida.list_functions), so ONE tool reached `confirmed` as two families.
        # The instrument is taken from the capability's declared `requires.tools`, and
        # where that is empty from the capability's own id namespace -- both properties
        # of the capability, and neither renamable without editing the registry.
        $tools = @()
        if ($c.requires -and $c.requires.tools) { $tools = @($c.requires.tools | ForEach-Object { $_.name } | Where-Object { $_ }) }
        if ($tools.Count -gt 0) { $inst[$c.id] = (@($tools | Sort-Object -Unique) -join '+') }
        else {
            $parts = @("$($c.id)".Split('.'))
            $inst[$c.id] = if ($parts.Count -ge 2) { $parts[1] } else { "$($c.id)" }
        }
    }
    return [ordered]@{ produces = $prod; consumes = $cons; family = $fam; instrument = $inst }
}

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
    $facts = Get-RegistryFacts $Registry

    # 1. process -- did anything actually run, AND is every round traceable to an id that
    #    resolves to a recorded round. The detail used to claim "recorded evidence ids"
    #    while nothing read one.
    $idProblems = Test-EvidenceIds $Evidence
    $processOk = ($good.Count -gt 0) -and ($idProblems.Count -eq 0)
    $processDetail = if (-not $good.Count) {
        'no capability invocation succeeded'
    } elseif ($idProblems.Count) {
        "evidence ids do not resolve to recorded rounds: $($idProblems -join '; ')"
    } else {
        "$($good.Count) capability invocation(s) succeeded, each with a unique, contiguous evidence id (e1..e$($good.Count))"
    }
    G 'process' $processOk $processDetail

    # 2. reachability -- a TYPED chain: the fact a capability DECLARES it consumes must be
    #    a fact an EARLIER round actually produced. Measured before this fix: two
    #    unrelated capabilities, with nothing consumed by anything, reached `confirmed`,
    #    while the gate's own docstring said "a typed chain, not two disconnected results".
    $hops = @(); $unbacked = @(); $have = @{}
    foreach ($e in $good) {
        $eid = "$($e.id)"
        $declared = @($facts.consumes["$($e.capability)"])
        foreach ($k in $declared) {
            if (-not $k) { continue }
            if ($have.ContainsKey($k)) { $hops += "$eid consumed '$k', produced earlier by $($have[$k])" }
            else { $unbacked += "$eid declares it consumes '$k', which no earlier round produced" }
        }
        foreach ($f in @($e.facts)) { if ($f.key -and -not $have.ContainsKey($f.key)) { $have[$f.key] = $eid } }
    }
    $reachOk = ($hops.Count -gt 0) -and ($unbacked.Count -eq 0)
    $reachDetail = if ($unbacked.Count) {
        "the chain is BROKEN: $($unbacked -join '; '). A capability cannot have consumed a fact that nothing produced."
    } elseif ($hops.Count -gt 0) {
        "$($hops.Count) typed hop(s): $($hops -join '; ')"
    } else {
        'no typed chain: no capability consumed a fact an earlier round produced. Two disconnected results are not corroboration.'
    }
    G 'reachability' $reachOk $reachDetail

    # 3. observation -- a fact on the ORIGINAL bytes, from a capability this host can
    #    actually run. A capability that is absent, blocked, or NOT IN THE REGISTRY AT ALL
    #    cannot have produced anything; before this fix an id absent from the registry was
    #    skipped by the `if ($capDef ...)` test and silently passed.
    $unavailable = @()
    foreach ($e in $good) {
        $capDef = $Registry.capabilities | Where-Object { $_.id -eq $e.capability } | Select-Object -First 1
        if (-not $capDef) { $unavailable += ("$($e.capability)=not-in-registry") }
        elseif ($capDef.state -ne 'observed') { $unavailable += ("$($e.capability)=$($capDef.state)") }
    }
    $obsDetail = if ($unavailable.Count) {
        "evidence includes facts from capabilities that are NOT observed: $($unavailable -join ', '). A fact from an absent or blocked capability is a fact nobody produced."
    } else {
        "$($good.Count) fact(s), all from capabilities whose registry state is observed"
    }
    G 'observation' ($unavailable.Count -eq 0) $obsDetail

    # 4. independence -- TWO AXES, and the family axis is a property of the INSTRUMENT,
    #    never of a per-capability label. Measured on the pre-fix gate: `families` was the
    #    set of `evidence_source` STRINGS, and one tool was free to supply two of them, so
    #    a registry edit that relabelled ONE capability manufactured a second family of
    #    evidence and a chain reached `confirmed` by construction. Measured concretely:
    #    `native.ida.list_functions` labelled `static-analysis` gave the chain
    #    list_functions -> decompile -> ghidra.decompile TWO families [decompiler,
    #    static-analysis] from TWO instruments, and it confirmed; and relabelling that one
    #    capability `binary-similarity` gave THREE families from TWO instruments, which is
    #    arithmetically impossible if a family belongs to an instrument.
    #
    #    So the family of an instrument is whatever its capabilities AGREE on:
    #      - they agree on one label -> that is the instrument's family, ONCE, no matter
    #                                how many capabilities contributed it;
    #      - they disagree           -> the registry does not state this instrument's
    #                                family, so it contributes NONE. Spelling a family
    #                                two ways is not a second family; it is the absence of
    #                                one, and it is the sibling registry's own written
    #                                rule ("two capabilities that drive the same instrument
    #                                are ONE opinion however they are labelled").
    #
    #    INVARIANT, and the reason a label can no longer buy anything: families are counted
    #    once per INSTRUMENT, so families <= instruments for every registry that has ever
    #    existed. Two decompilers (idalib-mcp and analyzeHeadless) are one opinion held
    #    twice, which is what this refusal has always said.
    $distinct = @($good | ForEach-Object { $_.capability } | Sort-Object -Unique)
    $instruments = @($distinct | ForEach-Object { $facts.instrument[$_] } | Where-Object { $_ } | Sort-Object -Unique)
    $labelsOf = @{}
    foreach ($cap in $distinct) {
        $ins = "$($facts.instrument[$cap])"
        if (-not $ins) { continue }
        if (-not $labelsOf.ContainsKey($ins)) { $labelsOf[$ins] = @() }
        if ($facts.family[$cap]) { $labelsOf[$ins] += "$($facts.family[$cap])" }
    }
    $families = @(); $unclassified = @()
    foreach ($ins in $instruments) {
        # @() around the PIPELINE, not around an `if` block: a one-element pipeline result
        # assigned from an `if` is unrolled to a scalar, and `'decompiler'[0]` is 'd'.
        $lbls = @($labelsOf[$ins] | Where-Object { $_ } | Sort-Object -Unique)
        if ($lbls.Count -eq 1) { $families += $lbls[0] }
        elseif ($lbls.Count -eq 0) { $unclassified += "$ins declares no evidence family" }
        else { $unclassified += "$ins spells its family $($lbls.Count) ways ($($lbls -join ', '))" }
    }
    $families = @($families | Sort-Object -Unique)
    $indepOk = ($families.Count -ge 2) -and ($instruments.Count -ge 2)
    $independenceDetail = if (-not $indepOk) {
        $why = "$($distinct.Count) capabilities resolve to $($instruments.Count) instrument(s) [$($instruments -join ', ')] carrying $($families.Count) distinct family/families [$($families -join ', ')]."
        if ($unclassified.Count) {
            $why += " A family is a property of the INSTRUMENT, not a label: $($unclassified -join '; ') -- so that instrument counts for no family at all."
        }
        if (($families.Count -lt 2) -and ($instruments.Count -ge 2)) {
            $why += ' Every instrument in this evidence sits in the SAME family, so the second witness is the first witness again.'
        }
        $why + ' Corroboration needs a SECOND INSTRUMENT and a second family of instrument: two labels from one tool are one opinion held twice, and so are two decompilers.'
    } else {
        "$($distinct.Count) capabilities across $($instruments.Count) instruments ($($instruments -join ', ')) carrying $($families.Count) distinct family/families [$($families -join ', ')] -- one family per instrument, never two"
    }
    G 'independence' $indepOk $independenceDetail

    # 5. bounded_claim -- the claim's SCOPE, derived from the question type and the
    #    capabilities that produced the evidence.
    #
    #    Measured before this fix: the gate was a five-token regex and any token anywhere
    #    passed. "100% safe" and "safe: no defects whatsoever, however ..." both reached
    #    `confirmed`, and `$limits` was computed and then compared to nothing.
    #
    #    Then a second, opposite failure, measured on our own Q2.locate acceptance run:
    #    requiring the CALLER to type a limitation word refused "the comparison against the
    #    decoded buffer happens in main" -- a located fact on the exact bytes
    #    native.ida.decompile claims it proves. That gate was measuring the caller's
    #    phrasing, not the claim's scope, which is the same defect as the keyword test: it
    #    decides the verdict from tokens in the string rather than from what the evidence
    #    covers. So the bound is now DERIVED:
    #
    #      (a) ABSENCE / UNIVERSAL is still refused outright, always. No does_not_prove can
    #          establish that nothing is there -- a limit on a tool cannot prove a negative.
    #          This is what refuses C1 and what refuses "100% safe".
    #      (b) SCOPE. At least one capability that produced the evidence must DECLARE this
    #          question type in its registry `question_types`. If none does, the evidence was
    #          gathered for a different question than the one being answered, and no bound
    #          exists to inherit. This is registry data, not a keyword.
    #      (c) A limitation the caller DID type must still be grounded in the producing
    #          capabilities' does_not_prove. Noise stays refused; only its ABSENCE stops
    #          being required.
    $LIMITMARK = '(?i)\b(but|however|except|although|though|nevertheless|that said|does not prove|do not prove|limitation|caveat)\b'
    $stop = @('this','that','they','them','with','from','into','does','not','never','nothing','prove','proven','proves','said','says','say','about','were','been','than','then','here','also','just','like','only','over','under','when','where','which','while','will','would','could','should','shall','have','has','had','one','two','some','such','more','most','very','many','much','might','make','makes','are','own','same','other','both','each','few','nor','too','their','there','because','onto')
    $ABSENCE = '(?i)\b(100\s*%|no|none|nothing|never|all|every|each|always|completely|entirely|totally|absolutely|universally|guarantee\w*|safe|secure|invulnerable|unhackable|unbreakable|exploit\w*|vulnerab\w*|defect\w*|bug\w*|harmless|clean)\b'
    $isUnbounded = $false
    $hasLimit = $false
    $assertion = $Claim
    $limitation = ''
    $m = [regex]::Match($Claim, $LIMITMARK)
    if ($m.Success) { $hasLimit = $true; $assertion = $Claim.Substring(0, $m.Index); $limitation = $Claim.Substring($m.Index) }
    if ($assertion -match $ABSENCE) { $isUnbounded = $true }

    function Toks($s) {
        $t = @()
        foreach ($x in [regex]::Matches("$s".ToLowerInvariant(), '[a-z][a-z0-9_]{3,}')) {
            if ($stop -contains $x.Value) { continue }
            $t += $x.Value
        }
        return @($t | Sort-Object -Unique)
    }
    $limitTokens = @()
    $limits = @()
    $inScope = @()
    foreach ($cap in $distinct) {
        $cd = $Registry.capabilities | Where-Object { $_.id -eq $cap } | Select-Object -First 1
        if (-not $cd) { continue }
        foreach ($d in @($cd.does_not_prove)) {
            if (-not $d) { continue }
            $limits += $d
            $limitTokens += Toks $d
        }
        # (b) The registry declares which questions each capability answers. That is the
        # scope of the evidence, and it is data rather than a token in the claim.
        if ($QuestionType -and (@($cd.question_types) -contains $QuestionType)) { $inScope += $cap }
    }
    $limitTokens = @($limitTokens | Sort-Object -Unique)
    $grounded = @(Toks $limitation | Where-Object { $limitTokens -contains $_ })
    # With no question type there is no scope to inherit; `uncertainty` owns that case, and
    # duplicating it here would make one fact fail two gates and blur every failed SET.
    $scopeOk = (-not $QuestionType) -or ($inScope.Count -gt 0)
    # A typed limitation must be grounded; an UNTYPED one is bounded by scope alone.
    $limitationOk = ((-not $hasLimit) -and $scopeOk) -or ($grounded.Count -gt 0)
    $boundedOk = ($Claim -ne '') -and (-not $isUnbounded) -and $scopeOk -and $limitationOk
    $bcDetail = if (-not $Claim) {
        'no claim was proposed, so nothing can be bounded by any does_not_prove'
    } elseif ($isUnbounded) {
        "the strongest assertion is an ABSENCE: `"$($assertion.Trim())`". No does_not_prove can establish that nothing is there -- a limit on a tool cannot prove a negative. An absence is answerable only through gate 7, by naming guards that EXECUTED."
    } elseif (-not $scopeOk) {
        "no capability that produced the evidence DECLARES question type '$QuestionType' in its registry question_types, so the evidence was gathered for a different question and there is no bound to inherit"
    } elseif ((-not $hasLimit) -and $scopeOk) {
        "the claim inherits its bound from the question type: $($inScope.Count) evidence-producing capability/capabilities declare '$QuestionType' ($($inScope -join ', ')), against $($limits.Count) declared does_not_prove entries"
    } elseif ($grounded.Count -eq 0) {
        "the claim carries a limitation word but it is GROUNDLESS: nothing in its stated limitation matches any does_not_prove of the capabilities that produced the evidence. `"however`" is not a bound."
    } else {
        "the claim's limitation is grounded in $($grounded.Count) declared does_not_prove entr(y/ies) of the capabilities that produced the evidence: $($grounded -join ', ')"
    }
    G 'bounded_claim' $boundedOk $bcDetail


    # 6. uncertainty stated -- a verdict with no unknowns is not a verdict
    G 'uncertainty' ($QuestionType -ne '') "question type $QuestionType makes the success criterion checkable; unknowns are listed in the artifact"

    # 7. discharged -- the strongest rule in the corpus. "I found nothing" is an ANSWER only
    #    when you can name the guards that would have found it. Measured before this fix:
    #    the gate checked that each named id EXISTS in the registry and is `observed`, and
    #    nothing more -- so naming four observed guards that NEVER RAN passed, and typing
    #    that list requires no work. Now every named guard must additionally appear in the
    #    recorded evidence with ok=true: a guard that did not execute did not answer.
    $discharged = @($script:vDischarged)
    $executed = @($good | ForEach-Object { $_.capability } | Sort-Object -Unique)
    $unknownIds = @()
    $unrunnable = @()
    $neverRan = @()
    foreach ($d in $discharged) {
        $c = $Registry.capabilities | Where-Object { $_.id -eq $d } | Select-Object -First 1
        if (-not $c) { $unknownIds += $d }
        elseif ($c.state -ne 'observed') { $unrunnable += ("$d=$($c.state)") }
        elseif ($executed -notcontains $d) { $neverRan += $d }
    }
    $findingsEmpty = ($good.Count -eq 0)
    $dischargedOk = ($unknownIds.Count -eq 0) -and ($unrunnable.Count -eq 0) -and ($neverRan.Count -eq 0) -and (-not $findingsEmpty -or $discharged.Count -gt 0)
    $dDetail = if ($unknownIds.Count) {
        "not in the registry: $($unknownIds -join ', ')"
    } elseif ($unrunnable.Count) {
        "named guards that could NOT have run: $($unrunnable -join ', '). A guard that is absent or blocked did not answer, so it cannot discharge anything."
    } elseif ($neverRan.Count) {
        "named guards that NEVER EXECUTED: $($neverRan -join ', '). They are observed and could have run, but no recorded round ran them -- a guard that was not run is not a guard that answered."
    } elseif ($discharged.Count -eq 0) {
        'no guards were named; acceptable only when there IS a finding, because "I found nothing" with no named guard is not an answer'
    } else {
        "$($discharged.Count) guard(s) named, all observed AND all present in the recorded evidence as executed rounds"
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

    # The signature a gate control asserts on: the TIER plus the exact SET of gates that
    # failed. A tier alone cannot tell seven gates from one -- which is precisely why six
    # of them were deletable with the suite still green. Asserting the set pins the
    # cause, so a control cannot pass for a second gate's reason.
    function Sig($v) { "$($v.tier) failed=$(@($v.failed_gates) -join '+')" }

    # THE SUBSTRATE. Every gate control below is read against this, so it satisfies all
    # seven gates; each control then changes exactly one thing to fail exactly one gate.
    #
    # Three rounds, and every field is real:
    #   e1 native.ida.list_functions -> native.func.addr, native.func.named
    #   e2 native.ida.decompile      DECLARES it consumes native.func.addr (consumes.inputs
    #                               [].from.field) and native.func.named (invoke.consumes_fact)
    #   e3 web.js.cdp                a second INSTRUMENT (chrome), so independence can pass
    # Evidence ids are contiguous e1..e3 so `process` passes; e1->e2 is a real typed hop so
    # `reachability` passes; every capability is observed; and $boundedClaim below is
    # grounded in their own does_not_prove entries.
    function ChainEvidence {
        return @(
            [ordered]@{ id = 'e1'; round = 1; capability = 'native.ida.list_functions'; ok = $true
                        facts = @([ordered]@{ key = 'native.func.addr'; value = '0x140001234' },
                                  [ordered]@{ key = 'native.func.named'; value = 'main' }) },
            [ordered]@{ id = 'e2'; round = 2; capability = 'native.ida.decompile'; ok = $true
                        facts = @([ordered]@{ key = 'native.dec.code'; value = 'int check(char*s){return 1;}' }) },
            [ordered]@{ id = 'e3'; round = 3; capability = 'web.js.cdp'; ok = $true
                        facts = @([ordered]@{ key = 'web.dom.nodes'; value = '<html/>' }) }
        )
    }
    # The pre-fix substrate, kept as the FALSIFICATION case: two unrelated capabilities
    # with nothing consumed by anything, which on the 2026-10-02 gates reached `confirmed`.
    # If it reaches confirmed again, reachability has rotted back.
    function TwoDisconnectedEvidence {
        return @(
            [ordered]@{ id = 'e1'; round = 1; capability = 'web.js.cdp'; ok = $true
                        facts = @([ordered]@{ key = 'web.dom.nodes'; value = 'x' }) },
            [ordered]@{ id = 'e2'; round = 2; capability = 'crypto.jose.parse'; ok = $true
                        facts = @([ordered]@{ key = 'crypto.jose.claims'; value = 'y' }) }
        )
    }
    # Bounded on purpose: it carries 'however', it asserts no absence, and its limitation is
    # GROUNDED -- "runtime behaviour" and "decompilation is one analysers reconstruction"
    # are words that appear in the does_not_prove of native.ida.decompile. A control that
    # another gate can turn green is worse than no control at all.
    $boundedClaim = 'the check is in main, however this says nothing about runtime behaviour and one decompilation is one analyser reconstruction'

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
        $ev = @([ordered]@{ id='e1'; round=1; capability = 'native.ida.decompile'; ok = $true
                            facts = @([ordered]@{ key = 'native.dec.code'; value = 'x' }) })
        (Get-Verdict -Claim 'the input validation is at main' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)).tier
    } 'unresolved'

    C 'verdict tier is computed, never authored by the caller' {
        # REPAIRED, not weakened. The substrate used to be two IDA capabilities, which is
        # exactly what the instrument-identity fix now refuses: two `evidence_source` labels
        # (`decompiler`, `static-analysis`) from ONE tool (idalib-mcp) is one instrument
        # spelling itself twice, and measured C1 reached `confirmed` that way. The claim is
        # still the bounded one and the expected tier is still `confirmed`; the evidence is
        # now a real typed chain across two real INSTRUMENTS. Same assertion, honest input.
        (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry)).tier
    } 'confirmed'

    # An UNBOUNDED claim must be refused outright. Before the bounded_claim fix this
    # reached `confirmed` with two capabilities' worth of evidence behind it.
    C 'bounded_claim: "completely safe, no vulnerabilities of any kind" is refused' {
        (Get-Verdict -Claim 'this binary is completely safe and has no vulnerabilities of any kind' `
            -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry)).tier
    } 'unresolved'

    # A guard that is ABSENT did not answer, so naming it discharges nothing. Before the
    # fix, naming dynamic.device.frida / native.il2cpp.symbols / native.ghidra.emulate all
    # passed, and typing that list requires no work.
    C 'discharged: naming an ABSENT guard does not discharge anything' {
        (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) `
            -Registry (Get-Registry) -DischargedIn @('dynamic.device.frida')).tier
    } 'unresolved'

    # discharged: the strongest rule in the corpus. "I found nothing" is an ANSWER ONLY
    # when you can name the guards that would have found it.
    C 'discharged: an empty finding with no named guard is NOT an answer' {
        (Get-Verdict -Claim 'nothing suspicious here' -QuestionType 'Q1.identify' -Evidence @() -Registry (Get-Registry)).tier
    } 'unresolved'

    C 'discharged: naming a guard that is not in the registry does not count' {
        (Get-Verdict -Claim 'nothing suspicious' -QuestionType 'Q1.identify' -Evidence @() `
            -Registry (Get-Registry) -DischargedIn @('a.capability.that.does.not.exist')).tier
    } 'unresolved'

    # Two DECOMPILERS are one opinion held twice. Distinct capability ids is not enough.
    #
    # FINDING, reported rather than hidden: this control can no longer isolate `independence`
    # on the FAMILY axis. Measured reason -- native.ida.decompile is the ONLY capability in
    # the registry that declares a consumed fact, so ANY substrate whose chain is valid
    # contains native.ida.list_functions, whose family is `static-analysis`. Families are
    # therefore already >= 2 whenever reachability passes, and the family axis can only
    # fail together with reachability. The instrument axis IS isolable, and the control
    # below ("two labels from ONE tool") covers that. This one keeps its own evidence and
    # pins the honest set: two decompilers are NOT independent, and the chain is absent.
    C 'independence: two decompilers from different tools are NOT independent' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ghidra.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.ghidra.summary'; value='y' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=reachability+independence'

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
        $ev = @([ordered]@{ id='e1'; round=1; capability = 'native.ida.decompile'; ok = $false; facts = @() })
        (Get-Verdict -Claim 'x' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)).tier
    } 'unresolved'

    # ------------------------------------------------------------------------------
    # C1. THE ACCEPTANCE CASE FOR THE WHOLE JOB.
    #
    # Quoted from this estate's own history: "the managed lab's wrong-entry-state case
    # produces a complete, confident, wrong answer, and the harness catches it." Measured on
    # the pre-fix code, this artefact -- every fact invented, NO TOOL RUN AT ALL, both
    # capabilities IDA Pro, four `observed` guards named that never ran -- scored 7/7 PASS,
    # failed_gates=[], tier=confirmed. It is here permanently, with the exact failed SET
    # pinned, because a suite that cannot name this failure is a suite that green-lights it.
    C 'C1 the complete, confident, wrong answer is REFUSED (all facts invented, no tool ran, all IDA)' {
        $inv = @(
            [ordered]@{ capability = 'native.ida.list_functions'; ok = $true
                        facts = @([ordered]@{ key = 'native.func.addr'; value = '0x140001234' }) },
            [ordered]@{ capability = 'native.ida.decompile'; ok = $true
                        facts = @([ordered]@{ key = 'native.dec.code'; value = 'int check(char*s){return 1;}' }) }
        )
        Sig (Get-Verdict -Claim 'there are no vulnerabilities of any kind, however this analysis never observed runtime values' `
            -QuestionType 'Q5.vuln-shape' -Evidence $inv -Registry (Get-Registry) `
            -DischargedIn @('native.ghidra.decompile', 're.corpus.solve', 'web.js.cdp', 'mobile.apk.static'))
    } 'unresolved failed=process+reachability+independence+bounded_claim+discharged'

    # Each of the five gates C1 trips has its own single-cause control below, so no one
    # control is carrying the whole refusal. Ablating any one of them still leaves C1 red
    # for the others, and each ablation reddens exactly its own control -- which is the
    # table `-Action Ablate` measures.

    # DEFECT 1 -- independence counted `evidence_source` STRINGS, so IDA Pro's two labels
    # (`decompiler` on native.ida.decompile, `static-analysis` on native.ida.list_functions)
    # counted as two instrument families and reached `confirmed`. Family identity must be a
    # property of the CAPABILITY: both declare `requires.tools = idalib-mcp`, so they are
    # one instrument.
    C 'gate independence: two labels from ONE tool (IDA) are one instrument' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=independence'

    # DEFECT 8 -- DEFECT 1's half-answer. The INSTRUMENT axis was fixed; the FAMILY axis was
    # still the set of per-capability `evidence_source` STRINGS, so the same tool could
    # still supply two families and any relabelling bought corroboration. The family is now
    # the INSTRUMENT's, counted once.
    #
    # The chain is the real acceptance shape: two IDA hops and one Ghidra hop. All three are
    # a decompiler's reconstruction of the same bytes, which the registry says in writing --
    # native.ghidra.decompile's evidence_source note reads "SAME FAMILY as IDA decompile" and
    # its does_not_prove says its only fact is a count and "the count is not a fidelity
    # claim". Three hops are not three opinions.
    #
    # Measured on the pre-fix gate with this exact evidence and a COPY of the registry in
    # which native.ida.list_functions is relabelled `static-analysis`:
    #   tier=confirmed failed=  3 capabilities across 2 instruments
    #                            (analyzeHeadless, idalib-mcp) and 2 evidence families
    #                            (decompiler, static-analysis)
    # That is the escape this control closes.
    C 'gate independence: IDA, IDA, then Ghidra is ONE opinion held twice, not three hops' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e3'; round=3; capability='native.ghidra.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.ghidra.summary'; value='y' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=independence'

    # DEFECT 8, the ATTACK, on a COPY. `manifests/` is never written: the mutation is made on
    # a JSON copy under %TEMP% and the ONLY difference is one `evidence_source` STRING.
    # Same claim, same evidence, one string.
    #
    #   pre-fix: relabelled -> `confirmed`, "2 evidence families" then 3 families from 2
    #            instruments, i.e. the label bought a family that no second tool provided.
    #   now:     live       -> `confirmed` (idalib-mcp and chrome really are two families)
    #            relabelled -> `unresolved failed=independence`, because idalib-mcp now
    #            spells its family two ways and therefore states no family at all.
    #
    # Both halves are asserted in one control on purpose: the refusal alone would also be
    # satisfied by a gate that refuses everything, so the control pins the honest verdict on
    # the live registry and the refusal on the mutated copy at the same time.
    C 'gate independence: relabelling ONE capability cannot manufacture a family' {
        $path = Join-Path $tmp 'capabilities-relabelled.json'
        $reg = Get-Registry
        foreach ($c in $reg.capabilities) {
            if ($c.id -eq 'native.ida.list_functions') { $c.evidence_source = 'binary-similarity' }
        }
        $reg | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $path -Encoding UTF8
        $mutated = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $liveSig = Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
        $mutSig = Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry $mutated)
        "live=$liveSig relabelled=$mutSig"
    } 'live=confirmed failed= relabelled=unresolved failed=independence'

    # DEFECT 8, the other side: a gate that refuses everything is not a gate. A chain whose
    # INSTRUMENTS sit in DIFFERENT families, and that is clean on every other axis, must
    # still reach `confirmed` -- measured on the LIVE registry, not on a fixture: idalib-mcp
    # is `decompiler` (static reconstruction of the bytes) and chrome is
    # `dynamic-observation` (watching a live page), which is a genuinely different kind of
    # witness from a genuinely different tool.
    #
    # The assertion reads the gate's OWN counts back rather than only the tier, so the
    # family axis is shown to be counting families: 2 from 2 instruments, never 3 from 2.
    C 'gate independence: two instruments in DIFFERENT families DO reach confirmed' {
        $v = Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry)
        $d = @($v.gates | Where-Object { $_.name -eq 'independence' })[0].detail
        $fam = [int]([regex]::Match($d, '(\d+) distinct family').Groups[1].Value)
        $ins = [int]([regex]::Match($d, '(\d+) instruments \(').Groups[1].Value)
        "$($v.tier) families=$fam instruments=$ins"
    } 'confirmed families=2 instruments=2'

    # DEFECT 2 -- `discharged` checked that each named guard EXISTS in the registry and is
    # `observed`. Naming four observed guards that NEVER RAN passed, and typing that list
    # requires no work. A guard that did not execute did not answer.
    C 'gate discharged: naming an OBSERVED guard that NEVER RAN fails discharged alone' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) `
            -Registry (Get-Registry) -DischargedIn @('net.pcap.analyse'))
    } 'unresolved failed=discharged'

    # DEFECT 3 -- bounded_claim was a five-token regex and `$limits` was compared to
    # nothing. "however" alone is not a bound: the limitation must be GROUNDED in a
    # does_not_prove belonging to a capability that produced the evidence.
    C 'gate bounded_claim: "however" with no grounding is not a bound' {
        Sig (Get-Verdict -Claim 'the check is in main, however everything is fine and the owner said so' `
            -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'unresolved failed=bounded_claim'

    # DEFECT 3, second half -- a claim of ABSENCE can never be bounded by a does_not_prove,
    # because a limit on a tool cannot prove a negative. This is gate 7's business.
    C 'gate bounded_claim: an absence claim ("no X at all") is refused however it is phrased' {
        Sig (Get-Verdict -Claim 'no vulnerabilities at all, however this analysis never observed runtime values' `
            -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'unresolved failed=bounded_claim'

    # DEFECT 4 -- reachability counted rounds that produced facts and never checked a chain.
    # Two unrelated capabilities with nothing consumed by anything reached `confirmed`.
    # Q4.data is the question type BOTH of these capabilities declare, so bounded_claim's
    # scope rule passes and reachability is the only gate that can fire here.
    C 'gate reachability: two unrelated capabilities with nothing consumed fail reachability alone' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q4.data' -Evidence (TwoDisconnectedEvidence) -Registry (Get-Registry))
    } 'unresolved failed=reachability'


    # MAIN's finding, 2026-10-02: on the real Q2.locate acceptance run the claim "the
    # comparison against the decoded buffer happens in main" was refused for stating no
    # limitation word. That measured the CALLER'S PHRASING, not the claim's scope -- the
    # same defect as the keyword test it replaced, deciding a verdict from tokens. A
    # located fact on the bytes native.ida.decompile claims it proves is bounded by SCOPE.
    # This is the exact claim from that run.
    C 'gate bounded_claim: a located Q2.locate claim is bounded by scope and needs no limitation word' {
        Sig (Get-Verdict -Claim 'the comparison against the decoded buffer happens in main' `
            -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'confirmed failed='

    # ...but the derived bound is SCOPE, not a free pass. No capability in this evidence
    # declares Q5.vuln-shape, so the evidence was gathered for a different question than
    # the one being answered and there is no bound to inherit.
    C 'gate bounded_claim: a claim whose question type NO evidence capability declares is out of scope' {
        Sig (Get-Verdict -Claim 'the comparison against the decoded buffer happens in main' `
            -QuestionType 'Q5.vuln-shape' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'unresolved failed=bounded_claim'

    # MAIN's second ask: the `discharged` detail says "acceptable only when there IS a
    # finding", and that conditional was prose in a string doing real work. Asserted here.
    C 'gate discharged: with a FINDING, naming no guards is accepted (the conditional holds)' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'confirmed failed='

    # The other arm of the same conditional: with NO finding, naming no guards is refused.
    C 'gate discharged: with NO finding, naming no guards is refused (the conditional holds)' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence @() -Registry (Get-Registry))
    } 'unresolved failed=process+reachability+independence+bounded_claim+discharged'

    # DEFECT 4, second half -- the chain may not be BROKEN either. native.ida.decompile
    # DECLARES it consumes native.func.addr; if no earlier round produced it, the round
    # consumed something nobody made. (native.func.named is its second declared input and is
    # produced by e1 here, so only native.func.addr is missing.)
    C 'gate reachability: a capability that consumed a fact NOBODY produced fails reachability alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e2'; round=2; capability='web.js.cdp'; ok=$true
                        facts=@([ordered]@{ key='web.dom.nodes'; value='y' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=reachability'

    # DEFECT 5 -- termination reported DONE with one good round and one FAILED round, while
    # printing "no failure forced a stop": a sentence about a condition never checked.
    # `$couldStillHelp` was computed and read by nothing.
    C 'gate termination: a FAILED round forbids DONE even with usable facts and budget left' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ida.decompile'; ok=$false; facts=@() }
        )
        (Get-Termination -Evidence $ev -Registry (Get-Registry) -MaxRounds 6 -Round 2 -FailedRounds 1 `
            -Planned @([ordered]@{ id='native.ida.list_functions'; state='planned' },
                       [ordered]@{ id='native.ida.decompile'; state='planned' })).state
    } 'EXHAUSTED'

    # The FIRST branch of Get-Termination owns "budget remains, progress was made" and
    # correctly returns CONTINUE. To reach the DONE question the budget must be gone, so
    # MaxRounds is 1 here: `$couldStillHelp` is non-empty (list_functions is observed and
    # still planned) and DONE must be refused.
    C 'gate termination: DONE is unreachable once the budget is gone with an OBSERVED capability unrun' {
        $ev = @([ordered]@{ id='e1'; round=1; capability='native.ida.decompile'; ok=$true
                            facts=@([ordered]@{ key='native.dec.code'; value='x' }) })
        (Get-Termination -Evidence $ev -Registry (Get-Registry) -MaxRounds 1 -Round 1 -FailedRounds 0 `
            -Planned @([ordered]@{ id='native.ida.list_functions'; state='planned' })).state
    } 'EXHAUSTED'

    # DEFECT 6 -- no gate read an evidence id. A fabricated id and an empty string both
    # reached `confirmed`, because the verdict only ever looked at `ok` and `facts`.
    C 'gate process: a FABRICATED evidence id that resolves to no round fails process alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id='e7'; round=7; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e3'; round=3; capability='web.js.cdp'; ok=$true
                        facts=@([ordered]@{ key='web.dom.nodes'; value='y' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=process'

    C 'gate process: an EMPTY evidence id fails process alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id=''; round=2; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e3'; round=3; capability='web.js.cdp'; ok=$true
                        facts=@([ordered]@{ key='web.dom.nodes'; value='y' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=process'

    # DEFECT 7 -- `-Registry` fed Get-Verdict directly, so a caller could point the verdict
    # at a registry whose capability states were flipped while the grant stayed bound to the
    # real one. The flag is refused outright rather than content-sniffed.
    C 'a caller-supplied -Registry is REFUSED, not honoured' {
        $script:Registry = (Join-Path $env:TEMP 'not-the-real-registry.json')
        $code = RefusalCode { Get-Registry | Out-Null }
        $script:Registry = ''
        $code
    } 6

    # ------------------------------------------------------------------------------
    # THE SEVEN GATE CONTROLS.
    #
    # Measured 2026-10-02: rewriting any six of these seven gates to `$true` left this
    # entire suite green. `bounded_claim` was the only load-bearing gate, so "the model
    # never writes the verdict" -- the claim this whole function exists for -- was
    # enforced by one gate in seven and the suite could not tell the difference.
    #
    # Each control below builds evidence for which EXACTLY ONE gate can fail, then
    # asserts the failed SET, not the tier. Proof of isolation is not asserted here, it
    # is measured: `-Action Ablate` rewrites one gate at a time and reports whether the
    # suite noticed. Seven controls, seven gates, one row each.
    #
    # All of them read `process` and `reachability` off the substrate, so those two gates
    # cannot fire on their account and no control here is green for a neighbour's reason.

    C 'gate reachability: two rounds that produced NO typed facts fail reachability alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true; facts=@() },
            [ordered]@{ id='e2'; round=2; capability='web.js.cdp'; ok=$true; facts=@() }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=reachability'

    C 'gate observation: a fact from an ABSENT capability fails observation alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e3'; round=3; capability='dynamic.device.frida'; ok=$true
                        facts=@([ordered]@{ key='dyn.frida.trace'; value='z' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=observation'

    # A capability id that is not in the registry at all used to be SKIPPED by the
    # `if ($capDef ...)` test and silently passed observation.
    # A capability id that is not in the registry at all used to be SKIPPED by the
    # `if ($capDef ...)` test and silently passed observation. An invented id contributes
    # no family and no instrument, so web.js.cdp is added to keep independence satisfied and
    # leave `observation` as the only failing gate.
    C 'gate observation: a capability that is NOT IN THE REGISTRY fails observation alone' {
        $ev = @(
            [ordered]@{ id='e1'; round=1; capability='native.ida.list_functions'; ok=$true
                        facts=@([ordered]@{ key='native.func.addr'; value='0x1400' },
                                [ordered]@{ key='native.func.named'; value='main' }) },
            [ordered]@{ id='e2'; round=2; capability='native.ida.decompile'; ok=$true
                        facts=@([ordered]@{ key='native.dec.code'; value='x' }) },
            [ordered]@{ id='e3'; round=3; capability='web.js.cdp'; ok=$true
                        facts=@([ordered]@{ key='web.dom.nodes'; value='y' }) },
            [ordered]@{ id='e4'; round=4; capability='a.capability.i.invented'; ok=$true
                        facts=@([ordered]@{ key='made.up'; value='z' }) }
        )
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry))
    } 'unresolved failed=observation'

    C 'gate bounded_claim: an unbounded safety claim fails bounded_claim alone' {
        Sig (Get-Verdict -Claim 'this binary is completely safe and has no vulnerabilities of any kind' `
            -QuestionType 'Q2.locate' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'unresolved failed=bounded_claim'

    C 'gate uncertainty: an unstated question type fails uncertainty alone' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType '' -Evidence (ChainEvidence) -Registry (Get-Registry))
    } 'unresolved failed=uncertainty'

    C 'gate discharged: naming a guard that could not have run fails discharged alone' {
        Sig (Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence (ChainEvidence) `
            -Registry (Get-Registry) -DischargedIn @('dynamic.device.frida'))
    } 'unresolved failed=discharged'

    C 'gate process: nothing succeeded, and `process` is named the failed gate' {
        # Named guards, all observed AND executed, so `discharged` cannot also fire.
        $v = Get-Verdict -Claim $boundedClaim -QuestionType 'Q2.locate' -Evidence @() `
            -Registry (Get-Registry) -DischargedIn @('native.ida.list_functions')
        "$($v.tier) process=$(@($v.gates | Where-Object { $_.name -eq 'process' })[0].pass)"
    } 'unresolved process=False'

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

function Invoke-Ablate {
    <#
      Is every one of the seven gates load-bearing, or are six of them a sentence in a
      comment that happens to look like a gate?

      Measured 2026-10-02, on the version that had 15 controls: rewriting any six of the
      seven `G '<name>' <expr>` expressions to `$true` left the whole suite green. This
      function is the instrument that found it, and it is kept so it cannot be undone
      quietly: it does the same seven rewrites, one at a time, on a temporary copy.

      Three things keep this from being a check that always passes:
        1. A PRISTINE copy is run first. If the suite is already red, "load-bearing" means
           nothing, so this refuses rather than reporting seven meaningless verdicts.
        2. The rewrite is matched on the `G '<name>'` CALL SITE, not a line number, and
           a rewrite that matches nothing is an ERROR, not a pass. A silently-unapplied
           rewrite would report the gate as untested for the wrong reason.
        3. The copy is deleted in a `finally`, so an exception cannot leave one behind.

      The copy lives BESIDE the script, not in %TEMP%: `$RepoRoot` is derived from
      `$PSScriptRoot`, so a copy anywhere else cannot find manifests\capabilities.json and
      every control would fail for an environmental reason instead of the gate's.
    #>
    $names = @('process', 'reachability', 'observation', 'independence', 'bounded_claim', 'uncertainty', 'discharged')
    $src = Get-Content -LiteralPath $PSCommandPath -Raw
    $copy = Join-Path $PSScriptRoot ('mission-ablate-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $loadBearing = 0; $unproved = 0; $errs = 0

    try {
        Set-Content -LiteralPath $copy -Value $src -NoNewline -Encoding UTF8
        & powershell -NoProfile -ExecutionPolicy Bypass -File $copy -Action Selftest *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ABORT: the unmodified copy's selftest already exits $LASTEXITCODE, so no gate can be shown load-bearing."
            return 3
        }

        foreach ($n in $names) {
            # `G '<name>' <pass-expr> <detail>` -- the pass expression is a parenthesised
            # group or a bare variable; the detail is whatever follows the next space.
            # Both shapes occur in this file and both match here.
            $rx = "(?m)^(\s*G\s+'" + [regex]::Escape($n) + "'\s+)(\([^()]*\)|\$\w+|[A-Za-z_]\w*)(\s+\S.*)$"
            $hits = [regex]::Matches($src, $rx)
            if ($hits.Count -ne 1) {
                Write-Host ("  {0,-14} ERROR: matched {1} call site(s); expected exactly 1" -f $n, $hits.Count)
                $errs++
                continue
            }
            $patched = [regex]::Replace($src, $rx, '$1$true$3')
            Set-Content -LiteralPath $copy -Value $patched -NoNewline -Encoding UTF8
            & powershell -NoProfile -ExecutionPolicy Bypass -File $copy -Action Selftest *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-Host ("  {0,-14} load-bearing" -f $n)
                $loadBearing++
            } else {
                Write-Host ("  {0,-14} NOT TESTED (suite stayed green)" -f $n)
                $unproved++
            }
        }
    } finally {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host ("ABLATE: {0} load-bearing, {1} unproved, {2} rewrite error(s)." -f $loadBearing, $unproved, $errs)
    if ($loadBearing -eq $names.Count -and $errs -eq 0) { return 0 }
    return 3
}

switch ($Action) {
    'Plan'  { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Run'   { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Selftest' { exit (Invoke-Selftest) }
    'Ablate' { exit (Invoke-Ablate) }
}
