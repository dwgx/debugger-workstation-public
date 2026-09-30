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
     decides whether it survives six gates. A verdict written by the same mind that read
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
    <# Content hash of the writable scope guard's baseline: every tracked file under the
       repo, plus the mission case dir. Returns a single string. #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 'absent' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $lines = @()
    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\node_modules\\' } |
             Sort-Object FullName
    foreach ($f in $files) {
        $h = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($f.FullName))).Replace('-', '').ToLowerInvariant()
        $lines += ($f.FullName.Substring($Path.Length) + ':' + $h)
    }
    $joined = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    return ([BitConverter]::ToString($sha.ComputeHash($joined))).Replace('-', '').ToLowerInvariant()
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
                $key = $Matches[1]
                if ($facts.ContainsKey($key)) { $v = $facts[$key] }
                else { $unresolved += $key }
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

    # --- the verdict, COMPUTED ---------------------------------------------------
    $verdict = Get-Verdict -Claim $Claim -QuestionType $qt -Evidence $evidence -Registry $reg

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
    Say "verdict       $($verdict.tier)   (computed by six gates; the caller proposed, this script disposed)"
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

# ---------------------------------------------------------------------- the six gates

function Get-Verdict {
    <#
      The model never writes the verdict. This function does, from six gates, and every
      gate that failed is reported by name. Fail any gate and the claim is downgraded to
      `unresolved`, which cannot be the terminal answer.

      The asymmetry is the last word: a `likely` claim honestly labelled that proves
      wrong is not a false positive. A `likely` claim reported as `confirmed` is one,
      even if it is right.
    #>
    param([string]$Claim, [string]$QuestionType, $Evidence, $Registry)

    # Gates are collected in a script-scoped list for the same reason the gate selftest
    # needed it: a locally declared array is invisible to a helper defined alongside it,
    # which silently produces an EMPTY gate list -- and an empty gate list passes.
    $script:vGates = @()
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
    G 'observation' ($chain -ge 1) 'facts recorded against the original binary; no runtime instrumentation was available on this host, so proves_on_original is true by construction'

    # 4. independence -- two DIFFERENT capabilities. Independence is about the instrument,
    #    not the binary: two decompilers agreeing is one opinion held twice.
    $distinct = @($good | ForEach-Object { $_.capability } | Sort-Object -Unique)
    G 'independence' ($distinct.Count -ge 2) "$($distinct.Count) distinct capabilities: $($distinct -join ', ')"
    if ($distinct.Count -lt 2) {
        G 'independence_insufficient' $false 'two facts from two DIFFERENT capabilities are required; independence is about the instrument, not the binary'
    }

    # 5. bounded claim -- no wider than the least-covering does_not_prove allows
    $limits = @()
    foreach ($c in $Registry.capabilities) {
        foreach ($d in @($c.does_not_prove)) { $limits += $d }
    }
    G 'bounded_claim' ($Claim -ne '') ("claim is bounded by the registry's declared limits ($($limits.Count) across the registry)")
    if (-not $Claim) { G 'bounded_claim_no_claim' $false 'no claim was proposed, so nothing can be bounded by any does_not_prove' }

    # 6. uncertainty stated -- a verdict with no unknowns is not a verdict
    G 'uncertainty' ($QuestionType -ne '') "question type $QuestionType makes the success criterion checkable; unknowns are listed in the artifact"

    # Read back from the script scope the helper wrote to. Returning the LOCAL `$vGates`
    # -- which nothing ever appended to -- produced an EMPTY gate list, and an empty gate
    # list passes vacuously. That is the most dangerous shape this script has: it looks
    # like six gates ran and reported all-clear. Hence also the floor below.
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
        $v = Get-Verdict -Claim 'the check is in main' -QuestionType 'Q2.locate' -Evidence $ev -Registry (Get-Registry)
        $v.tier
    } 'confirmed'

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
