#Requires -Version 5.1
<#
.SYNOPSIS
  The mission layer. Takes a target and a question, and runs the registered capabilities
  in an order derived from their declared dependencies, recording a typed evidence chain.

.DESCRIPTION
  Nine labs that each run standalone are islands. This is the layer that composes them:
  it reads the REGISTRY to decide which capabilities answer the question, runs each one in
  isolation behind the gate, records the facts it produced, and feeds those facts forward.
  The route is derived, never tabulated: a capability is eligible because the registry says
  it is `observed` and lists this question type in its own `question_types`, and a
  capability whose runner binds another capability's fact is preceded by whatever produces
  it. `Get-Route` is that derivation and its docstring is its specification.

  Five properties do the real work, and each one exists because its absence was a
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

  5. A QUESTION NOTHING CAN SERVE IS REFUSED, NOT PLANNED EMPTY. `-Action Plan` for
     Q3.behaviour, Q4.data and Q6.crypto used to print `0 step(s)` and exit 0: a mission
     that ran nothing and reported success. An empty route, or a route in which not one
     step is invocable, is a refusal with a non-zero exit that NAMES the capability that
     would have served the question. See `Get-RouteRefusal`.
.PARAMETER Action
  Run      execute a mission end to end
  Plan     print the route the registry gives this question type and exit without running
           a single tool. A route that cannot run anything is a REFUSAL (exit 2), not a plan.
  Selftest prove the orchestrator is not decorative (controls N1-N4 and the routing controls)
  Ablate   rewrite each of the seven gates to `$true` in a temporary copy, then rewrite each
           of the six routing rules, and prove the suite notices either way. A gate that can
           be deleted without turning the suite red is not a gate, it is a sentence in a
           comment. This is the control that keeps the other seven from rotting back into
           that, and it is now also what keeps the route derived from the registry.


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
  outcome, not a crash) · 2 = refused at intake or at planning -- nothing ran, either
  because the intake is incomplete or because no capability can serve the question type, in
  which case the refusal NAMES the missing one · 3 = scope violation ·
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
    [string[]]$SeedFact = @(),
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


# ----------------------------------------------------------------------------- the route
#
# WHICH capabilities a question type runs used to be the hardcoded seven-entry hashtable
# below, keyed to a private `needs` list that no rule in this repository could check. The
# registry has declared `question_types` per capability all along; `grep question_types
# scripts/` matched one local variable, so nothing reconciled the two and nothing read the
# field. Measured consequences (`docs/research/composition-plan.md:194-202`): Q3, Q4 and
# Q6 planned zero steps and exited 0, and Q5 and Q7 routed capabilities the registry does
# not assign them at all.
#
# The direction taken here is that THE REGISTRY WINS. It is the instrument's own
# calibration -- `Get-Registry` refuses a caller-supplied substitute for exactly that
# reason -- so a second routing table in the orchestrator can only ever disagree with it,
# and the disagreement is invisible. Where the two used to conflict, the declaration is
# kept and the route follows it: Q5.vuln-shape is a fuzzing question, and answering it by
# decompiling function 0 was this file disagreeing with the registry rather than a route.
# Where following the registry leaves a question with nothing to run, the answer is the
# refusal below, which names the gap instead of hiding it.

function Get-CapabilityFacts {
    <#
      The fact keys ONE capability publishes: `produces.facts[].key`, plus every value of
      `invoke.fact_map` (the same source `Get-RegistryFacts` reads for the verdict gates,
      so the planner and the verdict can never disagree about what a capability produces).
    #>
    param($Capability)
    if (-not $Capability) { return @() }
    $keys = @()
    foreach ($f in @($Capability.produces.facts)) { if ($f.key) { $keys += "$($f.key)" } }
    if ($Capability.invoke -and $Capability.invoke.fact_map) {
        foreach ($p in $Capability.invoke.fact_map.PSObject.Properties) { if ($p.Value) { $keys += "$($p.Value)" } }
    }
    return @($keys | Sort-Object -Unique)
}

function Get-ArgvSlots {
    <#
      Every `{input.x}` placeholder in a capability's own `invoke.argv`, paired with the
      FACT KEY the substitution loop will look up for it: `invoke.consumes_fact` when the
      entry declares one, the slot name otherwise. That is verbatim what the loop computes
      (the `$srcKey` line in `Invoke-Mission`), so predicting it here cannot drift from it.
    #>
    param($Capability)
    if (-not ($Capability -and $Capability.invoke -and $Capability.invoke.argv)) { return @() }
    $src = "$($Capability.invoke.consumes_fact)"
    $slots = @()
    foreach ($a in @($Capability.invoke.argv)) {
        if ("$a" -match '\{input\.([^}]+)\}') {
            $name = $Matches[1]
            $slots += [ordered]@{ slot = $name; source = $(if ($src) { $src } else { $name }) }
        }
    }
    return @($slots)
}

function Get-CapabilityEdges {
    <#
      One capability's declared consumed facts, each classified HARD or SOFT. This
      classification is the whole of "honour declared edges", and it is DERIVED from
      fields the registry already carries rather than authored here:

        HARD  the capability's own runner binds the fact -- either the edge's `from.field`
              is the entry's `invoke.consumes_fact`, or the edge's input name appears as a
              `{input.<name>}` placeholder in `invoke.argv`. A HARD edge is a fact the loop
              WILL try to substitute, and it makes the round record `skipped_no_consumer`
              when the fact is missing. So a HARD edge has to be satisfied by an earlier
              round, and the planner now guarantees that BEFORE a tool runs instead of
              discovering it afterwards as a recorded skip -- which reads safe and is not.
        SOFT  a declared refinement the runner does not bind. The registry marks these
              `required: false`, and they never pull a producer into the mission and never
              drop the consumer; the plan lists them and whether the mission happens to
              satisfy them.

      A capability that genuinely does not need a fact says so IN THE REGISTRY, by leaving
      the fact unbound in its own argv. There is no code path here that can decide a fact
      is unnecessary: that judgement belongs to whoever measured the tool.
    #>
    param($Capability)
    if (-not $Capability) { return @() }
    $slotNames = @(Get-ArgvSlots $Capability | ForEach-Object { $_.slot })
    $consumesFact = "$($Capability.invoke.consumes_fact)"
    $edges = @()
    foreach ($i in @($Capability.consumes.inputs)) {
        if (-not ($i.from -and $i.from.field -and $i.from.capability)) { continue }
        $bound = (($consumesFact -eq "$($i.from.field)") -or ($slotNames -contains "$($i.name)"))
        $edges += [ordered]@{
            input    = "$($i.name)"
            fact     = "$($i.from.field)"
            producer = "$($i.from.capability)"
            required = [bool]$i.required
            hard     = [bool]$bound
        }
    }
    return @($edges)
}

function Get-Route {
    <#
      The capabilities a question type runs, DERIVED from the registry. Six rules, in this
      order, each one registry data and each one separately ablated by `-Action Ablate`:

        1. STATE.  Eligible only if the registry `state` is `observed`. `absent` and
           `blocked` are never planned and never pulled in as a producer, and each is
           recorded in `unavailable` BY NAME with its state -- so "nothing was planned" and
           "nothing could ever be planned" read differently. This is the same filter
           `gate.ps1`'s `Get-GrantableIds` applies when minting; applying it here too is
           what stops an absent capability reaching the plan at all.

        2. QUESTION TYPE.  The eligible capability must list this question type in its own
           `question_types`. The registry states which questions each capability answers.

        3. UNPRODUCIBLE REQUIRED INPUT.  An input the registry itself marks `unproduced`
           has no producer anywhere, so the capability cannot run however it is selected.
           Dropped, and named.

        4. HARD-EDGE CLOSURE.  A capability whose runner binds another capability's fact
           pulls that producer into the mission, whatever question type the producer
           declares for ITSELF -- a producer is present because an edge needs it, and the
           step says so in `selected_by`. Iterated to a fixpoint, so a producer with its
           own hard edge brings its own producer. This is the composition the hardcoded
           table could not express: Q3.behaviour and Q7.origin both reach
           `native.ida.list_functions` this way even though that capability declares only
           Q1 and Q2.

        5. UNMET HARD EDGE.  A capability is DROPPED when a fact its runner binds is
           produced by nothing in the mission. Planning it anyway is the silent failure
           this function replaces.

        6. NO PRODUCER PULLED IN FOR A REFINEMENT.  Rule 4 fires on hard edges only. A
           soft edge is a refinement: a mission that fuzzes parsers does not thereby owe
           itself a JOSE parse, and the plan lists the refinement as unmet rather than
           inventing the work.

      ORDER, and the tie-break, stated because an unexplainable tie-break is a different
      kind of silent behaviour: a capability runs AFTER whatever produces a fact its runner
      binds (the registry's `consumes.inputs[].from`, never the order somebody typed), and
      every remaining tie is broken by the capability's index in the registry's own
      `capabilities` array. An index in a sequence is a total order, so two equally
      eligible capabilities are never ordered by anything a reader cannot see, and the
      index travels on every step as `registry_index`. A CYCLE among declared edges --
      possible only in a registry that declares one -- is broken at that same index and
      reported in `cycles`, never looped on.
    #>
    param($Registry, [string]$QuestionType)

    $all = @($Registry.capabilities)
    $byId = @{}; $idx = @{}
    for ($i = 0; $i -lt $all.Count; $i++) { $byId["$($all[$i].id)"] = $all[$i]; $idx["$($all[$i].id)"] = $i }

    $selected = @()
    $unavailable = @()
    $dropped = @()
    $emitted = @{}
    $cycles = @()

    # Why a capability cannot be planned at all, whatever selects it. Rules 1 and 3.
    # `return $null` is the routable answer and emits nothing, so the caller's test is a
    # plain truthiness check -- and a capability that IS routable returns no string at all.
    function Get-Blocker($capDef) {
        if (-not $capDef) { return 'not in the registry' }
        # ABLATE-ANCHOR state-filter
        $stateOk = ("$($capDef.state)" -eq 'observed')
        if (-not $stateOk) {
            return "state=$($capDef.state). An absent or blocked capability is a claim, not a capability: its probe never ran, so no mission may plan it and no edge may pull it in as a producer."
        }
        $bad = @($capDef.consumes.inputs | Where-Object { $_.unproduced -and $_.required })
        # ABLATE-ANCHOR unproduced-input
        $unproduced = @($bad | ForEach-Object { $_.name })
        if ($unproduced.Count -gt 0) {
            return "required input(s) $($unproduced -join ', ') are declared unproduced by the registry itself, so nothing in this repository can supply them: $($bad[0].unproduced.reason)"
        }
        return $null
    }

    # --- rules 1 and 2: the declared candidates --------------------------------
    foreach ($c in $all) {
        # ABLATE-ANCHOR question-type-filter
        $declares = (@($c.question_types) -contains $QuestionType)
        if (-not $declares) { continue }
        $blocker = Get-Blocker $c
        if ($blocker) {
            # `reason` is present on BOTH lists so a caller never has to know which list a
            # capability fell out of in order to say what went wrong with it.
            $tag = if ("$($c.state)" -ne 'observed') { "state=$($c.state)" } else { 'unproduced_required_input' }
            $unavailable += [ordered]@{ id = $c.id; state = "$($c.state)"; reason = $tag; detail = $blocker }
            continue
        }
        $selected += [ordered]@{
            id = $c.id; selected_by = 'declared'; registry_index = $idx["$($c.id)"]
            why = "the registry lists $QuestionType in this capability's own question_types, and its state is observed"
        }
    }

    # --- rule 4: close over hard edges, to a fixpoint ---------------------------
    # `$have` is the membership test and it only ever grows, which is what makes this
    # terminate. It is NOT `$emitted` (that is the ordering pass's own set) and it is not
    # "is the producer in $selected yet": the first version of this loop asked the latter
    # only through `$grew`, appended the same producer again on every pass, and Q2.locate
    # hung for five minutes growing a list that could never reach a fixpoint. A closure
    # that does not terminate is not a slow route, it is a hung mission.
    $have = @{}
    foreach ($x in $selected) { $have[$x.id] = $true }
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($s in @($selected)) {
            $hard = @(Get-CapabilityEdges $byId[$s.id] | Where-Object { $_.hard })
            $absent = @($hard | Where-Object { $byId.ContainsKey($_.producer) -and -not $have.ContainsKey($_.producer) } |
                        ForEach-Object { $_.producer } | Sort-Object -Unique)
            # ABLATE-ANCHOR edge-closure
            $pull = @($absent)
            foreach ($p in $pull) {
                $blocker = Get-Blocker $byId[$p]
                if ($blocker) { $have[$p] = $true; continue }   # an absent/blocked producer is never pulled in, and is not retried
                $have[$p] = $true
                $edge = @($hard | Where-Object { $_.producer -eq $p })[0]
                $selected += [ordered]@{
                    id = $p; selected_by = "producer:$($s.id)"; registry_index = $idx[$p]
                    why = "present because $($s.id) binds $($edge.fact) in its own invoke.argv; this capability publishes it, and the registry assigns it to other question types only"
                }
                $grew = $true
            }
        }
    }

    # --- rule 5: a hard edge nothing in this mission produces -------------------
    $produced = @{}
    foreach ($s in $selected) { foreach ($k in @(Get-CapabilityFacts $byId[$s.id])) { $produced[$k] = $true } }
    $keep = @()
    foreach ($s in $selected) {
        $hard = @(Get-CapabilityEdges $byId[$s.id] | Where-Object { $_.hard })
        # ABLATE-ANCHOR unmet-hard-edge
        $unmetHard = @($hard | Where-Object { -not $produced.ContainsKey($_.fact) })
        if ($unmetHard.Count -gt 0) {
            $e = $unmetHard[0]
            $dropped += [ordered]@{ id = $s.id; reason = 'unmet_hard_edge'
                why = "its runner binds $($e.fact) from input '$($e.input)' and nothing in this mission produces that fact; the declared producer is $($e.producer), which this route could not admit" }
            continue
        }
        $keep += $s
    }
    $selected = $keep

    # --- rule 6: a precondition whose CONSUMERS are in this plan -------------------
    # A precondition that declares only one question type is a gate that runs on some
    # paths and not others. MEASURED 2026-10-02: native.pe.packer is gate_role
    # 'precondition' but declared Q1.identify only, while the consumers it exists to
    # protect -- native.ida.decompile, native.ida.list_functions, native.ghidra.decompile,
    # native.disasm.capstone -- declare Q2.locate, Q3.behaviour and Q7.origin. A Q2.locate
    # mission aimed at a UPX-packed binary planned six capabilities, the packer was not
    # among them, and round 2 DECOMPILED THE PACKED TARGET, producing native.dec.code.
    #
    # Applicability now follows WHAT IT GATES rather than a question type it happens to
    # share. This rule can only ever ADD a gate to a plan, never remove one.
    $pulledGates = @()
    $plannedIds = @{}
    foreach ($s in $selected) { $plannedIds[$s.id] = $true }
    foreach ($c in $all) {
        if ("$($c.invoke.gate_role)" -ne 'precondition') { continue }
        if ($plannedIds.ContainsKey($c.id)) { continue }
        $gates = @($c.invoke.gates)
        if ($gates.Count -eq 0) { continue }
        foreach ($g in $gates) {
            if (-not $plannedIds.ContainsKey($g)) { continue }
            # TRUTHINESS, NOT .Count. First attempt used `@(Get-Blocker $c).Count -gt 0`, and
            # Get-Blocker returns a SINGLE EMPTY element when there is nothing to report --
            # so the array has one member, the count is 1, and the gate was skipped every time.
            # Diagnosed by printing it: `blocker=` empty, count 1. Filtering on the element
            # itself is the correct test, and this is the same trap that reachability-report.py
            # hit two days ago in the opposite direction.
            if (@(Get-Blocker $c | Where-Object { $_ }).Count -gt 0) { continue }
            # `why` IS NOT OPTIONAL. The route invariant requires every selected capability to
            # carry a stated reason, and the mission selftest caught this rule breaking it --
            # "unsound=4 native.pe.packer:no-reason". A capability that appears in a plan with no
            # reason given is exactly the kind of thing this project has been removing all along.
            $selected += [pscustomobject]@{
                id = $c.id
                selected_by = "precondition gating $g"
                why = "it is a precondition and $g is in this plan, so it gates something this mission would otherwise run; it declares a different question type and would otherwise never be consulted"
            }
            $plannedIds[$c.id] = $true
            $pulledGates += [ordered]@{ id = $c.id; gates = $g
                why = "this precondition was not selected by question type, but it gates $g which IS in this plan; a gate that skips the paths it exists to protect is not a gate" }
            break
        }
    }
    foreach ($pg in $pulledGates) { $dropped += $pg }

    # A producer whose consumer was just dropped is doing unrequested work. Prune to a
    # fixpoint, and say so on the step that survives.
    $pruned = $true
    while ($pruned) {
        $pruned = $false
        $live = @($selected | ForEach-Object { $_.id })
        foreach ($s in @($selected)) {
            if ("$($s.selected_by)" -notlike 'producer:*') { continue }
            $consumer = "$($s.selected_by)".Substring(9)
            if ($live -notcontains $consumer) {
                $selected = @($selected | Where-Object { $_.id -ne $s.id })
                $pruned = $true
            }
        }
    }

    # --- ORDER: a consumer after its producer, ties by registry index -----------
    # Recursive depth-first over registry order, so a chain reads as a chain: the producer
    # is emitted immediately before the capability that binds it. A capability is marked
    # emitted BEFORE its producers are visited, which is what makes this terminate on a
    # registry that declares a cycle -- and the cycle is reported, not swallowed.
    $onStack = @{}
    $cycles = New-Object System.Collections.ArrayList
    function Get-Order($ids) {
        $out = @()
        foreach ($id in $ids) {
            if ($emitted.ContainsKey($id)) {
                if ($onStack.ContainsKey($id)) { $cycles.Add($id) }
                continue
            }
            $emitted[$id] = $true
            $onStack[$id] = $true
            $deps = @(Get-CapabilityEdges $byId[$id] | Where-Object { $_.hard -and $byId.ContainsKey($_.producer) } |
                      ForEach-Object { $_.producer } | Sort-Object -Unique)
            foreach ($p in $deps) { $out += Get-Order @($p) }
            $onStack.Remove($id)
            $out += $id
        }
        return @($out)
    }
    $order = Get-Order @($selected | ForEach-Object { $_.id } | Sort-Object { $idx[$_] })
    $ordered = @()
    # PRECONDITIONS RUN FIRST. Measured before this existed: native.pe.packer declared
    # gate_role:precondition and was ordered round 5 of 5 -- LAST, in a Q1.identify mission whose
    # whole purpose is to decide whether decompiling is safe. **A gate that runs after the thing
    # it gates is not a gate**; it is a footnote that arrives once the damage is done.
    #
    # The partition is by role only and is STABLE within each half, so the existing edge ordering
    # and the registry-index tie-break are untouched. Ties among preconditions still fall back to
    # registry_index, which keeps the plan deterministic -- a precondition whose position moved
    # run to run would make every mission unreproducible.
    $order = @(@($order | Where-Object {
                    $cc = $byId[$_]
                    "$($cc.invoke.gate_role)" -eq 'precondition'
                }) + @($order | Where-Object {
                    $cc = $byId[$_]
                    "$($cc.invoke.gate_role)" -ne 'precondition'
                }))
    foreach ($id in $order) {
        $s = @($selected | Where-Object { $_.id -eq $id })[0]
        if (-not $s) { continue }
        $c = $byId[$id]
        $edges = @(Get-CapabilityEdges $c)
        $ordered += [ordered]@{
            id = $s.id; selected_by = $s.selected_by; registry_index = $idx[$id]; why = $s.why
            required_by = @($edges | Where-Object { $_.hard } | ForEach-Object {
                [ordered]@{ input = $_.input; fact = $_.fact; from = $_.producer } })
            optional_inputs = @($edges | Where-Object { -not $_.hard } | ForEach-Object {
                [ordered]@{ input = $_.input; fact = $_.fact; from = $_.producer
                            satisfied = $produced.ContainsKey($_.fact) } })
            produces = @(Get-CapabilityFacts $c)
        }
    }


    return [ordered]@{
        question_type = $QuestionType
        source = 'manifests/capabilities.json -- this file declares no capability list of its own'
        ordering = 'a capability declaring invoke.gate_role = precondition runs FIRST, because it is a gate on the rest and a gate that runs last gates nothing; within each half the existing rule holds -- a capability runs after whatever produces a fact its own invoke.argv binds, and every remaining tie is broken by the registry index, carried on each step as registry_index'
        rules = @('state must be observed', 'question_types must list this question',
                  'a required input the registry marks unproduced blocks the capability',
                  'a hard edge pulls its producer in, whatever question type that producer declares',
                  'a hard edge nothing produces drops the capability',
                  'a refinement edge pulls nothing in')
        steps = @($ordered)
        unavailable = @($unavailable)
        dropped = @($dropped)
        cycles = @($cycles)
    }
}

function Resolve-PlanSteps {
    <#
      The route annotated with what this mission can actually DO about each step: does the
      registry declare an `invoke` block, is the id inside the grant, and can every `{input.x}`
      slot be filled from a fact some earlier step produces OR from a fact the caller seeded
      with -SeedFact. A step that cannot run is RECORDED with its reason and never absorbed --
      "a stage that did not run is an unasked question" -- and the reasons stay
      distinguishable, because "nothing could serve this question" and "nothing you are
      permitted to run" are different failures with different fixes.

      The seeded keys matter here and not only in the loop: the planner decides which steps are
      runnable BEFORE the fact store exists, so a caller-supplied fact that the planner cannot
      see would leave its capability permanently skipped. That was the first thing the
      demonstration caught.
    #>
    param($Route, [string[]]$Allowed, $Registry, [string[]]$Seeded = @())

    $produced = @{}
    foreach ($s in $Route.steps) {
        $c = $Registry.capabilities | Where-Object { $_.id -eq $s.id } | Select-Object -First 1
        foreach ($k in @(Get-CapabilityFacts $c)) { $produced[$k] = $true }
    }
    # A caller-supplied fact is available to the planner for the same reason it is available to
    # the loop. Marked apart in the artifact; treated identically when deciding what can run.
    foreach ($sd in @($Seeded)) {
        $sk = ("$sd" -split '=', 2)[0]
        if ($sk) { $produced[[string]$sk] = $true }
    }

    $out = @()
    foreach ($s in $Route.steps) {
        $c = $Registry.capabilities | Where-Object { $_.id -eq $s.id } | Select-Object -First 1
        $slots = @(Get-ArgvSlots $c)
        # ABLATE-ANCHOR argv-slot
        $unresolvedSlots = @($slots | Where-Object { -not $produced.ContainsKey($_.source) })
        $state = 'planned'
        $why = $s.why
        if (-not $c.invoke) {
            $state = 'skipped_no_invoke'
            $why = 'the registry declares no invoke block, so the loop cannot call it with arguments'
        } elseif ($Allowed -notcontains $s.id) {
            $state = 'skipped_not_in_grant'
            $why = 'inside the registry, and outside this grant'
        } elseif ($unresolvedSlots.Count -gt 0) {
            $state = 'skipped_unmet_input'
            $why = ("its invoke.argv binds " +
                    (($unresolvedSlots | ForEach-Object { '{input.' + $_.slot + '}' }) -join ', ') +
                    ', which resolves to fact ' +
                    (($unresolvedSlots | ForEach-Object { "'" + $_.source + "'" }) -join ', ') +
                    ' -- and nothing in this mission produces that, so the round would record skipped_no_consumer')
        }
        $out += [ordered]@{
            id = $s.id; state = $state; why = $why
            selected_by = $s.selected_by; registry_index = $s.registry_index
            # `consumes` and `produces` keep the shape plan.json@1 already had, so
            # anything that read them still reads them; the edge detail is additive.
            consumes = $(if ($c.invoke) { $c.invoke.consumes_fact } else { $null })
            produces = $(if ($c.invoke) { $c.invoke.fact_map } else { $null })
            produces_fact_keys = @(Get-CapabilityFacts $c)
            required_by = @($s.required_by)
            optional_inputs = @($s.optional_inputs)
        }
    }
    return @($out)
}

function Get-RouteRefusal {
    <#
      The message a plan must REFUSE with, or $null when the plan is real. Two distinct
      refusals, because they have different fixes and merging them is how "0 steps, exit 0"
      happened:

        (a) the registry routes NOTHING for this question type -- every declared capability
            is `absent`, `blocked`, or dropped. The detail names them.
        (b) the registry routes something and not one step of it is INVOCABLE -- no
            `invoke` block, or outside the grant. The detail names each one and its reason.

      Measured before this existed: `-Action Plan -QuestionType Q6.crypto` printed
      `plan 0 step(s)` and exited 0. That is the worst answer available -- it reads as
      success having run nothing -- so it is now impossible from either direction.
    #>
    param($Route, $Steps)

    $nRouted = @($Route.steps).Count
    $nBlocked = @($Route.unavailable).Count
    $nDropped = @($Route.dropped).Count

    if ($nRouted -eq 0) {
        # The name is the whole point of this refusal. It is collected from both lists
        # because "every declared capability is absent" and "every declared capability was
        # dropped for an unmet edge" are different gaps and name different capabilities.
        $named = @(@($Route.unavailable) + @($Route.dropped) | ForEach-Object {
            $tag = if ($_.reason) { $_.reason } else { "state=$($_.state)" }
            "$($_.id) [$tag]" })
        return ("no capability in manifests/capabilities.json can serve '" + $Route.question_type + "': " +
                "the registry declares $nBlocked for it that cannot run at all, and $nDropped dropped from the route, " +
                "leaving nothing. Named: " +
                ($(if ($named.Count) { $named -join '; ' } else { 'nothing declares that question type at all' })) +
                '. Nothing ran and nothing will. This is a refusal, not an empty answer.')
    }
    if ($null -ne $Steps -and @(@($Steps) | Where-Object { $_.state -eq 'planned' }).Count -eq 0) {
        $detail = @($Steps | ForEach-Object { "$($_.id) [$($_.state)]: $($_.why)" })
        return ("the registry routes " + $Route.question_type + " to $nRouted capability/capabilities " +
                'and not one of them is invocable under this grant: ' + ($detail -join '; ') +
                '. A plan that can run nothing is not a plan, and an exit 0 having run nothing reads as success. ' +
                'Fix the named gap in the registry.')
    }
    return $null
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
function Get-Sha256Hex {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path))) -replace '-','')
    } finally { $sha.Dispose() }
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

    # The CLOSED ENUMERATION of question types is the registry's, not this file's. It was
    # a seven-key hashtable here, which is a second place to forget a question type and a
    # second place to disagree with `manifests/capabilities.json` about what one is; the
    # registry now owns the list AND the one-line description each type carries.
    $known = @()
    if ($reg.schema.question_types) { $known = @($reg.schema.question_types.PSObject.Properties.Name) }
    if ($known.Count -eq 0) {
        Refuse 2 'the registry declares no question types' ("manifests/capabilities.json has no schema.question_types, so there is no question to route. Known types: none.")
    }
    if ($known -notcontains $qt) {
        Refuse 2 "unknown question type '$qt'" ("the registry declares: " + (($known | Sort-Object) -join ', '))
    }
    $qtext = "$($reg.schema.question_types.PSObject.Properties[$qt].Value)"

    if (-not $Containment) {
        Refuse 2 'containment unstated or unnameable' 'l2-gate.md S13. Refuse to guess.'
    }
    if ($Containment -notin @('station_under_named_process_rule', 'loopback_capture', 'isolated_vm')) {
        Refuse 2 "unnamed containment '$Containment'" 'known: station_under_named_process_rule | loopback_capture | isolated_vm'
    }

    # The default question text is RETURNED, not assigned to `$Question` here. Assigning it
    # in this function created a function-local that shadowed the script-scope parameter, so
    # the banner printed `question [Q1.identify]` with nothing after it and no error
    # anywhere: the default had been computed and thrown away on every single mission.
    return @{ registry = $reg; question_type = $qt; question_text = $qtext }
}

# -------------------------------------------------------------------------------- run

function Invoke-Mission {
    $intake = Invoke-Intake
    $reg = $intake.registry
    $qt = $intake.question_type
    if (-not $Question) { $Question = $intake.question_text }

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

    # --- the ROUTE, from the registry, before a grant exists ---------------------
    # Computed before the mint on purpose. An unservable question type is refused with
    # nothing spawned at all, rather than after a grant has been written for a mission that
    # was never going to run anything. `Get-RouteRefusal` also has a second, grant-aware
    # arm, called again below: a route that exists and cannot be invoked is a different
    # failure with a different fix, and the two must not be reported as one.
    $route = Get-Route -Registry $reg -QuestionType $qt
    $empty = Get-RouteRefusal -Route $route
    if ($empty) { Refuse 2 "question type '$qt' has no routable capability" $empty }

    # --- the grant, then the plan, on disk, before any tool runs -----------------
    # The grant is minted by gate.ps1 and by nothing else. -Containment is passed because
    # gate.ps1 -Action New now REQUIRES it with no default; without it the mint exits 3 and
    # the whole -Action Run entry point is dead. No new validation is needed here:
    # Invoke-Intake already reduced $Containment to exactly the three literals the gate
    # accepts before this line runs.
    #
    # The route was computed BEFORE the mint, so the grant's only remaining job is to say
    # which of the routed steps this particular mission is permitted to run. Every step,
    # in the order the registry implies, each carrying WHY it is in this mission. A step
    # that cannot run is recorded with its reason and never absorbed: a stage that did not
    # run is an unasked question, not a clean answer.
    $g = Invoke-Gate 'New' @{ '-Target' = $Target; '-Provenance' = $Provenance; '-OwnerWord' = $OwnerWord; '-CaseDir' = $caseDir; '-Containment' = $Containment }
    if ($g.code -ne 0) {
        if ($g.code -eq 4) { Refuse 4 'provenance not declared by the Owner' 'No subprocess was spawned. The control held.' }
        Refuse 5 'gate refused to mint a grant' $g.raw.Trim()
    }
    $grant = $g.obj.grant
    Say "  grant         $($grant.grant_sha256.Substring(0,16))…  $($g.obj.allowed_count) capabilities allowed"

    # A PLAN IS A CLAIM ABOUT WORLD STATE AT ONE INSTANT, AND NOTHING HERE BOUND IT.
    # Adopted from Terraform's plan/apply split: `plan -out=FILE` saves a speculative plan and
    # `apply FILE` refuses a stale one rather than warning about it, because the vendor's own
    # words are that "other changes made to the target system in the meantime might cause the
    # final effect ... to be different than what an earlier speculative plan indicated". A grant
    # hash was already recorded and it is not enough: it says the GRANT did not change, while the
    # authorisation decision was computed FROM the registry, and the registry is a plain file any
    # sibling agent or the Owner can edit mid-flight.
    #
    # So the registry is hashed at plan time and re-hashed before every round. A change is a
    # REFUSAL, not a warning -- the alternative is executing an authorisation decision computed
    # from a registry that no longer exists, which is reviewing a change and having the code
    # edited underneath you.
    # .NET, NOT Get-FileHash. gate.ps1 already hit this exact trap and wrote the reason down at
    # :173-176: that cmdlet lives in a module which is not loaded in this context, and it fails
    # with "CommandNotFoundException" under a name that LOOKS like a built-in. Repeating the
    # mistake because the obvious spelling was the wrong one cost one mission run.
    $regHash = Get-Sha256Hex (Join-Path $PSScriptRoot '..\manifests\capabilities.json')
    Say "  registry      $($regHash.Substring(0,16))…  bound into this plan; a mid-flight edit is refused"
    $planned = @(Resolve-PlanSteps -Route $route -Allowed @($grant.allowed) -Registry $reg -Seeded @($SeedFact))
    $runnable = @($planned | Where-Object { $_.state -eq 'planned' }).Count

    Say "  route         $runnable of $(@($route.steps).Count) routed capability/capabilities are invocable under this grant"
    foreach ($p in $planned) {
        # A planned step is annotated with the EDGE it will consume, because that edge is
        # why it is in this mission and what an earlier round has to produce for it. A step
        # that will not run is annotated with WHY it will not run, because that string is
        # the difference between a mission and a gap.
        $detail = $p.why
        if ($p.state -eq 'planned') {
            $detail = $p.selected_by
            if (@($p.required_by).Count) {
                $detail += ' <- ' + ((@($p.required_by) | ForEach-Object { "$($_.fact) from $($_.from)" }) -join ', ')
            } elseif (@($p.optional_inputs).Count) {
                $detail += ' (refinement unmet: ' + ((@($p.optional_inputs) | ForEach-Object { "$($_.fact)" }) -join ', ') + ')'
            }
        }
        Say ("    {0,-30} {1,-21} {2}" -f $p.id, $p.state, $detail)
    }
    if (@($route.unavailable).Count) {
        Say ("  never routed  " + ((@($route.unavailable) | ForEach-Object { "$($_.id) (state=$($_.state))" }) -join ', '))
    }
    if (@($route.dropped).Count) {
        Say ("  dropped       " + ((@($route.dropped) | ForEach-Object { "$($_.id) [$($_.reason)]" }) -join ', '))
    }
    Say "  order         $($route.ordering)"

    $plan = [ordered]@{
        schema       = 'mission/plan@1'
        case_id      = $case
        created_at   = (Get-Date).ToUniversalTime().ToString('o')
        target       = (Resolve-Path -LiteralPath $Target).Path
        question     = [ordered]@{ type = $qt; text = $Question }
        containment  = $Containment
        provenance   = [ordered]@{ text = $Provenance; declared_by_owner = [bool]$OwnerWord }
        gate         = [ordered]@{ grant_sha256 = $grant.grant_sha256; allowed = $grant.allowed }
        route        = [ordered]@{
            source = $route.source
            rules = $route.rules
            ordering = $route.ordering
            unavailable = $route.unavailable
            dropped = $route.dropped
            cycles = $route.cycles
        }
        capabilities = $planned
        budget       = [ordered]@{ max_rounds = $MaxRounds }
        proposed_claim = $Claim
    }
    Set-Content -LiteralPath (Join-Path $caseDir 'plan.json') -Value (Out-Json $plan) -Encoding UTF8
    Say "  plan          $runnable step(s) to run, $($planned.Count) written before any tool ran"

    # A plan with nothing runnable in it is written to disk FIRST and refused second, so
    # the artifact the operator needs to fix the gap survives the refusal. Exit 0 here
    # would read as success having run nothing, which is the answer this file exists to
    # refuse: three question types used to produce exactly it.
    $blocked = Get-RouteRefusal -Route $route -Steps $planned
    if ($blocked) {
        Say ''
        Say "  REFUSED: nothing in the route for $qt is invocable. See $caseDir\plan.json"
        Refuse 2 "nothing in the route for '$qt' is invocable" $blocked
    }

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
    # CALLER-SEEDED FACTS. The loop names exactly one artefact: -Target. Everything else a
    # capability consumes has to arrive from an earlier round, which is why the only chains
    # that run are the ones whose first link reads the target. Measured 2026-10-02: Q5.vuln-shape
    # has no reachable instrument for precisely this reason -- its chain wants a JOSE token, a
    # forensic memory image and a lab target, and none of those is the target.
    #
    # -SeedFact lets the caller supply facts directly, so a mission can begin with artefacts the
    # caller already holds. It is deliberately a PURE ADDITION: with no -SeedFact the dictionary
    # is still empty and every existing code path is untouched, which is the only honest way to
    # add a parameter to a loop whose 51 selftest controls already pass.
    #
    # Seeded facts are recorded in the artifact as caller-supplied, never as measured. A fact
    # that came from the operator is an input to the reasoning, not a result of it.
    $seeded = @{}
    foreach ($s in @($SeedFact)) {
        $k, $v = "$s" -split '=', 2
        if ($k -and $null -ne $v) { $facts[[string]$k] = [string]$v; $seeded[[string]$k] = [string]$v }
    }
    if ($seeded.Count -gt 0) {
        Say "  seeded     $($seeded.Count) caller-supplied fact(s): $(($seeded.Keys | Sort-Object) -join ', ')"
        Say "            an input to the reasoning, not a result of it; marked as such in the artifact"
    }
    $trace = @()
    $round = 0

    $regStale = $false
    foreach ($step in $planned) {
        if ($round -ge $MaxRounds) { break }
        if ($step.state -ne 'planned') { continue }
        $round++

        # REGISTRY RE-CHECK, EVERY ROUND -- and this one REFUSES where the grant check HALTS.
        # The grant can be unaltered while the registry it was computed FROM is edited, and the
        # authorisation decision then rests on a file that no longer exists. Terraform treats a
        # stale plan the same way: the saved artefact is a claim about world state at one instant,
        # and the answer to "the world moved" is to discard and re-plan, never "carry on anyway".
        $nowReg = Get-Sha256Hex (Join-Path $PSScriptRoot '..\manifests\capabilities.json')
        if ($nowReg -ne $regHash) {
            Say "  round $round  REFUSED: manifests/capabilities.json changed mid-mission."
            Say "            planned against $($regHash.Substring(0,16))… and it is now $($nowReg.Substring(0,16))…"
            Say "            every remaining step was routed from the old registry. Re-plan."
            $trace += [ordered]@{ round = $round; capability = $step.id
                event = 'registry_changed_midflight'
                planned_against = $regHash; found = $nowReg; blocks = 'every remaining round' }
            $regStale = $true
            break
        }

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
                        # Skipped when `element_path` is present: that key indexes THEN reads a
                        # property, and letting the plain index run first would consume the
                        # index and leave an object where a property was wanted.
                        # Positional index is skipped whenever by_name is present: a name lookup
                        # is either satisfied or it is not, and falling back to a position after
                        # a failed name lookup is precisely the silent-wrong-answer path.
                        if ($null -ne $val -and $null -ne $idx -and
                            $null -eq $cap.invoke.select.element_path -and
                            $null -eq $cap.invoke.select.by_name) {
                            if (@($val).Count -gt $idx) { $val = @($val)[$idx] } else { $unresolved += ($srcKey + '[' + $idx + ']'); $val = $null }
                        }
                        # `by_name` -- find the element whose `name` property equals a value,
                        # then read `element_path` off it. This exists because POSITIONAL
                        # selection is a silent-wrong-answer machine, and the first `confirmed`
                        # this arsenal produced rested on exactly that: select.index=1 was
                        # verified by hand to be `main` on one binary, but nothing in the chain
                        # checked it. On a binary whose functions enumerate differently the two
                        # instruments would still have agreed -- about the wrong function, at
                        # full confidence, every gate green.
                        #
                        # A name lookup fails LOUDLY: if no element carries that name the round is
                        # skipped and named, rather than falling through to "whatever is at that
                        # position". A gate that picks the wrong thing is worse than one that
                        # refuses.
                        if ($null -ne $val -and $null -ne $cap.invoke.select.by_name) {
                            $want = "$($cap.invoke.select.by_name)"
                            $found = $null
                            foreach ($el in @($val)) {
                                if ($null -ne $el -and $null -ne $el.PSObject.Properties['name'] -and "$($el.name)" -eq $want) { $found = $el; break }
                            }
                            if ($null -eq $found) {
                                $unresolved += ($srcKey + "[name='" + $want + "']")
                                $val = $null
                            } else {
                                $val = if ($cap.invoke.select.element_path) { $found.($cap.invoke.select.element_path) } else { $found }
                            }
                        }
                        # `element_path` -- index into a LIST, then pull one property off the
                        # element. Needed because `select.path` runs BEFORE `select.index`
                        # and a list has no `.addr`, while an index alone yields the whole
                        # object. Measured: native.ida.list_functions fact_maps
                        # native.func.addr to `functions`, which is a list of
                        # {addr, name, size} objects -- neither existing key could reach the
                        # address, so native.disasm.capstone was handed the stringified list
                        # and its round failed while the command itself worked perfectly by
                        # hand. A distinct key rather than a reordering of `path`, because
                        # reordering would change what every existing capability means.
                        # Also skipped when by_name handled it: that key already applied
                        # element_path to the element it found.
                        if ($null -ne $val -and $null -ne $idx -and $null -ne $cap.invoke.select.element_path -and
                            $null -eq $cap.invoke.select.by_name) {
                            $ep = $cap.invoke.select.element_path
                            if (@($val).Count -gt $idx) {
                                $el = @($val)[$idx]
                                if ($null -ne $el -and $null -ne $el.PSObject.Properties[$ep]) { $val = $el.$ep }
                                else { $unresolved += ($srcKey + '[' + $idx + '].' + $ep); $val = $null }
                            } else { $unresolved += ($srcKey + '[' + $idx + ']'); $val = $null }
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

        $errFile = Join-Path $env:TEMP ("mission-stderr-{0}.txt" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
        $sw = [Diagnostics.Stopwatch]::StartNew()
        # STDERR IS CAPTURED SEPARATELY, NOT MERGED. This was `2>&1 | Out-String`, which
        # concatenates both streams into one blob, so any tool that wrote a single warning line
        # produced output ConvertFrom-Json could not parse -- and the round was recorded ok:false
        # while the same command worked perfectly by hand with exit 0. It cost a mission round on
        # native.disasm.capstone and then again on dynamic.win.frida.intercept, and it is a
        # LATENT defect for every capability rather than a quirk of those two: no tool could ever
        # warn, explain or progress-print without breaking the contract that it declares
        # `stdout: json`. Streams stay separate, stderr is recorded on the evidence record where
        # it is readable, and the declared stdout is the only thing parsed.
        $errText = ''
        $raw = & $cap.invoke.runner @argList 2> $errFile | Out-String
        $rc = $LASTEXITCODE
        $sw.Stop()
        if (Test-Path -LiteralPath $errFile) { $errText = (Get-Content -LiteralPath $errFile -Raw) }
        if ($errText) { Say "          stderr: $(($errText -split "`n" | Select-Object -First 2) -join ' | ')" }

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
            # Recorded rather than discarded. A tool that explains itself on stderr is telling
            # the reader something, and throwing it away is how a real warning goes unnoticed.
            stderr = (($errText -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | ')
        }

        # The honest success test is the declared one, not the exit code. This server
        # reports a failed analysis with exit 0 semantics and isError:false; requiring
        # both the process result AND the declared success_when is the fix.
        $parsed = $null
        try { $parsed = $raw | ConvertFrom-Json } catch { $parsed = $null }
        $declaredOk = ($rc -eq 0) -and ($null -ne $parsed)
        if ($cap.invoke.stdout -eq 'json') {
            if ($cap.invoke.fact_map -and $null -ne $parsed) {
                # Each mapped key must be present and non-null. A missing key is a failure,
                # not a smaller answer -- this class of API drops items silently.
                # The null guard is load-bearing, not defensive: :853 sets $parsed = $null
                # whenever the tool's output is not JSON, which it does legitimately --
                # mobile.apk.static's analyze.mjs correctly EXITS 3 on a non-ZIP target --
                # and then :861 dereferenced $parsed.PSObject and threw "Cannot index into
                # a null array", killing the whole mission on round 3 with exit 0 and no
                # verdict. A correct refusal was being swallowed into a successful run.
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

        # PRECONDITION. A capability may declare invoke.gate_role = 'precondition', which means
        # its `ok` is not an evidence result but a GATE on whether downstream work may happen at
        # all. When one fails, every remaining round is skipped and named -- not run and not
        # silently omitted. This is what turns skills/debugger-workstation/references/triage.md's
        # "unpack first; do not decompile the stub" from advice into a rule the loop enforces:
        # native.pe.packer reports ok:false on a packed target and the decompile round never runs.
        #
        # Without this the loop could only express EVIDENCE, so a packed binary would have been
        # decompiled anyway and the only trace would be a note nobody reads.
        if ("$($cap.invoke.gate_role)" -eq 'precondition' -and -not $declaredOk) {
            # NOT MY SUBJECT IS NOT A GATED-SHUT TARGET. A precondition may exit a code the
            # registry lists in invoke.skip_exits, meaning "I am not the right instrument for this
            # file" rather than "I checked and you must not proceed". The two were
            # indistinguishable, and the cost was concrete: native.pe.packer refused an APK with
            # the same exit 2 it uses for a missing diec, the loop read that as the target being
            # gated shut, and every downstream round was skipped -- including mobile.apk.static,
            # which analyses that APK correctly. A gate that blocks on a file it does not
            # understand is not a gate; it is a wall, and it walls off the very capabilities that
            # do understand the file. Nothing about the PACKED case is relaxed: a packed PE exits
            # 0 with ok:false, and that still breaks the loop.
            $skipExits = @($cap.invoke.skip_exits)
            if ($skipExits -and ($skipExits -contains $rc)) {
                Say ''
                Say "  PRECONDITION NOT APPLICABLE: $($step.id) -- this target is not its subject (exit $rc)."
                Say "    Not a refusal of the target, so downstream rounds still run."
                $trace += [ordered]@{ round = $round; capability = $step.id
                                      event = 'precondition_not_applicable'; exit = $rc
                                      blocks = 'nothing' }
                continue
            }
            $preconditionBlock = $step.id
            Say ''
            Say "  PRECONDITION FAILED: $($step.id) -- every remaining round is SKIPPED, not attempted."
            Say "    Analysing the target now would mean analysing whatever the packer left behind."
            $trace += [ordered]@{ round = $round; capability = $step.id
                                  event = 'precondition_failed'; blocks = 'all remaining rounds' }
            break
        }
    }

    # --- termination, COMPUTED over the artifact, never self-reported --------------
    $failedRounds = @($evidence | Where-Object { $_.ok -ne $true }).Count
    $term = Get-Termination -Evidence $evidence -Registry $reg -MaxRounds $MaxRounds -Round $round -FailedRounds $failedRounds -Planned $planned

    # --- the verdict, COMPUTED ---------------------------------------------------
    $verdict = Get-Verdict -Claim $Claim -QuestionType $qt -Evidence $evidence -Registry $reg -DischargedIn $Discharged

    # --- scope guard --------------------------------------------------------------
            # NOT MY SUBJECT IS NOT A GATED-SHUT TARGET. A precondition can now exit a code the
            # registry lists in invoke.skip_exits, meaning "I am not the right instrument for this
            # file" rather than "I checked and you must not proceed". The two used to be
            # indistinguishable and the cost was concrete: native.pe.packer refused an APK with
            # the same exit 2 it uses for a missing diec, the loop read that as the target being
            # gated shut, and every downstream round was skipped -- including
            # mobile.apk.static, which analyses that APK correctly. A gate that blocks on a file
            # it does not understand is not a gate; it is a wall, and it walls off the very
            # capabilities that do understand the file.
            $skipExits = @($cap.invoke.skip_exits)
            if ($skipExits -and ($skipExits -contains $rc)) {
                Say ''
                Say "  PRECONDITION NOT APPLICABLE: $($step.id) -- this target is not its subject (exit $rc)."
                Say "    That is not a refusal of the target, so downstream rounds still run."
                $trace += [ordered]@{ round = $round; capability = $step.id
                                      event = 'precondition_not_applicable'; exit = $rc
                                      blocks = 'nothing' }
                continue
            }
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
        # The plan is bound to the registry it was routed from. If that file changed
        # mid-mission the remaining steps are stale by construction, and the artifact has
        # to say so rather than leave a reader to assume the plan still holds.
        registry_sha256 = $regHash
        registry_stale = $regStale
        rounds     = $round
        chain      = @($trace | Where-Object { $_.capability } | ForEach-Object { [ordered]@{ round = $_.round; capability = $_.capability; ok = $_.ok; facts = ($_.facts | ForEach-Object { $_.key }) } })
        verdict    = $verdict
        termination = $term
        scope_guard = [ordered]@{ baseline = $baseline.Substring(0,16); after = $after.Substring(0,16); intact = $scopeOk }
        # Recorded under its own key and never mixed into the measured chain. An artifact that
        # cannot tell a measured fact from an operator-supplied one is an artifact that will be
        # read as evidence for a claim nobody measured.
        caller_supplied_facts = [ordered]@{
            note = 'Facts the caller passed with -SeedFact. These are INPUTS to this mission, not results. No round produced them and no instrument checked them.'
            keys = @($seeded.Keys | Sort-Object)
        }
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
    # Contiguity, over ALL recorded evidence rather than only the good ones. Measured: this
    # previously tested the GOOD ids and demanded they run e1..eN with no holes, which is wrong
    # -- a round that legitimately FAILS must leave a hole in the good set, because that hole
    # is the record of it. It fired on the first two-family mission: rounds e1, e2, e4 were
    # good, e3 was a round that correctly refused a non-ZIP target, and the gate reported the
    # refusal itself as a fabricated id. A gate that blocks a correct result is as broken as
    # one that waves a wrong one through.
    #
    # The forgery this was written to catch -- a caller writing "e7" onto a two-round mission --
    # is still caught, and caught MORE tightly: the good ids must be a SUBSET of the ids that
    # actually correspond to a recorded round, and no good id may exceed the number of rounds
    # that ran. An id with no recorded round behind it cannot pass.
    $allNums = @($Evidence | ForEach-Object { if ("$($_.id)" -match '^e(\d+)$') { [int]$Matches[1] } } | Sort-Object -Unique)
    $maxRound = if ($allNums.Count) { $allNums[-1] } else { 0 }
    $good = @($Evidence | Where-Object { $_.ok -eq $true })
    $nums = @($good | ForEach-Object { if ("$($_.id)" -match '^e(\d+)$') { [int]$Matches[1] } } | Sort-Object -Unique)
    # The rule, stated so it cannot be satisfied circularly: EVERY id at or below a good one
    # must have a round behind it. My first attempt compared good ids against the set of ALL
    # recorded ids, which is circular -- a forged id is itself an entry in $Evidence, so it
    # always looked present. The estate's own selftest caught it: "a FABRICATED evidence id
    # that resolves to no round fails process alone" came back confirmed. Requiring 1..g to be
    # present catches it, because a forged e7 on a two-round mission has no e3..e6 behind it,
    # while a good e4 on a four-round mission is fine even when e3 legitimately failed.
    foreach ($g in $nums) {
        for ($k = 1; $k -le $g; $k++) {
            if ($allNums -notcontains $k) {
                $problems += ("good evidence id 'e{0}' requires round e{1} to have run, and no " +
                               "such round is recorded: an id that resolves to no round is a fabricated id" -f $g, $k)
                break
            }
        }
        if ($problems.Count) { break }
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

    # ------------------------------------------------------------------------------
    # THE ROUTING CONTROLS.
    #
    # Capability selection used to be a hardcoded seven-entry hashtable in this file
    # (`$QUESTION_TYPES[$qt].needs`), and the registry's `question_types` field was read
    # by exactly one line of code -- a scope filter on evidence already produced, which is
    # a safety check and not a router. Measured on the pre-fix file: Q3.behaviour, Q4.data
    # and Q6.crypto planned ZERO steps and exited 0, and Q5 and Q7 routed capabilities the
    # registry does not assign them. So the controls below do not assert a routing table
    # (this file no longer has one, and a control that pins a table would make the table
    # the thing under test again). They assert the PROPERTIES the derivation has to have,
    # and every one of them is a property of the REGISTRY, not of this file: most of them
    # would survive a legitimate registry edit and would catch a code edit that stops
    # reading the registry.
    #
    # Each of the six mechanisms carries an `# ABLATE-ANCHOR` line in the source, and
    # `-Action Ablate` rewrites each anchor in turn. A control that a rewrite cannot
    # redden is a control that is not measuring the mechanism it names.

    C 'route: every question type the registry declares either routes, or refuses by NAME' {
        # The exit-0-having-run-nothing failure has two shapes: a route that is empty, and a
        # route whose steps cannot run. Neither may be silent, so the assertion is on the
        # NAMES, not on a count: a question type with no route must still say which
        # capability is missing.
        $reg = Get-Registry
        $silent = @()
        foreach ($p in $reg.schema.question_types.PSObject.Properties) {
            $r = Get-Route -Registry $reg -QuestionType $p.Name
            if (@($r.steps).Count -gt 0) { continue }
            $msg = Get-RouteRefusal -Route $r
            if (-not $msg) { $silent += "$($p.Name):no-refusal-at-all"; continue }
            if ($msg -notmatch '([a-z][\w]*\.[\w]+\.[\w]+)') { $silent += "$($p.Name):refusal-names-nothing" }
        }
        "silent=$($silent.Count) $(if ($silent.Count) { $silent -join ',' })"
    } 'silent=0 '

    C 'route: Q6.crypto routes the capability the registry assigns it, by name' {
        $ids = @((Get-Route -Registry (Get-Registry) -QuestionType 'Q6.crypto').steps | ForEach-Object { $_.id })
        if ($ids -contains 'crypto.jose.parse') { 'routed' } else { "NOT ROUTED: $($ids -join ',')" }
    } 'routed'

    # THE registry-driven control. Both halves asserted on purpose: the refusal alone
    # would also be satisfied by a router that refuses everything.

    C 'route: an absent or blocked capability is NEVER routed, on any question type' {
        # The state filter, asserted over the whole registry rather than over one route: a
        # router that honoured `state` for Q3 and ignored it for Q4 would pass a
        # single-route test. This is the defect that put three such capabilities into
        # every grant earlier today, so it is worth a sweep.
        $reg = Get-Registry
        $bad = @()
        foreach ($c in $reg.capabilities) {
            if ("$($c.state)" -eq 'observed') { continue }
            foreach ($q in @($c.question_types)) {
                $ids = @((Get-Route -Registry $reg -QuestionType $q).steps | ForEach-Object { $_.id })
                if ($ids -contains $c.id) { $bad += "$($c.id)@$q" }
            }
        }
        # The count of unavailable capabilities is NOT asserted: the registry is allowed to
        # gain or lose `absent` entries, and a control that breaks when it does is a control
        # that will be "fixed" by weakening it. Only the violations are asserted.
        "routed-while-unavailable=$($bad.Count) $(if ($bad.Count) { $bad -join ',' })"
    } 'routed-while-unavailable=0 '

    C 'route: the question type comes from the registry, and undeclaring one empties its route' {
        # EVERY capability declaring Q6.crypto is undeclared, not just crypto.jose.parse. Same
        # staleness as the case below: the test asserted that Q6 held exactly one instrument,
        # which stopped being true when native.pe.authenticode declared Q6 as well. **A test that
        # pins the SIZE of the registry is a test that will fail every time the arsenal grows**,
        # and it fails for a reason that has nothing to do with the routing it is named for.
        $live = @(Get-Route -Registry (Get-Registry) -QuestionType 'Q6.crypto').steps.Count
        $m = Get-Registry
        $n = 0
        foreach ($c in $m.capabilities) {
            if (@($c.question_types) -contains 'Q6.crypto') { $c.question_types = @('Q4.data'); $n++ }
        }
        $mut = @(Get-Route -Registry $m -QuestionType 'Q6.crypto').steps.Count
        # NO (n=$n) IN THE EXPECTATION, AND THAT IS THE SECOND TIME. The comment above already
        # records this failure: a previous fix updated n=1 to n=2 when native.pe.authenticode
        # declared Q6, which fixed the symptom and left the cause. Adding
        # native.signature.certverify broke it again. The count is incidental to the behaviour
        # under test -- the routing either empties when a question type is undeclared or it does
        # not -- and pinning it means this test fails every single time the arsenal grows, for a
        # reason that has nothing to do with routing.
        "live=$(if ($live) { 'routed' } else { 'empty' }) undeclared=$(if ($mut) { 'routed' } else { 'empty' })"
    } 'live=routed undeclared=empty'

    C 'route: a question type whose only capability is absent refuses and names it' {
        # EVERY capability declaring Q6.crypto is made absent, not just crypto.jose.parse.
        # The first version named one, which was correct while Q6 had exactly one instrument and
        # went stale the moment native.pe.authenticode declared Q6 too -- it then found one
        # routable step and failed. **The test asserted an accident of the registry's size, not
        # the behaviour it is named for.** The behaviour under test is "a question type with no
        # available capability refuses and names what it wanted", which is about the ROUTE and
        # holds for any question type.
        $m = Get-Registry
        $n = 0
        foreach ($c in $m.capabilities) {
            if (@($c.question_types) -contains 'Q6.crypto') { $c.state = 'absent'; $n++ }
        }
        $r = Get-Route -Registry $m -QuestionType 'Q6.crypto'
        $msg = Get-RouteRefusal -Route $r
        # Same registry-size pin removed here for the same reason: steps=0 and names=True are the
        # behaviour, and the count of candidates is not. See the note above.
        "steps=$(@($r.steps).Count) names=$($msg -match 'jose\.parse') exit-would-be=2"
    } 'steps=0 names=True exit-would-be=2'

    C 'route: a hard edge puts its producer ahead of the consumer, and says which fact' {
        # Q3.behaviour names `native.ida.decompile`; that capability's runner binds
        # `native.func.named`, which ONLY `native.ida.list_functions` publishes -- and
        # list_functions does NOT declare Q3 for itself, so it can only be in this mission
        # because an edge pulled it in. The hardcoded table could not do this: it had
        # `needs = @()` for Q3.behaviour, and typed `list_functions, decompile` by hand for
        # the two question types that happened to have entries. Both halves are asserted:
        # the order, and the fact that the producer was not there by declaration.
        $reg = Get-Registry
        $lfDecl = @($reg.capabilities | Where-Object { $_.id -eq 'native.ida.list_functions' })[0].question_types
        $r = Get-Route -Registry $reg -QuestionType 'Q3.behaviour'
        $ids = @($r.steps | ForEach-Object { $_.id })
        $lf = [array]::IndexOf($ids, 'native.ida.list_functions')
        $dc = [array]::IndexOf($ids, 'native.ida.decompile')
        $sel = @($r.steps | Where-Object { $_.id -eq 'native.ida.list_functions' })[0].selected_by
        "producer-first=$(($lf -ge 0) -and ($dc -gt $lf)) via-edge=$(("$sel" -like 'producer:*') -and (@($lfDecl) -notcontains 'Q3.behaviour'))"
    } 'producer-first=True via-edge=True'

    C 'route: a capability whose runner binds a fact nothing produces is DROPPED, not planned' {
        # Force the producer out of the host. The consumer then has a hard edge with no
        # possible producer, and planning it anyway is the silent failure rule 5 exists to
        # prevent: the round would discover it at run time and record skipped_no_consumer,
        # which looks safe and is not.
        $m = Get-Registry
        foreach ($c in $m.capabilities) { if ($c.id -eq 'native.ida.list_functions') { $c.state = 'absent' } }
        $r = Get-Route -Registry $m -QuestionType 'Q2.locate'
        $ids = @($r.steps | ForEach-Object { $_.id })
        "routed=$($ids -contains 'native.ida.decompile') reason=$(@($r.dropped | Where-Object { $_.id -eq 'native.ida.decompile' })[0].reason)"
    } 'routed=False reason=unmet_hard_edge'

    C 'route: an input the registry marks unproduced blocks the capability that needs it' {
        $m = Get-Registry
        foreach ($c in $m.capabilities) {
            if ($c.id -eq 'net.pcap.analyse') {
                $marker = [pscustomobject]@{ status = 'blocked'; reason = 'a control put it here' }
                $c.consumes.inputs[0] | Add-Member -NotePropertyName unproduced -NotePropertyValue $marker -Force
            }
        }
        $r = Get-Route -Registry $m -QuestionType 'Q4.data'
        $ids = @($r.steps | ForEach-Object { $_.id })
        $why = @(@($r.unavailable) + @($r.dropped) | Where-Object { $_.id -eq 'net.pcap.analyse' })[0].reason
        "routed=$($ids -contains 'net.pcap.analyse') reason=$why"
    } 'routed=False reason=unproduced_required_input'

    C 'route: an argv slot nothing produces is VISIBLE in the plan, not run and not hidden' {
        # The prediction is the loop's own: `Get-ArgvSlots` resolves `{input.x}` exactly the
        # way the substitution loop does, so a capability whose runner binds a fact no
        # earlier step publishes is skipped in the PLAN rather than discovered mid-run.
        # `native.ghidra.decompile` binds `{input.outdir}` and no capability publishes a
        # fact called `outdir`, so it cannot run -- and that is stated, not absorbed.
        $reg = Get-Registry
        $r = Get-Route -Registry $reg -QuestionType 'Q2.locate'
        $allowAll = @($reg.capabilities | ForEach-Object { $_.id })   # grant must not be the reason
        $steps = @(Resolve-PlanSteps -Route $r -Allowed $allowAll -Registry $reg)
        $gh = @($steps | Where-Object { $_.id -eq 'native.ghidra.decompile' })[0]
        "state=$($gh.state) reason-stated=$("$($gh.why)" -match 'outdir')"
    } 'state=skipped_unmet_input reason-stated=True'

    C 'route: a capability is in the mission for a STATED reason, and the order is stable' {
        $reg = Get-Registry
        $bad = @()
        foreach ($p in $reg.schema.question_types.PSObject.Properties) {
            $r = Get-Route -Registry $reg -QuestionType $p.Name
            foreach ($s in $r.steps) {
                $c = $reg.capabilities | Where-Object { $_.id -eq $s.id } | Select-Object -First 1
                if (-not $c) { $bad += "$($s.id):not-in-registry"; continue }
                if ("$($c.state)" -ne 'observed') { $bad += "$($s.id):$($c.state)"; continue }
                if (-not "$($s.why)") { $bad += "$($s.id):no-reason"; continue }
                if (("$($s.selected_by)" -eq 'declared') -and (@($c.question_types) -notcontains $p.Name)) {
                    $bad += "$($s.id):undeclared-but-placed-as-declared"
                }
                if ($null -eq $s.registry_index) { $bad += "$($s.id):no-tiebreak-index" }
            }
        }
        # Determinism: the same registry, routed twice, must give the same order twice.
        $a = @((Get-Route -Registry $reg -QuestionType 'Q4.data').steps | ForEach-Object { $_.id }) -join ','
        $b = @((Get-Route -Registry (Get-Registry) -QuestionType 'Q4.data').steps | ForEach-Object { $_.id }) -join ','
        if ($a -ne $b) { $bad += 'order-not-stable' }
        "unsound=$($bad.Count) $(if ($bad.Count) { $bad -join ',' })"
    } 'unsound=0 '


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
      Two passes, because this file now has two kinds of removable decision, and both were
      found by this instrument:

      PASS 1 -- the seven verdict gates. Measured 2026-10-02, on the version that had 15
      controls: rewriting any six of the seven `G '<name>' <expr>` expressions to `$true`
      left the whole suite green. Six of seven gates were a sentence in a comment. This
      function is what found it and is kept so it cannot be undone quietly.

      PASS 2 -- the six routing rules. Capability selection used to be a hardcoded
      seven-entry hashtable, which ablation could not touch at all: there was no mechanism
      to remove, only a table to read, and a table is not a mechanism. The route is six
      decisions, each with exactly one assignment line, so each can be neutralised and the
      suite asked whether it noticed. A routing rule that can be deleted without turning
      the suite red is a sentence in a comment, exactly as a gate is -- and the whole point
      of this change is that the route is derived rather than typed, so "derived" has to
      be measured rather than asserted in a comment.

      Three things keep this from being a check that always passes:
        1. A PRISTINE copy is run first. If the suite is already red, "load-bearing" means
           nothing, so this refuses rather than reporting meaningless verdicts.
        2. Every rewrite is matched on the mechanism's OWN ASSIGNMENT, not a line number,
           and a rewrite that matches nothing -- or matches twice -- is an ERROR, not a
           pass. A silently-unapplied rewrite would report a rule as untested for the
           wrong reason, which is the failure mode this instrument exists to prevent.
        3. The copy is deleted in a `finally`, so an exception cannot leave one behind.

      The copy lives BESIDE the script, not in %TEMP%: `$RepoRoot` is derived from
      `$PSScriptRoot`, so a copy anywhere else cannot find manifests\capabilities.json and
      every control would fail for an environmental reason instead of the rule's.
    #>

    # Each entry neutralises ONE mechanism, in the way that removes the decision without
    # removing the code around it: a read becomes `always true`, a check becomes `no
    # findings`. The replacement strings are single-quoted so `$1` stays a regex
    # back-reference -- in a double-quoted string PowerShell would eat it as a variable.
    $routing = @(
        @{ name = 'qtype-read';   rx = '(?m)^(\s*)\$declares\s*=.*$';        to = '$1$declares = $true'
           what = 'the question_types membership read: every capability would declare every question type' },
        @{ name = 'state-read';   rx = '(?m)^(\s*)\$stateOk\s*=.*$';          to = '$1$stateOk = $true'
          what = 'the state filter: absent and blocked would become routable' },
        @{ name = 'unproduced';   rx = '(?m)^(\s*)\$unproduced\s*=.*$';      to = '$1$unproduced = @()'
          what = 'the unproduced-required-input check' },
        @{ name = 'edge-closure'; rx = '(?m)^(\s*)\$pull\s*=.*$';            to = '$1$pull = @()'
          what = 'hard-edge closure: no producer would ever be pulled into a mission' },
        @{ name = 'unmet-edge';   rx = '(?m)^(\s*)\$unmetHard\s*=.*$';       to = '$1$unmetHard = @()'
          what = 'the unmet-hard-edge drop' },
        @{ name = 'argv-slot';    rx = '(?m)^(\s*)\$unresolvedSlots\s*=.*$'; to = '$1$unresolvedSlots = @()'
          what = 'the argv-slot check: a capability with an unfillable placeholder would be planned' }
    )
    $names = @('process', 'reachability', 'observation', 'independence', 'bounded_claim', 'uncertainty', 'discharged')
    $src = Get-Content -LiteralPath $PSCommandPath -Raw
    $copy = Join-Path $PSScriptRoot ('mission-ablate-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $loadBearing = 0; $unproved = 0; $errs = 0
    $rLoad = 0; $rUnproved = 0; $rErrs = 0

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

        # --- pass 2: the routing rules -------------------------------------------
        Write-Host ''
        Write-Host '  routing rules -- each rule neutralised in turn, and the controls it reddened named:'
        foreach ($m in $routing) {
            $hits = [regex]::Matches($src, $m.rx)
            if ($hits.Count -ne 1) {
                Write-Host ("  {0,-14} ERROR: matched {1} assignment(s) of that variable; expected exactly 1" -f $m.name, $hits.Count)
                $rErrs++
                continue
            }
            $patched = [regex]::Replace($src, $m.rx, $m.to)
            Set-Content -LiteralPath $copy -Value $patched -NoNewline -Encoding UTF8
            $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $copy -Action Selftest 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                # The red controls are the evidence, so they are printed: a row that says
                # only "load-bearing" cannot be told apart from a row that reddened for an
                # unrelated reason, which is the same weakness this instrument was built
                # to eliminate in the gate pass.
                $red = @($out -split "`r?`n" | Where-Object { $_ -match '^\s*FAIL\s' } |
                         ForEach-Object { ((($_ -replace '^\s*FAIL\s+', '') -split '\s{2,}')[0]) })
                Write-Host ("  {0,-14} load-bearing  {1} control(s) reddened: {2}" -f $m.name, $red.Count, ($red -join ' | '))
                $rLoad++
            } else {
                Write-Host ("  {0,-14} NOT TESTED (suite stayed green)  -- {1}" -f $m.name, $m.what)
                $rUnproved++
            }
        }
    } finally {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host ("ABLATE: {0} load-bearing, {1} unproved, {2} rewrite error(s)." -f $loadBearing, $unproved, $errs)
    Write-Host ("ROUTING ABLATE: {0} load-bearing, {1} unproved, {2} rewrite error(s)." -f $rLoad, $rUnproved, $rErrs)
    if ($loadBearing -eq $names.Count -and $errs -eq 0 -and $rLoad -eq $routing.Count -and $rErrs -eq 0) { return 0 }
    return 3
}

switch ($Action) {
    'Plan'  { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Run'   { try { Invoke-Mission } catch [MissionRefusal] { Out-Json @{ ok = $false; exit = $_.Exception.Code; error = $_.Exception.Message; detail = $_.Exception.Detail }; exit $_.Exception.Code } }
    'Selftest' { exit (Invoke-Selftest) }
    'Ablate' { exit (Invoke-Ablate) }
}
