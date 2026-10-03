#Requires -Version 5.1
<#
.SYNOPSIS
  The arsenal gate, as a program. The only thing on this station that may grant authority.

.DESCRIPTION
  A gate written in prose is advice. This one is a program, so "the gate said no" is an
  exit code and a hash rather than a sentence somebody remembered.

  The core invariant, and everything else follows from it:

      A MISSION CAN ONLY NARROW ITS AUTHORITY.

  The invocable set is a monotonic subset of the grant. Only this script produces a
  grant, and only an explicit Owner word produces a grant. No caller — not the mission
  loop, not an agent, not a model — has any interface that adds to it. A loop that can
  choose its own capabilities is one conversation away from choosing a broader one.

  Three escalation classes, and the middle one is the only one that can be granted at
  runtime:

      none         inside the grant; the loop proceeds
      owner_word   a new capability, same lane, same containment, no wider reach --
                   requires a verbatim Owner sentence recorded in the grant PLUS a fresh
                   run of `gate.ps1 escalate`
      impossible   anything that changes lane or reach. NOT a runtime decision. It needs
                   an Owner edit to AGENTS.md / CHARTER-ARSENAL.md in git. This script
                   refuses it by design; there is no flag that turns that refusal off.

.PARAMETER Action
  New      mint a grant from a verdict plus an Owner word
  Check    recompute a grant's hash and answer whether a capability is inside it
  Escalate widen an existing grant, only with a fresh Owner word, only within the class
  Selftest prove this script's own refusals fire

.EXAMPLE
  powershell -File scripts\gate.ps1 -Action New -Target C:\...\c01-stringobf.exe `
      -Provenance 'Owner named this exe in conversation 2026-09-30' -OwnerWord 'analyze this exe' -CaseDir E:\missions\c01
  powershell -File scripts\gate.ps1 -Action Check -CaseDir E:\missions\c01 -Capability native.ida.decompile
  powershell -File scripts\gate.ps1 -Action Selftest

.NOTES
  Exit codes: 0 = granted · 3 = refused · 4 = self-asserted provenance · 5 = grant tampered
  · 6 = the grant's claims could not be independently re-established
  · 7 = the `-Target` named is NOT the target the grant covers, or the target's bytes
  no longer hash to what the grant sealed.

  WHY exit 7 IS ITS OWN CODE AND NOT 3. A general refusal tells a caller "no". This one
  tells a caller something actionable: the capability IS granted and the case IS inside
  the containment, but the file you named is not the file the authority was minted over.
  A grant for `c01-stringobf.exe` used to make any file in the same directory legible,
  which is the hole `-RequestedTarget` was added to close (measured: naming
  `manifests/capabilities.json` gave exit 7 with both `requested_target` and
  `granted_target` printed, where before it was exit 0). Collapsing it into 3 would
  have hidden the distinction the code was written to make.

  Exit 7 was absent from this table for a full day after it was added — measured by a
  verifier reading the refusal codes off a live run. A refusal code nobody documented is
  one a caller cannot handle.

  THE ONE THAT MATTERS: `New` refuses when the provenance is self-asserted. "I found it
  on my disk" is not ownership. If no subprocess is spawned before that refusal, the
  control held; a subprocess appearing first means the control FAILED and that is the
  test.

  WHY exit 6 EXISTS. `grant_sha256` is an UNKEYED SHA-256 and the algorithm is in this
  file, so anybody can recompute it: a hash over a file the attacker rewrote proves only
  that the attacker can compute SHA-256. It is not a signature. So `Check` does not trust
  the file it is checking. Every property it reports is re-derived from an authority the
  grant file cannot forge:

      grant.identity   the identity projection (owner word, provenance, target, target
                       digest, containment, escalation, registry digest) sealed with DPAPI
                       at CurrentUser scope. Its plaintext exists only under the
                       interactive Windows account that minted it, so editing grant.json
                       to say something else no longer produces a matching seal.
      capabilities.json  the registry, for `allowed` and for each capability's `state`.
      the target's bytes  re-hashed on every Check, and a target that is not on disk is
                       refused rather than reported verified.

  WHAT THIS BREAKS, DELIBERATELY. (1) schema is now `gate/grant@2`. A `gate/grant@1`
  grant on disk has no `containment`, no `registry_sha256` and no `grant.identity`, so
  `Check` refuses it with exit 5 and says "re-mint". There is no silent default and no
  back-compat path, because a grant this gate cannot re-establish is exactly the grant
  the exit-6 path exists to refuse. (2) `New` now REQUIRES `-Containment`; guessing a
  containment class is what mission.ps1's intake refuses to do, so the gate refuses it
  too. As of this revision `mission.ps1` does not pass `-Containment`, so
  `mission.ps1 -Action Run` is refused at the mint until that call site is updated.
  (3) Editing `manifests\capabilities.json` changes its digest, which every grant records,
  so a registry edit invalidates existing grants and they must be re-minted. That is the
  point: a registry edit is a committed diff the Owner can see.

  (4) NEW, and the reason this file now knows what a caller is about to run. Ten registry
  entries carry `gate_must_not_delegate`: authority boundaries written as English sentences
  -- "never pass --unsafe", "never parse an APK as PE", "Interceptor.replace /
  Memory.patchCode". MEASURED 2026-10-03, and that is why this paragraph exists: deleting the
  whole key from all ten entries and re-running `registry-verify.py` still exits 0 with
  REGISTRY CLEAN. Nothing read them. A boundary that no program opens is a comment.

  So the boundary is now expressed twice, and neither half is allowed to drift:
      gate_must_not_delegate   the prose. What the Owner reads.
      gate_prohibitions        codes + structured operands. What this script can refuse.
  Every prohibition carries `covers`: the EXACT prose string it mechanises. Invoke-ProhibitionGate
  requires the union of `covers` to equal `gate_must_not_delegate` as a set -- a prose string no
  prohibition claims is a refusal, and a claim naming a string the entry no longer states is a
  refusal. That is the whole anti-drift mechanism, and it is why deleting the prose key is now
  visible to a program while deleting the structured key is equally visible.

  THE VOCABULARY IS CLOSED ($ProhibitionCodes). An unknown code, a missing operand, a bad
  `require` value or a malformed operand is exit 6, not a shrug. A prohibition this script
  cannot evaluate is worse than prose, because prose at least looks like a claim.

  THE CODES, AND WHAT EACH ONE CANNOT CATCH. Stated here because a gate that overstates is
  the failure this project exists to reject:
    target_must_be_self_authored   refuses a granted target that is neither under the repo root
                                   nor under %TEMP%. It is a PATH claim. It cannot tell a file
                                   that was built here from one copied in from elsewhere.
    target_must_be_temp_copy       the same check, stricter: under %TEMP% only. It cannot tell a
                                   copy of a self-authored challenge from an arbitrary file
                                   that happens to live in %TEMP%.
    container_must_be_pe           refuses a target whose first bytes are not `MZ`, so an APK, DEX,
                                   JAR, ELF or Mach-O cannot be handed to a PE parser and
                                   reported as PE structure. It reads two bytes; it does not
                                   validate that a file claiming MZ is a usable PE.
    no_forbidden_argv_token        whole-token match against the DECLARED invocation AND against
                                   the capability's own recorded `probe.command`, so the
                                   prohibition cannot be evaded by editing the registry's probe.
                                   Requires -Invocation, because a vocabulary nobody states
                                   cannot be checked -- omission is a refusal.
    unenforceable_prose            RECORDED, NEVER CHECKED. Thirteen of the thirty-eight prose
                                   prohibitions are claims about INTERPRETATION ("reading a match
                                   miss as evidence that code CHANGED", "reporting rules_matched
                                   as a risk score"). This gate authorises a capability; it does
                                   not read results. Declaring one unenforceable is the honest
                                   move, and the gate REPORTS the count rather than letting an
                                   unenforceable claim look enforced.

  WHAT IT STILL CANNOT CATCH: a caller that omits -Capability gets the grant's validity and no
  prohibition evaluation, because a prohibition is a property of a capability and a bare
  `Check` names none; and a prohibition whose tool argument is a different object from the
  granted target -- ops.skill.security forbids scanning outside this repository, and the scan
  root is not the granted binary -- is unenforceable here by construction, so it is declared
  unenforceable rather than approximated.

  THE CALL SITES THAT MUST NOW PASS -Invocation, and are not mine to change. Measured 2026-10-03:
  `scripts/arsenal_mcp_server.py` runs `gate.ps1 -Action Check` from `gate_check()` at
  arsenal_mcp_server.py:413, which is BEFORE the argv is assembled at :420 -- so it has nothing
  to pass yet. That is the right place for it to change: the check must move to after the argv is
  resolved from `invoke.argv` and placeholders, and then pass the joined argv. Until it does,
  every one of the sixteen invocable capabilities that carries a vocabulary prohibition is
  refused with `no_forbidden_argv_token(invocation-absent)`, which is a refusal, not a skip.
  `scripts/mission.ps1` already cannot reach the mint (this file's item (2)), so it needs the same
  change when that is fixed. Nothing else in the repository calls `-Action Check`.
#>
[CmdletBinding()]
param(
    [Parameter()][ValidateSet('New', 'Check', 'Escalate', 'Selftest')][string]$Action = 'Selftest',
    [string]$Target = '',
    [string]$Provenance = '',
    [string]$OwnerWord = '',
    [string]$CaseDir = '',
    [string]$Capability = '',
    [string]$EscalationClass = '',
    [string]$Lane = 'debug',
    [string]$Containment = '',
    [string]$Registry = '',
    # The command line the caller is about to execute, for -Action Check. A capability whose
    # registry entry declares an argv-vocabulary prohibition (`no_forbidden_argv_token`) makes
    # this REQUIRED, and omitting it is a refusal rather than a shrug -- see Invoke-ProhibitionGate
    # and the .NOTES entry "WHAT THIS BREAKS, (4)".
    [string]$Invocation = ''
)

$ErrorActionPreference = 'Stop'

function Out-Json($o) { $o | ConvertTo-Json -Compress -Depth 8 }

function Get-RegistryPath {
    # G10. The registry this gate reads is its OWN calibration, not a parameter. `-Registry`
    # is refused at every entry point (see Test-RegistrySubstitution below), so the only thing
    # that can still redirect the gate is this script-scoped override, which Invoke-Selftest
    # sets and no other script in this repo sets.
    #
    # THE LIMIT, stated because an earlier version of this comment claimed "nothing outside this
    # file can reach" and that was FALSE. Independent verification on 2026-10-03 measured it:
    # PowerShell dot-sourcing runs the callee in the CALLER's scope, so `$script:RegistryOverride`
    # here is the caller's own variable. Measured: `powershell -Command '$script:RegistryOverride=
    # <evil>; . scripts\gate.ps1 -Action New ...'` minted a fully attested grant whose allowed set
    # contained the forged capability and whose registry digest was the evil file's. That is a
    # property of PowerShell's scoping, not of this variable -- no `script:`-scoped name is safe
    # against a caller who dot-sources -- so the honest claim is the narrow one.
    #
    # What actually holds, and is pinned by the G10 control "a grant minted under the override
    # does not survive a plain -File Check": every in-repo caller invokes gate.ps1 with `-File`,
    # which runs it in its own scope, and a grant minted with the override records the OVERRIDE's
    # digest, so a subsequent Check over `-File` re-derives the real registry's digest, finds a
    # mismatch, and refuses with exit 6. The forgery is self-consistent only for a caller that
    # dot-sources on both sides, and nothing in this repo does that.
    #
    # MEASURED 2026-10-03, red-team finding, and the reason this is not a style change: with
    # `-Registry` honoured at the MINT, a hand-written capabilities.json containing one extra
    # capability minted a fully green grant -- allowed set, DPAPI seal, digest -- and a Check
    # with the same override answered ok:true. The authority of that grant was a file outside
    # git. The digest binding that G7 tests was real and did not help: a substituted mint
    # seals the substituted registry's own digest, so it matches itself perfectly.
    # mission.ps1 already refuses a caller-supplied registry at intake (Refuse 6). The gate is
    # the component that was left able to honour one.
    if ($script:RegistryOverride) { return $script:RegistryOverride }
    return (Join-Path (Split-Path -Parent $PSScriptRoot) 'manifests\capabilities.json')
}

function Test-RegistrySubstitution {
    # One refusal, three entry points. Returns $null when no substitution was attempted, so a
    # caller of this function can write `if ($r = Test-RegistrySubstitution) { return $r }`.
    if (-not $Registry) { return $null }
    return @{ ok = $false; exit = 6
             error = 'a caller-supplied -Registry is refused: the capability registry is this script''s own calibration, not a parameter'
             detail = "registry=$Registry"
             why = 'a gate that reads whichever registry the caller names cannot tell you which capabilities are real. The registry in git is the authority, and editing it is a committed diff the Owner can see.' }
}

function Get-CanonicalJson {
    <#
      Stable serialisation, because the grant hash must be reproducible by anyone.
      PowerShell's ConvertTo-Json orders nothing, so build the string explicitly with
      sorted keys and no whitespace drift between runs or hosts.

      PSCustomObject must be walked exactly like a dictionary. PowerShell round-trips an
      ordered dictionary through JSON into a PSCustomObject, so a grant written by New
      and read back by Check arrived here as an object rather than a dictionary, fell
      through to ConvertTo-Json, and hashed differently from the canonical form -- every
      fresh grant failed its own check with "the grant was altered after it was minted".
      The hash was right and the serialiser was wrong.
    #>
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $parts = @()
        foreach ($p in ($Value.PSObject.Properties | Sort-Object Name)) {
            $parts += ('{0}:{1}' -f (ConvertTo-Json -Compress $p.Name), (Get-CanonicalJson $p.Value))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($k in ($Value.Keys | Sort-Object)) { $parts += ('{0}:{1}' -f (ConvertTo-Json -Compress $k), (Get-CanonicalJson $Value[$k])) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $parts = @()
        foreach ($v in $Value) { $parts += (Get-CanonicalJson $v) }
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    return (ConvertTo-Json -Compress $Value)
}

function Get-GrantHash {
    # Enumerate the shape-agnostically. This was the second half of one bug: the
    # canonical serialiser had been taught PSCustomObject, but the hash still walked
    # `.Keys`, which exists on an ordered dictionary and is null on a PSCustomObject.
    # So New hashed the whole grant and Check hashed `{}` -- every freshly minted grant
    # reported "the grant was altered after it was minted". Two shapes, one function,
    # so the walk lives in one place and both call it.
    param($Grant)
    $clone = [ordered]@{}
    foreach ($entry in (Get-Entries $Grant)) {
        if ($entry.Key -eq 'grant_sha256') { continue }
        $clone[$entry.Key] = $entry.Value
    }
    $json = Get-CanonicalJson $clone
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
}

function Get-Entries {
    # Yields key/value pairs from either shape, in sorted key order.
    param($Value)
    $out = @()
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in $Value.Keys) { $out += [pscustomobject]@{ Key = [string]$k; Value = $Value[$k] } }
    } elseif ($null -ne $Value -and $null -ne $Value.PSObject -and $null -ne $Value.PSObject.Properties) {
        foreach ($p in $Value.PSObject.Properties) { $out += [pscustomobject]@{ Key = [string]$p.Name; Value = $p.Value } }
    }
    # Objects rather than pairs of arrays: PowerShell flattens a nested array on
    # return, so a list of @('a',1), @('b',2) arrives as four scalars and the caller
    # indexes null. Objects do not flatten.
    return @($out | Sort-Object -Property Key)
}

function Get-Sha256File {
    # Computed with .NET rather than Get-FileHash: that cmdlet lives in a module which
    # is not guaranteed to auto-load here, and a gate that cannot run because a helper
    # is missing is a gate that gets bypassed.
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLowerInvariant() }
    finally { $fs.Dispose(); $sha.Dispose() }
}

# Words that signal the caller is describing its own find rather than the Owner's word.
# This list is a heuristic, not a proof -- which is why an unverifiable provenance is
# refused outright rather than pattern-matched into acceptance.
$SelfAssertedPatterns = @(
    'i found', 'on my (disk|machine|pc|computer)', 'it was (already )?there',
    'locally', 'someone else', 'downloaded', 'from the internet', 'random'
)

function Test-SelfAsserted {
    param([string]$Text)
    $t = "$Text".ToLowerInvariant()
    foreach ($p in $SelfAssertedPatterns) { if ($t -match $p) { return $true } }
    return $false
}

# --------------------------------------------------------------------------------
# The grant schema, as a CLOSED set of fields.
#
# `gate/grant@1` had no allow-list, so `Test-Grant` hashed whatever it found and
# reported ok:true. Adding `attach_pid` to a grant and recomputing the unkeyed hash was
# accepted: "this grant names a process" was not even expressible as a refusal, let alone
# constrained to an Owner-named one. A field the gate does not define is a field the gate
# is silently ignoring, and a silently ignored field is an attack surface. So: unknown
# field, refused.
$GrantSchemaVersion = 'gate/grant@2'
$GrantRequiredFields = @(
    'schema', 'case_id', 'lane', 'target', 'target_sha256', 'provenance', 'owner_word',
    'granted_at', 'containment', 'allowed', 'escalation', 'registry_sha256', 'grant_sha256')
$GrantKnownFields = @($GrantRequiredFields + @('note', 'escalation_word', 'escalated_at', 'prior_grant_sha256'))
$GrantSealFile = 'grant.identity'

# `containment` is a mission.ps1 intake parameter validated against these three literals
# at mission.ps1:186 and never passed through to this script, so a grant minted under
# `station_under_named_process_rule` was byte-identical to one minted under `isolated_vm`.
# The declaration that exists to keep an untrusted sample off the host was the one thing
# the grant did not record. The gate now records it and refuses a grant without it.
$KnownContainments = @('station_under_named_process_rule', 'loopback_capture', 'isolated_vm')

# `escalation` is the OTHER authority field on a grant, and until 2026-10-03 it was the
# only one with no vocabulary anywhere in this file. Measured that day: `-Action Escalate
# -EscalationClass 'TOTALLY_MADE_UP_CLASS'` returned exit 0, wrote the caller's string into
# grant.escalation, re-sealed it with DPAPI, and the following Check answered ok:true with
# identity_reestablished=true. A freshly minted grant was fine; a grant that had been
# widened recorded a class this script cannot interpret, and every later read believed the
# record. registry-verify.py was already disciplined here -- R6 checks gate.escalation_class
# against VALID_ESCALATION -- so the gap was the gate, not the schema.
#
# Two lists, deliberately, because they answer different questions:
#   $KnownEscalations    what a grant may RECORD. `none` and `owner_word`.
#   $GrantableEscalation what an ESCALATION may LAND ON. `owner_word` only -- escalating
#                        while recording `none` would widen `allowed` and then state that
#                        nothing was widened.
$KnownEscalations = @('none', 'owner_word')
$GrantableEscalation = @('owner_word')

# --------------------------------------------------------------------------------
# THE PROHIBITION VOCABULARY. A CLOSED set, because the defect being closed here is
# exactly "a field the gate does not define is a field the gate is silently ignoring"
# (see the grant schema block above -- same argument, different field).
#
# `unenforceable_prose` is IN this list on purpose and is the one code this script never
# enforces. It exists so a prohibition nobody can express has a name in a checked
# vocabulary instead of silently vanishing: 13 of the 38 prose prohibitions are claims
# about how a RESULT may be read, and this gate authorises a capability, it does not read
# results. A boundary that is recorded as unchecked is honest; one that is quietly absent
# is not. Invoke-ProhibitionGate returns the enforced/unenforceable counts on every Check
# so a reader can see which is which without reading the registry.
$ProhibitionCodes = @(
    'target_must_be_self_authored',
    'target_must_be_temp_copy',
    'container_must_be_pe',
    'no_forbidden_argv_token',
    'unenforceable_prose'
)

# The `require` operand each target/container code accepts. Closed for the same reason.
$ProhibitionOrigins = @('repo_or_temp', 'temp')

# Characters that DELIMIT a token. A forbidden token only matches when it stands alone:
# `--unsafe` matches in `--unsafe`, `--unsafe=1` and `"--unsafe"`, and does NOT match in
# `--unsafely`. That last one is deliberate and it is the near-miss the selftest pins --
# a gate that refuses every string containing a flag is a gate that has no vocabulary.
$TokenCharClass = 'A-Za-z0-9_\-./\\:'

function Test-TokenPresent {
    param([string]$Haystack, [string]$Token)
    if ([string]::IsNullOrEmpty($Haystack) -or [string]::IsNullOrEmpty($Token)) { return $false }
    $esc = [regex]::Escape($Token)
    $rx = '(?<![' + $TokenCharClass + '])' + $esc + '(?![' + $TokenCharClass + '])'
    return [regex]::IsMatch($Haystack, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-RepoRoot {
    # Derived from where THIS FILE lives, not from a parameter and not from the registry.
    # A caller-supplied root would make `target_must_be_self_authored` satisfiable by typing.
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-TargetOrigin {
    # The three-valued answer the target-origin codes compare against. `foreign` is the only
    # one that refuses anything, and it is computed by RESOLVING the path, not by reading a
    # field anybody wrote.
    param([string]$Target)
    $root = [IO.Path]::GetFullPath((Get-RepoRoot)).TrimEnd('\','/')
    $temp = if ($env:TEMP) { [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\','/') } else { '' }
    $full = [IO.Path]::GetFullPath($Target)
    $underRepo = $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
                 $full.Equals($root, [StringComparison]::OrdinalIgnoreCase)
    $underTemp = $temp -and (
                 $full.StartsWith($temp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
                 $full.Equals($temp, [StringComparison]::OrdinalIgnoreCase))
    if ($underRepo) { return 'repo' }
    if ($underTemp) { return 'temp' }
    return 'foreign'
}

function Get-ContainerKind {
    # Two bytes, read from the file itself. `pe` is MZ. Everything else is named so the
    # refusal can say WHAT it refused rather than "not MZ".
    param([string]$Target)
    try {
        $fs = [System.IO.File]::OpenRead($Target)
        try { $b = New-Object byte[] 4; [void]$fs.Read($b, 0, 4) } finally { $fs.Dispose() }
    } catch { return 'unreadable' }
    if ($b.Length -ge 2 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A) { return 'pe' }
    if ($b.Length -ge 4 -and $b[0] -eq 0x50 -and $b[1] -eq 0x4B -and $b[2] -eq 0x03) { return 'zip' }
    if ($b.Length -ge 4 -and $b[0] -eq 0x64 -and $b[1] -eq 0x65 -and $b[2] -eq 0x78) { return 'dex' }
    if ($b.Length -ge 4 -and $b[0] -eq 0x7F -and $b[1] -eq 0x45 -and $b[2] -eq 0x4C) { return 'elf' }
    if ($b.Length -ge 4 -and $b[0] -eq 0xFE -and $b[1] -eq 0xED) { return 'mach-o' }
    return 'other'
}

function Get-ProhibitionRefusal {
    # `error` carries the operand as well as the code, and that is deliberate twice over. A
    # refusal that names only a code leaves the caller to go and find out what it tripped, and
    # it gives the selftest nothing to assert on but the exit code -- which is how a control
    # starts passing because SOME mechanism refused the same input. Both failures are the ones
    # this suite exists to reject.
    param([string]$Code, [string]$Detail, [string]$Why)
    return @{ ok = $false; exit = 6
             error = "prohibition refused: $Code :: $Detail"
             code = $Code; operand = $Detail; why = $Why }
}

function Get-ListField {
    # A presence-aware LIST read, returning @() for an absent or empty field. See the note at
    # the call site: `@(Get-GrantField ...)` yields @(''), and an empty member in a vocabulary is
    # not inert -- `[string].Contains('')` is true, so it matched everything.
    param($Object, [string]$Name)
    if (-not (Test-FieldPresent $Object $Name)) { return @() }
    $out = @(Get-GrantField $Object $Name)
    return @($out | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
}

function Invoke-ProhibitionGate {
    <#
      THE ENFORCEMENT POINT. Called from Test-Grant AFTER the registry is loaded and its
      digest verified and BEFORE the capability is reported as inside the grant, so no
      refusal here can be reached by a path that already returned ok:true.

      It answers one question: does the registry's own boundary block, for the capability
      being checked, refuse THIS grant and THIS invocation? Three fail-closed properties,
      in the order they are checked:

        1. STRUCTURE. prose with no prohibition, an unknown code, a missing `covers`, a
           missing/!valid operand, a `covers` string the entry no longer states, or a prose
           string no prohibition claims -- each is exit 6 naming the offending value. A
           boundary that cannot be evaluated is refused, never skipped. THIS is what makes
           deleting `gate_must_not_delegate` from the registry change what a program reports.

        2. DERIVATION. target origin and container kind are read from the granted file's
           own bytes and resolved path. Nothing the caller wrote is consulted, so no caller
           can satisfy these by typing a field.

        3. THE DECLARED INVOCATION. `no_forbidden_argv_token` needs the command line, so it
           REQUIRES -Invocation and an absent one is exit 6 naming the code. It is matched
           against BOTH the declared invocation and the capability's recorded `probe.command`,
           so editing the registry's probe to smuggle a flag is refused too. Matching is
           whole-token against `forbidden_argv_tokens` and case-insensitive substring against
           `forbidden_substrings` (paths inside a URL have no token boundary to stand on).

      `only_when_token` arms a prohibition conditionally -- "-KeepProjects against a path
      outside %TEMP%" is about the flag, not about the path. An armed-conditionally
      prohibition whose arming token cannot be determined is a refusal, for the same reason
      an absent invocation is.
    #>
    param($CapDef, [string]$Capability, [string]$Target, [string]$Invocation)

    # Presence, then value. `@(Get-GrantField ...)` on an absent field yields @(''), which is
    # ONE empty string, not zero entries -- so the naive read reports a capability with no
    # prohibitions as having one malformed prohibition, and reports a capability with no prose
    # as having one empty sentence. Both were measured on the first run of this function.
    $hasProse = Test-FieldPresent $CapDef 'gate_must_not_delegate'
    $hasBlock = Test-FieldPresent $CapDef 'gate_prohibitions'
    $prose = if ($hasProse) { @(Get-GrantField $CapDef 'gate_must_not_delegate') } else { @() }
    $block = if ($hasBlock) { @(Get-GrantField $CapDef 'gate_prohibitions') } else { @() }

    # (1a) prose with no mechanism. THE MEASURED HOLE: nothing in this file read either key,
    # so deleting `gate_must_not_delegate` from all ten entries left every Check green.
    if ($hasProse -and -not $hasBlock) {
        return (Get-ProhibitionRefusal -Code 'gate_must_not_delegate_without_mechanism' `
            -Detail "capability=$Capability prose=$($prose.Count) gate_prohibitions=absent" `
            -Why 'a boundary written only as English cannot be enforced by a program, and an unenforced boundary is a comment. Add gate_prohibitions, or delete the prose and admit there is no boundary.')
    }
    # And the mirror image: a mechanism that claims sentences the entry no longer carries. This
    # is what catches the half-edit in the OTHER direction, and it is what makes deleting the
    # prose key -- with `gate_prohibitions` left in place -- a refusal rather than a no-op.
    if ($hasBlock -and -not $hasProse) {
        return (Get-ProhibitionRefusal -Code 'prohibition_block_without_prose' `
            -Detail "capability=$Capability gate_prohibitions=$($block.Count) gate_must_not_delegate=absent" `
            -Why 'the two halves are pinned to each other. A prohibition with no sentence to mechanise is an unnamed rule, and an unnamed rule is one the next reader cannot check.')
    }

    $enforced = 0; $unenforceable = 0; $codes = @()
    foreach ($p in $block) {
        # The five fields are read through Get-GrantField rather than by property access: a
        # prohibition entry missing `covers` yields '' instead of $null, and '' is a refusal
        # below rather than a silent pass.
        $code = [string](Get-GrantField $p 'code')
        $covers = @(Get-GrantField $p 'covers')
        $op = Get-GrantField $p 'operand'
        $when = [string](Get-GrantField $p 'only_when_token')

        if ($ProhibitionCodes -notcontains $code) {
            return (Get-ProhibitionRefusal -Code 'unknown_prohibition_code' -Detail "capability=$Capability code='$code' known=$($ProhibitionCodes -join ' | ')" `
                -Why 'the vocabulary is closed. A code this script cannot interpret would be read as true by every later reader, which is how the escalation-class hole opened in the first place.')
        }
        if ($covers.Count -eq 0 -or @($covers | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            return (Get-ProhibitionRefusal -Code 'prohibition_covers_nothing' -Detail "capability=$Capability code=$code" `
                -Why 'every prohibition says which sentence of gate_must_not_delegate it mechanises. One that does not is prose with extra syntax.')
        }
        foreach ($cv in $covers) {
            if ($prose -notcontains [string]$cv) {
                return (Get-ProhibitionRefusal -Code 'prohibition_claims_a_sentence_the_entry_does_not_state' `
                -Detail "capability=$Capability code=$code claims='$cv'" `
                -Why 'the two halves of this boundary are pinned to each other in both directions. A claim naming a sentence the entry no longer carries means one half was edited without the other, and the gate is the only thing that notices.')
            }
        }

        if ($code -eq 'unenforceable_prose') { $unenforceable++; $codes += "$code(unchecked)"; continue }

        # ---- (3) arming, before anything else, because an unarmed prohibition is the one
        # ---- thing that must never be reached by accident.
        $armed = $true
        if ($when) {
            if ([string]::IsNullOrWhiteSpace($Invocation)) {
                return (Get-ProhibitionRefusal -Code "$code(arming-condition-unknown)" `
                    -Detail "capability=$Capability only_when_token=$when invocation=<absent>" `
                    -Why 'this prohibition is conditional, so the gate cannot know whether it applies without the command line. Assuming it does not apply is how a boundary disappears.')
            }
            $probeCmd = [string]((Get-GrantField $CapDef 'probe').command)
            $armed = (Test-TokenPresent $Invocation $when) -or (Test-TokenPresent $probeCmd $when)
        }
        if (-not $armed) { continue }

        switch ($code) {
            'target_must_be_self_authored' {
                if ([string]::IsNullOrWhiteSpace($op) -or $null -eq $op.require -or $op.require -ne 'repo_or_temp') {
                    return (Get-ProhibitionRefusal -Code 'malformed_operand' -Detail "capability=$Capability code=$code operand.require='$($op.require)' accepted=$($ProhibitionOrigins -join ' | ')" `
                        -Why 'an operand this script cannot evaluate would be silently treated as satisfied. A boundary whose operand is misspelled is not a boundary, it is a comment with a schema.')
                }
                $origin = Get-TargetOrigin -Target $Target
                if ($origin -eq 'foreign') {
                    return (Get-ProhibitionRefusal -Code $code `
                        -Detail "capability=$Capability target=$Target origin=$origin (not under $(Get-RepoRoot) and not under $env:TEMP)" `
                        -Why 'the granted target is neither inside this repository nor a %TEMP% copy, so nothing here establishes that this station authored it. This is a PATH claim and says no more than that.')
                }
            }
            'target_must_be_temp_copy' {
                if ([string]::IsNullOrWhiteSpace($op) -or $null -eq $op.require -or $op.require -ne 'temp') {
                    return (Get-ProhibitionRefusal -Code 'malformed_operand' -Detail "capability=$Capability code=$code operand.require='$($op.require)' accepted=$($ProhibitionOrigins -join ' | ')" `
                        -Why 'an operand this script cannot evaluate would be silently treated as satisfied. A boundary whose operand is misspelled is not a boundary, it is a comment with a schema.')
                }
                $origin = Get-TargetOrigin -Target $Target
                if ($origin -ne 'temp') {
                    return (Get-ProhibitionRefusal -Code $code `
                        -Detail "capability=$Capability target=$Target origin=$origin (expected a %TEMP% copy)$(if ($when) { " only_when_token=$when" })" `
                        -Why 'the operand for this prohibition is a %TEMP% copy of a self-authored challenge. It cannot tell such a copy from an arbitrary file that happens to live in %TEMP%; it can only refuse everything else.')
                }
            }
            'container_must_be_pe' {
                if ([string]::IsNullOrWhiteSpace($op) -or $null -eq $op.require -or $op.require -ne 'pe') {
                    return (Get-ProhibitionRefusal -Code 'malformed_operand' -Detail "capability=$Capability code=$code operand.require='$($op.require)' accepted=pe" `
                        -Why 'an operand this script cannot evaluate would be silently treated as satisfied. A boundary whose operand is misspelled is not a boundary, it is a comment with a schema.')
                }
                $kind = Get-ContainerKind -Target $Target
                if ($kind -ne 'pe') {
                    return (Get-ProhibitionRefusal -Code $code `
                        -Detail "capability=$Capability target=$Target container=$kind (first bytes are not MZ)" `
                        -Why 'pefile given a ZIP does not refuse cleanly; it produces a plausible PE structure out of a container. Reading two bytes is the whole enforcement, and it is enough for the case the boundary names.')
                }
            }
            'no_forbidden_argv_token' {
                # PRESENCE, then value, for the same reason as the prose/block read above --
                # and this one bit harder. `@(Get-GrantField ...)` on an absent field yields
                # @(''), and `[string].Contains('')` is TRUE, so a prohibition that names only
                # `forbidden_argv_tokens` matched its own EMPTY substring against every
                # invocation and refused all of them. Measured: it took out ten controls in one
                # run, including the near-miss and every recorded probe. A gate that refuses
                # everything passes every "refuses X" test, which is why these read as presence
                # and drop empty members.
                $tokens = @(Get-ListField $op 'forbidden_argv_tokens')
                $subs = @(Get-ListField $op 'forbidden_substrings')
                if ($tokens.Count -eq 0 -and $subs.Count -eq 0) {
                    return (Get-ProhibitionRefusal -Code 'malformed_operand' -Detail "capability=$Capability code=$code operand names no token" `
                        -Why 'a vocabulary with no members is an empty gate, and an empty gate is indistinguishable from no gate at all.')
                }
                if ([string]::IsNullOrWhiteSpace($Invocation)) {
                    return (Get-ProhibitionRefusal -Code "$code(invocation-absent)" `
                        -Detail "capability=$Capability forbidden=$((@($tokens) + @($subs)) -join ', ')" `
                        -Why 'this prohibition is about a command line, so the gate cannot evaluate it without one. Refusing an unstated command line is the only fail-closed answer: a vocabulary nobody states is a vocabulary nobody is held to.')
                }
                $probeCmd = [string]((Get-GrantField $CapDef 'probe').command)
                foreach ($tk in $tokens) {
                    if ((Test-TokenPresent $Invocation $tk) -or (Test-TokenPresent $probeCmd $tk)) {
                        $where = if (Test-TokenPresent $Invocation $tk) { 'the declared invocation' } else { 'the capability''s own recorded probe.command' }
                        return (Get-ProhibitionRefusal -Code $code -Detail "capability=$Capability token='$tk' matched in $where; invocation=$Invocation" `
                            -Why 'the boundary names this token as a way past the gate. Matching is whole-token, so a longer flag that merely contains it is still allowed.')
                    }
                }
                foreach ($sb in $subs) {
                    if ($Invocation.ToLowerInvariant().Contains([string]$sb.ToLowerInvariant()) -or
                        $probeCmd.ToLowerInvariant().Contains([string]$sb.ToLowerInvariant())) {
                        return (Get-ProhibitionRefusal -Code $code -Detail "capability=$Capability substring='$sb' present in invocation=$Invocation" `
                            -Why 'this operand is a substring rather than a token because it is a path inside a URL, where no token boundary stands on either side.')
                    }
                }
            }
        }
        $enforced++; $codes += $code
    }

    # (1b) the other direction of the same pin: a prose sentence no prohibition claims.
    $claimed = @(); foreach ($p in $block) { $claimed += @(Get-GrantField $p 'covers') }
    $uncovered = @($prose | Where-Object { $claimed -notcontains [string]$_ })
    if ($uncovered.Count -gt 0) {
        return (Get-ProhibitionRefusal -Code 'prose_with_no_prohibition' -Detail "capability=$Capability uncovered: $($uncovered -join ' || ')" `
            -Why 'adding one convenient prohibition and leaving the rest as English is how this field became decorative in the first place. Every sentence must be claimed by a code, or declared unenforceable, or deleted.')
    }

    return @{ ok = $true; exit = 0
             prohibitions = $block.Count; enforced = $enforced; unenforceable = $unenforceable
             codes = ($codes -join ', ') }
}

function Test-FieldPresent {
    # Get-GrantField yields '' for an ABSENT property, which is what makes a grant's canonical
    # form stable across "missing" and "empty". It is the wrong tool for a presence question,
    # and using it as one is a bug this function had on its first run: a capability with no
    # `gate_prohibitions` came back as @(''), so "prose with no mechanism" never fired and the
    # refusal came out as `unknown_prohibition_code code=''` instead. Right answer, wrong
    # reason -- which is exactly what the per-control error-regex assertions exist to catch.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    foreach ($e in (Get-Entries $Object)) { if ($e.Key -eq $Name) { return $true } }
    return $false
}


# --------------------------------------------------------------------------------
# The identity seal.
#
# THE KEY, AND WHERE IT LIVES. There is no key file and no key material in this repo. The
# seal is sealed with DPAPI at DataProtectionScope::CurrentUser, so the sealing key is
# the interactive Windows account's master key, held by LSA and reachable only through
# CryptProtectData. Consequences, stated plainly:
#   - A model, a mission loop, or an agent editing grant.json as text cannot produce a
#     matching seal. It would have to execute CryptProtectData as this user, which is a
#     different kind of act from editing a file and is itself auditable.
#   - A grant minted by user A does not unseal under user B, and does not unseal on
#     another machine. Re-sealing is one `gate.ps1 -Action New`.
#   - This is still weaker than an asymmetric signature: any code running as this user
#     can call CryptProtectData. It is a real step up from an unkeyed hash, not a claim
#     of non-forgeability by the account itself.
$script:GateEntropy = [System.Text.Encoding]::UTF8.GetBytes('debugger/gate.ps1 :: grant identity attestation v2')

function Initialize-GateCrypto {
    # `System.Security` is a .NET Framework assembly; in PowerShell 7 ProtectedData is
    # already in the box and there is nothing to add. Try both, then report.
    if ('System.Security.Cryptography.ProtectedData' -as [type]) { return $true }
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
    return [bool]('System.Security.Cryptography.ProtectedData' -as [type])
}

function Protect-Identity {
    param([string]$Plain)
    if (-not (Initialize-GateCrypto)) { throw 'DPAPI is unavailable on this host' }
    $sealed = [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::UTF8.GetBytes($Plain), $script:GateEntropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($sealed)
}

function Unprotect-Identity {
    param([string]$Sealed)
    if (-not (Initialize-GateCrypto)) { throw 'DPAPI is unavailable on this host' }
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        [Convert]::FromBase64String($Sealed.Trim()), $script:GateEntropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Text.Encoding]::UTF8.GetString($plain)
}

function Get-GrantField {
    # Shape-agnostic single-field read that yields '' for an absent property instead of
    # $null, so the canonical form of a grant that has never been escalated is identical
    # whether the fields are missing or empty.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return '' }
    foreach ($e in (Get-Entries $Object)) {
        if ($e.Key -eq $Name) { if ($null -eq $e.Value) { return '' }; return $e.Value }
    }
    return ''
}

function Get-GrantIdentity {
    # THE IDENTITY PROJECTION: who authorised this, for what, under what word, in what
    # containment, over which bytes, against which registry, and any escalation on top.
    #
    # `allowed` and `note` are deliberately NOT in it. Escalation is the one legal
    # operation that rewrites `allowed`, so sealing it would forbid escalation itself;
    # `allowed` is instead held to the registry, which is the authority for it anyway.
    # Everything here is minted once and must never change afterwards.
    param($Grant)
    $id = [ordered]@{}
    foreach ($k in @('schema', 'case_id', 'lane', 'target', 'target_sha256', 'provenance',
                     'owner_word', 'granted_at', 'containment', 'escalation',
                     'escalation_word', 'escalated_at', 'prior_grant_sha256', 'registry_sha256')) {
        $id[$k] = Get-GrantField $Grant $k
    }
    return $id
}

function Write-GrantSeal {
    # Called BEFORE grant.json is written, by both New and Escalate, so a grant whose seal
    # cannot be produced is never left on disk.
    param([string]$CaseDir, $Grant)
    $sealed = Protect-Identity (Get-CanonicalJson (Get-GrantIdentity $Grant))
    Set-Content -LiteralPath (Join-Path $CaseDir $GrantSealFile) -Value $sealed -Encoding UTF8
}

function Get-RegistryDigest {
    param([string]$Path)
    return Get-Sha256File -Path $Path
}

function Get-GrantableIds {
    # The invocable set the registry actually sanctions for a lane: same lane, the grant
    # IS the verdict, AND state 'observed'. The state filter is not a formality. Minting
    # `dynamic.device.frida` (state=absent) or `native.ghidra.emulate` (state=blocked) into
    # a grant handed the verdict layer a capability it can never run, which is worse than
    # refusing: it believes it holds evidence it never produced. registry-verify.py lists
    # observed | absent | degraded | planned | blocked; only 'observed' means the probe
    # actually ran, so only 'observed' is grantable.
    param($Registry, [string]$Lane)
    return @($Registry.capabilities | Where-Object {
        $_.gate -and $_.gate.lane -eq $Lane -and $_.gate.requires_verdict -and $_.state -eq 'observed'
    } | ForEach-Object { $_.id })
}

function New-Grant {
    param($Target, $Provenance, $OwnerWord, $CaseDir, $Lane, $Containment)
    if ($r = Test-RegistrySubstitution) { return $r }

    if (-not $Target -or -not (Test-Path -LiteralPath $Target)) {
        return @{ ok = $false; exit = 3; error = 'target missing or not a path we can see'; detail = "target=$Target" }
    }
    if ([string]::IsNullOrWhiteSpace($OwnerWord)) {
        # No Owner word, no grant. This is the whole gate. Whitespace counts as absent:
        # `"   "` was truthy to `-not`, so a caller could pass a blank sentence and the
        # gate would record that blank sentence as the Owner's authorisation.
        return @{ ok = $false; exit = 3; error = 'no Owner word recorded. A mission is not a permission, and a context boundary is not a new permission.' }
    }
    if ([string]::IsNullOrWhiteSpace($Provenance) -or (Test-SelfAsserted $Provenance)) {
        return @{ ok = $false; exit = 4; error = 'provenance is self-asserted or absent'; detail = $Provenance
                  why = '"I found it on my disk" is not ownership. Provenance must be checkable by the Owner, not asserted by the caller.' }
    }
    if ([string]::IsNullOrWhiteSpace($Containment) -or ($KnownContainments -notcontains $Containment)) {
        # No default, on purpose. mission.ps1:183-188 already refuses to guess a
        # containment class; defaulting one here would re-open exactly that hole one layer
        # down, in the component that is supposed to be the authority.
        return @{ ok = $false; exit = 3
                 error = "containment class is required and must be one of: $($KnownContainments -join ' | ')"
                 detail = "containment=$Containment"
                 why = 'a grant that does not say how the object is contained says nothing, and two grants over different containment are otherwise byte-identical.' }
    }
    if ([string]::IsNullOrWhiteSpace($CaseDir)) {
        return @{ ok = $false; exit = 3; error = 'a grant must be written into a case directory'
                 why = 'a grant that is not persisted cannot be attested, and an unattested grant cannot be checked.' }
    }

    $regPath = Get-RegistryPath
    $reg = Get-Content -LiteralPath $regPath -Raw | ConvertFrom-Json

    # The grant starts as the set of capabilities whose own gate declares they may run
    # on this lane AND whose registry state says they have actually been observed. Anything
    # else has to be escalated explicitly, later, with a word. See Get-GrantableIds for why
    # the state filter is load-bearing and not cosmetic.
    $allowed = @(Get-GrantableIds -Registry $reg -Lane $Lane)

    $grant = [ordered]@{
        schema         = $GrantSchemaVersion
        case_id        = [IO.Path]::GetFileName($CaseDir.TrimEnd('\','/'))
        lane           = $Lane
        target         = (Resolve-Path -LiteralPath $Target).Path
        target_sha256  = (Get-Sha256File -Path $Target)
        provenance     = $Provenance
        owner_word     = $OwnerWord
        granted_at     = (Get-Date).ToUniversalTime().ToString('o')
        containment    = $Containment
        allowed        = @($allowed | Sort-Object)
        escalation     = 'none'
        registry_sha256 = (Get-RegistryDigest -Path $regPath)
        note           = 'The invocable set may only shrink. Only gate.ps1 mints a grant; only an Owner word authorises one.'
    }
    $grant['grant_sha256'] = Get-GrantHash $grant

    New-Item -ItemType Directory -Path $CaseDir -Force | Out-Null
    # Seal FIRST. If this throws, no grant.json is written at all, so the case directory
    # never holds a grant that Check would have to refuse.
    try { Write-GrantSeal -CaseDir $CaseDir -Grant $grant }
    catch { return @{ ok = $false; exit = 6; error = "the grant could not be attested: $($_.Exception.Message)"
                     why = 'an unsealed grant is a grant whose identity anyone can rewrite. Refusing to mint beats minting one that Check will refuse.' } }
    Set-Content -LiteralPath (Join-Path $CaseDir 'grant.json') -Value (Out-Json $grant) -Encoding UTF8

    return @{ ok = $true; exit = 0; grant = $grant; allowed_count = @($allowed).Count
             containment = $Containment; attested = $true }
}

function Test-Grant {
    # Check does not trust the file it is checking. Every property it reports is
    # re-derived from an authority the grant file cannot forge: the DPAPI identity seal
    # (who/why/which bytes/which containment/which registry), the registry in git (which
    # capabilities, and whether they have been observed at all), and the target's bytes
    # re-hashed right now. `grant_sha256` is still checked, and it is still not a
    # signature: an unkeyed hash over a file the attacker rewrote proves only that the
    # attacker can compute SHA-256.
    # `$Invocation` is the command line the caller is about to execute. It is a PARAMETER OF
    # THIS FUNCTION, not just of the script, and the first version of this change forgot that:
    # the script and the dispatch switch both took `-Invocation`, so `Test-Grant -Invocation x`
    # bound nothing, every argv control silently fell through to the `invocation-absent`
    # refusal, and three controls went red while several more went green FOR THE WRONG REASON
    # -- a `$wantError` of 'prohibition refused: no_forbidden_argv_token' matches the
    # invocation-absent refusal as happily as a real token match. Which is why the token
    # controls below now assert the TOKEN, not the code.
    # $Target is the file the CALLER is about to point this capability at, and it was missing
    # until 2026-10-03. Without it the gate authorises "this capability, on THAT file" and the
    # caller may aim it anywhere: an independent audit of the MCP surface found the server
    # passing -Capability and never -Target, so a valid debug-lane grant for one self-built PE
    # was a licence to run the same capability on any file on this machine. The grant re-hashes
    # its own target, which proves the GRANTED file is unchanged -- it says nothing about which
    # file the caller chose. A grant authorises a pair (capability, bytes); a caller that names
    # only half of it must be refused, not trusted.
    # NAMED $RequestedTarget, not $Target, and that is a correction rather than a style
    # choice: PowerShell variable names are CASE-INSENSITIVE, and this function already
    # used `$target` for the path read out of the grant. Declaring a parameter `$Target`
    # bound the CLI value correctly and then silently lost it to `$target = (Get-GrantField
    # $grant 'target')` further down -- so the comparison compared the grant with itself
    # and every caller's file was accepted. Measured 2026-10-03, caught by a diagnostic
    # print rather than by reading.
    param($CaseDir, $Capability, $Invocation, $RequestedTarget)
    if ($r = Test-RegistrySubstitution) { return $r }

    $gp = Join-Path $CaseDir 'grant.json'
    if (-not (Test-Path -LiteralPath $gp)) {
        return @{ ok = $false; exit = 5; error = 'no grant.json in the case directory' }
    }
    $grant = Get-Content -LiteralPath $gp -Raw | ConvertFrom-Json

    # --- the field allow-list -------------------------------------------------
    # An unknown field used to be hashed along with everything else and reported ok:true.
    # Adding attach_pid=99999 and attach_to='any process on this host' to a grant and
    # recomputing the hash was ACCEPTED: the gate had no vocabulary for "this grant names
    # a process", so it could neither record nor refuse one. A field the gate ignores is
    # an attack surface, so an unknown field is now a refusal, not a shrug.
    $present = @(Get-Entries $grant | ForEach-Object { $_.Key })
    $unknown = @($present | Where-Object { $GrantKnownFields -notcontains $_ })
    if ($unknown.Count -gt 0) {
        return @{ ok = $false; exit = 5; unknown_fields = $unknown
                 error = "grant carries unknown field(s): $($unknown -join ', ')"
                 why = 'a grant may only say what this gate defines. An unrecognised field is refused rather than hashed, because a field the gate silently ignores is a field nobody constrains.' }
    }
    $missing = @($GrantRequiredFields | Where-Object { $present -notcontains $_ })
    if ($missing.Count -gt 0) {
        return @{ ok = $false; exit = 5; missing_fields = $missing
                 error = "grant is missing required field(s): $($missing -join ', ') -- re-mint it with 'gate.ps1 -Action New'"
                 why = "a grant minted by an older gate.ps1 (schema $GrantSchemaVersion) carries no attestation this version can check. It is refused, not defaulted: a grant the gate cannot re-establish is exactly the grant the exit-6 path exists to refuse." }
    }
    $schema = [string](Get-GrantField $grant 'schema')
    if ($schema -ne $GrantSchemaVersion) {
        return @{ ok = $false; exit = 5
                 error = "grant schema '$schema' is not '$GrantSchemaVersion' -- re-mint it with 'gate.ps1 -Action New'" }
    }

    $recomputed = Get-GrantHash $grant
    $stored = [string](Get-GrantField $grant 'grant_sha256')
    if ($recomputed -ne $stored) {
        # Somebody edited the grant in place, or it was rewritten by a tool that does not
        # preserve the canonical form. Either way the authority it claims is not trustworthy.
        return @{ ok = $false; exit = 5; error = 'grant hash mismatch -- the grant was altered after it was minted'
                 stored = $stored; recomputed = $recomputed }
    }

    # --- the identity, re-established field by field --------------------------
    # These four were NEVER re-validated. `Test-Grant` checked the hash, the allowed set
    # and the target, and then reported ok:true about owner_word, provenance and
    # escalation without ever reading them. Blanking owner_word and provenance in the
    # file and recomputing the unkeyed hash produced a grant that Check accepted with
    # exit 0 and `target_bytes_verified: true` -- an authority record with no authority
    # in it. The self-assertion heuristic ran only inside New-Grant, so a grant that said
    # "I found it on my disk" was accepted on every Check after the mint.
    $ownerWord = [string](Get-GrantField $grant 'owner_word')
    if ([string]::IsNullOrWhiteSpace($ownerWord)) {
        return @{ ok = $false; exit = 6
                 error = 'grant records no Owner word -- there is nothing in it that the Owner said'
                 why = 'only an Owner word authorises a grant. A grant with an empty owner word is not a weaker grant, it is no grant.' }
    }
    $provenance = [string](Get-GrantField $grant 'provenance')
    if ([string]::IsNullOrWhiteSpace($provenance)) {
        return @{ ok = $false; exit = 6
                 error = 'grant records no provenance -- there is nothing checkable behind the Owner word' }
    }
    if (Test-SelfAsserted $provenance) {
        return @{ ok = $false; exit = 6
                 error = 'grant provenance is self-asserted'
                 detail = $provenance
                 why = 'New refuses this at the mint. Check has to refuse it too, or the refusal is one rewrite away from being gone.' }
    }

    $containment = [string](Get-GrantField $grant 'containment')
    if ([string]::IsNullOrWhiteSpace($containment) -or ($KnownContainments -notcontains $containment)) {
        return @{ ok = $false; exit = 6
                 error = "grant containment class is missing or unnameable; known: $($KnownContainments -join ' | ')"
                 detail = "containment=$containment"
                 why = 'mission.ps1 requires a containment class at intake and never told the gate about it, so a grant under station_under_named_process_rule was byte-identical to one under isolated_vm. The gate now refuses a grant that does not say.' }
    }

    $escalation = [string](Get-GrantField $grant 'escalation')
    if (($escalation -ne 'none') -and [string]::IsNullOrWhiteSpace([string](Get-GrantField $grant 'escalation_word'))) {
        return @{ ok = $false; exit = 6
                 error = 'grant records an escalation but no Owner word for it -- the widening operation is the one that needed a word most'
                 detail = "escalation=$escalation" }
    }

    # G9, the same defect one layer down. `containment` above is re-established against a
    # literal list; `escalation` was only checked for "is there a word behind it", so a grant
    # naming a class this script does not define passed. The seal does not cover this: the
    # seal is DPAPI at CurrentUser and this file says so in its own notes -- any code running
    # as this user can re-seal, which the G9 selftest control does on purpose.
    if ($KnownEscalations -notcontains $escalation) {
        return @{ ok = $false; exit = 6
                 error = "grant escalation class is not one this gate defines; known: $($KnownEscalations -join ' | ')"
                 detail = "escalation=$escalation"
                 why = 'the class records HOW FAR this grant was widened. A class the gate cannot enforce is a class it will go on reading as true.' }
    }

    # --- the seal -------------------------------------------------------------
    # THE HEADLINE FIX. Un-keyed-hash re-derivation cannot be beaten by editing text, so
    # the identity is additionally sealed with DPAPI at mint time and unsealed here. The
    # plaintext of the sealed copy exists only under the Windows account that minted it.
    $sealPath = Join-Path $CaseDir $GrantSealFile
    if (-not (Test-Path -LiteralPath $sealPath)) {
        return @{ ok = $false; exit = 6
                 error = "grant has no identity attestation ($GrantSealFile) -- re-mint it with 'gate.ps1 -Action New'"
                 why = 'the identity of a grant has to survive the grant file being rewritten. Without a sealed copy, the only copy of the identity is the one the attacker edits.' }
    }
    $sealedJson = $null
    try { $sealedJson = Unprotect-Identity (Get-Content -LiteralPath $sealPath -Raw) }
    catch {
        return @{ ok = $false; exit = 6
                 error = "the identity attestation could not be unsealed: $($_.Exception.Message)"
                 why = 'the seal is bound to the Windows account that wrote it. A grant sealed elsewhere cannot be verified here; re-mint it as this user.' }
    }
    $sealedDoc = $sealedJson | ConvertFrom-Json
    $sealedCan = Get-CanonicalJson (Get-GrantIdentity $sealedDoc)
    $onDiskCan = Get-CanonicalJson (Get-GrantIdentity $grant)
    if ($sealedCan -ne $onDiskCan) {
        $sealedId = Get-GrantIdentity $sealedDoc
        $onDiskId = Get-GrantIdentity $grant
        $drift = @(Get-Entries $onDiskId | Where-Object {
            [string](Get-GrantField $sealedId $_.Key) -ne [string]$_.Value } | ForEach-Object { $_.Key })
        return @{ ok = $false; exit = 6
                 error = 'identity attestation does not match the grant -- the grant was rewritten after it was minted'
                 drifted_fields = $drift
                 why = 'the unkeyed hash over grant.json is not a signature, so the identity is compared against a DPAPI-sealed copy that a text edit cannot reproduce. Blank the owner word, swap the owner word, repoint the target, restate the containment class -- the seal is what notices.' }
    }

    # --- the registry, as the authority ---------------------------------------
    $regPath = Get-RegistryPath
    $reg = Get-Content -LiteralPath $regPath -Raw | ConvertFrom-Json

    # -Registry is a caller-controlled parameter, so "the registry authority" used to be
    # whatever file the caller named. A grant minted against the real registry, then
    # Checked with a hand-written one, passed: the registry subset test below was
    # evaluated against the attacker's own file. The digest the seal covers closes that --
    # the grant names the registry it was minted from, and Check refuses any other.
    $regDigest = Get-RegistryDigest -Path $regPath
    $claimedReg = [string](Get-GrantField $grant 'registry_sha256')
    if ($claimedReg -ne $regDigest) {
        $shortClaimed = if ($claimedReg.Length -gt 16) { $claimedReg.Substring(0, 16) } else { $claimedReg }
        $shortOnDisk = if ($regDigest.Length -gt 16) { $regDigest.Substring(0, 16) } else { $regDigest }
        return @{ ok = $false; exit = 6
                 error = "grant was minted against a different capabilities registry (grant $shortClaimed... / on disk $shortOnDisk...) -- re-mint it"
                 detail = "registry=$regPath"
                 why = '-Registry is caller-controlled, so the registry is bound into the sealed identity. Checking a real grant against a substituted registry now fails instead of passing.' }
    }


    # --- THE REGISTRY'S OWN AUTHORITY BOUNDARIES, ENFORCED --------------------
    # Placed here, and not at the end, for two reasons that are both load-bearing. FIRST
    # ORDER: it runs after the registry has been loaded and its digest has been matched
    # against the seal, so the boundary block it reads is the one the Owner granted against,
    # and BEFORE the membership test below, so a capability whose boundary refuses this grant
    # can never reach an ok:true by way of being "inside the grant". SECOND, and this is the
    # reason it is here at all rather than inside the membership branch: `$Capability` is the
    # only thing that names WHICH boundary applies, so this is where the caller states which
    # capability it is about to run. A caller that names none gets the grant's validity and no
    # boundary evaluation, which is the limit stated in .NOTES and is not papered over.
    if ($Capability) {
        $bndDef = $reg.capabilities | Where-Object { $_.id -eq $Capability }
        if ($bndDef) {
            # `$target` is assigned further down, at the re-hash. Read it from the grant here
            # rather than moving that assignment: this block must not depend on a variable a
            # LATER check produces, because a boundary that only evaluates when the file happens
            # to be intact is a boundary with a hole in the middle.
            $bndTarget = [string](Get-GrantField $grant 'target')
            $bnd = Invoke-ProhibitionGate -CapDef $bndDef -Capability $Capability -Target $bndTarget -Invocation $Invocation
            if (-not $bnd.ok) { return $bnd }
        }
    }
    # --- the capability, against that registry --------------------------------
    if ($Capability) {
        $capDef = $reg.capabilities | Where-Object { $_.id -eq $Capability }
        # Before the membership test, so the refusal says WHY rather than only "not in the
        # grant". Minting an absent or blocked capability used to yield a Check that
        # returned ok:true for a tool that cannot run -- the verdict layer then believes it
        # holds evidence it never produced.
        if ($capDef -and ($capDef.state -ne 'observed')) {
            return @{ ok = $false; exit = 3
                     error = "capability '$Capability' is registry state '$($capDef.state)', not 'observed' -- it cannot be granted"
                     detail = "state=$($capDef.state)"
                     why = 'only an observed capability has had its probe actually run. An absent or blocked capability in a grant is a claim about evidence that does not exist.' }
        }
    }

    $allowed = @(Get-GrantField $grant 'allowed')
    if ($Capability -and ($allowed -notcontains $Capability)) {
        return @{ ok = $false; exit = 3; error = "capability '$Capability' is not inside the grant"
                 allowed = $allowed
                 why = 'the invocable set is a monotonic subset of the grant; widening it is an escalation, not a lookup' }
    }

    # --- CRITICAL FIX, adversarial audit 2026-09-30 -------------------------
    #
    # The grant was protected by an UNKEYED SHA-256 over a file the mission loop itself
    # writes. That is not a boundary: anyone can widen `allowed` and recompute the hash,
    # because the algorithm is right here in this file. Demonstrated -- `allowed` was
    # widened to add `RULE.THE.WORLD`, the hash recomputed to the byte, and
    # `Check -Capability RULE.THE.WORLD` returned ok:true. The selftest only proved an edit
    # WITHOUT recomputing is caught, which is the one thing an attacker would not do.
    #
    # THE FIX IS NOT A SECRET. A secret is a new thing to leak, rotate and store. The fix
    # is that the registry -- manifests\capabilities.json, which is in git -- is the
    # authority, and grant.json is only a convenience. Anything `allowed` claims that the
    # registry does not grant for this lane is DROPPED, and a capability outside that set is
    # refused. E:\missions\ is outside git; the registry is not. Forging a grant now means
    # forging the registry, which is a committed diff an Owner can see.
    $lane = [string](Get-GrantField $grant 'lane')
    $registryAllows = @(Get-GrantableIds -Registry $reg -Lane $lane)
    $forged = @($allowed | Where-Object { $registryAllows -notcontains $_ })
    if ($forged.Count -gt 0) {
        return @{ ok = $false; exit = 3
                 error = "grant claims capabilities the registry does not grant for lane '$lane': $($forged -join ', ')"
                 why = 'the grant file is not the authority. The registry is, and it is in git. A hash over a file anyone can rewrite proves only that the rewriter can compute SHA-256.'
                 forged = $forged }
    }

    # --- CRITICAL FIX, same audit, second half --------------------------------
    # target_sha256 was ASSIGNED and never read again. Overwriting the granted binary with
    # 35 bytes of garbage left Check returning ok:true over the substituted bytes: the grant
    # was still valid for a target that no longer existed. Re-hash it here. Swapped bytes
    # are caught below and were already caught before this revision; what was NOT caught is
    # the branch above it, where a target that is not on disk skipped the re-hash entirely
    # and then reported `target_bytes_verified = $true` unconditionally. A file that does
    # not exist has no bytes, so there is nothing to have verified. Fail closed.
    $target = [string](Get-GrantField $grant 'target')
    if (-not $target) {
        return @{ ok = $false; exit = 5; target_bytes_verified = $false
                 error = 'grant records no target' }
    }
    if (-not (Test-Path -LiteralPath $target)) {
        return @{ ok = $false; exit = 5; target_bytes_verified = $false
                 error = 'the granted target is not on disk -- its bytes cannot be verified, so the grant is refused'
                 target = $target
                 why = 'this used to skip the re-hash and then report target_bytes_verified: true. A missing file has no bytes to hash; the only honest answer is that nothing was verified.' }
    }
    # --- the CALLER's target must be the GRANTED target -------------------------------
    # Measured 2026-10-03: a valid grant plus a different file was accepted, because the only
    # target this function knew about was the one inside the grant. Naming it is what makes the
    # grant a licence for one object instead of one capability.
    if ($RequestedTarget) {
        $wantPath = $null
        try { $wantPath = (Resolve-Path -LiteralPath $RequestedTarget -ErrorAction Stop).Path } catch { }
        if (-not $wantPath -or -not (Test-Path -LiteralPath $RequestedTarget)) {
            return @{ ok = $false; exit = 7; target_bytes_verified = $false
                     error = 'the requested target does not exist or cannot be resolved'
                     requested_target = $RequestedTarget; granted_target = $target
                     why = 'a grant authorises a specific file. Pointing a granted capability at a path this gate cannot see is refused rather than assumed to be the granted one.' }
        }
        $wantHash = Get-Sha256File -Path $wantPath
        if ($wantPath -ne $target) {
            return @{ ok = $false; exit = 7; target_bytes_verified = $false
                     error = 'the requested target is not the granted target'
                     requested_target = $wantPath; granted_target = $target
                     requested_sha256 = $wantHash; granted_sha256 = [string](Get-GrantField $grant 'target_sha256')
                     why = 'a grant names ONE file. Running the granted capability against a different file is a different authorisation, and this gate does not have one.' }
        }
    }

    $nowHash = Get-Sha256File -Path $target
    $grantedHash = [string](Get-GrantField $grant 'target_sha256')
    if ($nowHash -ne $grantedHash) {
        return @{ ok = $false; exit = 5; target_bytes_verified = $false
                 error = 'the granted target has changed on disk since the grant was minted'
                 granted_sha256 = $grantedHash; current_sha256 = $nowHash
                 why = 'a grant authorises BYTES, not a path. Re-issue the grant for the new target.' }
    }

    return @{ ok = $true; exit = 0
             case_id = [string](Get-GrantField $grant 'case_id')
             lane = $lane
             target = $target
             containment = $containment
             allowed = $allowed
             identity_reestablished = $true
             verified_against_registry = $true
             target_bytes_verified = $true
             # Reported, not just enforced: a reader of this JSON has to be able to see how
             # much of the boundary was actually checked. `unenforceable` in particular is the
             # number that must never be mistaken for a pass -- those are prohibitions this
             # gate records and does NOT evaluate, and hiding the count would make an
             # unchecked boundary look like a checked one.
             prohibitions_enforced = $(if ($bnd) { $bnd.enforced } else { 0 })
             prohibitions_unenforceable = $(if ($bnd) { $bnd.unenforceable } else { 0 })
             prohibition_codes = $(if ($bnd) { $bnd.codes } else { '' }) }
}

function Invoke-Escalate {
    param($CaseDir, $Capability, $NewWord, $NewClass)
    if ($r = Test-RegistrySubstitution) { return $r }

    $cur = Test-Grant -CaseDir $CaseDir
    if (-not $cur.ok) { return $cur }

    if ($NewClass -eq 'impossible') {
        return @{ ok = $false; exit = 3; error = 'the impossible class cannot be granted at runtime'
                 why = 'changing lane or reach is an Owner edit to AGENTS.md / CHARTER-ARSENAL.md in git. There is no flag on this script that changes that, by design.' }
    }

    # G9: the class is a closed vocabulary, checked here at the only place authority widens.
    # Before this, any string except the literal `impossible` was accepted, written into the
    # grant and re-sealed -- see the note above $KnownEscalations for the measurement.
    if ([string]::IsNullOrWhiteSpace($NewClass) -or ($GrantableEscalation -notcontains $NewClass)) {
        return @{ ok = $false; exit = 3
                 error = "escalation class is required and must be one of: $($GrantableEscalation -join ' | ')"
                 detail = "escalation_class=$NewClass"
                 why = 'this call widens allowed, so the class it records has to say that it did. "none" is what a grant that was never widened carries, and it is not a destination.' }
    }
    # G8. The one operation that WIDENS authority had no check at all on its
    # authorisation: `Escalate -NewWord ''` returned exit 0 and wrote an empty
    # escalation_word to disk. New refuses an empty Owner word, so the gate already knew
    # an empty sentence is not an authorisation -- it just did not say so here, on the one
    # path where the sentence is the only thing standing between the current grant and a
    # wider one.
    if ([string]::IsNullOrWhiteSpace($NewWord)) {
        return @{ ok = $false; exit = 3
                 error = 'escalation refused: no fresh Owner word was given. The operation that widens authority is the one that may not run on a blank.'
                 why = 'New refuses an empty Owner word. Escalation is strictly more dangerous than minting, so it cannot have a weaker rule.' }
    }

    $reg = Get-Content -LiteralPath (Get-RegistryPath) -Raw | ConvertFrom-Json
    $cap = $reg.capabilities | Where-Object { $_.id -eq $Capability }
    if (-not $cap) { return @{ ok = $false; exit = 3; error = "unknown capability '$Capability'" } }

    # Same lane, or it is the impossible class by definition.
    if ($cap.gate.lane -ne $Lane) {
        return @{ ok = $false; exit = 3; error = "capability '$Capability' is lane '$($cap.gate.lane)', grant is lane '$Lane'"
                 why = 'changing lane is the impossible class: it needs an Owner edit to AGENTS.md in git, not a runtime flag.' }
    }

    # An escalation must not be the back door around the state filter in New-Grant: if
    # `dynamic.device.frida` (absent) or `native.ghidra.emulate` (blocked) may not enter a
    # grant by minting, a single `Escalate` must not be able to put it there either.
    if ($cap.state -ne 'observed') {
        return @{ ok = $false; exit = 3
                 error = "capability '$Capability' is registry state '$($cap.state)', not 'observed' -- it cannot be escalated into a grant"
                 why = 'an Owner word authorises a capability that can run. It cannot conjure one whose probe never ran.' }
    }

    $gp = Join-Path $CaseDir 'grant.json'
    $grant = Get-Content -LiteralPath $gp -Raw | ConvertFrom-Json
    $prior = [string](Get-GrantField $grant 'grant_sha256')
    $grant.allowed = @(@(Get-GrantField $grant 'allowed') + $Capability | Sort-Object -Unique)
    $grant.escalation = $NewClass
    $grant.note = "escalated to $NewClass on $Capability with a fresh Owner word; prior grant hash retained in the trace"
    $grant | Add-Member -NotePropertyName prior_grant_sha256 -NotePropertyValue $prior -Force
    $grant | Add-Member -NotePropertyName escalation_word -NotePropertyValue $NewWord -Force
    $grant | Add-Member -NotePropertyName escalated_at -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
    $grant.grant_sha256 = Get-GrantHash $grant

    # Re-seal. escalation / escalation_word / escalated_at are part of the identity
    # projection, so without this a later text edit could restate what the Owner
    # authorised. Seal BEFORE writing grant.json so a failure here leaves the previous,
    # still-valid grant on disk rather than an escalated one that Check would refuse.
    try { Write-GrantSeal -CaseDir $CaseDir -Grant $grant }
    catch { return @{ ok = $false; exit = 6; error = "the escalation could not be attested: $($_.Exception.Message)"
                     why = 'grant.json was not modified. The previous grant is still on disk and still valid.' } }
    Set-Content -LiteralPath $gp -Value (Out-Json $grant) -Encoding UTF8

    return @{ ok = $true; exit = 0; escalation = $NewClass; capability = $Capability; prior = $prior; now = $grant.grant_sha256 }
}

function Invoke-Selftest {
    # Script-scoped, because T() appends from inside a function. Declaring this local
    # made the selftest collect ZERO cases and then announce "SELFTEST OK: 0 refusals
    # and grants all behaved" -- a green run that tested nothing, which is exactly the
    # failure this repo exists to reject. There is now an explicit floor below.
    $script:gateCases = @()
    function T($name, $body, $wantExit, $wantError = '') {
        $script:gateCases += ,@($name, (& $body), $wantExit, $wantError)
    }


    $tmp = Join-Path $env:TEMP ("gate-selftest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $tgt = Join-Path $tmp 'sample.bin'
    Set-Content -LiteralPath $tgt -Value 'not really a binary, but a path we can see'

    # =============================================================================
    # THE SELFTEST'S CONFORMING REGISTRY.
    #
    # WHY IT EXISTS. The boundary gate refuses an entry whose prose has no mechanism, and ten
    # entries in the registry in git are exactly that today -- which is CORRECT and is the whole
    # point, but it would mean every control below goes red for a reason that has nothing to do
    # with what each control was written for. That is the failure mode this suite exists to
    # reject, so the suite runs against a copy of the real registry that HAS the mechanism.
    #
    # IT IS NOT A FIXTURE IN THE USUAL SENSE, and the distinction is the point: this synthesises
    # a block ONLY for an entry that has prose and no block of its own. The moment the
    # integrator pastes the real `gate_prohibitions`, this function stops touching that entry
    # and the suite tests the registry's own data. Measured, and asserted by a control below.
    #
    # The table lists, per capability, which prose index gets a real code; every index NOT
    # listed becomes `unenforceable_prose`, which is what 13 of the 38 sentences genuinely are.
    # A fixture that enforced all 38 would be a fixture that lied.
    $script:SelfBnd = @{
        'native.ida.decompile' = @(
            @{ i = 0; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--unsafe') } }
            @{ i = 1; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--profile') } }
            @{ i = 2; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('POST'); forbidden_substrings = @('/config') } })
        'dynamic.win.frida' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 1; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('-U', 'frida-remote', 'frida-ps') } }
            @{ i = 2; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('-p', '-n') } }
            @{ i = 3; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('Interceptor.replace', 'Memory.patchCode') } })
        'ops.skill.security' = @(
            @{ i = 0; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--transitive') } }
            @{ i = 2; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('skillspector[mcp]') } }
            @{ i = 3; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--llm') } })
        'dynamic.win.frida.intercept' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 1; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('Interceptor.replace', 'Memory.patchCode') } }
            @{ i = 2; code = 'target_must_be_temp_copy'; op = @{ require = 'temp' } }
            @{ i = 3; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('frida.get_remote_device', 'frida.get_usb_device', 'get_remote_device', 'get_usb_device') } })
        'native.pe.container' = @(
            @{ i = 0; code = 'container_must_be_pe'; op = @{ require = 'pe' } }
            @{ i = 2; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('Interceptor.attach', 'Interceptor.replace', 'Memory.patchCode') } })
        'native.function.match' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 3; code = 'target_must_be_temp_copy'; op = @{ require = 'temp' }; when = '-KeepProjects' })
        'native.pe.packer' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 3; code = 'no_forbidden_argv_token'; op = @{ forbidden_substrings = @('PackedAtOrAbove') } })
        'native.disasm.capstone' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 1; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--force') } })
        'native.pe.authenticode' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } }
            @{ i = 3; code = 'no_forbidden_argv_token'; op = @{ forbidden_argv_tokens = @('--make-control') } })
        'native.behaviour.capa' = @(
            @{ i = 0; code = 'target_must_be_self_authored'; op = @{ require = 'repo_or_temp' } })
    }

    function New-ConformingRegistry {
        param([string]$Destination)
        $d = Get-Content -LiteralPath (Get-RegistryPath) -Raw | ConvertFrom-Json
        $synth = 0
        foreach ($c in $d.capabilities) {
            if (-not (Test-FieldPresent $c 'gate_must_not_delegate')) { continue }
            # POST-PASTE THIS FUNCTION BECOMES A NO-OP for that entry, by design.
            if (Test-FieldPresent $c 'gate_prohibitions') { continue }
            $prose = @(Get-GrantField $c 'gate_must_not_delegate')
            $tpl = @()
            if ($script:SelfBnd.ContainsKey([string]$c.id)) { $tpl = @($script:SelfBnd[[string]$c.id]) }
            $block = @()
            for ($i = 0; $i -lt $prose.Count; $i++) {
                $spec = $null
                foreach ($s in $tpl) { if ($s.i -eq $i) { $spec = $s } }
                $p = [ordered]@{ code = 'unenforceable_prose'; covers = @([string]$prose[$i]) }
                if ($spec) {
                    $p['code'] = [string]$spec.code
                    if ($spec.op) { $p['operand'] = $spec.op }
                    if ($spec.when) { $p['only_when_token'] = [string]$spec.when }
                }
                $block += [pscustomobject]$p
            }
            $c | Add-Member -NotePropertyName gate_prohibitions -NotePropertyValue $block -Force
            $synth++
        }
        Set-Content -LiteralPath $Destination -Value ($d | ConvertTo-Json -Compress -Depth 20) -Encoding UTF8
        return @{ path = $Destination; synthesised = $synth }
    }

    $conf = New-ConformingRegistry (Join-Path $tmp 'capabilities-conforming.json')
    # Printed rather than returned-and-ignored. After the integrator pastes, this reads 0, and
    # that zero IS the signal: the suite has stopped synthesising and is reading the registry's
    # own blocks. A number nobody prints is a number nobody checks.
    Write-Host ("  (conforming registry: $($conf.synthesised) of the ten boundary entries needed a synthesised gate_prohibitions block; the rest carry the registry's own)")

    $script:SelftestRegistry = $conf.path
    # The baseline for the rest of the suite. Every `$script:RegistryOverride = ''` below became
    # `= $script:SelftestRegistry`; leaving one as '' would silently drop every later control back
    # onto the un-pasted real registry, where the ten entries refuse for the wrong reason.
    $script:RegistryOverride = $script:SelftestRegistry
    # Read once so a control that needs a capability's own recorded probe command does not
    # have to re-read the file to get one.
    $regSelfRead = Get-Content -LiteralPath $script:SelftestRegistry -Raw | ConvertFrom-Json

    # `containment` is now a REQUIRED mint input (New refuses without it -- there is no
    # default, because guessing a containment class is what mission.ps1's intake refuses
    # to do). These five fixtures therefore carry one. The ASSERTIONS are untouched: same
    # scenarios, same expected exit codes, same names.
    $L = 'debug'
    $C = @{ CaseDir = $tmp; Target = $tgt; Provenance = 'Owner named this file in conversation 2026-09-30'
            OwnerWord = 'analyze this exe'; Containment = 'station_under_named_process_rule'; Lane = $L }

    T 'mint a grant with an Owner word and a checkable provenance' { New-Grant @C } 0
    T 'refuse with NO Owner word' { New-Grant -Target $tgt -Provenance 'Owner named it' -OwnerWord '' -CaseDir $tmp -Containment 'isolated_vm' -Lane $L } 3
    T 'refuse self-asserted provenance' { New-Grant -Target $tgt -Provenance 'I found it on my disk' -OwnerWord 'go' -CaseDir $tmp -Containment 'isolated_vm' -Lane $L } 4
    T 'refuse an empty provenance' { New-Grant -Target $tgt -Provenance '' -OwnerWord 'go' -CaseDir $tmp -Containment 'isolated_vm' -Lane $L } 4
    T 'refuse a target that does not exist' { New-Grant -Target (Join-Path $tmp 'nope.bin') -Provenance 'Owner named it' -OwnerWord 'go' -CaseDir $tmp -Containment 'isolated_vm' -Lane $L } 3

    $g = New-Grant @C
    # `$g.grant.allowed`, not `$g.allowed`: New-Grant returns `grant`, so `$g.allowed` is
    # $null, `-Capability $null` skipped the membership branch, and this control asserted
    # only that a lookup with no capability succeeds. Combined with the -Lane that these
    # fixtures did not pass -- without it every grant here had lane="" and allowed=[] --
    # this control was green while testing nothing at all. Both are real now.
    # `-Invocation` is the capability's own recorded probe command, read from the registry
    # rather than typed here, so this control keeps asking the question it was written for
    # ("is an allowed capability allowed?") and does not start asking a second one. Without it
    # the control would still be green -- the boundary gate's refusal carries the same exit
    # 0-versus-3 shape only by accident -- which is exactly the "passes for the wrong reason"
    # failure the $wantError regex exists to catch.
    $firstAllowed = [string]($g.grant.allowed | Select-Object -First 1)
    $firstAllowedCmd = [string](($regSelfRead.capabilities | Where-Object { $_.id -eq $firstAllowed }).probe.command)
    T 'a capability inside the grant is allowed' { Test-Grant -CaseDir $tmp -Capability $firstAllowed -Invocation $firstAllowedCmd } 0
    T 'a capability OUTSIDE the grant is refused' { Test-Grant -CaseDir $tmp -Capability 'not.a.real.capability' } 3

    # Tamper: the whole point of the hash.
    $gp = Join-Path $tmp 'grant.json'
    $doc = Get-Content -LiteralPath $gp -Raw | ConvertFrom-Json
    $doc.allowed = @('everything.i.want')
    Set-Content -LiteralPath $gp -Value (Out-Json $doc) -Encoding UTF8
    T 'refuse a grant whose allowed-set was edited in place' { Test-Grant -CaseDir $tmp -Capability 'everything.i.want' } 5

    # --- THE TWO THAT ACTUALLY SUCCEEDED against the previous version ---------
    # The old selftest proved that an edit WITHOUT recomputing the hash is caught. That
    # is the one thing an attacker would not do. These two replay the attacks that worked.
    $g2 = New-Grant @C
    $gp2 = Join-Path $tmp 'grant.json'
    $doc2 = Get-Content -LiteralPath $gp2 -Raw | ConvertFrom-Json
    $doc2.allowed = @($doc2.allowed) + 'RULE.THE.WORLD'
    $doc2.grant_sha256 = Get-GrantHash $doc2          # <-- recompute, as an attacker would
    Set-Content -LiteralPath $gp2 -Value (Out-Json $doc2) -Encoding UTF8
    T 'CRITICAL: a forged capability with a RECOMPUTED hash is still refused' { Test-Grant -CaseDir $tmp -Capability 'RULE.THE.WORLD' } 3

    $doc2b = Get-Content -LiteralPath $gp2 -Raw | ConvertFrom-Json
    $doc2b.allowed = @($doc2b.allowed | Where-Object { $_ -ne 'RULE.THE.WORLD' })
    $doc2b.grant_sha256 = Get-GrantHash $doc2b
    Set-Content -LiteralPath $gp2 -Value (Out-Json $doc2b) -Encoding UTF8

    # Substitute the granted TARGET's bytes, leave the grant alone.
    # The file must EXIST before New-Grant runs, or the gate refuses to mint and the old
    # grant is still on disk -- which made this control pass for the wrong reason on its
    # first attempt, the same failure mode as every other one in this selftest's history.
    $tamperTarget = Join-Path $tmp 'target-to-tamper.bin'
    Set-Content -LiteralPath $tamperTarget -Value 'the original bytes, before substitution'
    $g3 = New-Grant -Target $tamperTarget -Provenance 'Owner named this file in conversation 2026-09-30' -OwnerWord 'analyze this exe' -CaseDir $tmp -Containment 'station_under_named_process_rule' -Lane $L
    # Never call a method on the result unguarded: New-Grant returns a hashtable WITHOUT a
    # `raw` key on success and one WITH it on refusal, and under $ErrorActionPreference='Stop'
    # a null .raw took the whole selftest down before a single control printed.
    # The key is `exit`, not `code`: reading `.code` yielded $null, so this "the control
    # below would be vacuous" warning printed `exit ` and never once fired. A guard that
    # cannot fire is not a guard.
    $g3code = if ($g3 -is [array]) { $g3[0].exit } else { $g3.exit }
    if ($g3code -ne 0) { Write-Host ("  NOTE: tamper-case grant was not minted (exit " + $g3code + "); the control below would be vacuous") }
    Set-Content -LiteralPath $tamperTarget -Value ('X' * 35)     # substituted with garbage
    T 'CRITICAL: a grant over REPLACED target bytes is refused' { Test-Grant -CaseDir $tmp } 5

    # =============================================================================
    # THE EXPLOITED HOLES. Every control below reproduced a refusal that DID NOT HAPPEN
    # against the previous revision of this file, and each one asserts the SPECIFIC error
    # as well as the exit code, via T()'s $wantError. The regex is the point: a control
    # that checks only the exit code goes green the moment a second mechanism starts
    # refusing the same input, and then it is no longer testing the thing it was written
    # for. That is the failure mode this repo exists to reject, and it is why the
    # ablation table in the hand-off report is a per-control table and not a summary.
    # =============================================================================

    function Rewrite-Grant {
        # Edit grant.json AND recompute the unkeyed hash, exactly as an attacker would.
        # Without the recompute, every control here would go green on the hash check
        # alone -- which is the one thing no attacker does.
        param([string]$CaseDir, [scriptblock]$Mutate)
        $path = Join-Path $CaseDir 'grant.json'
        $d = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        & $Mutate $d
        $d.grant_sha256 = Get-GrantHash $d
        Set-Content -LiteralPath $path -Value (Out-Json $d) -Encoding UTF8
    }

    $Prov = 'Owner named this file in conversation 2026-09-30'
    $Cont = 'station_under_named_process_rule'
    $regRealPath = Get-RegistryPath

    # Scratch registries, so these controls test the gate and not a sibling's next edit
    # to manifests\capabilities.json. Written with -Depth 20 because Out-Json's -Depth 8
    # is not enough to round-trip a capability entry intact.
    $regStatePath = Join-Path $tmp 'capabilities-states.json'
    $regState = Get-Content -LiteralPath $regRealPath -Raw | ConvertFrom-Json
    foreach ($c in $regState.capabilities) {
        if ($c.id -eq 'native.ida.decompile') { $c.state = 'blocked' }
        elseif ($c.id -eq 'native.ida.list_functions') { $c.state = 'absent' }
    }
    Set-Content -LiteralPath $regStatePath -Value ($regState | ConvertTo-Json -Compress -Depth 20) -Encoding UTF8

    $regEvilPath = Join-Path $tmp 'capabilities-widened.json'
    $regEvil = Get-Content -LiteralPath $regRealPath -Raw | ConvertFrom-Json
    $regEvil.capabilities = @($regEvil.capabilities) + [pscustomobject]@{
        id = 'RULE.THE.WORLD'; state = 'observed'
        gate = [pscustomobject]@{ lane = 'debug'; requires_verdict = $true } }
    Set-Content -LiteralPath $regEvilPath -Value ($regEvil | ConvertTo-Json -Compress -Depth 20) -Encoding UTF8

    # --- G4b: absent and blocked capabilities may not enter a grant ------------
    # Minted against a registry where two observed capabilities are flipped, so this does
    # not depend on which entries happen to be absent or blocked today.
    $script:RegistryOverride = $regStatePath
    $cState = Join-Path $tmp 'c-state-filter'
    New-Item -ItemType Directory -Path $cState -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cState -Containment $Cont -Lane $L | Out-Null
    T 'G4b: a fresh grant contains no absent or blocked capability' {
        $gd = Get-Content -LiteralPath (Join-Path $cState 'grant.json') -Raw | ConvertFrom-Json
        $rd = Get-Content -LiteralPath $regStatePath -Raw | ConvertFrom-Json
        $bad = @()
        foreach ($a in @($gd.allowed)) {
            $cd = $rd.capabilities | Where-Object { $_.id -eq $a }
            if ($cd -and $cd.state -ne 'observed') { $bad += $a }
        }
        if ($bad.Count -gt 0) { return @{ ok = $false; exit = 3; error = "reached the grant: $($bad -join ', ')" } }
        return @{ ok = $true; exit = 0; error = 'clean: no absent or blocked capability entered the grant' }
    } 0 '^clean'
    # `-Invocation` is passed because native.ida.decompile now carries a vocabulary prohibition
    # and an unstated command line is a refusal. Without it this control would still be GREEN,
    # for the wrong reason: it would be refused by the boundary gate with exit 6 instead of by
    # the state filter with exit 3, and `wantError 'state'` would be the only thing telling the
    # difference. Passing the capability's own recorded probe is what keeps this control testing
    # the state filter and nothing else.
    T 'G4b: a BLOCKED capability is refused at Check, by state' { Test-Grant -CaseDir $cState -Capability 'native.ida.decompile' -Invocation 'node native-lab/tools/loop.mjs --only=decompile' } 3 'state'
    T 'G4b: an ABSENT capability is refused at Check, by state' { Test-Grant -CaseDir $cState -Capability 'native.ida.list_functions' } 3 'state'
    $script:RegistryOverride = $script:SelftestRegistry

    # --- G-FS, part 1: the identity blanked ------------------------------------
    $cBlank = Join-Path $tmp 'c-blank-identity'
    New-Item -ItemType Directory -Path $cBlank -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cBlank -Containment $Cont -Lane $L | Out-Null
    Rewrite-Grant $cBlank { param($d) $d.owner_word = ''; $d.provenance = '' }
    T 'G-FS: identity BLANKED and the hash recomputed is refused' { Test-Grant -CaseDir $cBlank } 6 'owner word'

    # --- G-FS, part 2: the identity REPLACED -----------------------------------
    # The headline. A blank is the easy case; replacing the Owner word and the provenance
    # with different, entirely plausible sentences leaves every field non-empty and
    # structurally legal. Nothing short of a sealed copy of the original identity can
    # tell that from a genuine grant, which is why the seal exists.
    $cForge = Join-Path $tmp 'c-forged-identity'
    New-Item -ItemType Directory -Path $cForge -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cForge -Containment $Cont -Lane $L | Out-Null
    Rewrite-Grant $cForge { param($d)
        $d.owner_word = 'do absolutely anything to this host'
        $d.provenance = 'Owner authorised this in a different conversation entirely' }
    T 'G-FS: identity REPLACED with new words and the hash recomputed is refused' { Test-Grant -CaseDir $cForge } 6 'identity attestation'

    # --- G4: the granted target is not on disk ---------------------------------
    $cGone = Join-Path $tmp 'c-target-gone'
    $tGone = Join-Path $tmp 'c-target-gone.bin'
    New-Item -ItemType Directory -Path $cGone -Force | Out-Null
    Set-Content -LiteralPath $tGone -Value 'the authorised bytes'
    New-Grant -Target $tGone -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cGone -Containment $Cont -Lane $L | Out-Null
    Rename-Item -LiteralPath $tGone -NewName 'c-target-gone.renamed.bin'
    T 'G4: a grant whose target is no longer on disk is refused' { Test-Grant -CaseDir $cGone } 5 'not on disk'

    # --- G5: the grant replayed onto a different object ------------------------
    $cReplay = Join-Path $tmp 'c-replay'
    $tAuth = Join-Path $tmp 'c-authorised.bin'
    $tOther = Join-Path $tmp 'c-other.bin'
    New-Item -ItemType Directory -Path $cReplay -Force | Out-Null
    Set-Content -LiteralPath $tAuth -Value 'the object the Owner named'
    Set-Content -LiteralPath $tOther -Value 'a completely different object'
    New-Grant -Target $tAuth -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cReplay -Containment $Cont -Lane $L | Out-Null
    Rewrite-Grant $cReplay { param($d) $d.target = $tOther; $d.target_sha256 = Get-Sha256File -Path $tOther }
    T 'G5: a grant replayed onto a DIFFERENT object is refused' { Test-Grant -CaseDir $cReplay } 6 'identity attestation'

    # --- G7: -Registry is caller-controlled ------------------------------------
    $cReg = Join-Path $tmp 'c-registry-swap'
    New-Item -ItemType Directory -Path $cReg -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cReg -Containment $Cont -Lane $L | Out-Null
    $script:RegistryOverride = $regEvilPath
    T 'G7: Check against a caller-substituted registry is refused' { Test-Grant -CaseDir $cReg -Capability 'native.ida.decompile' } 6 'registry'
    $script:RegistryOverride = $script:SelftestRegistry

    # --- G10: the caller cannot substitute the registry at ANY entry point -------
    # The measured attack, in the shape a caller produces it: set the one variable the
    # parameter used to write, and mint. Before the fix this produced a green grant whose
    # authority was a file outside git; G7 above could not catch it, because a substituted
    # mint seals the substituted registry's own digest and therefore matches itself.
    $cRegMint = Join-Path $tmp 'c-registry-at-mint'
    New-Item -ItemType Directory -Path $cRegMint -Force | Out-Null
    $script:Registry = $regEvilPath
    T 'G10: a mint that names another registry is refused' {
        $m = New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cRegMint -Containment $Cont -Lane $L
        if ($m.ok) { return @{ ok = $false; exit = 0; error = "the mint SUCCEEDED against a substituted registry (allowed_count=$($m.allowed_count))" } }
        return $m
    } 6 'registry'
    T 'G10: a Check that names another registry is refused' { Test-Grant -CaseDir $cReg -Capability 'native.ida.decompile' } 6 'registry'
    $script:Registry = ''
    # `Test-Path` returns a boolean, and T() reads `.exit` off the result -- the first version
    # of this control compared $null to 0 and printed an empty verdict, which is the shape of
    # a control that passes for a reason nobody can name.
    T 'G10: nothing was written by the refused mint' {
        if (Test-Path -LiteralPath (Join-Path $cRegMint 'grant.json')) {
            return @{ ok = $false; exit = 0; error = 'the refused mint left a grant.json on disk' }
        }
        return @{ ok = $true; exit = 0; error = 'none' }
    } 0 'none'

    # And the override the selftest itself uses still works, so this cannot be "completed"
    # later by deleting it -- the G4b controls above depend on it, and a suite that silently
    # stopped testing the state filter would be worse than the hole it closed.
    $cOverrideWorks = Join-Path $tmp 'c-override-works'
    New-Item -ItemType Directory -Path $cOverrideWorks -Force | Out-Null
    $script:RegistryOverride = $regEvilPath
    T 'G10: the selftest-only override still redirects the gate' {
        $m = New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cOverrideWorks -Containment $Cont -Lane $L
        if (-not $m.ok) { return $m }
        $d = Get-Content -LiteralPath (Join-Path $cOverrideWorks 'grant.json') -Raw | ConvertFrom-Json
        if (@($d.allowed) -notcontains 'RULE.THE.WORLD') {
            return @{ ok = $false; exit = 3; error = 'the override did NOT take effect, so the state-filter controls above were reading the real registry' }
        }
        return @{ ok = $true; exit = 0; error = 'none' }
    } 0 'none'
    $script:RegistryOverride = $script:SelftestRegistry

    # The control that makes the scoping claim in Get-RegistryPath's comment TRUE rather than
    # merely plausible, and it has to be a SEPARATE PROCESS: `-File` runs the gate in its own
    # scope, so the override cannot travel with it, while in-process `$script:RegistryOverride`
    # is this very variable. Written in-process it would pass for the wrong reason -- which is the
    # failure mode this suite exists to reject. Measured by the 2026-10-03 verifier: dot-sourcing
    # this file DOES let a caller set the variable, so the surviving property is that a forged
    # grant does not outlive the process that made it.
    $cOverrideThenFile = Join-Path $tmp 'c-override-then-file'
    New-Item -ItemType Directory -Path $cOverrideThenFile -Force | Out-Null
    $script:RegistryOverride = $regEvilPath
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cOverrideThenFile -Containment $Cont -Lane $L | Out-Null
    $script:RegistryOverride = $script:SelftestRegistry
    # It must name a capability that EXISTS in the real registry. The first version of this
    # control asked about RULE.THE.WORLD, which does not exist there, so it passed because the
    # capability was unknown -- a control that passes for a reason other than the one it was
    # written for, which is the failure this suite exists to reject. Mutation confirms the
    # difference: deleting Test-Grant's registry-digest refusal leaves THIS control green and
    # reddens only G7. Asking about a real capability is what makes it test the digest binding.
    T 'G10: a grant minted under the override does not survive a plain -File Check' {
        $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Action Check -CaseDir $cOverrideThenFile -Capability 'native.ida.decompile' 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            return @{ ok = $false; exit = 0; error = 'a grant minted against a substituted registry checked ok:true from a SEPARATE process' }
        }
        if ("$out" -notmatch 'minted against a different capabilities registry') {
            return @{ ok = $false; exit = 6; error = "refused, but NOT by the registry-digest binding this control exists for: $out" }
        }
        return @{ ok = $true; exit = 0; error = 'none' }
    } 0 'none'

    # --- G8: the widening operation, with no word ------------------------------
    $cEsc = Join-Path $tmp 'c-escalate-word'
    New-Item -ItemType Directory -Path $cEsc -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cEsc -Containment $Cont -Lane $L | Out-Null
    T 'G8: escalating on a BLANK Owner word is refused and writes nothing' {
        $e = Invoke-Escalate -CaseDir $cEsc -Capability 'net.pcap.analyse' -NewWord '   ' -NewClass 'owner_word'
        $after = Get-Content -LiteralPath (Join-Path $cEsc 'grant.json') -Raw | ConvertFrom-Json
        if ([string]$after.escalation -ne 'none') {
            return @{ ok = $false; exit = 0; error = "the refused escalation was written to disk anyway (escalation=$($after.escalation))" }
        }
        return $e
    } 3 'Owner word'
    # and the positive case, so the guard is not simply "escalation never works"
    T 'G8: a real Owner word still escalates and the grant still checks' {
        $e = Invoke-Escalate -CaseDir $cEsc -Capability 'net.pcap.analyse' -NewWord 'the Owner widened this to the pcap parser' -NewClass 'owner_word'
        if (-not $e.ok) { return $e }
        $c = Test-Grant -CaseDir $cEsc -Capability 'net.pcap.analyse'
        if (-not $c.ok) { return @{ ok = $false; exit = 0; error = "the escalated grant no longer checks: $($c.error)" } }
        return @{ ok = $true; exit = 0; error = 'none' }
    } 0 'none'

    # --- G9: the escalation CLASS is a vocabulary, not a field anybody may fill ------
    # MEASURED 2026-10-03, before any of the three checks below existed:
    #   gate.ps1 -Action Escalate -EscalationClass 'TOTALLY_MADE_UP_CLASS'
    # returned exit 0, wrote that string into grant.escalation, re-sealed with DPAPI,
    # and a following Check answered ok:true with identity_reestablished=true. So the one
    # field that records HOW MUCH authority a grant was widened into was free text, in the
    # same script where `containment` -- a different authority field -- has a literal list,
    # three enforcement points and four controls. The registry side was already disciplined:
    # R6 checks gate.escalation_class against VALID_ESCALATION. The gate was the gap.
    $cEscClass = Join-Path $tmp 'c-escalate-class'
    New-Item -ItemType Directory -Path $cEscClass -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cEscClass -Containment $Cont -Lane $L | Out-Null
    T 'G9: escalating into a class this gate never defined is refused and writes nothing' {
        $e = Invoke-Escalate -CaseDir $cEscClass -Capability 'net.pcap.analyse' -NewWord 'the Owner widened this' -NewClass 'TOTALLY_MADE_UP_CLASS'
        $after = Get-Content -LiteralPath (Join-Path $cEscClass 'grant.json') -Raw | ConvertFrom-Json
        if ([string]$after.escalation -ne 'none') {
            return @{ ok = $false; exit = 0; error = "the refused class was written to disk anyway (escalation=$($after.escalation))" }
        }
        return $e
    } 3 'escalation class'

    T 'G9: a BLANK escalation class is refused, not recorded as an empty escalation' {
        Invoke-Escalate -CaseDir $cEscClass -Capability 'net.pcap.analyse' -NewWord 'the Owner widened this' -NewClass ''
    } 3 'escalation class'

    # The identity projection covers `escalation`, so a plain text edit is already refused
    # by the seal. But this file states the limit itself: the seal is DPAPI at CurrentUser,
    # so ANY code running as this user can re-seal. So this control re-seals -- the attack
    # the free-text class enabled -- and asks whether Check re-establishes the CLASS as well
    # as the bytes. A check that cannot fire is not a check, so it has to be one that can.
    $cEscRestated = Join-Path $tmp 'c-escalation-restated'
    New-Item -ItemType Directory -Path $cEscRestated -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cEscRestated -Containment $Cont -Lane $L | Out-Null
    $restated = Get-Content -LiteralPath (Join-Path $cEscRestated 'grant.json') -Raw | ConvertFrom-Json
    # `escalation_word` is set too, on purpose. Without it this control was refused by the
    # PRE-EXISTING "escalation with no Owner word" check -- i.e. it would go red for a reason
    # that has nothing to do with the vocabulary, which is the failure mode this repo exists to
    # reject. The first run of this case did exactly that.
    $restated.escalation = 'owner_word_by_fiat'
    # `escalation_word` / `escalated_at` are ABSENT on a freshly minted grant (they only
    # come into existence when an escalation happens), so they must be added rather than
    # assigned -- `$d.escalation_word = ...` raises "property cannot be found on this
    # object" under $ErrorActionPreference='Stop' and takes the whole selftest down.
    $restated | Add-Member -NotePropertyName escalation_word -NotePropertyValue 'the Owner widened this, in words the gate does not define' -Force
    $restated | Add-Member -NotePropertyName escalated_at -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
    $restated.grant_sha256 = Get-GrantHash $restated
    Write-GrantSeal -CaseDir $cEscRestated -Grant $restated
    Set-Content -LiteralPath (Join-Path $cEscRestated 'grant.json') -Value (Out-Json $restated) -Encoding UTF8
    T 'G9: a grant whose escalation class was restated AND re-sealed is still refused' { Test-Grant -CaseDir $cEscRestated } 6 'escalation class'

    # And the contradiction case: `-NewClass 'none'` WIDENS `allowed` and then records
    # `escalation: none`, i.e. the grant says nothing was escalated while it was. Whether
    # that currently buys an attacker anything depends on which capability is named, which
    # is exactly why it should be a stated rule and not an accident of the code path.
    $cEscNone = Join-Path $tmp 'c-escalate-none'
    New-Item -ItemType Directory -Path $cEscNone -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cEscNone -Containment $Cont -Lane $L | Out-Null
    T 'G9: an escalation that RECORDS no escalation is refused' {
        $e = Invoke-Escalate -CaseDir $cEscNone -Capability 'net.pcap.analyse' -NewWord 'the Owner widened this' -NewClass 'none'
        $after = Get-Content -LiteralPath (Join-Path $cEscNone 'grant.json') -Raw | ConvertFrom-Json
        if ([string]$after.escalation -ne 'none') {
            return @{ ok = $false; exit = 0; error = "the refused class was written to disk anyway (escalation=$($after.escalation))" }
        }
        return $e
    } 3 'escalation class'

    # --- the field allow-list ---------------------------------------------------
    $cFields = Join-Path $tmp 'c-unknown-field'
    New-Item -ItemType Directory -Path $cFields -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cFields -Containment $Cont -Lane $L | Out-Null
    Rewrite-Grant $cFields { param($d)
        $d | Add-Member -NotePropertyName attach_pid -NotePropertyValue 99999 -Force
        $d | Add-Member -NotePropertyName attach_to -NotePropertyValue 'any process on this host' -Force }
    T 'a grant carrying unknown fields (attach_pid / attach_to) is refused' { Test-Grant -CaseDir $cFields } 5 'unknown field'

    # --- containment ------------------------------------------------------------
    $cNoCont = Join-Path $tmp 'c-containment-missing'
    New-Item -ItemType Directory -Path $cNoCont -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cNoCont -Containment $Cont -Lane $L | Out-Null
    Rewrite-Grant $cNoCont { param($d) $d.containment = '' }
    T 'a grant with its containment class blanked is refused' { Test-Grant -CaseDir $cNoCont } 6 'containment'

    $cContSwap = Join-Path $tmp 'c-containment-replay'
    New-Item -ItemType Directory -Path $cContSwap -Force | Out-Null
    New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $cContSwap -Containment 'station_under_named_process_rule' -Lane $L | Out-Null
    Rewrite-Grant $cContSwap { param($d) $d.containment = 'isolated_vm' }
    T 'a grant minted under one containment class, restated as another, is refused' { Test-Grant -CaseDir $cContSwap } 6 'identity attestation'

    T 'refuse a mint with NO containment class' {
        New-Grant -Target $tgt -Provenance $Prov -OwnerWord 'go' -CaseDir (Join-Path $tmp 'c-mint-no-containment') -Containment ''
    } 3 'containment'

    # =============================================================================
    # G11 -- THE REGISTRY'S OWN AUTHORITY BOUNDARIES ARE LOAD-BEARING.
    #
    # THE MEASUREMENT THAT PROVED THEY WERE NOT. 2026-10-03, read-only mutation audit: delete
    # `gate_must_not_delegate` from all ten entries, re-run `registry-verify.py`, and it still
    # exits 0 with REGISTRY CLEAN. The validator does not read that key and neither did this
    # script. Ten authority boundaries -- "never pass --unsafe", "never parse an APK as PE",
    # "Interceptor.replace / Memory.patchCode" -- were English with no program attached.
    #
    # Every control below is written so it goes RED if the mechanism it names is deleted, and
    # so it still goes red if a DIFFERENT mechanism starts refusing the same input: the
    # $wantError regex is the point, and it is why the first control here asserts the refusal
    # code rather than the exit code alone.
    # =============================================================================

    function New-BoundaryRegistry {
        # A scratch registry for one structural mutation, derived from the CONFORMING one so a
        # control's refusal can only come from the mutation and not from the fixture.
        param([string]$Name, [scriptblock]$Mutate)
        $path = Join-Path $tmp $Name
        $d = Get-Content -LiteralPath $script:SelftestRegistry -Raw | ConvertFrom-Json
        & $Mutate $d
        Set-Content -LiteralPath $path -Value ($d | ConvertTo-Json -Compress -Depth 20) -Encoding UTF8
        return $path
    }

    function Bnd-Check {
        # Mint and Check under ONE registry. The override has to be live for the Check as well
        # as the mint, because a grant records the digest of the registry it was minted from --
        # a Check against any other registry is refused for the registry digest, which is a
        # refusal for the right-looking wrong reason. Every G11 control therefore goes through
        # here rather than minting and checking by hand.
        param([string]$Reg, [string]$CaseDir, [string]$Capability, [string]$Target,
              [string]$Invocation, [switch]$OmitInvocation)
        $prev = $script:RegistryOverride
        $script:RegistryOverride = $Reg
        try {
            New-Item -ItemType Directory -Path $CaseDir -Force | Out-Null
            New-Grant -Target $Target -Provenance $Prov -OwnerWord 'analyze this exe' -CaseDir $CaseDir -Containment $Cont -Lane $L | Out-Null
            if ($OmitInvocation) { return Test-Grant -CaseDir $CaseDir -Capability $Capability }
            return Test-Grant -CaseDir $CaseDir -Capability $Capability -Invocation $Invocation -RequestedTarget $Target
        } finally { $script:RegistryOverride = $prev }
    }

    $CleanDecompile = 'node native-lab/tools/loop.mjs --only=decompile'

    # A PE-shaped file, because `container_must_be_pe` reads two bytes and a text file would
    # be refused for the wrong reason in the controls that are not about it.
    $tgtPe = Join-Path $tmp 'sample-pe.exe'
    [IO.File]::WriteAllBytes($tgtPe, ([byte[]](0x4D, 0x5A, 0x90, 0x00) + [byte[]](0) * 60))
    # A ZIP-shaped file: the exact case native.pe.container's first prohibition names.
    $tgtZip = Join-Path $tmp 'sample-container.apk'
    [IO.File]::WriteAllBytes($tgtZip, ([byte[]](0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00)))
    # A file under NEITHER the repo root NOR %TEMP%: the parent of %TEMP%, which is
    # .../AppData/Local -- one level up, so it is a real "foreign" path rather than a
    # synthetic string the matcher was never asked to handle.
    $foreign = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($env:TEMP))) 'gnd-foreign-fixture.bin'
    [IO.File]::WriteAllBytes($foreign, ([byte[]](0x4D, 0x5A, 0x90, 0x00) + [byte[]](0) * 60))
    $repoTarget = Join-Path (Get-RepoRoot) 'crackme-corpus/out/c01-stringobf.exe'

    # --- the headline: deleting the prose key is now visible to a program ----------
    $regNoMechanism = New-BoundaryRegistry 'capabilities-prose-only.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.PSObject.Properties.Remove('gate_prohibitions') }
    T 'G11: DELETING gate_must_not_delegate''s mechanism is refused and NAMES the gap' {
        Bnd-Check -Reg $regNoMechanism -CaseDir (Join-Path $tmp 'g11-no-mechanism') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'gate_must_not_delegate_without_mechanism'

    # The mirror image, and the one the mutation audit's exact operation produces once the
    # integrator pastes: the prose key goes, the mechanism stays, and every `covers` string is
    # now a sentence the entry does not state.
    $regNoProse = New-BoundaryRegistry 'capabilities-mechanism-only.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.PSObject.Properties.Remove('gate_must_not_delegate') }
    T 'G11: deleting the PROSE while the mechanism survives is refused' {
        Bnd-Check -Reg $regNoProse -CaseDir (Join-Path $tmp 'g11-no-prose') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'prohibition_block_without_prose'

    $regPhantom = New-BoundaryRegistry 'capabilities-phantom-cover.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.gate_must_not_delegate[1] = 'using a section name as evidence, but reworded' }
    T 'G11: a prohibition claiming a sentence the entry no longer states is refused' {
        Bnd-Check -Reg $regPhantom -CaseDir (Join-Path $tmp 'g11-phantom') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'claims_a_sentence_the_entry_does_not_state'

    $regUncovered = New-BoundaryRegistry 'capabilities-uncovered.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $keep = @($e.gate_prohibitions | Where-Object { $_.code -ne 'unenforceable_prose' })
        $e | Add-Member -NotePropertyName gate_prohibitions -NotePropertyValue $keep -Force }
    T 'G11: a prose sentence NO prohibition claims is refused' {
        Bnd-Check -Reg $regUncovered -CaseDir (Join-Path $tmp 'g11-uncovered') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'prose_with_no_prohibition'

    $regUnknownCode = New-BoundaryRegistry 'capabilities-unknown-code.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.gate_prohibitions[0].code = 'no_unsafe_flags_please' }
    T 'G11: a prohibition code outside the vocabulary is refused' {
        Bnd-Check -Reg $regUnknownCode -CaseDir (Join-Path $tmp 'g11-unknown-code') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'unknown_prohibition_code'

    $regNoCovers = New-BoundaryRegistry 'capabilities-no-covers.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.gate_prohibitions[0] | Add-Member -NotePropertyName covers -NotePropertyValue @() -Force }
    T 'G11: a prohibition that covers no sentence is refused' {
        Bnd-Check -Reg $regNoCovers -CaseDir (Join-Path $tmp 'g11-no-covers') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'prohibition_covers_nothing'

    $regBadOperand = New-BoundaryRegistry 'capabilities-bad-operand.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.pe.container' }
        $e.gate_prohibitions[0].operand.require = 'anything_at_all' }
    T 'G11: an operand value the gate cannot evaluate is refused, not ignored' {
        Bnd-Check -Reg $regBadOperand -CaseDir (Join-Path $tmp 'g11-bad-operand') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'malformed_operand'

    # --- the argv vocabulary -----------------------------------------------------
    T 'G11: --unsafe is refused and the refusal NAMES the token it matched' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-unsafe') `
                  -Capability 'native.ida.decompile' -Target $tgtPe `
                  -Invocation 'node native-lab/tools/loop.mjs --only=decompile --unsafe'
    } 6 "token='--unsafe'"

    # The near-miss. A gate that refused every string CONTAINING the flag would pass the
    # control above; this is what proves it has a vocabulary rather than a substring test.
    T 'G11: a flag that merely CONTAINS a forbidden token is allowed' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-near-miss') `
                  -Capability 'native.ida.decompile' -Target $tgtPe `
                  -Invocation 'node native-lab/tools/loop.mjs --only=decompile --unsafely-quiet'
    } 0 ''

    T 'G11: a clean declared invocation still checks ok' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-clean') `
                  -Capability 'native.ida.decompile' -Target $tgtPe -Invocation $CleanDecompile
    } 0 ''

    T 'G11: a vocabulary prohibition with NO stated command line is refused' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-no-invocation') `
                  -Capability 'native.ida.decompile' -Target $tgtPe -OmitInvocation
    } 6 'invocation-absent'

    # --no-llm against a --llm prohibition. The single most valuable near-miss in the set:
    # the capability's own recorded probe carries --no-llm, so a matcher that forgets token
    # boundaries would refuse the station's own sanctioned command.
    T 'G11: --no-llm is ALLOWED where --llm is forbidden' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-no-llm') `
                  -Capability 'ops.skill.security' -Target $tgtPe `
                  -Invocation 'skillspector scan skills --no-llm --fail-on-findings'
    } 0 ''

    T 'G11: --llm is refused where --no-llm is allowed' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-llm') `
                  -Capability 'ops.skill.security' -Target $tgtPe `
                  -Invocation 'skillspector scan skills --llm'
    } 6 "token='--llm'"

    # Substring operands: Interceptor.replace / Memory.patchCode. These appear inside a `-e`
    # script body, where no token boundary stands on either side, which is why they are
    # substring operands and the flags above are not.
    T 'G11: Interceptor.replace in a declared invocation is refused' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-replace') `
                  -Capability 'native.pe.container' -Target $tgtPe `
                  -Invocation 'python tools/x.py -e "Interceptor.replace(main, fn)"'
    } 6 "substring='Interceptor.replace'"

    # And the anti-smuggling control: the prohibition is evaluated against the capability's own
    # recorded probe.command as well as the declared invocation, so editing the registry to put
    # the flag in the probe is refused even when the caller declares something clean.
    $regSmuggled = New-BoundaryRegistry 'capabilities-smuggled-probe.json' { param($d)
        $e = $d.capabilities | Where-Object { $_.id -eq 'native.ida.decompile' }
        $e.probe.command = 'node native-lab/tools/loop.mjs --only=decompile --unsafe' }
    T 'G11: a forbidden token hidden in the registry''s own probe.command is refused' {
        Bnd-Check -Reg $regSmuggled -CaseDir (Join-Path $tmp 'g11-smuggled') `
                  -Capability 'native.ida.decompile' -Target $tgtPe -Invocation $CleanDecompile
    } 6 'recorded probe.command'

    # --- derived from the target's own bytes and resolved path --------------------
    T 'G11: a ZIP container is refused for a capability that parses PE' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-zip') `
                  -Capability 'native.pe.container' -Target $tgtZip -Invocation 'python tools/pe.py'
    } 6 'container=zip'

    T 'G11: a PE target is allowed for the same capability' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-pe-ok') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation 'python tools/pe.py'
    } 0 ''

    T 'G11: a target under NEITHER the repo root NOR %TEMP% is refused' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-foreign') `
                  -Capability 'native.pe.packer' -Target $foreign -Invocation 'powershell -File tools/triage-packer.ps1'
    } 6 'origin=foreign'

    # -KeepProjects is the conditional one: the boundary is about the flag, not the path, so
    # both directions are asserted. Without the flag the repo-path target is ALLOWED, which is
    # what makes this a control about arming rather than about path arithmetic.
    T 'G11: -KeepProjects against a NON-%TEMP% target is refused' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-keepprojects') `
                  -Capability 'native.function.match' -Target $repoTarget `
                  -Invocation 'powershell -File tools/match-functions.ps1 -KeepProjects'
    } 6 'only_when_token=-KeepProjects'

    T 'G11: the SAME target WITHOUT -KeepProjects is allowed' {
        Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-nokeep') `
                  -Capability 'native.function.match' -Target $repoTarget `
                  -Invocation 'powershell -File tools/match-functions.ps1 -Source a.exe -Dest b.exe'
    } 0 ''

    # --- the counts, reported rather than assumed ---------------------------------
    # DERIVED, NOT PINNED. Measured on 2026-10-03: 38 prose sentences, 25 enforceable,
    # 13 unenforceable. Those numbers are what .NOTES reports, but this control deliberately
    # does NOT assert them: a sibling editing a capability's prose is a legitimate change, and
    # a control that goes red for it is a control that will be "fixed" by deleting itself. So it
    # asserts the INVARIANT -- the counts reach the Check output, and they equal the counts
    # derived from the registry the gate actually read -- and it PRINTS the measured numbers so
    # drift is visible in the run instead of hidden in a comment.
    T 'G11: the boundary counts are REPORTED, unenforceable ones included' {
        $rd = Get-Content -LiteralPath $script:SelftestRegistry -Raw | ConvertFrom-Json
        $n = 0; $u = 0
        foreach ($c in $rd.capabilities) {
            if (-not (Test-FieldPresent $c 'gate_prohibitions')) { continue }
            foreach ($p in @(Get-GrantField $c 'gate_prohibitions')) {
                $n++
                if ([string](Get-GrantField $p 'code') -eq 'unenforceable_prose') { $u++ }
            }
        }
        if ($n -lt 1) { return @{ ok = $false; exit = 0; error = "the registry carries $n prohibitions" } }
        if ($u -lt 1) {
            return @{ ok = $false; exit = 0; error = "no prohibition is declared unenforceable, so this control proves nothing about reporting an unchecked boundary" }
        }
        $c = Bnd-Check -Reg $script:SelftestRegistry -CaseDir (Join-Path $tmp 'g11-counts') `
                  -Capability 'native.pe.container' -Target $tgtPe -Invocation 'python tools/pe.py'
        if (-not $c.ok) { return $c }
        $entry = @($rd.capabilities | Where-Object { $_.id -eq 'native.pe.container' })[0]
        $wantU = @(@(Get-GrantField $entry 'gate_prohibitions') | Where-Object { [string](Get-GrantField $_ 'code') -eq 'unenforceable_prose' }).Count
        if ([int]$c.prohibitions_unenforceable -ne $wantU) {
            return @{ ok = $false; exit = 0; error = "the Check reported $($c.prohibitions_unenforceable) unenforceable prohibitions; the registry carries $wantU for that entry" }
        }
        Write-Host ("  (registry carries $n prohibitions: " + ($n - $u) + " enforceable, $u unenforceable -- measured, not asserted)")
        return @{ ok = $true; exit = 0; error = "clean: $n prohibitions, $u unenforceable, and the count reaches the Check output" }
    } 0 '^clean'

    # The invariant that makes the whole vocabulary usable: no capability's own recorded
    # probe may trip its own prohibitions. Measured across all ten entries with the generator
    # before the table above was written, and asserted here so a future probe edit is caught
    # by a refusal at the gate rather than by a surprise.
    T 'G11: every capability''s recorded probe satisfies its OWN prohibitions' {
        $bad = @()
        $rdAll = Get-Content -LiteralPath $script:SelftestRegistry -Raw | ConvertFrom-Json
        foreach ($c in $rdAll.capabilities) {
            $blk = @(Get-GrantField $c 'gate_prohibitions')
            if ($blk.Count -eq 0) { continue }
            $cmd = [string]((Get-GrantField $c 'probe').command)
            $cap = $c.id
            $r = Invoke-ProhibitionGate -CapDef $c -Capability $cap -Target $tgtPe -Invocation $cmd
            if (-not $r.ok) { $bad += "$cap => $($r.code)" }
        }
        if ($bad.Count -gt 0) { return @{ ok = $false; exit = 0; error = "probe trips own boundary: $($bad -join '; ')" } }
        return @{ ok = $true; exit = 0; error = 'clean: no recorded probe trips its own prohibition' }
    } 0 '^clean'

    # The fixture's honesty, asserted rather than assumed: once the integrator pastes the real
    # blocks, New-ConformingRegistry must stop synthesising for those entries, so this suite
    # starts testing the registry's own data instead of a table in this file.
    T 'G11: the selftest synthesises a block ONLY for an entry that has none' {
        $rd = Get-Content -LiteralPath $script:SelftestRegistry -Raw | ConvertFrom-Json
        $real = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) 'manifests/capabilities.json') -Raw | ConvertFrom-Json
        $drift = @()
        foreach ($c in $rd.capabilities) {
            if (-not (Test-FieldPresent $c 'gate_prohibitions')) { continue }
            $rc = $real.capabilities | Where-Object { $_.id -eq $c.id }
            if (Test-FieldPresent $rc 'gate_prohibitions') {
                if ((Get-CanonicalJson @(Get-GrantField $c 'gate_prohibitions')) -ne
                    (Get-CanonicalJson @(Get-GrantField $rc 'gate_prohibitions'))) {
                    $drift += $c.id
                }
            }
        }
        if ($drift.Count -gt 0) {
            return @{ ok = $false; exit = 0; error = "the fixture OVERWROTE a real block: $($drift -join ', ')" }
        }
        return @{ ok = $true; exit = 0; error = 'clean: no synthesised block shadowed real registry data' }
    } 0 '^clean'

    if (Test-Path -LiteralPath $foreign) { Remove-Item -LiteralPath $foreign -Force -ErrorAction SilentlyContinue }

    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

    $cases = $script:gateCases

    # A checker that inspects zero items must fail. Without this floor the selftest can
    # report OK having tested nothing at all, which is how the scoping bug above stayed
    # invisible for a whole run.
    if ($cases.Count -eq 0) {
        Write-Host 'GATE SELFTEST FAILED: zero cases were collected. A green run that tested nothing is not a green run.'
        return 2
    }

    # $width was never assigned anywhere in this script. "abc".PadRight($null) is
    # PadRight(0), so every line happened to render unpadded and nothing looked wrong.
    $width = 0
    foreach ($c in $cases) { if ("$($c[0])".Length -gt $width) { $width = "$($c[0])".Length } }

    $failed = 0
    foreach ($c in $cases) {
        $got = $c[1]
        $okc = ($null -ne $got) -and ($got.exit -eq $c[2])
        # The exit code alone is not enough. Assert the refusal's OWN error text, so a
        # control cannot go green because some other mechanism started refusing the same
        # input. That is the difference between a control and a coincidence.
        if ($okc -and $c[3]) { $okc = ("$($got.error)" -match $c[3]) }
        if (-not $okc) { $failed++ }
        $detail = if ($okc) { "exit=$($got.exit)" } else { "WANT exit=$($c[2]) [$($c[3])] GOT exit=$($got.exit) $($got.error)" }
        Write-Host ("  {0}  {1}  {2}" -f $(if ($okc) { 'PASS' } else { 'FAIL' }), $c[0].PadRight($width), $detail)
    }
    Write-Host ''
    if ($failed) { Write-Host "GATE SELFTEST FAILED: $failed case(s). The gate is the bug, not the caller."; return 2 }
    Write-Host "GATE SELFTEST OK: $($cases.Count) refusals and grants all behaved."
    return 0
}

switch ($Action) {
    'New' {
        $r = New-Grant -Target $Target -Provenance $Provenance -OwnerWord $OwnerWord -CaseDir $CaseDir -Lane $Lane -Containment $Containment
        Out-Json $r
        exit ([int]$r.exit)
    }
    'Check' {
        # -Target is forwarded so a caller can be held to the file the grant names. Omitting it
        # keeps the previous behaviour, which is why the MCP server had to be fixed as well as
        # the gate: a gate that only binds a target when asked binds nothing by default.
        $r = Test-Grant -CaseDir $CaseDir -Capability $Capability -Invocation $Invocation -RequestedTarget $Target
        Out-Json $r
        exit ([int]$r.exit)
    }
    'Escalate' {
        $r = Invoke-Escalate -CaseDir $CaseDir -Capability $Capability -NewWord $OwnerWord -NewClass $EscalationClass
        Out-Json $r
        exit ([int]$r.exit)
    }
    'Selftest' {
        $code = Invoke-Selftest
        exit $code
    }
}
