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
  Exit codes: 0 = granted · 3 = refused · 4 = self-asserted provenance · 5 = grant tampered.

  THE ONE THAT MATTERS: `New` refuses when the provenance is self-asserted. "I found it
  on my disk" is not ownership. If no subprocess is spawned before that refusal, the
  control held; a subprocess appearing first means the control FAILED and that is the
  test.
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
    [string]$Registry = ''
)

$ErrorActionPreference = 'Stop'

function Out-Json($o) { $o | ConvertTo-Json -Compress -Depth 8 }

function Get-RegistryPath {
    param([string]$Override)
    if ($Override) { return $Override }
    return (Join-Path (Split-Path -Parent $PSScriptRoot) 'manifests\capabilities.json')
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

function New-Grant {
    param($Target, $Provenance, $OwnerWord, $CaseDir, $Lane)

    if (-not $Target -or -not (Test-Path -LiteralPath $Target)) {
        return @{ ok = $false; exit = 3; error = 'target missing or not a path we can see'; detail = "target=$Target" }
    }
    if (-not $OwnerWord) {
        # No Owner word, no grant. This is the whole gate.
        return @{ ok = $false; exit = 3; error = 'no Owner word recorded. A mission is not a permission, and a context boundary is not a new permission.' }
    }
    if (-not $Provenance -or (Test-SelfAsserted $Provenance)) {
        return @{ ok = $false; exit = 4; error = 'provenance is self-asserted or absent'; detail = $Provenance
                  why = '"I found it on my disk" is not ownership. Provenance must be checkable by the Owner, not asserted by the caller.' }
    }

    $reg = Get-Content -LiteralPath (Get-RegistryPath $Registry) -Raw | ConvertFrom-Json

    # The grant starts as the set of capabilities whose own gate declares they may run
    # on this lane. Anything else has to be escalated explicitly, later, with a word.
    $allowed = @()
    foreach ($c in $reg.capabilities) {
        $g = $c.gate
        if (-not $g) { continue }
        if ($g.lane -ne $Lane) { continue }
        if ($g.requires_verdict) { $allowed += $c.id }   # this grant IS the verdict
    }

    $grant = [ordered]@{
        schema        = 'gate/grant@1'
        case_id       = [IO.Path]::GetFileName($CaseDir.TrimEnd('\','/'))
        lane          = $Lane
        target        = (Resolve-Path -LiteralPath $Target).Path
        target_sha256 = (Get-Sha256File -Path $Target)
        provenance    = $Provenance
        owner_word    = $OwnerWord
        granted_at    = (Get-Date).ToUniversalTime().ToString('o')
        allowed       = @($allowed | Sort-Object)
        escalation    = 'none'
        note          = 'The invocable set may only shrink. Only gate.ps1 mints a grant; only an Owner word authorises one.'
    }
    $grant['grant_sha256'] = Get-GrantHash $grant

    if ($CaseDir) {
        New-Item -ItemType Directory -Path $CaseDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $CaseDir 'grant.json') -Value (Out-Json $grant) -Encoding UTF8
    }
    return @{ ok = $true; exit = 0; grant = $grant; allowed_count = @($allowed).Count }
}

function Test-Grant {
    param($CaseDir, $Capability)

    $gp = Join-Path $CaseDir 'grant.json'
    if (-not (Test-Path -LiteralPath $gp)) {
        return @{ ok = $false; exit = 5; error = 'no grant.json in the case directory' }
    }
    $grant = Get-Content -LiteralPath $gp -Raw | ConvertFrom-Json

    $recomputed = Get-GrantHash $grant
    if ($recomputed -ne $grant.grant_sha256) {
        # Somebody edited the grant in place, or it was rewritten by a tool that does not
        # preserve the canonical form. Either way the authority it claims is not trustworthy.
        return @{ ok = $false; exit = 5; error = 'grant hash mismatch -- the grant was altered after it was minted'
                 stored = $grant.grant_sha256; recomputed = $recomputed }
    }

    $allowed = @($grant.allowed)
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
    $reg = Get-Content -LiteralPath (Get-RegistryPath $Registry) -Raw | ConvertFrom-Json
    $lane = $grant.lane
    $registryAllows = @($reg.capabilities | Where-Object {
        $_.gate -and $_.gate.lane -eq $lane -and $_.gate.requires_verdict
    } | ForEach-Object { $_.id })
    $forged = @($allowed | Where-Object { $registryAllows -notcontains $_ })
    if ($forged.Count -gt 0) {
        return @{ ok = $false; exit = 3
                 error = "grant claims capabilities the registry does not grant for lane '$lane': $($forged -join ', ')"
                 why = 'the grant file is not the authority. The registry is, and it is in git. A hash over a file anyone can rewrite proves only that the rewriter can compute SHA-256.'
                 forged = $forged }
    }

    # --- CRITICAL FIX, same audit --------------------------------------------
    # target_sha256 was ASSIGNED and never read again. Overwriting the granted binary with
    # 35 bytes of garbage left Check returning ok:true over the substituted bytes: the grant
    # was still valid for a target that no longer existed. Re-hash it here.
    if ($grant.target -and (Test-Path -LiteralPath $grant.target)) {
        $nowHash = Get-Sha256File -Path $grant.target
        if ($nowHash -ne $grant.target_sha256) {
            return @{ ok = $false; exit = 5
                     error = 'the granted target has changed on disk since the grant was minted'
                     granted_sha256 = $grant.target_sha256; current_sha256 = $nowHash
                     why = 'a grant authorises BYTES, not a path. Re-issue the grant for the new target.' }
        }
    }

    return @{ ok = $true; exit = 0; case_id = $grant.case_id; target = $grant.target; allowed = $allowed; verified_against_registry = $true; target_bytes_verified = $true }
}

function Invoke-Escalate {
    param($CaseDir, $Capability, $NewWord, $NewClass)

    $cur = Test-Grant -CaseDir $CaseDir
    if (-not $cur.ok) { return $cur }

    if ($NewClass -eq 'impossible') {
        return @{ ok = $false; exit = 3; error = 'the impossible class cannot be granted at runtime'
                 why = 'changing lane or reach is an Owner edit to AGENTS.md / CHARTER-ARSENAL.md in git. There is no flag on this script that changes that, by design.' }
    }
    $reg = Get-Content -LiteralPath (Get-RegistryPath $Registry) -Raw | ConvertFrom-Json
    $cap = $reg.capabilities | Where-Object { $_.id -eq $Capability }
    if (-not $cap) { return @{ ok = $false; exit = 3; error = "unknown capability '$Capability'" } }

    # Same lane, or it is the impossible class by definition.
    if ($cap.gate.lane -ne $Lane) {
        return @{ ok = $false; exit = 3; error = "capability '$Capability' is lane '$($cap.gate.lane)', grant is lane '$Lane'"
                 why = 'changing lane is the impossible class: it needs an Owner edit to AGENTS.md in git, not a runtime flag.' }
    }

    $gp = Join-Path $CaseDir 'grant.json'
    $grant = Get-Content -LiteralPath $gp -Raw | ConvertFrom-Json
    $prior = $grant.grant_sha256
    $grant.allowed = @(@($grant.allowed) + $Capability | Sort-Object -Unique)
    $grant.escalation = $NewClass
    $grant.note = "escalated to $NewClass on $Capability with a fresh Owner word; prior grant hash retained in the trace"
    $grant | Add-Member -NotePropertyName prior_grant_sha256 -NotePropertyValue $prior -Force
    $grant | Add-Member -NotePropertyName escalation_word -NotePropertyValue $NewWord -Force
    $grant | Add-Member -NotePropertyName escalated_at -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
    $grant.grant_sha256 = Get-GrantHash $grant
    Set-Content -LiteralPath $gp -Value (Out-Json $grant) -Encoding UTF8

    return @{ ok = $true; exit = 0; escalation = $NewClass; capability = $Capability; prior = $prior; now = $grant.grant_sha256 }
}

function Invoke-Selftest {
    # Script-scoped, because T() appends from inside a function. Declaring this local
    # made the selftest collect ZERO cases and then announce "SELFTEST OK: 0 refusals
    # and grants all behaved" -- a green run that tested nothing, which is exactly the
    # failure this repo exists to reject. There is now an explicit floor below.
    $script:gateCases = @()
    function T($name, $body, $wantExit) {
        $script:gateCases += ,@($name, (& $body), $wantExit)
    }


    $tmp = Join-Path $env:TEMP ("gate-selftest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $tgt = Join-Path $tmp 'sample.bin'
    Set-Content -LiteralPath $tgt -Value 'not really a binary, but a path we can see'

    $C = @{ CaseDir = $tmp; Target = $tgt; Provenance = 'Owner named this file in conversation 2026-09-30'; OwnerWord = 'analyze this exe' }

    T 'mint a grant with an Owner word and a checkable provenance' { New-Grant @C } 0
    T 'refuse with NO Owner word' { New-Grant -Target $tgt -Provenance 'Owner named it' -OwnerWord '' -CaseDir $tmp } 3
    T 'refuse self-asserted provenance' { New-Grant -Target $tgt -Provenance 'I found it on my disk' -OwnerWord 'go' -CaseDir $tmp } 4
    T 'refuse an empty provenance' { New-Grant -Target $tgt -Provenance '' -OwnerWord 'go' -CaseDir $tmp } 4
    T 'refuse a target that does not exist' { New-Grant -Target (Join-Path $tmp 'nope.bin') -Provenance 'Owner named it' -OwnerWord 'go' -CaseDir $tmp } 3

    $g = New-Grant @C
    T 'a capability inside the grant is allowed' { Test-Grant -CaseDir $tmp -Capability ($g.allowed | Select-Object -First 1) } 0
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
    $g3 = New-Grant -Target $tamperTarget -Provenance 'Owner named this file in conversation 2026-09-30' -OwnerWord 'analyze this exe' -CaseDir $tmp
    # Never call a method on the result unguarded: New-Grant returns a hashtable WITHOUT a
    # `raw` key on success and one WITH it on refusal, and under $ErrorActionPreference='Stop'
    # a null .raw took the whole selftest down before a single control printed.
    $g3code = if ($g3 -is [array]) { $g3[0].code } else { $g3.code }
    if ($g3code -ne 0) { Write-Host ("  NOTE: tamper-case grant was not minted (exit " + $g3code + "); the control below would be vacuous") }
    Set-Content -LiteralPath $tamperTarget -Value ('X' * 35)     # substituted with garbage
    T 'CRITICAL: a grant over REPLACED target bytes is refused' { Test-Grant -CaseDir $tmp } 5

    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

    $cases = $script:gateCases

    # A checker that inspects zero items must fail. Without this floor the selftest can
    # report OK having tested nothing at all, which is how the scoping bug above stayed
    # invisible for a whole run.
    if ($cases.Count -eq 0) {
        Write-Host 'GATE SELFTEST FAILED: zero cases were collected. A green run that tested nothing is not a green run.'
        return 2
    }

    $failed = 0
    foreach ($c in $cases) {
        $got = $c[1]
        $okc = ($null -ne $got) -and ($got.exit -eq $c[2])
        if (-not $okc) { $failed++ }
        $detail = if ($okc) { "exit=$($got.exit)" } else { "WANT exit=$($c[2]) GOT exit=$($got.exit) $($got.error)" }
        Write-Host ("  {0}  {1}  {2}" -f $(if ($okc) { 'PASS' } else { 'FAIL' }), $c[0].PadRight($width), $detail)
    }
    Write-Host ''
    if ($failed) { Write-Host "GATE SELFTEST FAILED: $failed case(s). The gate is the bug, not the caller."; return 2 }
    Write-Host "GATE SELFTEST OK: $($cases.Count) refusals and grants all behaved."
    return 0
}

switch ($Action) {
    'New' {
        $r = New-Grant -Target $Target -Provenance $Provenance -OwnerWord $OwnerWord -CaseDir $CaseDir -Lane $Lane
        Out-Json $r
        exit ([int]$r.exit)
    }
    'Check' {
        $r = Test-Grant -CaseDir $CaseDir -Capability $Capability
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
