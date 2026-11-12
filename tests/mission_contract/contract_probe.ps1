#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
if (Test-Path -LiteralPath $OutDir) { throw 'Probe output directory already exists; preserve previous evidence' }
New-Item -ItemType Directory -Path $OutDir | Out-Null
. (Join-Path $RepoRoot 'scripts/mission-success-contract.ps1')
. (Join-Path $PSScriptRoot 'fixtures.ps1')
$registry = Get-Content -LiteralPath (Join-Path $RepoRoot 'manifests/capabilities.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$contracts = Read-MissionContractSet (Join-Path $RepoRoot 'manifests/success-contracts.json')
$script:contractCases = @()
function Check([string]$Name, [scriptblock]$Body, $Expected) {
    try { $actual = & $Body; $errorText = ''; $pass = ($actual -ceq $Expected) }
    catch { $actual = $null; $errorText = $_.Exception.Message; $pass = $false }
    $script:contractCases += [ordered]@{ name = $Name; pass = [bool]$pass; expected = $Expected; actual = $actual; error = $errorText }
}
function Cap([string]$Id) { return @($registry.capabilities | Where-Object { $_.id -ceq $Id })[0] }
function Copy-Json($Value) { return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 64 -Compress) }
function Outcome($Capability, $Fixture, [int]$Code = 0) {
    return Test-MissionSuccessContract -Capability $Capability -Subject $Fixture.subject -ExitCode $Code -Contracts $contracts -TransportSubject $Fixture.transport -ArtifactContext $Fixture.artifact_context
}
function Set-Field($Subject, [string]$Path, $Value) {
    $parts = $Path.Split('.'); $cursor = $Subject
    for ($i = 0; $i -lt $parts.Count - 1; $i++) { $cursor = (Get-ContractMember $cursor $parts[$i]).value }
    $name = $parts[-1]
    $cursor | Add-Member -NotePropertyName $name -NotePropertyValue $Value -Force
}
Check 'sidecar_schema_valid' { $contracts.valid } $true
Check 'all_29_declarations_have_explicit_entries' { @($contracts.document.contracts).Count } 29

$coverage = @()
foreach ($capability in $registry.capabilities) {
    if (-not $capability.invoke -and -not $capability.envelope) { continue }
    $fixture = New-MissionContractFixture $capability.id $OutDir
    if ($null -eq $fixture) { continue }
    $expected = $capability.id -cnotin @('native.yara.triage', 'native.ghidra.emulate')
    Check ('positive/' + $capability.id) { (Outcome $capability $fixture).ok } $expected
    $outcome = Outcome $capability $fixture
    foreach ($section in $outcome.sections) {
        $coverage += [ordered]@{ capability = $capability.id; section = $section.section; fixture_status = $section.status;
                                live_subject_available = $section.subject -cnotin @('transport_json', 'unsupported'); subject = $section.subject }
    }
}

# Delete one required property or invalidate its type/value, one predicate at a time.
# The assertions inspect that section's predicate outcome, not an unrelated refusal.
foreach ($entry in $contracts.document.contracts) {
    $capability = Cap $entry.capability
    foreach ($predicate in $entry.predicates) {
        $fixture = New-MissionContractFixture $entry.capability $OutDir
        $subject = if ($entry.subject -ceq 'transport_json') { $fixture.transport } else { $fixture.subject }
        switch -CaseSensitive ($predicate.op) {
            'absent' { Set-Field $subject $predicate.path 'must-be-absent' }
            'present' { Set-Field $subject $predicate.path $null }
            'boolean' { Set-Field $subject $predicate.path 'false' }
            'boolean_equals' { Set-Field $subject $predicate.path (-not $predicate.value) }
            'string_equals' { Set-Field $subject $predicate.path ('wrong-' + $predicate.value) }
            'nonempty_string' { Set-Field $subject $predicate.path '' }
            'array' { Set-Field $subject $predicate.path 'not-an-array' }
            'object' { Set-Field $subject $predicate.path @() }
            'integer' { Set-Field $subject $predicate.path 1.5 }
            'number_gt' { Set-Field $subject $predicate.path $predicate.value }
            'number_gte' { Set-Field $subject $predicate.path ($predicate.value - 1) }
            'array_length_equals' { Set-Field $subject $predicate.path @() }
            'array_objects' { Set-Field $subject $predicate.path @($null) }
            'fuzz_accounting' { Set-Field $subject 'executed' 119 }
            default { throw 'Test lacks a negative for a machine predicate' }
        }
        if ($entry.subject -ceq 'scratch_summary_json') {
            $fixture.subject | ConvertTo-Json -Depth 24 -Compress | Set-Content -LiteralPath $fixture.artifact_context.path -Encoding UTF8
        }
        Check ('negative/' + $entry.capability + '/' + $entry.section + '/' + $predicate.op + '/' + $predicate.path) {
            $outcome = Outcome $capability $fixture
            $section = @($outcome.sections | Where-Object { $_.section -ceq $entry.section })[0]
            $row = @($section.predicates | Where-Object { $_.op -ceq $predicate.op -and $_.path -ceq $predicate.path })
            ($section.status -ceq 'fail') -and ($row.Count -eq 1) -and ($row[0].pass -eq $false)
        } $true
    }
}

foreach ($id in @('native.ida.decompile', 'native.ida.list_functions')) {
    Check ('live_transport_missing/' + $id) {
        $capability = Cap $id; $fixture = New-MissionContractFixture $id $OutDir
        $r = Test-MissionSuccessContract -Capability $capability -Subject $fixture.subject -ExitCode 0 -Contracts $contracts
        (-not $r.ok) -and (-not $r.complete) -and (@($r.sections | Where-Object { $_.reason -ceq 'transport_subject_unavailable' }).Count -eq 1)
    } $true
}
foreach ($typeCase in @(
    @{ name = 'boolean_string'; field = 'ok'; value = 'true' },
    @{ name = 'boolean_numeric'; field = 'ok'; value = 1 },
    @{ name = 'numeric_string'; field = 'count'; value = '1' },
    @{ name = 'array_string'; field = 'nodes'; value = '[]' }
)) {
    Check ('strict_type/' + $typeCase.name) {
        $capability = Cap 'web.js.cdp'; $fixture = New-MissionContractFixture $capability.id $OutDir
        Set-Field $fixture.subject $typeCase.field $typeCase.value
        (Outcome $capability $fixture).ok
    } $false
}
Check 'field_names_are_case_sensitive' {
    $fixture = New-MissionContractFixture 'web.js.cdp' $OutDir
    $fixture.subject.PSObject.Properties.Remove('ok'); Set-Field $fixture.subject 'OK' $true
    (Outcome (Cap 'web.js.cdp') $fixture).ok
} $false
Check 'scalar_json_is_not_an_analysis_object' {
    (Test-MissionSuccessContract -Capability (Cap 'native.pe.authenticode') -Subject $true -ExitCode 0 -Contracts $contracts).ok
} $false
Check 'nonzero_process_exit_cannot_pass' {
    (Outcome (Cap 'web.js.cdp') (New-MissionContractFixture 'web.js.cdp' $OutDir) 3).ok
} $false
foreach ($drift in @('unknown_capability', 'changed_declaration', 'changed_argv')) {
    Check ('binding/' + $drift) {
        $capability = Copy-Json (Cap 'web.js.cdp'); $fixture = New-MissionContractFixture 'web.js.cdp' $OutDir
        switch ($drift) {
            'unknown_capability' { $capability.id = 'unknown-fixture-capability' }
            'changed_declaration' { $capability.invoke.success_when += ' AND new requirement' }
            'changed_argv' { $capability.invoke.argv += '--changed-route' }
        }
        (Outcome $capability $fixture).ok
    } $false
}
Check 'unknown_operation_is_rejected_before_evaluation' {
    $doc = Copy-Json $contracts.document; $doc.contracts[0].predicates[0].op = 'trust_me'
    $file = Join-Path $OutDir 'unknown-op.json'; $doc | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $file -Encoding UTF8
    (Read-MissionContractSet $file).valid
} $false
Check 'unknown_predicate_field_is_rejected' {
    $doc = Copy-Json $contracts.document; $doc.contracts[0].predicates[0] | Add-Member -NotePropertyName unless -NotePropertyValue $true
    $file = Join-Path $OutDir 'unknown-field.json'; $doc | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $file -Encoding UTF8
    (Read-MissionContractSet $file).valid
} $false

foreach ($mode in @('missing', 'stale', 'outside', 'malformed', 'stdout_mismatch')) {
    Check ('artifact/' + $mode) {
        $fixture = New-MissionContractFixture 'native.ghidra.decompile' $OutDir
        switch ($mode) {
            'missing' { Remove-Item -LiteralPath $fixture.artifact_context.path }
            'stale' { $fixture.artifact_context.absent_before = $false }
            'outside' { $fixture.artifact_context.path = Join-Path $OutDir 'outside-summary.json' }
            'malformed' { Set-Content -LiteralPath $fixture.artifact_context.path -Value '{invalid' }
            'stdout_mismatch' { $fixture.subject.functions = 99 }
        }
        (Outcome (Cap 'native.ghidra.decompile') $fixture).ok
    } $false
}
Check 'record_recheck_accepts_real_evaluator_result' {
    $capability = Cap 'web.js.cdp'; $r = Outcome $capability (New-MissionContractFixture $capability.id $OutDir)
    (Test-MissionContractRecord $r $capability $contracts).ok
} $true
Check 'serialized_trace_record_preserves_semantic_identity' {
    $capability = Cap 'forensics.memory.artefact'
    $r = Outcome $capability (New-MissionContractFixture $capability.id $OutDir)
    $roundtrip = Copy-Json $r
    (Test-MissionContractRecord $roundtrip $capability $contracts).ok
} $true
Check 'record_recheck_rejects_pass_marker_without_input' {
    (Test-MissionContractRecord ([ordered]@{ ok = $true; complete = $true }) (Cap 'web.js.cdp') $contracts).ok
} $false
Check 'record_recheck_recomputes_predicates_even_after_input_hash_updated' {
    $capability = Cap 'web.js.cdp'; $r = Outcome $capability (New-MissionContractFixture $capability.id $OutDir)
    $r.input.stdout.count = 0; $r.input_sha256 = Get-ContractValueSha $r.input
    (Test-MissionContractRecord $r $capability $contracts).ok
} $false
Check 'legacy_record_is_explicitly_unverified' { (Test-MissionContractRecord $null (Cap 'web.js.cdp') $contracts).reason } 'legacy_evidence_without_contract'
Check 'literal_dotted_json_keys_contribute_to_input_hash' {
    (Get-ContractValueSha ([ordered]@{ 'a.b' = 1 })) -cne (Get-ContractValueSha ([ordered]@{ 'a.b' = 2 }))
} $true
Check 'root_fact_map_forwards_the_actual_summary_object' {
    $capability = Cap 'native.ghidra.decompile'; $fixture = New-MissionContractFixture $capability.id $OutDir
    $facts = @(Get-MissionOutputFacts $capability $fixture.subject)
    $rootFact = @($facts | Where-Object { $_.source_field -ceq '$' })
    ($rootFact.Count -eq 1) -and ((Get-ContractValueSha $rootFact[0].value) -ceq (Get-ContractValueSha $fixture.subject))
} $true
Check 'invalid_json_produces_no_root_fact' { @(Get-MissionOutputFacts (Cap 'native.ghidra.decompile') $null).Count } 0

# Regression cases confirmed by an independent reviewer against the first candidate.
# Keep the original controls above; these target distinct bypasses rather than changing
# the old expected values or making the fixtures more permissive.
foreach ($deleted in @('envelope_declaration', 'envelope_section', 'invoke_declaration')) {
    Check ('required_section_cannot_be_deleted/' + $deleted) {
        $capability = Copy-Json (Cap 'native.ida.decompile')
        $fixture = New-MissionContractFixture $capability.id $OutDir
        switch ($deleted) {
            'envelope_declaration' { $capability.envelope.PSObject.Properties.Remove('success_when') }
            'envelope_section' { $capability.PSObject.Properties.Remove('envelope') }
            'invoke_declaration' { $capability.invoke.PSObject.Properties.Remove('success_when') }
        }
        $r = Outcome $capability $fixture
        (-not $r.ok) -and (-not $r.complete) -and (@($r.sections | Where-Object { $_.reason -ceq 'missing_or_invalid_declaration' }).Count -eq 1)
    } $true
}
foreach ($exitCase in @(
    @{ name = 'null'; value = $null },
    @{ name = 'string'; value = '0' },
    @{ name = 'boolean'; value = $false },
    @{ name = 'fraction'; value = 0.49 },
    @{ name = 'outside_int32'; value = 2147483648 }
)) {
    Check ('exit_code_original_type/' + $exitCase.name) {
        $capability = Cap 'web.js.cdp'; $fixture = New-MissionContractFixture $capability.id $OutDir
        $r = Test-MissionSuccessContract -Capability $capability -Subject $fixture.subject -ExitCode $exitCase.value -Contracts $contracts
        (-not $r.ok) -and ($r.errors -contains 'invalid_exit_code')
    } $true
    Check ('record_exit_code_original_type/' + $exitCase.name) {
        $capability = Cap 'web.js.cdp'; $r = Outcome $capability (New-MissionContractFixture $capability.id $OutDir)
        $r.input.exit_code = $exitCase.value
        $r.input_sha256 = Get-ContractValueSha $r.input
        (Test-MissionContractRecord $r $capability $contracts).reason
    } 'invalid_contract_exit_code'
}
Check 'sidecar_version_string_is_not_a_number' {
    $doc = Copy-Json $contracts.document; $doc.version = '1'
    $file = Join-Path $OutDir 'string-version.json'
    $doc | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $file -Encoding UTF8
    (Read-MissionContractSet $file).valid
} $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Check 'ordinary_artifact_leaf_below_junction_is_rejected' {
        $physical = Join-Path $OutDir 'junction-physical'
        $junction = Join-Path $OutDir 'junction-parent'
        New-Item -ItemType Directory -Path $physical | Out-Null
        $fixture = New-MissionContractFixture 'native.ghidra.decompile' $physical
        $before = Outcome (Cap 'native.ghidra.decompile') $fixture
        try {
            New-Item -ItemType Junction -Path $junction -Target $physical -ErrorAction Stop | Out-Null
            $fixture.artifact_context.directory = Join-Path $junction (Split-Path -Leaf $fixture.artifact_context.directory)
            $fixture.artifact_context.path = Join-Path $fixture.artifact_context.directory 'summary.json'
            $after = Outcome (Cap 'native.ghidra.decompile') $fixture
            $before.ok -and (-not $after.ok) -and (@($after.sections | Where-Object { $_.reason -like '*reparse ancestor*' }).Count -eq 2)
        } finally {
            # Nonrecursive deletion removes only this owned junction, never its target.
            if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }
        }
    } $true
}

$report = [ordered]@{ schema = 'mission-contract-probe/1'; observed_utc = (Get-Date).ToUniversalTime().ToString('o');
    shell_version = $PSVersionTable.PSVersion.ToString(); contract_sha256 = $contracts.sha256; module_sha256 = $contracts.module_sha256;
    method = 'Controlled objects through the real explicit evaluator; no capability runner or third-party provider executed';
    coverage = $coverage; cases = $script:contractCases; passed = @($script:contractCases | Where-Object { $_.pass }).Count; count = $script:contractCases.Count;
    limitation = 'IDA transport objects are synthetic and do not establish a live adapter. Ghidra files are owned fixtures, not real decompilation output.' }
$report | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath (Join-Path $OutDir 'results.json') -Encoding UTF8
Write-Output ("contract probe: {0}/{1}; evidence: {2}" -f $report.passed, $report.count, (Join-Path $OutDir 'results.json'))
foreach ($case in $script:contractCases) { if (-not $case.pass) { Write-Output ('FAIL ' + $case.name + ' actual=' + $case.actual + ' error=' + $case.error) } }
if ($report.passed -ne $report.count -or $report.count -lt 60) { exit 1 }
exit 0
