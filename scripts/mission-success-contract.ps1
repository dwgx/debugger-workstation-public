#Requires -Version 5.1
# Explicit success contracts. This module never parses success_when prose or runs a tool.
# The only filesystem reads during evaluation are the pinned sidecar and the runner-owned
# Ghidra summary. A transport fixture can test predicates; the live mission has no adapter
# supplying that subject and therefore reports unsupported instead of assuming it passed.

$script:MissionContractModuleFile = $PSCommandPath

function Get-ContractTextSha([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-ContractObject($Value) {
    return ($null -ne $Value) -and (($Value -is [Collections.IDictionary]) -or ($Value -is [pscustomobject]))
}

function Test-ContractArray($Value) {
    return ($null -ne $Value) -and ($Value -is [Collections.IList]) -and ($Value -isnot [string])
}

function Test-ContractNumber($Value) {
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string]) { return $false }
    $numeric = $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
               $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
               $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]
    return $numeric -and (-not [double]::IsNaN([double]$Value)) -and (-not [double]::IsInfinity([double]$Value))
}

function Test-ContractInt32($Value) {
    # Validate the original JSON value before any parameter binder or numeric cast can
    # turn null, a boolean, a numeric string or a fraction into a successful exit code.
    return (Test-ContractNumber $Value) -and $Value -ge [int32]::MinValue -and
           $Value -le [int32]::MaxValue -and ([decimal]::Truncate([decimal]$Value) -eq [decimal]$Value)
}

function Get-ContractMember($Subject, [string]$Path) {
    $value = $Subject
    if (-not $Path) { return [pscustomobject]@{ exists = $true; value = $value } }
    foreach ($part in $Path.Split('.')) {
        if (-not (Test-ContractObject $value)) { return [pscustomobject]@{ exists = $false; value = $null } }
        $found = $false
        if ($value -is [Collections.IDictionary]) {
            foreach ($key in $value.Keys) {
                if ([string]$key -ceq $part) { $value = $value[$key]; $found = $true; break }
            }
        } else {
            foreach ($property in $value.PSObject.Properties) {
                if ($property.Name -ceq $part) { $value = $property.Value; $found = $true; break }
            }
        }
        if (-not $found) { return [pscustomobject]@{ exists = $false; value = $null } }
    }
    return [pscustomobject]@{ exists = $true; value = $value }
}

function Get-ContractCanonical($Value, [int]$Depth = 0) {
    if ($Depth -gt 64) { throw 'contract input exceeds depth 64' }
    if ($null -eq $Value) { return 'null;' }
    if ($Value -is [bool]) { if ($Value) { return 'true;' } else { return 'false;' } }
    if ($Value -is [string]) { return ('s' + $Value.Length + ':' + $Value) }
    if (Test-ContractNumber $Value) {
        $number = if ($Value -is [double] -or $Value -is [single]) { $Value.ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
                  else { $Value.ToString([Globalization.CultureInfo]::InvariantCulture) }
        return ('n' + $number + ';')
    }
    if (Test-ContractArray $Value) {
        $items = @(); foreach ($item in $Value) { $items += Get-ContractCanonical $item ($Depth + 1) }
        return ('a' + $Value.Count + '[' + ($items -join '') + ']')
    }
    if (Test-ContractObject $Value) {
        [string[]]$keys = @()
        if ($Value -is [Collections.IDictionary]) { $keys = @($Value.Keys | ForEach-Object { [string]$_ }) }
        else { $keys = @($Value.PSObject.Properties | ForEach-Object { $_.Name }) }
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $items = @()
        foreach ($key in $keys) {
            $itemValue = $null
            if ($Value -is [Collections.IDictionary]) { $itemValue = $Value[$key] }
            else { foreach ($property in $Value.PSObject.Properties) { if ($property.Name -ceq $key) { $itemValue = $property.Value; break } } }
            $items += (Get-ContractCanonical $key ($Depth + 1)) + (Get-ContractCanonical $itemValue ($Depth + 1))
        }
        return ('o' + $keys.Count + '{' + ($items -join '') + '}')
    }
    throw 'contract input is not a JSON value'
}

function Get-ContractValueSha($Value) { return Get-ContractTextSha (Get-ContractCanonical $Value) }

function Test-ContractPredicate($Predicate, $Subject) {
    $member = Get-ContractMember $Subject ([string]$Predicate.path)
    $value = $member.value
    switch -CaseSensitive ($Predicate.op) {
        'present' { return $member.exists -and ($null -ne $value) }
        'absent' { return -not $member.exists }
        'boolean' { return $member.exists -and ($value -is [bool]) }
        'boolean_equals' { return $member.exists -and ($value -is [bool]) -and ($value -eq $Predicate.value) }
        'string_equals' { return $member.exists -and ($value -is [string]) -and ([string]::Equals($value, $Predicate.value, [StringComparison]::Ordinal)) }
        'nonempty_string' { return $member.exists -and ($value -is [string]) -and ($value.Length -gt 0) }
        'array' { return $member.exists -and (Test-ContractArray $value) }
        'object' { return $member.exists -and (Test-ContractObject $value) }
        'integer' { return $member.exists -and (Test-ContractNumber $value) -and ([math]::Truncate([decimal]$value) -eq [decimal]$value) }
        'number_gt' { return $member.exists -and (Test-ContractNumber $value) -and ($value -gt $Predicate.value) }
        'number_gte' { return $member.exists -and (Test-ContractNumber $value) -and ($value -ge $Predicate.value) }
        'array_length_equals' {
            $other = Get-ContractMember $Subject $Predicate.other
            return $member.exists -and $other.exists -and (Test-ContractArray $value) -and
                   (Test-ContractArray $other.value) -and ($value.Count -eq $other.value.Count)
        }
        'array_objects' {
            if (-not $member.exists -or -not (Test-ContractArray $value) -or $value.Count -eq 0) { return $false }
            foreach ($item in $value) { if (-not (Test-ContractObject $item)) { return $false } }
            return $true
        }
        'fuzz_accounting' {
            $budget = (Get-ContractMember $Subject 'budget').value
            $executed = (Get-ContractMember $Subject 'executed').value
            if (-not (Test-ContractNumber $budget) -or $budget -le 0 -or [math]::Truncate([decimal]$budget) -ne $budget -or
                -not (Test-ContractNumber $executed) -or $executed -ne (2 * $budget)) { return $false }
            foreach ($name in @('reference', 'flawed')) {
                $tally = (Get-ContractMember $Subject $name).value
                if (-not (Test-ContractObject $tally)) { return $false }
                $values = if ($tally -is [Collections.IDictionary]) { @($tally.Values) }
                          else { @($tally.PSObject.Properties | ForEach-Object { $_.Value }) }
                if ($values.Count -eq 0) { return $false }
                $sum = [decimal]0
                foreach ($number in $values) {
                    if (-not (Test-ContractNumber $number) -or $number -lt 0 -or [math]::Truncate([decimal]$number) -ne $number) { return $false }
                    $sum += $number
                }
                if ($sum -ne $budget) { return $false }
            }
            return $true
        }
        default { throw 'unsupported contract operation' }
    }
}

function Read-MissionContractSet([string]$Path) {
    $result = [ordered]@{ valid = $false; path = $Path; sha256 = ''; module_sha256 = ''; document = $null; errors = @() }
    try {
        $result.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $result.module_sha256 = (Get-FileHash -LiteralPath $script:MissionContractModuleFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($doc.schema -cne 'mission-success-contracts/1' -or -not (Test-ContractInt32 $doc.version) -or $doc.version -ne 1 -or -not (Test-ContractArray $doc.contracts)) { throw 'invalid contract document schema' }
        foreach ($field in $doc.PSObject.Properties.Name) { if ($field -cnotin @('schema', 'version', 'note', 'contracts')) { throw 'unrecognised contract document field' } }
        $seen = @{}
        $ops = @('present', 'absent', 'boolean', 'boolean_equals', 'string_equals', 'nonempty_string', 'array', 'object', 'integer', 'number_gt', 'number_gte', 'array_length_equals', 'array_objects', 'fuzz_accounting')
        foreach ($entry in $doc.contracts) {
            foreach ($field in $entry.PSObject.Properties.Name) { if ($field -cnotin @('capability', 'section', 'declaration_sha256', 'invoke_binding', 'subject', 'predicates', 'unsupported_reason')) { throw 'unrecognised contract entry field' } }
            if ($entry.capability -isnot [string] -or -not $entry.capability -or $entry.section -cnotin @('invoke', 'envelope') -or
                $entry.declaration_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $entry.subject -cnotin @('stdout_json', 'transport_json', 'scratch_summary_json', 'unsupported') -or
                -not (Test-ContractArray $entry.predicates)) { throw 'invalid contract entry' }
            $key = $entry.capability + '/' + $entry.section
            if ($seen.ContainsKey($key)) { throw 'duplicate contract entry' }; $seen[$key] = $true
            if ($entry.subject -ceq 'unsupported') {
                if ($entry.unsupported_reason -isnot [string] -or -not $entry.unsupported_reason -or $entry.predicates.Count -ne 0) { throw 'invalid unsupported contract' }
            } elseif ($entry.predicates.Count -eq 0) { throw 'empty predicates cannot establish success' }
            if ($null -ne $entry.invoke_binding) {
                foreach ($field in $entry.invoke_binding.PSObject.Properties.Name) { if ($field -cnotin @('runner', 'argv', 'stdout')) { throw 'unrecognised invoke binding field' } }
                if ($entry.invoke_binding.runner -isnot [string] -or $entry.invoke_binding.stdout -cne 'json' -or -not (Test-ContractArray $entry.invoke_binding.argv)) { throw 'invalid invoke binding' }
                foreach ($arg in $entry.invoke_binding.argv) { if ($arg -isnot [string]) { throw 'invalid invoke argument' } }
            }
            foreach ($predicate in $entry.predicates) {
                if ($predicate.op -cnotin $ops -or $predicate.path -isnot [string]) { throw 'unsupported or malformed predicate' }
                if ($predicate.path -and $predicate.path -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$') { throw 'invalid member path' }
                $fields = @('op', 'path')
                if ($predicate.op -cin @('boolean_equals', 'string_equals', 'number_gt', 'number_gte')) { $fields += 'value' }
                if ($predicate.op -ceq 'array_length_equals') { $fields += 'other' }
                foreach ($field in $predicate.PSObject.Properties.Name) { if ($field -cnotin $fields) { throw 'unrecognised predicate field' } }
                if ($predicate.op -ceq 'boolean_equals' -and $predicate.value -isnot [bool]) { throw 'boolean predicate requires a boolean' }
                if ($predicate.op -ceq 'string_equals' -and $predicate.value -isnot [string]) { throw 'string predicate requires a string' }
                if ($predicate.op -cin @('number_gt', 'number_gte') -and -not (Test-ContractNumber $predicate.value)) { throw 'numeric predicate requires a number' }
                if ($predicate.op -ceq 'array_length_equals' -and ($predicate.other -isnot [string] -or -not $predicate.other)) { throw 'array comparison requires another path' }
            }
        }
        $result.document = $doc; $result.valid = $true
    } catch { $result.errors = @('contract document unavailable or invalid: ' + $_.Exception.Message) }
    return $result
}

function Test-ContractInvokeBinding($Entry, $Capability) {
    $actual = $Capability.invoke; $expected = $Entry.invoke_binding
    if ($null -eq $actual -or $null -eq $expected) { return ($null -eq $actual -and $null -eq $expected) }
    if ($actual.runner -isnot [string] -or $actual.stdout -isnot [string] -or -not (Test-ContractArray $actual.argv) -or
        $actual.runner -cne $expected.runner -or $actual.stdout -cne $expected.stdout -or @($actual.argv).Count -ne @($expected.argv).Count) { return $false }
    for ($i = 0; $i -lt @($actual.argv).Count; $i++) { if ($actual.argv[$i] -isnot [string] -or $actual.argv[$i] -cne $expected.argv[$i]) { return $false } }
    return $true
}

function Get-ContractArtifactSubject($Context, $Stdout) {
    $result = [ordered]@{ status = 'unsupported'; reason = 'runner_artifact_context_unavailable'; value = $null; sha256 = $null }
    if ($null -eq $Context) { return $result }
    try {
        if ($Context.fresh_directory -isnot [bool] -or -not $Context.fresh_directory -or $Context.absent_before -isnot [bool] -or -not $Context.absent_before) { throw 'artifact directory was not created empty for this round' }
        $root = [IO.Path]::GetFullPath([string]$Context.directory)
        $expected = [IO.Path]::GetFullPath((Join-Path $root 'summary.json'))
        $path = [IO.Path]::GetFullPath([string]$Context.path)
        $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
        if (-not [string]::Equals($path, $expected, $comparison)) { throw 'artifact is outside the runner-assigned location' }
        $dir = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (-not $dir.PSIsContainer -or $file.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'artifact location is not an ordinary directory and file' }
        # Checking only the leaf misses a junction/symlink higher in the supplied path.
        # Conservatively refuse every reparse ancestor up to the volume root. This is
        # an artifact consistency check, not an OS sandbox or a race-proof file handle.
        $ancestor = $dir
        while ($null -ne $ancestor) {
            if (-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'artifact path has a nonordinary or reparse ancestor' }
            $parent = $ancestor.Parent
            if ($null -eq $parent) { break }
            $ancestor = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
        }
        $value = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-ContractObject $value) -or -not (Test-ContractObject $Stdout)) { throw 'artifact and stdout must be JSON objects' }
        if ((Get-ContractValueSha $value) -cne (Get-ContractValueSha $Stdout)) { throw 'artifact and stdout describe different objects' }
        $result.value = $value
        $result.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $result.status = 'pass'; $result.reason = 'fresh_runner_artifact_matches_stdout'
    } catch { $result.status = 'fail'; $result.reason = 'invalid_runner_artifact: ' + $_.Exception.Message }
    return $result
}

function Test-MissionSuccessContract {
    param($Capability, $Subject, $ExitCode, $Contracts, $TransportSubject = $null, $ArtifactContext = $null)
    $contractInput = [ordered]@{ stdout = $Subject; transport = $TransportSubject; artifact_context = $ArtifactContext; exit_code = $ExitCode }
    $record = [ordered]@{ schema = 'mission-success-result/1'; capability = $Capability.id; contract_sha256 = $Contracts.sha256;
                         module_sha256 = $Contracts.module_sha256; input = $contractInput; input_sha256 = ''; process_ok = ((Test-ContractInt32 $ExitCode) -and ($ExitCode -eq 0));
                         ok = $false; complete = $false; sections = @(); errors = @() }
    try { $record.input_sha256 = Get-ContractValueSha $contractInput } catch { $record.errors += 'invalid_contract_input'; return $record }
    if (-not (Test-ContractInt32 $ExitCode)) { $record.errors += 'invalid_exit_code'; return $record }
    if (-not $Contracts.valid) { $record.errors += 'invalid_contract_set'; return $record }
    $artifact = $null
    foreach ($section in @('invoke', 'envelope')) {
        $holder = Get-ContractMember $Capability $section
        $declaration = Get-ContractMember $holder.value 'success_when'
        $contractMatches = @($Contracts.document.contracts | Where-Object { $_.capability -ceq $Capability.id -and $_.section -ceq $section })
        # Coverage is bidirectional: every current declaration needs a sidecar entry,
        # and every section expected by that entry must still be declared. Deleting
        # an envelope must never remove the obligation to obtain its transport.
        if (-not $declaration.exists -and $contractMatches.Count -eq 0) { continue }
        $row = [ordered]@{ section = $section; declaration_sha256 = ''; subject = ''; status = 'unsupported'; reason = ''; predicates = @() }
        $record.sections += $row
        if (-not $declaration.exists -or $declaration.value -isnot [string] -or -not $declaration.value) { $row.reason = 'missing_or_invalid_declaration'; continue }
        $row.declaration_sha256 = Get-ContractTextSha $declaration.value
        if ($contractMatches.Count -ne 1) { $row.reason = 'unknown_capability_or_section'; continue }
        $entry = $contractMatches[0]; $row.subject = $entry.subject
        if ($entry.declaration_sha256 -cne $row.declaration_sha256 -or -not (Test-ContractInvokeBinding $entry $Capability)) { $row.reason = 'contract_declaration_or_invoke_drift'; continue }
        $value = $null
        switch -CaseSensitive ($entry.subject) {
            'stdout_json' { $value = $Subject }
            'transport_json' {
                if ($null -eq $TransportSubject) { $row.reason = 'transport_subject_unavailable'; continue }
                $value = $TransportSubject
            }
            'scratch_summary_json' {
                if ($null -eq $artifact) { $artifact = Get-ContractArtifactSubject $ArtifactContext $Subject }
                if ($artifact.status -cne 'pass') { $row.status = $artifact.status; $row.reason = $artifact.reason; continue }
                $value = $artifact.value; $row['artifact_sha256'] = $artifact.sha256
            }
            'unsupported' { $row.reason = $entry.unsupported_reason; continue }
        }
        # Continue in a switch exits the switch, not the surrounding foreach.
        if ($row.reason) { continue }
        if (-not (Test-ContractObject $value)) { $row.status = 'fail'; $row.reason = 'subject_is_not_a_json_object'; continue }
        foreach ($predicate in $entry.predicates) {
            try { $pass = [bool](Test-ContractPredicate $predicate $value); $predicateError = '' }
            catch { $pass = $false; $predicateError = 'predicate_evaluation_error' }
            $row.predicates += [ordered]@{ op = $predicate.op; path = $predicate.path; pass = $pass; error = $predicateError }
        }
        if (@($row.predicates | Where-Object { -not $_.pass }).Count -eq 0 -and $row.predicates.Count -gt 0) {
            $row.status = 'pass'; $row.reason = 'all_predicates_passed'
        } else { $row.status = 'fail'; $row.reason = 'predicate_failed' }
    }
    if ($record.sections.Count -eq 0) { $record.errors += 'no_declared_success_contract' }
    $record.complete = ($record.sections.Count -gt 0) -and (@($record.sections | Where-Object { $_.status -ceq 'unsupported' }).Count -eq 0) -and ($record.errors.Count -eq 0)
    $record.ok = $record.process_ok -and $record.complete -and (@($record.sections | Where-Object { $_.status -cne 'pass' }).Count -eq 0)
    return $record
}

function Test-MissionContractRecord($Record, $Capability, $Contracts) {
    if ($null -eq $Record) { return [ordered]@{ ok = $false; reason = 'legacy_evidence_without_contract' } }
    try {
        $exitMember = Get-ContractMember $Record 'input.exit_code'
        if (-not $exitMember.exists -or -not (Test-ContractInt32 $exitMember.value)) {
            return [ordered]@{ ok = $false; reason = 'invalid_contract_exit_code' }
        }
        if ($Record.schema -cne 'mission-success-result/1' -or $Record.capability -cne $Capability.id -or $Record.ok -isnot [bool] -or -not $Record.ok -or
            $Record.complete -isnot [bool] -or -not $Record.complete -or $Record.contract_sha256 -cne $Contracts.sha256 -or
            $Record.module_sha256 -cne $Contracts.module_sha256 -or $Record.input_sha256 -cne (Get-ContractValueSha $Record.input)) {
            return [ordered]@{ ok = $false; reason = 'invalid_or_unbound_contract_record' }
        }
        $again = Test-MissionSuccessContract -Capability $Capability -Subject $Record.input.stdout -ExitCode $Record.input.exit_code -Contracts $Contracts -TransportSubject $Record.input.transport -ArtifactContext $Record.input.artifact_context
        if (-not $again.ok) { return [ordered]@{ ok = $false; reason = 'contract_recheck_failed' } }
        return [ordered]@{ ok = $true; reason = 'contract_rechecked' }
    } catch { return [ordered]@{ ok = $false; reason = 'invalid_contract_record' } }
}

function Get-MissionOutputFacts($Capability, $Subject) {
    if ($null -eq $Subject -or -not $Capability.invoke.fact_map) { return @() }
    $facts = @()
    foreach ($mapping in $Capability.invoke.fact_map.PSObject.Properties) {
        $source = $mapping.Name; $destination = $mapping.Value; $value = $null
        if ($source -ceq '$') { $value = $Subject }
        elseif ($null -ne $Subject.PSObject.Properties[$source]) { $value = $Subject.$source }
        if ($null -ne $value) { $facts += [ordered]@{ key = $destination; source_field = $source; value = $value } }
    }
    return $facts
}
