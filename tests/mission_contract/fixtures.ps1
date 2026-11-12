# Controlled JSON objects for predicate and gate tests. These are not provider results.
# An explicit transport object proves its predicates only; the live mission cannot obtain
# it from today's flattened IDA wrappers and must report unsupported there.

function New-MissionContractFixture([string]$CapabilityId, [string]$FixtureRoot) {
    $subject = $null; $transport = $null; $artifactContext = $null
    switch -CaseSensitive ($CapabilityId) {
        'native.ida.decompile' {
            $subject = [ordered]@{ ok = $true; code = 'int main(){return 0;}'; refs = @() }
            $transport = [ordered]@{ body = [ordered]@{ code = 'int main(){return 0;}' } }
        }
        'native.ida.list_functions' {
            $subject = [ordered]@{ ok = $true; count = 1; functions = @([ordered]@{ addr = '0x140001234'; name = 'main' }); named = @('main') }
            $transport = [ordered]@{ queries = @([ordered]@{ count = 2000 }); result = @([ordered]@{ data = @([ordered]@{ name = 'main' }) }) }
        }
        'web.js.cdp' { $subject = [ordered]@{ ok = $true; count = 1; nodes = @([ordered]@{ id = 'fixture-node' }) } }
        'crypto.jose.parse' { $subject = [ordered]@{ ok = $true; claims = [ordered]@{ sub = 'owned-fixture' } } }
        'net.pcap.analyse' { $subject = [ordered]@{ ok = $true; stdout = '1'; detail = 'one fixture query' } }
        'forensics.memory.artefact' { $subject = [ordered]@{ ok = $true; triage = [ordered]@{ pslist = @{}; psscan = @{}; netscan = @{}; malfind = @{}; handlescan = @{} } } }
        'managed.il.decompile' { $subject = [ordered]@{ ok = $true; code = 'IL_0000: ret'; method = 'Main' } }
        'mobile.apk.static' { $subject = [ordered]@{ manifest = [ordered]@{}; pinning = [ordered]@{} } }
        're.corpus.solve' { $subject = [ordered]@{ ok = $true; verdict = 'SOLVED-AND-ACCEPTED-BY-THE-BINARY'; answer = 'owned-fixture' } }
        'dynamic.win.frida' { $subject = [ordered]@{ ok = $true; module_base = '0x1000'; export_addr = '0x2000'; hook_attach = 'ACCEPTED' } }
        'fuzz.differential.parse' { $subject = [ordered]@{ ok = $true; budget = 60; executed = 120; reference = [ordered]@{ parsed = 60; rejected = 0 }; flawed = [ordered]@{ parsed = 59; rejected = 1 }; findings = @(); finding = [ordered]@{ found = $false } } }
        'native.ghidra.decompile' {
            if (-not $FixtureRoot) { throw 'Ghidra contract fixture requires an owned directory' }
            $directory = Join-Path $FixtureRoot ('summary-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
            $path = Join-Path $directory 'summary.json'
            $artifactContext = [ordered]@{ directory = $directory; path = $path; fresh_directory = $true; absent_before = -not (Test-Path -LiteralPath $path) }
            $subject = [ordered]@{ ok = $true; tool = 'ghidra'; program = 'owned-fixture'; functions = 1; decompiled = 1; outdir = $directory }
            $subject | ConvertTo-Json -Compress -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
        }
        'native.crosscompare.ghidra' { $subject = [ordered]@{ ok = $true; changed_total = 0; changed = @() } }
        'ops.skill.security' { $subject = [ordered]@{ execution_successful = $true; issues = @(); analysis_completeness = [ordered]@{} } }
        'dynamic.win.frida.intercept' { $subject = [ordered]@{ ok = $true; verdict = 'INTERCEPT-PROVEN'; runtime_hook_hit = [ordered]@{ count = 1 }; instrument_ordering = @('spawn', 'attach', 'load', 'resume') } }
        'native.pe.container' { $subject = [ordered]@{ ok = $true; image_base = '0x140000000'; aslr = $false; entry_rva = 4096; sections = @() } }
        'native.function.match' { $subject = [ordered]@{ ok = $true; matched = 0; identical_inputs = $false; pairs = @() } }
        'native.pe.packer' { $subject = [ordered]@{ ok = $true; packed = $false; die_verdict = 'not packed'; die_score = 0 } }
        'native.disasm.capstone' { $subject = [ordered]@{ ok = $true; count = 1; rip_operands = @(); insns = @() } }
        'native.pe.authenticode' { $subject = [ordered]@{ ok = $true; signed = $false; security_offset = 0 } }
        'native.behaviour.capa' { $subject = [ordered]@{ ok = $true; rules_matched = 0; matches = @() } }
        'native.signature.certverify' { $subject = [ordered]@{ ok = $true; cert_state = 'no_certificate'; der_parsed = $false } }
        'net.pcap.selfparse' { $subject = [ordered]@{ ok = $true; dns_queries = 0 } }
        'native.pe.hardening' { $subject = [ordered]@{ ok = $true; image = [ordered]@{ arch = 'cil'; bintype = 'pe' }; mitigations = $null } }
        'native.yara.triage' { $subject = [ordered]@{ matches = @() } }
        'native.ghidra.emulate' { $subject = [ordered]@{ verdict = 'MATCHES_GROUND_TRUTH' } }
        default { return $null }
    }
    # Match ConvertFrom-Json's production object/array types, including empty arrays.
    $subject = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $subject -Depth 24 -Compress)
    if ($null -ne $transport) { $transport = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $transport -Depth 24 -Compress) }
    return [ordered]@{ subject = $subject; transport = $transport; artifact_context = $artifactContext }
}

function Add-MissionContractFixtures($Evidence, $Registry, $Contracts, [string]$FixtureRoot) {
    foreach ($entry in @($Evidence)) {
        if ($entry.ok -eq $true -and $null -eq $entry.success_contract) {
            $cap = @($Registry.capabilities | Where-Object { $_.id -ceq $entry.capability }) | Select-Object -First 1
            $fixture = New-MissionContractFixture $entry.capability $FixtureRoot
            if ($null -ne $cap -and $null -ne $fixture) {
                $entry['success_contract'] = Test-MissionSuccessContract -Capability $cap -Subject $fixture.subject -ExitCode 0 -Contracts $Contracts -TransportSubject $fixture.transport -ArtifactContext $fixture.artifact_context
            }
        }
        Write-Output $entry
    }
}
