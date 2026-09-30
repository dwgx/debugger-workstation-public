#Requires -Version 5.1
<#
.SYNOPSIS
  Memory / process forensics lab -- synthetic image generation, plugin triage, triangulation,
  third-party correlation. Self-authored, in-tree, zero npm dependencies (Node >= 22 only).

.DESCRIPTION
  Wraps `forensics-lab/tools/*.mjs` with the station's CLI-Anything convention:
  JSON on stdout, transcripts on stderr, exit code from the underlying tool.

  loop         the whole proof in one command: build -> triage -> narrow -> verify -> decoy
               -> correlate -> four negative controls. Exit 0 = the loop closed.
  generate     build the synthetic target and print its hashes (no analysis)
  analyze      triage + triangulate the target and print the report
  correlate    carve the injected region and run DiE / YARA-X on it, plus the Volatility probe
  carve        write the carved region to disk and print its hash
  status       node + third-party tool readiness, and where the target will be written
  doctor       run the real station tools and report what they can and cannot do here

  THE TARGET IS SYNTHETIC. There is no acquisition path in this lab, by design. See
  forensics-lab/README.md "Honest limits". Never point this at a host you do not own, and
  never feed it a real image expecting a real analysis: `banners` refuses a file that is
  not a D12LAB container, on purpose.

.EXAMPLE
  powershell -File scripts\forensics-lab.ps1 loop
  powershell -File scripts\forensics-lab.ps1 status
  powershell -File scripts\forensics-lab.ps1 analyze -NodeArgs '--target C:\temp\d12\target'

.NOTES
  No acquisition, no driver, no kernel access, no network. Loopback-free and offline:
  the only outbound traffic this lab can cause is whatever the installed third-party
  tools do, and nothing here invokes them against anything but the generated fixture.
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @(),
    # Tool flags must come through here, not as bare --flags: PowerShell binds `--out` to
    # -OutVariable etc. before $Rest ever sees it. Same trap as web-reverse-lab.ps1.
    [string[]]$NodeArgs = @()
)
$ErrorActionPreference = 'Stop'
$Rest = @(@($Rest) + @($NodeArgs) | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ -ne '' })

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'forensics-lab'
$ToolsDir = Join-Path $LabRoot 'tools'
$Work = if ($env:D12_FORENSICS_WORK) { $env:D12_FORENSICS_WORK } else { Join-Path $env:TEMP 'd12-forensics-lab' }
$Target = Join-Path $Work 'target'
$Carved = Join-Path $Work 'carved'

$Tools = @{
    vol  = Join-Path $RepoRoot 'System-Forensics\volatility3\vol.exe'
    diec = Join-Path $RepoRoot 'Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe'
    yr   = Join-Path $RepoRoot 'Static-Reversing\YARA-X\yr.exe'
    capa = Join-Path $RepoRoot 'Static-Reversing\capa\capa.exe'
}

function Invoke-Node {
    <#
      Runs a lab tool and returns ONLY its exit code.

      The child's stdout is sent to the host rather than returned, because a PowerShell
      function returns everything on its output stream: letting the transcript fall
      through would make this function return an array of strings plus an int, and
      `exit (Invoke-Node ...)` would then exit with the FIRST CHARACTER of the report.
      That is a silent, spectacular failure and it is why the transcript is written with
      Out-Host explicitly.
    #>
    param([string[]]$ScriptArgs)
    $node = (Get-Command node -ErrorAction SilentlyContinue)
    if (-not $node) { throw 'node not found on PATH (Node >= 22 required)' }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $node.Source @ScriptArgs 2>&1 | ForEach-Object { Write-Host $_ }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    return $code
}

function Get-Status {
    $tools = [ordered]@{}
    foreach ($k in $Tools.Keys) {
        $p = $Tools[$k]
        $tools[$k] = [ordered]@{ path = $p.Replace($RepoRoot, '<root>'); present = (Test-Path -LiteralPath $p) }
    }
    $payload = Join-Path $LabRoot 'lab\payload\d12payload.dll'
    [ordered]@{
        ok       = $true
        tool     = 'forensics-lab'
        node     = (& node --version 2>$null)
        work     = $Work
        target   = $Target
        carved   = $Carved
        targetExists = (Test-Path -LiteralPath (Join-Path $Target 'manifest.json'))
        labFiles = @('lab/spec.mjs', 'lab/mkimage.mjs', 'lab/payload/d12payload.c', 'tools/triage.mjs', 'tools/analyze.mjs', 'tools/correlate.mjs', 'tools/loop.mjs') |
            ForEach-Object { [ordered]@{ file = $_.Replace('\', '/'); present = (Test-Path -LiteralPath (Join-Path $LabRoot $_)) } }
        payload = [ordered]@{
            built   = (Test-Path -LiteralPath $payload)
            producer = if (Test-Path -LiteralPath $payload) { 'msvc' } else { 'handbuilt (no compiler needed)' }
            note    = 'the lab falls back to lab/mkimage.mjs:buildMinimalPe when the DLL is absent'
        }
        thirdParty = $tools
        sources  = [ordered]@{
            MEM  = 'the synthetic image: pslist, psscan, malfind, netscan, handlescan'
            AM   = 'Amcache-shaped execution log'
            PF   = 'Prefetch-shaped .pf run history'
            SRUM = 'SRUM-shaped per-app resource usage'
            rule = "a finding needs >= 2 independent source groups"
        }
        honesty  = 'SYNTHETIC TARGET. Not a real host, not a real capture, not a real user. Real Volatility 3 is installed but cannot consume a synthetic image; `doctor` shows its actual refusal.'
    }
}

function Invoke-Doctor {
    # Run the real station tools and print what they actually say. No prose about
    # capability: the tool's own output is the evidence. Native tools here write to
    # stderr when they refuse, and with $ErrorActionPreference='Stop' that becomes a
    # terminating error — so preference is relaxed for the duration and the refusal is
    # captured as text, which is the whole point of the probe.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $image = Join-Path $Target 'd12-lab-image.raw'
    $out = [ordered]@{ ok = $true; target = $Target; tools = @() }
    if ((Test-Path -LiteralPath $Tools.vol) -and (Test-Path -LiteralPath $image)) {
        $bannersText = (& $Tools.vol -q -f $image banners 2>&1) -join "`n"
        $bannersExit = $LASTEXITCODE
        $pslistText = (& $Tools.vol -q -f $image windows.pslist 2>&1) -join "`n"
        $pslistExit = $LASTEXITCODE
        $pick = { param($t) ((($t -split "`n") | Where-Object { $_ -match 'Unsatisfied|A translation layer|A symbol table' } | Select-Object -First 3) -join ' / ').Trim() }
        $out.tools += [ordered]@{
            tool  = 'Volatility 3'
            path  = $Tools.vol.Replace($RepoRoot, '<root>')
            probes = @(
                [ordered]@{ plugin = 'banners'; exit = $bannersExit; verdict = 'needs no kernel: runs on any file'; detail = (& $pick $bannersText) }
                [ordered]@{ plugin = 'windows.pslist'; exit = $pslistExit; verdict = 'needs KDBG + a matching PDB, which only a real acquisition produces'; detail = (& $pick $pslistText) }
            )
        }
    }
    foreach ($k in @('diec', 'yr', 'capa')) {
        if (Test-Path -LiteralPath $Tools[$k]) {
            $ver = switch ($k) {
                'diec' { (& $Tools.diec --version 2>&1) -join ' ' }
                'yr'   { (& $Tools.yr --version 2>&1) -join ' ' }
                'capa' { (& $Tools.capa --version 2>&1) -join ' ' }
            }
            $out.tools += [ordered]@{ tool = $k; path = $Tools[$k].Replace($RepoRoot, '<root>'); version = "$ver".Trim() }
        }
    }
    $ErrorActionPreference = $prev
    $out | ConvertTo-Json -Depth 6
}

$action = $Action.ToLowerInvariant()
switch ($action) {
    'status'  { Get-Status | ConvertTo-Json -Depth 6; exit 0 }
    'doctor'  { Invoke-Doctor; exit 0 }
    'loop'    { exit (Invoke-Node @((Join-Path $ToolsDir 'loop.mjs'))) }
    'generate' { exit (Invoke-Node @((Join-Path $LabRoot 'lab\mkimage.mjs'), '--out', $Target)) }
    'analyze' { exit (Invoke-Node (@((Join-Path $ToolsDir 'analyze.mjs'), '--target', $Target) + $Rest)) }
    'correlate' { exit (Invoke-Node (@((Join-Path $ToolsDir 'correlate.mjs'), '--target', $Target, '--out', $Carved) + $Rest)) }
    'carve'   { exit (Invoke-Node (@((Join-Path $ToolsDir 'correlate.mjs'), '--target', $Target, '--out', $Carved) + $Rest)) }
    default {
        [ordered]@{ ok = $false; error = "unknown action $Action"; actions = @('status', 'doctor', 'loop', 'generate', 'analyze', 'correlate', 'carve') } | ConvertTo-Json
        exit 2
    }
}
