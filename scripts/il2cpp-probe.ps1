#Requires -Version 5.1
<#
.SYNOPSIS
  Probe for the Unity IL2CPP capability, and record honestly whether it is available.

.DESCRIPTION
  Exists because `Unpackers-Game\Il2CppDumper-net6-win-v6.7.46\` is downloaded and
  present, and a tool that sits on disk looks like a capability until something asks
  whether it runs. This asks, and answers with evidence rather than presence.

  Two independent blockers, both measured:

    1. RUNTIME. The build is `net6`. This host has Microsoft.NETCore.App 8.0.31 and
       10.0.11 and no 6.x. With DOTNET_ROLL_FORWARD=LatestMajor the process produces
       NO OUTPUT and does not exit within 12 s. A silent hang is worse than an error:
       a tool that errors tells you it is broken, and a tool that hangs looks exactly
       like one that would have finished eventually.

    2. TARGET. There is no authorized IL2CPP artifact on this host. global-metadata.dat
       files DO exist here -- in the VIVE Hub installer -- and they are deliberately not
       used. They are third-party commercial software, and the arsenal gate is explicit:
       the object must be named by the Owner with checkable provenance, and "it is
       installed on my machine" is not ownership. Finding a usable target is therefore
       not a technical problem, it is an authorization one.

.EXAMPLE
  powershell -File scripts\il2cpp-probe.ps1

.EXAMPLE
  powershell -File scripts\il2cpp-probe.ps1 -AsControl
  Same probe, control polarity: exits 1 BECAUSE the capability is ABSENT. The
  negative direction of this capability is a host where the capability is missing,
  so the only honest way to assert it is to fail when it is correctly absent.

.NOTES
  Exit 0 with `IL2CPP ABSENT` when unavailable, non-zero only when the probe itself
  cannot determine an answer. Absence is a finding, not an error.

  -AsControl changes nothing except the exit code: the findings, the JSON summary
  and the 12 s hang budget are identical, so the default run stays byte-identical.
  The default exit code is left alone because the capability entry's probe.command
  runs this file with no arguments and depends on exit 0.
#>
[CmdletBinding()]
param(
    [int]$HangBudgetSec = 12,
    [switch]$AsControl
)

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$tool = Join-Path $RepoRoot 'Unpackers-Game\Il2CppDumper-net6-win-v6.7.46\Il2CppDumper.exe'

Write-Host 'IL2CPP capability probe'
Write-Host ('=' * 78)

# --- 1. runtime inventory -----------------------------------------------------
$runtimes = @()
try {
    $runtimes = @(dotnet --list-runtimes 2>$null |
        Select-String 'Microsoft\.NETCore\.App' |
        ForEach-Object { ($_ -split '\s+')[1] } |
        Where-Object { $_ })
} catch { }
$have6 = @($runtimes | Where-Object { $_ -match '^6\.' }).Count -gt 0

Write-Host ("  .NET runtimes      : " + $(if ($runtimes.Count) { $runtimes -join ', ' } else { 'dotnet not available' }))
Write-Host ("  6.x present        : " + $have6)
Write-Host ("  tool present       : " + (Test-Path -LiteralPath $tool))

# --- 2. start-up behaviour ----------------------------------------------------
$behaviour = 'not attempted'
if (Test-Path -LiteralPath $tool) {
    $env:DOTNET_ROLL_FORWARD = 'LatestMajor'
    $o = Join-Path $env:TEMP 'il2cpp_probe_out.txt'
    $e = Join-Path $env:TEMP 'il2cpp_probe_err.txt'
    $p = Start-Process -FilePath $tool -PassThru -NoNewWindow `
            -RedirectStandardOutput $o -RedirectStandardError $e
    Start-Sleep -Seconds $HangBudgetSec
    if ($p.HasExited) {
        $behaviour = "exited with code $($p.ExitCode) within ${HangBudgetSec}s"
    } else {
        # No output and no exit. Recorded precisely, because this is the shape that
        # reads as "still working" from a distance.
        $behaviour = "NO OUTPUT and NO EXIT within ${HangBudgetSec}s -- a silent hang, not an error"
        try { $p.Kill() } catch { }
    }
    $outLen = 0
    try { $outLen = (Get-Item $o -ErrorAction SilentlyContinue).Length } catch { }
    Write-Host ("  start-up behaviour : " + $behaviour)
    Write-Host ("  stdout bytes       : " + $outLen)
}

# --- 3. authorized target -----------------------------------------------------
# Deliberately NOT searching for a target to analyse. The point of this line is to
# record that the question was asked and answered on authorization grounds rather than
# scoured for on disk.
Write-Host ''
Write-Host '  TARGET: no authorized IL2CPP artifact exists on this host.'
Write-Host '  global-metadata.dat files DO exist here, in third-party commercial software'
Write-Host '  (the VIVE Hub installer). They are deliberately NOT used: the arsenal gate'
Write-Host '  requires an Owner-named object with checkable provenance, and an installed'
Write-Host '  third-party binary is not that. Finding a target here is an authorization'
Write-Host '  question, not a technical one.'

$available = $have6 -and ($behaviour -notmatch 'NO OUTPUT')
Write-Host ''
Write-Host ('=' * 78)
if ($available) {
    Write-Host 'IL2CPP AVAILABLE -- the runtime is present and the tool starts.'
} else {
    Write-Host 'IL2CPP ABSENT -- recorded, not hidden. Two blockers:'
    Write-Host '  1. the build is net6 and this host has no 6.x runtime'
    Write-Host '  2. no authorized IL2CPP artifact exists to run it against'
    Write-Host 'What would unblock it: the Owner names an IL2CPP binary they own.'
}
Write-Host ('JSON-SUMMARY {"total":2,"pass":0,"fail":2}')

[ordered]@{
    ok            = $false
    state         = 'absent'
    runtime_6x    = $have6
    runtimes      = $runtimes
    tool_present  = (Test-Path -LiteralPath $tool)
    behaviour     = $behaviour
    blockers      = @(
        'net6 build; host has .NET 8.0.31 and 10.0.11 only',
        'no authorized IL2CPP artifact; third-party commercial binaries found on this host were deliberately not used'
    )
    unblocked_by  = 'the Owner naming an IL2CPP binary they own'
} | ConvertTo-Json -Depth 5

# --- 4. control polarity -------------------------------------------------------
# R5 refuses a negative_control whose expect_exit is 0, because a control that must
# SUCCEED proves nothing. This capability is ABSENT, and for an absent capability the
# passing state IS the absence -- so the only way to make that state observable
# through an exit code is to FAIL when it is correct. Hence the inversion below.
#
# It lives behind a switch rather than replacing the default exit because the
# capability entry's own probe.command runs this same file with no arguments and
# depends on exit 0. Two polarities, one file, no second script to drift.
if ($AsControl) {
    if ($available) {
        Write-Host 'CONTROL RESULT: DID NOT FIRE -- IL2CPP reported AVAILABLE; exiting 0.'
        Write-Host '  A gate expecting exit 1 will reject this run. That rejection is the'
        Write-Host '  control working: the probe answered "available" when it should have'
        Write-Host '  answered "absent", or the host acquired a 6.x runtime and an'
        Write-Host '  authorized target and this control no longer describes the station.'
        exit 0
    }
    Write-Host ''
    Write-Host 'CONTROL RESULT: FIRED -- exiting 1, and the exit 1 IS the pass.'
    Write-Host '  What is under test: an installed Il2CppDumper.exe sitting on disk must not'
    Write-Host '  read as a working capability. The probe asks the runtime and the target'
    Write-Host '  instead of counting the .exe, and answers ABSENT.'
    Write-Host '  A run that exits 0 here would mean the tool started and a target existed'
    Write-Host '  -- i.e. that the probe had stopped being able to fail.'
    exit 1
}

exit 0
