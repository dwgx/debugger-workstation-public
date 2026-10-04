#Requires -Version 5.1
<#
.SYNOPSIS
  Probe for the Unity IL2CPP capability, and record honestly whether it is available.

.DESCRIPTION
  Exists because `Unpackers-Game\Il2CppDumper-net6-win-v6.7.46\` is downloaded and
  present, and a tool that sits on disk looks like a capability until something asks
  whether it runs. This asks, and answers with evidence rather than presence.

  ONE blocker, and the other one was retracted 2026-10-04.

    0. RETRACTED -- RUNTIME. This header used to claim a runtime blocker: "the build
       is net6, this host has 8.0.31 and 10.0.11 and no 6.x, and with
       DOTNET_ROLL_FORWARD the process produces NO OUTPUT and does not exit within 12 s".
       **That inference was wrong, and it was wrong because of how it was measured.** The
       old start-up check gave the process no stdin, so a tool blocked on its prompt read
       as a tool that would not launch. Measured directly on 2026-10-04: with no
       roll-forward the process exits 0x80008096 and prints "You must install or update
       .NET"; with DOTNET_ROLL_FORWARD it starts, stays alive, and waits for a target.
       The runtime was never the obstacle. The lesson is in the doctrine file: a probe
       that cannot tell FAILED-TO-START from WAITING-FOR-A-TARGET will keep inventing
       blockers, and an invented blocker is worse than none because it looks measured.

    1. TARGET. There is no authorized IL2CPP artifact on this host. global-metadata.dat
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


# The refusal is recorded on disk, and that is the point. This probe exists to answer ABSENT,
# and a refusal nobody can open later is indistinguishable from a probe that was never run.
# An artifact with ok = $false and the reason attached is a durable answer; an absent file is
# not an answer at all. Added 2026-10-05.
#
# AT SCRIPT SCOPE, immediately after the param block. The first attempt placed this between
# two halves of a multi-line Write-Host statement; it PARSED, and silently never ran, which is
# the worst of both -- a helper that looks loaded and is not.
. (Join-Path $PSScriptRoot 'probe_artifact.ps1')

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
#
# MEASURED 2026-10-04, and this block was WRONG until now. It used Start-Process with
# -RedirectStandardOutput to a FILE, waited, and reported "NO OUTPUT and NO EXIT -- a silent
# hang, not an error". From that it concluded blocker 1: "the build is net6 and this host has
# no 6.x runtime".
#
# Both halves of that are wrong, and the same measurement error produced both.
#
#   * `Start-Process` cannot redirect stdin. The tool therefore had no input source and, once
#     roll-forward had successfully started it under net10, it BLOCKED reading stdin. An
#     interactive tool waiting for a prompt and a tool that fails to start are indistinguishable
#     when you only look at "did it exit, and did the stdout file grow".
#   * Verified directly on 2026-10-04: with `DOTNET_ROLL_FORWARD=Major` the process stays alive
#     indefinitely and does NOT print the .NET error. Without it, it exits immediately with
#     -2147450730 (0x80008096) and prints "You must install or update .NET". So roll-forward
#     DOES work, and the runtime blocker was never real -- it was this block misreading a
#     prompt as a hang.
#
# The fix is to give the process a real stdin and a real conversation, and to report which of
# three states it is in: FAILED TO START / STARTED AND WAITING FOR A TARGET / EXITED. A probe
# that cannot tell those apart will keep inventing blockers, and an invented blocker is worse
# than none because it looks measured.
$behaviour = 'not attempted'
if (Test-Path -LiteralPath $tool) {
    $env:DOTNET_ROLL_FORWARD = 'LatestMajor'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $tool
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    # Give it a conversation rather than silence: a newline answers a bare prompt, and a path
    # would be answered by a run we are not authorised to do. Both are sent as INPUT, never as
    # an argument, so nothing is analysed.
    Start-Sleep -Seconds 4
    try { $proc.StandardInput.WriteLine('') } catch { }
    Start-Sleep -Seconds 4
    if ($proc.HasExited) {
        $behaviour = "STARTED and EXITED with code $($proc.ExitCode)"
    } else {
        $behaviour = ("STARTED OK and is WAITING FOR A TARGET -- it did not fail to launch. " +
                      "Alive for ${HangBudgetSec}s+ with stdin answered; this is an interactive tool, not a hang.")
        try { $proc.Kill() } catch { }
    }
    Write-Host ("  start-up behaviour : " + $behaviour)
    $outLen = 0
    try { $outLen = ($stdoutTask.Result).Length } catch { }
    Write-Host ("  stdout bytes       : " + $outLen)
    if ($outLen -gt 0) {
        # Quoted, and only the first lines: the tool may echo a path or a version banner, and
        # an echo is the receipt that it really ran.
        $first = (($stdoutTask.Result -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 4) -join ' | '
        Write-Host ("  first output       : " + $first.Trim())
    }
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
    Write-Host 'IL2CPP ABSENT -- recorded, not hidden. ONE blocker, not two:'
    Write-Host '  1. no authorized IL2CPP artifact exists to run it against'
    Write-Host ''
    Write-Host '  RETRACTED 2026-10-04: the second blocker this probe used to report --'
    Write-Host '  "the build is net6 and this host has no 6.x runtime" -- WAS NEVER REAL.'
    Write-Host '  It came from measuring start-up with no stdin, so a tool blocked on a'
    Write-Host '  prompt read as a tool that would not launch. Measured directly: without'
    Write-Host '  roll-forward the process exits 0x80008096 with "You must install or update'
    Write-Host '  .NET"; with DOTNET_ROLL_FORWARD it starts and waits for a target. The'
    Write-Host '  runtime was never the obstacle.'
    Write-Host ''
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
    Write-ProbeArtifact -Tool 'il2cpp_probe' -OutDir 'probe-artifacts' -Payload ([ordered]@{ ok = $false; verdict = 'ABSENT'; reason = $Message }) | Out-Null
    exit 1
}

# `ok` here is about the PROBE, not the capability. This probe exits 0 when it correctly
# reports that IL2CPP is ABSENT -- a successful measurement of an absence. The first
# attempt wrote verdict = 'PRESENT' on this path, which is the confident-wrong shape this
# project exists to reject: the artifact would have said a capability is available while
# the registry says `absent`. The verdict field now carries the capability's state and
# `ok` carries whether the probe itself worked.
$capVerdict = if ($available) { 'present' } else { 'absent' }
Write-ProbeArtifact -Tool 'il2cpp_probe' -OutDir 'probe-artifacts' -Payload ([ordered]@{
    ok              = $true          # the PROBE ran and answered; not a capability claim
    capability      = 'native.il2cpp.symbols'
    verdict         = $capVerdict    # the CAPABILITY's state
    tool_on_disk    = (Test-Path -LiteralPath $tool)
    runtime_6x      = $have6
    why             = 'the probe asks the runtime and the target, not whether the .exe is on disk'
}) | Out-Null
exit 0
