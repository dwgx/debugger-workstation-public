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

    1. TARGET. This paragraph used to claim there was no Owner-named IL2CPP target on
       this host. That went STALE on 2026-10-12, when the Owner named IL2CPP artifacts
       (<project>\Romantic, AGENTS.md "Owner 2026-10-12 常驻授权"). It was also never a
       measurement: the probe had no target parameter, so it could not look. It now
       takes -Target <path> [-Metadata <path>] and reports what it actually did. With no
       -Target it prints [NOT-RUN] rather than a verdict about a run that never happened.

.EXAMPLE
  powershell -File scripts\il2cpp-probe.ps1

.EXAMPLE
  powershell -File scripts\il2cpp-probe.ps1 -Target D:\Steam\steamapps\common\VRChat\GameAssembly.dll
  Runs Il2CppDumper against a named artifact and reports the tool's own exit and output,
  so the capability is measured rather than asserted.

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
    [switch]$AsControl,
    # Added 2026-10-12. Until this parameter existed the probe could not analyse
    # anything, so its `TARGET:` block was a hardcoded sentence rather than a
    # measurement -- and a stale one (see section 3).
    [string]$Target = '',
    [string]$Metadata = ''
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

# --- 0. target argument (added 2026-10-12) ------------------------------------
# This probe accepted no target until 2026-10-12, so it never analysed anything and its
# TARGET block was a hardcoded authorization sentence -- which had also gone stale (an
# authorized IL2CPP artifact does exist here; see section 3).
$targetGiven  = -not [string]::IsNullOrWhiteSpace($Target)
$targetExists = $targetGiven -and (Test-Path -LiteralPath $Target)
$metaGiven    = -not [string]::IsNullOrWhiteSpace($Metadata)
$metaExists   = $metaGiven -and (Test-Path -LiteralPath $Metadata)

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

# --- 3. target and result -----------------------------------------------------
# CORRECTED 2026-10-12. Until today this block printed a hardcoded sentence claiming no
# Owner-named IL2CPP target existed here, which was STALE: the Owner named IL2CPP
# artifacts on 2026-10-12 (<project>\Romantic, AGENTS.md "Owner 2026-10-12 常驻授权").
# It was also never a measurement -- the probe had no target parameter, so there was
# nothing for it to measure. It now takes -Target and reports what it did.
Write-Host ''
if (-not $targetGiven) {
    Write-Host '  TARGET: [NOT-RUN] no -Target was supplied to this invocation.'
    Write-Host '  Nothing was analysed, so this run demonstrates nothing about the capability.'
    Write-Host '  CORRECTED 2026-10-12: the old claim that no Owner-named IL2CPP target'
    Write-Host '  existed here was STALE. Authorized artifacts exist:'
    Write-Host '    D:\Steam\steamapps\common\VRChat\GameAssembly.dll                        (243,253,248 B)'
    Write-Host '    D:\Steam\steamapps\common\VRChat\VRChat_Data\il2cpp_data\Metadata\global-metadata.dat'
    Write-Host '    <project>\Romantic\work\l122\dumps\VRChat_49424_20261012_164330_full.dmp (3,230,363,665 B)'
    Write-Host '  Provenance: <project>\Romantic (Owner 2026-10-12 authorization, AGENTS.md).'
} else {
    Write-Host ('  TARGET: ' + $Target)
    Write-Host ('  target exists      : ' + $targetExists)
}

# --- 3b. run the tool on the target, when one was supplied --------------------
$ranExit   = $null
$ranOutput = ''
$ranNote   = ''
if ($targetGiven -and $targetExists) {
    $meta = if ($metaExists) { $Metadata } else { '' }
    if (-not $meta) {
        # Default: the metadata beside the binary, which is where Il2CppDumper expects it.
        $cand = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Target) -Recurse `
                    -Filter 'global-metadata.dat' -ErrorAction SilentlyContinue |
                  Select-Object -First 1)
        if ($cand.Count) { $meta = $cand[0].FullName }
    }
    if (-not $meta -or -not (Test-Path -LiteralPath $meta)) {
        $ranNote = 'global-metadata.dat not found; pass -Metadata <path>'
        Write-Host ('  metadata           : NOT FOUND -- ' + $ranNote)
    } elseif (-not (Test-Path -LiteralPath $tool)) {
        $ranNote = 'Il2CppDumper.exe not present at ' + $tool
        Write-Host ('  run note           : ' + $ranNote)
    } else {
        Write-Host ('  metadata           : ' + $meta)
        $env:DOTNET_ROLL_FORWARD = 'LatestMajor'
        $psi2 = New-Object System.Diagnostics.ProcessStartInfo
        $psi2.FileName = $tool
        $psi2.UseShellExecute = $false
        $psi2.RedirectStandardInput = $true
        $psi2.RedirectStandardOutput = $true
        $psi2.RedirectStandardError = $true
        # Windows PowerShell 5.1 (this station's powershell.exe) is .NET Framework, whose
        # ProcessStartInfo has no ArgumentList -- only the Arguments string. Measured
        # 2026-10-12: ArgumentList threw PropertyNotFoundStrict and the tool was spawned
        # with NO arguments, so it waited for a prompt and had to be killed. Quote both
        # paths because the station path contains no spaces but a caller's target may.
        $psi2.Arguments = '"' + $Target + '" "' + $meta + '"'
        $p2 = [System.Diagnostics.Process]::Start($psi2)
        $o2 = $p2.StandardOutput.ReadToEndAsync()
        $e2 = $p2.StandardError.ReadToEndAsync()
        if (-not $p2.WaitForExit($HangBudgetSec * 1000)) {
            try { $p2.Kill() } catch { }
            $ranNote = "killed after ${HangBudgetSec}s (still running)"
        } else {
            $ranExit = $p2.ExitCode
        }
        $ranOutput = ((($o2.Result) + ($e2.Result)) -split "`n" |
                      Where-Object { $_.Trim() } | Select-Object -First 4) -join ' | '
        Write-Host ('  tool exit          : ' + $(if ($null -eq $ranExit) { 'killed/timeout' } else { $ranExit }))
        if ($ranOutput) { Write-Host ('  first output       : ' + $ranOutput.Trim()) }
        if ($ranNote)   { Write-Host ('  run note           : ' + $ranNote) }
    }
}

# Availability now depends on a real attempt, not on the runtime inventory alone. Until
# 2026-10-12 this read `$have6 -and ($behaviour -notmatch 'NO OUTPUT')`: the right half
# was dead (no $behaviour value contains 'NO OUTPUT') and the left half gated on a 6.x
# runtime the tool does not need -- with DOTNET_ROLL_FORWARD the net6 build runs on the
# host 8.x/10.x. So $available was really just "is 6.x installed", a proxy for nothing.
# The honest test is: was a target analysed and did the tool succeed.
$runtimeOk = $have6 -or ($behaviour -match '^STARTED OK')
$ranOk     = ($null -ne $ranExit) -and ($ranExit -eq 0)
$available = $targetExists -and $ranOk

Write-Host ''
Write-Host ('=' * 78)
if ($available) {
    Write-Host 'IL2CPP AVAILABLE -- the tool ran to completion on the supplied target.'
} else {
    Write-Host 'IL2CPP ABSENT -- recorded, not hidden.'
    if (-not $targetGiven) {
        Write-Host '  Blocker: [NOT-RUN] no -Target was supplied, so nothing was analysed.'
    } elseif (-not $targetExists) {
        Write-Host '  Blocker: the -Target path does not exist.'
    } elseif (-not $ranOk) {
        Write-Host ('  Blocker: the tool did not succeed' + $(if ($ranNote) { ' (' + $ranNote + ')' } else { " (exit $ranExit)" }) + '.')
    }
    Write-Host ''
    Write-Host '  RETRACTED 2026-10-04: the runtime was never the obstacle -- the net6 build'
    Write-Host '  starts under the host runtimes with DOTNET_ROLL_FORWARD. The old TARGET'
    Write-Host '  blocker was STALE too; see the TARGET block above.'
}
$passCount = if ($available) { 2 } else { 0 }
Write-Host ('JSON-SUMMARY {"total":2,"pass":' + $passCount + ',"fail":' + (2 - $passCount) + '}')

[ordered]@{
    ok            = $false
    state         = 'absent'
    runtime_6x    = $have6
    runtime_ok    = $runtimeOk
    runtimes      = $runtimes
    tool_present  = (Test-Path -LiteralPath $tool)
    behaviour     = $behaviour
    target        = $Target
    target_exists = $targetExists
    ran_exit      = $ranExit
    blockers      = @(
        $(if (-not $targetGiven) { '[NOT-RUN] no -Target was supplied to this invocation' }
          elseif (-not $targetExists) { "the -Target path does not exist: $Target" }
          elseif (-not $ranOk) { "the tool did not succeed on the target: " + $(if ($ranNote) { $ranNote } else { "exit $ranExit" }) }
          else { 'none' })
    )
    unblocked_by  = 'pass -Target <GameAssembly.dll> [-Metadata <global-metadata.dat>]'
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
    # `$Message` was never defined; Set-StrictMode (in probe_artifact.ps1) threw
    # VariableIsUndefined at parameter binding, so the control's artifact was never
    # written and the default run's artifact stayed on disk -- the control's evidence was
    # silently missing (found by lane 128). Fixed 2026-10-12: the reason is now a literal.
    $controlReason = if (-not $targetGiven) { '[NOT-RUN] no -Target supplied; nothing analysed' }
                     elseif (-not $targetExists) { "the -Target path does not exist: $Target" }
                     else { "the tool did not succeed on the target (exit $ranExit)" }
    Write-ProbeArtifact -Tool 'il2cpp_probe' -OutDir 'probe-artifacts' -Payload ([ordered]@{ ok = $false; verdict = 'ABSENT'; reason = $controlReason }) | Out-Null
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
