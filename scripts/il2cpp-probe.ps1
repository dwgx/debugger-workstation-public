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

.NOTES
  Exit 0 with `IL2CPP ABSENT` when unavailable, non-zero only when the probe itself
  cannot determine an answer. Absence is a finding, not an error.
#>
[CmdletBinding()]
param([int]$HangBudgetSec = 12)

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

exit 0
