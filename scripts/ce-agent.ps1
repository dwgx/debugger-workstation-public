#Requires -Version 5.1
<#
.SYNOPSIS
  Cheat Engine has no headless CLI. This wrapper never stalls on a window.
  Default: report pipe/process status + x64dbg fallback.
  -StartCe starts CE minimized (still a window) so autorun ce_mcp_bridge.lua can open the pipe.
#>
param(
    [string]$InstallRoot = '',
    [switch]$StartCe,
    [int]$WaitMs = 15000
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$ce = Join-Path $InstallRoot 'Debuggers\Cheat Engine\cheatengine-x86_64.exe'
$pipe = '\\.\pipe\CE_MCP_Bridge_v99'
$proc = @(Get-Process -Name 'cheatengine-x86_64', 'cheatengine-i386' -ErrorAction SilentlyContinue)
$pipeUp = Test-Path -LiteralPath $pipe
$started = $false
if ($StartCe -and -not $pipeUp) {
    if (-not (Test-Path -LiteralPath $ce)) { throw "missing $ce" }
    Start-Process -FilePath $ce -WindowStyle Minimized | Out-Null
    $started = $true
    $deadline = [datetime]::UtcNow.AddMilliseconds($WaitMs)
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 400
        if (Test-Path -LiteralPath $pipe) { $pipeUp = $true; break }
    }
    $proc = @(Get-Process -Name 'cheatengine-x86_64', 'cheatengine-i386' -ErrorAction SilentlyContinue)
}
$ok = $pipeUp
[ordered]@{
    ok           = $ok
    tool         = 'cheatengine'
    process      = [bool]$proc.Count
    pids         = @($proc | ForEach-Object { $_.Id })
    pipe         = $pipeUp
    started      = $started
    fallback     = 'x64dbg'
    fallbackMcp  = 'router backend x64dbg (48 tools, no CE window)'
    liveMcp      = 'router backend cheatengine — needs this pipe (autorun ce_mcp_bridge.lua)'
    note         = if ($ok) { 'CE bridge up. Call router cheatengine.' } else { 'No CE pipe. Do not wait on GUI. Use x64dbg MCP, or pass -StartCe (minimized window).' }
} | ConvertTo-Json -Compress
if (-not $ok) { exit 2 }
exit 0
