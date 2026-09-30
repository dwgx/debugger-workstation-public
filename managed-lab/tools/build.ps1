#Requires -Version 5.1
<#
.SYNOPSIS
  Build every managed-lab sample.

.DESCRIPTION
  There is no gcc on this box and cl.exe is not on PATH, so the native half of
  m05 is built through a throwaway .bat that calls vcvars64.bat first. The exact
  commands are echoed, so the next agent does not have to rediscover them.

  Everything lands in managed-lab/out/<id>/ so nothing is written next to the
  sources. obj/ stays next to the .csproj (gitignored) because the SDK insists.

.EXAMPLE
  powershell -File managed-lab\tools\build.ps1
  powershell -File managed-lab\tools\build.ps1 -Only m01
#>
param(
    [string[]]$Only = @(),
    [string]$LabRoot = '',
    [string]$VcVars = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSScriptRoot
if (-not $LabRoot) { $LabRoot = $here }
$outRoot = Join-Path $LabRoot 'out'

$managed = [ordered]@{
    'm01' = 'm01-string-encryption'
    'm02' = 'm02-control-flow'
    'm03' = 'm03-resource-payload'
    'm04' = 'm04-binary-struct'
    'm05' = 'm05-pinvoke-bridge'
}

function Find-VcVars {
    $c = @()
    if ($VcVars) { $c += $VcVars }
    $c += @(
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
    )
    return ($c | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

$rows = @()
$failed = 0

foreach ($id in $managed.Keys) {
    if ($Only.Count -gt 0 -and ($Only -notcontains $id)) { continue }
    $proj = Join-Path $LabRoot "samples\$($managed[$id])\$id.csproj"
    $out = Join-Path $outRoot $id
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    if ($id -eq 'm05') {
        $c = Join-Path $LabRoot 'samples\m05-pinvoke-bridge\native\labnative.c'
        $dll = Join-Path $out 'labnative.dll'
        $vc = Find-VcVars
        if (-not $vc) { throw 'managed-lab: no vcvars64.bat found -- cannot build labnative.dll' }
        $bat = Join-Path ([System.IO.Path]::GetTempPath()) "managed-lab-$id-$([guid]::NewGuid().ToString('N').Substring(0,8)).bat"
        $cl = 'cl /nologo /LD /O1 /W3 /Fo:"{0}.obj" /Fe:"{1}" "{2}"' -f $out, $dll, $c
        @(
            '@echo off'
            "call `"$vc`" >nul 2>&1"
            'if errorlevel 1 exit /b 4'
            $cl
            'exit /b %ERRORLEVEL%'
        ) | Set-Content -LiteralPath $bat -Encoding ASCII
        Write-Host "managed-lab native: $cl" -ForegroundColor DarkGray
        & cmd.exe /c $bat | Out-Null
        $nrc = $LASTEXITCODE
        Remove-Item -LiteralPath $bat -Force -ErrorAction SilentlyContinue
        if ($nrc -ne 0) {
            $rows += [pscustomobject]@{ id = $id; step = 'cl (labnative.dll)'; ok = $false; detail = "cl exited $nrc" }
            $failed++
            continue
        }
        $rows += [pscustomobject]@{ id = $id; step = 'cl (labnative.dll)'; ok = $true; detail = $dll }
    }

    Write-Host "managed-lab: dotnet build $proj -> $out" -ForegroundColor DarkGray
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:DOTNET_NOLOGO = '1'
    $log = & dotnet build $proj -c Debug -o $out --nologo -v quiet 2>&1
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        $rows += [pscustomobject]@{ id = $id; step = 'dotnet build'; ok = $false; detail = (($log | Out-String) -replace '\s+', ' ').Trim() }
        $failed++
        continue
    }
    $warn = @($log | Select-String -Pattern 'warning').Count
    $rows += [pscustomobject]@{ id = $id; step = 'dotnet build'; ok = $true; detail = "exit 0, $warn warning line(s)" }
}

# m04 writes its artifact on first run; do it now so the solver has a file to work on
$m04 = Join-Path $outRoot 'm04\m04_struct.exe'
if (Test-Path -LiteralPath $m04) {
    $dat = Join-Path $outRoot 'm04\m04_records.dat'
    & $m04 $dat | Out-Null
    $rows += [pscustomobject]@{ id = 'm04'; step = 'write artifact'; ok = (Test-Path -LiteralPath $dat); detail = $dat }
    if (-not (Test-Path -LiteralPath $dat)) { $failed++ }
}

# m05 only proves itself by crossing the boundary: --selftest calls the native
# LabTransform through the DllImport, which also exercises the load resolver.
$m05 = Join-Path $outRoot 'm05\m05_bridge.exe'
if (Test-Path -LiteralPath $m05) {
    $probe = (& $m05 --selftest 'probe-bytes' 2>&1 | Out-String).Trim()
    $want = 'out     5a5f5f53515e1436463b20'
    $ok = $probe -match [regex]::Escape($want)
    $rows += [pscustomobject]@{ id = 'm05'; step = 'P/Invoke selftest'; ok = $ok; detail = (($probe -replace '\s+', ' ').Trim()) }
    if (-not $ok) { $failed++ }
}

$rows | Format-Table -AutoSize | Out-String | Write-Host
[ordered]@{ ok = ($failed -eq 0); failed = $failed; out = $outRoot; steps = $rows } | ConvertTo-Json -Depth 4 -Compress
exit $(if ($failed -eq 0) { 0 } else { 1 })
