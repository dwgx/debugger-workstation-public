#Requires -Version 5.1
<#
.SYNOPSIS
  Build the two native variants of the headless-lab sample.

.DESCRIPTION
  There is no gcc on this box and cl.exe is not on PATH, so each build goes
  through a throwaway .bat that calls vcvars64.bat first. The exact command is
  echoed so the next agent does not have to rediscover it.

  core_v1.dll and core_v2.dll differ in one compile-time constant. `classify` must
  come out byte-identical and `checksum` must not; that difference is the ground
  truth headless-lab/tools/loop.mjs holds the cross-binary diff to.

.EXAMPLE
  powershell -File headless-lab\tools\build.ps1
#>
param(
    [string]$LabRoot = '',
    [string]$VcVars = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSScriptRoot
if (-not $LabRoot) { $LabRoot = $here }
$out = Join-Path $LabRoot 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$src = Join-Path $LabRoot 'native\core.c'

$vc = @()
if ($VcVars) { $vc += $VcVars }
$vc += @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
)
$found = $vc | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $found) { Write-Error 'headless-lab: no vcvars64.bat found'; exit 3 }

$rows = @()
$failed = 0
$variants = @(
    @{ id = 'core_v1'; dll = 'core_v1.dll'; def = '' },
    @{ id = 'core_v2'; dll = 'core_v2.dll'; def = '/DLAB_MASK=0x3C' }
)

foreach ($v in $variants) {
    $dll = Join-Path $out $v.dll
    $obj = Join-Path $out "$($v.id).obj"
    $bat = Join-Path ([System.IO.Path]::GetTempPath()) "headless-lab-$($v.id)-$([guid]::NewGuid().ToString('N').Substring(0,8)).bat"
    $cl = 'cl /nologo /LD /O1 /W3 {0} /Fo:"{1}" /Fe:"{2}" "{3}"' -f $v.def, $obj, $dll, $src
    @(
        '@echo off'
        "call `"$found`" >nul 2>&1"
        'if errorlevel 1 exit /b 4'
        $cl
        'exit /b %ERRORLEVEL%'
    ) | Set-Content -LiteralPath $bat -Encoding ASCII
    Write-Host "headless-lab: $cl" -ForegroundColor DarkGray
    & cmd.exe /c $bat | Out-Null
    $rc = $LASTEXITCODE
    Remove-Item -LiteralPath $bat -Force -ErrorAction SilentlyContinue
    $ok = ($rc -eq 0 -and (Test-Path -LiteralPath $dll))
    $rows += [pscustomobject]@{ id = $v.id; ok = $ok; detail = if ($ok) { "$dll ($((Get-Item $dll).Length) bytes)" } else { "cl exited $rc" } }
    if (-not $ok) { $failed++ }
}

$rows | Format-Table -AutoSize | Out-String | Write-Host
[ordered]@{ ok = ($failed -eq 0); failed = $failed; out = $out } | ConvertTo-Json -Compress
exit $(if ($failed -eq 0) { 0 } else { 1 })
