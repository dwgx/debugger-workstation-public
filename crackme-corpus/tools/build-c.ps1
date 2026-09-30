#Requires -Version 5.1
<#
.SYNOPSIS
  Build one C challenge of crackme-corpus with MSVC cl.exe.
.DESCRIPTION
  There is no gcc/g++/clang on this box and cl.exe is not on PATH. This helper
  locates vcvars64.bat, writes a throwaway .bat that calls it and then runs cl,
  and executes that .bat with cmd.exe. The exact command that worked is echoed
  so the next agent does not have to rediscover it.

  All outputs (obj, exe, pdb) are written into -OutDir so nothing lands next to
  the source and `crackme-corpus/out/` stays the single gitignored build root.
#>
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string[]]$ClFlags = @('/Od', '/W3'),
    [string]$VcVars = ''
)
$ErrorActionPreference = 'Stop'

$candidates = @()
if ($VcVars) { $candidates += $VcVars }
$candidates += @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
)
$found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $found) {
    Write-Error "crackme-corpus: no vcvars64.bat found. Tried:`n  $($candidates -join "`n  ")"
    exit 3
}
if (-not (Test-Path -LiteralPath $Source)) { Write-Error "crackme-corpus: missing source $Source"; exit 3 }
# `powershell -File x.ps1 -ClFlags '/Od','/W3'` binds the two array elements into a
# single string '/Od,/W3' and cl then reads it as '/O/' + junk. Split on commas so
# both the direct and the -File invocation produce the same flag list.
$ClFlags = @($ClFlags | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' })
$Source = (Resolve-Path -LiteralPath $Source).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outExe = Join-Path $OutDir "$Id.exe"
$obj = Join-Path $OutDir "$Id.obj"
$pdb = Join-Path $OutDir "$Id.pdb"

$bat = Join-Path ([System.IO.Path]::GetTempPath()) ("crackme-build-$Id-$([guid]::NewGuid().ToString('N').Substring(0,8)).bat")
$cl = @('cl', '/nologo') + $ClFlags + @(
    "/Fo:`"$obj`"", "/Fe:`"$outExe`"", "/Fd:`"$pdb`"", "`"$Source`"",
    '/link', '/SUBSYSTEM:CONSOLE', '/INCREMENTAL:NO'
) -join ' '
@(
    '@echo off',
    "call `"$found`" >nul 2>&1",
    'if errorlevel 1 exit /b 4',
    $cl,
    'exit /b %ERRORLEVEL%'
) | Set-Content -LiteralPath $bat -Encoding ASCII

Write-Host "crackme-corpus build: vcvars64 = $found" -ForegroundColor DarkGray
Write-Host "crackme-corpus build: $cl" -ForegroundColor DarkGray
& cmd.exe /c $bat
$rc = $LASTEXITCODE
Remove-Item -LiteralPath $bat -Force -ErrorAction SilentlyContinue
if ($rc -ne 0) { Write-Error "crackme-corpus: cl failed rc=$rc"; exit $rc }
[ordered]@{ ok = $true; id = $Id; exe = $outExe; obj = $obj; compiler = 'cl.exe (MSVC)'; vcvars = $found } |
    ConvertTo-Json -Compress
exit 0
