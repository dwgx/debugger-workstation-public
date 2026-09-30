#Requires -Version 5.1
<#
.SYNOPSIS
  Agent Ghidra without GUI. Default: import + analyze + export C/JSON.
  -Http starts LaurieWired-compatible HTTP on 127.0.0.1:8080 so router backend ghidra works.
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [string]$OutDir = '',
    [string]$InstallRoot = '',
    [switch]$NoAnalysis,
    [switch]$Http,
    [int]$Port = 8080,
    [int]$MaxFunctions = 0,
    [int]$TimeoutMs = 600000,
    [string]$PostScript = '',
    [string[]]$PostArgs = @()
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
$ah = Join-Path $InstallRoot 'Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $ah)) { throw "missing $ah" }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }
$Sample = (Resolve-Path -LiteralPath $Sample).Path
if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP ('ghidra-out-' + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$scriptPath = Join-Path $PSScriptRoot 'ghidra'
$projRoot = Join-Path $env:TEMP ('ghidra-proj-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $projRoot | Out-Null
$projName = 'agent'
$postScriptName = if ($Http) { 'HeadlessMcpHttp.java' } elseif ($PostScript) { $PostScript } else { 'ExportDecompile.java' }
$postScriptArg = if ($Http) { "$Port" } elseif ($PostScript) { ($PostArgs -join ' ') } else { $OutDir }
$argList = New-Object System.Collections.Generic.List[string]
foreach ($a in @($projRoot, $projName, '-import', $Sample, '-overwrite', '-scriptPath', $scriptPath)) {
    [void]$argList.Add($a)
}
if ($NoAnalysis) { [void]$argList.Add('-noanalysis') }
if (-not $Http -and -not $PostScript) { [void]$argList.Add('-deleteProject') }
foreach ($a in @('-postScript', $postScriptName, $postScriptArg)) { [void]$argList.Add($a) }
if ($PostArgs.Count -gt 0) { foreach ($pa in $PostArgs) { [void]$argList.Add($pa) } }
if (-not $Http -and $MaxFunctions -gt 0) { [void]$argList.Add("$MaxFunctions") }

function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}
$joined = ($argList | ForEach-Object { Quote-Arg $_ }) -join ' '
$cmd = "`"$ah`" $joined"
Write-Host "GHIDRA $cmd" -ForegroundColor DarkGray
$outLog = Join-Path $OutDir 'analyzeHeadless.log'
if ($Http) {
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $cmd) -NoNewWindow -PassThru -RedirectStandardOutput $outLog -RedirectStandardError "$outLog.err"
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    $ready = $false
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 800
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
        if ($p.HasExited) { break }
    }
    $obj = [ordered]@{
        ok      = $ready
        tool    = 'ghidra'
        mode    = 'http'
        url     = "http://127.0.0.1:$Port/"
        pid     = $p.Id
        sample  = $Sample
        note    = 'router backend ghidra talks to this URL. POST /shutdown to stop.'
    }
    $obj | ConvertTo-Json -Compress
    if (-not $ready) { exit 1 }
    exit 0
}

$p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $cmd) -NoNewWindow -PassThru -RedirectStandardOutput $outLog -RedirectStandardError "$outLog.err"
if (-not $p.WaitForExit($TimeoutMs)) {
    try { $p.Kill() } catch {}
    @{ ok = $false; tool = 'ghidra'; error = "TIMEOUT ${TimeoutMs}ms"; log = $outLog } | ConvertTo-Json -Compress
    exit 1
}
$summary = Join-Path $OutDir 'summary.json'
if (Test-Path -LiteralPath $summary) {
    Get-Content -LiteralPath $summary -Raw
    exit $p.ExitCode
}
@{
    ok     = ($p.ExitCode -eq 0)
    tool   = 'ghidra'
    exit   = $p.ExitCode
    outdir = $OutDir
    log    = $outLog
} | ConvertTo-Json -Compress
exit $p.ExitCode
