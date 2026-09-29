#Requires -Version 5.1
<#
.SYNOPSIS
  Reputation / capability without stalling on a VirusTotal API key.
  Always: SHA256 + DIE + capa (timed). VT hash lookup only if VIRUSTOTAL_API_KEY is set.
  Never uploads a sample unless -Upload (still requires the key).
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [string]$InstallRoot = '',
    [switch]$Upload,
    [int]$CapaMs = 60000
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }
$Sample = (Resolve-Path -LiteralPath $Sample).Path
$hash = (Get-FileHash -LiteralPath $Sample -Algorithm SHA256).Hash.ToLowerInvariant()
$diec = Join-Path $InstallRoot 'Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe'
$capa = Join-Path $InstallRoot 'Static-Reversing\capa\capa.exe'
$dieText = ''
if (Test-Path -LiteralPath $diec) {
    $dieText = (& $diec -e $Sample 2>&1 | Select-Object -First 20) -join "`n"
}
$capaText = ''
$capaOk = $false
if (Test-Path -LiteralPath $capa) {
    $out = Join-Path $env:TEMP ("capa-" + [guid]::NewGuid().ToString('N') + ".out")
    $p = Start-Process -FilePath $capa -ArgumentList @('-q', '--', $Sample) -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    if (-not $p.WaitForExit($CapaMs)) {
        try { $p.Kill() } catch {}
        $capaText = "TIMEOUT ${CapaMs}ms"
    } else {
        $capaOk = $true
        $capaText = ((Get-Content $out -ErrorAction SilentlyContinue) | Select-Object -First 40) -join "`n"
    }
    Remove-Item -LiteralPath $out, "$out.err" -Force -ErrorAction SilentlyContinue
}

$vtKey = $env:VIRUSTOTAL_API_KEY
if (-not $vtKey) {
    $envFile = Join-Path $InstallRoot 'MCP\mcp-virustotal\.env'
    if (Test-Path -LiteralPath $envFile) {
        foreach ($line in Get-Content -LiteralPath $envFile) {
            if ($line -match '^\s*VIRUSTOTAL_API_KEY\s*=\s*(.+)$') { $vtKey = $Matches[1].Trim().Trim('"') }
        }
    }
}

$vt = [ordered]@{ skipped = $true; reason = 'no VIRUSTOTAL_API_KEY; local DIE/capa only' }
if ($vtKey) {
    $headers = @{ 'x-apikey' = $vtKey }
    try {
        $rep = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers $headers -TimeoutSec 30
        $stats = $rep.data.attributes.last_analysis_stats
        $vt = [ordered]@{
            skipped = $false
            mode    = 'hash-lookup'
            malicious = $stats.malicious
            undetected = $stats.undetected
            suspicious = $stats.suspicious
        }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 404 -and $Upload) {
            $vt = [ordered]@{ skipped = $false; mode = 'upload-not-implemented-here'; error = 'Use official VT MCP only after Owner names upload. Default is hash lookup.' }
        } elseif ($code -eq 404) {
            $vt = [ordered]@{ skipped = $false; mode = 'hash-lookup'; found = $false }
        } else {
            $vt = [ordered]@{ skipped = $false; error = $_.Exception.Message }
        }
    }
}

[ordered]@{
    ok      = $true
    tool    = 'intel'
    sample  = $Sample
    sha256  = $hash
    die     = $dieText
    capaOk  = $capaOk
    capa    = $capaText
    virustotal = $vt
    mcp     = 'router virustotal needs VIRUSTOTAL_API_KEY in MCP/mcp-virustotal/.env — do not commit it'
} | ConvertTo-Json -Compress -Depth 6
exit 0
