#Requires -Version 5.1
<#
.SYNOPSIS
  Agent MobSF without a browser.
  If MOBSF_URL + MOBSF_API_KEY: REST /api/v1/upload+scan+report_json (local key, not VirusTotal).
  Else: apktool decode + AndroidManifest parse (no Django, no window).
#>
param(
    [Parameter(Mandatory = $true)][string]$Sample,
    [string]$InstallRoot = '',
    [string]$OutDir = '',
    [int]$TimeoutSec = 120
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }
if (-not (Test-Path -LiteralPath $Sample)) { throw "missing sample $Sample" }
$Sample = (Resolve-Path -LiteralPath $Sample).Path
$ext = [IO.Path]::GetExtension($Sample).ToLowerInvariant()
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ('mobsf-out-' + [guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-EnvOrFile([string]$name, [string]$fileKey) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ($v) { return $v }
    $envFile = Join-Path $InstallRoot 'MCP\mobsf-mcp-server\.env'
    if (Test-Path -LiteralPath $envFile) {
        foreach ($line in Get-Content -LiteralPath $envFile) {
            if ($line -match "^\s*$fileKey\s*=\s*(.+)$") { return $Matches[1].Trim().Trim('"') }
        }
    }
    return ''
}

$url = Get-EnvOrFile 'MOBSF_URL' 'MOBSF_URL'
if (-not $url) { $url = 'http://127.0.0.1:8000' }
$key = Get-EnvOrFile 'MOBSF_API_KEY' 'MOBSF_API_KEY'

function Try-MobSfRest {
    if (-not $key) { return $null }
    try {
        $ping = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
        if ($ping.StatusCode -ge 400) { return $null }
    } catch { return $null }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { return $null }
    $uploadJson = & curl.exe -sS -m $TimeoutSec -H "Authorization: $key" -F "file=@$Sample" "$url/api/v1/upload"
    $upload = $uploadJson | ConvertFrom-Json
    if (-not $upload.hash) { throw "MobSF upload failed: $uploadJson" }
    $scanBody = @{ hash = $upload.hash; scan_type = $(if ($ext -eq '.ipa') { 'ios' } else { 'apk' }); file_name = $upload.file_name }
    $scanArgs = @('-sS', '-m', "$TimeoutSec", '-H', "Authorization: $key", '-H', 'Content-Type: application/x-www-form-urlencoded')
    foreach ($k in $scanBody.Keys) { $scanArgs += @('-d', "$k=$($scanBody[$k])") }
    $null = & curl.exe @scanArgs "$url/api/v1/scan"
    $reportJson = & curl.exe -sS -m $TimeoutSec -H "Authorization: $key" -H 'Content-Type: application/x-www-form-urlencoded' -d "hash=$($upload.hash)" "$url/api/v1/report_json"
    $reportPath = Join-Path $OutDir 'report.json'
    Set-Content -LiteralPath $reportPath -Value $reportJson -Encoding UTF8
    return [ordered]@{
        ok     = $true
        tool   = 'mobsf'
        engine = 'rest'
        url    = $url
        hash   = $upload.hash
        report = $reportPath
    }
}

if ($ext -in '.apk', '.ipa', '.xapk') {
    $rest = Try-MobSfRest
    if ($rest) { $rest | ConvertTo-Json -Compress; exit 0 }
}

if ($ext -ne '.apk' -and $ext -ne '.xapk') {
    [ordered]@{
        ok     = $false
        tool   = 'mobsf'
        error  = 'Need .apk for local fallback. Full MobSF REST needs MOBSF_API_KEY and a running manage.py/waitress (no browser).'
        sample = $Sample
    } | ConvertTo-Json -Compress
    exit 2
}

$java = Get-Command java -ErrorAction SilentlyContinue
$jar = Join-Path $InstallRoot 'Mobile-Android\Apktool\apktool.jar'
if (-not $java) { throw 'java not on PATH' }
if (-not (Test-Path -LiteralPath $jar)) { throw "missing $jar" }
$decoded = Join-Path $OutDir 'apktool'
& $java.Source -jar $jar d -f -o $decoded $Sample
$manifest = Join-Path $decoded 'AndroidManifest.xml'
$perms = @(); $acts = @(); $pkg = ''; $app = ''
if (Test-Path -LiteralPath $manifest) {
    $xml = Get-Content -LiteralPath $manifest -Raw
    [regex]::Matches($xml, 'package="([^"]+)"') | ForEach-Object { if (-not $pkg) { $pkg = $_.Groups[1].Value } }
    [regex]::Matches($xml, 'android:name="([^"]*permission[^"]*)"') | ForEach-Object { $perms += $_.Groups[1].Value }
    [regex]::Matches($xml, '<uses-permission[^>]*android:name="([^"]+)"') | ForEach-Object { $perms += $_.Groups[1].Value }
    [regex]::Matches($xml, '<activity[^>]*android:name="([^"]+)"') | ForEach-Object { $acts += $_.Groups[1].Value }
}
$perms = @($perms | Select-Object -Unique)
$acts = @($acts | Select-Object -Unique)
$result = [ordered]@{
    ok          = $true
    tool        = 'mobsf'
    engine      = 'local-static'
    sample      = $Sample
    package     = $pkg
    permissions = $perms
    activities  = $acts
    outdir      = $decoded
    note        = 'Django MobSF not running. This is apktool static. Start Mobile-Android/MobSF/run.bat for REST; key is local MobSF API key, not VirusTotal.'
}
$jsonPath = Join-Path $OutDir 'summary.json'
($result | ConvertTo-Json -Compress -Depth 6) | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Get-Content -LiteralPath $jsonPath -Raw
exit 0
