#Requires -Version 5.1
<#
.SYNOPSIS
  Web/JS reverse lab -- CDP capture, deobfuscation/key recovery, out-of-browser replay,
  bot-detection report. Self-authored, in-tree, zero npm dependencies (Node 24 only).

.DESCRIPTION
  Wraps `web-reverse/tools/*.mjs` with the station's CLI-Anything convention:
  JSON on stdout, transcripts on stderr, exit code from the underlying tool.

  status       node/chrome/lab-server readiness + the tool inventory
  loop         the whole proof in one command: gate -> capture -> recover -> replay -> fingerprint
  capture      capture a signed request from a lab page over CDP  (needs `serve` running)
  recover      recover the signing algorithm + key from a captured request
  replay       replay the captured request outside the browser (copy fails, recomputed passes)
  fingerprint  run the local bot-detection surface and report what it saw of us
  serve        start the lab target on loopback (blocking; Ctrl+C to stop)

.EXAMPLE
  powershell -File scripts\web-reverse-lab.ps1 loop
  powershell -File scripts\web-reverse-lab.ps1 status
  powershell -File scripts\web-reverse-lab.ps1 capture -Rest --url http://127.0.0.1:8787/obf

.NOTES
  Loopback only. The lab browser is disposable (%TEMP% profile) and is launched with
  --host-resolver-rules so it cannot reach anything but 127.0.0.1. Never point this at
  a system the owner does not own, and never build evasion for a third-party site.
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @(),
    # Tool flags must come through here, not as bare --flags: PowerShell binds
    # `--out` to -OutVariable etc. before $Rest ever sees it. Verified failure:
    #   web-reverse-lab.ps1 capture --url ... --out X  ->  AmbiguousParameter 'out'
    # Verified working, either form:
    #   -NodeArgs '--url http://127.0.0.1:8787/obf --clicks 1'      (one string; -File safe)
    #   -NodeArgs @('--url','http://127.0.0.1:8787/obf','--clicks','1')  (array; -Command/in-session)
    [string[]]$NodeArgs = @()
)
$ErrorActionPreference = 'Stop'
$Rest = @(@($Rest) + @($NodeArgs) | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ -ne '' })

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'web-reverse'
$ToolsDir = Join-Path $LabRoot 'tools'
$node = (Get-Command node -ErrorAction SilentlyContinue)
$chrome = @(
    $env:LAB_CHROME,
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1

function Get-LabHealth($base) {
    try {
        $raw = & curl.exe -sS -m 2 "$base/api/health" 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) { return ($raw | ConvertFrom-Json) }
    } catch { }
    return $null
}

$inventory = @(
    @{ tool = 'lab/serve'; script = 'lab/server.mjs'; does = 'loopback target: signed POST /api/submit gate + /fingerprint bot-detection surface' }
    @{ tool = 'capture'; script = 'tools/capture.mjs'; does = 'CDP: Network.requestWillBeSent + Runtime.addBinding XHR tap -> capture.json' }
    @{ tool = 'recover'; script = 'tools/recover.mjs'; does = 'string-array decode + key candidates verified by reproducing captures with node:crypto' }
    @{ tool = 'replay'; script = 'tools/replay.mjs'; does = 'plain node:http replay: verbatim copy must fail, recomputed signature must pass' }
    @{ tool = 'fingerprint'; script = 'tools/fingerprint.mjs'; does = 'bot-detection report: header + client signals, CDP footprint attribution' }
    @{ tool = 'loop'; script = 'tools/loop.mjs'; does = 'all of the above in one command, self-judging (exit 0 = loop closed)' }
)

if ($Action -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok        = $true
        action    = 'catalog'
        labRoot   = $LabRoot
        zeroDeps  = 'node >= 22 only (global WebSocket for CDP); no npm install, no vendored code'
        loopbackOnly = $true
        items     = $inventory
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

if (-not $node) {
    [ordered]@{ ok = $false; action = $Action; error = 'node not found on PATH'; fixes = @('install Node 22+', 'or run the .mjs tools with any node 22+') } | ConvertTo-Json -Compress
    exit 2
}

switch ($Action.ToLowerInvariant()) {
    'status' {
        $nodeVersion = (& $node -v) 2>&1
        $ws = (& $node -e "console.log(typeof WebSocket)") 2>&1
        $port = if ($env:WEB_REVERSE_PORT) { [int]$env:WEB_REVERSE_PORT } else { 8787 }
        $health = Get-LabHealth "http://127.0.0.1:$port"
        $ok = (Test-Path -LiteralPath $ToolsDir) -and ($ws -eq 'function')
        [ordered]@{
            ok         = $ok
            action     = 'status'
            labRoot    = $LabRoot
            node       = "$nodeVersion"
            webSocket  = "$ws"
            chrome     = $chrome
            chromeFound = [bool]$chrome
            labServer  = if ($health) { @{ url = "http://127.0.0.1:$port"; up = $true; keyId = $health.keyId; scheme = $health.scheme } } else { @{ url = "http://127.0.0.1:$port"; up = $false } }
            artifacts  = (Join-Path $env:TEMP 'web-reverse-captures')
            items      = $inventory
            note       = if ($health) { 'lab server up: capture/recover/replay can run now' } else { 'lab server down: run action serve first (loop starts its own server and needs none)' }
        } | ConvertTo-Json -Compress -Depth 6
        if (-not $ok) { exit 2 }
        exit 0
    }
    'serve' {
        $portArg = @('--port', '8787')
        if ($Rest.Count -ge 1 -and $Rest[0] -match '^\d+$') { $portArg = @('--port', $Rest[0]) }
        & $node (Join-Path $LabRoot 'lab\server.mjs') @portArg
        exit $LASTEXITCODE
    }
    default {
        $map = @{
            loop        = 'tools\loop.mjs'
            capture     = 'tools\capture.mjs'
            recover     = 'tools\recover.mjs'
            replay      = 'tools\replay.mjs'
            fingerprint = 'tools\fingerprint.mjs'
        }
        $key = $Action.ToLowerInvariant()
        if (-not $map.ContainsKey($key)) {
            [ordered]@{ ok = $false; action = $Action; error = "unknown action $Action"; actions = @('status', 'loop', 'serve', 'capture', 'recover', 'replay', 'fingerprint') } | ConvertTo-Json -Compress
            exit 2
        }
        $scriptPath = Join-Path $LabRoot $map[$key]
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            [ordered]@{ ok = $false; action = $key; error = "missing $scriptPath" } | ConvertTo-Json -Compress
            exit 2
        }
        $out = & $node $scriptPath @Rest 2>&1 | Out-String
        $code = $LASTEXITCODE
        [Console]::Error.Write($out)
        [ordered]@{
            ok        = ($code -eq 0)
            action    = $key
            exitCode  = $code
            tool      = $map[$key]
            nodeArgs  = @($Rest)
            artifacts = (Join-Path $env:TEMP 'web-reverse-captures')
            note      = if ($code -eq 0) { 'transcript on stderr; artifacts under the artifacts path' } else { "tool exited $code - read the stderr transcript" }
        } | ConvertTo-Json -Compress
        exit $code
    }
}
