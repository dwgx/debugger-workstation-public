#Requires -Version 5.1
<#
.SYNOPSIS
  JWT / token analysis lab -- decode and explain a token, name the weakness class it
  carries, and cross-check that verdict against two independent JWT libraries.

.DESCRIPTION
  Wraps `crypto-lab/tools/*.mjs` and `crypto-lab/tools/oracle.py` with the station's
  CLI-Anything convention: JSON on stdout, transcript on stderr, exit code from the tool.

  status    node / python-oracle / key / server readiness and the tool inventory
  loop      the whole proof in one command: 12 classification cases + a 5x4 verifier
            matrix + a live negative control. Exit 0 means every class was classified as
            expected and both oracles agreed.
  analyze   run the analyzer against one token and print the full JSON report
  oracle    run one cross-check (jsonwebtoken or PyJWT) against one token
  serve     start the lab target on loopback (blocking; Ctrl+C to stop)
  catalog   machine-readable inventory

.EXAMPLE
  powershell -File scripts\crypto-lab.ps1 loop
  powershell -File scripts\crypto-lab.ps1 status

  # analyze one token (first-class params; a JWT is full of dashes and dots, so the
  # generic -NodeArgs escaping path exists but these are easier)
  powershell -File scripts\crypto-lab.ps1 analyze -Token "eyJ..." -RsaPub keys\lab-rsa-2048.pub.pem -ServerAlg RS256

  # anything else goes through -NodeArgs, the -File-safe form
  powershell -File scripts\crypto-lab.ps1 analyze -NodeArgs '--token eyJ... --secret secret --quiet'

.NOTES
  Loopback only: the lab server refuses to bind anything but 127.0.0.1.

  STOP LINES. This lab analyses tokens we generated ourselves, so that we can recognise
  the same weaknesses in our own code. It is not a forging toolkit for anybody else's
  service, and it ships no credential-stuffing or token-replay tooling. The analyzer
  never dereferences a `jku`/`x5u` key URL: reporting that a token nominates one is the
  job, fetching it is outbound reach during analysis and is a station stop line.

  No secrets in git. The RSA keypair is generated at runtime into crypto-lab/keys/
  (gitignored); the HMAC secrets are published, obviously-fake constants.
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @(),
    # Tool flags must come through here, not as bare --flags: PowerShell binds
    # `--out` to -OutVariable etc. before $Rest ever sees it. Verified working form:
    #   -NodeArgs '--token eyJ... --rsa-pub keys\x.pem'
    [string[]]$NodeArgs = @(),
    # First-class pass-throughs for the analyzer. Convenience only; -NodeArgs is the
    # general path and both are merged.
    [string]$Token = '',
    [string]$TokenFile = '',
    [string]$Secret = '',
    [string]$RsaPub = '',
    [string]$ServerAlg = '',
    [int]$TtlMax = 0,
    [string]$Expect = '',
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
$Rest = @(@($Rest) + @($NodeArgs) | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ -ne '' })

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'crypto-lab'
$ToolsDir = Join-Path $LabRoot 'tools'
$KeysDir = Join-Path $LabRoot 'keys'
$node = (Get-Command node -ErrorAction SilentlyContinue)
$pyExe = Join-Path $LabRoot '.venv\Scripts\python.exe'
if ($env:CRYPTO_LAB_PY -and (Test-Path -LiteralPath $env:CRYPTO_LAB_PY)) { $pyExe = $env:CRYPTO_LAB_PY }
$jsDir = Join-Path $LabRoot 'node_modules\jsonwebtoken'

function Get-JsonAt($path) {
    try { if (Test-Path -LiteralPath $path) { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } } catch { }
    return $null
}

function Get-LabHealth($base) {
    try {
        $raw = & curl.exe -sS -m 2 "$base/api/health" 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) { return ($raw | ConvertFrom-Json) }
    } catch { }
    return $null
}

$jwtPkg = Get-JsonAt (Join-Path $jsDir 'package.json')

$inventory = @(
    @{ tool = 'lab/serve'; script = 'lab/server.mjs'; does = 'loopback issuer (5 profiles) + 4 verifiers, each printing the checks it ran' }
    @{ tool = 'analyze'; script = 'tools/analyze.mjs'; does = 'THE DELIVERABLE: decode one JWS, explain every claim, name the weakness classes. Zero dependencies.' }
    @{ tool = 'oracle-node'; script = 'tools/oracle-node.mjs'; does = 'cross-check with jsonwebtoken 9.0.3 (independent implementation #1)' }
    @{ tool = 'oracle.py'; script = 'tools/oracle.py'; does = 'cross-check with PyJWT 2.15.1 (independent implementation #2)' }
    @{ tool = 'loop'; script = 'tools/loop.mjs'; does = 'self-judging: 12 cases + 5x4 verifier matrix + negative control (exit 0 = every class classified as expected)' }
)

if ($Action -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok        = $true
        action    = 'catalog'
        labRoot   = $LabRoot
        loopbackOnly = $true
        analyzer  = 'zero dependencies (node:crypto only) -- the two libraries are oracles, not requirements'
        items     = $inventory
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

if (-not $node) {
    [ordered]@{ ok = $false; action = $Action; error = 'node not found on PATH'; fixes = @('install Node 24 (even major)') } | ConvertTo-Json -Compress
    exit 2
}

switch ($Action.ToLowerInvariant()) {
    'status' {
        $nodeVersion = (& $node -v) 2>&1
        $port = if ($env:CRYPTO_LAB_PORT) { [int]$env:CRYPTO_LAB_PORT } else { 8791 }
        $health = Get-LabHealth "http://127.0.0.1:$port"
        $pub = Join-Path $KeysDir 'lab-rsa-2048.pub.pem'
        $pyOk = Test-Path -LiteralPath $pyExe
        $pyVersions = $null
        if ($pyOk) {
            $raw = (& $pyExe -c "import jwt, cryptography, sys; print(sys.version.split()[0], jwt.__version__, cryptography.__version__)" 2>&1) -join ''
            if ($LASTEXITCODE -eq 0 -and $raw) {
                $f = $raw.Trim() -split '\s+'
                $pyVersions = @{ python = $f[0]; PyJWT = $f[1]; cryptography = $f[2] }
            }
        }
        $ok = (Test-Path -LiteralPath $ToolsDir) -and (Test-Path -LiteralPath (Join-Path $ToolsDir 'analyze.mjs'))
        [ordered]@{
            ok        = $ok
            action    = 'status'
            labRoot   = $LabRoot
            node      = "$nodeVersion"
            analyzer  = @{ path = 'tools/analyze.mjs'; dependencies = 'none (node:crypto only)'; available = (Test-Path -LiteralPath (Join-Path $ToolsDir 'analyze.mjs')) }
            oracleNode = @{ path = 'tools/oracle-node.mjs'; package = 'jsonwebtoken'; version = if ($jwtPkg) { $jwtPkg.version } else { $null }; installed = [bool]$jwtPkg }
            oraclePython = @{ path = 'tools/oracle.py'; interpreter = $pyExe; installed = $pyOk; versions = $pyVersions }
            keys      = @{ dir = $KeysDir; publicKey = $pub; generated = (Test-Path -LiteralPath $pub); note = 'generated at runtime; gitignored; no key material in git' }
            labServer = if ($health) { @{ url = "http://127.0.0.1:$port"; up = $true; kid = $health.kid; algorithms = $health.configAlgorithms } } else { @{ url = "http://127.0.0.1:$port"; up = $false } }
            items     = $inventory
            note      = if ($health) { 'lab server up: analyze/oracle can run now (loop starts its own server and needs none)' } else { 'lab server down: run action serve, or just run the loop' }
        } | ConvertTo-Json -Compress -Depth 6
        if (-not $ok) { exit 2 }
        exit 0
    }
    'serve' {
        $portArg = @('--port', '8791')
        if ($Rest.Count -ge 1 -and $Rest[0] -match '^\d+$') { $portArg = @('--port', $Rest[0]) }
        & $node (Join-Path $LabRoot 'lab\server.mjs') @portArg
        exit $LASTEXITCODE
    }
    default {
        $map = @{
            loop    = 'tools\loop.mjs'
            analyze = 'tools\analyze.mjs'
            oracle  = 'tools\oracle-node.mjs'
        }
        $key = $Action.ToLowerInvariant()
        if (-not $map.ContainsKey($key)) {
            [ordered]@{ ok = $false; action = $Action; error = "unknown action $Action"; actions = @('status', 'loop', 'serve', 'analyze', 'oracle', 'catalog') } | ConvertTo-Json -Compress
            exit 2
        }
        $scriptPath = Join-Path $LabRoot $map[$key]
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            [ordered]@{ ok = $false; action = $key; error = "missing $scriptPath" } | ConvertTo-Json -Compress
            exit 2
        }

        # merge the first-class params into the tool argument list
        $toolArgs = @($Rest)
        if ($Token)     { $toolArgs += @('--token', $Token) }
        if ($TokenFile) { $toolArgs += @('--file', $TokenFile) }
        if ($Secret)    { $toolArgs += @('--secret', $Secret) }
        if ($RsaPub)    { $toolArgs += @('--rsa-pub', $RsaPub) }
        if ($ServerAlg) { $toolArgs += @('--server-alg', $ServerAlg) }
        if ($TtlMax -gt 0) { $toolArgs += @('--ttl-max', "$TtlMax") }
        if ($Expect)    { $toolArgs += @('--expect', $Expect) }
        if ($Quiet)     { $toolArgs += @('--quiet') }

        $env:CRYPTO_LAB_PY = $pyExe
        # Child stderr is deliberately NOT redirected. In Windows PowerShell 5.1 any
        # redirection of a native command's stderr (`2>file`, `2>&1`) converts each line
        # into a NativeCommandError record, which decorates the transcript and, with
        # ErrorActionPreference=Stop, aborts the run. Left alone, the child's stderr
        # inherits this console's handle and arrives verbatim -- which is the contract:
        # transcript on stderr, machine-readable envelope on stdout.
        $raw = & $node $scriptPath @toolArgs | Out-String
        $code = $LASTEXITCODE
        if ($raw) { [Console]::Error.Write($raw) }

        # Findings and loop counts are the product, so surface them in the envelope
        # instead of making a caller scrape the transcript.
        $report = $null
        if ($key -eq 'analyze' -and $raw) { try { $report = ($raw | ConvertFrom-Json) } catch { } }
        $summary = $null
        if ($raw -match 'JSON-SUMMARY\s+(\{[^}]*\})') { try { $summary = ($Matches[1] | ConvertFrom-Json) } catch { } }

        $env2 = [ordered]@{
            ok       = ($code -eq 0)
            action   = $key
            exitCode = $code
            tool     = $map[$key]
            nodeArgs = @($toolArgs)
            keys     = $KeysDir
            note     = if ($code -eq 0) { 'transcript and report on stderr; this envelope on stdout' } else { "tool exited $code - read the stderr transcript (2 usage, 3 bad input, 4 --expect mismatch, 1 loop failure)" }
        }
        if ($report) {
            $env2['findingIds'] = @($report.summary.finding_ids)
            $env2['weaknessClasses'] = @($report.weaknessClasses.PSObject.Properties | Where-Object { $_.Value.present } | ForEach-Object { $_.Name })
            $env2['verdict'] = $report.summary.verdict
            $env2['report'] = $report
        }
        if ($summary) { $env2['summary'] = $summary }
        $env2 | ConvertTo-Json -Compress -Depth 12
        exit $code
    }
}
