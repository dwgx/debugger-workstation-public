#Requires -Version 5.1
<#
.SYNOPSIS
  Native lab -- IDA Professional 9.2 driven headlessly through idalib-mcp, against binaries we own.

.DESCRIPTION
  Wraps `native-lab/tools/loop.mjs` with the station's CLI-Anything convention:
  JSON on stdout, transcript on stderr, exit code from the underlying tool.

  status    probe the host: IDA install, licence file, idalib-mcp, port state
  loop      the whole proof in one command. Exit 0 = every check passed.
  tools     list the MCP tool surface idalib-mcp actually exposes right now
  decompile decompile one function by name or address from a binary we own

.EXAMPLE
  powershell -File scripts\native-lab.ps1 status
  powershell -File scripts\native-lab.ps1 loop
  powershell -File scripts\native-lab.ps1 decompile -Binary crackme-corpus\out\c01-stringobf.exe -Func main

.NOTES
  Exit codes: 0 = loop closed · 1 = a check failed · 2 = host not ready or unknown action.

  WHY THIS EXISTS. This station claimed for a long time that it had no IDA Pro. It has
  one: IDA Professional 9.2, licensed, behind the Static-Reversing junction, with
  ida-pro-mcp 2.0.0 serving 66 tools. A correction that is never re-checked decays back
  into the false claim, so `loop` re-checks it on every run.

  THE TRAP THIS LAB RECORDS. ida-pro-mcp reports a FAILED decompile with isError:false,
  a null `code` and an `error` string. A wrapper that trusts isError writes the failure
  down as a success with a null body -- the complete-and-confident-and-wrong shape this
  station exists to reject, arriving through a real tool rather than a hallucination.
  The loop asserts that hazard is still true, so a server that starts setting isError
  correctly fails loudly instead of quietly invalidating every wrapper in the repo.

  PATH. idalib is the agent route; OWNER.md:13 makes idalib or `idat -A` the default and
  AGENTS.md:123 forbids adding a second IDA server. The GUI plugin on 13337 is only for
  when a human has ida.exe open.

  STOP LINES. Owner-named or self-built binaries only. `loop` uses crackme-corpus, which
  we compile from our own source, so provenance is checkable by file. Nothing here is
  licensed to touch a process we were not pointed at: no lsass, no Defender, no daily
  Chrome.
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @(),
    # Tool flags go through here, not as bare --flags: PowerShell binds `--out` to
    # -OutVariable etc. before $Rest ever sees it. Same trap web-reverse-lab.ps1 documents.
    [string[]]$NodeArgs = @(),
    [string]$Binary = '',
    [string]$Func = ''
)

$ErrorActionPreference = 'Stop'
$Rest = @(@($Rest) + @($NodeArgs) | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ -ne '' })

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'native-lab'
$ToolsDir = Join-Path $LabRoot 'tools'

$IdalibMcp = 'D:\Software\Developer\Python314\Scripts\idalib-mcp.exe'
$IdaRoot = 'D:\Software\Tool\Debugger\IDA Professional 9.2'
$IdaJunction = Join-Path $RepoRoot 'Static-Reversing\IDA'
$Node = Get-Command node -ErrorAction SilentlyContinue
$Port = 8745

function Get-PortState {
    try {
        $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($c) { return [ordered]@{ listening = $true; pid = @($c)[0].OwningProcess } }
    } catch { }
    return [ordered]@{ listening = $false; pid = $null }
}

if ($Action -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok       = $true
        tool     = 'native-lab'
        cli      = 'node tools/loop.mjs (spawn idalib-mcp -> wait session -> list_funcs -> decompile -> 3 negative controls -> isError-hazard control)'
        gui      = 'n/a; OWNER.md:13 makes idalib or idat -A the agent default, not the GUI on 13337'
        mcp      = 'ida-pro-mcp 2.0.0 over POST http://127.0.0.1:8745/mcp (66 tools)'
        actions  = @('status', 'loop', 'tools', 'decompile')
        note     = 'proves IDA is present, licensed and usable; refuses to inherit a server it did not start'
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

if (-not $Node) {
    [ordered]@{ ok = $false; action = $Action; error = 'node not found on PATH (this lab needs Node >= 24 and nothing else)' } | ConvertTo-Json -Compress
    exit 2
}

switch ($Action.ToLowerInvariant()) {
    'status' {
        $licence = Join-Path $IdaRoot 'idapro.hexlic'
        $nodeVersion = (& $Node -v) 2>&1
        $issues = @()
        if (-not (Test-Path $IdalibMcp)) { $issues += "idalib-mcp missing at $IdalibMcp" }
        if (-not (Test-Path (Join-Path $IdaRoot 'ida.exe'))) { $issues += "IDA not found at $IdaRoot" }
        if (-not (Test-Path $licence)) { $issues += "no idapro.hexlic -- IDA may be unlicensed" }
        if (-not (Test-Path (Join-Path $ToolsDir 'loop.mjs'))) { $issues += "loop.mjs missing under $ToolsDir" }
        [ordered]@{
            ok           = ($issues.Count -eq 0)
            tool         = 'native-lab'
            node         = "$nodeVersion"
            labRoot      = $LabRoot
            idaRoot      = $IdaRoot
            idaJunction  = $IdaJunction
            idaPresent   = (Test-Path (Join-Path $IdaRoot 'ida.exe'))
            licence      = (Test-Path $licence)
            idalibMcp    = (Test-Path $IdalibMcp)
            mcpPort      = $Port
            portState    = Get-PortState
            warnings     = $issues
            note         = 'a leftover idalib worker holding 8745 will make `loop` refuse rather than inherit another run''s server; taskkill /T /F it'
        } | ConvertTo-Json -Compress -Depth 6
        if ($issues.Count -gt 0) { exit 2 }
        exit 0
    }

    'loop' {
        & $Node.Source (Join-Path $ToolsDir 'loop.mjs') 2>&1
        exit $LASTEXITCODE
    }

    'tools' {
        # Reflect the live tool surface. Useful when idalib-mcp is upgraded: the
        # registry's 66 is a recorded number, not a promise.
        $probe = Join-Path $ToolsDir 'list-tools.mjs'
        if (-not (Test-Path $probe)) {
            [ordered]@{ ok = $false; error = "helper missing: $probe" } | ConvertTo-Json -Compress
            exit 2
        }
        & $Node.Source $probe
        exit $LASTEXITCODE
    }

    'decompile' {
        if (-not $Binary -or -not $Func) {
            [ordered]@{ ok = $false; error = 'usage: decompile -Binary <path> -Func <name|addr>' } | ConvertTo-Json -Compress
            exit 2
        }
        if (-not (Test-Path $Binary)) {
            [ordered]@{ ok = $false; error = "binary not found: $Binary" } | ConvertTo-Json -Compress
            exit 2
        }
        $probe = Join-Path $ToolsDir 'decompile.mjs'
        if (-not (Test-Path $probe)) {
            [ordered]@{ ok = $false; error = "helper missing: $probe" } | ConvertTo-Json -Compress
            exit 2
        }
        & $Node.Source $probe $Binary $Func
        exit $LASTEXITCODE
    }

    default {
        [ordered]@{ ok = $false; error = "unknown action $Action"; actions = @('status', 'loop', 'tools', 'decompile') } | ConvertTo-Json -Compress
        exit 2
    }
}
