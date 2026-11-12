#Requires -Version 5.1
<#
.SYNOPSIS
  Mobile/Android lab -- build a real APK from source, analyse it statically, and
  logic-verify the Frida script library with no device attached.

.DESCRIPTION
  Wraps `mobile-lab/tools/*.mjs` with the station's CLI-Anything convention:
  JSON on stdout, transcripts on stderr, exit code from the underlying tool.

  status    what is installed, what is missing, and the emulator feasibility number
  build     build the self-authored sample APK (javac + d8 + aapt2 + zipalign + apksigner)
  analyze   static analysis of an APK: manifest, DEX, ELF, JNI boundary, pinning, strings
  frida     run the offline Frida suite (40 cases)
  loop      the whole proof in one command, with negative controls

  Zero npm dependencies. No network at run time.

.PARAMETER Action
  status | build | analyze | frida | loop

.PARAMETER Apk
  APK to analyse (for `analyze`). Defaults to mobile-lab\artifacts\mobilelab.apk.

.PARAMETER NodeArgs
  Extra arguments for the underlying .mjs, forwarded verbatim. PowerShell binds bare
  `--out` to -OutVariable before the script sees it, so tool flags go through here.

.EXAMPLE
  powershell -File scripts\mobile-lab.ps1 loop
  powershell -File scripts\mobile-lab.ps1 status
  powershell -File scripts\mobile-lab.ps1 analyze
  powershell -File scripts\mobile-lab.ps1 frida

.NOTES
  Stop lines (see mobile-lab\README.md):
    - authorized samples only; never a third-party production app
    - anti-frida/anti-debug DETECTION is in scope, BYPASSING is not
    - no pinning bypass, no repackaging-and-resigning of anyone else's app
    - no secrets and no third-party binaries in git; the APK and .so are build products
      in gitignored directories
#>
param(
    [Parameter(Position = 0)][string]$Action = 'status',
    [string]$Apk = '',
    [string[]]$NodeArgs = @()
)
$ErrorActionPreference = 'Stop'

# NodeArgs is an argv array, not a command string. Preserve each value exactly once,
# including spaces, commas and empty values.
$Rest = @($NodeArgs)

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LabRoot = Join-Path $RepoRoot 'mobile-lab'
$ToolsDir = Join-Path $LabRoot 'tools'

$node = Get-Command node -ErrorAction SilentlyContinue
$bt = if ($env:MOBILELAB_BUILD_TOOLS) { $env:MOBILELAB_BUILD_TOOLS } else { 'D:\Software\Android\Sdk\build-tools\35.0.0' }
$aapt2 = Join-Path $bt 'aapt2.exe'
$jadx = Join-Path $RepoRoot 'Mobile-Android\jadx\bin\jadx.bat'
$apktool = Join-Path $RepoRoot 'Mobile-Android\Apktool\apktool_3.0.3.jar'
$defaultApk = Join-Path $LabRoot 'artifacts\mobilelab.apk'
$venvPy = Join-Path $LabRoot '.venv\Scripts\python.exe'

$inventory = @(
    [ordered]@{ tool = 'node';      ok = [bool]$node; path = if ($node) { $node.Source } else { $null } }
    [ordered]@{ tool = 'build-tools'; ok = (Test-Path -LiteralPath $aapt2); path = $bt
        note = 'aapt2 + d8 + zipalign + apksigner. This is what makes a real APK buildable with no full SDK.' }
    [ordered]@{ tool = 'javac';     ok = [bool](Get-Command javac -ErrorAction SilentlyContinue); path = $null }
    [ordered]@{ tool = 'keytool';   ok = [bool](Get-Command keytool -ErrorAction SilentlyContinue); path = $null }
    [ordered]@{ tool = 'jadx';      ok = (Test-Path -LiteralPath $jadx); path = $jadx; role = 'independent static cross-check' }
    [ordered]@{ tool = 'apktool';   ok = (Test-Path -LiteralPath $apktool); path = $apktool; role = 'independent static cross-check' }
    [ordered]@{ tool = 'pyelftools'; ok = (Test-Path -LiteralPath $venvPy); path = $venvPy
        role = 'INDEPENDENT ELF oracle; not a dependency of the analyser' }
    [ordered]@{ tool = 'adb';       ok = $false; path = $null; note = 'absent: no platform-tools, no device' }
    [ordered]@{ tool = 'emulator';  ok = $false; path = $null
        note = 'NOT ATTEMPTED. Measured ~1.7 GB download (emulator 338-470 MB + a 1.37 GB system image); D: has 288 GB free, so disk is not the blocker. Blocked by: shell is not elevated (optional-feature install fails), WSL is disabled (Wsl/0x80070422), and Hyper-V is already running so the emulator would need the Windows Hypervisor Platform feature -- whose state cannot even be queried without elevation. See README "Why the emulator was not installed".' }
    [ordered]@{ tool = 'ndk';       ok = $false; path = $null
        note = 'absent: no Android sysroot. Hence the hand-assembled ELF in lab/build/make-so.mjs.' }
)

if ($Action -in @('catalog', 'list', '-h', '--help', '/?')) {
    [ordered]@{
        ok = $true; tool = 'catalog'
        pattern = 'CLI-Anything: one command builds a real APK, analyses it, and logic-verifies a Frida library with no device.'
        items = @('status', 'build', 'analyze', 'frida', 'loop')
    } | ConvertTo-Json -Compress -Depth 6
    exit 0
}

if (-not $node) {
    [ordered]@{ ok = $false; error = 'node not found on PATH' } | ConvertTo-Json -Compress
    exit 2
}

function Invoke-Node([string]$script, [string[]]$extra) {
    $file = Join-Path $ToolsDir $script
    if (-not (Test-Path -LiteralPath $file)) {
        [ordered]@{ ok = $false; error = "missing tool: $file" } | ConvertTo-Json -Compress
        exit 2
    }
    # Windows PowerShell 5.1's native binder drops empty arguments and consumes literal
    # quotes. Pass one encoded JSON argv to Node, then let Node spawn the same interpreter
    # with its argv API. No shell interprets the data; inherited stdio remains streaming.
    $argvJson = ConvertTo-Json -InputObject (@($file) + @($extra)) -Compress
    $argvData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argvJson))
    $forward = "const cp=require('node:child_process');const argv=JSON.parse(Buffer.from(process.argv[1],'base64').toString('utf8'));const r=cp.spawnSync(process.execPath,argv,{stdio:'inherit'});if(r.error){console.error(r.error.message);process.exit(2);}process.exit(r.status===null?2:r.status);"
    & $node.Source -e $forward $argvData
    $code = $LASTEXITCODE
    if ($code -ne 0) { exit $code }
}

switch ($Action.ToLowerInvariant()) {

    'status' {
        $apkPresent = Test-Path -LiteralPath $defaultApk
        $fe = $inventory | Where-Object { -not $_.ok }
        [ordered]@{
            ok         = $true
            tool       = 'status'
            labRoot    = $LabRoot
            apk        = [ordered]@{ path = $defaultApk; present = $apkPresent
                          note = 'gitignored build product; recreate with `build`' }
            inventory  = $inventory
            ceiling    = [ordered]@{
                realApkBuild = $true
                fridaOffline = $true
                fridaAttach  = $false
                disassembly  = $false
                device       = $false
            }
            missing     = @($fe | ForEach-Object { $_.tool })
            ready       = ($inventory | Where-Object { $_.tool -in @('node', 'build-tools', 'javac', 'keytool') -and $_.ok }).Count
        } | ConvertTo-Json -Depth 6
        exit 0
    }

    'build' {
        Invoke-Node '..\lab\build\build-apk.mjs' @('--quiet')
        [ordered]@{ ok = $true; tool = 'build'; apk = $defaultApk } | ConvertTo-Json -Compress
        exit 0
    }

    'analyze' {
        $target = if ($Apk) { $Apk } else { $defaultApk }
        if (-not (Test-Path -LiteralPath $target)) {
            [ordered]@{ ok = $false; error = "APK not found: $target (run 'build' first)" } | ConvertTo-Json -Compress
            exit 3
        }
        Invoke-Node 'analyze.mjs' (@($target) + $Rest)
        exit 0
    }

    'frida' {
        Invoke-Node 'frida-selftest.mjs' @()
        exit 0
    }

    'loop' {
        Invoke-Node 'loop.mjs' $Rest
        exit 0
    }

    default {
        [ordered]@{ ok = $false; error = "unknown action '$Action'"; items = @('status', 'build', 'analyze', 'frida', 'loop') } |
            ConvertTo-Json -Compress
        exit 2
    }
}
