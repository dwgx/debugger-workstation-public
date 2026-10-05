#Requires -Version 5.1
<#
.SYNOPSIS
  Agent-callable CLI smoke. 15s per tool. Exit 0 if every present CLI prints.
  GUI-only tools are existence checks. Does not run samples or install drivers.
#>
[CmdletBinding()]
param([string]$InstallRoot = '')


$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallRoot) { $InstallRoot = $RepoRoot }

function Invoke-Timed {
    param([string]$File, [string[]]$Arguments, [int]$Ms = 15000)
    $out = Join-Path $env:TEMP ("dbg-smoke-{0}.out" -f [guid]::NewGuid().ToString('N'))
    $err = "$out.err"
    $sp = @{
        FilePath = $File
        NoNewWindow = $true
        PassThru = $true
        RedirectStandardOutput = $out
        RedirectStandardError = $err
    }
    if ($Arguments -and $Arguments.Count) { $sp.ArgumentList = $Arguments }
    $p = Start-Process @sp
    if (-not $p.WaitForExit($Ms)) {
        try { $p.Kill() } catch {}
        return @{ exit = 'TIMEOUT'; text = '' }
    }
    $text = ((Get-Content $out -ErrorAction SilentlyContinue) + (Get-Content $err -ErrorAction SilentlyContinue) | Select-Object -First 4) -join ' | '
    Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
    return @{ exit = $p.ExitCode; text = $text }
}

$fail = 0
function Show([string]$Name, [bool]$Ok, [string]$Detail) {
    $tag = if ($Ok) { 'PASS' } else { 'FAIL'; $script:fail++ }
    Write-Host ("{0,-12} {1}  {2}" -f $tag, $Name, $Detail)
}

# CLI that must print
$cli = @(
    # `e` is a regex the output MUST match. Absent `e`, the check is PRESENCE ONLY, and the
    # summary says so rather than printing a PASS that reads like a version check.
    #
    # Measured 2026-10-05: capa, floss and diec were all invoked with a HELP flag (-h /
    # --help) while all three have a working `--version`, and the loop below scored any
    # non-empty output as a pass. So all three reported PASS having never read a version
    # number -- a check that cannot go red, which is what this repository's own R2 calls
    # a non-check. The version figures the wiki quotes for these tools (capa 9.4.0,
    # floss 3.1.1, die 3.21) are CORRECT, but they were corroborated by the parent
    # DIRECTORY NAME, not by anything this script did.
    #
    #   capa  --version -> capa.exe 9.4.0
    #   floss --version -> floss.exe v3.1.1-0-g3cd3ee6
    #   diec  --version -> die 3.21
    #
    # GoReSym and dnspy.con keep their help flags and carry NO `e`, because neither has a
    # version flag to use: GoReSym prints only usage for every flag tried. That is recorded
    # as presence-only rather than dressed up with an expectation the tool cannot meet.
    @{ n = 'capa'; f = 'Static-Reversing\capa\capa.exe'; a = @('--version'); e = 'capa\.exe\s+\d+\.\d+' },
    @{ n = 'yr'; f = 'Static-Reversing\YARA-X\yr.exe'; a = @('--version'); e = 'yara-x-cli\s+\d+\.\d+' },
    @{ n = 'radare2'; f = 'Static-Reversing\radare2\radare2-6.2.2-w64\bin\radare2.exe'; a = @('-v'); e = 'radare2\s+\d+\.\d+' },
    @{ n = '7z'; f = 'Unpackers-Game\7-Zip-full\7z.exe'; a = @(); e = '7-Zip\s+\d+\.\d+' },
    @{ n = 'upx'; f = 'Unpackers-Game\upx\upx-5.2.1-win64\upx.exe'; a = @('-V'); e = 'upx\s+\d+\.\d+' },
    @{ n = 'diec'; f = 'Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe'; a = @('--version'); e = 'die\s+\d+\.\d+' },
    @{ n = 'ilspycmd'; f = 'Static-Reversing\ilspycmd\ilspycmd.exe'; a = @('--version'); e = 'ilspycmd:\s+\d+\.\d+' },
    @{ n = 'GoReSym'; f = 'Unpackers-Game\GoReSym\GoReSym.exe'; a = @('-h'); presenceOnly = 'no version flag: prints usage for every flag tried' },
    @{ n = 'floss'; f = 'Static-Reversing\FLOSS\floss.exe'; a = @('--version'); e = 'floss\.exe\s+v?\d+\.\d+' },
    @{ n = 'dnspy.con'; f = 'Static-Reversing\dnSpyEx\dnSpy.Console.exe'; a = @('--help'); presenceOnly = 'no version flag found; usage is all it prints' }
)
foreach ($t in $cli) {
    $path = Join-Path $InstallRoot $t.f
    if (-not (Test-Path -LiteralPath $path)) { Show $t.n $false "missing $path"; continue }
    $r = Invoke-Timed $path $t.a
    # R2: a check that cannot go red is not a check. Presence-only is a real, weaker
    # outcome and is LABELLED as such -- never printed as a bare PASS that a reader takes
    # for a version verification it did not perform.
    $ok = ($r.exit -ne 'TIMEOUT') -and ($r.text.Length -gt 0)
    if ($t.e) { $ok = $ok -and ($r.text -match $t.e) }
    $tag = if ($t.e) { '' } elseif ($t.presenceOnly) { "[PRESENCE ONLY: $($t.presenceOnly)] " } else { '[NO VERSION ASSERTED] ' }
    Show $t.n $ok ($tag + ("exit={0} {1}" -f $r.exit, $r.text.Substring(0, [Math]::Min(120, $r.text.Length))))
}

$tshark = Join-Path $InstallRoot 'Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe'
if (Test-Path -LiteralPath $tshark) {
    $r = Invoke-Timed $tshark @('--version') 20000
    Show 'tshark' (($r.exit -ne 'TIMEOUT') -and ($r.text -match 'TShark|Wireshark')) ("exit={0} {1}" -f $r.exit, $r.text.Substring(0, [Math]::Min(80, $r.text.Length)))
} else { Show 'tshark' $false 'missing' }

$java = Get-Command java -ErrorAction SilentlyContinue
if ($java) {
    $jar = Join-Path $InstallRoot 'Mobile-Android\Apktool\apktool.jar'
    $r = Invoke-Timed $java.Source @('-jar', $jar, '--version') 30000
    Show 'apktool' ($r.text -match '3\.') ("exit={0} {1}" -f $r.exit, $r.text)
    $jadx = Join-Path $InstallRoot 'Mobile-Android\jadx\bin\jadx.bat'
    $r = Invoke-Timed 'cmd.exe' @('/c', $jadx, '--version') 30000
    Show 'jadx' ($r.text -match '1\.5') ("exit={0} {1}" -f $r.exit, $r.text)
} else { Show 'java' $false 'java not on PATH' }

# GUI / files only
foreach ($g in @(
    @{ n = 'ghidra'; f = 'Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\ghidraRun.bat' },
    @{ n = 'ida'; f = 'Static-Reversing\IDA' },
    @{ n = 'ILSpy'; f = 'Static-Reversing\ILSpy\ILSpy.exe' },
    @{ n = 'AssetRipper'; f = 'Unpackers-Game\AssetRipper\AssetRipper.GUI.Free.exe' },
    @{ n = 'x64dbg'; f = 'Debuggers\x64dbg\release\x64\x64dbg.exe' },
    @{ n = 'CE'; f = 'Debuggers\Cheat Engine\cheatengine-x86_64.exe' }
)) {
    Show $g.n (Test-Path -LiteralPath (Join-Path $InstallRoot $g.f)) $g.f
}

if ($fail) { Write-Host "SMOKE_CLI FAIL count=$fail"; exit 1 }
Write-Host 'SMOKE_CLI PASS'
exit 0
