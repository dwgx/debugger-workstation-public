#Requires -Version 5.1
<#
.SYNOPSIS
  Negative control for mobile.apk.static: the second AXML decoder must be ABLE to disagree.

.DESCRIPTION
  `mobile.apk.static` claims its manifest reading is corroborated by an independent decoder.
  That claim is only worth anything if the cross-check can FAIL. So this control truncates the
  lab's own APK to half its length -- which removes the ZIP end-of-central-directory record --
  and requires Apktool 3.0.3 to REFUSE it.

  The distinction under test is the one this project keeps having to relearn: an EMPTY answer
  and an ABSENT answer are different facts. A decoder handed a broken container and returning
  an empty permission set would look exactly like a clean APK with no permissions, and the entry's
  "inspected with independent decoders" would be true of nothing.

  Exits non-zero when Apktool refuses (the control passing), and 0 when it does NOT refuse --
  which is the shape every control here uses, and the opposite of "runs and exits 0 is a
  result".

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File mobile-lab/tools/apktool_refusal_control.ps1
#>
[CmdletBinding()]
param(
    [string]$Apk = 'mobile-lab\artifacts\mobilelab.apk',
    [string]$Apktool = 'Mobile-Android\Apktool\apktool_3.0.3.jar',
    # FALSIFIER, and a switch rather than a note: a control nobody can make fail is not a
    # control. -SkipTruncate hands the decoder an INTACT APK, so the decode succeeds and this
    # script exits 0 with CONTROL FAILED AS IT SHOULD -- the only way to know the check is
    # looking at the archive rather than passing on java's exit code by coincidence.
    [switch]$SkipTruncate
)

$ErrorActionPreference = 'Continue'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root

# EXIT 2 MEANS "THIS CONTROL COULD NOT RUN", and it is deliberately not 0. Independent acceptance
# (2026-10-03) caught every failure branch here exiting 0, which made exit 0 ambiguous: under
# -SkipTruncate the expected outcome IS 0, so "the falsifier proved the check is real" and "the
# APK was missing" were indistinguishable to anything reading the code. Three states, three
# codes: 1 = the decoder refused (the control fired); 0 = the decoder did not refuse (the
# control did not fire); 2 = the control never got to ask.

if (-not (Test-Path -LiteralPath $Apk))        { Write-Host "CANNOT RUN: no such APK: $Apk"; exit 2 }
if (-not (Test-Path -LiteralPath $Apktool))    { Write-Host "CANNOT RUN: no such Apktool jar: $Apktool"; exit 2 }

$t = Join-Path $env:TEMP ("apk-negctl-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $t | Out-Null
try {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Apk).Path)
    $target = Join-Path $t 'truncated.apk'
    if ($SkipTruncate) {
        [System.IO.File]::WriteAllBytes($target, $bytes)
        Write-Host "FALSIFIER: handing the decoder an INTACT $Apk ($($bytes.Length) bytes)"
    } else {
        $half = [int]($bytes.Length / 2)
        [System.IO.File]::WriteAllBytes($target, $bytes[0..($half - 1)])
        Write-Host ("truncated $Apk : $($bytes.Length) -> $half bytes")
    }

    $out = Join-Path $t 'decoded'
    $log = (& java -jar $Apktool d -f -p (Join-Path $t 'fw') -o $out $target 2>&1 | Out-String)
    $rc = $LASTEXITCODE
    ($log -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | '
    Write-Host "apktool exit: $rc"
    if ($SkipTruncate) {
        if ($rc -eq 0) { Write-Host 'CONTROL FAILED AS IT SHOULD when falsified: an intact APK decodes, so the refusal requirement has no excuse.'; exit 0 }
        Write-Host 'CANNOT RUN: the falsifier did not falsify -- apktool refused an INTACT APK, so the comparison below would prove nothing.'
        exit 2
    }

    # A refusal is the pass. Three ways NOT to fire, all of them ways this project has been
    # fooled, and all of them exit 0 -- which is reserved for exactly that meaning.
    if ($rc -eq 0) {
        Write-Host 'DID NOT FIRE: apktool exited 0 on a truncated APK -- it decoded a container with no end-of-central-directory record.'
        exit 0
    }
    if (Test-Path (Join-Path $out 'AndroidManifest.xml')) {
        Write-Host 'DID NOT FIRE: a truncated APK produced an AndroidManifest.xml -- an empty answer read as an answer.'
        exit 0
    }
    if ($log -notmatch 'NotAZipFileException|zip END header not found|not a zip') {
        Write-Host 'DID NOT FIRE: apktool failed, but not for a reason about the archive. A failure for the wrong reason is a control that cannot fire.'
        exit 0
    }
    Write-Host 'CONTROL FIRED: the second decoder refused the truncated APK, and refused it for a reason about the archive.'
    exit $rc
}
finally {
    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
}