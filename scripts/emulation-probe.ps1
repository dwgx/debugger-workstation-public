#Requires -Version 5.1
<#
.SYNOPSIS
  Probe for Ghidra p-code emulation, and report honestly whether it works.

.DESCRIPTION
  Ghidra ships ghidra.app.emulator (EmulatorHelper, DefaultEmulator) and nothing in this
  repo used it. Emulation would turn a dynamic question -- "what does this decode to?" --
  into a static one, with no debugger, no process and no device.

  MEASURED 2026-09-30, and the answer is BLOCKED:

    * The API is reachable. EmulatorHelper and DefaultEmulator were instantiated against
      our own c01-stringobf, the harness compiled, and it ran 15 p-code steps.
    * The CONTROLLED-INPUT setup does not take. The scratch stack is not mapped, so the
      writes that carry the arguments and the return address did not land; the function
      returned to PC=0 and the output buffer was 48 bytes of zero.
    * Ground truth was NOT recovered. The corpus records FLAG{c01_string_table_xor} for
      c01, and the harness returned no decoded string.

  ANSWERED 2026-10-04, and it changes the decision rather than settling it: there IS a
  supported surface to build on. `ghidra.app.emulator.{EmulatorHelper,DefaultEmulator}` is
  superseded by `ghidra.pcode.emu.PcodeEmulator`
  (https://ghidra.re/ghidra_docs/api/ghidra/pcode/emu/PcodeEmulator.html), whose javadoc
  states its purpose plainly -- "a p-code machine which executes on concrete bytes",
  "a simple concrete bytes emulator suitable for unit testing and scripting".

  Its `inject(Address, String)` is where this probe's bug is named: "The inject will need to
  replicate the semantics of that call to the desired fidelity. IMPORTANT: The inject must also
  return control to the calling function, usually by replicating the conventions of the target
  platform." The scratch stack was never mapped, so the argument and return-address writes did
  not land and execution returned to PC=0. The old helper did not make that obligation visible;
  the new API states it. `createSharedState()` returns a `BytesPcodeExecutorState` whose
  platform convention is the caller's job, and `checkLoad`/`checkStore` on
  `AbstractPcodeMachine` exist to assert a store was legal.

  SO the blocker is no longer "is this surface going away" -- it is "the successor exists and
  the fix is to write against it, mapping the stack per the target platform's convention." That
  is buildable work and it is the recommended route. Recorded in this header because this file
  is where a session re-reading the blocker will look, not because a wiki page says so.

  Recorded as state=blocked in manifests/capabilities.json rather than claimed.

  CONTROL MODE (-AsControl), added 2026-10-03
  ----------------------------------------
  The probe above answers a RESEARCH question and always exits 0, because the
  capability's own probe contract is `expect: "PCODE EMULATION BLOCKED", exit: 0`
  -- the script's job is to RECORD the outcome, not to gate on it. That is why
  this file could never serve as a negative control: a script that exits 0 in
  both directions cannot fail.

  -AsControl turns the SAME ground-truth comparison into the gate. The verdict
  still comes from the harness, which compares the decoded string against
  FLAG{c01_string_table_xor} -- deliberately, because c01 ships that string in
  plaintext in .rdata as a decoy, so "looks like a flag" is not evidence. With
  the switch:

    verdict MATCHES_GROUND_TRUTH -> exit 0   (the capability really works)
    anything else (MISMATCH / NO_OUTPUT / ERROR / no artifact) -> exit 1

  Without the switch, behaviour is byte-for-byte unchanged.
#>
[CmdletBinding()]
param(
    [int]$BudgetMs = 300000,
    [switch]$AsControl
)

$sw = [System.Diagnostics.Stopwatch]::StartNew()

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ah  = Join-Path $RepoRoot 'Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat'
$bin = Join-Path $RepoRoot 'crackme-corpus\out\c01-stringobf.exe'
$out = Join-Path $env:TEMP 'emu-probe-out'
$proj = Join-Path $env:TEMP ('emu-probe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $out, $proj | Out-Null
# A control must not be able to pass on a PREVIOUS run's artifact. The harness
# writes emulation.json into a fixed TEMP dir that survives across runs, so a run
# in which Ghidra never started would otherwise read the last good verdict and
# report success. Delete it first, then let the harness recreate it.
Remove-Item (Join-Path $out 'emulation.json') -Force -ErrorAction SilentlyContinue

# c01's main() calls sub_140001000(&unk_140017330, 18, 11, 90, Str2)
& $ah $proj agent -import $bin -overwrite `
    -scriptPath (Join-Path $RepoRoot 'scripts\ghidra') `
    -postScript EmulateDecode.java 0x140001000 0x140017330 18 11 90 0x140030000 `
                'FLAG{c01_string_table_xor}' 200000 $out 2>&1 | Out-Null

$art = Join-Path $out 'emulation.json'
$result = $null
if (Test-Path $art) { try { $result = Get-Content $art -Raw | ConvertFrom-Json } catch { } }

Write-Host ('=' * 78)
if ($result -and $result.verdict -eq 'MATCHES_GROUND_TRUTH') {
    Write-Host ("PCODE EMULATION WORKS: recovered '" + $result.decoded + "' in " + $result.steps + " steps")
    Write-Host 'JSON-SUMMARY {"total":1,"pass":1,"fail":0}'
    exit 0
}

Write-Host 'PCODE EMULATION BLOCKED -- recorded, not claimed.'
if ($result) {
    Write-Host ("  steps executed   : " + $result.steps)
    Write-Host ("  decoded          : " + $(if ($result.decoded) { $result.decoded } else { 'null' }))
    Write-Host ("  expected         : " + $result.expected)
    Write-Host ("  output non-zero  : " + $result.output_non_zero)
    Write-Host ("  error            : " + $result.error)
} else {
    Write-Host '  the harness produced no artifact at all'
}
Write-Host ''
Write-Host '  The API is reachable and ran. What does not work is the controlled-input'
Write-Host '  setup: the scratch stack is not mapped, so the argument and return-address'
Write-Host '  writes did not land. That is our bug, not a Ghidra limitation.'
Write-Host ''
Write-Host '  DEPRECATION, and this outranks the blocker: javac reports EmulatorHelper and'
Write-Host '  DefaultEmulator as deprecated and marked for removal. Before fixing the'
Write-Host '  setup, decide whether to build on an API Ghidra intends to delete.'
if ($AsControl) {
    Write-Host ''
    Write-Host ('  NEGATIVE CONTROL native.ghidra.emulate.must_not_claim_success')
    Write-Host ('  expected verdict : MATCHES_GROUND_TRUTH')
    Write-Host ('  observed verdict : ' + $(if ($result) { $result.verdict } else { 'NO_ARTIFACT' }))
    Write-Host ('  wall time        : ' + [math]::Round($sw.Elapsed.TotalSeconds, 1) + ' s  (harness step budget is the literal 200000 p-code instructions above; $BudgetMs is NOT wired to the harness and changes nothing)')
    Write-Host '  exit 1 -- the capability is NOT allowed to claim success.'
}
Write-Host ('=' * 78)
Write-Host 'JSON-SUMMARY {"total":1,"pass":0,"fail":1}'
if ($AsControl) { exit 1 }
exit 0
