# THE ONE COMMAND. Everything here used to be something somebody had to remember to run, and a
# check nobody runs is a check that does not exist. Three of these found real defects within a day
# of being written:
#
#   assert-probes.py          11 false drifts AND could be fooled by a 2-line stub
#   check-requires-tools.py   10 wrong precondition declarations, one of them a PowerShell probe
#                             that could never have run (a quoted path with no call operator)
#   doc-facts.py              a live false claim in the charter's own headline paragraph
#
# Each was correct, and each was silently checking nothing.
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$script:fail = @()

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "=== $Name" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) {
        $script:fail += "$Name (exit $LASTEXITCODE)"
        Write-Host "--- $Name FAILED" -ForegroundColor Red
    }
}

Step 'registry-verify'        { python scripts/registry-verify.py }
Step 'registry selftest'      { python scripts/registry-verify.py --selftest }
Step 'requires-tools'         { python scripts/check-requires-tools.py }
Step 'doc-facts (wiki drift)' { python scripts/doc-facts.py }
Step 'gate selftest'          { powershell -NoProfile -File scripts/gate.ps1 -Action Selftest }
Step 'mission selftest'       { powershell -NoProfile -File scripts/mission.ps1 -Action Selftest }
Step 'mission ablate'         { powershell -NoProfile -File scripts/mission.ps1 -Action Ablate }
Step 'reachability'           { python scripts/reachability-report.py }
# assert-probes runs real tools and takes ~15 min for a full sweep, so it is listed rather than
# run here and this command stays usable. Run it directly, or by id:
#   python scripts/assert-probes.py native.pe.packer native.pe.hardening
Step 'assert-probes --list'   { python scripts/assert-probes.py --list }

Write-Host ""
if ($script:fail.Count -eq 0) {
    Write-Host "VERIFY-ALL: every fast check passed. assert-probes still has to be run by hand." -ForegroundColor Green
    exit 0
}
Write-Host "VERIFY-ALL: $($script:fail.Count) FAILED -> $($script:fail -join ', ')" -ForegroundColor Red
exit 1