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

# scripts/mcp-probe.py drives scripts/arsenal_mcp_server.py with a REAL MCP client over stdio and
# proves two things nothing else here can: that a client which knows only a `mission_id` can run a
# granted capability, and that a refusal executes NOTHING (a `node.cmd` PATH shim sits first on the
# server's PATH and writes a sentinel instead of running). It was promoted into the repository on
# 2026-10-03 and was, for one commit, a proof nothing ran -- which is the defect this file exists to
# prevent, applied to itself.
#
# It is a Step and not a note because it takes ~8 s. It SKIPS, loudly and on the record, when the
# `mcp` package is absent, because that is a missing prerequisite rather than a passing check; a
# check that degrades to green when its instrument is missing is the failure mode doc-facts.py was
# just changed to refuse. It writes only under %TEMP%.
Step 'mcp surface' {
    # SINGLE quotes on purpose. With double quotes the native argument builder strips them and
    # python receives `-c import mcp`, which runs `import` as a statement and dies -- measured, and
    # it reported itself as "the mcp package is not installed", which is a false diagnosis of a
    # quoting bug. This is the same trap that made two frida controls SyntaxError earlier today.
    & python -c 'import mcp' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SKIP: the mcp package is not installed, so the MCP surface cannot be driven." -ForegroundColor Yellow
        Write-Host "      pip install mcp   # then re-run; a skipped proof is not a passing proof."
        # NOT `exit 0`. `exit` inside a scriptblock invoked with & leaves the WHOLE script, which
        # skipped the summary and returned 0 while a doc-facts failure was on the record -- a gate
        # reporting green because of something I added to it, measured, and exactly the class of
        # defect this file exists to catch.
        $global:LASTEXITCODE = 0
        return
    }
    python scripts/mcp-probe.py (Join-Path $repo 'scripts\arsenal_mcp_server.py')
}

Write-Host ""
if ($script:fail.Count -eq 0) {
    Write-Host "VERIFY-ALL: every fast check passed. assert-probes still has to be run by hand." -ForegroundColor Green
    exit 0
}
Write-Host "VERIFY-ALL: $($script:fail.Count) FAILED -> $($script:fail -join ', ')" -ForegroundColor Red
exit 1