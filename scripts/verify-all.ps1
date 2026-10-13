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
$t0 = Get-Date
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# ARGUMENT REFUSAL. This script declares NO param block, so every argument it is handed lands in
# $args and is silently ignored -- the strongest form of the defect. Measured 2026-10-05 on this
# very script: `ghidra-failopen-regress.ps1 C:/nope/nothing.dll` printed LOOP CLOSED, 4 of 4
# green, exit 0, having measured nothing the caller asked for. A script that accepts an
# argument it cannot honour reports a pass for work nobody did.
. (Join-Path $PSScriptRoot 'assert-no-stray-args.ps1')
Assert-NoStrayArgs -ScriptName 'verify-all.ps1'
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
# assert-probes runs REAL tools. Until 2026-10-03 this line was `--list`, which runs nothing --
# and assert-probes is the ONLY reader of probe.prepare, probe.expect and probe.expect_exit, so
# the three fields the North Star rests on were executed only when a human typed the command while
# this script printed "every fast check passed" and exited 0.
#
# It now runs for a BOUNDED time and names every entry it did not run. A partial sweep that says
# so is worth having; a partial sweep that reports a green whole is worse than no sweep.
# Raise the budget (or run the entry by id) when you want the rest.
# --require-complete, added 2026-10-05. WITHOUT IT THIS STEP COULD NOT FAIL. Measured: a bounded
# sweep deferred 9 of 10 entries and assert-probes.py still exited 0, because it failed only on
# DRIFT or on nothing having run at all. This budget is 150 s while the 27 entries measure ~261 s,
# so entries were genuinely being skipped and the step reported green anyway. "One command judges
# both trees" must not be able to say OK about a capability it never looked at.
# Two entries cannot fit any useful budget: fuzz.differential.parse measures 195-663 s AND is
# load-sensitive (documented in its own runtime_note), and native.crosscompare.ghidra analyses the
# same binary with Ghidra twice, 143 s measured. Running them inside a shared budget is how
# --require-complete turns this script permanently red; leaving them out is how it goes green
# without looking at them. So they are named explicitly with timeouts that fit.
# 150 was measured wrong. On 2026-10-05 the first end-to-end run of this script reported
# BUDGET SPENT: 22 of 25 entries ran in 170s, 3 deferred -- forensics.memory.artefact,
# re.corpus.solve and mobile.apk.static -- and --require-complete refused, correctly. So the
# flag works and the budget was simply too small for the 25 entries that are NOT slow. 420 s
# is the measured margin, and if it ever defers again that is a fact about the tree rather
# than about this number.
Step 'assert-probes (bounded, completeness required)' { python scripts/assert-probes.py --budget 420 --timeout 300 --require-complete --skip-slow }
Step 'assert-probes fuzz.differential.parse (slow, load-sensitive)' { python scripts/assert-probes.py fuzz.differential.parse --budget 800 --timeout 800 }
Step 'assert-probes native.crosscompare.ghidra (slow, 2x Ghidra)' { python scripts/assert-probes.py native.crosscompare.ghidra --budget 400 --timeout 400 }
Step 'assert-probes --list'   { python scripts/assert-probes.py --list }

# WHAT THE REGISTRY CLAIMS THAT NOTHING READS, by name. This is a REPORT and exits 0 by design:
# a name search cannot see a generic reader, so `image_base`, `aslr`, `sections` and nine other
# `invoke.fact_map` SOURCE keys appear unread and are false positives. It is in the chain because
# every rule added on 2026-10-03 came from asking that question, and the question should be
# askable after any change rather than only when someone remembers.
Step 'unread registry keys (report)' { python scripts/scan-unread-keys.py }

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

# ---------------------------------------------------------------------------
# THE GATES NOBODY RAN. Measured 2026-10-03: six scripts in scripts/ that check something real and
# were invoked by NO command in the repository -- not here, not by each other, not by any task.
# Their authors each wrote a negative control, watched it fail, and shipped a proof that nothing
# executes. A check nobody runs does not exist, and this file's own header says so; the six
# contradicted it.
#
# Each line below names what the gate is FOR, because "wire it up" without a reason produces a
# chain nobody can audit and a future editor who removes the slow ones without knowing which are
# load-bearing.

# `sync-wiki-figures.py --check` is the one that most deserves to be here. Its writer had a FALSE
# GREEN: two of doc-facts' twelve claims derive through the validator, the writer never set
# `_REPO`, and it silently skipped them -- a wiki claiming 41 rules read as "already current" while
# doc-facts on the same bytes exited 1. A drift check that cannot detect drift is worse than no
# drift check, and this one is the one that would have caught it.
Step 'wiki figures in sync'    { python scripts/sync-wiki-figures.py --check }

# Two writers and two readers, so that neither can be correct alone. `--selftest` proves the gate
# can fail; the other proves it is right. Both are mutation-tested inside the harness itself.
Step 'wiki writer harness'     { python scripts/sync-wiki-figures-selftest.py }

# The tools manifest had 60 entries and no gate, so three binaries the code launches by absolute
# path -- skillspector.exe, vcvars64.bat, msedge.exe -- were declared nowhere. The gate now
# computes the union of BOTH input shapes (repo source and registry probe commands); 12 + 23 was
# never 35, because those sets overlap.
Step 'tools manifest'          { python scripts/verify-tools-manifest.py }
Step 'tools manifest selftest' { python scripts/verify-tools-manifest.py --selftest }

# 24 of 27 OK verdicts from assert-probes are STRINGS ONLY -- every entry declares an exit code
# and a substring, so no entry looks like an exception and the eye stops checking. A measurement,
# and it exits 0 whatever it finds: a grade B is a fact about what the registry declares, not a
# build failure. It is in the chain because the question should be askable after any change.
Step 'probe coverage (report)' { python scripts/verify-probe-coverage.py }

# On the STATION this exits 0. In a CLONE it exits 1, and that is correct: a clone ships 383 files
# and no corpus, so 14 capabilities name a path that is not there. A gate that passes in a clone
# would be the always-green failure again, one directory up. If this goes red and you are in a
# clone, read `README.md` -> "What a fresh clone does not have" before touching anything.
Step 'clone freshness'        { python scripts/verify-clone-freshness.py }

# 6 of 6 runs of a six-step loop killed mid-flight were accepted as PRODUCED with zero DRIFT: the
# artifact records nothing about the five steps that never ran. ~19 s because the control measures
# the write window and the kill latency that hide the truncation it cannot produce.
Step 'artifact atomicity'      { python scripts/verify-atomic-artifacts.py }

# NOT WIRED, AND THE REASON IS A REAL DEFECT, NOT AN OVERSIGHT.
# `scripts/assert-probes-selftest.py` reports 9 properties: 5 PROVEN and 4 BROKEN. BROKEN means a
# GAP that used to reproduce now comes back GREEN -- a gap this harness found and I then fixed --
# and the harness reports a fixed gap as BROKEN precisely so it gets PROMOTED to an assertion.
# Until those four are promoted the script exits 2 by design. Wiring it now would put a permanent
# red in the chain, and a permanently red gate is a gate people learn to ignore. It is named here
# so its absence is a decision with a reason rather than an oversight.

# THE WIKI TREE, MEASURED FROM HERE. Every other gate in this file lives in this repository and
# validates the wiki tree FROM THE OUTSIDE, via doc-facts.py reading numbers out of the manifests.
# The wiki tree itself contains zero .py and zero .ps1 files, so until these two lines existed the
# coupling ran one way only: change the station and the wiki can go red; change the wiki and
# nothing can. `arsenal-two-tree-check.py` closes the other direction. ~1 s, two rules, five
# controls.
#
# Its first run on the live tree was RED, which is why it earns the two lines: it found
# `methods/arsenal-clone.md` -- added by that wiki tree's own most recent commit, bd841bd --
# registered nowhere, plus six survey pages and a card template, plus a relative link in
# `methods/repo-discovery-method.md` pointing at a directory that has never existed. Eight pages
# and one broken pointer, none of which any command in either tree could see.
Step 'wiki tree structure'   { python scripts/arsenal-two-tree-check.py }
Step 'wiki tree selftest'    { python scripts/arsenal-two-tree-check.py --selftest }

# RULE ENFORCEMENT, not structure. `arsenal-two-tree-check.py` above asks "is the wiki tree
# internally coherent"; this asks "does anything the dossiers assert actually exist". It exists
# because `docs/research/ecosystem-2026-10-02.md` -- the most-cited dossier in the estate --
# cited eight worker reports **232 times** that were never written to disk, and 159 of those
# citations pointed past the end of any surviving copy. `docs/research/WORKER-REPORT-LOSS.md`
# has the loss table; 212 dead line numbers are now struck in place rather than deleted, and
# this gate refuses any NEW unstruck one.
#
# It also REPORTS, at zero cost, two things no gate owns: R10, forbidden paths the wiki tree has
# tracked anyway (`.agent/HANDOFF.md`, against its own AGENTS.md); and R11, the wired MCP
# backends whose only provenance is a `git` URL -- including the egress warning on the one that
# posts IOCs to a public API. Reports, not gates, because a permanently red gate is a gate
# people learn to ignore.
Step 'doctrine (R4 provenance)' { python scripts/arsenal-doctrine-check.py }
Step 'doctrine selftest'        { python scripts/arsenal-doctrine-check.py --selftest }

# MAINTENANCE DEBT, by name: unpushed commits, tracked-mod/untracked/ignored counts, dotgit
# size, top wiki pages by bytes, and every file over GitHub's 50/100 MiB lines. Report-only
# (exits 0 by design): these numbers had no gate anywhere until 2026-10-14, and a permanently
# red gate is a gate people learn to ignore. Exemptions print by name.
Step 'maintenance doctor (report)' { python scripts/maintenance-doctor.py }

$elapsed = (Get-Date) - $t0
Write-Host ""
Write-Host ("VERIFY-ALL wall clock {0:mm\:ss}. ONE command, BOTH trees: the station gate set plus" -f $elapsed)
Write-Host "  the wiki tree's own structure. Re-measure any single figure with its own command;"
Write-Host "  every row of wiki/INDEX.md carries the command that produces it."

Write-Host ""
if ($script:fail.Count -eq 0) {
    Write-Host "VERIFY-ALL: every check passed, INCLUDING the bounded probe sweep above." -ForegroundColor Green
    Write-Host "  The sweep is partial by design: read its NOT RUN list. The full sweep is" -ForegroundColor Yellow
    Write-Host "  `python scripts/assert-probes.py` and takes ~24 min, dominated by the fuzz loop." -ForegroundColor Yellow
    exit 0
}
Write-Host "VERIFY-ALL: $($script:fail.Count) FAILED -> $($script:fail -join ', ')" -ForegroundColor Red
exit 1