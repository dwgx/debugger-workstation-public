---
tags: [debugger]
status: verified
source: agent-notes 2026-10-12
---

# il2cpp-probe-target-and-availability

il2cpp-probe.ps1 fixed 2026-10-12 (lane 137). Three defects, all measured.

(1) NO TARGET PARAMETER. The probe accepted only -HangBudgetSec and -AsControl, so it never
pointed Il2CppDumper at anything (stdout bytes: 0) and could not measure the capability. It
now takes -Target <path> [-Metadata <path>], runs the tool with DOTNET_ROLL_FORWARD, waits
HangBudgetSec and reports the exit code plus the first output lines. Measured against the
Owner-named artifact D:\Steam\steamapps\common\VRChat\GameAssembly.dll: tool exit -532462766,
first output "ERROR: Metadata file not found or encrypted." -- the metadata is encrypted,
which matches the Romantic project's own L87 finding.

(2) AVAILABILITY WAS A PROXY FOR NOTHING. The old line was
    $available = $have6 -and ($behaviour -notmatch 'NO OUTPUT')
The right half is dead: no $behaviour value contains the substring NO OUTPUT. The left half
gated on a 6.x runtime the net6 tool does not need under roll-forward. So the verdict was
really just "is .NET 6 installed". Now $available = $targetExists -and $ranOk, i.e. a target
was analysed AND the tool succeeded. With no -Target the probe prints [NOT-RUN] rather than a
verdict about a run that never happened.

(3) STALE STRING. It printed "TARGET: no authorized IL2CPP artifact exists on this host",
false since the Owner named IL2CPP artifacts on 2026-10-12 (<project>\Romantic AGENTS.md).
The string is gone from both the script and its output; the TARGET block now lists the
artifacts that DO exist.

Also fixed the $Message reference in the -AsControl branch (found by lane 128): it was
undefined, StrictMode threw VariableIsUndefined, and the control's artifact was silently
never written. The control now writes {ok:false, verdict:ABSENT, reason:"[NOT-RUN] ..."} to
probe-artifacts/last-run-il2cpp_probe.json.

Default polarity stays exit 0 and still prints IL2CPP ABSENT (smoke-all.ps1:62 depends on it).

Gates after the change:
  python scripts/assert-probes.py --budget 420 --timeout 300 --require-complete --skip-slow
      -> 25 entries; verdicts 22 OK, 3 SKIP; EXIT=0
  "%USERPROFILE%/.local/bin/skillspector.exe" scan skills --no-llm --fail-on-findings --fail-on-incomplete
      -> EXIT=0 (Recommendation SAFE)

Evidence: <project>\Romantic\work\l137\ and research/STATION-PROBE-GAPS.md.
