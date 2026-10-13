---
tags: [debugger]
status: observed
source: agent-notes 2026-10-12
---

# il2cpp-probe-no-target-parameter

il2cpp-probe.ps1 reports IL2CPP ABSENT for a runtime reason, not for a missing authorized artifact. Its status predicate is: available = have6 -and (behaviour -notmatch 'NO OUTPUT'). This host has no .NET 6, so have6 is false and the capability can never read present; the 'NO OUTPUT' term is dead code because none of the three behaviour strings contains that substring. The script takes no target parameter and never points Il2CppDumper at any artifact (it spawns once, answers stdin, waits 8 s, kills; stdout bytes 0), so supplying an Owner-named IL2CPP artifact cannot change the verdict. Separately, the -AsControl branch references an undefined variable Message while writing its artifact; Set-StrictMode makes that throw, ErrorActionPreference Continue lets the script exit 1 anyway, so the control's artifact is silently not written. Evidence: evidence/probes/native.il2cpp.symbols.probe.log and .control.log. Measured 2026-10-12, lane 128, board RM-20261012-L128.
