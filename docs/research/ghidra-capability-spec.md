# Ghidra capability spec

Research date **2026-09-30**. Author: `GhidraSpec`. Machine: `D:\Software\Tool\WorkStation\debugger`
(the clone), Ghidra 12.1.3, Windows 10.0.26300 x64.

**Scope of claims in this document.** Every number, path and line reference below was
read or executed on this box. The commands that produced them are in §6 and are
re-runnable. Where something could not be verified it says `[UNVERIFIED]` and the
capability is registered `state: "absent"` or `state: "degraded"` — never as a
confident entry, because a confidently wrong registry entry is worse than an absent
one: the orchestrator routes missions to it.

Companion design doc: `.agent\research\orchestration-design.md` §3 (the
`capabilities.v1` schema). This document supplies the Ghidra column of that registry
and nothing else — it does not re-specify the schema.

---

## 1. Part 1 — our own Ghidra, measured

### 1.1 Which Ghidras exist, and which the scripts use

Two installs, both verified headless-capable:

| install | `application.version` | headless `support\analyzeHeadless.bat` | verified by running it |
|---|---|---|---|
| `Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC` | `12.1.3` | yes | yes — §1.6 |
| `Static-Reversing\Ghidra\ghidra_12.1.2_PUBLIC` | `12.1.2` | yes | yes — 29 s, `{"functions":512,"decompiled":512}` |

Version strings read from each install's `Ghidra\application.properties`.

**There is no Ghidra 11.3.2 on this box.** The brief said there was. I searched
`C:\`, `D:\` and `E:\` to depth 6–7 for any directory matching `ghidra_11*` and found
none; the only `ghidra_*` directories on the machine are the two above, plus
`%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC` (per-user settings, not an install). The
brief's "Ghidra 11.3.2 also installed" is **wrong**, and the registry must not carry a
second-version fallback. The real second version is **12.1.2**, and it is a different
situation: 11.3.2 would have been an *older* major-minor with different APIs, 12.1.2 is
a patch-adjacent sibling.

**The scripts use 12.1.3 only, and fail closed on its absence.** `scripts\ghidra-headless.ps1:22`
hardcodes the 12.1.3 path; line 23 `throw`s if it is missing. There is no version
discovery, no 12.1.2 fallback, no `GHIDRA_INSTALL_DIR` env lookup. Consequence for the
registry: `native.*.ghidra` entries have a hard `tools[]` probe on
`…\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat`, and a box with only 12.1.2 must
report those capabilities `absent` even though 12.1.2 would work.

Other Ghidra-adjacent things we own, for the record:

- `mcp\GhidraMCP` — LaurieWired GhidraMCP, Apache-2.0, vendored clone with a `.venv`.
  It is a **CodeBrowser GUI plugin** plus a `bridge_mcp_ghidra.py` HTTP bridge. It is
  not a headless capability and is not wired into the router.
- `mcp\debugger-router\server.py:25` carries a `ghidra` backend as a **stub** —
  `{"category": "static-reversing", "note": "Ghidra project/plugin backed analysis."}`
  with no command, no probe, no health check. The router's `ghidra` backend must not
  be counted as a capability until it has one.
- `manifests\mcp-backends.json` already records `bethington/ghidra-mcp` as a fork of
  LaurieWired's GhidraMCP. That record is accurate (confirmed in §2.2).

### 1.2 The AutoVersionTrackingScript claim: **VERIFIED**

The brief asked me to verify, not to trust. The claim holds, in all three parts.

**File present in both installs:**
`Ghidra\Features\VersionTracking\ghidra_scripts\AutoVersionTrackingScript.java`
(16,372 bytes, 359 lines), shipped by NSA upstream, Apache-2.0 header at lines 1–15.

**Part 1 — the header documents a headless, non-shared-project invocation.**
`…\ghidra_12.1.3_PUBLIC\Ghidra\Features\VersionTracking\ghidra_scripts\AutoVersionTrackingScript.java:27-41`:

```
27: // HEADLESS MODE NON-SHARED PROJECT:
32: //    <ghidra_install>/support/analyzeHeadless.bat/sh c:/MyGhidraProjectFolder
33: //     MyProjectName/OptionalFolderContainingDestProgram -process DestinationProgram.exe -postScript
34: //     MyOptionsSetupScript -postScript AutoVersionTrackingScript.java "/FolderContainingSession"
35: //     "MySessionName" "/OptionalFolderContainingSourceProgram/SourceProgram.exe"
```

**Part 2 — it opens the source program around line 171.** Same file,
`:171-180`:

```java
171:  DomainFile sourceProgramDF =
172:      startupValues.getProjectFile("Please select the SOURCE program");
...
179:  Program sourceProgram =
180:      (Program) sourceProgramDF.getDomainObject(this, autoUpgradeIfNeeded, false, monitor);
```

That is a second `Program` object, materialised from a `DomainFile`, live in the same
process as `currentProgram` (the destination). The script then builds a
`VTSessionDB` over both at `:187`, runs `AutoVersionTrackingTask` at `:217-219`, and
saves the destination at `:222`.

**Part 3 — I ran it.** Not just read it. Setup and result:

- staged a copy of `AutoVersionTrackingScript.java` +
  `SetAutoVersionTrackingOptionsScript.java` + a hand-written
  `AutoVersionTrackingScript.properties` in
  `%TEMP%\ghcap-vt-20260930\scripts` (we must not write into the install);
- imported `c01-stringobf.exe` and `c02-cff-dispatch.exe` into one non-shared project
  (`analyzeHeadless <proj> vtproj -import a b`, 27 s, project 8,881,907 B);
- ran `analyzeHeadless <proj> vtproj -process c01-stringobf.exe -noanalysis
  -scriptPath <tmp> -postScript SetAutoVersionTrackingOptionsScript.java
  -postScript AutoVersionTrackingScript.java`.

Result, 7 s wall:

```
INFO  Reading script properties file: …\AutoVersionTrackingScript.properties (GhidraScriptProperties)
INFO  /vt_probe: file created (owner) (LocalFileSystem)
INFO  AutoVersionTrackingScript.java> Auto Version Tracking Command completed
      successfully with no apply markup errors. (GhidraScript)
INFO  REPORT: Save succeeded for processed file: /c01-stringobf.exe
```

**So: real cross-binary matching — exact, reference, and BSim correlators — is
available with nothing installed.** All three families ship in the install
(`Ghidra\Features\VersionTracking\lib\VersionTracking.jar`,
`Ghidra\Features\VersionTrackingBSim\lib\VersionTrackingBSim.jar`,
`Ghidra\Features\BSim\lib\BSim.jar` + `h2-2.2.220.jar`, plus `support\bsim`,
`support\bsim_ctl` CLIs).

### 1.3 Three things the shipped script's own header gets wrong

Recording these because they are the difference between a working capability and a
silent no-op, and each cost me a failed run.

**(a) `NUM_ARGS = 3` is declared at `:107` and never used.** `grep` over the file finds
no `getScriptArgs()` anywhere in it. The 3 command-line arguments the header documents
(`"/FolderContainingSession" "MySessionName" "/SourceProgram.exe"`) are **not read by
the code as shipped**.

**(b) The real headless input is `askValues`, and it is keyed by `"<title> <variable>"`.**
`run()` calls `askValues("Enter Auto Version Tracking Information", …)` at `:159-161`.
My first attempt used bare keys in the `.properties` file and got:

```
ERROR REPORT SCRIPT ERROR: java.lang.IllegalArgumentException: Error processing variable
'Enter Auto Version Tracking Information Version Tracking Session Name' in headless mode
-- it was not found in script arguments or a .properties file.
	at ghidra.app.script.GhidraScript.loadAskValue(GhidraScript.java:1986)
```

The required file is therefore:

```properties
Enter Auto Version Tracking Information Version Tracking Session Folder = /
Enter Auto Version Tracking Information Version Tracking Session Name = vt_probe
Enter Auto Version Tracking Information Please select the SOURCE program = /c02-cff-dispatch.exe
```

The co-located-`.properties` mechanism is documented by Ghidra itself in
`Ghidra\Features\Base\ghidra_scripts\AskScript.java:39-44` and
`AskScript.properties` (which has `Please choose a program to open. = /act.exe`,
i.e. the project-file path form). The second shipped example is
`Ghidra\Features\BytePatterns\ghidra_scripts\DumpFunctionPatternInfoScript.properties`.
Program paths are project-relative: `/<program-name>`.

**(c) Positional script args are consumed *before* the `.properties` file, and
consumption is per-`askXxx`-call, in call order.** I found this the hard way: a probe
script whose only script argument was an output directory had that directory consumed
by its first `askProgram("V1_Version1")`, producing
`java.lang.IllegalArgumentException: Invalid DomainFile: /C:\…\out`. So a
`ghidra-rpc`-style "one program arg, one options arg" design silently mis-wires. Any
registry entry that drives a Ghidra `askXxx`-based script must state the **argument
consumption order** as part of its contract, and must not pass a trailing options
argument to a script that calls `askXxx`.

This is why I do **not** recommend `AutoVersionTrackingScript` as the registry's
cross-binary entry. `ghidra.feature.vt.AbstractGhidraVersionTrackingScript` is strictly
better for automation — see §3.6.

### 1.4 The `DiffPrograms.java` justification is void — and its inputs are broken

`scripts\ghidra\DiffPrograms.java:6-12` states:

> *"Why manifests instead of opening the second program in-process: Ghidra 12 has no
> framework-level ProgramManager, so a headless script cannot open a sibling program
> from the same project."*

**This is false**, twice over:

1. `AutoVersionTrackingScript.java:171-180` does exactly the thing it claims is
   impossible, in the same Ghidra 12.1.3, in headless mode (§1.2).
2. I wrote a throwaway `VtProbe` extending `AbstractGhidraVersionTrackingScript` and ran
   it with **three** programs open in one headless process — `currentProgram`
   (`c03_antidebug.exe`, the `-process` target) plus `askProgram()`-resolved
   `c01-stringobf.exe` and `c02-cff-dispatch.exe` — and it enumerated and ran all 14
   program correlators across the latter two. Wall time 14–17 s.

Beyond the void justification, **the two-manifest workaround does not currently run**:

```
FunctionHashes.java:37: error: non-static variable currentProgram cannot be
                       referenced from a static context
			currentProgram.getMemory().getBytes(body.getMinAddress(), buf);
...
skipping D:\…\scripts\ghidra\FunctionHashes.java
skipping D:\…\scripts\ghidra\HeadlessMcpHttp.java
ERROR REPORT SCRIPT ERROR: FunctionHashes.java : The class could not be found.
  … ClassNotFoundException: FunctionHashes not found
```

`FunctionHashes.bodyHash(AddressSetView)` is `private static` (`FunctionHashes.java:30`)
and touches the inherited instance field `currentProgram` at `:37`. The fix is to drop
`static`. Until then it has **never compiled and never run** — which is one step worse
than the `headless-lab\README.md:134-137` position ("never been executed"; it had not
been compiled either).

Two structural consequences for the registry:

- **A Ghidra script directory is compiled as a unit and any member that fails to
  compile is silently `skipping`-ed.** Ghidra compiled `ExportDecompile.java` and
  `DiffPrograms.java` fine in the same invocation that `skipping`-ed the other two, and
  the run still reported `INFO REPORT: Post-analysis succeeded`. A broken sibling does
  not fail the run; it makes *that one script* vanish. A registry `probe` that only
  checks `summary.json` existence would have passed this run. The probe must check the
  specific artifact the entry claims to produce.
- Because `HeadlessMcpHttp.java` (35 KB) shares `scripts\ghidra\` and has two compile
  errors of its own (§1.7), any new postscript added to that directory inherits the
  risk. **The registry's postscript entries should each get their own `-scriptPath`
  directory**, one `.java` per directory, so a compile failure is unambiguous.

### 1.5 The Emulation framework: path corrected, and **not reachable from a postscript**

**Path correction.** The brief said `Emulation/Framework/lib/Emulation.jar`. The real
path is `Ghidra/Framework/Emulation/lib/Emulation.jar` — Framework, not Features.
Verified in both installs (1,271,831 bytes in 12.1.3). It ships
`ghidra/app/emulator/EmulatorHelper`, `DefaultEmulator`, `ProgramLoadImage`,
`ghidra/pcode/emu/*` (PcodeEmulator, PcodeStateInitializer, SleighInstructionDecoder…)
plus ASM 9.7.1.

`EmulatorHelper(Program)` has exactly the API a static-analysis capability would want:
`run(Address, ProcessorContext, TaskMonitor)`,
`readRegister/writeRegister`, `readMemory/writeMemory`, `readStackValue`,
`setBreakpoint/clearBreakpoint`, `registerDefaultCallOtherCallback`,
`getExecutionAddress`, `getLastError`.

**Nothing we own uses it.** `grep -ril "emulat"` across `scripts\`, `headless-lab\`,
`crackme-corpus\` returns only `scripts\floss-agent.ps1` and `scripts\mobile-lab.ps1`
(both incidental word matches) and the stored `analyzeHeadless.log` files under
`crackme-corpus\out\*-ghidra\`. No Emulation API, no `EmulatorHelper`, no
`PcodeEmulator` anywhere in the station.

**Reachability test — it fails.** I wrote a throwaway `EmuProbe.java` importing
`ghidra.app.emulator.EmulatorHelper` into a `-scriptPath` outside the install, and ran
it against `c01-stringobf.exe`:

```
ERROR REPORT SCRIPT ERROR: EmuProbe.java : The class could not be found. …
  ghidra.app.script.GhidraScriptLoadException: The class could not be found.
  …: Failed to get OSGi bundle containing script: …\scripts\EmuProbe.java
Caused by: java.lang.ClassNotFoundException: Failed to get OSGi bundle containing script
```

It compiled; the **class load** failed. I isolated the cause with a control script
importing only `ghidra.framework.model.Project`: it fails identically. The A/B is:

| script location | imports | result |
|---|---|---|
| in-tree `Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java` | `ghidra.framework.model.DomainFile` | **works** (ran, created a VT session) |
| out-of-tree `%TEMP%\…\VtProbe.java` | `ghidra.feature.vt.*`, `ghidra.program.model.listing.*` | **works** (ran all 14 correlators) |
| out-of-tree `%TEMP%\…\OsgiProbeA.java` | `ghidra.framework.model.Project` | **fails** — OSGi bundle not found |
| out-of-tree `%TEMP%\…\EmuProbe.java` | `ghidra.app.emulator.EmulatorHelper` | **fails** — OSGi bundle not found |

An out-of-tree script can only reach packages already wired into the headless script
classloader, and `ghidra.app.emulator` is not among them. `Emulation.jar` also ships no
manifests that export the package for script bundles (its `META-INF/MANIFEST.MF` is the
four-line stub, and its `Module.manifest` lists only ASM licences).

**Therefore `native.ghidra.emulate` — the id that shipped — is registered `state:
"blocked"`, not `absent`.** `absent` says the route does not exist; `blocked` says the
route runs and the ground truth was not recovered. The shipped probe
(`powershell -File scripts\emulation-probe.ps1`) reached `EmulatorHelper` and
`DefaultEmulator`, compiled and ran them, and executed **15 p-code steps**, then
returned to PC=0 with the 48-byte output buffer all zero —
`FLAG{c01_string_table_xor}` NOT recovered. What fails is the controlled-input setup,
not the API. `EmulatorHelper` / `DefaultEmulator` are also deprecated and marked for
removal, so this is worth deciding *before* the blocker is fixed.

The postscript finding below still stands for the route it measured. Reaching
`EmulatorHelper` from an out-of-tree `-postScript` requires either writing a script into
a module's `ghidra_scripts` directory inside the install (a brief-then-follow change to
an installed tool, and forbidden by this assignment's read-only constraint), or
building a Ghidra Extension with a `Module.manifest` that declares the `Emulation`
dependency — which is an install-class operation and an Owner decision. I am not writing
that spec blind: it would be a confidently wrong entry.

Note the contrast with Ghidra's own shipped `Ghidra/Debug/Debugger/ghidra_scripts`
(`PopulateDemoTrace.java`) — in-tree, therefore reachable, and the reason the framework
works from the GUI at all.

### 1.6 Cost of one headless run — measured

Three independent wall-clock samples, same target
(`crackme-corpus\out\c01-stringobf.exe`, 140.5 KB, MSVC x64 PE, 512 functions,
`md5 bbdf427148f7774b75f938e884ec66eb`):

| # | command path | wall | notes |
|---|---|---|---|
| 1 | `scripts\ghidra-headless.ps1` (bash-tool wall, includes post-measurement `du`/`find`) | ~25 s | inflated by the harness |
| 2 | `scripts\ghidra-headless.ps1`, `date +%s%N` bracketed | **19.08 s** | |
| 3 | same, via `Start-Job` + peak-RAM sampler | **18.05 s** | authoritative |

Inside run 3, Ghidra's own log reports `Total Time   9 secs` for auto-analysis. The
other ~9 s is JVM start, class searcher (`Class search complete (507 ms)`), headless
startup (`Headless startup complete (1422 ms)`), and writing 512 files.

| resource | measured | how |
|---|---|---|
| wall, import + analyze + export 512 functions | **18–20 s** | 3 samples, run 3 = 18.05 s |
| wall, auto-analysis alone | **8–10 s** | `Total Time` in `analyzeHeadless.log` |
| wall, `-import` of 2 programs | 27 s | §1.2 setup |
| wall, `-process … -noanalysis -postScript <VT probe>` | 14–17 s | VT runs: 16 s, 17 s, 14 s, 15 s |
| wall, `AutoVersionTrackingScript` end to end | **7 s** | 1.4 s of it is headless startup |
| wall, 12.1.2 doing the same as 12.1.3 | 29 s | first-touch; 12.1.3 on the same day = 18 s |
| **peak JVM working set** | **1,085.7 MB** | `Get-Process java` sampled at 150 ms during run 3 |
| export artifact size | **673,090–673,220 B**, 522 files | 512 `.c` + 10 meta files |
| retained project, 1 analyzed program | **3,621,968 – 4,457,571 B** | four retained projects measured |
| retained project, 2 analyzed programs | **8,881,907 B** | §1.2 setup project |
| project after `-deleteProject` | **0 B** (directory remains) | run 3 |

**On disk budgeting — a correction to the brief's framing.** Free-space *deltas* on this
box are worthless: one measurement showed a 633,988 KB (≈619 MB) C: delta for a 29 s
run that wrote 673 KB, because a sibling agent's lab was consuming C: concurrently. A
second showed a 5,256 KB delta for the same run. **Every disk figure in this document is
a direct `du -sb` / `Get-ChildItem | Measure-Object Length -Sum` of the artifact**, never
a `df` delta. E: is irrelevant to this measurement: `analyzeHeadless` puts its project
under `$env:TEMP` (C:), and I did not redirect it.

**Two leaks the orchestrator must budget for**, both measured on `%TEMP%` before I
started:

- 30 `ghidra-proj-*` directories already existed, 26 empty and **4 non-empty at
  ~3.5 MB each** (~14 MB stranded) — leftovers from earlier `-PostScript`/`-Http` runs,
  because `scripts\ghidra-headless.ps1:41` only adds `-deleteProject` on the
  no-`PostScript`, no-`Http` path.
- The default path deletes the *contents* but leaves the empty *directory* behind, every
  run. `scripts\ghidra-headless.ps1:31-32` creates `$projRoot` under `%TEMP%` and
  nothing ever removes it. 26 empty directories is exactly that pattern.

**Fail-open found while measuring — registry-relevant.** `analyzeHeadless.bat` returns
**exit 0** when the import fails outright:

```
=== CASE 1: plain text file
INFO  No load spec found for import file: plain.txt (ProgramLoader)
ERROR The ProgramLoader could not successfully load file:///…\plain.txt …
ERROR REPORT: Import failed for file: file:///…\plain.txt
CASE1_EXIT=0
CASE1_SUMMARY_ABSENT
=== CASE 2: zero byte file
INFO  No load spec found for import file: empty.bin (ProgramLoader)
…
CASE2_EXIT=0
CASE2_SUMMARY_ABSENT
```

Ghidra does the right thing at the artifact level — no `summary.json` is written, so
there is no fake success to read. But the process exit code is 0, and
`scripts\ghidra-headless.ps1` then reports `{"ok":false,…,"exit":null}` **and itself
exits 0**, because line 89/97 do `exit $p.ExitCode` and `$p.ExitCode` is `$null` under
`Start-Process -PassThru` + `WaitForExit(<int>)` (the .NET handle-caching quirk). I
confirmed the whole chain: the wrapper's PowerShell process exit code is 0 on a
refused import.

**Consequence:** no Ghidra registry entry may declare `expect_exit` as its success
criterion. Ghidra entries gate on **`ok:true` in the JSON payload plus the presence of
the entry's own named artifact**. Any entry that trusts the exit code will route a
mission into a run that produced nothing and report success.

### 1.7 `HeadlessMcpHttp.java` does not compile — the resident-HTTP capability is dead

The 12.1.3 `-Http` path of `scripts\ghidra-headless.ps1` drives
`scripts\ghidra\HeadlessMcpHttp.java` (35.2 KB, 571 lines) as the postscript for the
router's `ghidra` backend. It has two hard compile errors on Ghidra 12.1.3:

```
HeadlessMcpHttp.java:610: error: for-each not applicable to expression type
        for (PcodeOp op : res.getHighFunction().getPcodeOps()) {
  required: array or java.lang.Iterable
  found:    java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST>

HeadlessMcpHttp.java:703: error: cannot find symbol
        return currentProgram.getPointerSize();
  symbol:   method getPointerSize()
  location: variable currentProgram of type ghidra.program.model.listing.Program
```

Plus five `[removal]` deprecation warnings (lines 157, 162, 383 ×2, 567).

`headless-lab\README.md:126-127` claims this was *"found and fixed by compiling it"* —
`DecompileResults` has no `getPcode()`, it is `getHighFunction().getPcodeOps()`. That
substitution is right, but `getPcodeOps()` returns an `Iterator`, so the for-each is
still invalid. The second error is not mentioned in the README at all. The README's
`:70-79` table marks `/pcode`, `/cfg`, `/create_struct`, `/list_structs`,
`/resolve_type` "written, compile unverified" and the three formerly-stubbed routes
"implemented" — measured state is **compile failed**, so `/pcode`, `/cfg`,
`/create_struct`, `/list_structs`, `/resolve_type`, `/renameVariable`,
`/set_function_prototype` and `/set_local_variable_type` have **never returned a value
and cannot**.

Registered as `ghidra.resident.http`, `state: "degraded"` (§3.9).

### 1.8 What `ExportDecompile` actually emits — the triage fact shapes

Read from a real run against `c01-stringobf.exe`, `outdir` 673 KB / 522 files:

| file | shape | observed on c01 |
|---|---|---|
| `summary.json` | `{"ok":true,"tool":"ghidra","program":…,"language":…,"functions":N,"decompiled":N,"outdir":…}` | `language: x86:LE:64:default`, `functions: 512`, `decompiled: 512` |
| `segments.txt` | `<name>: <start> - <end>` | 8 lines: `Headers: 140000000 - 1400003ff`, `.text: 140001000 - 1400167ff`, …, `tdb: ff00000000 - ff0000184f` |
| `imports.txt` | `<Name> -> <space>` | 76 lines: `RtlCaptureContext -> EXTERNAL:00000001` |
| `exports.txt` | `<name> -> <va>` | 1 line: `entry -> 1400015d0` |
| `functions.txt` | `<name> @ <va>` | 512 lines: `FUN_140001000 @ 140001000`, `printf @ 140001260` |
| `strings.txt` | `<va> <string>` | 291 lines; first is `140017368 FLAG{c01_strings_gave_you_this_decoy}` |
| `decompiled/<safeName>.c` | Ghidra C output, or `// decompile failed; disassembly fallback` | 512 files |

The `FLAG{…}` on line 1 of `strings.txt` is the corpus's **own decoy** — the string the
challenge plants to punish a mission that stops at the first flag-shaped constant. It is
the best available negative control for the string capability and I use it as one.

### 1.9 The correlators this install actually offers — measured

From a `VtProbe` extending `AbstractGhidraVersionTrackingScript`, calling
`getProgramCorrelators()` and running each. **14** program correlators (counted: 14
`CORRELATOR … -> N matches` lines in the log, 14 names in the TSV header), on
`x86:LE:64:default` vs `x86:LE:64:default`:

| correlator | c01 vs c02 (related) | c01 vs **byte-identical copy** | c01 vs c05 (unrelated) |
|---|---:|---:|---:|
| BSim Function Matching | 460 | 461 | **461** |
| Combined Function and Data Reference Match | 0 | 0 | 0 |
| Data Reference Match | 0 | 0 | 0 |
| Duplicate Data Match | 224 | 940 | 187 |
| Duplicate Function Instructions Match | 114 | 114 | 116 |
| Duplicate Exact Symbol Name Match | 148 | 85 | 134 |
| Exact Data Match | 439 | 1052 | 393 |
| **Exact Function Bytes Match** | **135** | **463** | **163** |
| Exact Function Instructions Match | 411 | 413 | 410 |
| Exact Function Mnemonics Match | 394 | 396 | 393 |
| Function Reference Match | 0 | 0 | 0 |
| Similar Data Match | 39183 | 39722 | 36446 |
| Similar Symbol Name Match | 103 | 103 | 103 |
| Exact Symbol Name Match | 379 | 388 | 379 |

Three findings the registry has to carry, because a capability that reports all four
columns as "matches" is worse than one that reports none:

1. **`BSim Function Matching` does not discriminate on this corpus, and must not be
   sole evidence.** It returns 461 matches against a *byte-identical copy* and 461
   against a *completely different challenge* (c05), with 458 of 461 rows at similarity
   `1.000` and `src_len == dst_len` on all 461, a clean 1:1 permutation. Top confidence
   is 128.761 (identical) vs 103.346 (unrelated) — the same order of magnitude. The
   shared MSVC CRT saturates the signature. This holds **without a BSim database**;
   the correlator is present and runs, it is just not evidence on stripped PEs sharing a
   toolchain. A real BSim verdict needs a database built by
   `Ghidra/Features/BSim/ghidra_scripts/CreateH2BSimDatabaseScript.java` +
   `AddProgramToH2BSimDatabaseScript.java` over a reference corpus — a separate
   capability with its own disk cost, not a freebie.
2. **`Function Reference Match` and `Data Reference Match` return 0 on every pair
   here.** They need reference data these PEs do not carry. An entry that promises
   reference-correlator output for arbitrary binaries would be wrong.
3. **What does discriminate on this corpus**: `Exact Function Bytes Match`
   (463 / 135 / 163) and `Duplicate Data Match` (940 / 224 / 187). Both separate
   "same build" from "different build". Neither separates "related challenge" from
   "unrelated challenge" well, because 410 of 512 functions are byte-identical across
   *all* of them (`Exact Function Instructions Match`: 411 / 413 / 410). **Any verdict
   of the form "these two builds are the same" must come from a narrow slice, not from
   a whole-program match count** — which is invariant 2 of the analysis loop, now with
   a number attached.

### 1.10 Sibling research

`.agent\research\orchestration-design.md` §3.2 fixes the schema. Two of its own worked
examples are Ghidra capabilities — `native.decompile.ghidra` (round 3) and
`native.diff` (Q7.origin) — so I keep those exact ids where they fit and extend rather
than invent parallel names.

---

## 2. Part 2 — prior art

Both repos cloned `--depth 1` into
`%USERPROFILE%\AppData\Local\Temp\re-research\GhidraSpec\` (outside both repos), read,
not vendored, not installed.

### 2.1 `cellebrite-labs/ghidra-rpc`

Python package + CLI (`ghidra_rpc` 0.2.0, `pyproject.toml`), **11,485 lines** across
35 `.py` files, plus a 582-line `SKILL.md` and a 23 KB `AGENTS.md`. Dependencies:
`pyghidra>=2.2.1`, `click>=8.1.0`, `jpype1>=1.5.0`.

**Still no `LICENSE` file in the repository** — `ls` at the repo root returns only
`.editorconfig .env.template .github .gitignore .pi AGENTS.md CHANGELOG.md CLAUDE.md
CONTRIBUTING.md LICENSE README.md ROADMAP.md SECURITY.md build.gradle docker docs …`
for ghidra-mcp; for ghidra-rpc the root is `.github .gitignore .pi AGENTS.md
CHANGELOG.md CLAUDE.md README.md SKILL.md docs ghidra_rpc package.json pyproject.toml
tests`. `headless-lab\README.md:22-24` is correct. I add one thing it does not say: the
same repo is referenced by `manifests\mcp-backends.json` as a hazard class
("两个 dnSpy 仓库上游未声明 license(默认保留全部权利)"), so a second unvendored
vendor clone is a standing Owner decision, not a lab decision.

**How it keeps the program open.** Not via `analyzeHeadless`. `pyghidra` + JPype start
the Ghidra JVM **inside the Python daemon process**; `HeadlessContext.__init__`
(`server/context.py:177-201`) opens a `GhidraProject` once, and
`HeadlessContext.load_binary` (`:222-362`) imports, analyzes, saves, and then **holds
the live `Program` object** in `self.programs: dict[str, ProgramInfo]` (`:182`) for the
lifetime of the daemon. Each `ProgramInfo` (`:24-36`) carries the `Program`, a
`FlatProgramAPI`, and a `DecompilerPool` of 2 `DecompInterface` instances
(`:38-99`) with `flushCache`/`resetDecompiler` invalidation (`:75-82`).
`DaemonContext.close()` (`:397-413`) saves every program and releases every consumer
before the project closes.

Two hard-won details in that file are worth more than the feature list:

- `_take_ownership` (`:203-220`) with its comment: *"`GhidraProject` keeps every
  opened/imported program under one long-lived transaction until `GhidraProject.save()`
  settles it … becoming our own consumer and releasing the project's makes our
  transactions top-level instead. **Must be called AFTER initial auto-analysis and its
  `save()`** — releasing ownership earlier silently breaks `analyzeAll()` (no functions
  get created despite it reporting success)."* That is
  [NSA/ghidra#9347](https://github.com/NationalSecurityAgency/ghidra/issues/9347), and
  it is the kind of trap that would silently produce a `functions: 0` analysis and look
  like a clean result. Any registry entry that opens programs in-process inherits it.
- `_run_analysis` (`:101-147`) runs `analyzeAll` on a daemon thread with a
  `threading.Event` timeout and best-effort cancellation via
  `AutoAnalysisManager.cancelCurrentAnalysis`, and **only then** calls
  `GhidraProgramUtilities.setAnalyzedFlag(program, True)`. On timeout it deliberately
  leaves the flag unset and returns `False` (`context.py:335-336`: *"Only mark as fully
  analyzed when analysis actually finished. If it timed out, leave the flag unset so
  Ghidra knows it's partial."*). That is the correct honest-instrument behaviour and
  the registry should require it of every analysis entry.

**How it exposes an agent to it.** A `Unix domain socket` / named-pipe transport
(`ghidra_rpc/transport.py`, 125 lines) carrying newline-delimited JSON, plus a
`ghidra-rpc` CLI that emits JSON on stdout and human text on stderr
(`cli.py:1-4`, 2,185 lines with 1 command per capability). Session identity is a
**deterministic socket path derived from the `.gpr` path** —
`socket_path_for_project(gpr)` = `<endpoint_dir>/ghidra-rpc-<sha256(gpr)[:16]>.sock`
(`session.py:37-44`); the state file is
`<gpr.parent>/.ghidra-rpc-<digest>.json` (`:47-60`); a global `sessions.json` registry
(`:101-230`) is lock-protected with `msvcrt.locking` on Windows / `fcntl.flock`
elsewhere (`:13-16`, `:116-137`) and is **non-fatal on failure** — the caller degrades
to endpoint-directory globbing (`:179-180`). Liveness is a `ping` round-trip
(`daemon.py:14-24`), never a PID check.

**Tool surface: 69 handlers**, extracted from
`register_handler("<name>"` across `ghidra_rpc/server/tools/`:

`load save list_binaries list_project_programs decompile decompile_all disassemble
functions basic_blocks pcode search_decompiled find_bytes strings symbols imports
exports memory_map relocations metadata get_processor_context set_processor_context
goto xrefs_to xrefs_from read_bytes read_pointers write_bytes assemble create_function
delete_function create_label create_namespace rename_function rename_symbol
rename_variable set_comment set_flow_override set_function_signature
set_calling_convention list_calling_conventions batch_rename batch_set_comment
batch_edit_variables set_data_type retype_variable clear_data_range
apply_data_type_range create_struct create_union modify_struct create_enum modify_enum
set_equate list_equates set_bookmark remove_bookmark list_bookmarks tag_function
untag_function functions_by_tag list_tags version_track function_diff match_function
list_data_types list_namespaces list_vtable`

That is, by design, the capability surface our `HeadlessMcpHttp.java` was trying to
approximate — and it is ~5× the size of our 571-line attempt, with the p-code, CFG,
struct authoring and versioning that our half-finished file lacks.

**"The program under analysis" vs "a batch script".** ghidra-rpc **does not have a
`batch-script path at all** — `grep -rniE "batch|ghidra_script|analyzeHeadless|-postScript"`
over `ghidra_rpc/` returns 28 hits, in exactly 2 files (`cli.py`,
`server/tools/modifications.py`), and **zero** for `ghidra_script`/`analyzeHeadless`/
`-postScript`. Every hit is a *bulk RPC* (`batch_rename`,
`batch_set_comment`, `batch_edit_variables` — N edits in one round trip, e.g.
`modifications.py:1461-1464`: *"Executes all renames in a single Ghidra transaction, so
a 40-item batch takes roughly the same wall-clock time as a single rename."*). There is
no handler that executes a `GhidraScript`. The distinction it
draws is instead **two orthogonal axes made explicit on every call**:

1. *Which program* — every handler takes a binary/program handle, and the CLI requires
   `--project <path>` or `GHIDRA_RPC_PROJECT` on every command
   (`cli.py:49-60 _resolve_project` errors out without it).
2. *Which programs the daemon has resident* — `status` returns
   `{running, socket, mode, mode_source, project, binaries}`; `mode_source` is
   `"running"` (daemon live), `"session"` (state file only, daemon stopped), or `null`
   (`SKILL.md:68-70`).

And the sharpest statement of the cross-program problem is `SKILL.md:140-145`:

> *"a reference to a symbol in* different *loaded binaries is invisible to a
> single-binary `xrefs-to` lookup … Pass `--all-binaries` to also search every other
> currently loaded binary for a symbol with the same fully-qualified name."*

That is exactly the discipline our registry needs: a `xrefs[]` fact is
`(program_id, address)`, never a bare address, because a bare address is meaningless
once a second program is resident. I have made `program_id` a field on every
address-bearing fact in §3.

**What it does that we must copy regardless of whether we ever install it:** the
version-tracking handler's program bookkeeping. `version_tracking.py:17-73`
(`_open_vt_programs`) saves both programs, **disposes both `DecompilerPool`s**, closes
the daemon's own `Program` handles, removes them from `ctx.programs`, and re-opens
fresh writable references via `DomainFile.getDomainObject(consumer, …)` — with
`_restore_daemon_programs` (`:76-109`) in a `finally` (`:283-287`). The comment at
`:18-23` names the reason: *"VTSessionDB requires writable access to the destination
program, which conflicts with the daemon's exclusive write lock via GhidraProject."*
That is a real constraint, and it applies to our `AbstractGhidraVersionTrackingScript`
entry too (§3.6).

**The rest of that handler is our answer to the bethington question.** `version_tracking.py:116-125`:

```python
_CORRELATOR_FACTORIES = [
    "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactMatchMnemonicsProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.ExactDataMatchProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.DuplicateFunctionMatchProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.FunctionReferenceProgramCorrelatorFactory",
    "ghidra.feature.vt.api.correlator.program.CombinedFunctionAndDataReferenceProgramCorrelatorFactory",
]
```
plus `_run_bsim_correlator` at `:180`. Then `:189-245` collects `VTMatch`s from every
`match_set`, resolves function names at both ends, and **de-duplicates per source
address keeping the best `(similarity, confidence)`** — with the reason at `:226-231`:
*"Many-to-many correlators (e.g. DuplicateFunctionMatch) can produce N entries for
every stub function, exhausting the limit budget before better BSim/reference matches
are emitted."* The returned `summary` (`:268-282`) is `{source_functions_total,
source_functions_matched, source_functions_unmatched, changed_functions,
identical_functions, destination_functions_unmatched, bsim_used, correlators_run}`.

**A production project with exactly our choice in front of it used Ghidra's correlators
and did not reimplement a fuzzy scheme.** That is prior art with a track record, not a
README claim.

### 2.2 `bethington/ghidra-mcp` — `BinaryComparisonService.java`

**Apache-2.0** (`LICENSE` present, `head -3` → "Apache License / Version 2.0"). 1,015
lines at `src/main/java/com/xebyte/core/BinaryComparisonService.java`, with
`src/test/java/com/xebyte/offline/BinaryComparisonServiceTest.java`.
`manifests\mcp-backends.json` describes it as a LaurieWired GhidraMCP fork; the
`ghidra_scripts/` tree (40+ scripts) and `bridge`-style `HeadlessEndpointHandler`
confirm the lineage. It is listed in our manifest but **not installed** — there is no
`mcp/bethington-ghidra-mcp` and no build.

What the code actually does, read rather than summarised:

- **Class javadoc (`:22-30`)**: *"Shared service for cross-binary function comparison.
  Provides fuzzy function matching and structured diff for comparing functions across
  binaries **compiled by different compilers**. All methods are static, stateless, and
  thread-safe. Used by both GhidraMCPPlugin (GUI) and HeadlessEndpointHandler."*
  The stated problem is **cross-compiler**, not cross-build.
- **Feature vector `FunctionSignature` (`:72-121`)**: numerics `instructionCount,
  basicBlockCount, edgeCount, callCount, stringRefCount, paramCount,
  cyclomaticComplexity`; sets `calleeNames: Set<String>`, `stringConstants: Set<String>`,
  `immediateValues: Set<Long>`; structure `basicBlockHashes: List<String>`; plus
  `prologue_stripped` / `epilogue_stripped` metadata.
- **Weights (`:48-63`)**: `WEIGHT_NUMERIC 0.25`, `WEIGHT_SET 0.60`,
  `WEIGHT_STRUCTURAL 0.15`; numeric sub-weights instr 0.25 / blocks 0.25 / calls 0.20 /
  complexity 0.15 / edges 0.10 / string-refs 0.05; set sub-weights callees 0.50 /
  strings 0.30 / immediates 0.20. `computeSimilarity` at `:394-440`, `jaccard` at
  `:941`, `jaccardLong` at `:951`.
- **Two fixes in it that tell you the naive version is wrong.** `:39-45`:
  `MIN_MATCH_INSTRUCTIONS = 8`, because *"Functions smaller than this have too few
  features to fingerprint reliably. Tiny stubs/thunks (some of which Ghidra does NOT
  flag `isThunk`, e.g. a lone JMP) otherwise collide with everything: with no
  callees/strings/immediates their signatures are near-empty and used to score ~1.0
  against any source."* And `:420-421`:
  *"empty-vs-empty component is NOT evidence of similarity — rewarding the absence of
  features (`jaccard(∅,∅)=1.0`) made tiny/featureless functions…"*. That is the same
  failure mode I measured in Ghidra's own `BSim Function Matching` (461 matches at
  similarity 1.000 against an unrelated binary, §1.9) — reached from the other
  direction, and independently guarded against here.
- **Cost shape**: `bulkFuzzyMatchJson` (`:525-600`) precomputes every target
  signature once, then does an O(n_src × n_tgt) scan with an
  `INSTRUCTION_COUNT_RATIO_CUTOFF = 4.0` early-exit (`:37`, `:571-577`) and a
  `threshold` before emitting. It is `offset`/`limit` paginated — i.e. quadratic, and
  its author knew it needed paging.
- **Integration cost**: it takes **two live `Program` objects as arguments**
  (`srcProgram, tgtProgram`) and does nothing else. **No `VTSession`, no project, no
  destination-writability requirement, no session lifecycle.** It is a pure function of
  two open programs.
- `MAX_DIFF_INSTRUCTIONS = 2000`, `MAX_DIFF_ENTRIES = 500`, `MAX_PROLOGUE_INSTRUCTIONS =
  5`, `MAX_EPILOGUE_INSTRUCTIONS = 3` (`:33-37`), and the prologue/epilogue logic is
  **ARM-specific** (`:127-130 isARM`, `:140-145`).

### 2.3 Do we need both? — **No, and the split is not the one the brief assumed**

The brief framed it as "bethington's comparison service vs Ghidra's Version Tracking,
pick one". They are not alternatives. They answer different questions, and the
distinction is in both sources' own words:

| | Ghidra Version Tracking | BinaryComparisonService |
|---|---|---|
| stated target | same program, **two builds** | same program, **two compilers** (`:24-25`) |
| primitive | exact byte/instruction/mnemonic/symbol match, reference propagation, BSim | weighted Jaccard over behavioural features |
| survives `-O2` → `-O0` | no — everything moves | partially — features are optimiser-stable |
| survives a compiler swap | no | that is its reason to exist |
| needs a project + writable destination | yes (`version_tracking.py:18-23`) | no |
| cost | correlator sweeps, seconds | O(n×m) signature scan, paginated |
| licence | Apache-2.0, ships with Ghidra | Apache-2.0 |

**We need Version Tracking, and we do not need the Jaccard service, because on this
station's corpus the Jaccard service's target case does not exist and its failure mode
is one we already measured.** Concretely:

1. Our comparison targets are **rebuilds of the same source with a different
   compile-time constant** — `headless-lab\native\core.c` compiled twice with
   `/DLAB_MASK=0x3C`, and the crackme corpus. Same compiler, same `/O1`, same CRT. Ghidra's
   exact correlators already resolve this: `Exact Function Bytes Match` returned
   463/135/163 across identical / related / unrelated pairs (§1.9). The Jaccard scheme
   is built for the axis we do not vary.
2. §1.9 shows the discriminating-power problem is **not** "we need fuzzier matching" —
   it is "the shared MSVC CRT makes 410 of 512 functions byte-identical across
   *unrelated* challenges". A fuzzy scheme makes that *worse*, because it will happily
   score the CRT's `__security_check_cookie` at high similarity in every pair. Its own
   authors had to add `MIN_MATCH_INSTRUCTIONS = 8` and an empty-set guard to stop exactly
   that. We would be reimplementing, in Python-land, a guard against a problem Ghidra
   has, and would then have to write the same guard again.
3. ghidra-rpc — a vendor shipping this as a product to paying users — chose the
   correlator factories and did not ship a Jaccard comparator. `version_track` has 767
   lines; the nearest thing to a comparator in it is the per-source-address
   de-duplication at `:226-245`.
4. The one thing worth **stealing** is not the algorithm but the **shape**: two live
   `Program` objects, no session, no writability requirement, a paging interface, and a
   `similarity`+`confidence` pair per match — all of which
   `AbstractGhidraVersionTrackingScript` already gives us for free, and which VT's
   `VTMatch.getSimilarityScore()` / `getConfidenceScore()` / `getSourceLength()` /
   `getDestinationLength()` expose directly (verified by javap, §6.4).

**This contradicts a standing note in our own manifest, and the Owner should know
that.** `manifests\mcp-backends.json:42` records `GhidraMCP` (LaurieWired, Apache-2.0)
with the note: *"事实标准 GhidraMCP(~9.4k star)。0xflux/ghidra-mcp、bethington/ghidra-mcp
均为其 fork;13bm/GhidraMCP 为同名独立实现。**如需更多工具数可评估 bethington fork。**"*
("…if you need more tools, evaluate the bethington fork"). The four points above are
the reason to **decline** that suggestion today, and the manifest line should stay as it
is — the suggestion is sound for a *tool-count* motive and unsound for a
*diff-accuracy* motive, and only the second motive matters here. If the Owner later
adds a genuinely cross-toolchain corpus, point 1 stops applying and the note becomes
correct; that is the condition under which this verdict flips.

**Decision recorded for the registry: `native.diff.fuzzyjaccard` is NOT an entry.** If a
mission ever needs to compare a `/O1` Windows build against a `/O0` Linux build — a
cross-*platform* or cross-*compiler* question — the right move is a
`native.diff.crossplatform.*` capability with its own probe, gated on a corpus that
actually contains such a pair, not a speculative reimplementation of an Apache-2.0 file
we have already read.

### 2.4 What we take from the prior art, and what we build instead

| prior-art idea | source | our disposition |
|---|---|---|
| in-process JVM, live `Program`, no per-request JVM boot | ghidra-rpc `context.py:174-362` | **Not now.** It needs a Ghidra Extension (install-class) or the GUI. Blocked by §1.5's OSGi finding. |
| `_take_ownership` ordering (after analysis + save) | ghidra-rpc `context.py:203-220` | Carried as a hard ordering constraint on any future in-process entry. |
| mark-analyzed only on completion | ghidra-rpc `context.py:335-336` | Adopted as a registry rule: an entry must not report `analysis_complete` on a timeout. |
| de-dup per source address, best (sim, conf) | ghidra-rpc `version_tracking.py:226-245` | Adopted into `native.diff.ghidra.vt`'s `produces` contract. |
| save/close/reopen around VT to dodge the write lock | ghidra-rpc `version_tracking.py:17-109` | Recorded as a `requires` note; our postscript gets it for free by not holding the programs. |
| `program_id` on every address-bearing fact | ghidra-rpc `SKILL.md:140-145` | Adopted: `xrefs[]`, `functions[]`, `strings[]` all carry `program_id`. |
| weighted-Jaccard feature signature | bethington `:394-440` | **Rejected** — §2.3. |
| `MIN_MATCH_INSTRUCTIONS` floor | bethington `:39-45` | Adopted as a *negative-control rule* on every match-counting entry: a match count over functions below a floor is not evidence. |
| empty-vs-empty must not score 1.0 | bethington `:420-421` | Adopted as the negative control for `native.diff.ghidra.vt`, instantiated with the measured 461-vs-461 BSim failure. |

---

## 3. Part 3 — registry entries

### 3.0 Shared, measured host facts

`requires.tools[].probe` for every Ghidra entry is a file existence + version read, not
a version string in prose (`orchestration-design.md:263` — `state` is measured by
`probe`).

```jsonc
{ "name": "ghidra",
  "probe": "powershell -NoProfile -Command \"(Get-Content 'D:\\Software\\Tool\\WorkStation\\debugger\\Static-Reversing\\Ghidra\\ghidra_12.1.3_PUBLIC\\Ghidra\\application.properties' | Select-String '^application.version=').Line\"",
  "expect": "application.version=12.1.3",
  "expect_exit": 0 }
```

Conventions I fix here, so the entries compose:

- **`produces.facts[].key`** is the bare key, pluralised with `[]` where the value is a
  collection. Every address-bearing fact carries **`program_id`** (the file name as
  imported), because §2.4.
- **`consumes.prior`** is `"<namespace>.<key>"` — `decomp.functions[]`,
  `triage.imports[]`, `diff.matches[]` — so two capabilities producing the same key from
  different tools do not collide silently.
- **`requires.wall_minutes`** is the **measured** wall time (§1.6) rounded up, with the
  per-run measurement named in `provenance.record` so the next window can re-measure.
- **Every Ghidra entry gates on `ok:true` + its own named artifact, never on the process
  exit code** (§1.6). `expect_exit` is recorded for completeness and is `0` even on
  failure, which is why the `probe` is the gate.
- **Every Ghidra postscript must live in its own `-scriptPath` directory** (§1.4), so a
  sibling compile failure cannot silently `skipping` it.
- **`negative_control.expect_exit`** is likewise unreliable; each NC below states the
  **absent-artifact / `ok:false`** condition the orchestrator must assert instead.

### 3.1 `native.triage.ghidra`

```jsonc
{
  "id": "native.triage.ghidra",
  "version": 1,
  "title": "Ghidra headless import + auto-analysis: typed program manifest, section map, import/export tables",
  "domains": ["D3", "D14"],
  "question_types": ["Q1.identify", "Q2.locate"],
  "consumes": {
    "inputs": [
      { "name": "binary", "type": "file:pe|elf|mach-o", "required": true,
        "note": "read-only path; Ghidra writes nothing to the input" }
    ],
    "context": ["mission.question.type", "mission.containment"],
    "prior": []
  },
  "produces": {
    "facts": [
      { "key": "program.manifest", "type": "triage.manifest",
        "fields": { "program_id": "string", "format": "string", "arch": "string",
                    "language": "string", "functions": "uint32", "byte_size": "uint64",
                    "sha256": "hex64" } },
      { "key": "segments[]", "type": "triage.segment",
        "fields": { "program_id": "string", "name": "string",
                    "start": "uint64", "end": "uint64", "perm": "string" } },
      { "key": "imports[]", "type": "triage.symbol",
        "fields": { "program_id": "string", "name": "string", "space": "string" } },
      { "key": "exports[]", "type": "triage.symbol",
        "fields": { "program_id": "string", "name": "string", "va": "uint64" } }
    ],
    "artifacts": [
      { "key": "manifest", "type": "file:json", "path": "summary.json" },
      { "key": "segments", "type": "file:text", "path": "segments.txt" },
      { "key": "imports",  "type": "file:text", "path": "imports.txt" },
      { "key": "exports",  "type": "file:text", "path": "exports.txt" },
      { "key": "log",      "type": "file:text", "path": "analyzeHeadless.log" }
    ],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 12,        // measured: 673 KB artifacts + 4.3 MB project if retained
    "ram_mb": 1200,       // measured: 1,085.7 MB peak JVM working set
    "wall_minutes": 1,    // measured: 18.05 s
    "tools": [{ "name": "ghidra", "probe": "…see §3.0…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "that Ghidra's loaders accepted the file, and which loader/language ID it assigned",
    "the section (memory block) map with real addresses",
    "the import and export tables as Ghidra resolved them, including EXTERNAL-space thunks",
    "the number of functions Ghidra's auto-analysis discovered"
  ],
  "does_not_prove": [
    "that the file is NOT packed, obfuscated, or otherwise lying about its sections",
    "that 512 functions is the right count — it is what the analysers found, and a packed or anti-analysed binary yields a confidently small number",
    "anything about a different build, platform, or architecture",
    "runtime behaviour of any kind"
  ],
  "falsifies": ["H0: this file is not a recognised executable container"],
  "side_effects": ["writes <outdir>/ and a ~4.3 MB project under %TEMP% (deleted with -deleteProject, but the empty directory is left behind)"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "observed",
  "probe": {
    "command": "powershell -NoProfile -File scripts\\ghidra-headless.ps1 -Sample <our-crackme> -OutDir <case>/native/triage",
    "expect": "\"ok\":true … \"language\":\"x86:LE:64:default\"",
    "expect_exit": 0,
    "gate_on": "summary.json exists AND ok==true — NOT on the exit code (see §1.6)"
  },
  "negative_control": {
    "id": "triage-on-non-container",
    "command": "… -Sample <a .txt file>",
    "expect_artifact_absent": "summary.json",
    "expect_payload": "{\"ok\":false,…}",
    "expect_exit": 0,
    "why": "VERIFIED 2026-09-30: analyzeHeadless logs 'No load spec found for import file' + 'Import failed' and writes NO summary.json — but it still exits 0, and scripts\\ghidra-headless.ps1 also exits 0. A capability that gates on the exit code reports success for a file it never opened."
  },
  "provenance": { "source": "scripts\\ghidra-headless.ps1; scripts\\ghidra\\ExportDecompile.java",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.6, §1.8" }
}
```

**Measured instance** (`c01-stringobf.exe`): `ok:true`,
`language: x86:LE:64:default`, `functions: 512`; 8 segments, 76 imports, 1 export
(`entry -> 1400015d0`), 673,220 B in 522 files, 18.05 s, 1,085.7 MB peak.

### 3.2 `native.decompile.ghidra`

The id the design doc already uses (round 3 of the worked example), so I keep it.

```jsonc
{
  "id": "native.decompile.ghidra",
  "version": 1,
  "title": "Ghidra headless decompile-all: per-function C, with a disassembly fallback",
  "domains": ["D3", "D14"],
  "question_types": ["Q2.locate", "Q5.vuln-shape"],
  "consumes": {
    "inputs": [
      { "name": "binary", "type": "file:pe|elf|mach-o", "required": true },
      { "name": "max_functions", "type": "uint32", "required": false, "default": 0,
        "note": "0 = no limit; the wrapper only forwards it when > 0" }
    ],
    "context": ["mission.question.type"],
    "prior": ["triage.program.manifest", "triage.segments[]"]
  },
  "produces": {
    "facts": [
      { "key": "functions[]", "type": "code.function",
        "fields": { "program_id": "string", "va": "uint64", "name": "string",
                    "c_path": "string", "decompiled": "bool",
                    "fallback": "bool", "calls": "uint64[]", "body_bytes": "uint64" } },
      { "key": "decompile.summary", "type": "code.decompile_stats",
        "fields": { "program_id": "string", "functions": "uint32",
                    "decompiled": "uint32", "timeout_s": "uint32" } }
    ],
    "artifacts": [
      { "key": "c_sources", "type": "file:dir", "glob": "decompiled/*.c" },
      { "key": "index",  "type": "file:text", "path": "functions.txt" },
      { "key": "stats",  "type": "file:json", "path": "summary.json" }
    ],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 12, "ram_mb": 1200, "wall_minutes": 2,
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "Ghidra's C output for a named function at a cited VA",
    "the function inventory as Ghidra's analysers defined it (`functions[]` with VAs)",
    "when a function FAILED to decompile — `decompiled < functions`, and the artifact contains the literal marker `// decompile failed; disassembly fallback`"
  ],
  "does_not_prove": [
    "that the decompiled C is what the compiler emitted — it is a reconstruction through Ghidra's pcode lifter, and its variable names and types are guesses",
    "that the listed functions are the functions that matter; 512 is a count, not a ranking",
    "anything about control flow that was not lifted (unanalysed switch tables, computed jumps, tail calls through registers)",
    "runtime behaviour"
  ],
  "falsifies": ["H2: no function at this VA is reachable / does not exist"],
  "side_effects": ["writes <outdir>/decompiled/*.c (512 files ≈ 0.6 MB for a 512-function PE)"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "observed",
  "probe": {
    "command": "… -Sample <our-crackme> -OutDir <case>/native/decompile",
    "expect": "\"ok\":true … \"functions\":512,\"decompiled\":512",
    "expect_exit": 0,
    "gate_on": "decompiled/ contains one .c per line of functions.txt AND summary.json ok==true"
  },
  "negative_control": {
    "id": "decompile-count-must-not-be-silently-equal",
    "command": "… on a program that defeats the decompiler (e.g. one with an obfuscated switch table)",
    "expect": "decompiled < functions in summary.json AND at least one decompiled/*.c whose first line is `// decompile failed; disassembly fallback`",
    "expect_exit": 0,
    "why": "the wrapper passes a 30 s per-function timeout (ExportDecompile.java:68) and silently substitutes disassembly on failure (:74-76). Without this control a mission reads 100% 'decompiled' and believes it.",
    "status": "[UNVERIFIED] no such target exists in crackme-corpus; c01 decompiles 512/512. The control is specified, not yet exercised."
  },
  "provenance": { "source": "scripts\\ghidra\\ExportDecompile.java:53-99",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.6, §1.8" }
}
```

**Measured instance**: 512 `.c` files, 512/512 decompiled, +9 s over the analysis-only
baseline (18.05 s total vs ~9 s auto-analysis).

**Registry note that applies here and to §3.1:** `ExportDecompile.java:68` uses a hard
30 s `decompileFunction` timeout and `:75-76` writes a disassembly fallback **without
marking it in `summary.json`**. `decompiled: 512` in the payload and 512 files on disk
are not the same claim. The entry must add `fallback` per function (§3.2 facts) before
`decompile.summary` can be trusted. That is a one-line script change and an Owner
decision to make; I have not made it.

### 3.3 `native.strings.ghidra`

```jsonc
{
  "id": "native.strings.ghidra",
  "version": 1,
  "title": "Ghidra defined-string enumeration with addresses",
  "domains": ["D3", "D14"],
  "question_types": ["Q2.locate"],
  "consumes": {
    "inputs": [{ "name": "binary", "type": "file:pe|elf|mach-o", "required": true }],
    "context": ["mission.question.type"],
    "prior": ["triage.program.manifest"]
  },
  "produces": {
    "facts": [
      { "key": "strings[]", "type": "text.string",
        "fields": { "program_id": "string", "va": "uint64", "text": "string",
                    "encoding": "string", "space": "string",
                    "refs_from": "uint64[]" } }
    ],
    "artifacts": [{ "key": "strings", "type": "file:text", "path": "strings.txt" }],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 1, "ram_mb": 1200, "wall_minutes": 1,
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "every byte range Ghidra's string analysis classified as a defined string, at its address",
    "the address of a specific literal, which is what a later breakpoint capability consumes"
  ],
  "does_not_prove": [
    "that a string is meaningful — Ghidra's list is dominated by CRT noise (`__based(`, `__cdecl`, `__stdcall`, …: 291 entries on c01 of which the majority is the MSVC CRT)",
    "that the string is reachable from the program's logic; nothing here is a reference graph",
    "that a stack- or heap-constructed string is absent — it simply was not a defined string",
    "which of two same-looking constants the program actually compares"
  ],
  "falsifies": ["H1: the constant compared against is not present as a literal in the binary"],
  "side_effects": ["writes <outdir>/strings.txt"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "observed",
  "probe": {
    "command": "… -Sample <our-crackme>",
    "expect": "strings.txt exists and its first line is an address-prefixed literal",
    "expect_exit": 0,
    "gate_on": "strings.txt non-empty AND non-whitespace"
  },
  "negative_control": {
    "id": "decoy-flag-must-be-reported-as-data",
    "command": "… -Sample crackme-corpus\\out\\c01-stringobf.exe, then assert line 1 of strings.txt",
    "expect_line1": "140017368 FLAG{c01_strings_gave_you_this_decoy}",
    "why": "VERIFIED 2026-09-30: this is the corpus's own planted decoy. The capability must surface it as an ordinary string at 140017368, and the mission must not treat 'a FLAG{…} string exists' as the answer. A triage step that short-circuits on the first flag-shaped constant is wrong on this corpus by construction.",
    "expect_exit": 0
  },
  "provenance": { "source": "scripts\\ghidra\\ExportDecompile.java:137-148",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.8" }
}
```

**Measured instance**: 291 entries, 7,401 B, cap 4,000
(`ExportDecompile.java:85`). Line 1 is the decoy above. The script's whole output is
`strings(int limit)` at `ExportDecompile.java:137-148`: it walks
`getListing().getDefinedData(true)`, keeps every `d` with `hasStringValue()`, and emits
`d.getAddress() + " " + value`. So of the fields declared above, only `va` and `text`
are on disk today — `program_id` must be supplied by the caller from the run, and
`encoding`, `space` and `refs_from` are **not produced at all**. Those three are a
script change, an Owner decision, not a claim about today. `triage.imports[]` and
`triage.exports[]` have the same shape caveat: `name -> addr`, no `program_id`.

### 3.4 `native.symhash.ghidra` — `state: "degraded"` (does not compile)

```jsonc
{
  "id": "native.symhash.ghidra",
  "version": 1,
  "title": "Per-function content hash manifest (name, body size, MD5 of body bytes)",
  "domains": ["D3", "D14"],
  "question_types": ["Q7.origin"],
  "consumes": {
    "inputs": [{ "name": "binary", "type": "file:pe", "required": true }],
    "context": [],
    "prior": ["triage.program.manifest"]
  },
  "produces": {
    "facts": [
      { "key": "fnhashes[]", "type": "code.fnhash",
        "fields": { "program_id": "string", "name": "string", "va": "uint64",
                    "body_bytes": "uint64", "md5_8": "hex16" } }
    ],
    "artifacts": [{ "key": "manifest", "type": "file:text", "glob": "hashes-<program>.txt" }],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 8, "ram_mb": 1200, "wall_minutes": 1,
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "an exact content address per function: two functions with the same md5_8 have byte-identical bodies",
    "a text-manifest inventory that can be diffed, grepped and checked into a notes file without shipping a Ghidra project"
  ],
  "does_not_prove": [
    "similarity — the hash is a content address, not a score (FunctionHashes.java:10-14: 'a recompile with different optimisation moves every hash')",
    "that two functions with different hashes are unrelated; one changed byte changes it",
    "anything about semantics: two different functions can share a body (a thunk and its target)"
  ],
  "falsifies": ["H7: this function's body changed between two builds"],
  "side_effects": ["keeps the Ghidra project unless -deleteProject is passed (the wrapper omits it whenever -PostScript is used)"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "degraded",
  "probe": {
    "command": "… -PostScript FunctionHashes.java -PostArgs <outdir>",
    "expect": "hashes-<program>.txt exists and is non-empty",
    "expect_exit": 0,
    "gate_on": "hashes-<program>.txt exists",
    "measured_now": "FAILS. Ghidra skips the script: 'FunctionHashes.java:37: error: non-static variable currentProgram cannot be referenced from a static context' then 'skipping …\\FunctionHashes.java'. The run still reports 'Post-analysis succeeded'."
  },
  "negative_control": {
    "id": "hash-must-change-on-a-one-byte-change",
    "command": "hash the same function from two builds differing by one compile-time constant",
    "expect": "the affected function's md5_8 differs; every other function's is identical",
    "why": "an MD5 that never changes would make this entry a no-op that reports 'no change' for every mission",
    "status": "[UNVERIFIED] blocked by the compile error"
  },
  "provenance": { "source": "scripts\\ghidra\\FunctionHashes.java:30-74",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.4" }
}
```

**The blocking defect, precisely:** `FunctionHashes.java:30` declares
`private static String bodyHash(AddressSetView body)` and `:37` reads the inherited
instance field `currentProgram.getMemory()`. One-word fix (`static` removal). I have
**not** applied it: this assignment is read-only against the repo's scripts and the fix
belongs to whoever owns `headless-lab`.

### 3.5 `native.diff.manifest` — `state: "degraded"` (blocked by §3.4)

```jsonc
{
  "id": "native.diff.manifest",
  "version": 1,
  "title": "Text diff of two function-hash manifests: changed / same / added / removed by NAME",
  "domains": ["D3", "D14"],
  "question_types": ["Q7.origin"],
  "consumes": {
    "inputs": [
      { "name": "manifest_a", "type": "file:text", "required": true,
        "from": { "capability": "native.symhash.ghidra", "field": "fnhashes[]" } },
      { "name": "manifest_b", "type": "file:text", "required": true,
        "from": { "capability": "native.symhash.ghidra", "field": "fnhashes[]" } }
    ],
    "context": [],
    "prior": ["hash.fnhashes[]"]
  },
  "produces": {
    "facts": [
      { "key": "namediff[]", "type": "diff.by_name",
        "fields": { "name": "string", "verdict": "changed|same|added|removed",
                    "named": "bool", "size_a": "uint64", "size_b": "uint64",
                    "md5_a": "hex16", "md5_b": "hex16" } },
      { "key": "namediff.summary", "type": "diff.stats",
        "fields": { "changed": "uint32", "same": "uint32",
                    "removed": "uint32", "added": "uint32",
                    "named_a": "uint32", "named_b": "uint32" } }
    ],
    "artifacts": [{ "key": "diff", "type": "file:text", "path": "diff.txt" }],
    "invalidates_on": ["manifest_a.sha256 != recorded", "manifest_b.sha256 != recorded"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 1, "ram_mb": 256, "wall_minutes": 1,
    "tools": [{ "name": "python", "probe": "python --version", "expect": "Python 3." }]
  },
  "proves": [
    "which functions changed body, by NAME, between two manifests",
    "a clean separation of 'renamed' from 'changed' — a name present in both with a different hash is CHANGED; a name in only one is added/removed and is tagged [named] when it is not Ghidra-generated"
  ],
  "does_not_prove": [
    "that a name-keyed match is the RIGHT match — a function renamed between builds shows as added+removed, not as changed",
    "similarity, in any direction (see native.symhash.ghidra)",
    "that an unchanged hash means unchanged behaviour: a call target can change while every body stays identical",
    "anything about data, layout, or the linker"
  ],
  "falsifies": ["H7: this function's body is unchanged between the two builds"],
  "side_effects": ["writes <outdir>/diff.txt"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "degraded",
  "probe": {
    "command": "… -PostScript DiffPrograms.java -PostArgs <a> <b> <outdir>",
    "expect": "diff.txt exists and starts with `DIFF a=… b=…`",
    "expect_exit": 0,
    "gate_on": "diff.txt exists",
    "measured_now": "UNREACHABLE. DiffPrograms.java itself compiles, but its only input is FunctionHashes.java output, which cannot be produced (§3.4)."
  },
  "negative_control": {
    "id": "self-diff-must-be-quiet",
    "command": "DiffPrograms.java <m> <m> <out>",
    "expect": "SUMMARY changed=0 added=0 removed=0 and same == the manifest's row count",
    "why": "already specified in headless-lab\\README.md:145-146 and still unexercised. A name-keyed set diff that reports changes against itself is a broken comparator.",
    "status": "[UNVERIFIED] blocked by §3.4",
    "second_control": {
      "id": "manifest-from-a-different-program-must-not-look-clean",
      "command": "DiffPrograms.java <hashes-of-c01> <hashes-of-c05>",
      "expect": "changed >> 0",
      "why": "readManifest (DiffPrograms.java:55-71) keys a Map by name and ignores rows with <3 tab-separated fields. A truncated, empty, or wrong-program manifest therefore produces a short, confident, entirely plausible diff instead of an error. This is the failure mode a registry entry has to forbid."
    }
  },
  "provenance": { "source": "scripts\\ghidra\\DiffPrograms.java:78-138",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.4" }
}
```

**Also void:** the header note at `DiffPrograms.java:6-12` justifying the two-manifest
design ("Ghidra 12 has no framework-level ProgramManager, so a headless script cannot
open a sibling program from the same project") is false — §1.2, §1.4. The entry above
is specified anyway because a text manifest diff is useful and needs no Ghidra at all;
but the *reason* recorded in `provenance` must not repeat that claim.

### 3.6 `native.diff.ghidra.vt` — the cross-binary version-tracking entry

The programmatic path, not `AutoVersionTrackingScript`. One postscript extending
`ghidra.feature.vt.AbstractGhidraVersionTrackingScript`, driven by `-postScript` with
the two program paths as **positional args in `askProgram` call order** (§1.3c).

```jsonc
{
  "id": "native.diff.ghidra.vt",
  "version": 1,
  "title": "Ghidra Version Tracking: enumerate + run program correlators over two programs, emit typed matches",
  "domains": ["D3", "D14"],
  "question_types": ["Q7.origin", "Q2.locate"],
  "consumes": {
    "inputs": [
      { "name": "project", "type": "path:dir", "required": true,
        "note": "ONE non-shared Ghidra project containing BOTH programs; both must be analyzed before the -process run" },
      { "name": "source_program", "type": "string", "required": true,
        "note": "project-relative, '/name'; positional script arg #1 (consumed by the first askProgram call)" },
      { "name": "destination_program", "type": "string", "required": true,
        "note": "project-relative, '/name'; positional script arg #2" },
      { "name": "host_program", "type": "string", "required": true,
        "note": "the -process target. MUST be a THIRD program: AskScript-level locking means neither compared program may equal currentProgram" }
    ],
    "context": ["mission.question.type", "mission.containment"],
    "prior": ["triage.program.manifest", "decomp.functions[]"]
  },
  "produces": {
    "facts": [
      { "key": "correlators[]", "type": "diff.correlator",
        "fields": { "name": "string", "ran": "bool", "matches": "uint32", "error": "string" } },
      { "key": "matches[]", "type": "diff.match",
        "fields": { "correlator": "string",
                    "source_program_id": "string", "source_va": "uint64",
                    "dest_program_id": "string",   "dest_va": "uint64",
                    "source_len": "uint32", "dest_len": "uint32",
                    "similarity": "float", "confidence": "float",
                    "tag": "string", "best_for_source": "bool" } },
      { "key": "diff.summary", "type": "diff.stats",
        "fields": { "correlators_ran": "uint32",
                    "identical": "uint32", "changed": "uint32",
                    "unmatched_source": "uint32", "unmatched_dest": "uint32",
                    "source_functions_total": "uint32" } }
    ],
    "artifacts": [
      { "key": "matches_tsv", "type": "file:tsv", "path": "vt-matches.tsv",
        "header": "correlator\tsource_addr\tdest_addr\tsrc_len\tdst_len\tsimilar\tconfidence\ttag" },
      { "key": "log", "type": "file:text", "path": "analyzeHeadless.log" }
    ],
    "invalidates_on": ["source_program.sha256 != recorded", "dest_program.sha256 != recorded"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 12,        // measured: 8,881,907 B for a 2-program project
    "ram_mb": 1200,       // measured: 1,085.7 MB peak JVM working set
    "wall_minutes": 2,    // measured: 14-17 s for a -process run over two 512-function PEs
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "which of Ghidra's 14 program correlators exist on this install, by name — measured, not assumed",
    "for each correlator, the exact (source VA, dest VA, source length, dest length, similarity, confidence, tag) tuples it produces",
    "that a specific function at source VA has a specific counterpart at dest VA, with a similarity and a confidence attached"
  ],
  "does_not_prove": [
    "that two builds are 'the same program' — on this corpus 410 of 512 functions are byte-identical across completely DIFFERENT challenges (Exact Function Instructions Match: 411 related / 413 identical / 410 unrelated). A whole-program match count is invariant and carries no verdict.",
    "that BSim similarity means anything here — measured: 461 matches against a byte-identical copy and 461 against an unrelated binary, 458/461 at similarity 1.000, src_len == dest_len on all 461. Without a BSim database, over a shared-toolchain corpus, BSim Function Matching is not a discriminator. See negative_control.",
    "that the reference correlators work — Function Reference Match and Data Reference Match returned 0 on all three measured pairs; they need reference data these binaries do not carry",
    "that an unmatched function is new — it may be a renamed function the name-keyed and reference correlators both missed",
    "anything about runtime behaviour"
  ],
  "falsifies": [
    "H7: function F is unchanged between build A and build B",
    "H7b: function F is NEW in build B"
  ],
  "side_effects": [
    "creates a VTSessionDB domain file in the project (measured: '/vt_probe: file created')",
    "SAVES the destination program (AutoVersionTrackingScript.java:222) — the -process target's database copy is modified; the on-disk input binary is not"
  ],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "observed",
  "probe": {
    "command": "analyzeHeadless <proj> vt -import <a> <b> -overwrite  &&  analyzeHeadless <proj> vt -process <c> -noanalysis -scriptPath <dir> -postScript VtDiff.java /<a> /<b>",
    "expect": "vt-matches.tsv exists, its header matches the declared one, and the log contains one `CORRELATOR <name> -> <n> matches` line per enumerated correlator",
    "expect_exit": 0,
    "gate_on": "vt-matches.tsv exists AND its header lists all 14 correlators AND it has ≥1 data row"
  },
  "negative_control": {
    "id": "unrelated-binary-must-score-materially-lower-than-self",
    "command": "run the probe three ways: (A) c01 vs a byte-identical copy of c01, (B) c01 vs c02, (C) c01 vs c05",
    "expect": "for every correlator used as evidence, matches(A) must exceed matches(C) by a material margin",
    "why": "VERIFIED 2026-09-30, and this is the reason the entry carries its own 'does_not_prove'. Exact Function Bytes Match passes: 463 (A) vs 135 (B) vs 163 (C). BSim Function Matching FAILS: 461 / 460 / 461. Similar Symbol Name Match FAILS: 103 / 103 / 103. Exact Function Instructions Match FAILS: 413 / 411 / 410. A capability that reports 'N functions matched' without this control is reporting a number that is nearly constant across unrelated binaries. A mission must never conclude 'same build' from a match count alone — only from a high-similarity match set on a NAMED, non-generated function.",
    "measured_now": "PASS for Exact Function Bytes Match and Duplicate Data Match; FAIL for BSim Function Matching, Similar Symbol Name Match, and Exact Function Instructions Match",
    "expect_exit": 0
  },
  "provenance": {
    "source": "ghidra.feature.vt.AbstractGhidraVersionTrackingScript (javap, §6.4); AutoVersionTrackingScript.java:171-187; ghidra-rpc server/tools/version_tracking.py:116-282",
    "record": ".agent\\research\\ghidra-capability-spec.md §1.2, §1.9"
  }
}
```

**Also required, from the measured VT API** (`javap` of
`AbstractGhidraVersionTrackingScript`):

- `createVersionTrackingSession(String, Program, Program)`,
  `openVersionTrackingSession(String)`, `saveVersionTrackingSession()`,
  `getProgramCorrelators(): List<String>`, `runCorrelator(String)`,
  `getMatchesFromLastRunCorrelator(): Collection<VTMatch>`,
  `getSourceFunction(VTMatch)`, `getDestinationFunction(VTMatch)`,
  `getSourceFunctions(): Set<String>`, `getDestinationFunctions(): Set<String>`.
- `VTMatch`: `getSourceAddress()`, `getDestinationAddress()`, `getSourceLength()`,
  `getDestinationLength()`, `getSimilarityScore()`, `getConfidenceScore()`,
  `getTag()`, `getMatchSet()`, `getAssociation()`.
- `cleanup(boolean)` is **`public`** in the base class — declaring it `protected` is a
  compile error (`cleanup(boolean) in X cannot override cleanup(boolean) in
  AbstractGhidraVersionTrackingScript`). I hit this; the shipped
  `FindChangedFunctionsScript.java:36` has it `public` for the same reason.
- **Both compared programs must be released in `cleanup`**, or the project cannot be
  written. My probe's `saveVersionTrackingSession()` failed with
  `java.lang.RuntimeException: Attempted to save a session when not open!` after the
  correlator loop — the session was already closed by a correlator. The entry must treat
  session save as best-effort and take matches from memory.
- **De-duplicate per source address keeping best `(similarity, confidence)`** before
  emitting, per `version_tracking.py:226-245`. Without it the many-to-many
  correlators flood the budget: on one 512-function pair `Similar Data Match` alone
  produced 39,183 rows and `Duplicate Data Match` 224, against 135 for
  `Exact Function Bytes Match`.
- Measured artifact size for all 14 correlators on one pair: **2,889,483 B of TSV**
  (39,183 of those rows are `Similar Data Match` alone).

### 3.7 `native.diff.ghidra.autovt` — `state: "observed"`, lower fidelity

Specified separately because it is a *different* capability with a *different* fact
shape, and the orchestrator must be able to choose.

```jsonc
{
  "id": "native.diff.ghidra.autovt",
  "version": 1,
  "title": "NSA's AutoVersionTrackingScript: default option set, implied matches applied, destination saved",
  "domains": ["D3", "D14"],
  "question_types": ["Q7.origin"],
  "consumes": {
    "inputs": [
      { "name": "project", "type": "path:dir", "required": true },
      { "name": "session_name", "type": "string", "required": true,
        "note": "must not already exist: the validator refuses an existing session (AutoVersionTrackingScript.java:141-146)" },
      { "name": "source_program", "type": "string", "required": true,
        "note": "project-relative '/name', supplied via a co-located AutoVersionTrackingScript.properties keyed '<askValues title> <variable>' — see negative_control" }
    ],
    "context": [],
    "prior": ["triage.program.manifest"]
  },
  "produces": {
    "facts": [
      { "key": "autovt.status", "type": "diff.autovt_status",
        "fields": { "session_name": "string",
                    "source_program_id": "string", "dest_program_id": "string",
                    "completed": "bool", "message": "string" } },
      { "key": "vt.session_ref", "type": "ref.domain_file",
        "fields": { "path": "string", "name": "string" } }
    ],
    "artifacts": [
      { "key": "log", "type": "file:text", "path": "analyzeHeadless.log" }
    ],
    "invalidates_on": ["source_program.sha256 != recorded", "dest_program.sha256 != recorded"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 12, "ram_mb": 1200, "wall_minutes": 1,   // measured 7 s
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [
    "that Ghidra's own default AutoVT configuration completed without error",
    "the destination program has been re-analysed with implied matches APPLIED — it is saved with match-derived names and comments (AutoVersionTrackingScript.java:222)",
    "the existence and path of a persisted VTSessionDB in the project"
  ],
  "does_not_prove": [
    "WHICH functions matched — the script's only machine-readable output is one status line: 'Auto Version Tracking Command completed successfully with no apply markup errors.' The matches live inside the opaque session DB.",
    "that the default options are the right ones — createDefaultOptions() (:270-291) hardcodes MIN_VOTES 2, MAX_CONFLICTS 0, ref-correlator min score 0.95 / min confidence 10.0, and data/symbol/function min lengths 5/3/10. A mission cannot see or change them except by shipping its own SetAutoVersionTrackingOptionsScript.",
    "anything about the correlates' individual scores (unlike §3.6, VTMatch is never surfaced)",
    "the same discriminative-power caveats as §3.6 — the exact and BSim correlators it runs by default are the same ones measured there"
  ],
  "falsifies": ["H7: AutoVT could not complete on this pair"],
  "side_effects": [
    "MUTATES the destination program inside the project and saves it",
    "APPLIES implied matches by default (APPLY_IMPLIED_MATCHES_OPTION true, :284)",
    "creates a session domain file — measured '/vt_probe: file created'"
  ],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "observed",
  "probe": {
    "command": "… -process <dest> -noanalysis -scriptPath <dir> -postScript SetAutoVersionTrackingOptionsScript.java -postScript AutoVersionTrackingScript.java",
    "expect": "log contains 'Auto Version Tracking Command completed successfully'",
    "expect_exit": 0,
    "gate_on": "that log line is present"
  },
  "negative_control": {
    "id": "properties-keys-must-include-the-askvalues-title",
    "command": "supply a .properties file with bare keys",
    "expect": "java.lang.IllegalArgumentException: Error processing variable 'Enter Auto Version Tracking Information Version Tracking Session Name' in headless mode -- it was not found in script arguments or a .properties file.",
    "why": "VERIFIED 2026-09-30 — this is what actually happens on a first attempt. The failure is loud, which is good; the risk is an orchestrator that 'fixes' it by passing a positional arg, which then gets eaten by a different askXxx call in a different order (§1.3c). The entry must pin the exact key strings and the exact argument order, and must copy the two .java files into a scratch -scriptPath (the install is read-only).",
    "expect_exit": 0
  },
  "provenance": {
    "source": "Static-Reversing\\Ghidra\\ghidra_12.1.3_PUBLIC\\Ghidra\\Features\\VersionTracking\\ghidra_scripts\\AutoVersionTrackingScript.java:27-41,141-222,270-291",
    "record": ".agent\\research\\ghidra-capability-spec.md §1.2, §1.3"
  }
}
```

**Note `NUM_ARGS = 3` at `:107` is dead code.** Any registry entry or wrapper that
passes the 3 command-line arguments the file's own header documents is passing arguments
nothing reads. If the orchestrator ever surfaces those, it is a confident no-op.

### 3.8 `native.ghidra.emulate` — `state: "blocked"` (proposal below, written as `"absent"`)

> **PROPOSAL, superseded by `manifests/capabilities.json`.** The shipped entry is
> `native.ghidra.emulate`, `state: "blocked"`, probe
> `powershell -File scripts\emulation-probe.ps1`, last run 2026-09-30: *"API reached,
> compiled, ran 15 p-code steps and returned to PC=0; output buffer 48 bytes all zero;
> ground truth FLAG{c01_string_table_xor} NOT recovered."* The JSON below is the research
> proposal as written that day and is kept as the record of what was measured and argued
> then. Where it says `absent`, the shipped diagnosis is `blocked` — the controlled-input
> setup is what fails, not the API (§1.5).

```jsonc
{
  "id": "native.ghidra.emulate",
  "version": 1,
  "title": "P-code emulation of a function with ghidra.app.emulator.EmulatorHelper (no debugger, no GUI)",
  "domains": ["D3", "D10", "D14"],
  "question_types": ["Q3.behaviour"],
  "consumes": {
    "inputs": [{ "name": "binary", "type": "file:pe|elf", "required": true },
               { "name": "function_va", "type": "uint64", "required": true,
                 "from": { "capability": "native.decompile.ghidra", "field": "functions[].va" } }],
    "context": [],
    "prior": ["decomp.functions[]"]
  },
  "produces": {
    "facts": [
      { "key": "emu.trace[]", "type": "emu.step",
        "fields": { "program_id": "string", "va": "uint64", "pc": "uint64",
                    "sp": "uint64", "reached_breakpoint": "bool",
                    "call_other": "string", "error": "string" } }
    ],
    "artifacts": [{ "key": "log", "type": "file:text", "path": "analyzeHeadless.log" }],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },
  "requires": {
    "runtime": "local", "net": "none", "admin": false, "device": false,
    "disk_mb": 8, "ram_mb": 1200, "wall_minutes": 1,
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" },
              { "name": "emulation-bundle-visible-to-scripts", "state": "absent",
                "probe": "postscript importing ghidra.app.emulator.EmulatorHelper from a -scriptPath outside the install",
                "expect": "NOT REACHABLE — see negative_control" }]
  },
  "proves": [],
  "does_not_prove": [
    "EVERYTHING. This entry proves nothing today. It is registered absent so that the orchestrator refuses to route a Q3.behaviour mission to a Ghidra static capability, and so the absence is discoverable rather than silent."
  ],
  "falsifies": [],
  "side_effects": [],
  "gate": { "lane": "debug", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  // proposal value as written 2026-09-30; SHIPPED state is "blocked" (probe reached and
  // ran the API, ground truth not recovered) — see the note above this block
  "state": "absent",
  "probe": {
    "command": "analyzeHeadless <proj> p -import <bin> -scriptPath <outside-install> -postScript EmuProbe.java",
    "expect": "NEVER 'EMUPROBE_OK'",
    "measured_now": "FAILS with ClassNotFoundException: Failed to get OSGi bundle containing script"
  },
  "negative_control": {
    "id": "out-of-tree-script-cannot-import-ghidra-app-emulator",
    "command": "… -postScript EmuProbe.java  (imports ghidra.app.emulator.EmulatorHelper)",
    "expect": "ghidra.app.script.GhidraScriptLoadException: The class could not be found … Failed to get OSGi bundle containing script",
    "why": "VERIFIED 2026-09-30, and the reason this entry is absent rather than 'unverified'. Emulation.jar IS present (Ghidra/Framework/Emulation/lib/Emulation.jar, 1,271,831 B, in BOTH 12.1.3 and 12.1.2) and EmulatorHelper has exactly the right API (run(Address, ProcessorContext, TaskMonitor), read/writeRegister, read/writeMemory, readStackValue, setBreakpoint, registerDefaultCallOtherCallback, getLastError). It is simply not on the out-of-tree script classloader. Control: an out-of-tree script importing only ghidra.framework.model.Project fails identically, while an out-of-tree script importing ghidra.feature.vt.* works, and the IN-TREE AutoVersionTrackingScript importing ghidra.framework.model.DomainFile works. Reaching Emulation therefore requires either a script inside a module's ghidra_scripts directory (a write into the installed tool) or a Ghidra Extension with a Module.manifest declaring the Emulation dependency (an install-class operation). Both are Owner decisions and neither is specified here."
  },
  "provenance": { "source": "Ghidra/Framework/Emulation/lib/Emulation.jar; javap ghidra.app.emulator.EmulatorHelper",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.5" }
}
```

### 3.9 `ghidra.resident.http` — `state: "degraded"`, does not compile

```jsonc
{
  "id": "ghidra.resident.http",
  "version": 1,
  "title": "Resident headless Ghidra HTTP server on 127.0.0.1:8080 (the router's `ghidra` backend)",
  "domains": ["D3", "D14"],
  "question_types": ["Q2.locate", "Q3.behaviour"],
  "consumes": { "inputs": [{ "name": "binary", "type": "file:pe", "required": true }],
                "context": [], "prior": [] },
  "produces": {
    "facts": [
      { "key": "http.routes[]", "type": "ref.route",
        "fields": { "path": "string", "implemented": "bool", "compiled": "bool" } }
    ],
    "artifacts": [{ "key": "log", "type": "file:text", "path": "analyzeHeadless.log" }],
    "invalidates_on": []
  },
  "requires": {
    "runtime": "local", "net": "loopback", "admin": false, "device": false,
    "disk_mb": 8, "ram_mb": 1200, "wall_minutes": 1,
    "tools": [{ "name": "ghidra", "probe": "…", "expect": "application.version=12.1.3" }]
  },
  "proves": [],
  "does_not_prove": [
    "ANYTHING today. The postscript does not compile, so the server never starts, so /health never answers 200, so scripts\\ghidra-headless.ps1:58-76 loops to the 600 s TimeoutMs and then exits 1 with ok:false.",
    "That /pcode, /cfg, /create_struct, /list_structs, /resolve_type, /renameVariable, /set_function_prototype, /set_local_variable_type exist. All eight are listed as implemented in headless-lab\\README.md:70-79. Measured: the file has two compile errors and none of them has ever returned a value."
  ],
  "falsifies": [],
  "side_effects": ["binds 127.0.0.1:8080", "spawns a detached cmd.exe whose lifetime outlives the wrapper"],
  "gate": { "lane": "static", "requires_verdict": "ALLOW_LOCAL", "escalation_class": "owner_word" },
  "state": "degraded",
  "probe": {
    "command": "powershell -NoProfile -File scripts\\ghidra-headless.ps1 -Sample <bin> -Http -TimeoutMs 30000",
    "expect": "NEVER '\"ok\":true' with mode=http",
    "measured_now": "FAILS. compile errors below."
  },
  "negative_control": {
    "id": "headlessmcphttp-must-compile",
    "command": "any -postScript HeadlessMcpHttp.java run",
    "expect": "no 'error:' lines in analyzeHeadless.log.err and no 'skipping …\\HeadlessMcpHttp.java'",
    "why": "VERIFIED 2026-09-30. Two hard errors: HeadlessMcpHttp.java:610 'for-each not applicable to expression type … found: java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST>' (getHighFunction().getPcodeOps() returns an Iterator, not an Iterable — headless-lab\\README.md:126-127 recorded the substitution as fixed; it is not) and HeadlessMcpHttp.java:703 'cannot find symbol: method getPointerSize() … variable currentProgram of type ghidra.program.model.listing.Program' (not mentioned in the README at all). Plus five [removal] deprecation warnings. A single compile failure in one script also makes every other failing sibling in the same -scriptPath vanish silently, while the run still logs 'Post-analysis succeeded'.",
    "expect_exit": 0
  },
  "provenance": { "source": "scripts\\ghidra\\HeadlessMcpHttp.java:610,703; scripts\\ghidra-headless.ps1:34,54-78",
                  "record": ".agent\\research\\ghidra-capability-spec.md §1.7" }
}
```

### 3.10 Deliberately **not** registered

| candidate | why not |
|---|---|
| `native.diff.fuzzyjaccard` | §2.3. Apache-2.0 and readable, but it targets cross-*compiler* matching, which this corpus does not vary, and its known failure mode (featureless tiny functions scoring 1.0) is one I measured happening inside Ghidra's own BSim correlator. Reimplementing it would add a second, weaker verdict path to `Q7.origin`. |
| `native.diff.bsim.database` | Real and available (`CreateH2BSimDatabaseScript.java`, `AddProgramToH2BSimDatabaseScript.java`, `support\bsim`, `support\bsim_ctl`, `h2-2.2.220.jar`), and §1.9 shows a database is the precondition for BSim being evidence. It is not specified because it needs a **reference corpus** decision (which binaries, how many, what disk) that is the Owner's, and because without one it produces the 461-vs-461 non-discriminator measured above. Specifying it now would be a confidently wrong entry. |
| `native.triage.ghidra.1212` | 12.1.2 works headlessly (verified) but `scripts\ghidra-headless.ps1:22` hardcodes 12.1.3 and `:23` throws. A second id implies a fallback that does not exist. One id, one probe. |
| `native.strings.ghidra.decoded` | Stack-string recovery is FLOSS's job and already has an id in the design doc (`native.strings.floss`, round 2). Ghidra's `strings[]` must not claim `decoded[]`. |

---

## 4. Coverage and honest gaps

The brief asked for at minimum: program triage, decompile, string/symbol extraction,
cross-binary version tracking, p-code emulation. Status:

| required | entry | state |
|---|---|---|
| program triage | `native.triage.ghidra` | **observed** — measured 18.05 s, 673 KB, verified NC |
| decompile | `native.decompile.ghidra` | **observed** — 512/512 measured; one NC `[UNVERIFIED]` |
| string/symbol extraction | `native.strings.ghidra` | **observed** — 291 entries measured, decoy-flag NC verified |
| cross-binary version tracking | `native.diff.ghidra.vt`, `native.diff.ghidra.autovt`, `native.diff.manifest` | **observed / observed / degraded** — VT measured end-to-end with 3 measured controls |
| p-code emulation | `native.ghidra.emulate` | **blocked** — the API is reachable and ran 15 p-code steps; the controlled-input setup does not take, so ground truth was not recovered. Shipped, not this document's proposal |

Plus, because the research turned them up: `native.symhash.ghidra` (degraded, does not
compile) and `ghidra.resident.http` (degraded, does not compile). Neither id is in the
shipped registry; see §5.

**Facts in this document that are `[UNVERIFIED]` or inference, stated plainly:**

1. `native.decompile.ghidra`'s negative control is specified but not exercised — no
   target in `crackme-corpus` defeats the decompiler.
2. `native.symhash.ghidra` and `native.diff.manifest` are specified from source reading
   only; neither has ever run, and `headless-lab\README.md:134-137` is right that
   neither has.
3. `headless-lab\README.md:70-79,122-127,129-147` contains three claims this document
   contradicts with measurements: the `/pcode` fix was not a fix, the compile was never
   clean, and "FunctionHashes/DiffPrograms have never been executed" understates it —
   they never compiled. That README should be corrected by its owner.
4. The 12.1.2 timings (29 s) are first-touch on a cold run and were not repeated; treat
   them as ±50%.
5. All wall times are from one 140 KB PE with 512 functions. They scale with
   auto-analysis, not with file size — a 40 MB Android `.so` or a 200 MB unstripped
   binary will not fit these numbers, and the registry's `wall_minutes` is a floor, not
   a model.

**One owner-gated decision this research surfaces** (not mine to make, recorded so it is
not lost): the fix set is small and entirely mechanical —

- `FunctionHashes.java:30` drop `static` (unblocks `native.symhash.ghidra`);
- `HeadlessMcpHttp.java:610` `Iterator` → loop (unblocks `/pcode`);
- `HeadlessMcpHttp.java:703` `currentProgram.getPointerSize()` →
  `currentProgram.getDefaultPointerSize()` or `getAddressFactory().getDefaultPointerSize()`;
- `ExportDecompile.java` record the disassembly-fallback count in `summary.json`;
- `ghidra-headless.ps1:89,97` `$p.ExitCode` is `$null` after
  `Start-Process -PassThru` + `WaitForExit(<int>)` — cache `$p.Handle` (or use `-Wait`)
  so the exit code is real, and remove the leaked empty `%TEMP%\ghidra-proj-*`
  directory at `:31-32`;
- give each postscript its own `-scriptPath` directory so one compile failure cannot
  `skipping` its siblings;
- correct `headless-lab\README.md` and delete or rewrite the void note in
  `DiffPrograms.java:6-12`.

None of these were applied — this assignment is read-only against the repo.

---

## 5. Registry-entry id list (the answer to the brief's last question)

> **PROPOSAL, superseded by `manifests/capabilities.json`.** The shipped registry held
> **15 entries** when this document was written (`python scripts/registry-verify.py` →
> `capabilities: 15`, CLEAN) and holds **16 at `HEAD` = `e246427`** (re-verified 2026-10-02:
> `capabilities: 16`, `REGISTRY CLEAN`, exit 0). The sixteenth is **`dynamic.win.frida`** —
> Windows-local Frida, added by commit `4e381f0`; it is not a Ghidra entry and does not
> change anything below. *(A sibling added a 17th, `ops.skill.security`, to the working tree
> during the 2026-10-02 reconciliation; the committed count is 16.)* Of the nine ids proposed
> below, `native.ghidra.emulate` shipped (as `blocked`); the other eight —
> `native.diff.ghidra.vt`, `native.symhash.ghidra`, `ghidra.resident.http` and the rest —
> are **not** in the shipped registry. Kept as the research record.

```
native.triage.ghidra          observed
native.decompile.ghidra       observed
native.strings.ghidra         observed
native.symhash.ghidra         degraded   (does not compile: FunctionHashes.java:37)
native.diff.manifest          degraded   (blocked by native.symhash.ghidra)
native.diff.ghidra.vt         observed
native.diff.ghidra.autovt     observed
native.ghidra.emulate         blocked     (SHIPPED id; proposal said absent. API reached,
                                         ran 15 p-code steps; ground truth not recovered)
ghidra.resident.http          degraded   (does not compile: HeadlessMcpHttp.java:610,703)
```

Nine entries. `native.diff.fuzzyjaccard` and `native.diff.bsim.database` are
deliberately absent — §3.10.

---

## 6. Reproduction

Everything above, on this box, with the paths as they are.

### 6.1 The AutoVersionTrackingScript run (the load-bearing claim)

```bash
G=/d/Software/Tool/WorkStation/debugger/Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC
B=%USERPROFILE%/AppData/Local/Temp/ghcap-vt-20260930
mkdir -p "$B"/{scripts,proj,out}
cp "$G/Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java" "$B/scripts/"
cp "$G/Ghidra/Features/VersionTracking/ghidra_scripts/SetAutoVersionTrackingOptionsScript.java" "$B/scripts/"
printf 'Enter Auto Version Tracking Information Version Tracking Session Folder = /\nEnter Auto Version Tracking Information Version Tracking Session Name = vt_probe\nEnter Auto Version Tracking Information Please select the SOURCE program = /c02-cff-dispatch.exe\n' > "$B/scripts/AutoVersionTrackingScript.properties"
# then, via import.bat / vt.bat in that dir:
#   analyzeHeadless <proj> vtproj -import c01-stringobf.exe c02-cff-dispatch.exe -overwrite
#   analyzeHeadless <proj> vtproj -process c01-stringobf.exe -noanalysis -scriptPath <scripts> \
#     -postScript SetAutoVersionTrackingOptionsScript.java -postScript AutoVersionTrackingScript.java
# look for: 'Auto Version Tracking Command completed successfully with no apply markup errors.'
```

### 6.2 The version-tracking probe that produced §1.9

Same directory, same `-process c03_antidebug.exe -noanalysis` host. `VtProbe.java`
extends `AbstractGhidraVersionTrackingScript`, takes the two program paths as
positional args 1 and 2 (arg order = `askProgram` call order), reads its output
directory from the `VTPROBE_OUT` env var, and writes `vt-probe.tsv` with header
`correlator\tsource_addr\tdest_addr\tsrc_len\tdst_len\tsimilar\tconfidence\ttag`.
Three invocations: `/c01-stringobf.exe`+`/c02-cff-dispatch.exe`,
`/c01-stringobf.exe`+`/c01-copy.exe` (md5-identical),
`/c01-stringobf.exe`+`/c05-binary-format.exe`.

### 6.3 The cost measurement

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File 'D:/Software/Tool/WorkStation/debugger/scripts/ghidra-headless.ps1' \
  -Sample 'D:/Software/Tool/WorkStation/debugger/crackme-corpus/out/c01-stringobf.exe' \
  -OutDir '%USERPROFILE%/AppData/Local/Temp/ghcap-a2-20260930-1'
# 19.08 s wall, 673,220 B, 522 files
```
RAM: `scripts`-external `measure.ps1` (Start-Job + `Get-Process java | Sort WorkingSet64`
every 150 ms) → `{"wall_seconds":18.05,"peak_java_ws_mb":1085.7,…}`.
Project sizes: `du -sb` on the retained `%TEMP%\ghidra-proj-*` directories.

### 6.4 API signatures

```bash
cd "$G/Ghidra/Features/VersionTracking/lib"
javap -cp "D:\\…\\VersionTracking.jar" ghidra.feature.vt.AbstractGhidraVersionTrackingScript
javap -cp "D:\\…\\VersionTracking.jar" ghidra.feature.vt.api.main.VTMatch
cd "$G/Ghidra/Framework/Emulation/lib"
javap -cp "D:\\…\\Emulation.jar" ghidra.app.emulator.EmulatorHelper
```
(classpath must be Windows-style; the POSIX form fails with `class not found`)

### 6.5 The negative controls

```bash
# triage / decompile NC — a file with no loader
printf 'not a container\n' > %USERPROFILE%/AppData/Local/Temp/ghcap-nc/out/plain.txt
# → 'No load spec found for import file: plain.txt' / 'Import failed' / exit 0 / NO summary.json
# strings NC — the corpus's own decoy
head -1 %USERPROFILE%/AppData/Local/Temp/ghcap-a-20260930-1/strings.txt
# → 140017368 FLAG{c01_strings_gave_you_this_decoy}
# VT NC — the three-way comparison, §1.9 table
```

### 6.6 Prior-art clones

```bash
gh repo clone cellebrite-labs/ghidra-rpc -- --depth 1
gh repo clone bethington/ghidra-mcp     -- --depth 1
# into %USERPROFILE%\AppData\Local\Temp\re-research\GhidraSpec\
```
Key files read: `ghidra_rpc/server/context.py:24-413`,
`ghidra_rpc/server/main.py:26-34`, `ghidra_rpc/server/launcher.py:15-140`,
`ghidra_rpc/session.py:37-230`, `ghidra_rpc/daemon.py:14-208`,
`ghidra_rpc/server/tools/version_tracking.py:17-320`, `SKILL.md:24-145`,
`src/main/java/com/xebyte/core/BinaryComparisonService.java:22-1015`.

Nothing was installed, no git writes, no Docker, and no write to either Ghidra install.
All scratch work is under `%TEMP%` (`ghcap-*`, `emu-manifest`) and
`re-research\GhidraSpec`, outside both repos.

---

## 7. One-paragraph answer to the brief

The `AutoVersionTrackingScript` claim **verified** — the header at
`AutoVersionTrackingScript.java:27-41` documents the headless non-shared-project
invocation and `:171-180` opens the second program in-process, and I ran it end to end
(7 s, "completed successfully with no apply markup errors"), which makes the
`DiffPrograms.java:6-12` justification void and is a bonus finding rather than a
workaround. One headless run on our own 140 KB crackme costs **18.05 s wall, 1,085.7 MB
peak JVM RSS, 673 KB of artifacts, ~4.3 MB if the project is retained** (three wall
samples: 18.05 / 19.08 / ~25 s; 12.1.2 does the same in 29 s cold). We do **not** need
bethington's `BinaryComparisonService`: it targets cross-*compiler* matching, which this
corpus never varies, its known failure mode is the one I measured inside Ghidra's own
BSim correlator (461 matches against a byte-identical copy *and* 461 against an
unrelated binary), and ghidra-rpc — a vendor shipping this for money — chose Ghidra's
correlator factories. The nine registry ids proposed here are in §5 — a PROPOSAL,
superseded: of the nine only `native.ghidra.emulate` shipped, and it shipped **`blocked`**
(API reached and ran 15 p-code steps, ground truth not recovered), not `absent`. Of the
proposed set: **five `observed`** with measured costs and measured negative controls,
**three `degraded`** because their scripts have
never compiled (`FunctionHashes.java:37`, `HeadlessMcpHttp.java:610,703`, and
`DiffPrograms.java` which depends on the first), and **one `blocked`** because the
controlled-input setup is what fails, not the `ghidra.app.emulator` API. One fail-open
surfaced that the registry must encode: `analyzeHeadless`
**exits 0 when the import fails** and `scripts\ghidra-headless.ps1` exits 0 too, so no
Ghidra entry may gate on the exit code.
