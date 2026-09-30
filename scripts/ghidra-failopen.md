Source: local path — measured on this host 2026-09-30, `Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC`
Fetched: 2026-09-30 (UTC)
Status: verified

# Ghidra headless: what is true, what was false, and one fail-open we fixed

## The recorded blocker was false

`scripts\ghidra\DiffPrograms.java:6-12` claimed: *"Ghidra 12 has no framework-level
ProgramManager, so a headless script cannot open a sibling program from the same
project"*, and used that to justify a two-manifest design.

**Void.** `Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java`
is present in both installs (16,372 B, 359 lines). Its header at :27-41 documents the
headless non-shared-project invocation, and :171-180 does
`startupValues.getProjectFile('Please select the SOURCE program')` then
`sourceProgramDF.getDomainObject(this, autoUpgradeIfNeeded, false, monitor)` — a second
`Program` live in the same process.

Ran it rather than reading it: two of our own crackmes imported into one project,
**7 s wall**, `Auto Version Tracking Command completed successfully with no apply markup
errors.` A second probe held **three** programs open in one headless process and ran
all 14 program correlators across two of them (14–17 s, 2,889,483 B TSV).

**Real cross-binary matching needs nothing installed.** The blocker note is deleted
rather than annotated, because an annotated false claim is still a false claim waiting
to be believed.

Three defects in that script's header, found on the way: `NUM_ARGS=3` at :107 is dead
code — `getScriptArgs()` appears nowhere in the file, so the three documented CLI
arguments are never read. Headless `askValues` is keyed `"<askValues title> <variable>"`
in a co-located `.properties`, not by bare key. And positional script arguments are
consumed by `askXxx` **in call order** before the properties file is consulted, so a
trailing options argument gets eaten by the first `askProgram`.

## Measured cost of one headless run

Target `c01-stringobf.exe`, 140.5 KB, MSVC x64 PE, 512 functions.

| | |
|---|---|
| wall | **18.05 s** (first sample ~25 s; auto-analysis alone reports `Total Time 9 secs`) |
| peak RAM | **1,085.7 MB** java working set, sampled every 150 ms |
| artifacts | 673,090–673,220 B across 522 files (512 `.c` + 10 meta) |
| project on disk | 3.62–4.46 MB for **one** retained analysed program; 8.88 MB for two |

Disk figures are direct `Get-ChildItem` measurements of the artifact, **never a
`df` delta**. Free-space deltas on this box are garbage: one 29 s run showed a
633,988 KB `C:` delta while writing 673 KB, because a sibling lab was consuming `C:`
concurrently.

For scale: `VT -process` 14–17 s, `AutoVT` 7 s, and **Ghidra 12.1.2 doing the identical
job 29 s cold**.

## Fail-open, found and fixed

`analyzeHeadless.bat` **exits 0 when the import fails outright** — reported by research,
and confirmed in the form that matters: **our own wrapper**.

Feeding a `.txt` to `scripts\ghidra-headless.ps1`:

```json
{"ok":false,"outdir":"...","tool":"ghidra","log":"...","exit":null}
OUR_WRAPPER_EXIT = 0
```

The cause is not Ghidra. `Start-Process -PassThru` combined with `WaitForExit(<int>)`
hits a .NET handle-caching quirk: the handle is never fully populated, so
`$p.ExitCode` reads **`$null`** — and PowerShell's `exit $null` is **exit 0**. A failed
import was a PASS for anything checking the exit code.

Two corrections to the record, because getting this backwards is easy:

- The research also claimed `analyzeHeadless.bat` itself exits 0. **That did not
  reproduce here.** Measured directly on 12.1.3 with a `.txt` input, `ExitCode` was **1**
  and the output carried a stack trace through `AnalyzeHeadless.launch`. The wrapper
  behaviour above is confirmed and is the one that mattered; the batch file's own exit
  code is 1.
- **My first fix was wrong in the opposite direction.** Requiring `exit -eq 0` *and* the
  artifact made every run fail, because `ExitCode` is `$null` on the success path too.
  The only honest signal is the artifact.

Fixed by gating on the named artifact alone: if `summary.json` exists, Ghidra got far
enough to finish; if it does not, the run failed whatever any exit code claims.

Regression: `scripts\ghidra-failopen-regress.ps1` — **4/4, LOOP CLOSED**. Negative:
a non-binary exits non-zero and produces no `summary.json`. Positive: a real crackme
still exits 0 and still produces it.

**No Ghidra registry entry may gate on `expect_exit`.** Gate on `ok:true` plus the
entry's own named artifact.

## Leak found

**30** `%TEMP%\ghidra-proj-*` directories already existed before this work began — 26
empty, 4 non-empty at ~3.5 MB each, roughly **14 MB stranded on `C:`**.
`ghidra-headless.ps1:41` only adds `-deleteProject` on the no-PostScript/no-Http path,
so the normal path leaves the project directory behind every run.

## Answer: is bethington's comparison service needed?

**No**, and the split is not the one assumed. Ghidra's own Version Tracking already
provides exact, reference and BSim correlators headlessly. Reimplementing a
Jaccard-over-features comparator would duplicate shipped functionality — and would have
had to reproduce its documented bug, where `jaccard(∅,∅)=1.0` made featureless functions
score ~1.0 until empty-vs-empty components were excluded.

## Reproduction

```powershell
# cross-binary matching, zero install
#   stage AutoVersionTrackingScript.java + a .properties, import two crackmes into one
#   project, run it. ~7 s.
# cost of one headless run
powershell -File scripts\ghidra-headless.ps1 -Sample crackme-corpus\out\c01-stringobf.exe `
    -OutDir $env:TEMP\gh-cost
# the fail-open regression
powershell -File scripts\ghidra-failopen-regress.ps1
```
