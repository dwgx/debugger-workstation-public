# Binary-analysis agent/MCP ecosystem map — how far behind is the native station?

**Date:** 2026-09-30 · **Author:** `BinaryMcpMap` (delegated research)
**Scope:** public repos only. Every repo below was opened via the authenticated `gh` CLI; the
five highest-value ones were shallow-cloned to
`%USERPROFILE%\AppData\Local\Temp\re-research\BinaryMcpMap\` and read at file level.
Claims marked `[INFERENCE]` are not directly evidenced by a file read.

---

## 0. TL;DR

Our native headless path is **not far behind on API surface** — it is behind on **four specific
capabilities**, and two of them are already shippable inside Ghidra with **zero install**.

The uncomfortable finding first: **our own lab's claimed blocker is wrong.**
`headless-lab/README.md` §1 records the reason `cellebrite-labs/ghidra-rpc` was refused, and
`notes/2026-09-30-managed-native-depth.md` line 82-84 asserts:

> *"Ghidra 12 has no framework-level `ProgramManager`, so a headless script cannot open a sibling
> program from the same project. Hence the two-manifest design for the diff."*

The `ProgramManager` half is true. The conclusion is false. Ghidra ships
`Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java`, which
(a) documents a **headless non-shared-project** invocation in its own header comment
(lines 27-36), and (b) opens the source program at **line 171** via

```java
DomainFile sourceProgramDF = startupValues.getProjectFile("Please select the SOURCE program");
...
Program sourceProgram = (Program) sourceProgramDF.getDomainObject(this, autoUpgradeIfNeeded, false, monitor);
```

`GhidraValuesMap.getProjectFile(String)` exists — verified by extracting
`ghidra/features/base/values/GhidraValuesMap.class` from our own
`Ghidra/Features/Base/lib/Base.jar` and running `javap -p`:

```
public ghidra.framework.model.DomainFile getProjectFile(java.lang.String);
public ghidra.framework.model.DomainFolder getProjectFolder(java.lang.String);
```

It resolves a **project-relative** `DomainFile` and opens it through
`DomainFile.getDomainObject` — the project file system, not `ProgramManager`. So a headless
postscipt **can** open a sibling program from the same project, and therefore
**real Ghidra Version Tracking (exact + reference + BSim correlators) is available to us today
with nothing installed.** That is the single largest item in this report.

---

## 1. What our native path already does (ground truth, so the delta is honest)

Read: `scripts/ghidra-headless.ps1` (98 lines), `scripts/ghidra/*.java`, `headless-lab/README.md`,
`notes/2026-09-30-managed-native-depth.md`.

| file | lines | role |
|---|---|---|
| `scripts/ghidra-headless.ps1` | 98 | wrapper over `analyzeHeadless.bat`, hard-pinned to `ghidra_12.1.3_PUBLIC`; 3 modes: default export, `-Http`, `-PostScript/-PostArgs` |
| `scripts/ghidra/HeadlessMcpHttp.java` | 1083 | 33 HTTP routes, `GhidraScript` postscript, wired to router backend `ghidra` on `127.0.0.1:8080` |
| `scripts/ghidra/ExportDecompile.java` | 179 | default mode: decompile every function to `.c` + `summary.json` |
| `scripts/ghidra/FunctionHashes.java` | 75 | one line/function: name, size, **MD5 of body bytes** |
| `scripts/ghidra/DiffPrograms.java` | 149 | two-manifest diff, match by name then hash |

Routes served today (from `HeadlessMcpHttp.java`, `createContext` scan): `/health /decompile
/decompile_function /disassemble_function /list_functions /searchFunctions /get_function_by_address
/get_current_address /get_current_function /function_xrefs /xrefs_to /xrefs_from /strings /imports
/exports /segments /classes /methods /namespaces /data /pcode /cfg /create_struct /list_structs
/resolve_type /renameFunction /rename_function_by_address /renameData /renameVariable
/set_function_prototype /set_local_variable_type /set_decompiler_comment /set_disassembly_comment
/shutdown`.

**Proven on this box:** `labnative.dll` → 398 functions, 398 `.c` files, `{"ok":true}`, exit 0
(README §4, re-verified after the `-PostScript` addition).

**Not proven — do not claim:** `/pcode`, `/cfg`, `/create_struct`, `/list_structs`,
`/resolve_type`, `/renameVariable`, `/set_function_prototype`, `/set_local_variable_type` have
never returned a value. `FunctionHashes.java` and `DiffPrograms.java` have **never been executed**.
`headless-lab/tools/loop.mjs` **does not exist** (verified: `find headless-lab -type f` returns
`native/core.c`, 5 `out/*` build artifacts, `README.md`, `tools/build.ps1` — nothing else).

So the honest statement of the native path is: **a 33-route single-program headless HTTP server
whose read routes work and whose new write routes are compile-verified but unexercised, with a
two-manifest cross-binary diff that has never run, and no self-judging runner.**
`managed-lab` (27/27 pass) is the only proven thing; `headless-lab` is half-finished code.

---

## 2. The comparison set (verified metadata, 2026-09-30)

All rows from `gh api repos/OWNER/REPO` (stars, `license.spdx_id`, `pushed_at`, `size`).

| repo | stars | license | pushed | size | read how |
|---|---|---|---|---|---|
| `LaurieWired/GhidraMCP` | 10,224 | Apache-2.0 | **2025-06-23** (15 mo stale) | 180 KB | README in full (119 lines) |
| `bethington/ghidra-mcp` | 4,059 | Apache-2.0 (+NOTICE) | 2026-09-29 | 14.6 MB | **shallow clone**; README 1550 lines; `EmulationService.java`, `BinaryComparisonService.java`, `DocumentationHashService.java`, `tests/endpoints.json` |
| `cyberkaida/reverse-engineering-assistant` (ReVa) | 840 | Apache-2.0 | 2026-09-29 | 2.7 MB | **shallow clone**; README + all 21 `*ToolProvider.java` |
| `mrexodia/ida-pro-mcp` | 12,411 | MIT | 2026-09-26 | 2.5 MB | README in full (433 lines) |
| `HexRaysSA/ida-mcp` (new, official) | 424 | MIT | 2026-09-29 | — | metadata only |
| `cellebrite-labs/ghidra-rpc` | 355 | **NONE** | 2026-09-17 | 1.6 MB | **shallow clone**; `docs/internals.md`, `SKILL.md` headings, `version_tracking.py` |
| `llnl/OGhidra` | 445 | BSD-3-Clause **+ commercial alternative** (API reports `NOASSERTION`) | 2026-09-28 | 3.8 MB | README in full (608 lines) |
| `LING71671/open-reverselab` | 1,193 | GPL-3.0 | 2026-09-29 | 7.3 MB | README (264 lines) |
| `blacktop/ida-mcp-rs` | 848 | MIT | 2026-09-24 | 961 KB | README head |
| `P4nda0s/IDA-NO-MCP` | 2,036 | **NONE** | 2026-07-26 | 125 KB | README head |
| `MeroZemory/ida-multi-mcp` | 442 | **NONE** | 2026-09-19 | 609 KB | README head |
| `Claude-Reverser/IDA-instances-MCP` | 457 | MIT | 2026-08-23 | 2.8 MB | metadata only |
| `cycraft-corp/BinaryAnalysisMCPs` | 117 | MIT | **2025-08-26** (13 mo stale) | 116 KB | README in full |
| `xiaoyeuzixi/revlab` | 70 | **NOASSERTION** | 2026-09-03 | 1.2 MB | README head |
| `Ap3x/BinaryAnalysis-MCP` | 25 | GPL-3.0 | 2026-03-06 | 165 KB | metadata only |
| `bethington/re-universe` (BSim/Postgres) | 17 | MIT | **2026-03-12** (6 mo stale) | — | metadata only |

Also surfaced by `gh search repos` and judged: `clearbluejar/pyghidra-mcp` (427, Apache-2.0),
`mrphrazer/ghidra-headless-mcp` (180, GPL-2.0), `13bm/GhidraMCP` (143, Apache-2.0, socket-based,
10 read-only tools), `dnakov/frida-mcp` (434, mobile-side, out of scope here),
`20urc3/Sekiryu` (361, Ghidra headless), `galoget/ghidra-headless-scripts` (83).

**`bethington/ghidra-mcp` Ghidra 12.1.3 claim: VERIFIED.** `pom.xml` line:
`<ghidra.version>12.1.3</ghidra.version>`, and all 14 `<dependency>` blocks pin
`<version>${ghidra.version}</version>`. README badge and `docs/INSTALL_GUI.md` agree.
Tool count claim **VERIFIED**: `python -c "json.load(open('tests/endpoints.json'))"` →
`total_endpoints = 253`, actual `len(d['endpoints']) = 253`. (The README's own split:
239 GUI / 226 headless / 212 both / 27 GUI-only / 14 headless-only — so **no single server
exposes all 253**.)

**ReVa Ghidra 12.1.3: VERIFIED** via releases — `v7.3.1`, published 2026-09-03, titled
*"ReVa 7.3.1 - Ghidra 12.1.3 and MCP 2.0 support"*.

---

## 3. Question 1 — Capability delta, named concretely

### 3.1 What the best public Ghidra integration gets that we cannot

Ranked by how much it would actually change our lab's loop.

#### D1 — Real cross-binary function matching (Version Tracking / BSim). **We have none.**

bethington's cross-binary story is **not** BSim, and this is worth stating because our own note
credits `ghidra-rpc` with BSim. What bethington actually ships:

- `find_similar_functions_fuzzy`, `bulk_fuzzy_match`, `find_similar_functions` →
  `src/main/java/com/xebyte/core/BinaryComparisonService.java` (1015 lines). Scoring at lines
  390-447: `computeSimilarity = WEIGHT_NUMERIC*numeric + WEIGHT_SET*set + WEIGHT_STRUCTURAL*structural`.
  - numeric axis: instruction count, basic-block count, call count, cyclomatic complexity,
    edge count, string-reference count;
  - set axis: **Jaccard** over callee names, string constants, immediate values — with a
    documented fix at lines 417-424 that *excludes empty-vs-empty components and renormalizes the
    weights*, because `jaccard(∅,∅)=1.0` made tiny featureless functions score ~1.0 against
    everything;
  - structural axis: block-hash similarity.
- `get_bulk_function_hashes`, `get_function_hash`, `apply_function_documentation`,
  `merge_program_documentation`, `compare_programs_documentation`, `diff_functions` →
  `DocumentationHashService.java` (1992 lines). Line 195-204: `SHA-256` over a **normalized
  mnemonic+operand string** where scalars `< 0x10000` are kept as `IMM:<value>`, larger ones
  collapse to `IMM_LARGE`, and address-space operands collapse to `ADDR` (line ~160).
  This survives recompiles. `grep -rn "FunctionID\|bsim" src/main` finds **one hit, a tool
  description string** — so bethington does **not** use Ghidra BSim; the BSim story is delegated
  to `bethington/re-universe` (17 stars, MIT, stale since 2026-03-12), which needs Docker +
  PostgreSQL + Spring Boot.

  **Our equivalent is `FunctionHashes.java`: MD5 of raw function body bytes.** That is
  *recompile-fragile by construction* — any recompile that shifts a function's bytes (a changed
  constant elsewhere in the translation unit, a different optimization level, one added function)
  changes its MD5, and `DiffPrograms.java` will call it CHANGED.

  **But our own sample does not prove this**, and the gap is worth naming precisely.
  `headless-lab/native/core.c:12` states *"`classify` is byte-identical between them; `checksum` is
  not"*, and the build is `cl /O1 /DLAB_MASK=0xA7` vs `cl /O1 /DLAB_MASK=0x3C` (line 16) — the same
  optimization level, so nothing shifts. Verified: `md5sum out/core_v1.dll out/core_v2.dll` gives
  two different file hashes (`0d9e1210…`, `4ed4fc98…`), same size 104,448 bytes, and the single
  `#ifndef LAB_MASK` at line 23 feeds only `checksum`'s FNV seed (line 38). So MD5-of-bytes
  **passes** the existing acceptance check and the sample therefore **cannot discriminate**
  MD5 from a normalized hash. The sample was engineered for a name-then-hash matcher, not to
  stress one. Fixing that is a prerequisite of Step 2, not a footnote to it.

  **Meanwhile the real thing is already on disk**, unused:
  `Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java` and
  `FindChangedFunctionsScript.java`, plus `Ghidra/Features/BSim/ghidra_scripts/`
  (`CreateH2BSimDatabaseScript.java`, `GenerateSignatures.java`, `LocalBSimQueryScript.java`,
  `CompareExecutablesScript.java`) and `Ghidra/Features/FunctionID/ghidra_scripts/`
  (`FunctionIDHeadlessPostscript.java`, `CreateEmptyFidDatabase.java`, `FindFunctionByHash.java`).
  All present in **our** 12.1.3 install. Zero install required.

  Blocker on our side is purely the wrapper: `ghidra-headless.ps1` creates a fresh temp project
  (line 31-32), imports **one** sample, and `-deleteProject`s it (line 41) unless `-Http`.
  `support/analyzeHeadlessREADME.md` line 144-149 confirms `-import` may be **repeated** and
  take multiple files, so a two-step run is possible:
  `analyzeHeadless <proj> agent -import v1.dll v2.dll -overwrite` then
  `analyzeHeadless <proj> agent -process v2.dll -postScript AutoVersionTrackingScript.java / sess /v1.dll`.

#### D2 — P-code emulation. **We have none, and it is the cheapest large win.**

`EmulationService.java` (502 lines) wraps `ghidra.app.emulator.EmulatorHelper`. The class
javadoc (lines 22-42) documents the exact agent workflow: decompile the hash function →
identify input/output registers → `emulate_function(hash_func_addr, registers={ECX: str_ptr},
memory=[{addr: str_ptr, data: "CreateProcessW\0"}])` → read EAX → compare to target hash →
comment the call site. `emulate_hash_batch` brute-forces up to `MAX_CANDIDATES = 10_000`
strings at `MAX_STEPS = 100_000` per run with a 10 s default timeout, writing candidates into
scratch memory at `SCRATCH_BASE = 0x7FFE0000`, `SCRATCH_SIZE = 0x10000`, with a
`wide_string` flag for UTF-16LE.

This turns "brute-force an import hash" from a dynamic-execution problem into a static,
milliseconds, **headless** one. `m04` in our `managed-lab` (FNV-1a/32 over length-prefixed
records) and `m01` (keystream XOR) are exactly this shape — our current answer is "read the
constant out of the decompilation", which works because we authored the samples. On a real
binary with a computed hash, we are stuck.

**Our box is ready:** `Ghidra/Framework/Emulation/lib/Emulation.jar` exists. That jar is one of
bethington's 14 declared dependencies.

#### D3 — PCode-graph dataflow (forward/backward value propagation). **We have raw P-code only.**

bethington `analyze_dataflow` — "Trace value propagation through a function (PCode graph,
forward/backward)". ReVa has the same idea as two tools, `trace-data-flow-forward` and
`trace-data-flow-backward`.

Ours is `/pcode?address=` → a dump of `getHighFunction().getPcodeOps()` with source addresses.
A dump is not a dataflow. The dump gives the agent raw SSA it must interpret; the dataflow tool
answers "where did this register value come from / where does it go", which is the question
`/pcode` leaves open. And ours is **unproven** (never returned a value).

#### D4 — Struct/type authoring from real C headers. **We have hand-rolled field strings.**

ReVa's `parse-c-header`, `parse-c-structure`, `validate-c-structure` (all three verified present
in `DataTypeToolProvider.java` / `StructureToolProvider.java`) take a C header and produce
Ghidra `Structure` types.

Ours is `/create_struct` with `fields` as a hand-formatted string
`off:len:type[:name];…` (README §2). An agent reverse-engineering a PE with a `tbsa`/`DRIVER_HEADER`
layout must hand-format offsets and lengths, and gets no validation. ReVa validates.

#### D5 — C++ vtable / virtual-dispatch reconstruction. **We have nothing close.**

ReVa `VtableToolProvider.java` — 3 tools, `analyze-vtable`, `find-vtable-callers`,
`find-vtables-containing-function`. The detection heuristic is documented in the class header
(lines 42-60): `VTABLE_PROBE_ENTRIES = 5` probe depth, `MIN_VTABLE_FUNCTION_POINTERS = 2`,
and `OFFSET_LOOKBACK_INSTRUCTIONS = 32` — the last with the comment that this is sized for
**ARM64 split `ldr`/`blr` patterns** while x86/x64's `call [reg+offset]` resolves inside the call
instruction's own P-code. That is a real engineering detail, not a vibe.

bethington's nearest is `add_memory_reference` (for vtables the analyzer missed) and
`find_similar_functions` — neither reconstructs a vtable.

#### D6 — Staged diff as a first-class subsystem (ReVa's 13 tools). **We have one untested script.**

`diff-create-session`, `diff-add-correlator`, `diff-status`, `diff-cancel`, `diff-summary`,
`diff-data`, `diff-strings`, `diff-function`, `diff-list-functions`, `diff-list-sessions`,
`diff-delete-session`, `diff-apply-match`, `diff-transfer-markup`. Correlators are *added to a
session incrementally*, status is async and cancellable, and `diff-transfer-markup` moves
documentation from one side to the other.

`DiffPrograms.java` is 149 lines, reads two static manifests, matches name-then-hash, and has
never run. This is the gap between "a diff script" and "a diff subsystem".

#### D7 — Ghidra Server + multi-user version control. **We have none, and do not need it.**

bethington: 14 `server_*` tools — `server_repositories`, `server_repository_create`,
`server_version_control_checkout/checkin/history/add/undo_checkout`, `server_authenticate`,
`server_admin_users`, `server_admin_set_permissions`, `server_admin_terminate_checkout`.
Requires a running Ghidra Server (its own process + its own RAM). For a single-owner station
this is capability we should decline, not acquire.

#### D8 — Live debugger over TraceRmi. **Partial: our jars are here, our surface is not.**

bethington: 17 Java endpoints + 22 Python proxy tools, explicitly gated — the proxies register
**only** when `GHIDRA_DEBUGGER_URL` is set (documented under "The `debugger_*` tools do not
appear"). Verified against the catalog rather than the README: `tests/endpoints.json` has
**18** entries whose `path` contains `debugger`, and **every one** carries `servers: ['gui']` — so
the debugger is unreachable from the headless server by construction, not by omission.
`/debugger/dynamic_to_static` and `/debugger/static_to_dynamic` give ASLR-aware address
translation between the static program and the live trace — that pairing is the interesting part.

Important: **the debugger server itself moved out of the repo** to `d2-game-exe` on 2026-08-11
("its D2 calling-convention layer made it game-specific"). So adopting the debugger means
adopting a game-specific repo. Our box *does* have `Ghidra/Debug/Debugger-agent-dbgeng` and
`Ghidra/Debug/Debugger-agent-x64dbg` installed.

#### D9 — Convention enforcement in the tool layer (bethington v5.0). **A design idea, not a capability.**

Three tiers: **auto-fix** (`count` field on a `uint32` → silently prefixed `dwCount` on save),
**warn** (`processData` → "should be PascalCase with a verb"), **reject** (`undefined → undefined`
→ no-op rejected, type unchanged). Rationale in the README: *"v5.0 moves conventions from 'things
to remember' into the tool layer, where they can actually be enforced."* Plus
`analyze_function_completeness` — a 0-100 score with structural deductions forgiven, log-scaled
categories, and tiered plate-comment quality.

The scoring function is the more interesting half: it gives us a **machine-checkable definition of
"documented"**, which is exactly what our self-judging runners currently lack. Our `managed-lab`
runner has invariants; it has no per-function completeness metric.

#### D10 — Lazy tool loading (bethington). **Directly applicable to our 19-backend router.**

`load_tool_group` / `unload_tool_group` / `list_tool_groups` / `search_tools` / `check_tools`.
The bridge registers only `listing,function,program` on connect; the model discovers the rest.
`search_tools` works even for unloaded groups and returns the exact `load_tool_group(...)` call
needed. bethington's README also works out the **minimum viable read-only set of 4 tools**
(`get_metadata`, `list_methods`, `get_entry_points`, `decompile_function`) and, creditably,
documents the failure mode of over-narrow allowlists (the agent bypasses MCP and `curl`s
`127.0.0.1:8089` directly).

#### D11 — Multi-program in one session. **Structurally impossible for us today.**

bethington: `switch_program`, `list_open_programs`, `open_program`, `close_program`,
`import_file`, `archive_project`, `export_program`/`import_program` (`.gzf`), `restore_project`
(`.gar`). Our `HeadlessMcpHttp` is a postscript: it is handed exactly **one** `currentProgram`
by `analyzeHeadless`, and per our own note Ghidra 12 exposes no framework `ProgramManager` to
open a sibling — which is precisely why VT (§3.1 D1) must go through the project file system
instead.

#### D12 — Decompiler scripting driven by the agent. **We have it, differently.**

bethington: `list_scripts`, `run_ghidra_script`, `run_script_inline`. Note the security posture:
**off by default since v5.4.1** — `GHIDRA_MCP_ALLOW_SCRIPTS` must be set, and enabling it in
headless mode triggers OSGi `BundleHost` init at startup (the README says "Felix framework,
~hundreds of ms"). That is a sane default and worth copying regardless of adoption.

Ours: `-PostScript <name> -PostArgs <a,b>` drives any postscript in `scripts/ghidra/` from the
command line. **We are not behind here** — we have a smaller, safer version of the same thing.
`mrphrazer/ghidra-headless-mcp` (180, GPL-2.0) is the same idea with a generated CLI
(`--script_args` repeatable, `--values:json`, `--kwargs:json`, and a `--function_start:int`
escape for decimal addresses) — worth reading purely for the CLI ergonomics.

### 3.2 What an IDA-capable agent gets, and whether it is portable

`mrexodia/ida-pro-mcp` requires **IDA Pro 8.3+ (9 recommended), explicitly "IDA Free is not
supported"**, plus `idalib` activated globally via `uv run ".../idalib/python/py-activate-idalib.py"`.
`blacktop/ida-mcp-rs` requires "IDA Pro 9.4 with a valid license". **We refuse all of these** —
no commercial seat on this box. Note the README's own header now recommends
`HexRaysSA/ida-mcp` (424, MIT) instead, so mrexodia is in maintenance/deprecation posture for
its GUI plugin ("no longer recommended and will eventually be deprecated").

The *portable* parts, none of which need IDA to adopt as a design:

1. **Headless session with no binary at start.** `uv run idalib-mcp --host 127.0.0.1 --port 8745`
   with no path, then `idb_open(...)` later. A warm daemon whose lifetime is decoupled from any
   one binary. Directly the answer to our "one HTTP server = one program" constraint (D11).
2. **MCP Resources as a separate read-only surface** from tools: *Core IDB State*, *UI State*,
   *Type Information*, *Lookups*. We have no resource concept at all — everything we expose is a
   tool call, so orientation costs a tool round-trip.
3. **Extension gating by query param.** `?ext=dbg` hides debugger tools by default. Our router's
   19-backend model is a heavier version of the same idea.
4. **The anti-hallucination prompt rule.** *"NEVER convert number bases yourself. Use the
   `int_convert` MCP tool if needed!"* The design principle: **remove the operation from the
   model's head and give it a tool.** We have no number-conversion route in
   `HeadlessMcpHttp.java` (bethington has `convert_number`). For hex/decimal/octal/base-N work
   in a RE loop this is a real hallucination source and we are undefended.
5. **Pre-LLM hygiene advice** (README "Tips"): resolve open-source library code with FLIRT/Lumina
   and remove string encryption, import hashing, CFF, and anti-decompilation tricks **before**
   letting the LLM work. Portable as a lab invariant, not a tool.

Not portable: anything built on IDA internals — Hex-Rays microcode, FLIRT/Lumina signature
matching, IDA's type/flowgraph model, `resolve_thunk`'s IDA semantics. bethington's
`resolve_thunk` equivalent in our world is Ghidra's own thunk analysis, which exists.

`MeroZemory/ida-multi-mcp` (442) and `Claude-Reverser/IDA-instances-MCP` (457) are the
multi-instance lesson: *"Each plugin-equipped IDA Pro database auto-registers when opened"* —
one MCP endpoint, N instances, no per-binary client config. That is a real design; the
implementation is IDA-bound. `P4nda0s/IDA-NO-MCP` (2,036) is the **opposite** and equally
instructive thesis: *"Text, Source Code, Shell are LLM-native languages"* — do **not** expose
MCP tools, export decompiled C plus `function_index.txt` to disk, and let the agent read files,
with a Rust binary whose `--skip-analysis` dodges IDA's analysis hang on 100 MB+ inputs.

**On that axis we are already on the right side of the argument**: `ExportDecompile.java` writes
398 `.c` files with an index. Our weakness is that we *also* built a 1083-line MCP-shaped HTTP
surface, and did not finish either.

---

## 4. Question 2 — Adopt / learn / refuse, with licence and cost

**Machine reality first** (measured, not assumed):

| fact | value | how |
|---|---|---|
| `E:` free | **15 GB** (21 G total, 5.7 G used) | `df -h /e` |
| `D:` free | **288 GB** (641 G total) | `df -h /d` |
| Ghidra 12.1.3 install size | **874 MB** | `du -sh` |
| second Ghidra already present | `ghidra_12.1.2_PUBLIC` | `ls -d Static-Reversing/Ghidra/*/` |
| RAM | **31.4 GB** | `Win32_ComputerSystem.TotalPhysicalMemory` |
| Java | Temurin **21.0.12.1** LTS | `java -version` |
| Python / uv | **3.14.7** / **0.12.6** | `python --version`, `uv --version` |
| Ghidra jars needed for D1+D2, present? | `Emulation.jar`, `BSim.jar`, `FunctionID.jar`, `VersionTracking.jar`, `Decompiler.jar`, `PDB.jar` — **all present** under `Ghidra/…` | `find` |
| user Ghidra profile | `%USERPROFILE%\AppData\Roaming\ghidra\ghidra_12.1.3_PUBLIC` exists | `ls` |
| deploy target | `<install>/Extensions/Ghidra` exists | `ls -d` |

**The E: constraint is not binding.** The station lives on `D:` with 288 GB free. `E:`'s 15 GB
only becomes relevant if someone proposes standing up a Postgres + BSim + LLM stack there, and
no item in the plan below does. Stated plainly so the plan is not distorted by it.

**The real cost is RAM, not disk**, and it is one number: a **resident Ghidra JVM**.
bethington recommends `JAVA_OPTS=-Xmx4g -XX:+UseG1GC` for its headless server. So
"adopt a warm daemon" ≈ **1.5–4 GB RSS held for the life of the session**, against 31.4 GB total.
That is affordable, but it competes with the mobile and managed labs for the same box.
`llnl/OGhidra` is the only proposal that would actually break the budget: its README pulls
`gemma3:27b` (**20 GB RAM**) or `gpt-oss:120b` (**80 GB RAM**).

| repo | verdict | licence | cost on this box | why |
|---|---|---|---|---|
| **Ghidra's own `AutoVersionTrackingScript` + BSim/FID scripts** | **ADOPT (zero install)** | Apache-2.0 (already installed) | 0 bytes, +1 headless run | D1. Shipped, headless-documented, opens siblings via the project file system |
| **Ghidra's own `Emulation.jar` + `EmulatorHelper`** | **ADOPT (reimplement)** | Apache-2.0 | 0 bytes | D2. Port `EmulationService.java`'s 502 lines; jar already on disk |
| `cyberkaida/reverse-engineering-assistant` (ReVa) | **ADOPT (best single package)** | **Apache-2.0**, LICENSE verified | `uv tool install`; needs `GHIDRA_INSTALL_DIR`; headless projects ephemeral in `./.reva/projects/`; MCP on `:8080` | Only 12.1.3-targeted, Apache-2.0, installable without a build, and uniquely has D4 (C-header→struct), D5 (vtable), D6 (13-tool diff). One verification command before believing it |
| `bethington/ghidra-mcp` | **LEARN, do not install** | **Apache-2.0** + `NOTICE` present — porting is legal with attribution | clone 14 MB, `.m2` ≈ 37 MB of jars, build target | Its unique value to us is D2's implementation, D9, D10, and the 253-endpoint surface as a *reference*. Installing a second Ghidra HTTP server to get there is disproportionate. Note the fork lineage: it "was originally derived from `LaurieWired/GhidraMCP` in August 2025" |
| `LaurieWired/GhidraMCP` | **REFUSE (superseded)** | Apache-2.0 | — | README is 119 lines: decompile, list, rename. Stale 15 months. bethington is its fork and supersedes it. Nothing to learn that ours does not already do |
| `cellebrite-labs/ghidra-rpc` | **REFUSE install, LEARN two things** | **NONE — re-verified: no `LICENSE*` file in a fresh clone; `pyproject.toml` v0.2.0 has no `license` field; GitHub API `license: null`** | `uv tool install`; writes a PyGhidra extension into `$GHIDRA_INSTALL_DIR` | Our prior refusal stands and the licence situation has not changed. **But our note over-credits it**: `_run_bsim_correlator` (`ghidra_rpc/server/tools/version_tracking.py:323-354`) calls `BSimProgramCorrelatorFactory` with default options and **no function database**, wrapped in `try/except ImportError` → `"BSim correlator not available (VersionTrackingBSim not loaded)"`. Its BSim is opportunistic, not a feature. **Learn instead:** (a) the resident-daemon + session-JSON persistence model (`docs/internals.md`), including a genuinely hard-won Windows detail — `CREATE_BREAKAWAY_FROM_JOB` is required or the detached daemon dies when the launching SSH job closes; (b) the **39 KB `SKILL.md` as the actual interface**, with a 22 KB `AGENTS.md` — the largest skill-authored RE corpus I read |
| `mrexodia/ida-pro-mcp` | **REFUSE install, LEARN §3.2 items 1-5** | MIT | n/a | Needs IDA Pro 8.3+ commercial, "IDA Free is not supported", `idalib` global activation. And the author now points users at `HexRaysSA/ida-mcp` |
| `HexRaysSA/ida-mcp` | **REFUSE** | MIT | n/a | Same IDA requirement; official does not change the seat we do not have |
| `blacktop/ida-mcp-rs` | **REFUSE** | MIT | n/a | "IDA Pro 9.4 with a valid license" |
| `MeroZemory/ida-multi-mcp`, `Claude-Reverser/IDA-instances-MCP` | **REFUSE install, LEARN instance-registry design** | NONE / MIT | n/a | IDA-bound |
| `P4nda0s/IDA-NO-MCP` | **REFUSE install, LEARN the thesis** | **NONE** | n/a | 2,036 stars and the most useful idea in the set: MCP-per-call is the wrong interface for huge binaries; export-to-disk is right, and dual-track (in-process plugin for small interactive files, out-of-process CLI with `--skip-analysis` for batch) is the answer to "both cannot be one thing" |
| `llnl/OGhidra` | **REFUSE** | BSD-3-Clause **with a commercial alternative** (LLNS) | `ollama pull gemma3:27b` = **20 GB RAM**; `gpt-oss:120b` = **80 GB RAM** | Exceeds the box. Also targets **Ghidra 12.0.3**, tested 11.0.3/11.3.2/12.0.2/12.0.3 — **not 12.1.3**. Its one portable idea (plan → execute → review agentic loop) is what the Owner already wants to build |
| `LING71671/open-reverselab` | **REFUSE vendor, LEARN two tool names** | **GPL-3.0** | repo 7.3 MB | 180+ articles, 100+ tools, 5 boards — genuine orchestration work, and GPL-3.0 forbids vendoring into our tree. Do not copy its code. Worth naming only: `sample_full_workup` (one-call mission) and `mcp_smoke_check` + `ai_toolcheck` (the acceptance harness shape our `loop.mjs` should take) |
| `xiaoyeuzixi/revlab` | **REFUSE install, LEARN the stage model** | **NOASSERTION** | n/a | 70 stars. Value is one sentence: *"AI 节点放在证据节点之后"* — the AI node goes **after** the evidence node. Staged `identify → unpack → disassemble → decompile → dynamic`, SQLite-backed sample records, every stage records the reason it was skipped. That provenance discipline is what our labs half-have |
| `cycraft-corp/BinaryAnalysisMCPs` | **REFUSE** | MIT | — | 116 KB, stale 13 months, thin README, no Ghidra |
| `Ap3x/BinaryAnalysis-MCP` | **REFUSE** | GPL-3.0 | — | 25 stars; LIEF header analysis we already exceed |
| `bethington/re-universe` | **REFUSE** | MIT | Docker + PostgreSQL | The only real BSim-with-a-database option here, and Docker is stopped and must stay stopped |
| `clearbluejar/pyghidra-mcp` (427), `mrphrazer/ghidra-headless-mcp` (180), `13bm/GhidraMCP` (143) | **LEARN selectively, no install** | Apache-2.0 / GPL-2.0 / Apache-2.0 | — | `13bm` is 10 read-only tools; `mrphrazer`'s generated-CLI ergonomics are the only thing worth copying |

---

## 5. Question 3 — Headless Ghidra: what we already have, stated plainly

Covered in §1. The short version, without flattery:

- **Proven:** import → analyze → decompile-everything → write `.c` + `summary.json`, one command,
  one process, exit 0, JSON on stdout. `labnative.dll` → 398 functions.
- **Code-complete but unexercised:** 33 routes including `/pcode`, `/cfg`, `/create_struct`,
  `/resolve_type`, and the three formerly-lying write routes.
- **Never executed:** the entire cross-binary path (`FunctionHashes.java`, `DiffPrograms.java`).
- **Absent:** no self-judging runner (`headless-lab/tools/loop.mjs` does not exist), no P-code
  emulation, no dataflow, no BSim/VT, no C-header type import, no vtable analysis, no
  multi-program session, no warm daemon, no MCP resource surface, no number-base tool.
- **Wrapper constraint that blocks D1:** `ghidra-headless.ps1` hard-codes one temp project, one
  sample, and `-deleteProject`.

---

## 6. Question 4 — The upgrade plan, ranked

North Star honoured throughout: **every item is provable by one command or one file read.**

### Step 1 — Prove the half we already wrote. Zero install, zero new code. **Do this first.**

- `powershell -File headless-lab\tools\build.ps1`
- then drive the existing wrapper and add `headless-lab/tools/loop.mjs`
- **Acceptance:** one command prints a PASS table covering: `/pcode` on `checksum` contains
  `INT_XOR` and `INT_MULT`; `/cfg` on `classify` has ≥3 blocks with the entry block having 2
  successors; `create_struct` + `apply_to` makes `/data` show a typed item;
  `set_function_prototype` changes the reported signature; `DiffPrograms` reports **exactly one**
  changed function, `checksum`. **Negative controls:** non-existent function refused, bad type
  name refused, `core_v1.dll` vs itself reports zero changes.
- **Why first:** until this passes, every later step is built on unverified ground, and
  `headless-lab/README.md` §4 currently says so in print.

### Step 2 — Replace MD5-of-bytes with a recompile-stable hash. **Needs a new sample first.**

**Prerequisite, and it is a real one:** the existing `core_v1`/`core_v2` pair cannot demonstrate
this, because `classify` is byte-identical between them by construction (§3.1 D1). Add a third
variant that *does* move unchanged code — e.g. build `core_v3.dll` with `/O2` instead of `/O1`, or
insert one dummy exported function before `classify` so the linker relayouts it. The ground truth
is unchanged by construction: `classify` is logically identical, `checksum` is not.

Then reimplement the normalization from `DocumentationHashService.java:160-204` (small scalars
kept as `IMM:<value>`, large → `IMM_LARGE`, address-space operands → `ADDR`, then SHA-256) in
our `FunctionHashes.java`.
- **Acceptance:** against that new variant, `DiffPrograms` reports `classify` UNCHANGED and
  `checksum` CHANGED **under the normalized hash, and reports `classify` CHANGED under the
  current MD5** — run both and print both. The MD5 column is the control that makes this a
  capability claim rather than a diff-format change. If the new variant does not in fact move
  `classify`'s bytes, the sample is wrong, not the hash.

### Step 3 — Real Version Tracking via Ghidra's shipped script. **The big one. Zero install.**

- Extend `ghidra-headless.ps1` with `-ProjectRoot` / `-KeepProject` (today it hard-codes a temp
  project at lines 31-32 and `-deleteProject`s at line 41).
- Two-step run: `-import core_v1.dll core_v2.dll` into one project, then
  `-process core_v2.dll -postScript AutoVersionTrackingScript.java / sess /core_v1.dll`.
  `support/analyzeHeadlessREADME.md:144-149` confirms `-import` repeats and takes multiple files.
- **Acceptance:** one headless run produces a VT session whose matches include `classify` as
  matched/unchanged and `checksum` as changed, printed as text.
- **This retires `DiffPrograms.java` and the two-manifest design** justified by the incorrect
  `ProgramManager` blocker in `notes/2026-09-30-managed-native-depth.md:82-84`.
- *Unverified by execution* — the headless invocation is documented by Ghidra's own script
  header; whether our wrapper needs the `-ProjectRoot` change first is exactly what the run
  answers.

### Step 4 — P-code emulation. Port `EmulatorHelper`, don't install a plugin.**

Port the ~150-line core of `EmulationService.java` into `HeadlessMcpHttp.java` as `/emulate` and
`/emulate_hash_batch` (scratch base `0x7FFE0000`, 64 KB, `MAX_CANDIDATES` 10,000,
`MAX_STEPS` 100,000). `Emulation.jar` is already in our install. Apache-2.0 + NOTICE attribution.
- **Acceptance:** one request emulating a hash function we can compute independently returns the
  expected value; a request with a deliberately wrong candidate set returns no match. Both must
  come from `headless-lab` (add `m04`-style computed-hash sample, not an authored constant).

### Step 5 — Adopt ReVa for the three things it uniquely has (D4, D5, D6).

- **Acceptance, gate 0:** `uv tool install reverse-engineering-assistant` succeeds, then a
  headless launch with `GHIDRA_INSTALL_DIR` pointing at our 12.1.3 answers on `:8080`. **This is
  the one command that decides adopt-vs-doom** — if it needs a build or a Ghidra-tree write, stop
  and keep the design lessons only.
- **Acceptance, gate 1:** `parse-c-header` on a real struct header yields a Ghidra `Structure`
  matching the C layout field-for-field.
- **Acceptance, gate 2:** `analyze-vtable` on our own C++ crackme returns slot indices matching
  the class's virtual method order.
- Note: ReVa is a **second** Ghidra server. Per `AGENTS.md` §3 that is a decision for the Owner,
  not for a lab — and the router already has a `ghidra` backend.

### Step 6 — Learn the architecture, and consider replacing our bridge shape.

ReVa registers tools **in-process** on `McpSyncServer` (official MCP Java SDK) — no Python
bridge, no HTTP hop, no second port, no second process. Ours is 1083 lines of Java HTTP plus a
Python router backend. Adopt this **shape**: fewer moving parts to prove, and MCP-native instead
of REST-that-happens-to-be-proxied.
- **Acceptance:** a file read of one ReVa `*ToolProvider.java` and one of our
  `HeadlessMcpHttp.java` route blocks, and a written decision in `notes/` — no code change until
  Step 1-3 pass.

### Step 7 — Borrow bethington's three design ideas (no install).

- **Convention tiers** (auto-fix / warn / reject) — naming rules in the tool layer, not the prompt.
- **`analyze_function_completeness`** as a machine-checkable definition of "documented".
- **Lazy tool groups** + a documented minimum viable read-only set — directly applicable to our
  19-backend router.
- **Acceptance:** `notes/` gains one page naming the three, each mapped to the specific route or
  router file it would change. No code.

### Step 8 — Borrow the IDA-side lessons without IDA (§3.2).

- Add a `convert_number`-equivalent route — the *"NEVER convert number bases yourself"* rule is the
  cheapest hallucination guard available and we are currently undefended.
- Model orientation state as **MCP Resources**, not tool calls.
- Adopt P4nda0s's dual-track reasoning explicitly: `ExportDecompile` (file export) is the answer
  for big binaries, the HTTP surface is the answer for small ones. Stop trying to make one shape
  serve both.
- **Acceptance:** one file read of the ReVa resource declaration + one `notes/` paragraph.

### Step 9 — Orchestration layer. Ours to build; nothing to adopt.

`OGhidra`'s plan → execute → review loop and `open-reverselab`'s `sample_full_workup` both
describe the missing layer, and both are unusable here (RAM; GPL). The evidence discipline from
`revlab` — *AI node after evidence node* — should be the invariant.
- **Acceptance:** a single command takes a sample path and drives the whole seven-phase loop with
  no human in the path, failing loudly rather than emitting a plausible empty artifact.

---

## 7. What I did not read, and what that costs

Stated so no claim is over-read:

- `hex-rays` blog post and `HexRaysSA/ida-mcp` source: metadata + README pointer only.
- `Ap3x/BinaryAnalysis-MCP`, `cycraft-corp` source: metadata + README only.
- `bethington/re-universe` source: metadata only — it is a refuse, so this is cheap.
- `13bm/GhidraMCP`, `clearbluejar/pyghidra-mcp`, `mrphrazer/ghidra-headless-mcp`: README
  fragments only. `mrphrazer`'s CLI table is quoted from its README, not its code.
- **`gh search repos` was rate-limited to a handful of queries** and returned nothing useful for
  `"reverse engineering orchestration agent"`, `"mcp decompiler"`, `"bsim function matching"`,
  and `"apk reverse mcp"`. The sweep is broad but not exhaustive; a mobile/Frida-focused
  subagent would find more on that side (there are ≥8 `frida-mcp` forks, largest 434 stars).
- **No repo was installed, built, or executed.** Every claim about our own box is a command I ran
  on this box; every claim about a repo is a file I read. Where the two meet — Step 3 and Step 5
  gate 0 — I have marked it `[UNVERIFIED]` because it needs a run.

## 8. Refusals, one line each

- **IDA anything** (`mrexodia`, `HexRaysSA`, `blacktop/ida-mcp-rs`, `MeroZemory`,
  `Claude-Reverser`): no commercial seat. Design only.
- **`cellebrite-labs/ghidra-rpc`**: no LICENSE file, re-verified on a fresh clone today. All
  rights reserved by default. Its BSim is opportunistic anyway.
- **`LING71671/open-reverselab`**: GPL-3.0 — do not vendor, do not copy code.
- **`Ap3x/BinaryAnalysis-MCP`**: GPL-3.0 and redundant.
- **`llnl/OGhidra`**: 20–80 GB of local LLM on a 31.4 GB box, and it targets Ghidra 12.0.3.
- **`bethington/re-universe`**: needs Docker + PostgreSQL. Docker is stopped and stays stopped.
- **`xiaoyeuzixi/revlab`, `P4nda0s/IDA-NO-MCP`, `MeroZemory/ida-multi-mcp`**: no enforceable
  licence (`NOASSERTION` / `null`).
