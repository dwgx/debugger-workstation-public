# 2026-09-30 — managed-RE lab (D4) built and proven; native headless (D3) assessed, half-implemented

## D4 — `managed-lab/`, PROVEN

Five self-authored C# samples, five solvers, one self-judging runner.

- `powershell -File managed-lab\tools\build.ps1` → 5/5 build, exit 0. The m05
  native half builds through a throwaway `.bat` that calls `vcvars64.bat`, because
  there is no gcc on this box and `cl.exe` is not on `PATH`.
- `node managed-lab\tools\loop.mjs` → **27 checks, 27 pass, exit 0**.

The five techniques, one per sample, each with a known answer computed
independently before the sample was written:

| id | technique | answer |
|---|---|---|
| m01 | string encryption: per-index keystream XOR + odd-index byte swap | `the quick brown fox jumps over the lazy dog` |
| m02 | control-flow flattening + opaque predicates + a decoy block | `dbb9c662`, order `0x1C→0x07→0x4A→0x35→0x11→0x2E→0x59→0x41` |
| m03 | base64 payload in an embedded resource, seed from the resource name length | `sha256 ae5ee44b…00f24`, 117 bytes, magic `M03P` |
| m04 | 16-byte header + length-prefixed records, FNV-1a/32, 4-byte aligned | the 5-record table, reproduced byte-for-byte |
| m05 | P/Invoke boundary; the key is in `labnative.dll` | `M05-BRIDGE-KEY` (14 bytes) |

Facts worth keeping:

- **ilspycmd 11.0.0.9375** (`Static-Reversing\ilspycmd\ilspycmd.exe`) is the
  headless ildasm. `-il` gives raw IL; `--list-resources` / `--resource` extract
  embedded resources with no re-implementation. `ildasm.exe` is **not** in .NET SDK
  10.0.400, so this is the ildasm equivalent here. See `managed-lab/IL-READING.md`.
- Every solver reads its constants out of the decompilation — no key, seed, length,
  offset multiplier or checksum prime is hard-coded. `tools/clrlib.mjs` has a
  `evalCsharp()` with a character allow-list that has no letters in it except the
  literal suffixes, so a decompiled expression cannot smuggle a call through.
- The runner's section 2 compares each static answer against **the sample's own
  output**, which is the loop's invariant 3 made mechanical. Section 4 re-runs
  every solver in the mode that breaks it and requires a non-zero exit: 8 controls,
  all failing as required. Without them "PASS" would only mean "the solver
  returned something".
- Solver exit protocol: `0` right, `4` ran and got the wrong answer, `1` could not
  run. m02's `--entry 43` control is the interesting one: a **complete, confident,
  wrong** answer, which is the failure mode invariant 3 exists to catch.
- Ghidra decompiles the m05 DLL to 398 functions in ~20 s through
  `scripts\ghidra-headless.ps1`, and the three facts the solver needs
  (`param_2 != 0xe`, `(&DAT_18000f300)[i] ^ 0xa7`, the `* '\x03'` multiplier) are
  all inline literals in that decompilation — which is why the solve needs no
  symbols.

## D3 — `headless-lab/`, ASSESSED, NOT PROVEN

**`cellebrite-labs/ghidra-rpc` was verified and deliberately not installed.**

- Exists; 355 stars; last pushed 2026-09-17; Python, not Node.
- **The survey's npm framing is wrong**: `npm view ghidra-rpc` → E404. It is a
  Python package installed with `uv tool install`.
- **No LICENSE file** in the repository; the README claims MIT and the GitHub API
  reports `license: null`. That alone is a reason not to add it without the owner.
- Prerequisites are all met here (`uv` 0.12.6, Python 3.14.7, Ghidra 12.1.3 with
  `Ghidra/Features/PyGhidra`, JDK 21); `uv pip install --dry-run` resolves four
  wheels. So the blocker is licence and tree-modification, not feasibility.
- It would write a PyGhidra extension into the Ghidra install directory.

Instead, the station's own self-developed headless surface was deepened.
`scripts/ghidra/HeadlessMcpHttp.java` used to answer `/renameVariable`,
`/set_function_prototype` and `/set_local_variable_type` with "not implemented" —
a route that lies is worse than no route. Those three are now implemented, and
`/pcode`, `/cfg`, `/create_struct`, `/list_structs` and `/resolve_type` were added.
`scripts/ghidra/FunctionHashes.java` + `DiffPrograms.java` add cross-binary diff
(the one thing a single-program HTTP server cannot serve).

**This half is NOT proven.** See `headless-lab/README.md` §4 for the exact list.
The second compile round and an actual request have not run; the two postscripts
have never executed; `headless-lab/tools/loop.mjs` does not exist yet.

Ghidra 12 API facts learned by compiling (each cost a round trip):

- `FlowType` is `ghidra.program.model.symbol.FlowType`, not `.lang`.
- `ParameterImpl` is `ghidra.program.model.listing.ParameterImpl`, not `.data`.
- There is no top-level `FunctionUpdateType`; it is `Function.FunctionUpdateType`.
- `DataTypeManager.getAllDataTypes()` returns an `Iterator`, not an `Iterable`.
- `DecompileResults` has no `getPcode()`. Use
  `getHighFunction().getPcodeOps()` (`HighFunction extends PcodeSyntaxTree`).
- `Variable.setDataType()` returns `void`, not `boolean`.
- **Ghidra 12 has no framework-level `ProgramManager`**, so a headless script
  cannot open a sibling program from the same project. Hence the two-manifest
  design for the diff rather than the in-process one `ghidra-rpc` uses.

## Changes to shared station files

- `scripts/ghidra-headless.ps1` gained `-PostScript <name>` and `-PostArgs <a,b>`.
  Default behaviour is unchanged and re-verified: `labnative.dll` → 398 functions,
  398 `.c` files, `{"ok":true}`, exit 0.
- **PowerShell variable names are case-insensitive.** Naming a parameter
  `$ScriptName` and a local `$scriptName` silently made the parameter truthy, which
  dropped `-deleteProject` and blanked the postscript argument. The parameters are
  now `-PostScript` / `-PostArgs`. This is the kind of bug that costs an hour if you
  do not know it is possible.
- `scripts/ghidra/HeadlessMcpHttp.java`, `DiffPrograms.java`, `FunctionHashes.java`
  — new/extended. First one is compile-unverified; see above.
- `.gitignore` — `/managed-lab/out/`, `/headless-lab/out/`, `managed-lab/**/obj/`.
  No binaries committed; the station's existing `*.exe` `*.dll` `obj/` rules
  already cover the rest.

## Placement in the analysis loop

Both are columns of the same seven phases, not loops of their own. The per-phase
tables are in `managed-lab/README.md` and `headless-lab/README.md` §5. The
load-bearing invariant for both is invariant 2 — static before dynamic, narrow the
slice — and m05 is the case that tests it hardest, because narrowing means changing
binaries and toolchains while the question stays the same.
