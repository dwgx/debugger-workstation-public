# headless-lab — native RE, headless depth

**Status: assessment complete, implementation in progress, not yet proven.**
Read this section before trusting anything below it. What is verified and what is
not is stated explicitly at the bottom.

The question this lab answers is narrow and cheap: **can an agent get more out of
headless Ghidra on this box without installing a third-party MCP server?** The
survey that started this work pointed at
[`cellebrite-labs/ghidra-rpc`](https://github.com/cellebrite-labs/ghidra-rpc) as
the way to do it. That was checked, and the check is recorded below.

---

## 1. The ghidra-rpc assessment (verified 2026-09-30)

| question | answer | how it was checked |
|---|---|---|
| does it exist? | yes, `cellebrite-labs/ghidra-rpc`, 355 stars, last pushed 2026-09-17 | `api.github.com/repos/cellebrite-labs/ghidra-rpc` |
| is it on npm, as the survey implied? | **no** — `npm view ghidra-rpc` → `E404`. It is a Python package, not a Node one | `npm view ghidra-rpc`, `npm view @cellebrite/ghidra-rpc` |
| what is it? | a CLI + daemon that runs Ghidra in-process via `pyghidra` and speaks JSON over a socket | README, `pyproject.toml` |
| licence | README says MIT, **but there is no LICENSE file in the repository** and the GitHub API reports `license: null` | `ls LICENSE*` on a fresh clone, API field |
| size | repo 5.5 MB with `.git`; dependency closure resolves to 4 wheels (`pyghidra` 3.1.0, `jpype1` 1.5.2, `click` 8.5.0, `packaging` 26.3) | `du -sh` on a clone, `uv pip install --dry-run` |
| would it work here? | **prerequisites are all present**: `uv` 0.12.6, Python 3.14.7, Ghidra 12.1.3 with `Ghidra/Features/PyGhidra`, JDK 21. Wheels resolve for cp314, so the install is not the blocker | `uv --version`, `ls .../Ghidra/Features/PyGhidra`, dry-run resolution |
| does it run headless? | yes, by design: `ghidra-rpc start --project <p.gpr> --headless`; the README documents Windows paths (`%LOCALAPPDATA%\ghidra-rpc\...`) | README (unverified by execution — see limits) |

### Decision: not installed

Three reasons, in order of weight.

1. **No LICENSE file.** The README claims MIT; the repository grants nothing
   enforceable. The station's `AGENTS.md` stop line is "official sources only",
   and `manifests/mcp-backends.json` already flags unlicensed upstream clones as a
   standing hazard ("两个 dnSpy 仓库上游未声明 license(默认保留全部权利)"). Adding a
   second one, from a vendor rather than the Ghidra/NSA upstream, is a decision
   for the owner, not for a lab.
2. **It writes into the Ghidra tree.** `pyghidra` bootstraps a Ghidra extension
   into `$GHIDRA_INSTALL_DIR`. That modifies an installed tool, which is a
   brief-then-follow operation, not a silent one.
3. **The station already has most of it.** `scripts/ghidra/HeadlessMcpHttp.java`
   is a 571-line self-developed headless server already wired to the router's
   `ghidra` backend, already serving decompile, disassemble, xrefs, strings,
   exports, rename, and comments. The honest gap is small and is enumerated
   below — and closing it in-tree costs no install, no licence, and no new
   process model.

The cost of the decision, stated plainly: if `ghidra-rpc` does work headlessly on
this box, this station is foregoing its BSim-based function matching, its
warm-daemon state, and a maintained CLI. None of those are needed for the loop
below, and the first two are not cheap to get from anywhere else. **This is a
reversible decision** — the repo is public, `uv tool install` is one command, and
nothing has been installed.

## 2. The real gap, measured

`scripts/ghidra/HeadlessMcpHttp.java`, before this work, answered three routes
with a lie:

```java
server.createContext("/renameVariable",        ex -> send(ex, "headless: renameVariable not implemented; use batch export"));
server.createContext("/set_function_prototype",ex -> send(ex, "headless: set_function_prototype not implemented"));
server.createContext("/set_local_variable_type",ex -> send(ex, "headless: set_local_variable_type not implemented"));
```

and had no P-code, no CFG, and no way to author a type. That is the gap worth
closing, and it is the whole of what this lab is about.

Implemented in `scripts/ghidra/HeadlessMcpHttp.java` (in progress, see §4):

| route | what it does | state |
|---|---|---|
| `/pcode?address=` \| `?name=` | P-code ops of one function, with the address each op came from | written, compile unverified |
| `/cfg?address=` \| `?name=` | basic blocks with their edges | written, compile unverified |
| `/create_struct` | `name`, `fields` (`off:len:type[:name];…`), optional `apply_to` address — authors a `StructureDataType` and can apply it with `createData` | written, compile unverified |
| `/list_structs` | the program's types | written, compile unverified |
| `/resolve_type?type=` | turns `int`, `uint32`, `ptr`, `char*`, `byte[16]`, or a created type name into a real `DataType` | written, compile unverified |
| `/renameVariable` | was a stub; now implemented | written, compile unverified |
| `/set_function_prototype` | was a stub; now implemented (`return_type`, `params`) | written, compile unverified |
| `/set_local_variable_type` | was a stub; now implemented | written, compile unverified |

Plus two new postscripts for the one capability a single-program HTTP server
cannot serve — cross-binary diff:

- `scripts/ghidra/FunctionHashes.java` — one line per function: name, size,
  MD5-of-body-bytes. A function inventory you can diff without shipping a project.
- `scripts/ghidra/DiffPrograms.java` — reads two manifests and writes what
  changed. Matching is by name first (exported and named functions survive a
  recompile), then by hash; a name match with a different hash is a `CHANGED`.

`scripts/ghidra-headless.ps1` gained `-PostScript <name> -PostArgs <a,b>` so any
postscript in `scripts/ghidra/` can be driven through the station's existing
headless entry point. Default behaviour is unchanged.

## 3. The sample: two builds of one source

`native/core.c` is compiled twice, differing in a single compile-time constant:

```powershell
powershell -File headless-lab\tools\build.ps1
#   cl /nologo /LD /O1 /W3                  core.c /Fe:core_v1.dll
#   cl /nologo /LD /O1 /W3 /DLAB_MASK=0x3C  core.c /Fe:core_v2.dll
```

- `classify(a, b)` — four basic blocks including a loop with an early exit, so
  the CFG has a real edge that is not fallthrough. **Byte-identical** in both
  builds.
- `checksum(buf, len)` — an XOR and an IMUL, dense in P-code. **Different** in
  both builds.

That difference is the ground truth a cross-binary diff has to reproduce: report
`checksum` as changed and `classify` as unchanged, from a source that never saw
the build flags.

## 4. What is proven and what is not

**Proven on this machine, 2026-09-30:**

- `headless-lab/tools/build.ps1` → both variants build, 104,448 bytes each, exit 0.
- `scripts/ghidra-headless.ps1` still decompiles exactly as before after the
  `-PostScript` addition: `{"ok":true,"functions":398,"decompiled":398}`,
  398 `.c` files written. **The shared wrapper is not regressed.**
- The Ghidra 12 API mismatches in the new Java were found and fixed by compiling
  it — `FlowType` lives in `ghidra.program.model.symbol`, `ParameterImpl` in
  `ghidra.program.model.listing`, `FunctionUpdateType` is
  `Function.FunctionUpdateType`, `getAllDataTypes()` returns an `Iterator`, and
  `DecompileResults` has no `getPcode()` (it is
  `getHighFunction().getPcodeOps()`).

**Not proven — do not claim these:**

- **`/pcode`, `/cfg`, `/create_struct` and the three formerly-stubbed routes have
  never returned a value.** The first compile round reported five errors; those are
  fixed; the second compile round and an actual request have not run.
- **`FunctionHashes.java` and `DiffPrograms.java` have never been executed.** A
  dry run of the wrapper's `-PostScript` path was in flight when it was found to
  be broken by a PowerShell case-insensitivity bug (`$ScriptName` and
  `$scriptName` are the same variable), which is fixed; the postscripts are
  untested.
- **`headless-lab/tools/loop.mjs` does not exist yet.** The self-judging runner
  for this lab is the next piece of work, and it should assert: P-code contains
  `INT_XOR`/`INT_MULT` for `checksum`; `classify`'s CFG has ≥3 blocks and the
  entry block has 2 successors; `create_struct` + `apply_to` makes `/data` show a
  typed item; `set_function_prototype` changes the reported signature; and the diff
  reports exactly one changed function, `checksum`. **Negative controls:** a
  request for a non-existent function must be refused, a bad type name must be
  refused, and diffing `core_v1.dll` against itself must report zero changes.

Until that runner prints its PASS table, this lab is an assessment plus
half-finished code, and `managed-lab` is the part of this job that is actually
proven.

## 5. Placement in the analysis loop

Same seven phases, native column, different instruments. What the headless surface
buys, phase by phase:

| phase | instrument | what it replaces |
|---|---|---|
| ACQUIRE | `scripts/ghidra-headless.ps1` | the Ghidra GUI, entirely |
| PRESERVE | one-shot export into a gitignored `out/`; the project is `-deleteProject`ed unless you ask for HTTP | opening a project and keeping it |
| **TRIAGE** | `/imports` `/exports` `/strings` `/classes` `/segments` `/methods`, `--list` | right-clicking through the GUI |
| **NARROW** | `/function_xrefs`, `/xrefs_to`, `/xrefs_from`, `/searchFunctions`, `/decompile`, **`/cfg`** | manual xref following; the CFG is what you cannot reconstruct from decompiled C# once it has printed an `if` |
| **INSTRUMENT** | `/renameFunction`, `/renameData`, `/set_decompiler_comment`, **`/renameVariable`**, **`/set_function_prototype`**, **`/set_local_variable_type`**, **`/create_struct`** | annotating in the GUI, which an agent cannot do |
| **VERIFY** | **`/pcode`** (read the translation, do not trust the pretty-printer), `FunctionHashes` + `DiffPrograms` (an independent second look at "did this change") | recompiling and re-running |
| DOCUMENT | the manifests and `diff.txt` are text, and belong in a notes file | a screenshot |

The invariant this column leans on hardest is invariant 2 — static before
dynamic, narrow the slice. Headless Ghidra is a static instrument, and the
capabilities that matter (`/cfg`, `/pcode`, struct authoring) are the ones that
narrow *before* anything is executed. A GUI-driven session tempts you to set a
breakpoint; these routes are built to answer the question without one.
