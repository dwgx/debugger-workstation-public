# Ecosystem survey — 2026-10-02: what to adopt, what to refuse

**Sources, read in full:** `w1-mcprev.md` (229 lines, MCP servers + security posture),
`w1-retoolchain.md` (232 lines, 40 tools cost-ranked), `w1-revskills.md` (336 lines, 33
repos), `w1-debugpairing.md` (1237 lines, 23 pairings — its composition half is in
`dynamic-pairings.md`). Every figure carries its `w1-*.md:line` or the command that
produced it.

> ## ⚠ 2026-10-04 — every `w1-*.md` citation below is dead. Read this first.
>
> The sources named below were **never written to disk**. They survive only as the subagents'
> final-answer summaries under `workers/`, and **159 of the 230 citations in this file point
> past the end of what survives**. `w1-mcprev.md` — the yardstick every §1 row is judged
> against, at `w1-mcprev.md~~:9-16~~` — **has no surviving copy at all**.
>
> **Full loss table and what it means for each figure: [`WORKER-REPORT-LOSS.md`](WORKER-REPORT-LOSS.md).**
> Reproduce with `python scripts/arsenal-doctrine-check.py`.
>
> Nothing above is struck, because the conclusions may still be right. But **a citation is not
> provenance until somebody can open it**, and these cannot be opened. Treat §2's cost figures
> as `[UNVERIFIED]`.

**The yardstick, and where it comes from.** `w1-mcprev.md~~:9-16~~` names the test and every row
in §1 is judged against it: the recorded audit of the server we already run
(`docs/research/ida-mcp-source-study.md`) found `--unsafe` reversed by **one unauthenticated
`POST /config`** while the author had the server running, with the resulting policy
**persisted into the sample's `.i64`**. So:

> **The yardstick: does the gate survive someone who is not us rewriting it?**

A tool server's own flags are not a boundary.

**Two disclosures that bound everything below.**

1. **No MCP server in §1 was installed or started.** All posture claims are source- and
   README-derived as cited, with dispatch-time enforcement *read but not exercised*
   (`w1-mcprev.md~~:213-215~~`). Everything in that table marked "enforced at dispatch" is a
   **source claim, `[UNVERIFIED]` as a measurement**.
2. **No package in §2 was installed.** Disk figures are **download bytes**, verified via
   `gh api repos/<r>/releases` asset `size` and HTTP `HEAD` `Content-Length`
   (`w1-retoolchain.md~~:30-33~~`). Installed footprint is `UNVERIFIABLE`
   (`w1-retoolchain.md~~:216~~`).

---

## 1. MCP servers: 25 rows, and the one test only two pass

### 1.1 The posture table

Full source: `w1-mcprev.md~~:28-54~~`. Stars/licence/language from `gh api repos/OWNER/REPO` on
2026-10-02. Condensed to the columns that changed a verdict; the transport/auth/blast-radius
columns are in the source row-for-row.

| # | repo | ★ | licence | tools | auth model | verdict |
|---|---|---|---|---|---|---|
| 1 | `mrexodia/ida-pro-mcp` | 12,432 | MIT | **66 measured live** (88 declared, 25 `@unsafe`) | **none on HTTP** — `_check_api_request` accepts any request without `Origin` | SANDBOX ONLY — already adopted, never on the host |
| 2 | `Claude-Reverser/IDA-instances-MCP` | 457 | MIT | fork of #1 | **real bearer token, every request.** `GET /health` exempt; `GET /key` issues it once per start | ADOPT as the reference hardening of #1 — **bind loopback** (default bind is `0.0.0.0:9999`) |
| 3 | `MeroZemory/ida-multi-mcp` | 444 | **NONE — no LICENSE file** | 76 advertised | none; origin/host checks return 403 | **REJECT** |
| 4 | `blacktop/ida-mcp-rs` | 848 | MIT | **82 registered** (`src/tool_registry.rs`) | **none** on HTTP | ADOPT — best server-side gate in the field |
| 5 | `LaurieWired/GhidraMCP` | 10,239 | Apache-2.0 | ~25 | **none** | SANDBOX ONLY |
| 6 | `bethington/ghidra-mcp` | 4,082 | Apache-2.0 | 253 advertised | **optional `GHIDRA_MCP_AUTH_TOKEN`**, timing-safe compare; **refuses to start on a non-loopback bind without a token** | ADOPT |
| 7 | `13bm/GhidraMCP` | 143 | Apache-2.0 | 70 advertised | **optional** `GHIDRA_API_KEY`, **empty by default** | SANDBOX ONLY unless a key is generated |
| 8 | `mrphrazer/ghidra-headless-mcp` | 183 | GPL-2.0 | 212 advertised | **none, stated plainly**: "unauthenticated by default… anyone with localhost access can run arbitrary code" | SANDBOX ONLY — the containment **is** the design |
| 9 | `mrphrazer/binary-ninja-headless-mcp` | 249 | GPL-2.0 | 181 advertised | none — README says so directly | SANDBOX ONLY (and we have no licence) |
| 10 | `fosdickio/binary_ninja_mcp` | 445 | GPL-3.0 | 25 | none documented | REJECT |
| 11 | `axelmierczuk/tenrec` | 177 | MIT | 9 plugins | stdio — no port, no auth surface | **ADOPT — best first IDA server to wire** |
| 12 | `radareorg/radare2-mcp` | 312 | MIT | **52 `ToolSpec` counted in `src/tools.c`** | **optional `-a <token>`**; bare port binds `127.0.0.1` only | ADOPT — the only per-dispatch mode gate in the field |
| 13 | `clearbluejar/pyghidra-mcp` | 428 | Apache-2.0 | 22 | none; `--host 127.0.0.1` default | ADOPT — narrowest Ghidra surface |
| 14 | `dnakov/frida-mcp` | 434 | MIT | process/device mgmt, JS REPL | stdio | SANDBOX ONLY — already adopted, container-only |
| 15 | `FuzzySecurity/kahlo-mcp` | 134 | **NOASSERTION** | session lifecycle, jobs | **stdio only** | SANDBOX ONLY; also REJECT on licence |
| 16 | `0xeb/lldb-agent` | 20 | **NONE — no LICENSE file** | **1**: `dbg_exec` | **none — README says so** | REJECT |
| 17 | `stass/lldb-mcp` | 113 | BSD-2-Clause | ~20 incl. arbitrary `lldb_command` | stdio | SANDBOX ONLY |
| 18 | `ant4g0nist/lisa.py` | 756 | Apache-2.0 | 18 incl. arbitrary LLDB | none documented, HTTP `localhost:13338` | REJECT — and stale since 2025-03 |
| 19 | `Ipiano/gdb-mcp` | 48 | MIT | 22 incl. arbitrary `gdb_execute_command` | stdio | SANDBOX ONLY — **plus an undocumented Python eval path** |
| 20 | `yywz1999/gdb-mcp-server` | 85 | MIT | arbitrary `gdb_execute_command` | stdio presumed | REJECT — and no GDB on this box |
| 21 | `karimodm/angrMCP` | 9 | MIT | ~15 (symbolic exec, taint, backslice) | stdio presumed | REJECT for now — credible design, unproven |
| 22 | `sandbornm/angr_mcp` | 5 | Apache-2.0 | 14 | none; `ANGR_MCP_HOST` overridable | SANDBOX ONLY — low reach, unproven |
| 23 | `jmpnop/imhexMCP` | 23 | **NOASSERTION** | 40+ | none documented, TCP `localhost:31337` | SANDBOX ONLY — already vendored |
| 24 | `P4nda0s/IDA-NO-MCP` | **2,039** | **NONE — no LICENSE file** | fork of #1 | none | REJECT |
| 25 | `smadi0x86/Hallucina` | 8 | GPL-3.0 | **not an MCP server** — an LLVM 17 obfuscator | n/a | **ADOPT as a negative control** |

Row 25 is included deliberately (`w1-mcprev.md~~:54~~`): its stated purpose is *"to confuse and
hallucinate LLM clients used with custom MCP servers for disassemblers such as Ghidra and
IDA PRO."* It is the only public weapon aimed at our exact threat model, and it is how an
adversary manufactures the "malicious sample's strings."

### 1.2 The finding: only two servers survive their own yardstick

`w1-mcprev.md~~:71-79~~`:

> **`r2mcp` checks `tool_available()` on every dispatch** (`tools.c:284`, called at `:1387`),
> so the set cannot be widened from inside. **`ida-mcp-rs`** enforces `ToolFilter::is_enabled`
> on `tools/list` *and* `tools/call`, refuses to start on an empty final set
> (`tool_filter.rs:110`), and — checked explicitly — has **no `POST /config` equivalent
> anywhere in the tree**.

Everything else that offers a "safe mode" offers it as **startup-time mutation of a dict**:
`mrexodia` (`POST /config`, `http.py:414-447`) and `MeroZemory` (`http.py:400-404`) both
rebuild the registry from an import-time snapshot and **both persist the result into the
IDB**. That is the recorded study's measured failure reproduced in a second codebase.

**"Safe mode" is a curated deny-list, and deny-lists are where the holes are**
(`w1-mcprev.md~~:81-89~~`): `ida-mcp-rs --read-only` removes 19 named tools; counting its
82-tool registry against that list, `open_idb`, `open_dsc`, `close_idb`, `load_debug_info`
and its siblings **survive by explicit design** ("lifecycle/discovery tools stay enabled so
the server stays usable"). `open_idb` takes an arbitrary path and can write an `.i64` next to
it — *"you may not modify the analysis, but you may point it at any file on the machine"*.
`r2mcp` is structurally better: safety is a property of each `ToolSpec`'s `ToolMode` mask, so
a new tool must be classified before it exists.

**Every RE debugger is `SANDBOX ONLY` by construction, and four of them say so themselves**
(`w1-mcprev.md~~:98-105~~`). `radare2-mcp`, `frida-mcp`, `lldb-mcp`, `gdb-mcp` all drive a
process, so they run the target. `mrphrazer`'s two headless servers state the trade
plainly. That honesty is worth something — it is a containment claim you can check, unlike
a `--read-only` flag. The genuinely surprising entry is `0xeb/lldb-agent`: **one** tool,
unauthenticated, `0.0.0.0` a documented one-flag change, and a runtime `Invoke-WebRequest`
of an embedded Python. Maximum reach, minimum surface, no licence.

### 1.3 Three repos have no licence at all

`w1-mcprev.md~~:91-96~~`, confirmed by listing each repo root for `LICENSE` / `COPYING` /
`NOTICE` — **not by trusting the badge**:

| repo | ★ | why it matters |
|---|---|---|
| `MeroZemory/ida-multi-mcp` | 444 | default-on `py_eval`, no `--unsafe` flag exists, the same unauthenticated `POST /config` re-enable, policy persisted into the IDB |
| `P4nda0s/IDA-NO-MCP` | **2,039** | no licence, inherits every `ida-pro-mcp` flaw, adds an unconstrained export tree writing large file trees wherever pointed |
| `0xeb/lldb-agent` | 20 | no licence, unauthenticated arbitrary LLDB command execution, runtime download |

Two more report `NOASSERTION` from the API: `FuzzySecurity/kahlo-mcp` and
`jmpnop/imhexMCP`. The report's own observation is the one to carry forward: **the
highest-starred unlicensed candidate is 2,039 stars** — star count is actively misleading
about licensing. Our own `mcp-backends.json` already flags two vendored dnSpy repos as
`未声明`; this is the same finding five rows further out.

### 1.4 The five adoption proposals, each with its mitigation

**These are proposals with no run on record**, per the standard this dossier holds. None of
these five servers was installed, started, or probed; the mitigations below are what would
*have* to be true for the adoption to be safe, not something that has been demonstrated.
Source: `w1-mcprev.md~~:111-135~~`.

1. **`axelmierczuk/tenrec`** (MIT, 177★, 9 plugins) — *stdio only, so there is no port and
   no auth surface to get wrong.* Gate the `Bytes` (patches) and `Comments` (IDB mutation)
   plugins behind `escalation_class: owner_word`; open nothing but `<case>/obj/`.
2. **`blacktop/ida-mcp-rs`** (MIT, 848★) — start `--toolsets=core,functions,disassembly,decompile
   --read-only`, **no** `--enable-debugger`; bind stdio, never `serve-http`. Because
   `--read-only` still permits `open_idb` on any path, the gate must refuse a request whose
   `input_path`/`idb_out` is not under `<case>/obj/` **before the process is spawned** —
   negative control **N8**. Set `IDA_MCP_READ_ONLY=1` explicitly.
3. **`clearbluejar/pyghidra-mcp`** (Apache-2.0, 428★, 22 tools) — `--host 127.0.0.1`, and do
   **not** pass `--gui`. Point `--project-path` at `<case>/`.
4. **`bethington/ghidra-mcp`** (Apache-2.0, 4,082★) — **set `GHIDRA_MCP_AUTH_TOKEN` and
   leave `GHIDRA_MCP_ALLOW_SCRIPTS` unset.** The script endpoints are arbitrary Java inside
   the Ghidra process and v5.4.1 already defaults them off. Leave `GHIDRA_DEBUGGER_URL` unset
   so the 22 `debugger_*` tools never register.
5. **`radareorg/radare2-mcp`** (MIT, official) — already wired. Run over **stdio**, or
   `-H 127.0.0.1:<port> -a <token>` and **never** `-A`/`0.0.0.0`. **This is the one server
   whose safety property is enforced per-dispatch and is worth copying as a design.**

**The five rules that follow from the table, in priority order** (`w1-mcprev.md~~:189-211~~`):

1. **Stdio over HTTP, everywhere.** Ten of these servers have no auth and no port, so stdio
   is the mitigation for all of them at once.
2. **The gate decides paths; the server's flags are inputs to that decision, never the
   decision.** `--read-only`, `--unsafe`, `READ_ONLY_DENY_LIST` are all startup-time dict
   edits inside the process being gated. `reach.fs_read` must be enforced by `gate.ps1`
   *before* spawn.
3. **Bind loopback explicitly, and set the token when one exists.** Pin `127.0.0.1` in the
   command line, never in prose.
4. **Never let a sample's bytes leave the host by default.** Every HTTP-server row is an
   injection vector. `reach.net: "loopback-only"` and refuse any tool whose schema offers a
   `file_path`/`url`/fetch argument — negative control **N10**.
5. **Run the negative controls before believing the probe.** For a newly adopted server the
   first probe should be the one that must **fail**. A probe that cannot fail is not a probe.

---

## 2. The toolchain, cost-ranked, with LLVM named as the single gate

### 2.1 What this box has — verified, because it gates every verdict

`w1-retoolchain.md~~:42-53~~`:

| Fact | Value | How verified |
|---|---|---|
| Python | **3.14.7** (pip 26.2.1, `uv` present) | `python -c "import sys;print(sys.version)"` |
| **clang / clang-cl / llvm-config** | **ABSENT** | `Get-Command clang,clang-cl,llvm-config` → no output |
| VS 2022 "LLVM tools" component | **only `clang-format.exe` + `clang-tidy.exe`** | `Get-ChildItem …\VC\Tools\Llvm\x64\bin -Filter *.exe` |
| VS 2022 MSVC | `cl.exe` at `…\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` | `Get-ChildItem` |
| cmake 4.4.3 / git 2.55 / cargo 1.98.0 / go 1.26.7 | present | `Get-Command` |
| .NET SDK **10.0.400** | present | `dotnet --list-sdks` |
| `E:` free | 30,080,245,760 B = **28.01 GiB** | `Get-PSDrive E` |
| Installed pip RE packages | **`capstone==5.0.9`, `pefile==2024.8.26`** — nothing else from this survey | `pip list` |
| `yr` / `yara-x` / `capa` / `floss` | **not on PATH in that shell** | `Get-Command` → empty |

**A correction this survey made to its own wording** (`w1-debugpairing.md~~:78-100~~`): writing
that `gcc`/`clang`/`cl` were "all ABSENT from PATH" is true but misleading, and the
difference changes a verdict. `cl.exe` **is** installed; it is simply not initialised on
PATH. The gate is therefore not "no compiler" — it is **no LLVM**. The only near-miss
anywhere on the box is `lld-link.exe` under `rustup\toolchains\…\gcc-ld\`, which is a
linker shim, not a compiler: it cannot compile C, cannot be `clang-cl`, and there is no
`clang` or `clang-cl` beside it.

**Consequence that drives the whole survey** (`w1-retoolchain.md~~:55~~`):

> **There is no LLVM on this machine.** One LLVM install (374 MB download, verified for
> 21.1.0) is the single gate for **libFuzzer, Intel PIN pintools, AFL++ Windows, atheris,
> and SymCC-class concolic work.**

The four rows it gates, and why each is LLVM-blocked specifically:

| row | why it needs LLVM, not merely "a compiler" | source |
|---|---|---|
| **Intel Pin 4.4** | *"Starting with Pin 4.0, a MSVC toolset compatible kit is no longer provided… On Windows, LLVM with clang-cl toolset is supported"* | `w1-retoolchain.md~~:113~~` |
| **AFL++ 5.03c** | requires `clang` **and has no Windows build at all** | `w1-retoolchain.md~~:114~~` |
| **atheris 3.1.0** | requires `clang` / `clang-cl`; its wheels are `cp312/cp313/cp314-manylinux_x86_64` **only** (36.8 MB of unusable Linux wheels) | `w1-retoolchain.md~~:116~~` |
| **LLVM + clang-cl → libFuzzer** | `clang-cl /fsanitize=fuzzer harness.c /Fe:harness.exe` | `w1-retoolchain.md~~:109~~` |

**A sibling reached the same conclusion from the other direction** (`w1-debugpairing.md~~:98-100~~`):
*"every row previously blocked on 'no compiler on PATH' is now marked **BLOCKED-ON-LLVM**,
with LLVM named as the single gate. None is blocked on policy, and none would unblock by
installing MSVC — only by installing LLVM."* Two independent measurements, one conclusion.
`w1-debugpairing.md~~:1211-1216~~` re-verified it a third time and found nothing.

**LLVM is the highest-leverage single install available to this station** — and it is the
one thing this survey found that a capability registry cannot express on its own
(`w1-debugpairing.md~~:1140-1144~~`).

### 2.2 Top 8 by capability per gigabyte

**Proposals, no run on record.** Nothing in this table is installed or verified on this
host. `ADOPT` is the surveying agent's recommendation ranking, not a capability: the
"verified cost" column is verified **download bytes** for a file never fetched here, and
"what it buys" is what the upstream documentation claims. Adopting a row means installing
it and then running a command that proves it.


`w1-retoolchain.md~~:197-208~~`, ranked on *new named domain closed ÷ verified bytes consumed*.

| Rank | Pick | Verified cost | What it buys | Verdict |
|---|---|---|---|---|
| **1** | **libFuzzer-dotnet + SharpFuzz** | **1.5 MB** + existing .NET SDK | coverage-guided fuzzing for managed code (D4 → D11) | ADOPT |
| **2** | **LIEF 1.0.0** | **4.1 MB** | PE/DLL static rewriting: import fixups, section injection, dump reconstruction (D13/D14) | ADOPT |
| **3** | **Speakeasy** | **19.4 MB** | unattended Windows unpacking/shellcode triage with JSON reports | ADOPT — **⚠ isolate in its own venv** |
| **4** | **Unicorn + Keystone** | **17.3 MB** | CPU emulation + assembly for decryptors and shellcode | ADOPT (enabler) |
| **5** | **angr 10.0.1** | **69.9 MB** | CFGFast function inventory on stripped PEs + decompiler + symbolic execution | ADOPT |
| **6** | **WinAFL + DynamoRIO** | **466.2 MB** + small build | coverage-guided black-box fuzzing of closed-source Windows binaries | ADOPT (enabler + loop) |
| **7** | **LLVM + clang-cl** | **374.3 MB** | unlocks libFuzzer, Intel PIN, AFL++-on-Windows, atheris | ADOPT — **a multiplier, not a tool** |
| **8** | **retdec v5.0** | **165.6 MB** | independent LLVM decompiler, headless CLI | ADOPT — the disagreement check against IDA/Ghidra |

**Adopt-set total:** ≈ **1.12 GB** of verified download bytes — the report's own arithmetic
at `w1-retoolchain.md~~:208~~` lists the components as LIEF 4.1 + unicorn 15.9 + keystone 1.4 +
speakeasy 19.4 + libfuzzer-dotnet 1.5 + angr 69.9 + retdec 165.6 + DynamoRIO 466.2 +
LLVM 374.3, which sums to ≈1.12 GB, and that sum is labelled "≈ 1.12 GB … = **4 % of the
28.01 GiB free**". **The percentage is arithmetically inconsistent with the components** —
1.12 GB of 28.01 GiB is ≈ 3.8 %, which rounds to 4 %, so the percentage is right and the
label "1.12 GB" understates the itemised sum (which is ≈1.12 GB only if LLVM and DynamoRIO
are counted once each and the rest are the smaller wheels — the itemised sum is in fact
≈1.12 GB, so the two agree; the figure is carried as the source states it, with the
components visible so a reader can re-add them). Installed footprint is `UNVERIFIABLE`;
budget **~5 GB** to be safe. That still leaves >22 GiB.

**Order of work, loop-first** (`w1-retoolchain.md~~:210~~`): 1) Speakeasy in a private venv →
D14 loop. 2) Unicorn/Keystone/LIEF → D14/D13 primitives. 3) WinAFL+DynamoRIO → D11.
4) SharpFuzz → D4. 5) angr → D3. 6) LLVM → **only when a mission needs libFuzzer/PIN/atheris.**

### 2.3 Six traps found before writing the table — the instrument, not the subject

`w1-retoolchain.md~~:59-67~~`. Each of these would have produced a wrong answer, and each is
carried because the failure is silent:

1. **`pip install speakeasy` installs the wrong product.** PyPI `speakeasy 2.0.0` is *"Metrics
   aggregation server"*. The Mandiant Windows emulator is **`speakeasy-emulator` 1.5.11**.
2. **`speakeasy-emulator` pins `unicorn==1.0.2`.** Direct conflict with the `unicorn 2.1.4`
   an angr/Qiling-era engine wants. **Isolate it in its own venv** or it silently downgrades
   an engine you already rely on. A sibling measured the deeper form of this
   (`w1-debugpairing.md~~:591-609~~`): the three emulation candidates pin **mutually exclusive**
   Unicorn versions, so speakeasy and Qiling **cannot coexist in one environment**; and
   Unicorn 1.0.2 **does not import on Python 3.14.7** (`ModuleNotFoundError: No module named
   'distutils'`), fixed by `pip install "setuptools<81"`.
3. **`pip install snowman` is not a decompiler.** PyPI `snowman 0.2.0` is *"An interactive
   system for portfolios on xueqiu.com"*. The real upstream is HTTP 404; the fork's last
   push is **2017-09-29**.
4. **Triton cannot be pip-installed on Windows at all.** `triton 3.8.0` ships **12 wheels,
   all `manylinux`**. Dry-run: `rc=1 ERROR: No matching distribution found for triton`.
5. **VS's "LLVM" is a lie of naming.** If a tool says "needs clang-cl", Visual Studio's LLVM
   component will *not* satisfy it — that component is clang-format/tidy only.
6. **Three tools the plan names no longer exist.** `nccgroup/Nemesis`, `ezyang/muesli`,
   `VirusTotal/ligma` → **HTTP 404**. `sslab-gatech/qsym` → **archived**, last push
   2022-11-23.

**Check the sum:** 4.1 + 15.9 + 1.4 + 19.4 + 1.5 + 69.9 + 165.6 + 466.2 + 374.3 =
**1118.3 MB ≈ 1.12 GB**, which is 3.8 % of 28.01 GiB — the source's "4 %" is the rounded
figure and it is correct. The components are listed so a reader can re-add them rather than
trust the total.

### 2.4 The refusals, with reasons

`w1-retoolchain.md` verdict columns, condensed to the ones a reader might otherwise
re-propose:

| tool | refusal | reason |
|---|---|---|
| Triton | REJECT | no Windows artifact exists today — 12 `manylinux` wheels, 2.85 GB of unusable downloads |
| Snowman | REJECT | upstream dead since 2017; the PyPI name is an unrelated package |
| Hopper | REJECT | macOS-native; Windows only under Wine |
| rev.ng | REJECT | Linux/macOS toolchain; not worth a Linux VM on this volume |
| goblin | REJECT | duplicates `pefile` + `LIEF`; adds no loop |
| KLEE / SymCC / muesli / QSYM | REJECT | Linux/clang-only, or 404, or archived |
| AFL++ / honggfuzz / atheris | DEFER | blocked on LLVM (§2.1) |
| Qiling | DEFER | GPL-2.0, rootfs dependency; and a sibling **measured the install failing** on 3.14.7 via `python-fx → pillow<11` with no prebuilt Windows wheel (`w1-debugpairing.md~~:666-702~~`) |
| Miasm | DEFER | pip resolves but **no Windows-supported command on the project's own docs** |
| unblob | DEFER | firmware-shaped; every external extractor is **apt-only**; no Windows install path documented |
| yara-python 4.5.4 | REJECT | wheels stop at `cp313` ⇒ source build on 3.14; YARA-X already covers us |
| hashdeep | DEFER | 12 years stale; our hashing/Volatility/tshark cover the mission |
| vivisect | DEFER | overlaps angr + LIEF; no proven loop of its own |
| Fuzzilli | REJECT | needs a patched V8/JSC — no D-domain here |
| `firmware-tools` | **UNVERIFIABLE** | **no such PyPI package (404)** and no authoritative repo located. *Treat the name as unverified.* |
| Binary Ninja | DEFER | Free tier is disassembler-only; Personal $199 / Commercial $1799 is Owner money for what IDA already gives |

**The adopt-side rows that are gated on the debugging lane, not on tool availability**
(`w1-retoolchain.md~~:231~~`): **DynamoRIO / Dr. Fuzz attach to processes.** That is an
`ALLOW_LOCAL` / `STOP` boundary, not a tool-availability question — the same for WinAFL's
`-A <module>` attach mode. Flagged, not decided. The red team's independent finding is in
`review-2026-10-02.md` §2 (`H1`: *the grant binds a FILE and has no vocabulary for a
PROCESS*).

---

## 3. The reverse-skill survey: 33 repos, and the four we already have

### 3.1 A rubric that does not exist

`w1-revskills.md~~:8-23~~`. The brief cited
`docs/research/skill-adoption-checklist.md` as "10 hard blocks before adopting any
third-party skill or MCP". Measured:

```
read D:/Software/Tool/WorkStation/debugger/docs/research/skill-adoption-checklist.md
  -> File not found
glob **/*adoption*  under the whole debugger repo
  -> only docs/research/; no checklist
```

Rather than invent ten blocks and pass them off as ours, the survey derived its rubric from
rules that **are** written down, citing each (`w1-revskills.md~~:25-38~~`): B1 no licence file =
no grant; B2 share-alike text imposes an obligation; B3 GPL/AGPL may be *run* but not
vendored; B4 refuse machine-global registry as capability identity; B5 refuse
environment-injected policy; B6 implicit preconditions an agent cannot satisfy are a defect;
B7 a contributing-guide rule no validator enforces is a preference; B8 no third-party binary
is ever an analysis target; B9 the North Star; B10 no phone-home, no executed downloaded
code, no API key we do not hold.

> **The checklist the brief cites was never written.** — `w1-revskills.md~~:23~~`

That is a finding, and it is not closed by this dossier.

### 3.2 The already-vendored four — a duplicate-adoption failure, prevented

`w1-revskills.md~~:73-87~~`. `mcp/` already vendors MCP servers. **Four "top candidates" from
the search results are already here:**

| in-tree path | upstream | consequence |
|---|---|---|
| `mcp/radare2-mcp` | `radareorg/radare2-mcp` (312★) | ALREADY PRESENT |
| `mcp/apktool-mcp-server` | `zinja-coder/apktool-mcp-server` (662★) | ALREADY PRESENT |
| `mcp/frida-mcp` | `dnakov/frida-mcp` | already adopted |
| `mcp/ida-pro-mcp` | `mrexodia/ida-pro-mcp` (v2.0.0, 66 tools) | already adopted |

Three more in-tree were also found already present: `mcp/GhidraMCP`
(`LaurieWired/GhidraMCP`), `mcp/YaraFlux` (`ThreatFlux/YaraFlux`), `mcp/volatility3-mcp`
(`Kirandawadi/volatility3-mcp`).

> *"Recommending these as new adoptions would have been a **duplicate-adoption failure** —
> exactly the 'only add, never subtract' chronic failure in reverse. `radare2-mcp` upstream
> latest is `1.8.8` (2026-09-06, ships `r2mcp-windows.zip` **with a `.sha256`**); the useful
> action is **upgrade + hash verify**, not install."* — `w1-revskills.md~~:87~~`

**Verified today, 2026-10-02:** all five directories exist —
`mcp/radare2-mcp`, `mcp/frida-mcp`, `mcp/ida-pro-mcp`, `mcp/GhidraMCP`,
`mcp/apktool-mcp-server` (`ls mcp/`). One correction to the survey's method: each of those
directories' `git config --get remote.origin.url` now reports
`https://github.com/dwgx/debugger-workstation.git` — the monorepo — so the per-directory
upstream origin the survey measured is **not reproducible today**. The **existence** of the
four is; the origin URLs are carried as the survey recorded them.

### 3.3 Five adoptions, each with a concrete install-and-prove command

**Proposals, no run on record.** The commands in this section are the proof each adoption
would owe, not a record of one.

`w1-revskills.md~~:136-252~~`. **Nothing below was run to completion — installing was out of
scope.** Every command is written against the measured host state.

| # | pick | ★ / licence | why | the risk that is named, not buried |
|---|---|---|---|---|
| 1 | `akiselev/ghidra-cli` v0.2.2 | 226 / GPL-3.0 | a Ghidra path an agent can drive **without a GUI and without our `-PostScript` wrapper**; Windows prebuilt, no compiler | **never run `ghidra setup`** — it downloads and unzips a Ghidra release from `api.github.com` (`src_ghidra_setup.rs:45,59,199`). Point `GHIDRA_INSTALL_DIR` at the Ghidra we own. GPL-3.0 ⇒ run, never vendor. |
| 2 | `bl4ckr0ss3/knife` v1.8.2 (`reknife`) | 357 / MIT | the only candidate with **no dependency risk at all** verifiable from source; an independent third implementation for triangulation, which the `independence` verdict gate wants | **`--json` is a *global* flag** (`src/main.rs:30` `#[arg(long, global = true)]`) — it must precede the subcommand. Three negative controls specified: non-PE input refused; `diff` exit 0 on identity; IOC output **defanged** (`185.220.101[.]47`). |
| 3 | `jtsylve/re-mcp` | 166 / **Apache-2.0 + MIT** | cleanest grant available; its in-process sandbox denylist blocks `subprocess`, `create_subprocess_exec`, `open_connection` (`re_mcp_sandbox.py:352-392`) — a design our verdict gates should copy | **B4 caution, stated rather than buried:** it discovers sessions through shared instance files, which B4 rejects as capability identity. Adopt the sandbox; refuse the instance-file registry. |
| 4 | `2akouwu/reverify` core | 1253 / MIT | the closest external thing to our own North Star | **adopt only the deterministic core with `--mock`.** `openai_proposer` calls `api.openai.com` and we hold no such key. And `reverify_boundary_auditor.py:404-411` ships a **default URL list to probe**, including `https://api.openai.com/v1` and `http://169.254.169.254/...` — **running that as-shipped would have this box send requests to third-party infrastructure. That is a red-line hit.** If ever wanted, the URL list must be emptied and supplied per-case. |
| 5 | `morluto/rea` v3.1.0 | 421 / MIT | only MIT candidate shipping a real CLI, no compiler, no Python env; ships a `SKILL.md` **and** a per-backend conformance suite — the shape we lack | 27 runtime deps including `@lydell/node-pty` and a `prepare` script npm runs on install. **Install with `--ignore-scripts`** and prove the husky hook did not fire. `[UNVERIFIED]`: the `skills list` / `analyze` subcommand *names* were not verified against its CLI definition. |

### 3.4 The refusals, with the licence reason stated

`w1-revskills.md~~:296-318~~`. A rejection with a reason is a result; these are the ones worth
carrying:

| repo | block | reason |
|---|---|---|
| `1-3-7/disrobe` | **Licence** | `LicenseRef-Disrobe-Source-Available-1.1`. Its `LICENSE-SUMMARY.md:11` permits companies to *"Read source and preparing contributions only"*; `:19-20` **no public forks**; `:21` a restriction lasting **while you use it and 24 months after**; `:7` requires a signed licence for bug-bounty work. **Our entire mission is authorised bug-bounty work.** Hard reject. |
| `signal-slot/mcp-gdb` (159★), `haikow/claude-reverse-skills`, `PeiweiHu/DeGPT`, `crowdere/Awesome-RE-MCP` | **B1** | no licence file at all |
| `symgraph/GhidrAssistMCP` (760★) | **B10** | installed by downloading a `.zip` from a Releases page and unzipping into Ghidra — **executed downloaded code** |
| `sjkim1127/Reversecore_MCP` (205★) | key we lack | optional VirusTotal egress requiring `REVERSECORE_VT_API_KEY` |
| `incogbyte/android-reverse-engineering-claude-skill` | **red line** | step 9 **exfiltrates Firebase/Google API keys** and fires live requests at `firebaseio.com` (`SKILL.md:495-533`) |
| `ngwg/ceasta`, `mrphrazer/binary-ninja-headless-mcp`, `fosdickio/binary_ninja_mcp` | **B3** | GPL-3.0 / no commercial licence on this box / GPL-2.0 |
| `zhaoxuya520/reverse-skill` (39,220★) | **partial** | 599 files incl. `competition-ad-certificate-abuse` and `competition-cloud-metadata-path` — offensive skills that hit our red lines. **Borrow the structure, refuse the corpus.** |
| `gadievron/raptor` (3,839★), `FuzzySecurity/kahlo-mcp` | **B1** | no SPDX id |
| `miunasu/IDA-Skill` | **B3** | AGPL-3.0 — running it beside our IDA is fine, vendoring is not |

### 3.5 Two instrument defects from this survey, both of which nearly produced a wrong answer

`w1-revskills.md~~:44-51~~`:

1. **`gh search repos` returns exit 0 and an empty body.** `gh search repos "reverse
   engineering skill claude" --sort stars --order desc --limit 10` printed nothing and exited
   0, while `gh api -X GET search/repositories -f q="reverse engineering skill claude"` on
   the same account returned `total_count=94`. **Silent-empty-with-success is the dangerous
   shape: a caller cannot tell "no results" from "client bug."** Every query in that report
   was rerun through `gh api search/repositories`.
2. **`search/code` ignores `OR`** — `reqwest OR ureq OR telemetry` returned `total_count=0`
   for repos that demonstrably contain those strings. **A `total_count=0` from that endpoint
   is a false negative, not evidence of absence.**

Plus: **GitHub secondary rate limit hit 12 of 30 queries**; *"An `ERROR` is not a zero."*
And a bounded-fetch lesson worth keeping (`w1-revskills.md~~:262~~`): the fetch took the first 40
files in tree order, so `knife`'s `main.rs` — where its entire CLI lives — was never
retrieved. **A bounded fetch is not a whole repo, and every "no egress found" verdict
inherits that bound.** The same report corrected its own first table entry after re-checking:
`disrobe` was first recorded "No network" and is not — it *declares* `reqwest` at
`Cargo.toml:267`, with 0 hits across 21 fetched files, so no egress is *observed* but the
capability is **one code path from live**.

### 3.6 The borrow list, because these are shapes not code

`w1-revskills.md~~:277-292~~`, condensed. Each is specific enough to implement.

1. **`re-mcp` attribute-denylist sandbox** — including the CPython `fromlist` escape at
   `:449`, and the note that `_sandbox_getattr` exists *because* `from X import Y` resolves
   after CPython's own `_getattr_` — **a real hole we do not currently guard**.
2. **`re-mcp` MCP tool annotations as a safety class** — `readOnlyHint` / `destructiveHint` /
   `idempotentHint` / `openWorldHint`; map `destructiveHint` onto `gate.ps1`'s refusal path.
3. **`reverify` claim ledger as a first-class artifact** (`reverify_ledger.py:4-8`): separate
   *state* from *chatter* so compaction cannot summarize both away. Our own
   `.agent/HANDOFF.md` is exactly the thing that gets summarized into mush.
4. **`rea` conformance tests per backend** — for every capability we claim, a case asserting
   the tool agrees with our known-answer fixture. Fits the North Star better than
   pass/fail wiring tests, which our own rules forbid as vacuous.
5. **`knife` offline IOC snapshot with defanging** — a committed, hash-keyed
   suspicious-driver snapshot, defanged in all output, zero network at analysis time.
6. **`agentic-malware-analysis` tool-log provenance** — every lab run persists raw tool JSON
   next to the verdict, so a verdict is always re-derivable from artifacts. Directly serves
   the estate's *current-run Ghidra summary provenance* priority.
7. **`ghidra-cli` count-first + server-side filter discipline** (`SKILL.md:414-433`) — add a
   mandatory `--limit` default to every `query`/`summary` tool, and a `count` subcommand that
   runs before any body fetch.
8. **Size discipline** — a skill that needs more than ~20 files has stopped being a skill and
   become a framework.

---

## 4. The debugging pairings in our own fact-key vocabulary

Full treatment in `dynamic-pairings.md`. Summarised here because the *vocabulary* is the
finding, and it is a correction to the brief itself.

**Two of the three example fact keys in the brief do not exist in the registry**
(`w1-debugpairing.md~~:12-48~~`):

| brief said | registry actually has | consequence |
|---|---|---|
| `forensics.mem.artefact` | **`forensics.artefact.rows`** | any pairing written against the brief's name would fail `registry-verify.py` rule `r4_fact_types_agree` |
| `net.pcap.record` | **`net.flow.summary`** — and fact type `pcap` is declared but **no capability produces a fact of type `pcap`** | a latent inconsistency in the schema itself |
| `native.dec.code` | correct | — |

**Verified today, 2026-10-02:** the `fact_types` enum declares **10** types — `address`,
`string`, `structure`, `bytes_ref`, `verdict`, `path_ref`, `pcap`, `apk`, `token`,
`evidence_source` — and the capabilities actually produce facts of only **4**: `address`,
`string`, `structure`, `verdict`. **Six declared fact types are never produced by anything.**

**Count: 23 pairings — 3 expressible today, 11 need only a new fact key, 9 need a new
capability entry** (`w1-debugpairing.md~~:1135-1138~~`). Of those 9: **4 are BLOCKED-ON-LLVM**
(P5b, P7, P8, P9 — all one gate, one install), 1 is blocked by choice (P12, deliberately),
1 is a measured rejection (P13), and **3 are actionable today** (P1, P3, P16).

---

## 5. What was not verified

- **No MCP server installed or started.** All of §1 is source- and README-derived. *"where I
  say 'enforced at dispatch', that is a source claim, not a measurement"* — `[UNVERIFIED]`
  (`w1-mcprev.md~~:6-7~~`, `:213-215`).
- **No package installed.** All disk figures in §2 are **download** bytes; installed
  footprint is `UNVERIFIABLE` (`w1-retoolchain.md~~:216~~`).
- **Six explicit `UNVERIFIABLE`s from the toolchain survey** (`w1-retoolchain.md~~:214-224~~`):
  installed size of any package after extraction; `LLVM-23.1.2-win64.exe` size (21.1.0 was
  measured at 374.3 MB); whether `frida` / `objection` / `capa` / `floss` / `yara-x` are
  actually runnable — **not on PATH in that survey's shell, and the main inventory lists
  them, so confirm before any "run" claim**; Qiling rootfs size; Miasm on Windows;
  `firmware-tools`; the `yara-x` CLI binary name (`yr`); Binary Ninja installer size; Intel
  Pin kit *installed* size.
- **The per-directory upstream origins in §3.2 are not reproducible today** — the
  directories' `git remote.origin.url` now reports the monorepo. Existence verified;
  origin carried as recorded.
- **`[UNVERIFIED]` `rea`'s subcommand names** (`w1-revskills.md~~:252~~`).
- **A bounded fetch is not a whole repo** — every "no egress found" verdict in §3 inherits
  a 40-file cap (`w1-revskills.md~~:262~~`).

---

## 6. The one sentence

Twenty-five MCP servers assessed against one yardstick and **two survive it** — because
every other "safe mode" is a dict edit inside the process being gated; **three repos have no
licence at all and the highest-starred of them has 2,039 stars**; forty tools cost-ranked
behind a single fact, that **there is no LLVM on this machine and one 374 MB install gates
four of them**; thirty-three skill repos of which **four are already vendored in our own
`mcp/` tree**; and twenty-three debugging pairings of which three are expressible today —
with the measurement that would move the most of them being that **Frida 17.17.0 works
against our own Windows PE** (`dynamic-pairings.md` §1).
