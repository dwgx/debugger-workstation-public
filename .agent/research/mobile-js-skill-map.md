# Mobile / Android / JS reverse-engineering skill ecosystem — map and upgrade plan

Research date: 2026-09-30. Author: research subagent. No code was changed; no third-party
code is vendored. Every claim below names the file and line it came from, or the command
that produced it. Clones were read under
`%LOCALAPPDATA%\Temp\re-research\MobileJsSkills\` and are deletable.

Local baseline this is measured against (all re-verified today, not taken from a README):

| Fact | Evidence |
|---|---|
| `mobile-lab/tools/loop.mjs` passes 25 checks, exit 0 | run today: 25 PASS / 0 FAIL / 3 negative controls, `LOOP CLOSED`, 40/40 Frida cases |
| Android SDK is **build-tools 35.0.0 only** | `ls D:/Software/Android/Sdk` → `build-tools`; no `platform-tools`, no `ndk`, no `emulator` |
| Free space: `D:` 288 GB, `E:` 15 GB | `df -h /e /d` |
| `frida-mcp` is **already vendored** | `mcp/frida-mcp` exists; `manifests/mcp-backends.json` → `frida-mcp | mobile-runtime | MIT` |
| `Il2CppDumper` is **already installed and pinned** | `manifests/tools.json:46`; `Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/` |
| **…and it does not run on this box** | see §8, finding 1 |
| `web-reverse` loop2 has 24 step call sites, 4 explicit negative-control records | `grep -c 'record(' tools/loop2.mjs` → 16; `[^a-z]run(` → 9 (1 is the `function run(` definition) |
| `webcrack@2.16.0` **already bundles** all of kuizuo/js-deobfuscator's transforms | `node_modules/webcrack/dist/deobfuscate/self-defending.d.ts` and `debug-protection.d.ts` both exist |

---

## 1. Target-by-target

### 1.1 `SimoneAvogadro/android-reverse-engineering-skill` — 7,936 ★, Apache-2.0, pushed 2026-09-08

**What I read (in full).** The whole repo is 194 KB / 26 files. I read `SKILL.md` all
313 lines, `scripts/fingerprint.sh` all 241 lines, `commands/decompile.md` in full, both
plugin manifests, and the heading tables of all six references.

**Structure.**

```
.claude-plugin/marketplace.json            marketplace, version 1.5.0
plugins/android-reverse-engineering/
  .claude-plugin/plugin.json               name/version/author/license/keywords["security"]
  commands/decompile.md                    user-invocable slash command
  skills/android-reverse-engineering/
    SKILL.md                               313 lines — the whole workflow
    references/  6 files, 967 lines        loaded on demand, never in context
    scripts/     10 files, 2,358 lines     every script has BOTH .sh and .ps1
```

**The shape is the lesson, and it is three specific decisions:**

1. **A routing phase before any tool runs.** `SKILL.md:28-51` is "Phase 0: Fingerprint
   the App", and it is the *first* phase — before dependency check, before decompile. Its
   stated reason (`SKILL.md:31-33`) is that decompiling Java is "mostly useless for
   Flutter, React Native, Cordova/Capacitor, and Xamarin apps". `fingerprint.sh:82-117`
   is a priority-ordered detector: `libflutter.so` → Flutter; `libhermes.so` /
   `assets/index.android.bundle` / `libreactnativejni.so` → React Native;
   `assets/www/index.html` / `assets/public/index.html` → Cordova; `libmonodroid.so` /
   `assemblies/` → Xamarin. It then reports *the marker that triggered the verdict* —
   `fingerprint.sh:84-85` sets `RATIONALE="lib/<abi>/libflutter.so present"`. A verdict
   without a cited reason is not a verdict.

2. **It refuses to be confidently wrong.** `fingerprint.sh:218-241` maps the verdict to
   a *different next step per framework*. Flutter → "use reFlutter / Doldrums / blutter",
   and it says outright "Java decompilation will yield ~no app code". This is the single
   most copyable thing in the repo: **the triage output's last line is an instruction to
   not use the rest of the skill.**

3. **Cost-bounded output, stated in the skill.** `SKILL.md:252-296` splits API
   documentation into Tier 1 (a flat table, always) and Tier 2 (per-endpoint detail), and
   says at `SKILL.md:292-294`: "As a default, do not produce Tier 2 entries for more than
   ~10 endpoints unless the user explicitly asks for more". That is a token-budget
   decision written into the prompt, not left to the model.

**Two smaller things worth stealing outright:**

- **Phase 3.5 is a *repair* stage, not a *read* stage** (`SKILL.md:164-189`). R8 renames
  JVM symbols but cannot strip Kotlin metadata, so `@DebugMetadata.c` and
  `@Metadata.d2` leak the original FQNs (`references/kotlin-name-recovery.md:11-40`).
  It ships two scripts for it (`recover-kotlin-names.sh`, `lookup-name.sh`) and quotes a
  measured recovery rate — "~100% of `*Repository`/`*ViewModel`/`*UseCase` classes, ~80%
  of DTOs".
- **`decompile.sh:532-562` detects the failure mode it actually hits**: a bundle wrapper
  where the outer APK contains `base.apk` + `split_config.*.apk`. The test is
  `java_count <= 10 && base.apk exists` (`decompile.sh:543`) — a *falsifiable* heuristic
  on output volume, not a filename match.

**Verdict: LEARN, aggressively. Do not vendor.** The content is a workflow, and we already
have a better-verified lab. What we lack is the *shape* — see §2.

### 1.2 `CreditTone/android-reverse-engineering-skill` — 522 ★, Apache-2.0, pushed 2026-05-07

**What I read.** Full file listing (36 files), `SKILL.md` frontmatter and first 40 lines,
all headings of `references/dynamic-analysis.md`, the heading diff between the two
`SKILL.md`s, and the first 40 lines of each of the two bypass scripts.

**What a port preserves.** The stage skeleton, the dual `.sh`/`.ps1` script convention,
the `references/` lazy-load discipline, the decompile wrapper, `check-deps`, and the
`/decompile` command. It also correctly *adds* an escalation rule at `SKILL.md:18-26`
("Do not jump straight into Frida, packet capture, or SO analysis") and a genuinely sharp
tool-selection heuristic at `SKILL.md:28-40` — suggest IDA only if the SO is not
obfuscated, detected by "only a handful of huge functions (>10 KB each) instead of many
small ones".

**What a port drops — and this is the finding.** Diffing the heading trees:

| Present in SimoneAvogadro | Present in CreditTone |
|---|---|
| `### Phase 0: Fingerprint the App` | **absent** |
| `### Phase 3.5: Recover Kotlin Class Names` | **absent** |
| `#### Tier 1` / `#### Tier 2` output bounds | **absent** |
| `## Output`, `## References` | **absent** |
| `scripts/fingerprint.sh` (241 ln) | **absent** |
| `scripts/recover-kotlin-names.sh`, `lookup-name.sh` | **absent** |
| `references/kotlin-name-recovery.md` | **absent** |

The port kept **the tooling** and threw away **the decision structure**. The
fingerprint stage — the part that stops the agent doing the wrong thing — was the first
thing dropped, and the port grew in exactly the direction fingerprint.sh was designed to
prevent: seven runtime scripts, seven of which are on our red line (§7).

**Verdict: LEARN THE NEGATIVE.** This is the counter-example. A harness port should
preserve the *routing* and the *output bounds*, because those are what encode judgment;
the script inventory is the part that can be re-derived per host.

### 1.3 `dnakov/frida-mcp` — 434 ★, MIT, pushed 2025-05-12 (stale ~16 months)

**What I read.** `pyproject.toml` (45 lines), all 13 `@mcp.tool` signatures in
`src/frida_mcp/cli.py` (477 lines total), and the README feature list.

Deps are `frida>=16.0.0` and `mcp>=1.5.0`. The tool surface: `enumerate_processes`,
`enumerate_devices`, `get_device`, `get_usb_device`, `get_local_device`,
`get_process_by_name`, `attach_to_process`, `spawn_process`, `resume_process`,
`kill_process`, `create_interactive_session`, `execute_in_session`,
`get_session_messages`. Plus 3 resources and 1 prompt.

**Against our mobile-lab: this is not a competitor, it is a session manager.** Our 40-case
offline suite proves that hook *scripts* are correct — overload selection, `onEnter`
before `onLeave`, JNI name mangling, `TracerPid` classification, credential redaction.
`frida-mcp` proves nothing about correctness; it provides a *stateful session handle*
(`session_id` + `keep_alive=True` + `get_session_messages`) so an agent can attach once
and iterate on one live process without re-attaching. Those are orthogonal, and the
session model is the one idea worth taking.

**We already have it.** `mcp/frida-mcp` is in our tree and `manifests/mcp-backends.json`
lists it as `frida-mcp | mobile-runtime | MIT`. There is nothing to adopt; the blocker is
`frida-ls-devices` hanging indefinitely on this box (measured, `mobile-lab/README.md:80`),
which is a device-absence problem, not a packaging problem.

**Verdict: ALREADY ADOPTED. Learn the session-handle shape; refresh it (16 months stale).**

### 1.4 `index-login/MobileRE-Skill` — 81 ★, MIT, pushed 2026-09-30 (very active)

**What I read.** Full 92-file listing, all 9 `references/*.md` heading trees, the shell
vendor table and the decision trees in `unpacking.md:84-132`, the phase list in
`anti-detection.md`, and the first 40 lines of the two worst scripts.

**Structure.** Six `.kilo/` skills (`frida-mobile-security`, `rev-dex-dumper`,
`rev-struct`, `rev-symbol`, `rev-unicorn-debug`, `karpathy-guidelines`), nine
`references/`, 30 Python tools, 20+ Frida JS modules. It is the deepest *technique*
library in this survey and the one with the clearest defensive/circumventive split.

**The half that is genuinely good and genuinely ours to adopt** — this is the finding I
did not expect:

- `unpacking.md:12-27` is a **cost-ascending triage ladder**: Step 0 asks three questions
  (is there a shell? what is the DEX shape? how many `native`/return-void methods?) and
  its stated conclusion for a clean app is "直接 `unzip` 提取 DEX，**到此为止**，不进任何
  dump 流水线" — *stop here, do not enter any dump pipeline*. The default action is to do
  nothing. That is the same discipline as SimoneAvogadro's fingerprint phase, arrived at
  from the other direction.
- `unpacking.md:84-104` is a **packer vendor fingerprint table** keyed on `.so` filename
  and Application classname: `libjiagu.so`→360, `libshell*.so`/`libtup.so`→Tencent Legu,
  `libDexHelper.so`→Bangcle, `libexec.so`→IJiami, `libnaga.so`→Nagа, `libnesec.so`→NetEase
  Yidun; `com.stub.StubApp`→360, `com.tencent.StubShell.TxAppEntry`→Tencent. Plus a
  three-generation model: whole-DEX-encrypted → instruction-extracted → Dex2C/VMP, with
  the honest note that on gen-3 "脱壳无效，转 native-analysis.md" — *unpacking does not
  work; switch lanes*. **Detection and triage, with an explicit give-up condition.**
- `unpacking.md:106-116` is a **product verification decision tree** keyed on what jadx
  actually shows, and `unpacking.md:118-127` records four failure modes an AI "commonly
  misses", including the one that matters most: every dumped DEX needs its checksum fixed
  or jadx reports `Bad dex file checksum`, and a past session misjudged 7 DEXs as usable.
  That is a *negative* result written down so nobody re-derives it — which is exactly what
  our own READMEs do.
- `rev-dex-dumper/mem-dex-dumper.c` reads `/proc/<pid>/mem` and **does not inject, does
  not ptrace**. The repo states the motivation plainly: it is invisible to Frida-based
  detection. It is observation, not evasion — it defeats nothing, it just does not
  announce itself.

**The half we refuse** is §7.

**Verdict: ADOPT the triage + vendor table + decision trees (rebuild, don't copy). REFUSE
the `scripts/bypass/` directory and `references/anti-detection.md` wholesale.**

### 1.5 `tihanyin/REx-skill` — 99 ★, MIT, pushed 2026-09-23

**What I read.** `SKILL.md` all 351 lines, all 7 agent files in full, the `general-skill/`
AGENTS.md, and line counts of everything else.

**This is the orchestration layer the brief says is missing, and it is the best-designed
thing in the survey.** Not the mobile content — the *process*.

**The 3-phase subagent protocol** (`SKILL.md:246-278`):

- **Phase 1, `re-recon`, alone.** Threat model, artefacts, import gate, `ruled_out`.
  `SKILL.md:248-250` gives the reason: "Running stances before recon means each
  re-derives the threat model differently and their disagreements tell you nothing."
- **Phase 2, five stance agents in parallel, non-communicating** — `re-bughunt` (any
  demonstrable defect), `re-safety` (the guard on every risky operation), `re-arithmetic`
  (size/index/width/signedness), `re-lifecycle` (allocation, free, ownership, init, error
  paths), `re-logic` (authorisation, state machines, crypto, validate-here-use-there).
  Each agent file is 32-35 lines and each one carries the same clause: "You will not see
  another reviewer's findings, and must not ask for them."
- **Phase 3, `re-reconcile`, alone.** `re-reconcile.md:8-10`: "**Read the code before you
  read anyone's conclusions in detail.** A confident rationale is not evidence; the code
  is." It then adjudicates case by case, with a rule that matters:
  `re-reconcile.md:16-18` — agents sharing a decompiler are *correlated*, so "All agree,
  same sink, same class — take it, but confidence does not go to certainty."

`SKILL.md:271-274` names the whole mechanism: "One leak collapses five opinions into one
held five times, which is worse than one opinion because it now looks corroborated."

Three more transferable pieces:

- **Content-addressed evidence.** `SKILL.md:140-148`: everything for one binary lands in
  `results/<filename>-<first 8 of SHA-256>/`, because "two builds of the same filename
  would otherwise overwrite each other's evidence in silence". `results/index.json` maps
  SHA-256 → directory.
- **`pipeline_status.py` names every stage that did not run** (`SKILL.md:178-180`, and
  `SKILL.md:335-338`: "A stage that did not run is an unasked question, not a clean
  answer — and it is the one gap that produces no error to notice"). This is the exact
  failure our own `mobile-lab/README.md` §"Honest limits" is written against, mechanised.
- **`capabilities.sh` before planning** (`SKILL.md:158-166`): "a missing tool never fails
  loudly, it silently narrows the analysis."

**It is Linux/Nix-shaped** — `install.sh`, `flake.nix`, `devshell/`, `qemu-user`, AFL++,
angr, `$ANGR_PYTHON`. On Windows the scripts largely degrade. But `general-skill/SKILL-RE.md`
(3,750 lines) is a harness-agnostic rewrite, and the *agent protocol* has no toolchain
dependency at all.

**Verdict: ADOPT the 3-phase stance protocol and the content-addressed evidence layout.
This is the missing orchestration layer. Learn the evidence standard; skip the Nix devshell.**

### 1.6 `kuizuo/js-deobfuscator` — 1,178 ★, MIT, pushed 2026-08-11

**What I read.** Full pass listing with line counts (21 files, 2,415 lines in
`deobfuscate/`), `index.ts` in full, `vm.ts:1-45`, `self-defending.ts:1-25`.

**The pass set** (`packages/deob/src/deobfuscate/`): `string-array`, `array-rotator`,
`decoder`, `inline-decoder-wrappers`, `inline-decoded-strings`, `inline-object-props`,
`merge-object-assignments`, `dead-code`, `control-flow-switch`, `control-flow-object`,
`self-defending`, `debug-protection`, `var-functions`, `evaluate-globals`, `save-objects`,
`vm`, plus `my-*` variants.

**The most important thing I learned: we already have it.** `kuizuo/js-deobfuscator` is
the engine inside **webcrack**, and `web-reverse/static/package.json:27` already pins
`"webcrack": "2.16.0"`. Verified on disk:

```
node_modules/webcrack/dist/deobfuscate/self-defending.d.ts     exists
node_modules/webcrack/dist/deobfuscate/debug-protection.d.ts   exists
node_modules/webcrack/dist/deobfuscate/control-flow-switch.d.ts exists
node_modules/webcrack/dist/deobfuscate/string-array.d.ts        exists
```

**And we deliberately never exercise two of them.** `static/gen-obf.mjs:184-185`:

```js
selfDefending: false,
debugProtection: false,
```

Our own README (`web-reverse/README.md`, "Honest limits") documents this as an unmeasured
gap. So the 1.2k-star deobfuscator is in our dependency tree, and the only work is turning
two booleans on and adding negative controls. **Footprint: zero bytes. This is the highest
value-per-effort item in the whole survey.**

Two design details worth copying regardless:

- **Passes are tagged `safe` vs `unsafe`** — `index.ts:29` tags the deobfuscate transform
  `['unsafe']`; `self-defending.ts:21` tags itself `['safe']`. The reader can tell whether a
  transform might execute untrusted code.
- **Decoder evaluation is sandboxed with a hard timeout.** `vm.ts:16-33` uses
  `isolated-vm` with `timeout: 10_000`, `copy: true`, `filename: 'file:///obfuscated.js'`.
  Our `static/lib/sandbox.mjs` is a bare V8 context — cheaper and adequate for our own
  samples, but unbounded against a hostile decoder.

**Verdict: NO new dependency. Adopt the two disabled transforms and the `safe`/`unsafe`
tagging. Learn the sandbox timeout.**

### 1.7 `Perfare/Il2CppDumper` — 9,445 ★, MIT, pushed 2026-09-30

**What I read.** Repo metadata via `gh api`; the installed directory listing.

`Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/` holds `Il2CppDumper.exe` (892 KB),
`Il2CppDumper-x86.exe`, `config.json`, and six Python scripts that emit
Ghidra/IDA loadable structures (`ghidra_with_struct.py`, `ida_with_struct.py`,
`il2cpp_header_to_ghidra.py`). It consumes `libil2cpp.so` + `global-metadata.dat` and emits
a C# stub (`DummyDll`) plus `script.json` — i.e. it **restores method names onto addresses**,
which is exactly the "IL2CPP method restoration" capability the brief asks about.

**It is already installed, pinned, and driven by nothing.** `manifests/tools.json:46` pins
it. `grep -ril il2cppdumper` across the repo returns only docs, manifests, notes and
`scripts/download-tools.ps1` — **no lab, no `tools/`, no fixture, no loop.** This is the
same "installed and inert" condition mobile-lab was created to fix, in a domain we have
**zero** coverage of: there is no `game-lab`, and `Unpackers-Game/GoReSym`,
`AssetRipper` and `UniExtract` are in the same state.

**And it does not run here.** Measured:

```
$ 'D:/.../Il2CppDumper.exe'
You must install or update .NET to run this application.
Framework: 'Microsoft.NETCore.App', version '6.0.0' (x64)
The following frameworks were found:
  8.0.31 ... 10.0.11
```

`DOTNET_ROLL_FORWARD=LatestMajor` does **not** rescue it: with stdin closed it produced
0 bytes and had to be killed at 60 s, then again at 45 s (`EXIT=124`). So it is a hard
blocker before any capability work.

**This is a static-only capability** — `libil2cpp.so` is a file on disk. It needs no
device, no emulator, no NDK. It needs a .NET runtime that works.

**Verdict: ADOPT, after fixing the runtime. Highest-value *new domain*. Needs an Owner call
on installing a .NET 6 runtime (or a newer Il2CppDumper release built for net8).**

### 1.8 `firstrui/codex-reverse-skills` — 43 ★, MIT, pushed 2026-03-26

**What I read.** All 1,373 lines, including the full 579-line `web-js-reverse-master-flow/SKILL.md`
and the first 50 lines of `jsvmp-wasm-and-deobf.md`.

**The master flow is a 6-phase state machine with real stop discipline** — the closest
existing thing to the orchestration layer for web/JS specifically:

`证据门 -> locate -> recover(必要时) -> runtime diff -> env-patch -> sign-replay`

Three mechanisms our `web-reverse` does not have:


1. **An Anti-Spiral Protocol with numeric thresholds** (`SKILL.md` "Anti-Spiral"): "同一
   阶段连续两轮没有新增证据，必须切换动作，不允许第三次重复同类操作" — two consecutive
   rounds with no new evidence *forces* a change of action, and a third repetition is
   forbidden. Six rounds without convergence forces escalation. Every escalation must
   state "为什么当前打法失败、下一步准备验证什么、放弃了哪些假设".
2. **A Hard-Site Escalation Ladder with a ban on skipping rungs**: "禁止跨级 — 没有第 2 步
   就做第 5 步; 没有第 4 步就宣称本地环境已经足够; 没有第 6 步评估就强行追求'必须纯本地'".
   The final rung is *accept browser-side black-box reuse* — giving up on full local
   recovery is a legitimate, named outcome.
3. **Seven scenario branches** (A/B/C/D/E/F/G) that pre-select a phase order from
   observed signals — e.g. seeing `JSVMP/227/226/basearr/opcode` routes to Phase 2 *before*
   Phase 1 completes. This is SimoneAvogadro's fingerprint idea, applied to JS, and it is
   the direct fix for a gap we have: our `triage.mjs` classifies `jsvmp` and then says
   "NOT static-deobfuscatable", which is honest but leaves the analyst with no route.

Its `1997-pro-web-reverse-casebook` adds `jsvmp-wasm-and-deobf.md` (106 lines) — casebook
notes on Akamai/Kasada/PX/227/Tencent-VMP, with the right core principle: "壳层恢复必须围绕
已证明的目标边界做最小切片" (recover only the minimal slice around the proven boundary).
The most transferable single line: Tencent's VMP articles are valuable because they change
"解释执行" (interpret execution) into "生成 AST" (emit AST) — i.e. **treat a VM as a
tracing problem, not a lifting problem.**

**Verdict: ADOPT the Anti-Spiral thresholds and the escalation ladder as `web-reverse` loop
discipline. LEARN the JSVMP route. REFUSE the vendor-specific casebook as a default (it is
named-bot-defeat material — §7).**

### 1.9 Additional targets found by my own `gh search`

| Repo | ★ | License | Note |
|---|---|---|---|
| `skylot/jadx` | 50,684 | Apache-2.0 | Already installed (JADX 1.5.6, cross-checks our loop) |
| `APKLab/APKLab` | 3,997 | **AGPL-3.0** | VS Code workbench. AGPL — do not vendor; a GUI is not what we lack |
| `zinja-coder/jadx-ai-mcp` | 2,842 | Apache-2.0 | MCP inside jadx; interesting seam, but adds a third-party MCP to user-global config, which `AGENTS.md` §3 forbids by default |
| `DERE-ad2001/Frida-Labs` | 1,325 | — | Frida CTF challenges. **Needs a device** — out of reach today |
| `WhiteNightShadow/firefox-reverse` | 863 | — | "SpiderMonkey 引擎层非侵入 trace" for JSVMP/WASM. Non-invasive engine-level tracing is the right idea and the right direction for our JSVMP gap, but a whole patched Firefox is a large footprint |
| `WhiteNightShadow/camoufox-reverse-mcp` | 522 | — | Anti-detection browser MCP. **Out of scope** — the whole product is evasion |
| `715494637/reverse-skill` | 367 | — | Chinese web/JS RE skill; same family as firstrui |
| `FuzzySecurity/kahlo-mcp` | 134 | **NOASSERTION** | Frida MCP; no license declared = all rights reserved. Skip |
| `WhiteNightShadow/…`, `zhizhuodemao/frida-mcp` | 121 | — | Duplicate frida-mcp forks; no reason to prefer over the MIT original we already have |

Note on search: `gh search repos` with **multi-word queries returns empty** on this box
(`"javascript deobfuscator babel"` → `[]`, `"apk deobfuscator"` → `[]`), while
single-token queries work (`"jsvmp"` → 6 results, `"jadx"` → 10). Use plain spaces, and
prefer one distinctive token. This is worth knowing before anyone concludes "there is
nothing else out there".

---

## 2. Structural lesson — what a 7.9k-star skill does that we do not

**Their structure beats ours on exactly one axis, and it is not the tooling.**

Our labs are the stronger artefact. `mobile-lab` builds a genuinely signed APK from source
with the real Google `aapt2`/`d8`/`zipalign`/`apksigner`, hand-assembles an ELF64 AArch64
`.so`, cross-checks it against **pyelftools** (which caught a real `sh_link` bug), and
cross-checks its own findings against **JADX and Apktool** — two independent decoders.
25 checks, exit 0, 40/40 Frida cases with a modelled runtime. SimoneAvogadro has *no
fixture, no oracle, and no negative control of any kind.* It is 2,358 lines of shell and
PowerShell that call `jadx` and grep for URLs.

**What we are missing is that our labs are *tools*, and theirs is a *decision procedure*.**

Our entry point is `node tools/loop.mjs` — do the work, print PASS lines. Theirs is a
document that says *which work to do, in what order, and when to stop*. Specifically:

| Their asset | We have? | Cost to add |
|---|---|---|
| Triage/route phase that can say "do not decompile this" | **No.** `analyze.mjs` reports what is in the APK; nothing routes | ~150 lines, one file |
| Named output tiers with a stated cap | **No** — our output format is fixed | prompt + schema change |
| Per-phase exit conditions and "go back" rules | **No** | prompt-level |
| Anti-spiral thresholds | **No** | prompt-level, ~30 lines |
| Multi-agent stance protocol with an adjudicator | **No** — this is the orchestration gap | `skills/` + agent files, no toolchain dep |
| Content-addressed evidence dirs keyed by hash | **No** — we use fixed `out/` dirs | ~50 lines |
| A "which stage did not run" reporter | Partially — each README has a manual "Honest limits" section | ~80 lines |
| Dual `.sh`/`.ps1` for every script | **No** — ours is Node + one PowerShell wrapper | not needed; Node is our harness |
| Shell/packer vendor fingerprint table | **No** | ~60 lines, pure data |

1. **Route before you act.** `fingerprint.sh` runs before the dependency check, and its
   output ends with a *prohibition*. Ours starts by parsing.
2. **Name the marker, not just the verdict.** `fingerprint.sh:84-85` always records which
   file or string produced the call. Our `analyze.mjs` prints `pinning-native` as a kind
   with no per-finding provenance line the analyst can audit.
3. **Bound your own output in the prompt.** Tier 1 / Tier 2, capped at ~10. We have no
   equivalent and our loops are verbose.
4. **Independent stances, then adjudicate — never in parallel with agreement.** REx's
   3-phase protocol, and its warning that co-reading a decompiler makes five agents
   correlated.
5. **Default the escalation ladder to "accept what you have".** firstrui's rung 6 is
   browser-side black-box reuse. REx's equivalent is `ruled_out` as a deliverable. Both
   treat *stopping correctly* as a first-class result — and ours does too, in prose
   ("This lab does not disassemble"), but not in code.

---

## 3. Capability delta — what we cannot do today

| # | Capability | Us today | Target | Needs a device? |
|---|---|---|---|---|
| 1 | **Packing / shell detection** | **Zero.** `grep -ciE 'packer\|packing\|jiagu\|shell\|encrypt' tools/analyze.mjs` → **0** | `unpacking.md:84-104` vendor table; `fingerprint.sh` | **No** — pure ZIP+DEX inspection |
| 2 | **Anti-emulator detection** | **Zero.** `grep -ciE 'emulator\|goldfish\|qemu'` → **0** | standard signal set | Partly — *detecting the check* is static; *firing it* is runtime |
| 3 | **Root / Magisk detection (detect, not bypass)** | **Zero statically.** The 13 `root` grep hits are all XML-tree roots, not signals | `bypass_root_detect.js`'s **signal list** | Static list = no; firing = yes |
| 4 | **DEX dump from memory** | **None** | `mem-dex-dumper.c`, `dump_dex.js` | **Yes** |
| 5 | **Anti-frida detection (static)** | **None**; the runtime `02-anti-instrumentation-detector.js` covers TracerPid/maps only | static string/symbol scan for the signal set | **No** for the scan |
| 6 | **JNI native analysis** | **Strong.** 5/5 `Java_` exports resolved; `.dynsym`, `DT_NEEDED`, JNI mangling, all four pinning mechanisms | — | No. We are ahead here |
| 7 | **Hook orchestration** | 40 offline cases, no live handle | `frida-mcp` `session_id`/`keep_alive` | **Yes** |
| 8 | **Cert-pinning observation** | **Strong.** 4 mechanisms distinguished + compiled `network_security_config.xml` digests | — | No (static). Our hook needs a device |
| 9 | **Device traffic capture** | **None.** No `adb`, no `platform-tools` | `ssl_log.js`, mitm/reqable | **Yes** |
| 10 | **IL2CPP method restoration** | **None** — tool installed and broken | Il2CppDumper | **No** — static, once .NET works |
| 11 | **self-defending / debug-protection removal** | **Have the code, disabled.** `gen-obf.mjs:184-185` | already in `webcrack` | **No** |
| 12 | **JSVMP route** | Detected and declared unsupported; no route given | `firstrui` Phase 2, `jsvmp-wasm-and-deobf.md` | No (statically) / tracing (dynamically) |
| 13 | **Kotlin name recovery** | **None** | `recover-kotlin-names.sh` (claimed ~100%/~80%) | **No** — DEX strings only |
| 14 | **Multi-agent RE protocol** | **None** | REx 3-phase | **No** |

Rows 1, 2, 3, 5, 10, 11, 13, 14 are all reachable today with no device.

---

## 4. Adopt / learn / refuse

Footprint is measured, not estimated. "Vendor" means copying code into our tree, which
`web-reverse/README.md` and `mobile-lab/README.md` both already forbid in principle.

| Item | Verdict | License | Footprint | Why |
|---|---|---|---|---|
| `fingerprint.sh` routing pattern | **ADOPT (rebuild in Node)** | Apache-2.0 | ~150 ln, 0 dep | Highest value/cost in the survey. Ours is Node-only; porting the *logic* to `tools/triage.mjs` keeps one harness |
| Anti-spiral thresholds + escalation ladder | **ADOPT (prompt-level)** | MIT | ~60 lines of skill text | Pure process; no code; directly fixes our unbounded loops |
| REx 3-phase stance protocol | **ADOPT (agents, no devshell)** | MIT | 7 agent files, ~230 lines | The missing orchestration layer; zero toolchain dependency |
| Content-addressed `results/<name>-<sha8>/` | **ADOPT** | MIT | ~50 lines | Prevents silent evidence overwrite |
| Packer vendor table + triage ladder | **ADOPT as reference data** | MIT | ~60 lines, pure data | Detection, with an explicit give-up condition |
| Two disabled webcrack transforms | **ADOPT (flip 2 booleans)** | MIT (webcrack) | **0 bytes** | Already a dependency. Best ratio in the survey |
| `safe`/`unsafe` transform tagging | **ADOPT** | MIT | ~20 lines | Lets a reader know if a pass executes untrusted code |
| Sandbox eval timeout | **ADOPT** | MIT | 1 line | `vm.ts:27` `timeout: 10_000`; ours is unbounded |
| `pipeline_status.py` | **ADOPT (simplify)** | MIT | ~80 lines | Automates what our READMEs do by hand |
| Kotlin name recovery | **ADOPT (rebuild)** | Apache-2.0 | ~140 lines | DEX strings only; no device; big win on obfuscated apps |
| Il2CppDumper | **ADOPT after .NET fix** | MIT | 892 KB (already on disk) | Only entry into a domain we have zero of |
| `frida-mcp` session handle | **ALREADY VENDORED** | MIT | 0 | Refresh — 16 months stale |
| `apktool-mcp-server`, `mobsf-mcp-server` | **ALREADY IN MANIFEST** | Apache-2.0 / MIT | 0 | Not exercised; no lab drives them |
| APKLab | **SKIP** | **AGPL-3.0** | — | AGPL; and a GUI is not the gap |
| `jadx-ai-mcp` | **SKIP for now** | Apache-2.0 | — | Would add a user-global MCP; `AGENTS.md` §3 forbids by default |
| Frida-Labs | **DEFER** | — | — | Every exercise needs a device |
| REx Nix devshell / AFL++ / angr | **SKIP** | MIT | ~2 GB | Wrong host; no WSL, no elevation |
| js-deobfuscator | **NO NEW DEP** | MIT | 0 | Already inside `webcrack@2.16.0` |
| CreditTone runtime scripts | **REFUSE** | Apache-2.0 | — | §7 |
| MobileRE `scripts/bypass/` | **REFUSE** | MIT | — | §7 |
| `firefox-reverse` | **DEFER** | — | ~1 GB | Right idea, large footprint; revisit with JSVMP work |
| `camoufox-reverse-mcp` | **REFUSE** | — | — | Evasion is the product |
| `kahlo-mcp` | **SKIP** | **none declared** | — | All rights reserved |

---

## 5. Top 5 structural lessons

1. **Route before you act, and let triage say "don't".** `fingerprint.sh` runs *before*
   the dependency check and can conclude "Java decompilation will yield ~no app code".
   Our loops start by parsing. The triage output's last line should be an instruction.
2. **Cite the marker, not the verdict.** `fingerprint.sh:84-85` always records which file
   or string fired. A classifier that cannot show its evidence is a vibe.
3. **Bound your own output in the prompt.** Tier 1 always / Tier 2 capped at ~10
   (`SKILL.md:292-294`). A skill that cannot say "stop at ten" burns the context budget
   that made it worth having.
4. **Independent stances, then one adjudicator — never five agreeing agents.** REx's
   Phase 2 is explicitly non-communicating and its adjudicator reads the code *before*
   the conclusions, because co-reading one decompiler makes five opinions correlated and
   "looks corroborated".
5. **A port should preserve judgment and drop inventory — and most get it backwards.**
   The 522★ Codex port kept the 13 scripts and dropped Phase 0, Phase 3.5, the output
   tiers, and both repair scripts. The dropped parts were the decision structure; the
   kept parts were re-derivable. That is why it drifted into bypass territory.

---

## 6. Top 5 capability deltas

1. **No packing/shell detection at all** — `grep -c 'jiagu\|shell\|packer' analyze.mjs`
   → 0. Reachable today with no device.
2. **No anti-emulator or root detection statically** — both greps → 0. The *signal lists*
   are static analysis; only firing them needs a device.
3. **IL2CPP: zero coverage of a whole domain, with the tool already installed and
   broken** — `.NET 6.0.0` required, 8.0.31/10.0.11 present, roll-forward does not help.
4. **Kotlin name recovery** — the single highest-yield transform for obfuscated Android
   apps, ~100%/80% claimed, and we have none of it.
5. **self-defending and debug-protection are unexercised** — the code is in our
   `node_modules` and switched off in our own sample factory at `gen-obf.mjs:184-185`.

---

## 7. What we refuse, and why

These are listed separately because "we read it and said no" is the finding. In every case
the refusal is about the *use*, not the file format.

**7.1 `bypass_root_detect.js` and `bypass_frida_svc_detect.js` (CreditTone, Apache-2.0).**
Both make a third-party app's protection checks *not fire*. `bypass_root_detect.js:11-25`
carries a 25-package root-tool blocklist and hooks `PackageManager`, `SystemProperties`,
`ProcessBuilder` and `Runtime` to return clean answers. `bypass_frida_svc_detect.js:5-40`
scans `r-x` ranges for the ARM64 `svc #0` opcode (`01 00 00 D4`) to find the raw
`SYS_OPEN` (56) syscall and hook it, so the app cannot see `/proc/self/maps` reads.
`AGENTS.md` §5 puts "circumventing copyright protection" out of scope, and our own
`mobile-lab/README.md` already draws the line: *"Anti-frida / anti-debug DETECTION is in
scope; BYPASSING is not."* **Refused. The signal list inside the root bypass is fair game
(see §9, item 3); the neutering is not.**

**7.2 MobileRE `scripts/bypass/` — all 9 files.** `frida_feature_hider.js`,
`dlsym_tracer.js`, `exit_blocker.js`, `function_patcher.js`, `init_hook.js`,
`root_bypass.js`, `shellcode_detector.js`, `so_loader_tracer.js`, `thread_blocker.js`.
Same category as 7.1, at greater sophistication. **Refused wholesale.**

**7.3 `references/anti-detection.md` (287 lines) — refused wholesale.** It is a 7-phase
pipeline to defeat anti-instrumentation in commercial packers, and it is specific:
Phase 0 validates a `linker64` `call_constructors` offset, Phase 1 locates the detection
`.so`, Phase 5 finds the crash offset, Phase 6 is "精确 bypass", and the "经验积累"
section is organised by vendor — bangcle, ijiami, 360, dead-signal thread detection,
`clone()` thread location with PROT_NONE. A named-vendor defence-evasion manual. **Refused
wholesale — not selectively.** I have described *that* it exists and *what class* it is;
I have deliberately not reproduced the offsets or the per-vendor techniques, and nothing
from it should enter this station.

**7.4 `keystore_dump.js` (CreditTone) — refused as shipped.** It exports Android
Keystore client certificates to `.p12` with a **hardcoded password `"hooker"`** at line 3.
Dumping another party's TLS client credentials is credential extraction. The underlying
activity is legitimate *for an app you own* — it is how you debug your own mTLS — but the
shipped form (generic tool + fixed password) is not something we take. If we ever need it:
rebuild, scope to our own fixture, generate the password at runtime, gitignore the output.

**7.5 `dump_dex.js` and `dump_so.js` (CreditTone) — capability deferred, not refused.**
These are memory extraction and only run against a live process. On our own fixture they
would be fine. There is no device, so this is a *reachability* problem, not a policy one.
Re-evaluate if an owner-authorised device appears.

**7.6 firstrui's vendor casebook — refused as a default.** `1997-pro-web-reverse-casebook`
is organised around named commercial bot-management products (Akamai, Kasada,
PerimeterX, reese84, Incapsula, BlackBox, `a_bogong`) and captcha products. Our
`web-reverse/antibot.md` already draws the correct line: *"No captcha/anti-bot evasion
tooling, here or anywhere in this station. Recognising and reporting anti-automation
interference on an authorized target is in scope; defeating someone else's gate is not."*
The **process** content — the Anti-Spiral Protocol, the escalation ladder, the scenario
branches, the JSVMP minimal-slice principle — is ours to take. The vendor index is not.

**7.7 `WhiteNightShadow/camoufox-reverse-mcp` and `WhiteNightShadow/firefox-reverse` —
camoufox refused outright.** An anti-detection browser MCP server is evasion as a product
category. `firefox-reverse` is *deferred* rather than refused: its "non-invasive
SpiderMonkey-level trace" is a legitimate technique (it observes, it does not defeat), and
it is the plausible future answer to our JSVMP gap — but a patched browser is a large
footprint and not a decision to make inside a research task.

**7.8 `Frida-Labs` — deferred, not refused.** 1,325 ★ of Frida CTF challenges, every one
of which needs a device or emulator. Not a policy question; a reachability one.

---

## 8. The upgrade plan

Each step is provable by one command or one file read. Ordered by value-per-effort. **No
step below requires a device or an emulator.** Steps that *would* be improved by one are
marked and have a stated fallback.

### Step 1 — Fix Il2CppDumper's runtime. `(Owner decision — installs a .NET runtime)`

The tool is installed, pinned at `manifests/tools.json:46`, and does not start. Prove the
blocker:

```bash
'D:/Software/Tool/WorkStation/debugger/Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/Il2CppDumper.exe'
# -> Framework: 'Microsoft.NETCore.App', version '6.0.0' (x64)
# -> found: 8.0.31, 10.0.11
```

Roll-forward was tested and does **not** work (`DOTNET_ROLL_FORWARD=LatestMajor`, stdin
closed → 0 bytes, killed at 60 s and 45 s, `EXIT=124`).

Two options, both requiring the Owner's word because they change the machine:
- **(a)** install the .NET 6 runtime (`winget install Microsoft.DotNet.Runtime.6`) — ~55 MB,
  supported by Microsoft but out of support since Nov 2024;
- **(b)** take a newer Il2CppDumper release built for `net8.0` — preferred, and it stays
  on official upstream (`github.com/Perfare/Il2CppDumper/releases`, MIT).

Disk: 15 GB free on `E:`, 288 GB on `D:`. A .NET runtime is not the constraint; **elevation
and the stop-line are.** This step is listed first because it is the only blocker on a
whole new domain, and it costs ~55 MB either way.

### Step 2 — Turn on the two deobfuscation passes we already ship. `(no device, no deps)`

`web-reverse/static/gen-obf.mjs:184-185`:

```js
selfDefending: false,
debugProtection: false,
```

Both corresponding transforms are present in our dependency tree
(`node_modules/webcrack/dist/deobfuscate/self-defending.d.ts`, `debug-protection.d.ts`).
Set both to `true`, add a `loop2` step asserting the sample *is* self-defending
(`/Function\.prototype\.toString/` survives deobfuscation, per our own
`static/lib/triage.mjs` `self-defending` family test), and add a negative control that
the check is *removed* rather than merely absent.

**Prove it:** `cd web-reverse/static && node tools/loop2.mjs` — currently 24 steps / exit 0;
after the change the step count grows by one and the existing 4 negative controls still fail
as designed. **Footprint: 0 bytes. This is the single highest-value upgrade that works
today with no device.**

### Step 3 — Add an APK triage/route stage. `(no device)`

New `mobile-lab/tools/triage.mjs`, modelled on `fingerprint.sh`'s *shape* but written in
Node against the ZIP listing and DEX string table `analyze.mjs` already parses. It must
answer, with a cited marker for each verdict: framework (Flutter / RN / Cordova /
Xamarin / native), HTTP stack, DI, serialization, obfuscation level, and **— the gap —
packing / shell detection** from the MobileRE vendor table (`.so` filenames, shell
Application classnames, and DEX string markers).

The output's last line must be a **route**, and for an unknown framework it must be
"decompiling Java will not help you here".

**Prove it:** `node mobile-lab/tools/triage.mjs mobile-lab/artifacts/mobilelab.apk`
reports `native Android (Java)`, no packer, and recommends the decompile path — one file
read against the APK we already build. A negative control: point it at a hand-made
APK with `libjiagu.so` in it and it must name 360 and route to the unpacking lane.

### Step 4 — Static anti-emulator / root / anti-frida signal *detection*. `(no device)`

Add to `tools/analyze.mjs` the **signal sets only** — never the neutralisation. Three new
finding kinds: `emulator-signals`, `root-signals`, `injection-signals`. Sources: the
standard emulator properties (`ro.kernel.qemu`, `ro.hardware`, `ro.product.model`),
`/proc` and filesystem indicators reachable as DEX strings, and the agent-module /
`TracerPid` names our own `02-anti-instrumentation-detector.js` already enumerates at
runtime. A finding is "this app *checks* for X" — exactly the question
`mobile-lab/README.md` says the detector exists to answer.

**Prove it:** `grep -c "'emulator-signals'\|'root-signals'" mobile-lab/tools/analyze.mjs`
goes 0 → 2, and `node mobile-lab/tools/loop.mjs` still exits 0. Refuse-to-build rule, stated
in the file header: no bypass, no concealment, no unhooking — matching
`02-anti-instrumentation-detector.js`'s existing header, which is the precedent.

### Step 5 — Kotlin name recovery. `(no device)`

Reimplement `recover-kotlin-names.sh` in Node: extract `@DebugMetadata` `c=` values and
`@Metadata.d2` descriptors from the DEX string table that `analyze.mjs` already reads
(`DEX 037, 10 classes, 74 methods, 195 strings`), emit a name mapping, and make the
existing `lookup` step annotate every hit with its owning class.

**Prove it:** one file read — the mapping is written to `mobile-lab/out/mapping.json` from
our own APK. A negative control: on a DEX with no `@Metadata` the tool emits an empty map
and says so, rather than inventing names. This is a *report* stage, so it must be able to
return "nothing recovered" cleanly.

### Step 6 — Adopt the REx 3-phase stance protocol as the station's RE orchestration. `(no device)`

New `skills/debugger-multi-agent/` with 7 agent files (~230 lines): `re-recon` (alone),
`re-bughunt` / `re-safety` / `re-arithmetic` / `re-lifecycle` / `re-logic` (parallel,
non-communicating), `re-reconcile` (alone). Copy the mechanism, not the Nix devshell.
Carry across verbatim: "Read the code before you read anyone's conclusions";
"agents sharing a decompiler are correlated"; "a finding is a source, a sink, a broken
guard, and an affected principal"; "prefer no finding to a weak finding".

**Prove it:** one file read — `skills/debugger-multi-agent/SKILL.md` exists and names all
7 agents with the non-communication clause. The test that matters is behavioural, and it
is: run one mobile-lab and one `headless-lab` target through it and check that
`re-reconcile`'s output contains a `ruled_out` section, not only findings.

### Step 7 — Content-addressed evidence + stage accounting. `(no device)`

Two small changes that make the rest auditable:
- `mobile-lab/out/` → `mobile-lab/out/<artifact>-<sha8>/` so a rebuilt APK never
  silently overwrites the previous run's evidence. Content, not name, is the key.
- `tools/pipeline_status.py` (or `.mjs`) enumerates which stages actually produced output
  and which silently did not, and `loop.mjs` copies that into its own report.

**Prove it:** run `loop.mjs` twice after changing the APK; two distinct directories exist,
and the second run's `pipeline_status` block names any skipped stage. The negative control
is that a deliberately-skipped stage appears in the output as a *missing* line, not silence.

### Step 8 — Web-reverse: Anti-Spiral Protocol and the escalation ladder. `(no device)`

Port firstrui's numeric stop discipline into `web-reverse` — two rounds with no new
evidence forces a change of action, six rounds without convergence forces escalation, and
an escalation must state what failed / what is next / which hypotheses are dropped. Port
the ladder's rung 6 too: **accepting browser-side black-box reuse is a named success
outcome**, not a failure.

**Prove it:** one file read — the thresholds appear in `web-reverse/README.md` and in the
skill text; and `node tools/loop2.mjs` still exits 0.

### Step 9 — Give the `jsvmp` family a route. `(no device for the triage half)`

Today `static/lib/triage.mjs` detects `jsvmp` and correctly says
`NOT static-deobfuscatable` — then stops. Add the *next move*: identify the dispatcher's
state variable and the opcode families from the AST we already parse, and route to
interpreter-boundary instrumentation, per `jsvmp-wasm-and-deobf.md`'s principle (recover
the minimal slice around a proven boundary) and its best idea (turn execution into AST
emission rather than attempting a full lift).

**Prove it:** `node web-reverse/static/deobf.mjs --print` on a generated `while(true)
switch` sample emits a route line naming the state variable and opcode count, and still
refuses to claim a deobfuscation. No device needed for the triage half; the tracing half
would need the CDP runtime lane, which we have.

### Step 10 — Refuse-list documentation. `(no device)`

Write `notes/` and the lab READMEs' stop-lines sections to record §7 explicitly — what we
read, what we declined, and why. This is what stops the next agent from re-deriving it, and
it is the same discipline `unpacking.md:118-127` models when it records the checksum
failure that caused a prior session to misjudge 7 DEXs as usable.

**Prove it:** one file read of `notes/<date>-mobile-js-skill-map-refusals.md`.

### What a device or emulator would change

Deliberately excluded from the ranked plan, because none of it is reachable today
(`platform-tools` absent, no `ndk`, no `emulator`, no elevation, WSL disabled, ~1.7 GB
download / ~2.9 GB installed, Windows optional feature + reboot → Owner's call):

- the 7 runtime scripts in §7.1–7.2 (refused regardless of device);
- memory DEX/SO dump (#4 in §3) — `mem-dex-dumper.c` reads `/proc/<pid>/mem` and needs a
  live process;
- live Frida session iteration (#7) — `frida-mcp` is vendored and correct; the blocker is
  that `frida-ls-devices` hangs on this box with no device;
- device traffic capture (#9) — needs `adb`;
- `Frida-Labs`-style exercises (#8 in §1.9).

**The fallback for all of them is already in place**: `mobile-lab`'s Frida emulator
(`frida/lib/frida-emulator.mjs`) runs every hook offline against a modelled runtime and the
40-case suite asserts the traces. That is why items 1-10 above are all provable without a
device, and why the plan does not need one to start.

---

## 9. Verification record

Commands run on this box today, with results as stated above:

- `node mobile-lab/tools/loop.mjs` → 25 PASS, 0 FAIL, 3 negative controls, `LOOP CLOSED`, exit 0
- `'.../Il2CppDumper.exe'` → .NET 6.0.0 required; found 8.0.31 / 10.0.11
- `DOTNET_ROLL_FORWARD=LatestMajor '.../Il2CppDumper.exe' < /dev/null` → 0 bytes, exit 124
- `grep -ciE 'packer|packing|jiagu|shell|encrypt' mobile-lab/tools/analyze.mjs` → 0
- `grep -ciE 'emulator|goldfish|qemu' mobile-lab/tools/analyze.mjs` → 0
- `grep -niE 'root|magisk|supersu' mobile-lab/tools/analyze.mjs` → 13 hits, all XML-tree
  roots, zero security signals
- `ls web-reverse/static/node_modules/webcrack/dist/deobfuscate/` → includes
  `self-defending.d.ts`, `debug-protection.d.ts`
- `grep -n 'selfDefending\|debugProtection' web-reverse/static/gen-obf.mjs` → lines 184, 185
- `grep -c 'record(' web-reverse/tools/loop2.mjs` → 16; `[^a-z]run(` → 9 (1 is the
  definition) → 24 step call sites; 4 unique `negative control` records
- `ls D:/Software/Android/Sdk` → `build-tools` only
- `df -h /e /d` → `E:` 15 GB avail, `D:` 288 GB avail

Star counts and licenses via `gh api repos/<owner>/<repo>`, 2026-09-30:

| Repo | ★ | License | Last push |
|---|---|---|---|
| SimoneAvogadro/android-reverse-engineering-skill | 7,936 | Apache-2.0 | 2026-09-08 |
| Perfare/Il2CppDumper | 9,445 | MIT | 2026-09-30 |
| kuizuo/js-deobfuscator | 1,178 | MIT | 2026-08-11 |
| CreditTone/android-reverse-engineering-skill | 522 | Apache-2.0 | 2026-05-07 |
| dnakov/frida-mcp | 434 | MIT | 2025-05-12 |
| 715494637/reverse-skill | 367 | — | — |
| tihanyin/REx-skill | 99 | MIT | 2026-09-23 |
| index-login/MobileRE-Skill | 81 | MIT | 2026-09-30 |
| firstrui/codex-reverse-skills | 43 | MIT | 2026-03-26 |
