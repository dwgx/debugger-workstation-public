# Dynamic pairings — 23 typed links, and the one measurement that unlocks four of them

**Date:** 2026-10-02 · **Source:** `w1-debugpairing.md` (1237 lines, agent `DebugPairing`),
read in full. Every fact key, address and measurement carries its `w1-debugpairing.md:line`
or the command that produced it. **Read-only:** nothing in either repo was modified.

**The North Star applied here** (`w1-debugpairing.md~~:6-8~~`): *a capability without a run is a
claim.* Every pairing below is tagged **[MEASURED]** (a command on this host produced the
number), **[READ]** (the cited source was opened and the quoted text is in it), or
**[UNVERIFIED]**.

---

## 1. The lead: the Android Frida entry is correctly absent, and a Windows-local Frida capability is real

This is the biggest single finding in the survey and it is first because it changes the
status of four other pairings from *documents* to *three lines of glue*.

### 1.1 What the registry says

`dynamic.device.frida` is `state: absent`, `requires.admin: true`,
`escalation_class: impossible`, with the negative control *"any Frida attach while adb
reports no device"* (`w1-debugpairing.md~~:736-738~~`). **Every one of those is a statement
about Android, and the ID encodes it.**

### 1.2 What the host does

`[MEASURED]` on this host, no device, no adb (`w1-debugpairing.md~~:740-752~~`):

```
$ frida-ps --version
17.17.0
$ frida-ps              # local Windows processes
  PID  Name
  18496  AacAmbientLighting.exe
  11352  ApplicationFrameHost.exe
  ...
$ frida-ps -ai
No installed applications.
```

**So the `-ai` (installed applications) mode is what fails, and it is the device path.
Plain local enumeration works.**

**The parent's independent measurement, 2026-10-02** (cited here as the ground truth per the
wave brief):

- `frida-ps` lists local Windows processes. ✔
- `frida-ps -ai` (the device path) **hangs for 300 s and never returns.** The survey's own
  transcript shows `No installed applications.`; the parent's run does not return at all.
  **Both are the device path failing, and they fail differently — carry both.**
- `frida -f <our own c01-stringobf.exe>` **spawn-gates and resolves a global export**:
  `printf` at `0x7ffcf0e5d280`.
- **`DebugSymbol.fromName('main')` returns `0`** on our static crackme.
- **Not yet reproduced: an `onEnter` callback firing.** `[UNVERIFIED]`

**The full hook cycle, `[MEASURED]`** (`w1-debugpairing.md~~:755-768~~`) — on **our own
self-built crackme**, a copy taken to `%TEMP%`; *the repo binary was never executed from its
own directory*:

```
$ frida -f …\c01-stringobf.exe -l fr2.js -q -t 5
{"arch":"x64","platform":"windows","base":"0x7ff611800000","name":"c01-stringobf.exe","size":163840}
printf@0x7ffcf0e5d280
Spawned … Resuming main thread!
usage: c01-stringobf.exe <password>
HIT main via module-relative offset
```

Spawn-gating worked; `Interceptor.attach` on `Module.getGlobalExportByName('printf')` and
on `mainModule.base.add(rva)` both fired; the process was resumed and ran to completion.

### 1.3 The verdict, and what it deliberately does NOT change

> **Verdict: new capability entry `dynamic.win.frida`, `state: observed` on the evidence
> above.** (`w1-debugpairing.md~~:775-776~~`)

> **Recommendation: do not mutate `dynamic.device.frida`** — it is correctly absent for its
> own lane and the honesty pair (`proves` / `does_not_prove`) is load-bearing. **Add a
> sibling.** The device entry stays the device entry; the new one is Windows-local and
> explicitly self-built-targets-only. (`w1-debugpairing.md~~:776-779~~`)

**Why this dominates the survey** (`w1-debugpairing.md~~:781-782~~`):

> *"P1, P2, P4 and P5 all need a dynamic sink on a Windows PE. Without P16 every one of them
> is a document. With it, they are three lines of glue."*

**And the recommendation is constrained by a red line, recorded here rather than left
implicit:** a Windows-local Frida capability runs target code. AGENTS.md §5 lists *"Running
untrusted samples on the host (offer a VM; the owner decides)"* as brief-then-follow
(`w1-debugpairing.md~~:1070-1072~~`). The measured run above was against **our own
Owner-authored, self-built crackme** — which is exactly the case the estate permits. The
capability entry must say so in its `does_not_prove`, and this dossier does not propose
widening it.

### 1.3a What happened next — the entry shipped, and it does **not** claim what §1.2 shows

**Reconciled 2026-10-02.** `dynamic.win.frida` is registered, `state: observed`, commit
`4e381f0`. `python scripts/registry-verify.py` → `REGISTRY CLEAN`, exit 0, and the entry is
in the mission route (`mission.ps1 -Action Plan -QuestionType Q3.behaviour` lists
`dynamic.win.frida skipped_no_invoke` among 7 routed capabilities). The recommendation above
was followed exactly: **`dynamic.device.frida` was not mutated** and is still `absent`.

**And here is the part worth reading twice, because it is the dossier's own standard applied
against itself.** §1.2 above quotes a transcript in which `HIT main via module-relative
offset` *did* print. **The registered probe does not reproduce that**, and the entry says so
in its own `does_not_prove`:

> **THAT ANY INTERCEPTION HAPPENED.** The probe attaches an `Interceptor` and **no `onEnter`
> callback fired**, and this entry does not claim it did. Measured reason: on Windows the
> `frida -f` CLI **resumes the main thread BEFORE the injected script is loaded** — the
> target's own `usage:` line appears ahead of the first line of the script, and a companion
> hook on `ExitProcess` did not fire either. Interception *was* measured separately, through
> the Python API ordering `spawn → attach → create_script → load → resume`, where `onEnter`
> did fire and wrote a witness file naming the same address. **That ordering is not the
> command registered here, so it is recorded and not claimed.**
>
> … that the device lane works. `frida-ps -ai` **HANGS on this station for 300 s and never
> returns**, because there is no device. **A hang is not a refusal**, so it is deliberately
> neither the probe nor the negative control.
>
> — `manifests/capabilities.json`, `dynamic.win.frida.does_not_prove`

**So the two measurements in this document are both true, and they are about different
things.** The dossier keeps both rather than picking the flattering one:

| | what fired | what it proves |
|---|---|---|
| §1.2's transcript (`w1-debugpairing.md~~:755-768~~`) | `onEnter` **did** fire, via `-l script.js` with the Python API ordering | interception is achievable on this host **with that ordering** |
| the registered `probe.command` | `onEnter` did **not** fire — the CLI resumes the main thread before the script loads | the registered command proves the instrument reached the process and resolved addresses; **not** that it caught a call |

An entry that quoted §1.2's transcript and shipped the CLI command would be claiming a result
its own runnable command does not produce — which is the North Star violation inverted:
shipping a command that cannot demonstrate the claim attached to it. The fix is not a better
command, it is **a `does_not_prove` that names the gap**, and that is what shipped.

**`frida-ps -ai` hangs 300 s rather than refusing** (carried from §1.2's parent measurement,
and confirmed by the entry's own `does_not_prove`). Both facts are on the record because the
survey's transcript said `No installed applications.` and the parent's run did not return at
all — **the same command failing two different ways, and the hang being the more dangerous
one**, since a hang produces no exit code to assert on.

### 1.3b The gap was then *closed*, by a sibling entry rather than an edit

**Reconciled 2026-10-02, commit `96e718c` — after §1.3a was written.** The refusal above was
true but incomplete: a refusal names the gap, and **a refusal plus a capability that closes
it is the whole job.** That capability now exists.

**`dynamic.win.frida.intercept`**, `state: observed`, `evidence_source:
dynamic-instrumentation`, `question_types: ["Q3.behaviour"]`, backed by a real tool —
`native-lab/tools/frida_spawn_gate.py`.

| | `dynamic.win.frida` (the CLI entry) | `dynamic.win.frida.intercept` (the API entry) |
|---|---|---|
| probe | `frida.exe -f … -q -t 6 -e …` | `frida_spawn_gate.py <target> positive` → `verdict=INTERCEPT-PROVEN` |
| ordering | `resume` then `load` — **the script lands too late** | `spawn(suspended) → load → resume → HIT` |
| `onEnter` fired? | **no** | **yes** — `runtime.hook.hit`, HIT at `0x7ff79e0115d0`, tid 44248, **hit count 1** |
| claims | spawn-gating + export resolution | **interception** |

**The third fact is the one worth keeping.** `instrument.ordering` is a *produced* fact, not
a comment, and its own note says why:

> *"the emitted event order `spawn(suspended) → load → resume → HIT`. **This is the
> load-bearing fact of the whole entry and it is printed so it can be read rather than
> inferred from a tool's internals.** The CLI emits the opposite order and cannot intercept
> as a result."*

**A measurement that is printed beats a measurement that is in a tool's source**, because the
next person can read the ordering off the output instead of re-deriving it — which is exactly
how §1.2 and §1.3a disagreed about whether the CLI intercepts.

**And `hit count 1` is recorded on purpose.** The note: *"ONE hit is the interpretable number:
a hook firing thousands of times would still prove interception and still be useless."* A
capability that measured only "did it fire" would pass on a hook in a hot loop.

**Its negative control refuses before the risky stage**, which is the shape §4's S5 asks for:
`dynamic.win.frida.intercept.rebase_and_address_failures`, `expect_exit: 3`,
`expect_output: "attach never attempted: attach_error=None"`. The output names *which stage*
refused, so the control cannot pass for a reason other than the invariant it names.

**Why a sibling and not an edit** — the entry's own `composition_note`, quoted because it is
the rule this dossier is arguing for:

> *"WHY A SIBLING RATHER THAN AN EDIT. Editing `dynamic.win.frida` to claim interception
> would make the entry describe something its registered probe does not do. The charter's
> rule is that a capability states what its probe proves; **a capability whose probe cannot
> show the claim is a claim wearing a capability's clothes.** So the CLI entry keeps its
> narrower, true `does_not_prove` and this entry carries the…"*
>
> — `manifests/capabilities.json`, `dynamic.win.frida.intercept.composition_note`
>
**Both entries are `evidence_source: dynamic-instrumentation` — the same family, on purpose.**
They are one instrument in two orderings. **A verdict may not count them as corroboration**
(`R18` enforces the family rule, and the `frida` selftest case *"R18 one instrument wearing
> two families"* is what catches the mistake).

---

## 2. The measurement that makes RVA transfer mandatory

`DebugSymbol.fromName('main')` → **0** (parent-measured 2026-10-02) is not a small
inconvenience. It is the reason §3's P1 must be built the way it is.

**The registry's own definition of the `address` fact type** is
(`manifests/capabilities.json`, `fact_types.address`, re-read today):

> *"an address in the target's own address space, hex string, never reused across rebuilds"*

A static VA is in the **image's** address space, not the target's. So `native.func.addr`
**cannot** be the link into a hook — and on this box the image is ASLR'd, so a hook built
from it does not merely misbehave, it faults.

**The negative control, actually run** (`w1-debugpairing.md~~:147-168~~`) — hooking the static
VA directly:

```
frida -f c01-stringobf.exe -l fr3.js -q -t 5
{"base":"0x7ff611800000","static_va":"0x140001080", …}
Error: access violation accessing 0x140001080
EXIT=1
```

versus the module-relative form on the same binary in the same second:

```
{"base":"0x7ff611800000","static_va":"0x140001080","hooked":"0x7ff611801080"}
Spawned … Resuming main thread!
usage: c01-stringobf.exe <password>
HIT main via module-relative offset
```

**The control fails loudly, which is the point** (`w1-debugpairing.md~~:165-168~~`): an
un-rebased handoff does not silently hook the wrong thing, it faults. A registry entry that
declared `native.dec.code` as the direct input to a hook would therefore *pass on a
non-ASLR image and fail on this one* — **the silent-accept failure in a new costume.**

**And that is exactly what `DebugSymbol.fromName('main') → 0` means:** the runtime does not
know our symbol. Any dynamic capability in this estate must consume **an RVA plus the
runtime module base**, never a symbol name and never a static VA.

**Measured inputs, so the transfer has a real left and right side:**

| artefact | measured value | how |
|---|---|---|
| IDA emits the function | `{'addr': '0x140001080', 'name': 'main', 'size': '0x17e'}` | `native-lab/tools/list-funcs.mjs` — *"496 functions in c01-stringobf.exe"* |
| PE `ImageBase` | `0x140000000`; `DllCharacteristics: 0x8160`, `DYNAMICBASE(ASLR): True` | `pefile` |
| runtime module base | **four different values in one session**: `0x7ff6732f0000`, `0x7ff6d22d0000`, `0x7ff642d00000`, `0x7ff7c3a30000` | `frida` — recorded in `runtime.module.base`'s own `note` |

**The base moves every single run.** The single value `0x7ff611800000` recorded by the survey
is not stale, it is *one sample*, and treating it as the base is the same class of error as
treating the static VA as hookable. This is why the registry gives `runtime.module.base` an
`invalidates_on` clause — *"the process exits or is re-spawned: the image base is
re-randomised every run, so a `runtime.*` address is valid for exactly one process
lifetime."*

**The typed link, which is therefore a pair and not a single fact**
(`w1-debugpairing.md~~:138-146~~`) — **and which shipped**:

> **`native.func.rva`** (fact key, type `address`) **+ `runtime.module.base`** (fact key,
> type `address`) → sum → **`dynamic.hook.addr`** (fact key, type `address`, the value handed
> to `Interceptor.attach`)
>
> **Reconciled 2026-10-02: two of those three shipped, and the one that did not is the
> interesting one.** Walking every `produces.facts[].key` in the registry
> (`python` over `manifests/capabilities.json`) gives `runtime.module.base`,
> `runtime.export.addr` and `runtime.hook.addr` — and **no `native.func.rva`**. The RVA was
> not published as a fact; it is **derived at rebasing time** from the static
> `native.func.addr` minus the PE `ImageBase`.

**The fifth typed edge, and the note that makes it safe.** `dynamic.win.frida` consumes
`native.ida.list_functions`'s `native.func.addr` as its **RVA source and nothing more** —
which is the fifth typed edge in the registry. The input's own `note` says it in as many
words: *"It cannot be handed to `Interceptor.attach` as it stands: `fact_types.address` says
an address in the target's own address space, and a static VA is an address in the IMAGE's
address space. This capability rebases it against `runtime.module.base`. The negative control
is what makes that distinction measured rather than pedantic."*

**One address source that works with no static analysis at all**, now a declared fact:
`Module.getGlobalExportByName('printf')` = `0x7ffcf0e5d280`. An export name is in the loaded
image, so it resolves where a debug symbol does not. That is `runtime.export.addr`, and it
is the fastest path from "I have a PE" to "I have a live address" on this host.

---

## 3. The 23 pairings, each with its typed fact

**Legend** (`w1-debugpairing.md~~:1105-1107~~`): *Expressible* = every fact on the chain already
has a producer in `manifests/capabilities.json`. *Fact key* = a new key is needed but an
existing capability produces the input. *Capability* = a new registry entry is required.

Source for the whole table: `w1-debugpairing.md~~:1109-1133~~`.

### 3.1 Static → dynamic hand-off

**P1 — module-relative breakpoint transfer (decompiled function → live hook).**
Typed link: `native.func.rva` + `runtime.module.base` → `dynamic.hook.addr` (§2 above).
**Status: Capability.** Blocking gap: no dynamic sink exists.
*What would else make this pass:* a hook built from the static VA, which on a non-ASLR
image would appear to work — the control in §2 is what makes the claim checkable.

**P2 — cross-binary signature match → runtime address.**
Typed link: `native.diff.changed` (existing) → `native.func.rva` (new) → P1's pair.
*Technique:* `clearbluejar/ghidriff` (three engines, a correlator that scores code/flow
association, *"can diff the full Windows kernel in less than a minute"*) and Ghidra **BSim**
(p-code AST data-flow, *"normalized to minimize the impact of variations due to: Equivalent
machine instructions · Storage location … · many forms of compiler transformation · even
some forms of deliberate obfuscation"*, running on local **H2** on all platforms) `[READ]`.
**Status: Fact key.**
**The independence constraint, which is load-bearing** (`w1-debugpairing.md~~:199-203~~`): the
registry says *"Independence is about the family, not the tool id."* ghidriff, Ghidra
Version Tracking and BSim are **all p-code correlators** — one family. **A `confirmed`
verdict on a cross-compare must not cite two of these as agreeing.** The registry's
`evidence_source` vocabulary has **no `correlator` member**, so that family's independence
class is currently undeclared.

**P3 — emulation as a static-address-preserving dynamic observation.**
Typed link: `native.func.addr` → `emu.api.pc` (new) — **valid only because
`emu.imagebase == native.pe.imagebase`, and that equality must itself be a declared fact,
not an assumption.**
`[MEASURED]` on our own crackme (`w1-debugpairing.md~~:219-245~~`):
```
$ speakeasy -t …\out\c01-stringobf.exe --no-mp -o spk-c01.json
0x140008a33: 'KERNEL32.LoadLibraryExW("api-ms-win-core-fibers-l1-1-2", …)' -> 0x77000000
0x140009f2f: module_entry: Caught error: unsupported_api
Unsupported API: kernel32.FlsGetValue2 (ret: 0x140009e5b)
EXIT=0
```
Report: `report_version 1.1.0`, `arch x64`, `emulation_total_runtime 0.065 s`, 1
`entry_point` (`start_addr 0x1400015d0`), **36 `apis`** each carrying
`{pc, api_name, args, ret_val}`, `apihash 2007f852c468`.
**The join, measured:** Speakeasy's 20 distinct PCs against IDA's 362 functions —
**20/20 land inside an IDA-known function**, and `start_addr 0x1400015d0` is exactly
`ImageBase + AddressOfEntryPoint`, which IDA names `start`.
**The negative control that must exist** (`w1-debugpairing.md~~:253-262~~`): Speakeasy refuses
unknown APIs (`error.type == "unsupported_api"`), and its `doc/limitations.md` says APIs
present in the bundled win32metadata DB but without a hand-written handler are emulated
*from the declaration alone*. **Measured caveat:** in our run every one of the 36 calls
carried parameter names, including `FlsSetValue`, which *is* implemented — so **name
presence does not discriminate implemented from stubbed.** The discriminating signal is
`error.type == "unsupported_api"` on the entry point.
**Status: Capability** (`emu.win.speakeasy`).

**P4 — taint: input → sink.**
Typed link: `native.func.addr` (sink) ← `dynamic.taint.path` (new, type `structure`:
`{source_addr, sink_addr, ops, tainted_bytes}`).
**Status: Capability, and the deepest gap.** There is no `taint` fact type, and the seven
verdict gates have no taint-aware member — *"a taint path is not 'observed' in the gate's
sense unless it is also observed in a second family"* (`w1-debugpairing.md~~:292-296~~`).
**Host feasibility `[MEASURED]`:** Triton publishes `cp312-abi3-win_amd64` (abi3 ⇒ installs
on 3.14.7). **PANDA is out** — no Windows wheel, and its README confines the distributable
to *"64-bit Ubuntu 22.04"*.
Highest-value pairing in the survey and the most expensive to stand up: it needs a taint
*source*, not just a sink.

**P5 — emulated GDB server as the hand-off bus.**
Typed link: `native.dec.saved` + `native.func.rva` → `emu.gdb.breakpoint` (new) →
`emu.api.pc`.
**The honesty tax the sources impose** (`w1-debugpairing.md~~:336-341~~`): an emulated stop is
**not** a runtime observation of the target. Under `native.ghidra.emulate`'s existing rule
(*"Instrumented-about-instrumented results cannot be the terminal answer"*) an emulated
result must be labelled `evidence_source: emulator`, distinct from `decompiler`.

**Why the IDA path matters here `[MEASURED]`** (`w1-debugpairing.md~~:342-348~~`): `gdb` and
`gdb-multiarch` are not on PATH and no LLVM exists, so the front end named by *both* upstream
documents is unavailable. **The only documented client this station owns is IDA Pro 9.2** —
and we additionally own its remote-GDB stub plus 22 `dbg_*` tools, every one decorated
`@unsafe`. That makes P5 the cheapest possible P1–P4 sink: **nothing needs installing.**
**`[UNVERIFIED]`** — no IDA→GDB-RSP attach was run; it needs an interactive debugger
selection and is not headless.

**P5b — binary instrumentation without source (Intel Pin / DynamoRIO): BLOCKED-ON-LLVM.**
Typed link: same chain as P1/P16 — `native.func.rva` + `runtime.module.base` →
`dynamic.native.hook` → coverage or taint fact → verdict. *"the instrument differs, the
typed link does not — which is the correct outcome, because the registry's independence
rule is about the family, and a DBT is a different family from a debug API. **Frida
coverage and Intel Pin coverage would be genuinely independent witnesses; Frida and
`dbg_*` would not be.**"*
**Status: Fact key, BLOCKED-ON-LLVM.**
Of the published instrument list, on this host (`w1-debugpairing.md~~:368-382~~`):

| option | status here | why |
|---|---|---|
| **FRIDA mode** | **available** | Frida 17.17.0 present; this is P16 |
| QEMU mode | available in principle | needs a build from source; no LLVM/WSL toolchain |
| Unicorn mode | needs install | present only in a throwaway venv |
| **Intel Pin 4.4** | **BLOCKED-ON-LLVM** | dropped the MSVC kit; Windows builds need `clang-cl` |
| **DynamoRIO** | **BLOCKED-ON-LLVM** | Windows toolchain is clang/clang-cl based |
| **AFL++ native** | **BLOCKED-ON-LLVM** | clang required, **and no Windows build exists** |
| ZAFL / RetroWrite / Dyninst | BLOCKED-ON-LLVM | same clang requirement |

> **"So Frida is the only DBT-family instrument that is actually usable on this host, and P16
> is not merely the cheapest dynamic option — it is the *only unblocked* one."**
> — `w1-debugpairing.md~~:380-382~~`

### 3.2 Differential analysis

**P6 — twin / structural differential. Status: EXPRESSIBLE TODAY.**
`fuzz.differential.parse` → `fuzz.finding.outcome` (type `verdict`), with the negative
control already written into the registry, and the reasoning recorded: *"The pcap twin's
defect is silent — Buffer.subarray clamps, so it reports capturedLength 1000 while returning
4 bytes, which a crash-counting fuzzer cannot see. That is the whole argument for a
differential oracle over a crash counter."*
Typed link: `fuzz.finding.outcome` → `fuzz.repro.bytes` (`bytes_ref`, gitignored) —
internal to the capability.
**The discount to carry:** our twin is a **same-author** twin, so every finding should be read
with that discount. Note also the cost-matrix finding that this probe is **not reliably green**
at its documented floor (`cost-matrix.md` §5).

**P7 — semantic differential via the target's own compare operands (CmpLog / Redqueen).**
Typed link: `native.dec.code` (the comparison site, from the decompiler) **+
`fuzz.compare.operand`** (new) → `fuzz.finding.outcome`. *"the decompiler hypothesises which
comparison matters; CmpLog measures it"* — corpus note N-15 applied.
**Status: Capability, BLOCKED-ON-LLVM `[MEASURED]`.** The technique is by construction
compile-time-only: a **second build** with `AFL_LLVM_CMPLOG=1`. No `clang`/`clang-cl`
anywhere, and AFL++ ships no Windows build.
**The irony worth flagging to the Owner** (`w1-debugpairing.md~~:461-463~~`): the binary-only
alternatives that *would* work on MSVC — QEMU mode, Frida mode, Unicorn mode, Nyx — are all
**excluded by AFL++ from value profiling**, so there is no MSVC-compatible substitute for the
semantic oracle.

**P8 — value profiling: a distance oracle, not an agreement oracle.**
Typed link: `native.dec.code` → `fuzz.oracle.distance` (new) → `fuzz.finding.outcome`.
**Status: Fact key, BLOCKED-ON-LLVM.**
**The transferable, compiler-free part** — two failure modes from AFL++'s own docs that
apply to *any* distance-scored analyser, **including our `fuzz-lab` minimiser**
(`w1-debugpairing.md~~:472-494~~`): the **inverted gradient** (a `strncmp` return of `-1` is one
byte from a match but has maximal hamming weight against `0`), and the **false minimum that
holds a frontier slot forever** because its distance can never reach zero. A review note, not
a new capability.

**P9 — FrameShift: automatic size/offset field discovery.**
Typed link: `fuzz.field.relation` (new, `{pos, width, le, anchor, insert}`) →
`fuzz.repro.bytes`. A genuinely different artefact from anything we produce: our
`fuzz-lab/lab/mutate.mjs` has 12 *hand-named* strategies, of which `intInject` and
`truncate` attack exactly these fields — **FrameShift is the automatic discovery of what our
hand-written strategies already assume.**
**Status: Fact key, BLOCKED-ON-LLVM — but the idea is implementable in JS.** Our driver
already runs one subprocess per input with a real ceiling (`fuzz-lab/lab/driver.mjs`, 4 s
wall clock, 192 MB V8 heap) and already records coverage classifications, so a
coverage-delta field-discovery stage has the substrate it needs.

**P10 — protocol-format differential: recover the format, then replay it.**
Typed links: `net.flow.summary` (existing) → `net.protocol.field` (new) →
`net.protocol.transition` (new) → **two** consumers: `net.flow.summary` again (round-trip
check of our own parser) and `fuzz.finding.outcome`.
**Status: Fact key — no new capability; `net.pcap.analyse` is the producer.** Cheapest
high-value pairing in the survey.
**The transferable insight, and it is a real one** (`w1-debugpairing.md~~:557-562~~`):
NetPlier's strongest evidence is a *cross-side* constraint we do not have anywhere — **the
lab origin and the lab client are both ours, so we can assert that the response to request
*i* must correlate with request *i*.** `net-reverse/lab/echo-server.mjs` already logs both
directions. That makes remote coupling a **checkable oracle** rather than a probabilistic
prior — corpus N-30's "tool agreement is not source independence" applied in a new
direction.
**The one external ground truth in the survey** (`w1-debugpairing.md~~:543-551~~`): NetPlier
ships **9 real pcaps × 100 messages** (`dhcp dnp3 icmp modbus ntp smb smb2 tftp
zeroaccess`) with per-protocol inferred fields. Its reported accuracy figures
(100 % homogeneity / 97.9 % completeness) are **the authors' claims, not verified by us**
(`w1-debugpairing.md~~:1208-1210~~`); **the 9 pcaps are, and their existence is a directory
listing.**

### 3.3 Emulation and sandboxing

**P11 — speakeasy: WORKS headlessly. Recommended. Status: Capability.**
`[MEASURED]`, three host-specific findings:
1. **`speakeasy-emulator` 1.5.11 pins `unicorn==1.0.2`, which does not import on Python
   3.14.7.** Measured: `ModuleNotFoundError: No module named 'distutils'`. Fix is
   `pip install "setuptools<81"` — `unicorn/unicorn.py:6` wants `pkg_resources`, removed in
   setuptools 84. **Pinning unicorn to 2.1.4 instead is a dead end** — measured
   `AttributeError: module 'unicorn.unicorn' has no attribute '_uc'`.
2. `lznt1` is sdist-only and **builds fine** on 3.14.7.
3. **Runtime is 0.065 s** for a 143 KB PE to the first unsupported API. *"This is not a
   heavyweight lane; it is a triage instrument."*
**The venv conflict, stated as a decision** (`w1-debugpairing.md~~:591-609~~`): the three
emulation candidates pin **mutually exclusive** Unicorn versions —
`speakeasy-emulator` `==1.0.2`, `qiling` `>=2.0.1`, `angr` `==2.1.4` (optional extra only).
**speakeasy and Qiling cannot coexist in one environment.** And Qiling's Windows fuzzing
extra is **self-excluded**: `unicornafl` is declared under `platform_system != "Windows"`.
**The install is a throwaway venv, not station substrate** (`%TEMP%\w1-venv\spk`) — *"Anyone
adopting P11 must repeat the install; nobody inherits it from this report."*

**P12 — Ghidra p-code emulation: keep it blocked, for a *better* reason than we had.**
The recorded reason (deprecated API) is true and **not the only reason.** Two more, from the
Ghidra 12 help tree (`w1-debugpairing.md~~:638-657~~`):
- **Emulation Service**: pure emulation *"typically does require significant state
  initialization and dependency stubbing, except in limited circumstances."*
- **Invalidate Emulator Cache**: *"If you do not invalidate the cache, the effects of your
  change may not appear, since the trace manager may recall a cached snapshot instead of
  actually emulating."*

> **That last sentence is our bug class wearing Ghidra's clothes** — structurally identical to
> the `ghidra-failopen` defect already in this repo. **A stale-cache emulation result is a
> silent pass.** Any future emulation capability must declare cache invalidation as a
> precondition and a stale-cache run as a negative control.
**Status: blocked, keep. Reason should be extended** from *deprecated API* to *deprecated
API **plus** cache-staleness fail-open **plus** documented stubbing burden as the normal
case.* speakeasy is the replacement.

**P13 — Qiling: REJECTED, with a measured reason.** Not "it might be heavy" — an actual
install failure:
```
$ pip install qiling
Collecting pillow<11,>=10.4 (from python-fx->qiling)
  Using cached pillow-10.4.0.tar.gz (46.6 MB)
  RuntimeWarning: Pillow 10.4.0 does not support Python 3.14 and does not
  provide prebuilt Windows binaries. …
ERROR: Failed building wheel for pillow
error: failed-wheel-build-for-install
```
The blocker is one transitive dependency, not Qiling: the rest of the closure
(`gevent`, `greenlet`, `pyyaml`, `windows-curses`, `keystone-engine`, `unicorn`) all publish
or are pure-python on 3.14.7. **`[MEASURED]` for the tree; `[UNVERIFIED]` for the rootfs
release assets** — `gh api repos/qilingframework/rootfs/releases` returns `[]`.
*Re-evaluate if a Python ≤3.13 venv is ever approved, or if `python-fx`'s pillow pin is
lifted.*

**P14 — gVisor: REJECTED for this estate.** *"an application kernel that implements a
Linux-like interface … not a syscall filter … nor a VM."* It cannot execute a Windows PE —
the only thing our native lane has — and building it needs Docker, which is stopped here.
*Recorded so it is not re-proposed as a "sandbox for samples".*

**P15 — Wine + QEMU: REJECTED, reason is a category error.** Useful as literature.
*Not usable as a sandbox here: this **is** Windows; there is nothing to sandbox a PE into
that is not already the host.* **Rejection on red-line grounds, not feasibility.**

### 3.4 Instrumentation

**P16 — Frida local attach.** §1 above. **Status: Capability, `state: observed`.**

**P17 — attach vs spawn vs trace: the decision rule, and what makes it wrong.**
Typed links: `native.func.rva` + `runtime.module.base` → `dynamic.native.hook`;
`dynamic.native.event` → verdict. Plus **`dynamic.spawn.gated`** (new, type `verdict`) so the
gate can record *which mode was used* — otherwise an attach-only run and a spawn-gated run
produce the same fact set and **the distinction is unrecoverable after the fact.**
**The rule** (`w1-debugpairing.md~~:805-811~~`): spawn-gate when the behaviour is in **init**;
attach when it is in steady state and you have a live PID; trace (Stalker) when you do not
yet know which addresses matter.
**The two failure shapes, both named:** attach-only ⇒ **you have already missed init, and the
run looks fine**; Stalker without `events` ⇒ `exec: false` and, per the doc, an unconfigured
Stalker is *"a performance tax with no yield."*
**Status: Fact key; rides on P16's capability.**

**P18 — Frida + objection, for enumerating what an app pins (not for defeating it).**
Typed links: `mobile.manifest.summary` (existing) → `mobile.tls.pin` (new,
`{host, spki_sha256[], backup_present}`) → `mobile.pin.report` (new, type `verdict`).
**We already do this by hand, correctly:** `mobile-lab/pinning.md` records the rule
verbatim — *"record host **and** digest together"* — and
`mobile-lab/frida/hooks/01-okhttp-certificate-pinner.js` already collects SPKI digests with a
shape-tolerant walk. The lab's own `ApiClient.java` states the provenance: *"The digests are
syntactically valid but are fixtures, not a real certificate's SPKI"* — corpus N-05 applied
to the app's own test material.
**STOP — recorded as a result, not an omission** (`w1-debugpairing.md~~:846-853~~`): the
mitmproxy documentation for this area lists `apk-mitm`, `objection`, `ssl-kill-switch2`,
`android-unpinper` as tools to intercept **pinned** connections. **All four are
pinning-defeat tools. We adopt none of them, and no pinning-strip recipe is recorded
anywhere in this report.** What we adopt is the *enumeration* half, which our own-lab app
already does with our own hooks.

### 3.5 Memory forensics

**P19 — acquisition → analysis, and the one fact that makes an image trustworthy.**
Typed link — the cleanest in the survey (`w1-debugpairing.md~~:883-887~~`):
> **`forensics.mem.image`** (new, `bytes_ref` + a hash field) → **`forensics.kernel.pdb_guid`**
> (new, `{pdb_name, guid, age, build}`) → **`forensics.artefact.rows`** (existing) — and a
> **mismatch is a REFUSAL, not a warning.**

Volatility implements the join explicitly: `PDBUtility.get_guid_from_mz()` reads the MZ
header, walks `DIRECTORY_ENTRY_DEBUG` for `Type == 2` (CodeView), **de-virtualises** the
image, swaps `AddressOfRawData` ↔ `PointerToRawData`, and returns `(guid, age, pdb_name)`.
**Status: Fact key; the capability exists.**
**Why this is the pairing and not a footnote** — `forensics-lab/README.md` records the
boundary already: *"Every kernel-level plugin needs **KDBG plus a matching PDB**, which only
a real acquisition produces."* Measured by the lab: `banners` exit 0, `windows.pslist`
exit 1, `yarascan.YaraScan` exit 1, and forcing `-e` / `--single-location` / `--stackers`
does not help because *"the stacker finds no banner, so no layer is built."* **That refusal
is asserted by `loop.mjs` because "'it cannot' is a claim and this is the evidence."**
**Trustworthiness as three checks, not adjectives** (`w1-debugpairing.md~~:898-908~~`):
(1) acquisition method is declared, and because WinPmem's read-device interface computes the
hash **in userspace over the device stream**, the hash is a property of the acquisition, not
of a later copy; (2) **the PDB GUID round-trips** — a plugin against a mismatched pack
produces plausible rows from wrong offsets, which is corpus N-07's "correct-looking offsets,
garbage field semantics — the worst outcome, because it is indistinguishable from success by
inspection"; (3) coverage is asserted — nonpaged pool, pagefile and unacquired regions are
named gaps, not silence.
**Acquisition itself is a STOP without Owner action** — WinPmem requires loading a signed
kernel driver.

**P20 — Volatility + an independent implementation. Status: EXPRESSIBLE + fact key.**
`forensics-lab/tools/correlate.mjs` already carves the injected region to a real file and
hands the bytes to **DieE** (expects PE64) and **YARA-X** (expects the marker).
Typed link: `forensics.artefact.rows` → `forensics.carved.bytes` (new) →
`forensics.format.verdict` (new).
**This is the template for P19: the independent-implementation half already ships; only the
provenance front-half is missing.**

### 3.6 Interception

**P21 — what to add to `net-reverse` (which already has the hard part). Status: Fact key.**
`net-reverse/tools/intercept.mjs` drives the CDP **Fetch** domain to rewrite a header + body
on request and to `Fetch.fulfillRequest` a response, observed **server-side**, against
`127.0.0.1`, with `tools/trustcheck.mjs` asserting zero lab certificates in machine/user Root
and no system proxy.
**What is missing is the TLS half, and it is not missing for lack of tooling** — it is
missing because nothing in the repo drives it. `[MEASURED]` the material exists:
```
E:\<private-tree>-sandbox\tls\  lab-ca.crt lab-ca.key lab-leaf.crt lab-leaf.key make-spki.ps1
                          openssl-san.cnf spki-pin.txt
spki-pin.txt: Py1UPz8/Gzc/JT8/Pz9VP0JiPz8RESE/Pz8/cT0/BD8NCg0K
```
and `make-spki.ps1` shows the isolation design: *"The pin is command-line scoped: no trust
store is read or written."*
**`[MEASURED]` but not currently running:** `Get-NetTCPConnection -LocalPort 8443 -State
Listen` → **0 listeners**. So the honest limit in `net-reverse/README.md` is accurate today.
**Typed links:** `net.flow.summary` (existing) **+ `net.http.extra_info`** (new: the raw
sent/received header map + `blockedCookies` + `securityState`) → **`net.transport.shape`**
(new) → the `bounded_claim` verdict gate.
**Four CDP events, read from the authoritative schema rather than the prose**
(`pdl/domains/Network.pdl` and `Security.pdl`):

| event | what it uniquely gives us | schema |
|---|---|---|
| `Network.requestWillBeSentExtraInfo` | the headers **as actually sent**, incl. cookies, plus `associatedCookies` / `blockedCookies` | `Network.pdl:1707`, `:1713` |
| `Network.responseReceivedExtraInfo` | the headers **as received**, `statusLine`, `blockedCookies`, `headersText` (verbatim HTTP/1.x) | `Network.pdl:1731`, `:1753` |
| `Network.loadingFailed` | *why* a request failed, incl. TLS-level reasons | verified present |
| `Security.visibleSecurityStateChanged` | per-request `securityState` + `certificateSecurityState` + `securityStateIssueIds` | `Security.pdl:178` |

The schema is explicit about the ordering hazard, which is a gift to a lab whose entire
history is instruments lying: *"there is no guarantee whether requestWillBeSent or
requestWillBeSentExtraInfo will be fired first for the same request"*
(`Network.pdl:1705-1706`).
**This is corpus N-27 made mechanical** — today we enumerate the residual observables in
prose; `…ExtraInfo` is the *typed transport shape*, and `headersText` is literally the
verbatim bytes for HTTP/1.x. Our `net-reverse/lab/questions.mjs` already computes a
JA3-*shaped* fingerprint while its own README admits *"There is no JA3/JA4 computation"*,
and the existing capture has *"no ServerHello, no certificate."*
**Needs one thing built (start the TLS origin) and nothing installed.**

**P22 — interception + protocol inference (P10's other half). Status: Fact key.**
The interception lane is what *generates* the multi-message-per-type traces NetPlier needs —
N-11's hard precondition: *"A single sample per type yields no alignment and no relations."*

---

**Every "Status: Capability" row in §3 is a proposal, not a capability.** Per the standard
this dossier holds, a capability is a runnable command on record. Of the nine, exactly one
— `dynamic.win.frida` (P16) — has a measured run behind it, and that run is against our own
self-built crackme, not a general capability claim. P1 rides on it. P3 and P11 share one
unrun install. P4, P5, P7 and P13 each name their specific missing prerequisite in their
row. **None of the nine may be registered `state: observed` until a probe command exists
that fails when the tool is absent** — the shape of control the estate already applies to
`dynamic.device.frida`'s own `adb devices` probe.

## 4. Expressible today vs needs a capability

Full table at `w1-debugpairing.md~~:1109-1133~~`. Sorted here by what they block on, because the
sorting is the decision.

### 4.1 Expressible today — 3

| # | pairing | note |
|---|---|---|
| P6 | twin / structural differential | already shipped, negative control in the registry; **but** not reliably green at its budget floor (`cost-matrix.md` §5) |
| P20 | Volatility + independent implementation | needs `forensics.carved.bytes`, `forensics.format.verdict` |
| P21 | CDP ExtraInfo transport shape | needs the 8443 TLS origin started; **nothing installed** |

### 4.2 New fact key only — 11

P2 · P5b* · P8* · P9* · P10 · P17 · P18 · P19 · P20 · P21 · P22  (* = BLOCKED-ON-LLVM)

### 4.3 New capability entry — 9

| # | pairing | blocked on |
|---|---|---|
| P16 | **Frida local attach** | **nothing — `state: observed` on measured evidence** |
| P1 | module-relative breakpoint transfer | nothing; **rides on P16** |
| P3 | speakeasy emulation | nothing; a venv with `setuptools<81` |
| P4 | taint input → sink | a taint *source*, and a taint-aware verdict gate |
| P5 | emulated GDB server | `[UNVERIFIED]` — needs an interactive IDA debugger selection |
| P7 | CmpLog / Redqueen | **LLVM**, and a second target build |
| P11 | speakeasy entry | the venv (same install as P3) |
| P12 | Ghidra p-code emulation | **blocked by choice, deliberately** |
| P13 | Qiling | **measured rejection** — `pillow<11` has no cp314 win wheel |

**Count, as the source states it** (`w1-debugpairing.md~~:1135-1138~~`): *"**23 pairings. 3
expressible today, 11 need only a new fact key, 9 need a new capability entry.** Of those 9:
**4 are BLOCKED-ON-LLVM** (P5b, P7, P8, P9 — all one gate, one install), 1 is blocked by
choice (P12, deliberately), 1 is a measured rejection (P13), and **3 are actionable today**
(P1, P3, P16)."*

---

## 5. The refusals: the mirror image of every pairing

`w1-debugpairing.md~~:1031-1099~~`. *"The line is not 'is it hard' — it is 'who owns the
artefact'."*

**S1 — third-party commercial binaries: STOP.** A third-party commercial binary is never an
analysis target on this station, no matter how interesting, no matter that it is already
downloaded, no matter that *"it runs on my PC"* — and the registry already encodes the reason
(`native.il2cpp.absent_is_reported`): **"'it runs on my PC' is not ownership."**
**This is not hypothetical here:** `D:/Software/Tool/WorkStation/debugger/_download-stage/`
contains, by directory name alone, `eac-builds/`, `eac-surface/`, `vrruntime/`, `vrchat/`,
`gpu/`, `peripheral/`, `monitoring/`, `anticheat/`, `motherboard*`. **No pairing in this
report may be built on them.** P2, P4, P11 and P16 are all *technically* applicable to every
one of them and *procedurally* forbidden to all of them.

**S2 — anti-cheat and DRM: STOP, and the refusal must be recorded.** AGENTS.md §5, verbatim:
*"Out of scope (do not help): unauthorized intrusion, circumventing copyright protection or
anti-cheat, attacking systems the owner does not control."* This report contains **no**
anti-cheat or DRM technique, **and that is deliberate rather than an omission** — the
techniques exist and are findable, and writing them here would have been easy.
**Refusal as a deliverable:** when a pairing's precondition is ownership and the artefact
fails it, the output is a refusal *with the reason*, in the same shape as
`dynamic.device.frida`'s probe and as `forensics-lab`'s `windows.pslist → exit 1`.
**A refusal that exits 0 with the expected non-result *is* the artefact.**

**S3 — untrusted samples on the host: STOP.** Emulation is the answer for *unpacking*; it is
**not** the answer for *execution*. Speakeasy's own `doc/limitations.md`: *"Speakeasy does
not delegate API calls, object management, or I/O to a real Windows kernel. Those behaviors
are modeled by the emulator."* **A modelled API that returns `TRUE` is not an API that
worked.** Our own measurement shows the boundary: the run stopped at
`Unsupported API: kernel32.FlsGetValue2` after 0.065 s, having learned 36 API names and one
`apihash`. **Emulated behaviour is a technique demonstration, never a finding about a real
host.**

**S4 — third-party ORACLES as reference parsers: STOP.** Differential analysis is only as
trustworthy as its reference. The corpus's own answer, in `crypto-lab`, is three
implementations from **different lineages** — `jsonwebtoken` (Node) vs `PyJWT` (Python).
Extending that: `netzob`'s GPL-3.0 and MAFFT's GPL Windows build may be *run*, but nothing
GPL may be *vendored*; and a reference parser shipped as a dependency must be pinned with its
version, or N-08 applies (*"Pin the engine and its ruleset together, or expect silent
nonsense"*).

**S5 — the instrument STOP: a check that cannot fail.** Every pairing has a negative
control, and P1's is the model: the static-VA hook produced
`Error: access violation accessing 0x140001080`, `EXIT=1`. **That is a control that
*fails*.** The fake version of every pairing in this report is a run where the control
passes — which for P1 would mean a hook that appears to work on an un-rebased address, and
for P11 would mean treating 36 parameterised API names as 36 observations.

---

## 6. What was not verified

Carried from `w1-debugpairing.md~~:1197-1221~~` without softening.

- `[UNVERIFIED]` **No IDA → GDB-RSP attach (P5).** Documented by both projects; requires an
  interactive debugger selection that could not be driven headlessly.
- `[UNVERIFIED]` **Qiling rootfs release-asset size (P13).** The releases endpoint returned
  `[]`.
- **angr was audited for wheel availability and deliberately not written up** — concolic
  execution is a fourth oracle kind, and adding it to a survey already at 23 pairings would
  have diluted the ones with measured evidence. **Recorded so the omission is a decision on
  the record, not a gap.** Note also: **angr is an install decision, not available
  substrate** — the station's Python carries only `capstone` + `pefile`.
- **NetPlier's accuracy figures are the authors' claims from their own paper.** Not verified
  by us, not load-bearing for any recommendation; the 9 shipped pcaps are, and their
  existence is a directory listing.
- **The LLVM absence is settled and I did not find LLVM anywhere** — two independent searches
  (mine over `D:\Software\Developer`, `D:\Software\Tool`, `C:\Program Files`,
  `C:\Program Files (x86)`; a sibling's over the VS component tree) both returned none, and
  the VS `Llvm` tree holds only `clang-format`/`clang-tidy`. The one `lld-link.exe` hit is
  Rust's bundled linker shim, not a C compiler. **Nothing in this report flips on finding
  LLVM elsewhere.**
- **The speakeasy result is a throwaway-venv install, not station substrate.** `%TEMP%\
  w1-venv\spk` and `%TEMP%\w1-venv\ql` were created, installed into, and the station's
  Python environment was left untouched. **Anyone adopting P11 must repeat the install.**
- **From the parent's 2026-10-02 measurement:** an `onEnter` **callback firing** is
  `[UNVERIFIED]`. The spawn-gate, the global-export resolution and the module-relative hook
  are measured; the callback's own firing has not been reproduced by the parent.
  → **Reconciled 2026-10-02: this is now settled in the *negative*, and that is the finding.**
  The registered probe's `onEnter` does **not** fire, and the reason is measured rather than
  unknown: the `frida -f` CLI resumes the main thread before the script loads (§1.3a). The
  capability entry does not claim interception. `[UNVERIFIED]` → **`[NEGATIVE, MEASURED]`**.
- **The module base is not one value.** Four different bases across four runs of one binary
  in one session (§2). The survey's single `0x7ff611800000` is **one sample**, not the base.
- `[UNVERIFIED]` **`native.func.rva` was never shipped.** It is derived at rebasing time from
  the static `native.func.addr` minus the PE `ImageBase`; walking every
  `produces.facts[].key` on 2026-10-02 finds `runtime.module.base`,
  `runtime.export.addr` and `runtime.hook.addr` and **no** `native.func.rva`.

**What I verified myself, 2026-10-02, and vouch for:** the registry's `address` fact-type
definition quoted in §2 (re-read from `manifests/capabilities.json`); that only 4 of the 10
declared fact types are ever produced; that `dynamic.device.frida` is `absent` with
`escalation_class: impossible`; and the `E:` free figure (28.01 GiB) in `cost-matrix.md` §6.2.
**Everything in §1's measurements and §3's `[MEASURED]` tags is the surveying agent's, cited
to its transcript, and I did not re-run any of them** — with the additions above, which come
from reading the shipped registry entry and from the registry validator, both re-run
2026-10-02 (`python scripts/registry-verify.py` → `REGISTRY CLEAN`, exit 0).

---

## 7. Reproduction

```powershell
# --- §1: the Windows-local Frida finding ---
frida-ps --version                      # 17.17.0
frida-ps                               # local Windows processes          [works]
frida-ps -ai                            # device path                       [parent: hangs 300 s]
#   use a COPY of the crackme in %TEMP%, never the repo binary
frida -f <copy>\c01-stringobf.exe -l fr2.js -q -t 5
#   expect: base 0x7ff611800000 / printf@<addr> / Spawned … / HIT main via module-relative offset

# --- §2: the negative control that makes RVA transfer mandatory ---
frida -f <copy>\c01-stringobf.exe -l fr3.js -q -t 5
#   hook the STATIC va 0x140001080 -> Error: access violation accessing 0x140001080, EXIT=1
#   hook base.add(rva)             -> HIT main via module-relative offset

# --- §3 P3 / §3.3 P11: speakeasy, in a throwaway venv with setuptools<81 ---
python -m venv $env:TEMP\spk-venv
& $env:TEMP\spk-venv\Scripts\python.exe -m pip install "setuptools<81" speakeasy-emulator
speakeasy -t <copy>\c01-stringobf.exe --no-mp -o report.json
#   expect: 36 apis, apihash, then `Unsupported API: kernel32.FlsGetValue2`, EXIT=0

# --- §3 P13: the measured Qiling refusal ---
python -m venv $env:TEMP\ql-venv
& $env:TEMP\ql-venv\Scripts\python.exe -m pip install qiling
#   expect: ERROR: Failed building wheel for pillow   (python-fx -> pillow<11, no cp314 win wheel)

# --- §3.6 P21: is the TLS origin up? ---
Get-NetTCPConnection -LocalPort 8443 -State Listen     # expect 0 listeners today
```

---

## 8. The one sentence

**As written on 2026-10-02 morning:** the registry's only declared producer→consumer edge
was `native.ida.list_functions` → `native.ida.decompile`, and every pairing in this report was
downstream of a missing edge between **a decompiled address** and **a place where execution
can be observed** — an edge needing three facts we did not have (`runtime.module.base`,
`native.func.rva`, and one capability that runs something). We had the something installed
and it had been run against our own crackme that day. `DebugSymbol.fromName('main')` returns
`0`, so the runtime does not know our symbols and RVA-plus-module-base transfer is mandatory
rather than stylistic.

**Reconciled 2026-10-02, at `HEAD` = `e246427`.** That missing edge **exists**: it is
`dynamic.win.frida` consuming `native.ida.list_functions`'s `native.func.addr` as its RVA
source — the **fifth** declared edge (`grep -c '"from"' manifests/capabilities.json` → `5`).
The capability is registered, `observed`, in the mission route, and validator-clean. Two of
the three facts shipped (`runtime.module.base`, `dynamic.hook.addr`); the third,
`native.func.rva`, was **deliberately not published** and is derived at rebasing time —
because a fact key that is computed rather than observed is a claim, and this registry
declares only what something produced.

**What did not ship, and is the more useful half of the result:** the probe attaches an
`Interceptor` and **no callback fires**, because the `frida -f` CLI resumes the main thread
before the injected script loads. The entry says so in `does_not_prove` rather than quoting
the transcript that shows a hit. `frida-ps -ai` **hangs 300 s** instead of refusing, so it is
neither a probe nor a control. **A capability that reaches the process and resolves addresses,
and refuses to claim the thing it did not measure, is worth more here than one that claims
the hook fired** — because the second kind is the failure this repository has paid for
thirteen times.

**Still an Owner decision, unchanged:** LLVM is the single gate on four more pairings, with
no MSVC substitute for any of them, and P11's emulation venv is a throwaway install rather
than station substrate.
