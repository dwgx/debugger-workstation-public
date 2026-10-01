# Composition plan — the arsenal's stated core gap

**Date:** 2026-10-02 · **Source:** `w1-composition.md` (513 lines, agent `CompositionAudit`),
read in full. Every number carries its `w1-composition.md:line` or a command I ran against
`manifests/capabilities.json` today. **Read-only:** nothing in
`D:\Software\Tool\WorkStation\debugger` or `<private-tree>` was modified by the survey
that produced this.

**Why this deserves its own document rather than a section.** The estate's own diagnosis,
confirmed and made worse by measurement (`w1-composition.md:6-12`):

> *"The repo's diagnosis is **CONFIRMED and worse than stated**: the gap is not coverage, it
> is composition, and the layer that was supposed to fix it — `mission.ps1` — **does not read
> the registry's composition data at all**. It reads a hardcoded 7-line hashtable and runs
> capabilities in the literal order that hashtable happens to list them. `question_types` is
> declared on all 15 capabilities and read by **zero lines of code**."*

---

## 1. The capability graph

### 1.1 The table

Columns: `consumes.inputs[].name:type` (**bold** = has a `from` edge) →
`produces.facts[].key:type` → `question_types` → has `invoke`?
Source: `w1-composition.md:23-48`, whose line anchors I spot-verified today.

| # | id | state | consumes (name:type) | produces (key:type) | question_types | invoke | lane |
|---|---|---|---|---|---|---|---|
| 1 | `native.ida.decompile` | observed | binary:path_ref, **function:address**←LF | `native.dec.code`:string, `native.dec.refs`:structure | Q2, Q3, Q7 | ✅ `capabilities.json:124` | debug |
| 2 | `native.ida.list_functions` | observed | binary:path_ref, queries:structure[] | `native.func.addr`:address, `native.func.named`:string | Q1, Q2 | ✅ `:265` | debug |
| 3 | `web.js.cdp` | observed | url:string | `web.dom.nodes`:structure | Q1, Q3, Q4 | ❌ | **bounty** |
| 4 | `crypto.jose.parse` | observed | token:token | `crypto.jose.claims`:structure | Q4, Q6 | ❌ | debug |
| 5 | `net.pcap.analyse` | observed | capture:pcap | `net.flow.summary`:structure | Q3, Q4, Q7 | ❌ | debug |
| 6 | `forensics.memory.artefact` | observed | image:path_ref | `forensics.artefact.rows`:structure | Q1, Q4, Q7 | ❌ | debug |
| 7 | `managed.il.decompile` | observed | assembly:path_ref | `managed.method.code`:string | Q2, Q3 | ❌ | debug |
| 8 | `mobile.apk.static` | observed | apk:apk | `mobile.manifest.summary`:structure | Q1, Q2 | ❌ | debug |
| 9 | `re.corpus.solve` | observed | binary:path_ref | `re.solve.answer`:string | Q3, Q7 | ❌ | debug |
| 10 | `dynamic.device.frida` | **absent** | device:string | *(empty)* `:909` | Q3, Q4 | ❌ | debug |
| 11 | `fuzz.differential.parse` | observed | target:string | `fuzz.finding.outcome`:verdict | Q1, Q5 | ❌ | debug |
| 12 | `native.ghidra.decompile` | observed | binary:path_ref, outdir:path_ref | `native.ghidra.summary`:structure | Q1, Q2 | ✅ `:1183` | debug |
| 13 | `native.crosscompare.ghidra` | observed | source:path_ref, dest:path_ref | `native.diff.changed`:structure | Q7 | ❌ | debug |
| 14 | `native.il2cpp.symbols` | **absent** | binary:path_ref | *(empty)* `:1341` | Q1, Q7 | ❌ | debug |
| 15 | `native.ghidra.emulate` | **blocked** | binary:path_ref, function:address, arguments:structure[] | `native.emul.result`:structure | Q3, Q4 | ❌ | debug |

**Verified today, 2026-10-02, by my own commands against the tree:**

```
$ python -c "…(Get-Content manifests/capabilities.json -Raw | ConvertFrom-Json).capabilities.Count"
15
states: Counter({'observed': 12, 'absent': 2, 'blocked': 1})
declared question_types: ['Q1.identify','Q2.locate','Q3.behaviour','Q4.data','Q5.vuln-shape','Q6.crypto','Q7.origin']
fact types: ['address','string','structure','verdict']      # what capabilities actually produce
fact_types enum declares 10: address, string, structure, bytes_ref, verdict,
                           path_ref, pcap, apk, token, evidence_source
artifacts declared: 3  — native.dec.saved, fuzz.repro.bytes, native.ghidra.c
$ grep -c '"from"' manifests/capabilities.json
1
```

Two of those lines are findings in their own right and are carried below: **the enum
declares 10 fact types and only 4 are ever produced** (§4.3), and **3 artifacts are declared
with none bound by a `fact_map`** (§4.3).

**Only 3 of 15 capabilities have an `invoke`** — `native.ida.decompile`,
`native.ida.list_functions`, `native.ghidra.decompile`. Verified today; the mission loop can
call those and record `skipped_no_invoke` for the other twelve (`w1-composition.md:250-251`).

---

## 2. The declared-vs-ideal edge diff

### 2.1 Declared: exactly one, and it is the wrong one

A program walked the whole JSON tree for a `from` key (`w1-composition.md:54-57`):

```
DECLARED EDGES (consumes.inputs[].from): 1
   native.ida.list_functions  ->  native.ida.decompile   field=native.func.addr
```

`capabilities.json:43-46` is the **only** `from` block in **1493 lines**; 14 capabilities
consume inputs that name no producer (`w1-composition.md:59-60`). Re-verified today:
`grep -c '"from"' manifests/capabilities.json` → **1**.

**And that single declared edge is misaligned with the edge the loop binds**
(`w1-composition.md:64-70`):

```
DECLARED edge (consumes.inputs[].from):
   input=function type=address  from.capability=native.ida.list_functions from.field=native.func.addr
EXECUTED edge (invoke.consumes_fact):
   invoke.consumes_fact = native.func.named
ALIGNMENT: MISALIGNED -- declared field is native.func.addr but the loop binds native.func.named
```

Re-verified today: `capabilities.json:43-46` declares `"field": "native.func.addr"`;
`:137` binds `"consumes_fact": "native.func.named"`. Different facts, different types
(`address` vs `string`), on the same arrow. `mission.ps1:302` reads `invoke.consumes_fact`,
**not** `consumes.inputs[].from`, so the registry's own note at `:138` describes something
that does not happen.

**Why the chain fires anyway** (`w1-composition.md:79-94`): the loop survives on a
coincidence inside the tool. `native-lab/tools/list-funcs.mjs:56` emits both keys as
siblings, so `native.func.named[0]` happens to be a usable argument, and
`native-lab/tools/decompile.mjs:33-39` re-resolves the name to an address itself — **a
second, undeclared address-resolution step living in tool source**:

```
list-funcs.mjs  --emits-->  native.func.named[0]  --argv[2]-->  decompile.mjs
                                                                    |
                                                          re-runs list_funcs internally (:34)
                                                          resolves name->addr (:39)
                                                          decompile(addr)
```

**One of those three hops exists only in tool source and is invisible to the registry.**

### 2.2 Chainable as declared: one pair, zero triples

`w1-composition.md:98-102`: pairs = **1**; triples = **0**; of 15 capabilities **14 are
roots and 14 are leaves**. The graph is a 2-node path with 13 isolated vertices.

### 2.3 The graph that complete declarations would produce

`w1-composition.md:106-118`. Every type-compatible producer→consumer pair was enumerated
(produced fact of type *T* feeding a consumed input of type *T*), then filtered to pairs
that are semantically defensible: **31 raw type-compatible pairs, 7 survive** as real
chains.

| # | Edge | Fact | Type match | Why it is real |
|---|---|---|---|---|
| 1 | `list_functions → decompile` | `native.func.addr` | address→address | **already declared** (misaligned, §2.1) |
| 2 | `list_functions → ghidra.decompile` | `native.func.addr` | address→(selector) | Ghidra's `EmulateDecode.java`/export already accepts a function; today Ghidra re-analyses the whole binary blind |
| 3 | `list_functions → ghidra.emulate` | `native.func.addr` | address→address | `capabilities.json:1402` declares `function: address, required: true` **with no `from`**. The single most obviously missing edge in the file. |
| 4 | `ghidra.decompile → crosscompare.ghidra` | `native.ghidra.c` (artifact) | path_ref→path_ref | `:1280` literally says *"needs both programs imported into ONE project first"* — and names the producer in prose without declaring it |
| 5 | `apk.static → managed.il.decompile` | `mobile.manifest.summary.component` | structure→path_ref | a DEX extracted from the APK is the assembly; today the two labs share nothing |
| 6 | `pcap.analyse → fuzz.differential.parse` | `net.flow.summary` | structure→string | `:991` says the target is *"one of pcap \| jose \| forensic-pf \| web-triage"* — the four parsers are the four labs, declared as one opaque `string` |
| 7 | `jose.parse → fuzz.differential.parse` | `crypto.jose.claims` | structure→string | same line, `jose` leg |

**The diff, as one line: `6 missing edges, 1 declared-but-misaligned`**
(`w1-composition.md:120`).

### 2.4 The validator is blind to all of it

`w1-composition.md:126-148`. The registry was mutated in memory and the real validator run
against each mutant:

```
A  consumes_fact -> unproduced key:            1 problem   (R10 fires)
B  from.capability -> nonexistent id:          0 problems  <-- BLIND
C  silently drop a from-edge:                  0 problems  <-- BLIND
D  retype an input that has no from-edge:      0 problems  <-- BLIND
E  invent question_type Q99.made-up:           0 problems  <-- BLIND
F  DELETE the chain producer (list_functions): 1 problem   (R10 fires)
G  remove question_types from EVERY capability: 0 problems <-- BLIND
    DROP native.ghidra.decompile   (an island):    0 problems <-- BLIND
    DROP native.crosscompare.ghidra (an island): 0 problems <-- BLIND
    DROP crypto.jose.parse / net.pcap.analyse /
        fuzz.differential.parse (islands):      0 problems <-- BLIND
H  flip native.func.addr type addr->string:   1 problem    (R4 fires)
I  retype an input WITH a from-edge:           1 problem    (R4 fires)
```

Three consequences, each a control that cannot fire:

- `R4` (`registry-verify.py:130-155`) only type-checks inputs that **have** a `from`. Since
  only one input has one, **R4's cross-lab guarantee covers 1 of 42 consumed inputs**
  (`w1-composition.md:143`).
- `R10` checks `consumes_fact` existence but **never checks that `consumes_fact` and
  `consumes.inputs[].from.field` name the same fact** — which is exactly the §2.1
  misalignment.
- **No rule checks `from.capability` exists** (B), **no rule checks `question_types`** against
  any enum (E, G), and **deleting a capability that nothing consumes is silent** (the DROP
  cases).

And the registry validates clean today — `capabilities: 15`, `REGISTRY CLEAN`, exit 0
(`w1-composition.md:151-155`). Re-verified today: 15 capabilities, one `from` block.
**Clean, and blind to composition. That is the whole finding.**

---

## 3. Question-type coverage: two routing tables that disagree

The enum is closed at `mission.ps1:85-93` — **Q1.identify, Q2.locate, Q3.behaviour, Q4.data,
Q5.vuln-shape, Q6.crypto, Q7.origin** (confirmed today from the registry's declared set).
**Two routing tables exist and nothing reconciles them** (`w1-composition.md:163-167`):
`mission.ps1` hardcodes `needs` per question; the registry declares `question_types` per
capability.

I rebuilt this table today from both sources. `mission_runs` is `$QUESTION_TYPES[$qt].needs`
(read at `mission.ps1:245` in the working tree today; `:220` when the survey was taken):

| Q | mission `needs` (what RUNS) | registry declares for it | capabilities declared but **never routed** | contradiction |
|---|---|---|---|---|
| Q1.identify | `list_functions` | 7 | 6 | — |
| Q2.locate | `list_functions`, `decompile` | 5 | 3 | — |
| **Q3.behaviour** | **∅ — 0 steps** | **7** | **7** | dead question |
| **Q4.data** | **∅ — 0 steps** | **6** | **6** | dead question |
| Q5.vuln-shape | `list_functions`, `decompile` | **1** (`fuzz.differential.parse`) | 1 | **routes 2 capabilities the registry does not list** |
| **Q6.crypto** | **∅ — 0 steps** | **1** (`crypto.jose.parse`) | **1** | dead question |
| Q7.origin | `list_functions` | 6 | 6 | **routes `list_functions`, which the registry does not list for Q7** |

Source for every cell: `w1-composition.md:169-177`, rebuilt against
`manifests/capabilities.json` and `scripts/mission.ps1:105` on 2026-10-02.

### 3.1 Q3, Q4, Q6 route nothing

`w1-composition.md:187-199`. `needs = @()` ⇒ zero planned steps. Proven by running Plan:

```
$ powershell -File scripts\mission.ps1 -Action Plan -QuestionType Q6.crypto ...
  grant         50e139070a7035d9…  11 capabilities allowed
  plan          0 step(s), 0 written before any tool ran
  EXIT=0
```

**Q6 exits 0 having run nothing.** That is the failure the estate's own doctrine forbids —
`mission.ps1:28-29`: *"A stage that did not run is an unasked question, not a clean answer —
and it is the one gap that produces no error to notice."* Here there is not even a STOP note,
because the STOP note is generated from `$reg.capabilities`, not from the plan
(`w1-composition.md:199`).

**What else would also have produced this observation:** a question type legitimately with
no applicable capability. The discriminator is that 7, 6 and 1 capabilities respectively
*do* declare these types and are runnable or nearly so — `crypto.jose.parse` in particular
is `state: observed` with a working lab behind it.

### 3.2 The two hard contradictions

`w1-composition.md:179-186`. **Q5 and Q7 route capabilities the registry does not list for
them.** `mission.ps1:90` sends Q5.vuln-shape to `list_functions` + `decompile`; the registry
declares **only** `fuzz.differential.parse` for Q5 (`:980-983`). `mission.ps1:92` sends
Q7.origin to `list_functions`; the registry lists six others for Q7 and **not**
`list_functions` (`:188-191` = Q1, Q2 only). The registry says "where does it trust
something" is a *fuzzing* question; the loop answers it by decompiling function 0. And the
registry cannot object, because no rule reads `question_types`.

### 3.3 Real analyst questions, routable or not

`w1-composition.md:201-212`:

| Question | Q | Routable today? |
|---|---|---|
| "where is the input validation" | Q2 | ⚠️ **partially** — runs 2 steps, but `select.index: 0` (`:139-142`) takes the *first* non-`sub_` name, which has no relationship to the question text. **The question text is not an input to routing.** |
| "what writes this config" | Q2 | ❌ no config-writer capability exists at all |
| "how does the TLS pinning work" | Q1/Q2 | ❌ `mobile-lab/tools/analyze.mjs:687-690` measures four pinning mechanisms (`pinning-declarative`, `pinning-okhttp`, `pinning-native`, `pinning-trustmanager`) and publishes **none** — `produces` is one `mobile.manifest.summary` with fields `permission, component` (`:751-757`). **The measurement exists; the fact does not.** |
| "which function is obfuscated" | Q2 | ❌ nothing produces or consumes an obfuscation fact |
| "is this the same build as last week" | Q7 | ❌ `crosscompare.ghidra` has no `invoke`, is never routed, and per `:1280` needs a pre-imported project nothing produces |
| "what is in this pcap" | Q4 | ❌ Q4 has zero steps |

**Of the six questions, one is partially answerable and five are not.**

---

## 4. Ranked registry patches

Ranked by **composition bought per line changed** (`w1-composition.md:339-341`). Each is a
JSON fragment for `manifests/capabilities.json`. **The write path belongs to the sibling
that owns that file, and these must land as one coherent change.**

### P1 — Fix the one edge that exists *(1 line; removes a lie)*

`capabilities.json:137`. `native.func.addr` (address) is what the producer publishes;
`native.func.named` (string) is what the loop binds. Make the registry state what runs.

```json
      "consumes_fact": "native.func.named",
      "note": "The loop binds a NAME, not an address (scripts/mission.ps1:302 reads this field, not consumes.inputs[].from). list-funcs.mjs:56 emits native.func.named as a sibling of native.func.addr; decompile.mjs:33-39 resolves the name to an address in-tool. That in-tool resolution is UNDECLARED and is the real reason the chain fires. The declared from.field below names native.func.addr, which no code path reads."
```

*Companion at `:43-46` — make the declared edge name the executed key, or delete it and say
why:*

```json
          {
            "name": "function",
            "type": "string",
            "required": false,
            "from": {
              "capability": "native.ida.list_functions",
              "field": "native.func.named"
            }
          }
```

*R4 (`registry-verify.py:151`) will then agree: `string` vs `string`.*

**Highest value in the list: one line, and it deletes a false statement the registry is
currently making about itself.**

### P2 — Give `{outdir}` something to resolve to *(1 line; unblocks the whole Ghidra arm)*

`capabilities.json:1193-1194`. **Verified today:** the live argv is
`['-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/ghidra-headless.ps1','-Sample','{target}','-OutDir','{outdir}']`.
`mission.ps1` substitutes only `{target}` (`:294`) and `{input.x}` (`:295`); running the
exact substitution loop over the real argv leaves the placeholder intact
(`w1-composition.md:286-291`):

```
resolved argv: [ … "-Sample" "C:\some\target.exe" "-OutDir" "{outdir}" ]
SURVIVING UNSUBSTITUTED PLACEHOLDERS: {outdir}
```

`ghidra-headless.ps1:26-29` then creates a directory *literally named* `{outdir}` relative
to the CWD. **The Ghidra hop is one line of registry from working.**

```json
          "-Sample",
          "{target}"
        ],
```

*Prefer this form.* Deleting two argv entries is safer than inventing a placeholder the loop
does not implement, and `ghidra-headless.ps1:26` already defaults `-OutDir` to a temp dir
when empty. If `{case_dir}` is added to `mission.ps1:294` instead, use `"{case_dir}/ghidra"`
here.

### P3 — Declare the Ghidra project's producer *(3 lines; unlocks Q7)*

`capabilities.json:1229-1238`. `native.crosscompare.ghidra` states its own precondition at
`:1280` and does not declare it.

```json
        "inputs": [
          {
            "name": "source",
            "type": "path_ref",
            "required": true,
            "from": {
              "capability": "native.ghidra.decompile",
              "field": "native.ghidra.summary"
            }
          },
          {
            "name": "dest",
            "type": "path_ref",
            "required": true,
            "note": "the PREVIOUS build. Nothing in this registry can produce it: a cross-build question needs two Owner-named objects, and a second-target input is not part of mission.ps1's single -Target contract. Stated rather than faked."
          }
        ],
```

*Honest limit, and it is the point: this declares the half that is derivable and names the
half that is not, instead of implying both work.*

### P4 — Declare the emulate hop *(4 lines; the most obviously missing edge)*

`capabilities.json:1402-1404`. `function: address, required: true` with no producer, while
`native.ida.list_functions` publishes exactly that type.

```json
          {
            "name": "function",
            "type": "address",
            "required": true,
            "from": {
              "capability": "native.ida.list_functions",
              "field": "native.func.addr"
            }
          },
```

*Caveat the sibling must weigh: `state: blocked` (`:1400`). This edge is correct and still
unfirable — `mission.ps1:543` refuses a `blocked` capability's facts at the `observation`
gate. **That is the system working. Declare the edge; let the state keep it honest.***

### P5 — Un-narrow `fuzz.differential.parse`'s target *(4 lines; connects 4 labs)*

`capabilities.json:985-995`. The note at `:991` already names the four parsers; the *type*
is what hides them.

```json
        "inputs": [
          {
            "name": "target",
            "type": "string",
            "required": true,
            "note": "one of pcap | jose | forensic-pf | web-triage. All four parsers are ours.",
            "from": {
              "capability": "net.pcap.analyse",
              "field": "net.flow.summary",
              "conditional": "only for the `pcap` leg; the jose leg consumes crypto.jose.claims from crypto.jose.parse, the forensic-pf leg consumes forensics.artefact.rows from forensics.memory.artefact, the web-triage leg consumes web.dom.nodes from web.js.cdp. One input, four producers: the enum is the discriminator and it is not yet in the schema."
            }
          }
        ],
```

*Buys 4 edges for 4 lines and simultaneously states the schema gap that hides them.*

### P6 — Publish the pinning measurement that already exists *(3 lines; closes a real question)*

`capabilities.json:751-757`. The measurement is computed and thrown away (§3.3 above).

```json
        "facts": [
          {
            "key": "mobile.manifest.summary",
            "type": "structure",
            "fields": ["permission", "component"]
          },
          {
            "key": "mobile.tls.pinning",
            "type": "structure",
            "fields": ["mechanism", "kind"],
            "note": "measured today by mobile-lab/tools/analyze.mjs:687-690 (pinning-declarative | pinning-okhttp | pinning-native | pinning-trustmanager) and thrown away. kinds: declarative | okhttp-certificate-pinner | native-pin-table | custom-trust-manager."
          }
        ],
```

*The only patch here that answers a question an analyst actually asks. "How does the TLS
pinning work" becomes routable the day mission consults `question_types`.*

### P7 — Add the `invoke` that makes P3/P4/P5 reachable *(~8 lines each)*

The structural blocker: 12 of 15 capabilities are probe-only and the loop can call only the 3
with `invoke`. `R10` already checks argv shape, script existence and `success_when`.

| capability | proposed `invoke` | source of the envelope |
|---|---|---|
| `net.pcap.analyse` | `argv: ["net-reverse/tools/pcap-lab.mjs","ask","--pcap","{target}","--question","<id>","--json"]`, `stdout: json`, `success_when: "ok == true"` | the tool already emits exactly this envelope (`pcap-lab.mjs:137-141`) |
| `crypto.jose.parse` | `argv: ["crypto-lab/tools/analyze.mjs","{target}","--json"]`, `fact_map: {"result": "crypto.jose.claims"}` | `analyze.mjs:698,773` |
| `mobile.apk.static` | `argv: ["mobile-lab/tools/analyze.mjs","{target}","--json"]`, `fact_map: {"manifest":"mobile.manifest.summary","pinning":"mobile.tls.pinning"}` | `analyze.mjs:710-711` |
| `managed.il.decompile` | `argv: ["managed-lab/tools/clrlib.mjs", …]`, `stdout: json` | `clrlib.mjs:204` |
| `native.crosscompare.ghidra` | needs a wrapper first | `scripts/ghidra/DiffPrograms.java` and `FunctionHashes.java` have **never executed** (`headless-lab/README.md:134`). **Declare the `invoke` only after one green run** — otherwise P3 declares a chain into a script that does not run. |

**`[UNVERIFIED]` — carried, not dropped:** P7's proposed argv shapes are read off each
tool's CLI parser (`pcap-lab.mjs:126`, `analyze.mjs:663`, `clrlib.mjs:179`) but were **not
executed** (`w1-composition.md:509-511`). The `--json` envelopes exist; whether the fact
lands on the declared key is untested.

### P8 — Bind the three orphan artifacts *(3 lines; closes the fact/artifact hole)*

`capabilities.json:74`, `:1011`, `:1118`. **Verified today** — my own walk of
`produces.artifacts` against every `invoke.fact_map` value:

```
fact_map bound keys: ['native.dec.code','native.dec.refs','native.func.addr','native.func.named','native.ghidra.summary']
  native.dec.saved         bound_by_fact_map=False
  fuzz.repro.bytes         bound_by_fact_map=False
  native.ghidra.c          bound_by_fact_map=False
```

No `fact_map` binds any of them, so the loop can never hand a `.c` file or a crash
reproducer to a later step.

```json
          "from": {
            "capability": "native.ghidra.decompile",
            "field": "native.ghidra.c"
          }
```

*on `native.crosscompare.ghidra`'s `dest` input — the decompiled-diff hop of §4.4.*

### Ranked order and what each buys

| patch | lines | buys | inert until `mission.ps1` changes? |
|---|---|---|---|
| **P1** | 1 | removes an active falsehood | **no** — worth landing now |
| **P2** | 1 (delete 2 argv entries) | unblocks the whole Ghidra arm | **no** |
| **P6** | 3 | the only patch answering a real question | **no** |
| P3 | 3 | declares the Ghidra project producer | yes |
| P4 | 4 | the most obviously missing edge | yes |
| P5 | 4 | 4 edges at once | yes |
| P8 | 3 | binds 3 orphan artifacts | yes |
| P7 | ~8 each | makes P3/P4/P5 reachable | yes |

`w1-composition.md:491-493` is explicit that P1, P2 and P6 are still worth landing because
P1 and P2 remove active falsehoods, while P3, P4, P5, P7 and P8 are **inert** until the
selection mechanism changes.

---

## 5. The chain that matters most, hop by hop

Target: `crackme-corpus/out/c01-stringobf.exe` — Owner-authored, self-built, the same object
`mission.ps1:689` uses for its selftest. **Read the declarations; ran no analysis**
(`w1-composition.md:262`, `:504-505`).

| Hop | Declared? | Executable today? | Fact at N == fact consumed at N+1? |
|---|---|---|---|
| 1 `list_functions` | ✅ full | ✅ yes | — |
| 2 `decompile` | ⚠️ wrong key | ✅ yes | ❌ addr→string |
| 2.5 in-tool name→addr resolve | ❌ **undeclared** | ✅ (invisible) | ❌ |
| 3 `ghidra.decompile` | ❌ no edge | ❌ `{outdir}` unsubstituted | ❌ |
| 4 `crosscompare` | ❌ no edge | ❌ no `invoke` | ❌ |
| 5 diff of decompiled output | ❌ does not exist | ❌ | ❌ |

**The strongest chain the estate can actually execute today is two hops long**, and even it
lies about which fact crosses the arrow. Everything past hop 2 is blocked by **declaration
gaps, not missing tools** — the Ghidra install, the wrapper, the scripts and the project
machinery are all present (`w1-composition.md:330-333`).

**Hop 3's two blockers, named** (`w1-composition.md:284-296`): **A** — `argv` contains
`"{outdir}"` and the substitution loop leaves it verbatim (P2 fixes this). **B** — even with
the path fixed, `native.ghidra.summary` (`:1106`) is consumed by nothing and
`native.crosscompare.ghidra` (`:1217`) has no `invoke`, so the loop cannot call it at all.

---

## 6. Blockers that are not registry problems

`w1-composition.md:484-500`. Three things gate this work and **no amount of JSON fixes
them.**

1. **`mission.ps1` must be changed or nothing composes.** `:85-93` (hardcoded table),
   `:245` (selection), and the absent topological sort. Until selection reads
   `$reg.capabilities | Where-Object { $_.question_types -contains $qt }` **and** topologically
   sorts by `consumes.inputs[].from`, every patch above is a declaration that no code
   executes. *Sibling `AgentWorkflow` owns the script write path.*
2. **`{case_dir}` does not exist as a placeholder.** `mission.ps1:294` knows `{target}`;
   `:295` knows `{input.x}`. P2's alternative needs that added first.
3. **`registry-verify.py` cannot police any of this** (§2.4). It needs three new rules:
   `from.capability` must resolve (blind spot B); `consumes_fact` must equal the
   `from.field` of the input it serves (§2.1 misalignment); `question_types` must be a member
   of a closed enum (blind spots E, G).

**Consequences of the current selection mechanism, stated plainly**
(`w1-composition.md:243-253`):

1. **No topological sort exists.** Ordering is literal hashtable order — `list_functions`
   precedes `decompile` because a human typed it that way. Add a producer *after* its
   consumer and the chain silently degrades to `skipped_no_consumer` (`:322-326`), a
   *recorded skip*, which is safe-looking and wrong. The registry's `from` edges, which
   would make ordering derivable, are ignored **even for the one edge that exists**.
2. **12 of 15 capabilities can never run**, because only 3 have `invoke`. Recorded
   `skipped_no_invoke` (`:228`) — honest, and still islands.
3. **Q5/Q7 route against the registry's own declarations** (§3.2), and the registry cannot
   object.

**`grep` evidence, re-run today** (`w1-composition.md:233-239` claims `question_types` was
read by zero lines of code; the working tree has since changed under a sibling, so both
states are recorded):

```
$ grep -rn 'question_types' scripts/     # working tree, 2026-10-02
scripts/mission.ps1:740:    # question type in its registry `question_types`. …
scripts/mission.ps1:778:    if ($QuestionType -and (@($cd.question_types) -contains $QuestionType)) { $inScope += $cap }
scripts/mission.ps1:793:    "no capability that produced the evidence DECLARES question type '$QuestionType' …"
```

That is **one** reader, and it is a *scope filter on evidence already produced* — a
safety check, not a router. `$QUESTION_TYPES` is still a hardcoded 7-key table at
`scripts/mission.ps1:105` and selection still reads `$QUESTION_TYPES[$qt].needs` at `:245`,
so the routing half of the finding stands unchanged. The header claim at `mission.ps1:9` —
*"it picks capabilities whose `consumes` are satisfied"* — **remains false**: `grep
'\.consumes\b'` over `mission.ps1` returns nothing.

---

## 7. What was not verified

Carried verbatim from `w1-composition.md:502-513`, because a composition plan that hides
its bounds is a diagram.

- `[UNVERIFIED]` **No analysis was run.** Every hop in §5 was determined by reading
  declarations, `invoke.argv`, and tool source. IDA, Ghidra and every lab tool were not
  executed.
- `[UNVERIFIED]` **Whether `native.ghidra.emulate` would succeed if reached.** `:1400` says
  `blocked` and its probe summary records the ground-truth flag NOT recovered. P4 declares
  a correct edge to a capability the host cannot run; it was not tested.
- `[UNVERIFIED]` **P7's proposed argv shapes** were read from CLI parsers, not executed.
- `[UNVERIFIED]` `headless-lab/tools/loop.mjs` does not exist
  (`docs/research/binary-mcp-map.md:78`) — cited from the repo's own research doc, not
  re-derived.

**What I verified myself today, 2026-10-02, and can therefore vouch for:** 15 capabilities;
`observed=12 absent=2 blocked=1`; exactly one `"from"` block in 1493 lines; the
`:43-46` / `:137` field misalignment; the live `{outdir}` in the ghidra argv; the three
unbound artifacts; the question-type table in §3; and that `$QUESTION_TYPES` is still a
hardcoded table.

---

## 8. The one sentence

The estate has 15 capabilities, 1 declared edge, 0 triples, 14 roots and 14 leaves, three
question types that **exit 0 having run nothing**, and a registry that validates clean while
being structurally blind to all of it — and the one edge it does declare is the one the loop
does not bind, so **the strongest chain the estate can actually execute is two hops long, and
it lies about which fact crosses the arrow.**
