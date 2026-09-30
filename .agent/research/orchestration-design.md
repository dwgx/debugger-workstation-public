# Mission — the orchestration layer for the debugger workstation

**Status:** design only. Nothing here is implemented. No commit, no `git add`, no install, no Docker.
**Author:** research window, 2026-09-30. **For:** the Owner.
**Station root:** `D:\Software\Tool\WorkStation\debugger` (referred to below as `debugger\`).
**Governing documents (read, binding):** `debugger\AGENTS.md`, `debugger\OWNER.md`, `<private-tree>\AGENTS.md`, `<private-tree>\wiki\CHARTER-ARSENAL.md`, `wiki/methods/pipeline.md`, `wiki/methods/l2-gate.md`, `wiki/methods/analysis-loop.md`, `wiki/methods/arsenal-inventory.md`.

---

## 0. The gap, and the name

Nine labs run standalone. `debugger\scripts\agent-cli.ps1` is a catalog of eleven CLI entry points that print JSON and nothing more — it routes *tools*, and each tool knows nothing about the others. There is no layer that takes a question and decides which of those tools to run, in what order, feeding each one's output into the next one's input.

**The layer is named `mission`.**

| Artifact | Path | One-line job |
|---|---|---|
| Registry | `debugger\manifests\capabilities.json` | every lab and tool, one machine-readable contract each |
| Gate | `debugger\scripts\gate.ps1` | the arsenal gate as a **program**; the only thing that may grant authority |
| Orchestrator | `debugger\scripts\mission.ps1` | `intake → plan → loop → artifact`, with a fixed-phase state machine |
| Verifier | `debugger\scripts\registry-verify.py` | fails when the registry is unprovable, unmeasured, or empty |
| Case dir | `E:\missions\<case-id>\` | content-addressed evidence, decision trace, and artifact |

The name is deliberately boring. The repo already says `scripts/`, `manifests/`, `notes/`, `Reports/`; `mission\` slots in without a new convention.

**The claim this document makes:** the registry is the upgrade. Nine labs stay exactly as they are. What is new is that each one acquires a *declared* contract, and a loop that can read the contract, pick, invoke, record, and stop. Without the registry there is no orchestrator; with it, the orchestrator is ~600 lines of glue over things that already work.

---

## 1. Mission intake — from a sentence to a typed plan

### 1.1 What "analyze this exe" is actually missing

A mission statement is missing three things, and the system must refuse to guess any of them:

1. **The object** — a path with a hash, or a process, or a loopback endpoint. Per `CHARTER-ARSENAL.md`: *"the object must be named by the Owner in this conversation and its provenance must be checkable."*
2. **The question** — what "analyze" resolves to. `find the flag` and `find why the APK leaks the token` and `work out this PCAP` are three different question types with three different capability sets and three different stopping rules.
3. **The containment** — isolated VM / station under the named-process rule / loopback capture. `l2-gate.md` lists this as S13, *"Containment unstated or unnameable"*, and that unnameable containment is a STOP.

Missing (1) or (3) → intake **halts and asks**. No tool runs. This is the same discipline as `l2-gate.md`: *"Nothing is attached, captured, or probed at this gate."*

### 1.2 Question types

Seven types. The type is chosen by the model, **printed in the plan, and shown to the Owner before the loop starts** — a mis-typed mission is the cheapest possible failure, so it is the one the system is most eager to surface.

| Type | The question it answers | Succeeds when | Typical capabilities |
|---|---|---|---|
| `Q1.identify` | what is this file, is it packed, what is its shape | a typed manifest with hashes, arch, packer verdict, section map | `native.triage.*`, `packer.detect`, `apk.manifest` |
| `Q2.locate` | where is the code that does X | a named function/offset/field, cited to a disassembly address | `native.decompile.*`, `js.deobfuscate`, `managed.decompile`, `mobile.decompile` |
| `Q3.behaviour` | what does it actually do at runtime | a recorded observation — crash, syscall, hook hit, packet — on the *original* bytes | `native.debug.breakpoint`, `dynamic.frida.*`, `net.capture` |
| `Q4.data` | what is in this capture / image / dump | a decoded field set with a provenance pointer per field | `net.pcap.*`, `forensics.*` |
| `Q5.vuln-shape` | where does it trust something it should not | a source/sink/guard/principal tuple (borrowed verbatim from REx-skill) | `Q2` + `Q3`, plus `bounds.discharge` |
| `Q6.crypto` | what token/signature/key handling is this | a classified scheme plus an independent verifier's verdict | `crypto.*`, `net.replay` |
| `Q7.origin` | what changed between these two builds | a diff over functions, guards, dependency pins | `native.diff` |

`Q1` is nearly always a **precondition** for any other type — the loop runs it regardless, and its output is what makes the rest of the plan concrete. That ordering is the station's existing rule (`analysis-loop.md` Invariant 2: *static before dynamic, narrow the slice before instrumenting*) and revlab's (`DEFAULT_STAGES = ["identify", "unpack", "disassemble", "decompile", "dynamic", "report"]` — identify first, always).

### 1.3 How the system picks labs

Three inputs, three rules, no model freedom at the routing level:

1. **Declared capability ids, not tool names.** The plan names `native.decompile.ghidra`, not "Ghidra". If the registry does not list a capability, it does not exist to the orchestrator. This is the rule `open-reverselab`'s router gets wrong: `.claude/workflows/ctf-attack-router.js` asks a model for JSON, then selects workers by `routeText.includes('recon')` — a substring match on prose. A worker id mentioned in the *rationale* selects a worker; a worker id the model forgot silently vanishes, and the run reports success. **The orchestrator validates the routed set against the allowlist and exits non-zero if it is empty or contains an unknown id.** "A checker that inspects zero items must fail, not pass" is a ToB rule (`AGENTS.md`) that generalises into the anti-pattern here: a router that matched nothing must not pass.
2. **Artifact shape narrows the candidate set.** `ljagiello/ctf-skills`' `solve-challenge/SKILL.md` classifies three ways — by file type, by description keyword, by service behaviour — and that triple is a good intake heuristic. The station already has the harder version: `net-reverse\lab\questions.mjs` encodes sixteen *real* analyst questions against a *self-authored* corpus, each with a `guarantee` and a `negative`. Those are the question bank a `Q4` mission draws from.
3. **Dependency edges do the rest.** The registry declares `consumes.prior` — which evidence keys a capability needs. `native.debug.breakpoint` consumes `decomp.functions`. So the plan is not a list the model writes; it is a **topological closure** of the declared edges, and the model only picks the seed. This is the difference between a script and a plan, and it is why the same plan can be re-derived from the registry by a later window instead of remembered.

### 1.4 The typed plan, on disk before any tool runs

```
E:\missions\<case-id>\plan.json
```

```json
{
  "case_id": "2026-09-30-c01-stringobf",
  "mission_class": "debug",
  "object": { "path": "D:/.../c01-stringobf.exe", "sha256": "<64 hex>", "kind": "pe64" },
  "provenance": { "class": "owner_authored", "declared_by_owner": true, "evidence": "crackme-corpus/README.md" },
  "containment": "station_under_named_process_rule",
  "question": { "type": "Q2.locate", "text": "where is the input validation" },
  "gate": { "verdict": "ALLOW_LOCAL", "issued_at": "<utc>", "grant_sha256": "<hex>" },
  "capabilities": ["native.triage.die", "native.decompile.ghidra"],
  "budget": { "wall_minutes": 45, "disk_mb": 2048, "max_rounds": 12, "max_evidence": 60 }
}
```

Two properties matter. `provenance.evidence` points at a **file**, not a sentence — this is `l2-gate.md`'s *"not a sentence in a chat log"* made structural. And `gate.grant_sha256` is the hash of the capability grant, which §4 makes unforgeable-by-the-mission.

---

## 2. The loop

### 2.1 Stated as a loop

```
        ┌──────────────────────────────────────────────────────────┐
        │                                                          │
   INTAKE ──▶ GATE ──▶ PLAN ──▶ ┌── ROUND ─────────────────┐      │
                  │      │      │ 1. hypothesize           │      │
                  │      │      │ 2. choose capability     │      │
                  │      │      │ 3. grant-check           │      │
                  │      │      │ 4. execute in isolation  │      │
                  │      │      │ 5. scrub + record        │      │
                  │      │      │ 6. score the delta       │      │
                  │      │      │ 7. decide                │      │
                  │      │      └──────┬──────────────────┘      │
                  │      │             │ next round ────────────▶│
                  │      │             │ stop ──▶ ARTIFACT        │
                  ▼      ▼             ▼                          │
                STOP  ALLOW_LOCAL    DONE / UNRESOLVED ────────────┘
```

**1. Hypothesis.** One sentence, typed, with a success criterion and a *falsifier* — the observation that would kill it. `revlab`'s pipeline has no hypothesis stage at all; `REx-skill` requires a threat model before step 1. A hypothesis with no falsifier is not admitted.

**2. Choose capability.** Highest-`expected_information_gain` among capabilities whose `consumes` are satisfied and whose `requires` are met by the *measured* host, tie-broken by the `analysis-loop.md` order (static before dynamic, narrow before wide). No free-text: an unknown capability id is a hard error.

**3. Grant-check.** Re-verify `grant_sha256` and confirm the capability id is inside the grant. **Every round, not just intake.** ToB's `AGENTS.md` is the rule being honoured: *"Do not add verification scaffolding to prompts… Put the check in `make check` or the validator, where it runs deterministically and cannot be talked out of firing."*

**4. Execute in isolation.** One capability, one subprocess, one artifact dir, bounded by `requires` (timeout, memory, and — critically — **argv as an array, never a shell string**). That last one is REx-skill's rule and it is not stylistic: *"Never build a shell command from a recovered filename, path or banner — pass arguments as an array, never through a shell."* A mission whose input is a hostile path is the case this exists for.

**5. Scrub, then record.** Two passes, in this order, in **separate trust domains** (see §4.4). Recorded as typed evidence with `id`, `capability`, `argv`, `exit`, `probes[]`, `facts[]`, `artifacts[]`, `scrub_report`, `ts`.

**6. Score the delta.** Did this round add a fact that was not already in the knowledge base? `Rikugan`'s `exploration_mode.py` `KnowledgeBase.add_finding` dedups by address and *merges* rather than appends — the right primitive, and the reason a re-run of the same capability must not count as progress. Output is a boolean: `progressed | no_progress`.

**7. Decide.** `continue` (hypothesis survives and a consumer exists for the new facts) / `pivot` (hypothesis falsified, pick another) / `escalate` (needs authority the grant does not carry — §4.3) / `stop` (§5).

### 2.2 How evidence from one capability feeds the next

This is the part that makes the labs compose instead of sit next to each other. The mechanism is the registry's `produces.facts` — **typed, addressable, consumable keys**. Worked example, mission "work out how `c01-stringobf.exe` validates its input" on the station's own crackme:

| Round | Capability | Consumes | Produces (facts) | What the *next* round can now do that it could not before |
|---|---|---|---|---|
| 1 | `native.triage.die` | `file:pe` | `format=pe64`, `arch=x86_64`, `packer=none` | decides whether a pack stage is needed at all; without it, round 2 is a guess |
| 2 | `native.strings.floss` | `file:pe` | `strings[]`, `decoded[]` (stack strings recovered) | names the comparison constants; turns "find the check" into "find the check *against these 6 values*" |
| 3 | `native.decompile.ghidra` | `file:pe`, `strings[]` | `functions[]` (each with `va`, `name`, `c_path`, `calls[]`), `xrefs[]` | gives a **VA** — the thing a breakpoint needs |
| 4 | `native.debug.breakpoint` | `functions[]`, `requires:debugger` | `observations[]` — registers and memory at `va`, on the **original binary** | turns a static guess into a runtime fact; also the first round where the label "input validation" can be confirmed or killed |
| 5 | `native.memdump.process` | `observations[]` | `regions[]`, `slices[]` | shows whether the check operates on a runtime-decoded buffer rather than a static constant |
| 6 | `net.capture.loopback` | `requires:capability` (the target opened a socket) | `flows[]` | *only reachable if round 1's import table showed a network API* — this is the composition that is impossible today, because round 1 and round 6 live in different labs with no shared vocabulary |
| 7 | `deobfuscate.strings.xref` | `functions[]`, `decoded[]`, `observations[]` | `resolved_map[]` | the final answer: which decoded constant is compared where, with each cell citing a VA |

Two rules make this more than a diagram:

- **A capability that produces nothing its declared consumers need is dead weight for this mission** and is dropped from the plan. `revlab` runs all six stages unconditionally and returns `{"ok": False, "message": "Ghidra 未安装,跳过反编译"}` — a silent skip that the report absorbs. Here, a capability that yields no consumable fact is recorded as `skipped_no_consumer` and never appears as a completed step.
- **"Every instrumented result is a hypothesis about the instrumented program."** Rounds 4–6 are hypotheses about the *running* process, and REx-skill's rule applies verbatim: each must **reproduce against the original binary** before it can be the terminal answer. The loop therefore keeps a `proves_on_original` flag per fact, and the verdict function (§5.2) will not promote a claim whose flag is false.

### 2.3 Anti-spiral, quantified

The best no-progress detector in the prior art is the least famous: `firstrui/codex-reverse-skills`'s **Anti-Spiral Protocol**, which sets numbers instead of asking for judgement.

- **Two consecutive rounds in the same phase with no new fact → the loop must switch instrument class.** A third identical round is refused by the loop, not merely discouraged.
- **Six consecutive rounds without a hypothesis change → stop and escalate** with a written reason: why the current approach failed, what the next strategy would test, which hypotheses are abandoned.

ToB's `plugins/code-improver/workflows/improve.js` supplies the second detector, and it is worth copying exactly because it is a *code* detector, not a prompt:

- `nonDecreasingOver3(h)` — blocking-finding count not decreasing over three rounds.
- `recurringBlocking()` — a blocking finding seen in three consecutive rounds.
- `refixed()` — a finding "fixed" twice, i.e. oscillating.
- plus the re-file rule, verbatim in intent: *"Re-filed without new evidence: the verdict stands. Counted, not re-litigated."*

Any of these halts the loop with an escalation record. `buildEscalation` supplies the wording the artifact must carry: *"This is structural — it needs a design decision, not another fix round. Do not weaken documented guarantees to make it converge."*

---

## 3. The capability registry

### 3.1 Why this is the real upgrade

Nine READMEs describe what a human can do. A registry describes what a **program** can be asked to do, with the same object, every time. Composition is impossible without it: the loop cannot chain `tshark` output into a Frida script if neither declares what the other produces. The registry is the vocabulary; the loop is grammar over it.

**Load-bearing test from `CHARTER-ARSENAL.md`, applied to every entry:** one command proves it, the next window can re-run it, and the result changes a decision. An entry that cannot state all three is not in the registry — it is a line in `wiki/methods/`, exactly as the charter already says for tools.

### 3.2 The schema

`debugger\manifests\capabilities.json`, `schema_version: "capabilities.v1"`.

```jsonc
{
  "id": "native.debug.breakpoint",
  "version": 1,
  "title": "x64dbg / Ghidra debugger breakpoint with memory read at a VA",
  "domains": ["D3", "D10", "D14"],
  "question_types": ["Q2.locate", "Q3.behaviour", "Q5.vuln-shape"],

  // ---- what it eats -------------------------------------------------------
  "consumes": {
    "inputs": [
      { "name": "binary", "type": "file:pe|elf|mach-o", "required": true,
        "note": "read-only copy on E:\\; never the original" },
      { "name": "target_va", "type": "uint64", "required": true,
        "from": { "capability": "native.decompile.ghidra", "field": "functions[].va" } }
    ],
    "context": ["mission.question.type", "mission.containment"],
    "prior": ["decomp.functions", "strings.decoded"]
  },

  // ---- what it makes ------------------------------------------------------
  "produces": {
    "facts": [
      { "key": "observations[]", "type": "debug.observation",
        "fields": { "va": "uint64", "regs": "map", "mem": "bytes:hex", "hit": "bool" } }
    ],
    "artifacts": [
      { "key": "trace", "type": "file:jsonl", "glob": "dynamic/trace-*.jsonl" }
    ],
    "invalidates_on": ["binary.sha256 != mission.object.sha256"]
  },

  // ---- what the host must have -------------------------------------------
  "requires": {
    "runtime": "local",            // local | vm | container | loopback
    "net": "none",                 // none | loopback
    "admin": false,
    "device": false,
    "disk_mb": 300,
    "ram_mb": 2048,
    "wall_minutes": 10,
    "tools": [{ "name": "x64dbg", "probe": "...", "expect": "..." }]
  },

  // ---- the honest part ----------------------------------------------------
  "proves": [
    "the value of `regs` at `va` on the original binary at run time",
    "whether control reaches `va` at all (`hit`)"
  ],
  "does_not_prove": [
    "anything about a *different* build of the same source",
    "the behaviour of any path not exercised by the input given",
    "absence of a bug on an unexecuted path"
  ],
  "falsifies": ["H3: the branch at va is unreachable"],

  // ---- effect and authority ----------------------------------------------
  "side_effects": ["writes <case>/dynamic/", "spawns the target process", "CPU + RAM only"],
  "gate": { "lane": "debug", "requires_verdict": "ALLOW_LOCAL",
            "escalation_class": "owner_word" },

  // ---- proof, and the measurement of proof -------------------------------
  "state": "observed",            // observed | degraded | absent | blocked
  "probe": { "command": "node tools/capability-probe.mjs native.debug.breakpoint",
             "expect": "probe: OK debugger=x64dbg version=…", "exit": 0 },
  "negative_control": {
    "id": "breakpoint-on-unreached-va",
    "command": "... va=0xdeadbeef",
    "expect_exit": 3,
    "why": "a breakpoint that is never hit must report 'not hit', not a plausible register dump"
  },
  "provenance": { "source": "debugger\\scripts\\ghidra-headless.ps1, x64dbg-automate-pyclient",
                  "record": "notes/2026-09-30-*.md" }
}
```

### 3.3 Field rationale — what each part is defending against

| Field | Defends against | Prior art it is lifted from |
|---|---|---|
| `id` as a dotted, versioned token | tool-name drift; the model inventing a capability | `agent-cli.ps1` already has a stable `tool` key — this generalises it to `capability` |
| `consumes.inputs[].from` | the plan being prose instead of a dependency graph | revlab's fixed `DEFAULT_STAGES` has no edges; this is the fix |
| `produces.facts[].key` + `type` + `fields` | "evidence" as an untyped blob nobody downstream can consume | `ReiPenFlow`'s `evidence-schema.md` evidence item (`id`/`type`/`source`/`summary`/`path_or_url`/`timestamp`/`hash`/`confidence`) and its `findings[].evidence_ids` back-reference — same idea, made mandatory |
| `produces.invalidates_on` | stale facts surviving a rebuild or a re-hash | REx-skill keys results by `<filename>-<first 8 of SHA-256>` and keeps `results/index.json` mapping hash → dir, precisely so two builds of one filename do not silently overwrite each other |
| `requires` | planning against a tool that is not on this box | REx-skill's `capabilities.sh` — *"a missing tool never fails loudly, it silently narrows the analysis"* |
| `proves` / `does_not_prove` | **the confident-complete-wrong artifact** | REx-skill: *"Every tool's output is a candidate, never a finding."* |
| `falsifies` | a loop that can only accumulate, never test | `analysis-loop.md` Invariant 3 and REx-skill's confidence ladder |
| `gate.escalation_class` | a mission widening its own authority | `pipeline.md`: the lane branch is at L2 so *"a debug ALLOW can never be misread as a bounty ALLOW"* |
| `state` + `probe` | capability claims decaying like notes do | `arsenal-inventory.md` line 23: `sandbox-ops.md` said "engine verified 2026-08-29", true when written, false three months later with no edit between |
| `negative_control` | a capability that passes on everything | `net-reverse\lab\questions.mjs` (every question carries a `negative` capture) and `managed-lab\tools\loop.mjs` line 48 (`wrong entry state (a complete, confident, wrong answer)`) |

### 3.4 What the registry forces today, concretely

Registering all nine labs means writing down, for each, what it **proves** and what it **does not prove**. Three honest entries already fall out of `arsenal-inventory.md`, and they are the ones that matter:

- `dynamic.frida.ondevice` → `state: "absent"`. Measured today: `adb` is not on `PATH` on this box. D10 is proved **logic-only**, and the registry must say so in the artifact rather than let a mission assume a device.
- `fuzz.any` → `state: "absent"`. D11 is the one genuine gap in the inventory.
- `net.capture.admin` → `requires.admin: true`. revlab probes this exactly right — `pktmon list` returning non-zero means no capture — and the registry copies that probe.

And one that corrects a premise: the brief for this window states there is no IDA Pro on this box. Measured now, `debugger\Static-Reversing\IDA` is a junction to `D:\Software\Tool\Debugger\IDA Professional 9.2` and that directory is populated. **This is exactly why `state` is measured by `probe` and never asserted in prose** — the registry answers the question, and `debugger\OWNER.md` remains the authority on whether it may be used.

### 3.5 Schema validation — the rule that keeps this honest

`scripts\registry-verify.py` fails, non-zero, when:

1. the entry list is **empty** (ToB: a checker that inspects zero items must fail);
2. any `state: "observed"` entry has no `probe`, or its probe has no recorded run under `debugger\notes\`;
3. any entry has an empty `proves` **or** an empty `does_not_prove` (a capability that claims to prove everything proves nothing);
4. any `produces.facts[].key` is consumed by another entry but has a different `type`;
5. any entry lacks a `negative_control` with a non-zero expected exit;
6. any `requires` block claims `net: "any"` or `admin: true` **without** a non-`none` `gate.escalation_class`.

Rule 6 is the machine form of the charter's stop on outbound reach (`l2-gate.md` S8) and non-loopback capture (S7).

---

## 4. Isolation and gating, inherited

This is the part that must not be wrong. The design principle, taken from ToB `AGENTS.md`, is that **the gate is a program and never a sentence**: a check the model can be talked out of firing is not a control.

### 4.1 The grant

At intake, `scripts\gate.ps1` emits a verdict and a **capability grant**:

```
ALLOW_LOCAL  →  grant = { capability ids the mission may invoke }
                 grant_sha256 = sha256(canonical_json(grant) + object.sha256)
```

The grant is written to `plan.json` and never rewritten by the loop. Every round, before a subprocess spawns, the loop re-reads `plan.json` and recomputes the hash. A mismatch halts the run.

**The invariant, stated once:**

> A mission can only *narrow* its authority. The set of capabilities it may invoke is a subset of the grant, monotonically. Only `gate.ps1` can produce a grant, and only an explicit Owner word can produce a grant.

The model has no API that adds to the set. It can choose *which* of the granted capabilities to call, and it may drop any of them. It cannot create one. This is the design's load-bearing sentence.

### 4.2 Three escalation classes

Every capability declares one, statically, in the registry. The class is what a mission would need *before* it runs.

| Class | Meaning | What it takes |
|---|---|---|
| `none` | inside the grant | nothing; the loop proceeds |
| `owner_word` | a new capability, same lane, same containment, no wider reach | a **verbatim Owner sentence in the live conversation**, recorded in the artifact, plus a fresh `gate.ps1 escalate` run that re-evaluates the gate from scratch and issues a new grant. The previous grant is retained in the trace. |
| `impossible` | anything that would change the *lane* or the *reach* | **not a runtime decision at all.** Editing `debugger\AGENTS.md` / `wiki\CHARTER-ARSENAL.md` in git, by the Owner, as a separate act. |

`impossible` exists because a runtime word is the wrong instrument for a lane change. `pipeline.md` puts the branch at L2 precisely so *"a debug ALLOW can never be misread as a bounty ALLOW"*. If the orchestrator could promote itself to the bounty lane on a chat word, that branch would be decorative. So: touching a third-party host, reaching beyond loopback, attaching to an unnamed process (`l2-gate.md` S2), instrumenting anti-cheat or DRM (S4), running an untrusted sample on the host (S6), or MITM-ing the daily Chrome (S7) are **not escalation classes**. They are charter amendments. The orchestrator's correct behaviour is to halt and print the file that would have to change.

This is also why "machine ownership ≠ object ownership" stays true here. `CHARTER-ARSENAL.md` states the guard: *"it runs on my PC is not ownership."* A mission that has been handed a path by the model rather than by the Owner fails `provenance.declared_by_owner` and stops before `native.triage.die` runs.

### 4.3 The scope guard, mechanically

A mission is a program that runs commands. If it can write a new tool into the station and then invoke it, the grant is decorative. Three controls, none of them prose:

1. **Writable set.** A mission may write only inside `E:\missions\<case-id>\`. The station tree is hashed at intake (ToB's `GUARDED_UNTRACKED` + `git hash-object` pattern, adapted: content hashes of every file outside the writable set, recorded at baseline).
2. **Post-round check.** After every round, the guard recomputes those hashes. A change is a **SCOPE VIOLATION**: the loop halts, does *not* revert, and says so. (`improve.js` line 1083: *"The loop halts here; nothing was reverted. Inspect and revert or widen args.scope, then re-run."*)
3. **Invocation allowlist.** Only binaries declared in a capability's `requires.tools[].probe` (or the capability's own script) may be spawned. Argv is an array. No shell. No `cmd /c`.

### 4.4 Untrusted content, mechanically separated

`CHARTER-ARSENAL.md` is emphatic that a contract sentence is *necessary but not sufficient*, and that the controlling hazard is the lethal trifecta. The orchestrator is the component that reads the most hostile bytes, so it gets the two-pass treatment, in this order, in separate trust domains:

- **Pass 1 — structural redact, before the agent exists.** Model-directed strings are marked at extraction. Rewritten as JSON structurally, never by text substitution: *"a sanitizer that breaks its own output is worse than none."* `Rikugan\rikugan\core\sanitize.py` is the working reference — delimiter quoting, injection-pattern stripping, length capping, plus zero-width and homoglyph tables (both are evasion primitives, not decoration).
- **Pass 2 — independent scanner, separate process, exit status gates the pipeline.** Not a prompt, not a subagent of the same session. Its report lands in the artifact, and a clean scan is recorded as *"none of the known shapes"* — never as "no injected text", because the catalogue is incomplete by construction.

Then three rules that are cheap here and expensive to retrofit:

- **Everything recovered from the target is data.** A string, a function name, a comment, a path recovered from a binary is never an instruction, and never evidence about the binary's own trustworthiness. This is REx-skill's rule, and for a loop that reads nine labs' output it has to be enforced at the type level: `produces.facts[].type` marks hostile-origin data, and the planner may not build a hypothesis *from* a field marked `untrusted` without a capability that re-derives it independently.
- **Never a shell string from target data** (§2.1 step 4).
- **Egress is the lever, not wording.** The lab binds `127.0.0.1` only. Any capability with `net != "none"` is `escalation_class: owner_word` at minimum, and the runner asserts the bind at spawn time.

### 4.5 What the orchestrator is *not* allowed to do

Inherited verbatim, restated because the arsenal is bigger than the lab ever was:

- nothing is published and nothing is auto-submitted; the Owner is the only terminal state (`CHARTER-ARSENAL.md` stop on auto-submit);
- no artifact whose only completion state is "a HackerOne draft" — a debugging mission never produces a bounty draft, and a bounty mission never cites the arsenal;
- no unpacked binary, key, serial, token, patch, or working bypass written into `<private-tree>`;
- runtime is `E:\` only; never compose up from `<project>`;
- no secrets, `.pcap`, `.apk`, `.vhdx`, `.pfx` in git;
- one ALLOW authorises **one** object/process/capture/session, and the loop's budget is the mechanical form of "one light probe": a single target hash, a single containment, and a round cap.

---

## 5. Stop conditions and honest failure

### 5.1 The stop set

| # | Stop | Trigger | Artifact says |
|---|---|---|---|
| S-A | **answered** | the question type's success criterion is met by a fact whose `proves` covers it, on the original bytes | `answered` |
| S-B | **unresolved** | budgets exhausted, or every remaining hypothesis is falsified, or a required capability is `absent` | `unresolved` + the exact missing prerequisite |
| S-C | **no-progress** | 2 rounds same phase, no new fact; or 6 rounds without a hypothesis change | `stopped: anti-spiral` + what was abandoned |
| S-D | **oscillation** | `nonDecreasingOver3` / `recurringBlocking` / `refixed` | `stopped: structural, needs a design decision` |
| S-E | **gate refusal** | gate returns STOP, or the grant hash does not match, or provenance is self-asserted | `stopped: gate` + the S-row from `l2-gate.md` |
| S-F | **owner stop** | the Owner says stop | `stopped: owner` |

**S-B is not a failure and must never be dressed as one.** It is the station's own rule — REx-skill: *"an analysis ending 'nothing conclusive' with a thin `ruled_out` is indistinguishable from one that never looked."* So S-B carries the mandatory `ruled_out` list, which is what makes the absence informative.

### 5.2 The verdict is computed, not authored

`analysis-loop.md` Invariant 3 states the sharpest version: **seal verdicts before the model sees the evidence; a verdict authored by the same mind that read the evidence is not independent.** ReiPenFlow gestures at this with `confidence: low|medium|high` per evidence item. We do better, because we can do better:

> **The model never writes the verdict.** The loop computes it.

A candidate conclusion is a claim plus a list of evidence ids. The loop accepts it only if **all** of the following hold — these are the station's own `fp-check` six gates (`plugins/fp-check/skills/fp-check/references/gate-reviews.md`), re-pointed from code review to analysis:

1. **Process** — the claim names a phase of `analysis-loop.md` that actually ran, and every step it rests on has a recorded evidence id.
2. **Reachability** — the chain from entry to the claimed site is evidenced, not assumed. (REx-skill: *"Cite addresses, not impressions… Never invent an address."*)
3. **Observation** — at least one fact whose `proves` list covers the claim, with `proves_on_original` true. An instrumented result about an instrumented program does not count.
4. **Independence** — at least two facts from **two different capabilities**, and no two from the same tool family. `proves_on_original` is about the binary; independence is about the *instrument*. REx-skill: *"An ensemble of readers shares the decompiler's blind spots."*
5. **Bounded claim** — the claim is no wider than the least-covering `does_not_prove` allows. A claim of "safe" is rejected unless it names the guards that make it safe.
6. **Uncertainty stated** — the claim carries a confidence tier, an `unknowns[]`, and a next observation that would raise it.

Fail any gate → the claim is downgraded to `unresolved` and **cannot be the terminal answer**. It goes into `notes` with the gate that failed it. This is the harness rule from `arsenal-inventory.md` mechanised: the managed lab's wrong-entry-state case produces *a complete, confident, wrong answer* and the harness catches it — here the harness is a function, and it cannot be argued with.

Confidence tiers are REx-skill's, because they are the best three we found and they are not a number:

- `speculative` — a suggestive shape; the guard is unexamined. Stays in notes.
- `likely` — source, sink, guard, principal all located; the guard found inadequate. Reportable, labelled.
- `confirmed` — the above **plus an independent observation** that reproduces on the original bytes. Reportable, labelled.

And REx-skill's asymmetry is the last word: **a `likely` claim honestly labelled that proves wrong is not a false positive; a `likely` claim reported as `confirmed` is one, even if it is right.** A lower tier is never a failure. A mislabelled tier always is.

### 5.3 The artifact

The `CHARTER-ARSENAL.md` debug artifact, produced mechanically:

| Element | Source in the loop |
|---|---|
| **Target** | `object.path` + `object.sha256` — never a bare filename |
| **Instrumentation** | the full decision trace: every round, every `argv`, every `exit`, every `probe` output, and the granted ids |
| **Observation** | the typed `facts[]` with their provenance pointers, not a narrative |
| **Conclusion** | §5.2's computed verdict, per claim, with the gate that failed each rejected one |
| **STOP note** | what was deliberately not done: un-run capabilities, the `ruled_out` list, every escalation the mission asked for and did not get, and every capability whose `state` was not `observed` |

That last row is the direct fix for a documented failure in this project. `arsenal-inventory.md` line 51 already says D10 is proved **logic-only**, and REx-skill says it best: *"A stage that did not run is an unasked question, not a clean answer — and it is the one gap that produces no error to notice."* Here the STOP note is generated from the registry, so it cannot go stale.

---

## 6. Prove it

The charter's North Star applies to the orchestrator itself: one command, on this machine, with the result recorded.

### 6.1 The acceptance run

```
powershell -File scripts\mission.ps1 run `
  --target D:\Software\Tool\WorkStation\debugger\crackme-corpus\out\c01-stringobf.exe `
  --question "where is the input validation" `
  --json
```

**Pass = all of:**

- exit 0, and `E:\missions\<case-id>\plan.json`, `trace.jsonl`, `artifact.md` exist;
- the trace names **≥ 3 distinct capabilities** from **≥ 2 different labs**, each with a recorded `probe` output and a non-zero `exit` from its real tool;
- at least one round's `consumes.inputs[].from` is satisfied by a *previous* round's `produces.facts[].key` — the chain is in the artifact, not in the narration;
- the conclusion carries `confirmed` and **names the two independent capabilities** that support it;
- the STOP note lists every capability whose `state` was not `observed`.

**Target choice is deliberate:** `c01-stringobf.exe` is Owner-authored, self-built by `crackme-corpus\tools\loop.py` from source on this station, so provenance is checkable by file, and it needs exactly the chain the design claims: strings → decompile → breakpoint → memory.

### 6.2 The negative controls — what proves it is not decorative

Four. All four must fail loudly; a pass here is a **failure of the harness**.

| # | Control | Must happen |
|---|---|---|
| **N1 gate** | run the same command against an object the Owner did not name (a Windows system DLL path) | intake halts **before any tool spawns**; exit 4; artifact says `provenance not declared by owner`. If a subprocess started, the control failed. |
| **N2 tamper** | after a successful run, edit one byte of one `facts` JSON in the case dir, re-run `registry-verify.py --case <case-id>` | exit non-zero naming the file. A verifier that passes a corrupted case is decorative. |
| **N3 empty** | `registry-verify.py` against a registry whose `probes` array is emptied | exit non-zero. ToB's rule verbatim: *a checker that inspects zero items must fail, not pass* — and the CI is currently green on repos that shipped exactly this bug for months. |
| **N4 overclaim** | run `--question "where is the input validation"` against the `managed-lab` m02 sample in its wrong-entry-state mode, the case that is documented to yield *a complete, confident, wrong answer* | the loop must return `unresolved` with the independence gate named, **not** `confirmed`. This is the single most important control: it is the station's own known failure mode, aimed straight at the new code. |

**One command proves all four:**

```
powershell -File scripts\mission.ps1 selftest
```

Exit 0 = N1–N4 all behaved. A partial pass is a failure, not a partial pass.

### 6.3 What needs a device, admin, or more disk than we have

Honest inventory, measured on this box 2026-09-30:

| Need | State | Consequence for the acceptance run |
|---|---|---|
| **A device** (Frida on-device, ART, on-device TLS interception) | `adb` **not on PATH**; no device | `dynamic.frida.ondevice` stays `state: "absent"`. The N4/acid chain must be the **logic-only** Frida suite `mobile-lab\tools\frida-selftest.mjs` (40 cases, no device) and the artifact must say so. This is exactly how D10 is recorded today. |
| **Admin** (pktmon/Npcap capture) | `requires.admin: true` on `net.capture.admin` | The acceptance run uses the loopback CDP path, not a driver-level capture. revlab's `pktmon list` probe is copied verbatim so the registry reports `degraded` rather than pretending. |
| **Disk** | `E:` **14.52 GB free**, `C:` 67.73, `D:` 287.86, `F:` 1475.19 (measured now; `arsenal-inventory.md` says 15.19 GB on the same day) | The `mission` layer itself costs **< 5 MB**. Every dynamic capability declares `requires.disk_mb`, and the loop refuses to start a round whose declared cost exceeds the remaining budget. A Ghidra project is ~300–800 MB, so roughly **15 full Ghidra rounds fit on `E:`**; beyond that the case must be compacted or moved. Tier-B containers are out of the question at 14.5 GB. |
| **Docker** | stopped, and staying stopped | the acceptance run touches no container. |
| **MSVC** | present, no gcc | the crackme corpus builds with MSVC already; the acceptance run needs no rebuild. |

### 6.4 Build order, if the Owner approves

1. `manifests\capabilities.json` with **three** entries, not nine — `native.triage.die`, `native.decompile.ghidra`, `native.debug.breakpoint`. A three-entry registry that the loop can chain is worth more than a ninety-entry one that was never exercised, and it is the only way the chain in §2.2 gets tested rather than asserted.
2. `scripts\registry-verify.py` with the six failure rules.
3. `scripts\gate.ps1` — grant, hash, three escalation classes, scope guard.
4. `scripts\mission.ps1` — intake, plan, loop, artifact, `selftest`.

---

## 7. What is newly possible, and the risk

### 7.1 Five capabilities the orchestrator unlocks that we cannot do today

1. **Cross-lab evidence chaining on one real target, with the chain in the artifact.** Today `c01-stringobf.exe` gets decompiled by Ghidra and, separately, a pcap corpus gets decoded by tshark, and nothing connects them. After: DiE → FLOSS → Ghidra VA → x64dbg breakpoint at that VA → memory dump → capture of the socket the import table said it opens → string-xref resolution, with every arrow a typed fact. **Not** "call the tools in order" — the *typed handoff* is the new thing, and the part that makes a `Q3.behaviour` or `Q5.vuln-shape` mission possible at all.
2. **Negative controls as a property of the capability, not a per-lab favour.** Today every lab hand-wrote its own controls (six in `net-reverse`, four in `forensics-lab`, five in `crackme-corpus`, one documented wrong-entry-state in `managed-lab`). In the registry a control is part of the contract, so a four-capability mission **inherits four controls for free** — and the acceptance run is judged partly on whether they held.
3. **Continuous, generated `limitations`.** `pipeline_status.py`'s job, generalised. The artifact's STOP note is emitted from `state` fields that were measured this run, so "which stage did not run" stops being a thing a later window has to remember. This is the single concrete cause of `arsenal-inventory.md` being wrong three months after it was written.
4. **One answer to "what can this host actually do today."** `capabilities.sh` and the 19-backend smoke matrix, replaced by one command that probes every registered capability and reports `observed / degraded / absent`. A mission can no longer be planned against a tool that is not here, and a plan that hits an absent capability stops at intake with the prerequisite named, instead of degrading silently mid-run.
5. **Comparable, replayable missions.** Because a mission is a typed decision trace over a content-addressed case dir, "run mission X on target Y" is re-runnable, and two traces are diffable. Today every analysis is a bespoke narrative; the estate already has the counter-example — `sandbox-ops.md` claimed a verified engine and was wrong three months later. This is the archive-vs-chronicle fix.

### 7.2 The single biggest risk

**The loop narrating work it did not do.**

Every control in this document is a *program*, and the failure mode is that one of them gets written as markdown. Then a mission reports a decompile that never ran, a breakpoint that never hit, a chain of four labs that is really one lab and three optimistic sentences — and it does so **at a far higher rate than a human analyst ever would**, because the loop's whole job is to sound confident across nine labs. That is precisely the `arsenal-inventory.md` line 53 hazard, scaled up: the managed lab produces a complete, confident, wrong answer *per sample*; an orchestrator with an unmeasured `state` field produces one *per mission*, and the cross-lab chain makes it harder to spot because every individual step is plausible.

The structural defences are the four in §6.2, and N4 is the one that matters: aim the known failure mode at the new code and require it to return `unresolved`. Second-order, and worth stating plainly: **a loop that may choose its own capabilities is one conversation away from choosing a broader one.** `grant_sha256` re-checked every round, the monotonic-narrowing invariant, and the `impossible` escalation class are the whole defence. If the grant check is ever allowed to run "only at intake" — the single most tempting simplification in this document — the layer stops being a gate and becomes a narrator with a subprocess.
