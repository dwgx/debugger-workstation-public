# Deep review and expansion — 2026-10-02

**One line:** Owner asked for a deep review with concurrent subagents over both the
`<private-tree>` wiki repo and this station — tool performance, tool pairings, open-ended
web/GitHub research on reusable reverse-engineering engineering, reverse skills and
reverse-agent workflows, methods and techniques to fold in, more expansion and debug
pairings, "我们要做到军火库", spend tokens freely. That is done for this round; **two
workers are still in flight** (see §2). The headline outcome is not new tooling: it is
that the arsenal's own verification layer was not verifying itself.

---

## 1. 契约 (the contract — unchanged, do not re-litigate)

- **North Star:** every capability this project claims is proved by one runnable command.
  A capability without a run is a claim, not a capability.
- **The caller proposes the claim; the loop disposes of it.** The model never writes the
  verdict.
- **Two lanes, one gate each.** `gate.ps1` mints authority for the debugging lane only,
  and only for an object the Owner named with checkable provenance. A debugging ALLOW is
  never a bounty ALLOW.
- **Red lines unchanged:** never `certutil -addstore`, never a one-click CA install,
  never the Windows system proxy; no `docker compose up` from `<project>`; no scanning
  github.com or HackerOne; no exploit PoCs, samples, captures, keys or unpacked
  binaries in either repo; no third-party anti-bot or DRM circumvention; a third-party
  binary is never an analysis target; running an untrusted sample on the host instead of
  an isolated VM is a STOP.
- **Third-party code adopted this round: zero.** Everything landed is either a fix to our
  own code or a recorded rejection with a reason.

---

## 2. 当前状态 (current state — measured, not remembered)

Every figure below was produced by running the command beside it on 2026-10-02 from the
repo root. **Re-run them; do not trust this table if the tree has moved.**

| Suite / fact | Command | Result |
|---|---|---|
| Registry validate | `python scripts/registry-verify.py` | `capabilities: 16`, `REGISTRY CLEAN`, exit 0 |
| Registry selftest | `python scripts/registry-verify.py --selftest` | `SELFTEST OK: 46 cases each fire on a registry built to break them.` — **a case count**; 19 rule functions |
| Gate selftest | `powershell -File scripts\gate.ps1 -Action Selftest` | `GATE SELFTEST OK: 24 refusals and grants all behaved.` |
| Mission selftest | `powershell -File scripts\mission.ps1 -Action Selftest` | `MISSION SELFTEST OK: 51 controls behaved.` |
| Verdict ablation | `powershell -File scripts\mission.ps1 -Action Ablate` | `ABLATE: 7 load-bearing, 0 unproved` and `ROUTING ABLATE: 6 load-bearing, 0 unproved` |
| Full-station smoke | `powershell -File scripts\smoke-all.ps1` | `SMOKE SUMMARY pass=19 fail=0`, ~270 s — **not re-run after today's changes** |
| Acceptance mission | `mission.ps1 -Action Run … -QuestionType Q2.locate …` | `unresolved`, `failed_gates=[independence]` — correct, see §3 |
| Typed edges | count `from` keys in `manifests/capabilities.json` | **5** |
| `E:` free | `Get-Volume -DriveLetter E` | 28.01 GiB free of 33.67 GiB |

**Two workers in flight when this file was written. Do not write to their paths until
their results land, and do not re-dispatch them:**

| Board id | Worker | Owns | Deliverable |
|---|---|---|---|
| `W10-RECONCILE` | `Reconcile` | `docs/research/` | reconciles the 2026-10-02 dossier against the final tree |
| `W10-WIKIRECONCILE` | `WikiReconcile` | `wiki/methods/arsenal-upgrade-plan.md`, `wiki/CHARTER-ARSENAL.md`, `wiki/INDEX.md` (sibling repo) | reconciles the wiki against the final tree |

`W8-SELECTION` was **interrupted before writing its report** but its change landed and was
verified by the parent (registry CLEAN at 16, 46 cases, gate 24, mission 51, both
ablations clean). Its report file `%USERPROFILE%/AppData/Local/Temp/w8-routing.md` does
not exist — that is expected, not a lost artifact.

Commits this session, station repo: `f1d23de`, `5ec8878`, `4e381f0`.

---

## 3. 已定决策 (decisions, with the reason)

1. **Ablation becomes the project's own audit method** — remove a mechanism, require the
   existing suite to turn red. A suite that stays green proves a component *untested*, not
   correct. Reason: it is the only instrument that found the defects below. Six of seven
   verdict gates and one of eleven validator rules were untested until it was applied.
2. **The gate's grant identity is sealed with DPAPI** at `CurrentUser`, not with a key
   file. Reason: no key material goes in the repo, and an unkeyed hash is not a signature.
   The weakness is stated in the file header: any code running as the Owner can call
   `CryptProtectData`. What it buys is that a *text edit* to the grant can no longer
   reproduce a valid identity.
3. **`gate/grant@2`; every `@1` grant on disk is refused by design**, and any registry edit
   invalidates existing grants because `registry_sha256` is in the sealed identity.
   Reason: a grant the gate cannot re-establish is exactly what the refusal exit exists for.
   Defaulting containment would be guessing.
4. **A finished dispatch releases its scope.** Reason: measured on the real ledger, 145
   closed ids still held a write scope, so paths became permanently un-dispatchable. That
   inverts the tool's purpose. See §4 for the bug I introduced here.
5. **`independence`'s family axis is a property of the instrument, not of a per-capability
   `evidence_source` label.** Reason: IDA Pro carried two labels (`decompiler`,
   `static-analysis`) from one tool, so relabelling a capability manufactured a second
   family of evidence. `families <= instruments` now holds by construction.
6. **`bounded_claim`'s bound is derived from the registry's declared `question_types`**, not
   from a keyword in the claim. Reason: a five-token regex meant `"100% safe"` passed, and
   a token test measures the caller's phrasing rather than the claim's scope. Absence and
   universal claims are still refused outright.
7. **The acceptance mission stays `unresolved`.** Reason: its chain is
   `native.ida.list_functions → native.ida.decompile`, one instrument held twice. No pair
   of decompilers on this toolset can corroborate — a design review confirmed Ghidra is the
   same family and that its only fact is a count, which its own `does_not_prove` says "is
   not a fidelity claim". **Do not weaken `independence` to make it confirm.**
8. **Three cross-lab links were deliberately NOT declared as typed edges.** Reason: they are
   module imports returning untyped values. Declaring them would assert a handoff that does
   not exist — the exact "diagram, not a contract" failure `R11` exists to prevent. The
   edge count is 5, and the shortfall is recorded rather than faked.
9. **`dynamic.win.frida` was added as a *sibling*, and `dynamic.device.frida` was not
   touched.** Reason: the device entry's absence is a statement about *Android* and is
   correct; mutating it would destroy a load-bearing honesty pair. The new entry declares
   `reach.containment = station_under_named_process_rule` because it really does
   instrument a process on this host.
10. **A refusal is a result.** Recorded rejections this round: `disrobe` (source-available
    licence with a signed-licence requirement, no public forks, 24-month non-compete),
    `MeroZemory/ida-multi-mcp` (reproduces the `ida-pro-mcp` failure and is worse, and has
    no licence), `0xeb/lldb-agent` (one tool running arbitrary LLDB, unauthenticated,
    `0.0.0.0` one flag away), Triton (no Windows wheels), Hopper and rev.ng (wrong
    platform), Qiling, gVisor, AFL++, honggfuzz, atheris, panda.

---

## 4. 走过的死路 (dead ends — do not re-walk)

- **I overwrote `~/.omp/extra-hands/CACHE/board.py` with 72 bytes of JSON.** It was a
  mis-typed `write` path while trying to extend a board scope. The `.pyc` in `__pycache__`
  was an *older* build (no `--read-only`), so it could not serve as the source. Blindly
  replaying 36 recorded edits from the session transcript onto a truncated snapshot produced
  duplicated blocks and would not parse. What worked: rewrite from the tool's own
  documented contract, then prove it with tests. Now `board.tests.py` (34 gates) and
  `board.tests_concurrent.py` (24 concurrent mints) both run from
  `%USERPROFILE%/.omp/extra-hands/CACHE/`. **Two real concurrency bugs were found while
  testing and fixed:** `os.O_APPEND` is not an atomic append on Windows (the CRT seeks at
  open time, so 4–6 of 24 rows were silently lost per round while every process printed
  `board: OPEN`), and `write_text` truncates. Both are now behind a lock file.
- **A reconstruction bug I introduced and caught:** my restored `cmd_open` never released a
  CLOSEd job's scope, so 145 finished dispatches still held their paths and `scripts/`
  became un-claimable. Found because the board refused my own next scope. Fixed, with a
  control ("a CLOSEd dispatch releases its scope").
- **I asserted a premise into a brief that was false.** I told a worker that
  `skill-adoption-checklist.md` did not exist. It existed — 9,325 bytes, committed. The
  worker searched the station repo, not `<private-tree>`, and correctly refused to
  accept my claim, then rewrote the file to be *executable* (30,430 bytes, ten blocks, ten
  pasteable PowerShell checks). **Lesson: propagating an unverified claim into a brief is
  the same failure as writing it into a document.**
- **`-Action Plan` needs the full intake.** It refuses without `-Target`, and then without
  `-Containment`. A plan invocation that omits them exits 2 at intake, which reads as a
  routing failure and is not one.
- **`frida-ps -ai` HANGS for 300 s** on this device-less box. It does not fail. A probe that
  hangs instead of refusing is worse than one that errors — same lesson as `fuzz-lab`'s
  budget floor.
- **Refuted, do not repeat:** the handoff claimed *"the full aggregate contends on three
  Ghidra-consuming probes and is killed by timeout"*. Measured, it is **not reproduced** —
  running them concurrently took 103.47 s against 161.93 s serial, all passing. The real
  hazard is fixed loopback ports: two `crypto-lab` runs both bind 8791 and one dies
  `EADDRINUSE`; two `native-lab` runs both bind 8745 and the loser exits 1.
- **Third category of control failure, now named in the charter:** not a check that always
  passes, and not a control that passes for the wrong reason, but **a correct control
  quoted as if it were an end-to-end result**. A selftest fixture with a synthetic
  substrate produced a `confirmed` reading that was then reported as "the acceptance
  mission reproduces"; the real mission ran IDA twice and refused. Neither instrument
  covers that gap.
- **An AST audit finds unused locals, not duplicated blocks.** A worker's own
  `bounded_claim` rewrite left a duplicated 34-line block that parsed cleanly and would
  have executed, appending a second gate entry reporting a stale value. It self-disclosed.
  `-Action Ablate` would have caught it, but only after shipping a wrong verdict.

---

## 5. 唯一待解问题 (the single open question)

**How does this arsenal obtain a genuine second opinion?**

The `independence` gate is now honest, and being honest has exposed the real gap: the
only end-to-end mission chain is IDA Pro alone, so it cannot corroborate itself. Ghidra is
the same family. Candidates that are not decompilers and are measurable on this box:

- **`dynamic.win.frida`** is registered but does not yet claim interception — the `frida`
  CLI resumes the main thread before the injected script loads. Interception *was* measured
  through the Python API's spawn→attach→load→resume order, which is not the registered
  probe. **Closing this honestly is the cheapest route to a second instrument.**
- A byte-level or structural comparison capability (`native.crosscompare.ghidra` declares
  `binary-similarity` and is a *different* family, so a chain through it would satisfy the
  gate — but it has no `invoke` block and its own `consumes` says it needs both programs in
  one Ghidra project first, which is not expressible).
- LLVM is **absent** from this box (MSVC `cl` 14.44 only), and its 374 MB install is the
  single gate on four toolchain rows including libFuzzer and Intel PIN.

Do not answer this by weakening a gate. The refusal is correct until a second instrument
exists.

---

## 附: research corpus (this round's inputs, all under `%TEMP%`)

`w1-agentworkflow.md` (22 reliability patterns, primary-sourced) · `w1-composition.md`
(capability graph) · `w1-gateredteam.md` (red team, 688 lines) · `w1-mcprev.md` (25 MCP
servers) · `w1-retoolchain.md` (40 tools, cost-ranked) · `w1-revskills.md` (33 repos) ·
`w1-debugpairing.md` (23 pairings, 1237 lines) · `w1-toolperf.md` (15-probe cost matrix) ·
`w2-checklist.md` · `w2-missiongates.md` · `w3-gatefix.md` · `w4-verdictlogic.md` ·
`w5-dossier.md` · `w5-wikiplan.md` · `w7-familyaxis.md` · `w9-winfrida.md`

**Durable copies live in `docs/research/`** — five new files (`review-2026-10-02.md`,
`cost-matrix.md`, `composition-plan.md`, `ecosystem-2026-10-02.md`,
`dynamic-pairings.md`) plus an updated `README.md`. The `%TEMP%` copies do not survive.