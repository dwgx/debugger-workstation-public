# Deep review and expansion — 2026-10-02

**One line:** Owner asked for a deep review with concurrent subagents over both the
`<private-tree>` wiki repo and this station — tool performance, tool pairings, open-ended
web/GitHub research on reusable reverse-engineering engineering, reverse skills and
reverse-agent workflows, methods and techniques to fold in, more expansion and debug
pairings, "我们要做到军火库", spend tokens freely, keep the goal running. That is
ongoing. The headline outcome is not new tooling: **the arsenal's own verification layer
was not verifying itself**, and fixing that exposed the real gap.

---

## 1. 契约 (the contract — unchanged, do not re-litigate)

- **North Star:** every capability this project claims is proved by one runnable command.
  A capability without a run is a claim, not a capability.
- **The caller proposes the claim; the loop disposes of it.** The model never writes the
  verdict.
- **Two lanes, one gate each.** `gate.ps1` mints authority for the debugging lane only, and
  only for an object the Owner named with checkable provenance. A debugging ALLOW is never a
  bounty ALLOW.
- **Red lines unchanged:** never `certutil -addstore`, never a one-click CA install, never
  the Windows system proxy; no `docker compose up` from `<project>`; no scanning
  github.com or HackerOne; no exploit PoCs, samples, captures, keys or unpacked
  binaries in either repo; no third-party anti-bot or DRM circumvention; a third-party
  binary is never an analysis target; running an untrusted sample on the host instead of an
  isolated VM is a STOP.
- **Third-party code adopted so far: zero.** Everything landed is a fix to our own code, a
  recorded measurement, or a recorded refusal with a reason.

---

## 2. 当前状态 (current state — measured, not remembered)

Run these from the repo root. **Re-run them; if the tree has moved, this table is stale and
the tree wins.**

| Suite / fact | Command | Result |
|---|---|---|
| Registry validate | `python scripts/registry-verify.py` | `capabilities: 16`, `REGISTRY CLEAN` |
| Registry selftest | `python scripts/registry-verify.py --selftest` | `SELFTEST OK: 46 cases each fire…` — **a case count**; 19 rule functions |
| Gate selftest | `powershell -File scripts\gate.ps1 -Action Selftest` | `GATE SELFTEST OK: 24 refusals and grants all behaved.` |
| Mission selftest | `powershell -File scripts\mission.ps1 -Action Selftest` | `MISSION SELFTEST OK: 51 controls behaved.` |
| Verdict ablation | `powershell -File scripts\mission.ps1 -Action Ablate` | `7 load-bearing` verdicts + `6` routing, `0 unproved` |
| Full-station smoke | `powershell -File scripts\smoke-all.ps1` | `pass=19 fail=0`, ~270 s — **not re-run since 2026-10-01** |
| Acceptance mission | `mission.ps1 -Action Run … -QuestionType Q2.locate …` | `unresolved`, `failed_gates=[independence]` |
| Typed edges | count `from` keys in the registry | **5** |
| `E:` free | `Get-Volume -DriveLetter E` | 28.01 GiB of 33.67 GiB |
| MCP exposure | `Get-NetTCPConnection -State Listen` filtered to 13337/8745/9222/8080/3000/18765 | **no rows — nothing of ours is listening** |

**Six workers are in flight when this file was written. Do not write to their paths, and do
not re-dispatch them. When each lands: read its report → check its DONE WHEN → `board.py
close --verdict ok --verify "<真跑过的>"`. The board is append-only; never rewrite a row.**

| Board id | Worker | Owns | Deliverable |
|---|---|---|---|
| `W11-DOSSIER` | Reconcile2 | `docs/research/` | reconcile the dossier against the final tree |
| `W11-WIKI` | WikiReconcile2 | `arsenal-upgrade-plan.md`, `CHARTER-ARSENAL.md`, `INDEX.md` | reconcile the wiki against the final tree |
| `W12-MCP` | McpExposure | read-only | is the estate exposed to the recorded `ida-pro-mcp` failure; interception recipe |
| `W12-SECOND` | SecondInstrument | read-only | what a genuine second instrument is, and its cost |
| `W12-STARMINED` | StarMined | read-only | high-star mining sweep — see §4 |
| `W12-PENTAGI` | PentagiDeep | read-only | deep dive on PentAGI against our gate design |

Earlier `W10-RECONCILE` and `W10-WIKIRECONCILE` **died during a compaction having written
neither a report nor an edit.** They are closed `abandoned` and replaced by the `W11-*` pair.
That is why the "write the file before you reply" rule is in every brief now.

Commits this session, station: `f1d23de`, `5ec8878`, `4e381f0`, `c0624bd`. Both repos
pushed.

---

## 3. 已定决策 (decisions, with reasons)

1. **Ablation is the project's own audit method** — remove a mechanism, require the existing
   suite to turn red. A suite that stays green proves a component *untested*, not correct.
   It is the only instrument that found the defects below, and it is now a charter rule.
2. **The grant identity is sealed with DPAPI** at `CurrentUser`, not with a key file. No key
   material goes in the repo, and an unkeyed hash is not a signature. The weakness is stated
   in the file header: any code running as the Owner can call `CryptProtectData`. What it
   buys is that a *text edit* to a grant can no longer reproduce a valid identity.
3. **`gate/grant@2`; every `@1` grant is refused by design**, and any registry edit
   invalidates existing grants because `registry_sha256` is in the sealed identity. A grant
   the gate cannot re-establish is exactly what the refusal exit exists for.
4. **A finished dispatch releases its scope.** Measured on the real ledger, 145 closed ids
   still held a write scope, making paths permanently un-dispatchable — the inverse of the
   tool's purpose.
5. **`independence`'s family axis is a property of the instrument, not of a per-capability
   label.** IDA Pro carried two labels (`decompiler`, `static-analysis`) from one tool, so
   relabelling manufactured corroboration. `families <= instruments` now holds by
   construction.
6. **`bounded_claim`'s bound comes from the registry's declared `question_types`**, not a
   keyword. A five-token regex meant `"100% safe"` passed, and a token test measures the
   caller's phrasing rather than the claim's scope.
7. **The acceptance mission stays `unresolved`.** Its chain is one instrument held twice.
   No pair of decompilers on this toolset can corroborate — a design review confirmed
   Ghidra is the same family and that its only fact is a count, which its own `does_not_prove`
   says "is not a fidelity claim". **Do not weaken `independence` to make it confirm.**
8. **Three cross-lab links were deliberately NOT declared as typed edges.** They are module
   imports returning untyped values; declaring them would assert a handoff that does not
   exist. The count is 5 and the shortfall is recorded, not faked.
9. **`dynamic.win.frida` added as a *sibling*; `dynamic.device.frida` untouched.** The device
   entry's absence is a statement about *Android* and is correct; mutating it would destroy
   a load-bearing honesty pair.
10. **A refusal is a result.** Recorded rejections include `disrobe` (source-available, no
    public forks, 24-month non-compete), `MeroZemory/ida-multi-mcp` (no licence, worse),
    `0xeb/lldb-agent` (no licence, arbitrary LLDB, `0.0.0.0` one flag away), Triton, Hopper,
    rev.ng, Qiling, gVisor, AFL++, honggfuzz, atheris, panda.
11. **The estate is not currently exposed to the recorded `ida-pro-mcp` HTTP failure** —
    verified by hand, see §4. The router's gate is a real server-side per-backend
    allow-list enforced on every path (`mcp/debugger-router/server.py:144-147`), but its
    granularity is the *backend*, not the tool: `call_backend_tool` forwards any
    `tool_name` unfiltered (`:219-227`).
    **CORRECTION, from a worker that was told this and checked it: two of my premises were
    wrong, and the correction cuts both ways — safer than I said, and more fragile.**
    (a) **stdio is a FLAG, not the default.** `idalib_supervisor.py:1471-1473` defines
    `--stdio` with defaults `--host 127.0.0.1 --port 8745`, and `:1524-1530` serves HTTP
    unless the flag is present. **The default is an HTTP listener on 127.0.0.1:8745** — a
    port that was in my own "no rows" port list. The estate is safe *only* because
    `mcp/bin/ida-pro-mcp.cmd:7` passes `--stdio`, and there is no `--http` flag: the
    exposure comes from **removing** that one argument. One flag in one `.cmd` file,
    enforced by nothing.
    (b) **The unsafe tools are removed by default, not shipped enabled.**
    `idalib_server.py:285-289` pops them from `tools.methods` unless `--unsafe`, restored
    only by that flag (`idalib_supervisor.py:1496-1497`), and upstream
    `test_server.py:213-232` asserts the negative. **So there is a real server-side
    `tools/call` gate — inside `ida-pro-mcp`, not in the router.**
    (c) `http.py:93` does snapshot the tool registry at import time before the removal runs,
    but that yields **reconnaissance, not code execution**: the removal still happens. My
    phrasing would have had a reader believe the gate was defeated. It is not.
    **The lesson is the one this project keeps relearning: I asserted a conclusion and
    stopped. Both my supporting claims were wrong, in the estate's favour and against it
    simultaneously.**

---

## 4. 走过的死路 (dead ends — do not re-walk)

- **Eight research agents all missed `vxcontrol/pentagi`** — 25,177 stars, 3,241 forks, Go,
  pushed 2026-09-30, *"Fully autonomous AI Agents system…penetration testing"*. Owner caught
  it; I confirmed it was in neither our corpus nor any of the eight reports. **The method was
  wrong, not the luck:** every previous brief searched by *capability keyword*, which only
  finds projects that describe themselves the way you searched for. **Mining by stars, by
  topic, by language and by adjacency is now required.** Do not send another keyword-only
  brief.
  **CORRECTION, same day:** I first recorded pentagi as having **no licence file**. That was
  wrong — a field-name error in my own probe, not a missing file. It is **MIT**
  (`gh api repos/vxcontrol/pentagi/license` → `spdx_id: MIT`, `path: LICENSE`, with `NOTICE`
  and a `licenses/` directory). I nearly repeated the exact failure this project exists to
  catch: recording a confident, wrong claim instead of checking. **Verify a licence by
  listing the repo root**, not by a field you have not confirmed.
- **I overwrote `~/.omp/extra-hands/CACHE/board.py` with 72 bytes of JSON** (mis-typed
  `write` path while extending a board scope). The `.pyc` was an *older* build, so it could
  not serve as the source, and blindly replaying 36 recorded edits from the transcript onto a
  truncated snapshot produced duplicated blocks that would not parse. What worked: rewrite
  from the tool's own documented contract, then prove it. `board.tests.py` (34 gates) and
  `board.tests_concurrent.py` (24 concurrent mints) both run from that directory. **Two real
  concurrency bugs were found while testing:** `os.O_APPEND` is not an atomic append on
  Windows (the CRT seeks at open time, so 4–6 of 24 rows were silently lost per round while
  every process printed `board: OPEN`), and `write_text` truncates. Both now behind a lock.
- **A reconstruction bug I introduced and caught:** the restored `cmd_open` never released a
  CLOSEd job's scope, so 145 finished dispatches still held paths and `scripts/` became
  un-claimable. Found because the board refused my own next scope. Fixed, with a control.
- **I asserted a false premise into a brief.** I told a worker `skill-adoption-checklist.md`
  did not exist. It did — 9,325 bytes, committed `881e826`. The worker searched the wrong
  repo, refused to accept my claim, and rewrote the file into something better (30,430 bytes,
  ten blocks, ten pasteable PowerShell checks). **Propagating an unverified claim into a
  brief is the same failure as writing it into a document.**
- **`-Action Plan` needs the full intake.** It refuses without `-Target`, then without
  `-Containment`. A plan invocation omitting them exits 2 at intake, which reads as a routing
  failure and is not one.
- **`frida-ps -ai` HANGS for 300 s** on this device-less box. It does not fail. A probe that
  hangs instead of refusing is worse than one that errors — same lesson as `fuzz-lab`'s
  budget floor.
- **Refuted, do not repeat:** the handoff's *"the full aggregate contends on three Ghidra
  probes and is killed by timeout"*. Measured, **not reproduced** — concurrent 103.47 s vs
  161.93 s serial, all passing. The real hazard is fixed loopback ports: two `crypto-lab`
  runs both bind **8791** and one dies `EADDRINUSE`; two `native-lab` runs both bind **8745**
  and the loser exits 1.
- **Third category of control failure, now named in the charter:** not a check that always
  passes, and not a control that passes for the wrong reason, but **a correct control quoted
  as if it were an end-to-end result**. A selftest fixture with a synthetic substrate
  produced a `confirmed` reading reported as "the acceptance mission reproduces"; the real
  mission ran IDA twice and refused.
- **An AST audit finds unused locals, not duplicated blocks.** A worker's own
  `bounded_claim` rewrite left a duplicated 34-line block that parsed cleanly and would have
  executed, appending a second gate entry with a stale value. Self-disclosed. `-Action
  Ablate` would have caught it, but only after shipping a wrong verdict.
- **Known `gh` instrument defects:** `gh search repos` can exit 0 with an empty body while
  `gh api` returns a real `total_count`; `gh search code` ignores `OR`; `curl.exe` gets 403
  from crates.io for every crate. **An error is not a zero, and a zero is not a proof.**

---

## 5. 唯一待解问题 (the single open question)

**How does this arsenal obtain a genuine second opinion?**

The `independence` gate is now honest, and being honest exposed the real gap: the only
end-to-end mission chain is IDA Pro alone, so it cannot corroborate itself. Ghidra is the
same family. Candidates that are *not* decompilers:

- **`dynamic.win.frida`** is registered but does not yet claim interception — the `frida` CLI
  resumes the main thread before the injected script loads. Interception **was** observed
  through the Python API's spawn→attach→create_script→load→resume order, which is not the
  registered probe. `W12-MCP` is producing the recipe; closing this honestly is the cheapest
  route to a second family of evidence, at zero disk cost.
- **`native.crosscompare.ghidra`** declares `binary-similarity` — a genuinely different
  family — but has no `invoke` block, and its `consumes` says both programs must be in one
  Ghidra project first, which is not expressible.
- **LLVM is absent** (MSVC `cl` 14.44 only). Its 374 MB install is the single gate on four
  toolchain rows: libFuzzer, Intel PIN, AFL++-on-Windows, atheris.
- `W12-SECOND` is ranking these with real costs; `W12-PENTAGI` is asking whether a
  supervisor pattern could produce corroboration that is not a second label off one
  instrument.

Do not answer this by weakening a gate. The refusal is correct until a second instrument
exists.

---

## 附: research corpus

Round one: `w1-agentworkflow.md` · `w1-composition.md` · `w1-gateredteam.md` ·
`w1-mcprev.md` · `w1-retoolchain.md` · `w1-revskills.md` · `w1-debugpairing.md` ·
`w1-toolperf.md`. Fixes: `w2-composefix.md` · `w3-gatefix.md` · `w4-verdictlogic.md` ·
`w7-familyaxis.md` · `w9-winfrida.md`. Synthesis: `w5-dossier.md` · `w5-wikiplan.md` ·
`w6-chain.md`. All under `%USERPROFILE%/AppData/Local/Temp/` — **which does not survive.**

**Durable copies live in `docs/research/`**: `review-2026-10-02.md`, `cost-matrix.md`,
`composition-plan.md`, `ecosystem-2026-10-02.md`, `dynamic-pairings.md`, plus an updated
`README.md`. Round two (`W12-*`) is read-only research with **no durable destination yet** —
when it lands, someone must copy the findings into `docs/research/` or they are lost with
`%TEMP%`. That is an open task, not a completed one.