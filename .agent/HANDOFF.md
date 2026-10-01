# HANDOFF — reverse workstation

**刚发生的事 (2026-10-02):** a deep review with concurrent subagents found this repo's own
verification layer was not verifying itself. The headline — **C1**, the "complete, confident,
wrong answer" this harness exists to reject — still reached `tier=confirmed` with every fact
invented, no tool run, both capabilities IDA Pro and four guards named that never ran. Under
it: `gate.ps1` accepted a grant whose Owner word and provenance were blanked with the
attacker-recomputed public hash (eight exploited holes); the registry validator's R8 could
never fire for any of its five effects; the registry declared **one** composition edge, and
capability selection was a hardcoded table that never read the registry at all. All
reproduced first, all fixed, all covered by a control that reddens when its mechanism is
removed. Commits `f1d23de`, `5ec8878`, `4e381f0`.

**下一步:** the gate and the verdict layer are now honest, and that exposed the real gap —
**the only end-to-end mission chain is one instrument, IDA Pro, held twice, so it cannot
corroborate itself and `Q2.locate` correctly returns `unresolved`.** Do not weaken
`independence` to change that. Two workers are in flight: board `W10-RECONCILE` (this file's
`docs/research/` figures) — wait, do not duplicate. Full record with every measured number
and the dead ends not to re-walk: **`.agent/detail-2026-10-02-deep-review.md`**. What
follows below is the 2026-09-30 record; §9 is the only part kept current.

Written 2026-09-30 at the end of a long session. Every number below was produced by a
command in this repo. Nothing here is remembered.

---

## 0. The one rule

> **本项目声称的每一个能力,都由一条可运行的命令证明。**
> **A capability without a runnable command is a claim, not a capability.**

Three corollaries that the whole repo is built on:

1. **A check that always passes is not evidence.**
2. **`rejected` is not `correct`.** The tool returned a decision, not the right one.
3. **The instrument, not the subject, is usually what is broken.** This session produced
   **13 separate instances** of that, and every one was caught by a program rather than by
   reading more carefully. Section 8 lists them, because the next window will produce the
   fourteenth.

---

## 1. What this workstation is for

Two repos, non-overlapping:

| Repo | Job |
|---|---|
| `<private-tree>` | **Policy, authorization, knowledge, the lab range.** Decides *whether* something may be done. Contains no tools. |
| `debugger-workstation` (this one) | **Tools, labs, the capability registry, the orchestrator.** Decides *how* to do it and *whether it worked*. |

The split is deliberate: a debug ALLOW must never be misread as a bounty ALLOW.

---

## 2. How to use it — the actual workflow

```
  you ──▶ gate.ps1 New ──▶ grant.json          only this mints authority; only an
                                              Owner sentence authorises one
     ──▶ mission.ps1 Run ──▶ plan.json         written BEFORE any tool runs
                         ├─ round 1  capability A   gate re-checked EVERY round
                         ├─ round 2  capability B   fed A's typed fact forward
                         └─ verdict    computed by seven gates, not written by the model
                         ──▶ artifact.json + trace.jsonl + STOP note
```

Concretely:

```powershell
# 1. prove the whole station still works
powershell -File scripts\smoke-all.ps1

# 2. mint authority for one object
powershell -File scripts\gate.ps1 -Action New -Target crackme-corpus\out\c01-stringobf.exe `
  -Provenance "Owner-authored; built by crackme-corpus/tools/loop.py from our own source" `
  -OwnerWord "analyze this exe" -CaseDir E:\missions\mycase

# 3. run a mission behind it
powershell -File scripts\mission.ps1 -Action Run -Target crackme-corpus\out\c01-stringobf.exe `
  -Question "where is the input validation" -QuestionType Q2.locate `
  -Provenance "..." -OwnerWord "..." -Containment station_under_named_process_rule `
  -Claim "what you think the answer is -- the loop decides whether it survives"

# 4. a single capability on its own
powershell -File scripts\native-lab.ps1 loop
node fuzz-lab\tools\loop.mjs
```

`agent-cli.ps1 catalog` lists every lab entry point as JSON.

---

## 3. The one command that proves the orchestrator is real

```powershell
powershell -File scripts\mission.ps1 -Action Selftest     # 15/15, incl. N4
```

**N4 is the one that matters:** it aims the station's own documented failure mode — the
managed lab's *complete, confident, wrong answer* — straight at the new code, and requires
`unresolved`. A harness that is a function cannot be argued with.

Measured acceptance run on our own crackme:

```
round 1  native.ida.list_functions  →  native.func.addr, native.func.named
round 2  native.ida.decompile       →  native.dec.code, native.dec.refs
termination DONE | verdict confirmed | scope guard INTACT | STOP note: 11 did not run
```

The recorded evidence was **checked against the claim**, not assumed to support it: the
decompiled `main` does compare `argv[1]` against the decoded buffer `Str2` *and* does carry
the plaintext decoy. So the claim is what the artifact shows.

---

## 4. The seven verdict gates

The caller proposes a claim. **The loop disposes of it.** Fail any gate → `unresolved`,
which cannot be the terminal answer.

| Gate | Refuses |
|---|---|
| `process` | a conclusion with no recorded run behind it |
| `reachability` | two disconnected results presented as a chain |
| `observation` | a fact that does not cover the claim |
| `independence` | **facts from one instrument FAMILY.** `{ghidra.decompile, ida.decompile}` is refused — two decompilers share the blind spots that come from reconstructing machine code into C |
| `bounded_claim` | a claim wider than any `does_not_prove` allows |
| `uncertainty` | a verdict with no unknowns |
| `discharged` | **"I found nothing" without naming the guards that would have found it.** Strictly stronger than anything this repo had before. Naming a guard not in the registry does not count |

And termination is computed too, in three states. **DONE ≠ EXHAUSTED** — a mission that ran
out of budget and one that answered both stop, and reading the first as the second turns a
gap into a verdict. `EXHAUSTED` names the guards it did not run.

---

## 5. What is claimed, and how each is proved

15 capabilities in `manifests/capabilities.json`; **12 observed, 2 absent, 1 blocked**.
Verify the claims, not the file:

```powershell
python scripts\registry-verify.py               # 15 capabilities, CLEAN
python scripts\registry-verify.py --selftest    # 18 selftest cases across 11 rules, each
                                                # case built to violate exactly that rule
```

**Never trust a `last_summary` in the registry.** Re-run the `probe.command`. A recorded
number that no longer reproduces is worse than no number.

The two absent and one blocked, so you do not go looking:

- **`dynamic.device.frida`** — no device, no `adb`, no emulator.
- **`native.il2cpp.symbols`** — the tool is a net6 build, this host has .NET 8/10 only,
  and it **hangs silently** rather than erroring. Separately: no *authorized* IL2CPP
  artifact exists. `global-metadata.dat` files are present on this host inside the VIVE
  Hub installer — **third-party commercial software — and were deliberately not used.**
  "It is installed on my machine" is not ownership.
- **`native.ghidra.emulate`** — the API is reachable and ran; the controlled-input setup
  does not take, so ground truth was not recovered. **And `EmulatorHelper` / `DefaultEmulator`
  are deprecated and marked for removal.** Fixing the setup would mean building a durable
  capability on an API Ghidra intends to delete. Decide that *before* the fix.

---

## 6. The traps in this repo's own tooling

All measured. All of these cost real time.

| Trap | Cost |
|---|---|
| `Start-Process -PassThru` + `WaitForExit(<int>)` | `$p.ExitCode` is **`$null`**; `exit $null` is **exit 0**. Ghidra wrapper failed open on a failed import. Gate on the artifact, never the code |
| `ida-pro-mcp` failure reporting | `isError:false`, `code:null`, `error:"…"`. Test the `error` field, require non-null `code` |
| `--unsafe` on that server | **a speed bump, not a boundary.** One unauthenticated loopback POST made `py_eval` callable; the result is persisted into the sample's `.i64`. And `idb_save` is *not* tagged unsafe |
| Batches drop items silently | 5 queries in, 4 results out, no index, no counter. Contract is `len(result) == len(queries)` |
| Orphaned `idalib` worker holds 8745 | the loop attaches to a server it did not start. `portFree()` refuses |
| IDA lists no session until analysis ends | an early poll returns `[]`, indistinguishable from failure-to-open |
| Ghidra compiles the whole scriptPath dir | one broken file pollutes **every** headless run's output |
| Bash here is **WSL2** | `C:\Windows\system32\bash.exe`; its root is a Linux filesystem and `D:` is absent. Three bash smoke attempts failed 15/15 for that reason. **PowerShell only** |
| `command -v` is not a package check | webcrack/wakaru are npm packages under `web-reverse/static/node_modules/`, not PATH binaries |
| Research claims about our own tooling | "we lack a JS transform engine" was false. A claim about *your own* tooling deserves **more** scrutiny than one about someone else's |
| `.agent/` in `<private-tree>` is excluded; here it is not | this recovery doc is tracked **on purpose** — it is the only artifact that survives a lost machine |

---

## 7. Two premises that were wrong, and the rule they produced

Both were asserted limitations nobody re-checked. Both had already spread into a manifest
and into a briefing sent to four research agents.

1. **"This box has no IDA Pro."** False. IDA Professional **9.2**, licensed
   (`idapro.hexlic`), with `ida-pro-mcp` v2.0.0 serving **66 tools**.
2. **"Ghidra cannot open a sibling program headlessly."** False.
   `AutoVersionTrackingScript` does exactly that — verified with three programs open in one
   process, 14 correlators, 14–17 s.

> **Rule: a claim of the form "the tool cannot do X" is unverified until someone has run it.**

---

## 8. The thirteen times the instrument was wrong

Recorded because the next window will produce the fourteenth, and because the pattern is
the actual lesson of this session.

1. Counted `PASS` lines as checks — forensics 74 lines = 37 checks. Nearly "corrected" three
   correct numbers with a bad ruler.
2. A negative control that passed **for the wrong reason** — refused because no session id
   was bound, so it never reached the address it was testing.
3. A selftest that collected **zero** cases and still announced "OK: 0 rules".
4. Smoke reported four green labs as red (`JSON-SUMMARY` shadowed the verdict line).
5. `ida-pro-mcp` wrapper: hashtable splatted as one argument → `target=System.Collections.Hashtable`.
6. Ghidra fail-open (above).
7. Verdict gate list came back **empty**, so six gates passed vacuously.
8. `$failed` vs `$FailedRounds` — different variable names; `$null -eq 0` is false, so
   CONTINUE was unreachable and every mission reported DONE.
9. Scope guard hashed the 1 GB Ghidra install — minutes per run. **A guard nobody waits for
   is not a guard.** Now `git ls-files`, 50 ms.
10. Android environment detector reported root/emulator checks present **on our own clean
    APK** — `"sdk"` matched the literal `"sdk="`, and `"su"` matched XML element names.
11. A Ghidra project-cleanup block sat **after** the exits, so it was unreachable on the
    only path that creates a project: looked right, fixed nothing.
12. Smoke reported `IL2CPP ABSENT` as a FAILURE **while printing that exact string** — the
    scan pattern was a hardcoded list the new probes' `expect` values were never in.
13. `.agent/RECOVERY-STATION.md` recorded a "50-minute anomaly" that was **my own waiting,
    not the run** — it finished in 740 s, LOOP CLOSED.

Structural fixes, not fourth patches:

- The smoke scan pattern is now **derived from each probe's own `expect`**, so a checklist
  and the thing it checks cannot drift apart.
- Every selftest has an **explicit zero-case floor**. A checker over zero items must fail.
- `registry-verify` has **11 rules, exercised by 18 selftest cases** — each case builds a
  registry that violates exactly the rule it covers.

---

## 9. Current state

| | |
|---|---|
| registry | **16 capabilities**, CLEAN · **19 validator rules, 46 selftest cases** |
| gate selftest | **24** refusals and grants |
| mission selftest | **51** controls incl. N4; **7** verdict gates; **6** routing rules |
| ablation | `-Action Ablate` → **7 verdict + 6 routing load-bearing, 0 unproved** |
| ghidra fail-open regression | **4/4 LOOP CLOSED** |
| fuzz lab | **24/24 LOOP CLOSED**, 740 s at budget 90 (floor 40) |
| native-lab | **15/15 LOOP CLOSED**, ~2.4 s |
| full aggregate smoke | **pass=19 fail=0**, ~270 s. The old "contends on three Ghidra probes and is killed by timeout" is **REFUTED** — concurrent run 103.47 s vs 161.93 s serial, all passing. The real hazard is **fixed loopback ports**: two `crypto-lab` runs both bind 8791 and one dies `EADDRINUSE`; two `native-lab` runs both bind 8745 and the loser exits 1 |
| research | `docs/research/` — 8 reports, 5,634 lines. Measured 2026-10-02 with `(Get-ChildItem docs\research -Filter *.md \| Where-Object Name -ne README.md \| Get-Content).Count`, summed per file |
| `E:` | **28.01 GiB free of 33.67 GiB** (measured 2026-10-02, `Get-Volume -DriveLetter E`). The VHDX **never returns bytes**; budget by peak cumulative pull |

Both trees clean at the time of the 2026-10-02 review commit. `<private-tree>` 18 commits,
station 49 — **re-measure with `git rev-list --count HEAD` in each**; the station moved
three times after this line was last written.

---

## 10. Do not

- Do not claim a capability from a manifest entry without running its probe.
- Do not treat a third-party binary as an analysis target. The gate is an Owner-named
  object with checkable provenance, and this repo has already found and declined several.
- Do not add a second IDA server (`AGENTS.md:123`). The agent route is `idalib`, not the
  GUI on 13337.
- Do not `docker compose up` from `<project>` — the working dir is `E:\<private-tree>-sandbox\compose`.
- Do not weaken a control to make something converge. Record the failure instead.
- Do not use bash. See §6.

## 11. Still open, honestly

1. **18.1 MB of stale `%TEMP%\ghidra-proj-*`** on `E:` — 5 directories that hold data, left
   by runs from before the leak fix. New runs leak nothing (verified 56 dirs before, 56
   after). **Needs an Owner word before recursive deletion.**
2. **The aggregate smoke contends** on three Ghidra-consuming probes. Split them onto
   separate cadences.
3. **`p-code emulation`** — blocked, and deprecated upstream. See §5.
4. **IL2CPP** — unblocked only by the Owner naming an IL2CPP binary they own.
5. **Android device lane** — needs the emulator (≈1.7 GB download, ≈2.9 GB installed, plus
   a Windows optional feature and a reboot). **Owner decision; deliberately not taken.**
