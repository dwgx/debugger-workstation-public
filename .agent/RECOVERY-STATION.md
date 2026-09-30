# RECOVERY — reverse workstation (`D:\Software\Tool\WorkStation\debugger`)

Written 2026-09-30 before a context compaction. Everything below was **measured**, not
remembered. Where a number is quoted it carries the command that produced it, because a
recovery document written from memory inherits every assumption the session already got
wrong — and this session got two of them wrong in writing.

---

## 0. Count the evidence, not the lines

**Counting `PASS` lines does not count checks.** Each check prints a verdict *and* its
evidence, and some labs also print per-case rows:

| Lab | PASS lines | actual checks |
|---|---|---|
| forensics-lab | 74 | **37** |
| managed-lab | 46 | **27** |
| crypto-lab | 29 | **17** |

Counting unique check names, or reading the lab's own `JSON-SUMMARY` line. A bad ruler
"corrects" correct numbers — that happened during this session before it was caught.

**Rule 1 of this repo:** a check that always passes is not evidence.
**Rule 2:** a `rejected` outcome is not a correctness claim.
**Rule 3:** a capability with no runnable command is a claim, not a capability.

---

## 1. What was wrong in my own writing, and is now fixed

Both were **asserted limitations nobody re-checked**. This pattern has now bitten twice
in one session; treat any "the tool cannot do X" as unverified until someone has run it.

1. **"This box has no IDA Pro."** False. IDA Professional **9.2** is installed and
   licensed (`idapro.hexlic` present) at `D:\Software\Tool\Debugger\IDA Professional 9.2`,
   junctioned as `Static-Reversing\IDA`. `ida-pro-mcp` **v2.0.0** (mrexodia) plus Hex-Rays
   `idapro` 0.0.10 are installed. The false claim had propagated into
   `manifests/tools.json`, the upgrade plan, and a briefing to four research agents.
2. **"Ghidra 12 cannot open a sibling program headlessly."** False, per
   `scripts/ghidra/DiffPrograms.java:6-12`. `AutoVersionTrackingScript.java` does exactly
   that — verified by running it with three programs open in one process, all 14
   correlators, 14–17 s, no apply markup errors.

---

## 2. Verified state

> Superseded in part by `.agent/HANDOFF.md`, which is the shorter and more current
> entry point. Section 13 below covers the mission layer, which postdates §2.

Run from the repo root. Each is the registry's `probe.command`.

| Capability | Command | Result |
|---|---|---|
| registry selftest | `python scripts/registry-verify.py --selftest` | **18/18 rules fire** |
| registry validate | `python scripts/registry-verify.py` | **15 capabilities, CLEAN** |
| ghidra fail-open | `powershell -File scripts\ghidra-failopen-regress.ps1` | **4/4 LOOP CLOSED** |
| web/JS | `node web-reverse/tools/loop.mjs` | LOOP CLOSED |
| web AST deobf | `node web-reverse/tools/loop2.mjs` | all checks incl. negative controls |
| crypto/JWT | `node crypto-lab/tools/loop.mjs` | `{"total":17,"pass":17,"fail":0}` |
| network/protocol | `node net-reverse/tools/loop.mjs` | LANE CLOSED |
| isolation | `node net-reverse/tools/trustcheck.mjs` | ISOLATION HELD |
| crackme corpus | `python crackme-corpus/tools/loop.py` | 20 checks, 5 negative controls |
| forensics/memory | `node forensics-lab/tools/loop.mjs` | **37** checks |
| managed .NET | `node managed-lab/tools/loop.mjs` | `{"total":27,"pass":27,"fail":0}` |
| mobile/Android | `node mobile-lab/tools/loop.mjs` | 25 checks incl. 40-case Frida suite |
| **native / IDA** | `node native-lab/tools/loop.mjs` | **15/15 LOOP CLOSED, ~2.4 s** |
| fuzzing (D11) | `node fuzz-lab/tools/loop.mjs` | **LOOP CLOSED 24/24, 740 s at budget 90** — budget floor 40, default 90; 12 flawed-twin findings, 6/6 regressions holding |

Full-station one-liner (read-only, ~3 min), from the repo root:

```powershell
powershell -File scripts\smoke-all.ps1
```

It requires **both** that each probe exits 0 **and** that the lab printed the line it is
supposed to print. Exit code alone is the mistake that made a failed Ghidra import look
like a pass, so the smoke test refuses to make that mistake twice.

It is PowerShell, not bash, after two failed bash attempts: `bash` on this box resolves
to `C:\Windows\system32\bash.exe`, which is **WSL2** — its root is a Linux filesystem and
`D:` is not present at all. A bash version reported 15/15 failures that had nothing to do
with any lab.

---

## 3. The four defects the fuzzer found in our own parsers

All fixed, all under regression guard. `fuzz-lab` targets parsers **this repo wrote**,
so every finding was a real robustness bug and never a third-party target.

| Where | Class | Fix |
|---|---|---|
| `forensics-lab/tools/triage.mjs` `parsePrefetch` | uncaught over-read | bounds from the record layout; truncation **reported**, not thrown |
| `crypto-lab/tools/analyze.mjs` `EMAIL_VALUE_RE` | ReDoS, quadratic | anchored + bounded runs. 400k: 54.0 s → **11 ms** |
| `web-reverse/static/lib/triage.mjs` `tableAccessorCalls` | ReDoS | 300k: 22 s → **1 ms** |
| `web-reverse/static/lib/triage.mjs` `TRANSPILER_HINTS[nullish-lowering]` | ReDoS | 200k: 8.7 s → **18 ms** |

The fourth is the one that justifies the lab: it is on no list, in a different function
in the same file, and was found only because the fuzzer appends 400 000 copies of a random
character and waits to see whether anything comes back. A neighbouring hint with the
**same regex shape** was deliberately **left alone** because it measured 0 ms — fixing by
shape would have been wrong.

**Sharpest argument for a differential oracle over a crash counter:** the pcap twin's
defect is *silent*. `Buffer.subarray` clamps, so the flawed reader returns a 4-byte frame
while **reporting** `capturedLength 1000`. Nothing throws. An analyst reading that report
would believe they had a kilobyte of traffic, and a crash-counting fuzzer sees nothing.

---

## 4. Traps in our own tooling — all measured, all fixed

| Trap | Consequence | State |
|---|---|---|
| `Start-Process -PassThru` + `WaitForExit(<int>)` | `$p.ExitCode` is **`$null`**; `exit $null` is **exit 0** | fixed in `ghidra-headless.ps1`; gate on the artifact |
| MCP `POST` vs `GET` | GET `/mcp` returns 405 — protocol, not fault | documented |
| `ida-pro-mcp` failure reporting | `isError:false`, `code:null`, `error:"..."` | **test the `error` field**, require non-null `code` |
| orphaned `idalib` worker holds 8745 | loop attaches to a server it did not start | `portFree()` refuses; verified with a decoy listener |
| IDA lists no session until analysis ends | early poll returns `[]`, looks like failure-to-open | `waitForSession()` |
| `proc.kill('SIGKILL')` on Windows | libuv assertion | use `taskkill /T /F` |
| fuzz-lab budget below 40 | hang-class twin unreachable → false "SURVIVED" | floor guard refuses in 0.1 s |

---

## 5. Security findings on `ida-pro-mcp` — the server is not a boundary

**`--unsafe` is a speed bump and was reversed live on this host.** On a worker started
*without* it, one unauthenticated loopback POST made `py_eval` callable and it returned 2:

```
POST /config   apply_profile=1&profile_text=py_eval
```

- `http.py:93` snapshots `ORIGINAL_TOOLS` at import, **before** `idalib_server.py:285-289`
  deletes the unsafe tools; `http.py:442-446` rebuilds `tools.methods` from that snapshot
- `_check_api_request` (`mcp.py:303-328`) accepts any request with no `Origin` header →
  **no token needed**
- persisted into the IDB netnode `$ ida_mcp.enabled_tools` (`http.py:447`) → **the policy
  travels inside the sample's `.i64`**
- `idb_open`/`idb_list` are `protected` from `--profile` (`idalib_server.py:57-60`), and the
  supervisor never applies `--profile` to its own registry
  (`idalib_supervisor.py:1498-1499`) → a "read-only" profile still grants arbitrary-path reads
- **`idb_save` is NOT tagged unsafe** and writes 2.7 MB to an arbitrary path
- `X-IDA-MCP-External-Base` rewrites the download URL → measured `http://attacker.invalid:9999/…`

**Never** pass `--unsafe`, **never** send `POST /config`, **never** trust `--profile`. The
gate enforces authority; the server's flags do not. Recorded as `gate_must_not_delegate`.

**Batches drop items silently** (measured): `normalize_dict_list` drops non-dict elements
(`utils.py:704-706`) — 5 queries in, 4 results out, no index, no echo; empty array becomes
`[{}]` (`utils.py:694-695`); past a 50,000-char cap the whole result is replaced by a
10-item preview (`rpc.py:20`) — measured 6,000 `get_int` → 10 items. So the contract is
`len(result) == len(queries)`. **A short result is a failure, not a smaller answer.**

**Sessions are not durable handles:** a supervisor's `idb_open` adopted *another process's*
worker via shared discovery files, then lost the session on the next call. Bind to
`sha256(object)`, re-derive each round.

---

## 6. The registry and its validator

`manifests/capabilities.json` (11 entries) is a **contract**; `manifests/tools.json` stays
an **inventory**. Conflating them is how a machine-readable file makes unverified claims.

14 rules, each exercised by `--selftest` against a registry built to violate it:

```
R1 empty registry fails          R8 reach declared as an effect, not a tag
R2 observed needs a probe        R9 batch consumed => envelope.batch declared
R3 proves + does_not_prove      R-shape required fields, valid state
R4 fact type agreement          R5 control present and expects non-zero
R6 reach needs escalation       R7 ids unique
```

`R3` binds **claims, not absences**: an `absent` entry must prove nothing but must still
declare `does_not_prove`. Two selftest cases pin that — one asserting the rule stays
silent, one asserting it still catches a stripped absent entry — so the relaxation cannot
quietly widen into a hole. That refinement came from the validator firing on my own data,
which is the second reason to run validators on real registries rather than fixtures.

---

## 7. Environment (measured — do not assume)

- **IDA Pro 9.2** installed + licensed; `idalib-mcp.exe` at
  `D:\Software\Developer\Python314\Scripts\`; MCP over **POST** `127.0.0.1:8745/mcp`,
  **66 tools**. Agent default is `idalib` or `idat -A`, **not** GUI 13337
  (`OWNER.md:13`); `AGENTS.md:123` — do not add a second IDA server.
- **Ghidra 12.1.3** (12.1.2 also present). One headless run of a 140.5 KB PE:
  **18.05 s wall, 1,085.7 MB peak RAM, 673 KB across 522 files**; project dir 3.6–4.5 MB.
  12.1.2 doing the same job: 29 s cold. Projects go to `%TEMP%` (**C:**), not `E:`.
- **~30 stranded `%TEMP%\ghidra-proj-*` dirs, ~14 MB** — `ghidra-headless.ps1:41` only adds
  `-deleteProject` on the no-PostScript/no-Http path.
- `E:` ≈ 14.5 GB free. The VHDX is dynamic and **never returns bytes** — budget by peak
  cumulative pull, not current usage.
- **No gcc anywhere.** MSVC 2022 is the C toolchain. Docker stopped; do not start it.
- No Android device, no `adb`. The emulator is ~1.7 GB and needs a Windows optional
  feature + reboot — **an Owner decision**, never taken unilaterally.

---

## 8. Stop lines (unchanged)

Never `certutil -addstore`, never Reqable's one-click CA, never the Windows system proxy —
the lab CA lives as files on `E:` and is trusted by a per-instance Chrome SPKI pin.
No `docker compose up` from `<project>`. No scanning github.com/HackerOne. No HackerOne
submit. No exploit PoCs, samples, captures, keys or unpacked binaries in either repo. No
anti-cheat or DRM circumvention. No third-party anti-bot bypass. No untrusted sample on the
host instead of an isolated VM. Running an untrusted sample on the host is a STOP.

**Self-authored targets only for fuzzing.** `tshark`, `Wireshark`, `jadx`, `Volatility` and
`DiE` are installed third-party parsers and are deliberately **not** targets — a finding
there is not a finding about this tree.

---

## 9. Next actions, in order

1. **Read `proc://` for `bg_204` / `bg_205`** — the default-budget fuzz run and the
   full-station smoke. Confirm both closed before trusting §2.
2. Fold the four research deliverables into committed wiki. They are in
   `.agent/research/` (git-excluded) and need copying into a tracked location:
   `agent-craft-principles.md`, `ghidra-capability-spec.md`, `ida-mcp-source-study.md`.
3. **Build `scripts/mission.ps1`** — the orchestration layer. Design is complete in
   `.agent/research/orchestration-design.md` (495 lines, shipped with negative controls
   N1–N4, N4 being the station's own known failure mode aimed at the new code). One
   command proves it on `crackme-corpus/out/c01-stringobf.exe`.
4. Add Ghidra registry entries, gating on `ok:true` plus the named artifact and **never**
   on `expect_exit` — the fail-open above makes that unsafe.
5. Apply the strongest un-implemented principle from `agent-craft-principles.md`:
   **"I found nothing" is an answer only when you can name the guards that would have
   found it** (`discharged[]`). It is strictly stronger than anything here now.

---

## 10. How to research here

The browser at `:9333` is **shared with other sessions and GitHub-rate-limited**. Three
distinct failures cost real time and none were visible from the symptom:

1. `evaluate_script` ran against a tab that had drifted to another site, so every
   cross-origin fetch returned nothing — **identical to "no results"**.
2. GitHub returned **429** with an error page that parsed as zero result rows. *A parser
   that cannot tell "no rows" from "error page" will lie about the world.*
3. `gh search repos "ida%20pro%20mcp"` returns `[]`; plain spaces work.

**Use the authenticated `gh` CLI.** `web_search` is expected dead.

```bash
gh search repos "QUERY" --limit 10 --json fullName,stargazersCount,description,updatedAt \
   --sort stars --order desc          # plain spaces, not %20
gh api repos/OWNER/REPO/contents/PATH
gh repo clone OWNER/REPO -- --depth 1  # into %LOCALAPPDATA%\Temp\re-research\<name>\
```

---

## 11. Repos

| Repo | Branch | Commits | Remote |
|---|---|---|---|
| `<private-tree>` | `master` | **16** | `<private-tree>` PRIVATE |
| `debugger-workstation` | `main` | **26** | `github.com/dwgx/debugger-workstation` PRIVATE |

Both trees clean and both remotes pushed at time of writing.

`.agent/RECOVERY-STATION.md` is **tracked** here on purpose, unlike in the <private-tree> repo.
That repo treats `.agent/` as per-session control plane and excludes it via
`.git/info/exclude`; here this document is the only thing that survives a lost machine,
and an untracked recovery document is a recovery document that decays. `.agent/research/`
**is** excluded, because `docs/research/` holds the canonical copy and two copies of
eight reports is two things that drift apart.

Re-measure before trusting any figure above — a recovery document that inflates its own
numbers is worse than one that omits them. That happened twice in this session: a station
commit count claimed 17 when the real figure was 16, and `PASS` lines were read as check
counts for three labs at once.

---

## 12. A correction I had to make to this document

An earlier draft of this section recorded an "unexplained anomaly": that
`node fuzz-lab/tools/loop.mjs` at the default budget 90 was still running past fifty
minutes against a recorded 682 s for budget 60.

**That was wrong, and it was my error rather than the lab's.** The run finished at
**740.05 s — about 12.3 minutes — with LOOP CLOSED**: 24/24 assertions, 12 flawed-twin
findings recorded, 6/6 regression guards holding, and the negative control satisfied by
flawed-twin findings rather than by the reference parser crashing.

The mistake was conflating my own elapsed waiting with the job's runtime. I read a
still-running status several times over a long span and treated the span as the run
time. It is the same failure mode as everything else in this session's notes — **the
observer, not the observed, was the thing that needed fixing** — and it is recorded here
rather than deleted so the next reader does not repeat it.

Budget 90 at ~12 min and budget 60 at ~11 min are consistent. There is no anomaly.

For the record, the two things that are genuinely budget-sensitive, both real and both
already handled: the triage cap is 3 per target/variant/outcome class, and `hang`-class
findings near the 4 s ceiling are unstable to minimise, so the lab records them as
`MARGINAL` instead of loosening the check.

---

## 13. The mission layer (added 2026-09-30, after section 2)

This is the piece the Owner's original request was actually about, and it did not exist
when sections 2 and 3 were written.

| Piece | Command | Result |
|---|---|---|
| **Orchestrator** | `powershell -File scripts\mission.ps1 -Action Run -Target <bin> -Question "..." -QuestionType Q2.locate -Provenance "..." -OwnerWord "..." -Containment station_under_named_process_rule -Claim "..."` | **DONE / confirmed / scope INTACT** |
| Orchestrator selftest | `-Action Selftest` | **13/13**, incl. N4 |
| Gate | `powershell -File scripts\gate.ps1 -Action Selftest` | **8/8** |
| Registry | `python scripts/registry-verify.py` | **13 capabilities** |
| Validator | `python scripts/registry-verify.py --selftest` | **18 rules** |

The acceptance case is our own `c01-stringobf.exe`, chosen because provenance is checkable
by file and because it needs exactly the chain:

```
round 1  native.ida.list_functions  ->  native.func.addr, native.func.named
round 2  native.ida.decompile       ->  native.dec.code, native.dec.refs
```

Seven verdict gates, and the model never writes the verdict — it proposes a claim and the
loop disposes of it: process, reachability, observation, independence, bounded claim,
uncertainty, and **discharged** ("I found nothing" is an answer only when you can name
the guards that would have found it).

**Independence is about the instrument FAMILY.** `{ghidra.decompile, ida.decompile}` is
refused as corroboration: two decompilers share the blind spots that come from
reconstructing machine code into C.

Termination is computed from the artifact in three states. **DONE is distinguished from
EXHAUSTED**, and an EXHAUSTED mission names the guards it did not run and says in its own
text that it must never be read as "nothing was there".

### The two traps in this file worth remembering

- **`probe` proves a capability runs; `invoke` is what makes it CALLABLE.** A capability
  with only a probe cannot take arguments, so nothing downstream can be handed an address.
- **The plan records what was INTENDED and is never mutated.** Anything that counts "left
  to run" from the plan's own state field will claim work remains after it has finished;
  count from the evidence instead.

### Scope guard

Enumerated with `git ls-files --cached --others --exclude-standard` — 50 ms. The first
version walked the directory, recursed the 1 GB Ghidra install, and took minutes. **A
scope guard nobody waits for is not a control.** Third-party tool payloads are skipped by
name; untracked files are hashed, because a mission that writes a new tool and then
invokes it is exactly the attack it guards against.
