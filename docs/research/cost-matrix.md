# Cost matrix — measured probe costs and the routing rule they imply

**Date:** 2026-10-02 · **Source:** `w1-toolperf.md` (588 lines, agent `ToolPerf`), read in
full; every row below carries its `w1-toolperf.md:line` and the command that produced it.
**Host conditions during measurement** (`w1-toolperf.md:42-46`): `31.4 GiB` RAM total,
`3.5–5.7 GiB` available, **81.9–88.7 % used** — the parent was using the machine
throughout. This is why absolute times carry a wide spread and why the RAM figures should
be read as "peak under contention", not "peak on an idle box."

**Read this before the numbers, because the instrument was wrong first — twice**
(`w1-toolperf.md:10-32`):

1. `CIM`/`WMI` is dead on this box. A first harness sampled RSS through
   `Get-CimInstance Win32_Process` and got *nothing*, silently. The same call returned an
   empty result for `Win32_LogicalDisk`. The shipped sampler uses `psutil`.
2. The first contention runner reported `0.00 s` for a probe that had already exited — it
   timed each child from when the main loop reached `communicate()`, not from launch. A
   second version fixed the timer but built its results list *before* joining the watcher
   threads, so two of three probes read `0.00 s` again. **Had v1 or v2 been trusted, the
   report would have "measured" that concurrency is free.**

> *"Had I trusted v1 or v2 I would have 'measured' that concurrency is free."*
> — `w1-toolperf.md:26`

Only the third version (`contend.py` v3, per-child thread owns the whole lifecycle) is
trustworthy. Both earlier RSS samplers also died on `psutil.NoSuchProcess` for the Ghidra
probes — whose `java.exe` children churn constantly — and degraded to reporting **0 MB**,
i.e. **the most expensive probes looked free**. The shipped sampler records
`rssDegraded`/`rssErrors` so a degraded number can never be mistaken for a clean one.

**Harness:** `%USERPROFILE%/AppData/Local/Temp/w1perf/` (`measure2.py`, `contend.py`,
`leaktest.ps1`); raw per-run JSON in `...\w1perf\logs\`.
**Disclosed side effect** (`w1-toolperf.md:38-40`): `psutil` 7.2.2 was `pip install`ed into
`D:\Software\Developer\Python314` as the measurement instrument. Outside both repos. No
repo file, config, or manifest was touched.

---

## 1. The matrix — 15 probes, every row with its exact command

`n` = runs. `wall` min/med/max in seconds. `tree MB` = peak RSS summed over the probe
**and all its descendants**, sampled at 50–250 ms. `disk Δ` = bytes appearing in the
watched `out/` dir across a run. **Source for the whole table:
`w1-toolperf.md:58-74`.**

| # | probe | n | wall min | wall med | wall max | spread | tree MB (peak) | biggest proc | disk Δ / run | exit |
|---|-------|---|----------|----------|----------|--------|----------------|--------------|---------------|------|
| 1 | `net-reverse/tools/trustcheck.mjs` | 3 | 0.21 | **0.22** | 0.22 | 0.01 | 65.6 | node.exe 53.8 | 0 | 0 |
| 2 | `native-lab/tools/loop.mjs` | 3 | 2.11 | **2.13** | 4.12 | 2.01 | 247.9 | node.exe 135.9 | 0 | 0 |
| 3 | `scripts/smoke-tools.ps1` | 3 | 2.84 | **2.84** | 2.90 | 0.06 | 169.5 | powershell.exe 86.0 | 0 | 0 |
| 4 | `web-reverse/tools/loop.mjs` | 3 | 3.87 | **3.92** | 3.97 | 0.10 | 689.3 | node.exe 121.7 | 0 | 0 |
| 5 | `crypto-lab/tools/loop.mjs` | 3 | 4.01 | **4.27** | 5.21 | 1.20 | 129.4 | node.exe 69.9 | 0 | 0 |
| 6 | `mobile-lab/tools/loop.mjs` | 3 | 5.21 | **5.33** | 5.90 | 0.69 | 388.6 | node.exe 319.6 | ±4 B | 0 |
| 7 | `forensics-lab/tools/loop.mjs` | 3 | 6.51 | **6.95** | 22.30 | 15.79 | 144.3 | node.exe 68.5 | 0 | 0 |
| 8 | `web-reverse/tools/loop2.mjs` | 3 | 6.55 | **7.03** | 17.32 | 10.77 | 751.3 | node.exe 121.6 | 0 | 0 |
| 9 | `net-reverse/tools/loop.mjs` | 3 | 8.26 | **8.28** | 10.70 | 2.44 | 595.5 | node.exe 121.1 | 0 | 0 |
| 10 | `scripts/il2cpp-probe.ps1` | 3 | 12.34 | **12.34** | 12.48 | 0.14 | 162.4 | powershell.exe 84.4 | 0 | 0 |
| 11 | `managed-lab/tools/loop.mjs` | 3 | 13.30 | **13.46** | 14.99 | 1.69 | 188.9 | ilspycmd.exe 67.5 | 0 | 0 |
| 12 | `scripts/emulation-probe.ps1` | 6 | 17.14 | **17.68** | 22.30 | 5.16 | **1321.5** | java.exe 1118.4 | 0 | 0 |
| 13 | `scripts/ghidra-failopen-regress.ps1` | 2 | 23.84 | **24.77** | 25.71 | 1.87 | **1447.8** | java.exe 1198.6 | 0 | 0 |
| 14 | `crackme-corpus/tools/loop.py` | 3 | 113.48 | **119.48** | 139.95 | 26.47 | **1410.6** | java.exe 1189.0 | +2 B | 0 |
| 15 | `fuzz-lab/tools/loop.mjs --budget 40` | 4 | 33.10 | 704.70 | **1071.37** | 1038.27 | 542.5 | node.exe 80.8 | +2.2…+4.7 KB | 0,0,**9**,0 |

**Reproduction of any row** (`w1-toolperf.md:79-89`), e.g. row 12:

```
D:/Software/Developer/Python314/python.exe \
  %USERPROFILE%/AppData/Local/Temp/w1perf/measure2.py \
  --label emulation-probe --cwd D:/Software/Tool/WorkStation/debugger \
  --file C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe \
  '--arg=-NoProfile' '--arg=-ExecutionPolicy' '--arg=Bypass' \
  '--arg=-File' --arg scripts/emulation-probe.ps1 \
  --reps 3 --watch D:/Software/Tool/WorkStation/debugger/out --interval 0.1
```

**Not run, by instruction** (`w1-toolperf.md:76-77`): `scripts/smoke-all.ps1` — the parent
was using the machine.

---

## 2. The routing rule the numbers imply

Three tiers, derived in `w1-toolperf.md:475-518`. The rule underneath them is stated at
`w1-toolperf.md:512-518`:

> **RAM, not time, is the scarce resource.** The three heaviest probes are
> `ghidra-failopen` (1448 MB), `crackme-corpus` (1411 MB), `emulation-probe` (1322 MB) —
> all Ghidra JVMs, ~1.2–1.3 GB each. Three of them at once measured **3405 MB / 61 procs**
> on a box with 3.5 GiB free, and that is precisely where `WinError 1455` (paging file too
> small) appeared. **Serialise anything that starts a Ghidra JVM; parallelise everything
> else.**

### ALWAYS — every mission (≤ 3 s, ≤ 250 MB, no shared port)

`w1-toolperf.md:475-485`

| probe | cost | why |
|---|---|---|
| `net-reverse/tools/trustcheck.mjs` | 0.22 s, 65.6 MB, spread **0.01 s** | cheapest guard in the estate |
| `native-lab/tools/loop.mjs` | 2.13 s, 247.9 MB | cheap **but port-bound** — see §4 |
| `scripts/smoke-tools.ps1` | 2.84 s, 169.5 MB, spread 0.06 s | tool-presence check, writes nothing |

**The caveat belongs on the tier, not in it** (`w1-toolperf.md:483-485`): `native-lab` is
Tier-A by cost and **must not run concurrently with any other 8745 consumer**. Its own
`portFree()` guard turns that into a clean refusal rather than a corruption.

### ON-DEMAND — when the question type needs it (3–14 s)

`w1-toolperf.md:487-501`

| probe | run when | cost |
|---|---|---|
| `crypto-lab/tools/loop.mjs` | JWT/JOSE/crypto parsing. **binds 8791.** | 4.27 s |
| `web-reverse/tools/loop.mjs` | obfuscated JS in scope | 3.92 s |
| `mobile-lab/tools/loop.mjs` | Android/APK in scope | 5.33 s, 388.6 MB |
| `forensics-lab/tools/loop.mjs` | memory-image or pcap forensics | 6.95 s warm / **22.3 s cold** |
| `web-reverse/tools/loop2.mjs` | AST-level deobfuscation, not just strings | 7.03 s warm / 17.3 s cold |
| `net-reverse/tools/loop.mjs` | network traffic in scope | 8.28 s |
| `scripts/il2cpp-probe.ps1` | Unity/IL2CPP question | 12.34 s, spread **0.14 s** |
| `managed-lab/tools/loop.mjs` | .NET assembly in scope | 13.46 s, ilspycmd |

Whole tier B serially: **~57 s**. As one concurrent batch: **8.40 s** measured
(`w1-toolperf.md:500-501`, trial 2 of §3.4) — because none of them collide on ports.

### NEVER on a mission — dedicated cadence only

`w1-toolperf.md:503-510`

| probe | cost | why it cannot be a mission step |
|---|---|---|
| `crackme-corpus/tools/loop.py` | **113–140 s, 1410 MB, 24 procs** | 4 Ghidra launches (74 % of wall). Rebuilds the corpus with MSVC and re-derives 5 flags. Proves the *tooling*, not the mission's target. |
| `fuzz-lab/tools/loop.mjs` | **705–1071 s, 542 MB** | 12–18 minutes at the budget floor. Nightly, not per-mission. **Also not reliably green at `--budget 40`** — §5. |
| `scripts/emulation-probe.ps1` | 17.68 s, **1321 MB** | Records a `blocked` capability on a **deprecated-and-marked-for-removal** Ghidra API. Second-heaviest RAM item in the estate, zero delivered capability. |
| `scripts/ghidra-failopen-regress.ps1` | 24.77 s, **1448 MB** | Heaviest RAM item measured. It is a *harness* regression (does the wrapper fail closed?), not an analysis. Belongs on harness-change CI. |

### The distinction that makes the rule a rule

`w1-toolperf.md:368-400`. Measured boots: `node -e console.log(1)` = **0.035 s**,
`python -c print(1)` = **0.033 s**, `java -version` = **0.04 s**,
`powershell -NoProfile -Command 1` = **0.18 s**. One full Ghidra headless run on the
140.5 KB crackme, isolated: **20.7 s / 21.9 s wall, 981.7 MB / 1201.7 MB**, 23 processes.

> *"Ghidra's fixed cost is ~21 s and ~1.0–1.2 GB per launch, and it barely depends on the
> input. The JVM itself boots in 0.04 s; the ~21 s is Ghidra framework init + analysis of
> one 140 KB PE."* — `w1-toolperf.md:368-371`

So there are **two different kinds of expensive thing**:

- **Node/Python labs are compute-bound.** Interpreter boot is 0.3–1.6 % of wall. The cost is
  real work and it scales with what they examine.
- **Ghidra-backed probes are startup-bound.** `emulation-probe` at 17.68 s is *less than one*
  Ghidra launch and delivers zero capability (recorded `blocked`); its fixed-start share is
  **>100 %** (`w1-toolperf.md:386`). `crackme-corpus` is 4 Ghidra launches (74 %) plus ~35 s
  of MSVC builds and solver work.

**A cold start is not a cost.** `w1-toolperf.md:325-330`: a 21.65 s `forensics-lab` sample
inside a concurrent batch looked like contention; re-measured solo immediately after it
returned **5.99 / 6.14 / 6.40 s**, and 6.77 s in a pair test. The 21.65 s was a cold cache
first run — the same effect as row 7's 22.30 s outlier and row 8's 17.32 s.
**A single 22 s sample in this estate is a cold start, not a cost.**

**One more cost that is not RAM:** `net-reverse` and `web-reverse` spawn heavily despite
modest wall time — **60** and **51** distinct child processes, 13 concurrent at peak
(`w1-toolperf.md:402-404`). Their cost is process churn, and that is what would bite under
parallel load.

---

## 3. The contention claim — REFUTED

`HANDOFF.md:233` and `:257` assert the aggregate smoke *"contends on three Ghidra-consuming
probes and is killed by timeout"* (`w1-toolperf.md:229-231`). Three separate claims, tested
separately.

### 3.1 Do the three Ghidra-consuming probes serialise? **No.**

All three launched simultaneously by `contend.py` v3 (`w1-toolperf.md:238-253`):

```
D:/Software/Developer/Python314/python.exe contend.py --spec spec-ghidra3.json \
  --cwd D:/Software/Tool/WorkStation/debugger --timeout 1800 --interval 0.2
```

```json
{"batchWall":103.47,"batchPeakMB":3405.5,"batchPeakProcs":61,"rssSamples":379,
 "rssDegraded":false,"allPassed":true,
 "sumConcurrentWall":147.02,"maxConcurrentWall":103.47,
 "probes":[
  {"label":"ghidra-failopen","concurrentWall":25.61,"exit":0,"timedOut":false, …},
  {"label":"emulation-probe","concurrentWall":17.94,"exit":0,"timedOut":false, …},
  {"label":"crackme-corpus","concurrentWall":103.47,"exit":0,"timedOut":false, …}]}
```

**The refutation, as an arithmetic identity** (`w1-toolperf.md:255-261`): solo medians for
the same three are 24.77 + 17.68 + 119.48 = **161.93 s**; the concurrent batch wall is
**103.47 s**. So concurrency **saved ~59 s** (0.64× of serial) rather than costing time,
`allPassed: true`, and the claim "killed by timeout" did not reproduce at any concurrency
level the harness could produce. The batch is bounded by `crackme-corpus` alone, exactly as
it is when serial.

### 3.2 Does contention show up as a slowdown at all? **Yes, but only as wall-time noise.**

`w1-toolperf.md:263-276`

| probe | solo med | concurrent | Δ |
|---|---|---|---|
| ghidra-failopen | 24.77 | 25.61 | +3.4 % |
| emulation-probe | 17.68 | 17.94 | +1.5 % |
| crackme-corpus | 119.48 | 103.47 | **−13.4 % (faster)** |

**`crackme-corpus` came out faster than solo, and that is the giveaway:** the dominant
effect is **host load from the parent's parallel work**, not probe-vs-probe contention. On a
box already at 88 % RAM, wall time is not a clean signal — which is also the honest reason
this row is a *refutation with a caveat* and not a clean win.

### 3.3 What is real in that sentence, and what replaces it

`w1-toolperf.md:332-343`. Not reproduced: the contention/timeout claim. Real and
undocumented: **(a)** concurrent Ghidra work pushes the box to **3.4 GB / 61 processes** at
88 % RAM, which is where `psutil` began failing with
`OSError [WinError 1455] The paging file is too small` during the first measurement pass;
**(b)** the genuine contention is *fixed ports*, where it is a hard `EADDRINUSE`, not a
timeout. §4.

**Replacement wording, proposed** (`w1-toolperf.md:342-343`, quoted rather than invented):

> Concurrent Ghidra probes do not serialise; the batch is bounded by the longest and all
> pass. The real hazards are **peak RSS** (3.4 GB / 61 procs for three Ghidra JVMs, which
> reaches the paging-file limit on a 31 GiB box) and **fixed loopback ports**, where a second
> concurrent run of `crypto-lab` or `native-lab` fails hard rather than slowly.

### 3.4 The cheap tier overlaps cleanly, twice

`w1-toolperf.md:315-323`. Five labs simultaneously (`net-trustcheck`, `crypto-lab`,
`web-reverse`, `forensics-lab`, `mobile-lab`), two independent trials:

| trial | batch wall | sum of the five | peak MB | all passed |
|---|---|---|---|---|
| 1 | 21.65 | 36.44 | 899.3 | true |
| 2 | **8.40** | 25.10 | 1010.2 | true |

Trial 1's 21.65 s was the cold-cache artefact of §2, not contention.

---

## 4. The real hazard: fixed loopback ports. **Hard fail, not slow fail.**

This is the finding that changes what a "concurrency" fix should look like. A timeout
degrades; an `EADDRINUSE` does not.

`w1-toolperf.md:283-293`:

| pair | ports | batch wall | sum | peak MB | all passed |
|---|---|---|---|---|---|
| 2 × `crypto-lab` | both bind **8791** | 4.81 | 4.89 | 128.2 | **false** |
| 2 × `native-lab` | both bind **8745** | 2.02 | 3.10 | 333.2 | **false** |

```
  crypto-lab-A 0.08 s exit 1 |
  crypto-lab-B 4.81 s exit 0 | JSON-SUMMARY {"total":17,"pass":17,"fail":0}
  native-lab-A 1.08 s exit 1 | JSON-SUMMARY {"total":2,"pass":1,"fail":1}
  native-lab-B 2.02 s exit 0 | JSON-SUMMARY {"total":15,"pass":15,"fail":0}
```
Quoted verbatim from `w1-toolperf.md:289-292`. The two `exit 1` rows are the port losers;
the two `exit 0` rows are the winners. Note `native-lab-A` still prints a
`JSON-SUMMARY {"total":2,"pass":1,"fail":1}` — it reports the collision as a **failed
control** rather than crashing, which is the `portFree()` guard of §4's last paragraph.

The loser's stderr, reproduced (`w1-toolperf.md:297-301`):

```
loop: Error: listen EADDRINUSE: address already in use 127.0.0.1:8791
    at Server.setupListenHandle [as _listen2] (node:net:2167:16)
    at listenInCluster (node:net:2224:12)
    at node:net:2448:7
```

**Port sources** (`w1-toolperf.md:304-308`): `crypto-lab/lab/server.mjs:318`
(`port = 8791`); `native-lab/tools/ida-client.mjs:23` and `native-lab/tools/loop.mjs:22`
(`PORT = 8745`); the `net-reverse` TLS origin `127.0.0.1:8443`
(`net-reverse/README.md:113`); `scripts/ghidra-headless.ps1 -Http` on `127.0.0.1:8080`
(`docs/TOOLS_INDEX.md:39`).

**The asymmetry, which is a real finding** (`w1-toolperf.md:310-313`): `native-lab` degrades
more gracefully than `crypto-lab` — it has a `portFree()` guard (`loop.mjs:105`, `:122`) and
reports `{"total":2,"pass":1,"fail":1}` rather than crashing. **`crypto-lab` has no such
guard and dies on an uncaught `EADDRINUSE`.** So the two labs present the same shape of
hazard at two different severities, and a reader of the summary table alone cannot tell.

**What else would also have produced the same observation:** a firewall rule or an
orphaned listener from a previous run. The evidence that discriminates is the stderr —
`EADDRINUSE` on the exact port with the exact source line, and `allPassed: false` only for
the colliding pairs and not for the non-colliding five-lab batch of §3.4.

**Consequence for the routing rule:** "parallelise everything else" is safe only because the
Tier-B set has no overlapping port. Adding a fifth lab to that batch, or running any
mission that touches 8791 or 8745 in parallel with a smoke, inherits a crash.

**Cross-reference:** all ten range ports are currently closed and Docker is stopped
(parent-measured 2026-10-02). The hazard is latent, not firing.

---

## 5. `fuzz-lab --budget 40` — an unexplained failure mode, not a number

**Four runs, and the spread is the finding** (`w1-toolperf.md:531-540`):

> 4 runs: `1071.37 s` exit 0, **`33.10 s` exit 9**, `704.70 s` exit 0, `982.05 s` exit 0.

The matrix row carries the same: wall min **33.10**, med 704.70, max **1071.37**, spread
**1038.27** (`w1-toolperf.md:74`).

**The 33.10 s run exited 9 and failed the negative control.** From the captured output
(`w1-toolperf.md:203-214`):

```
fuzz-lab — run id fuzz-2026-10-01T17-36-01-544Z
  budget 40 inputs/target · 2 mutation steps max · 4000ms/input ceiling · 192MB heap ceiling
1. corpus — built from other labs, hashed, and proven stable across two builds
     network 6 · forensic 10 · crypto 5 · web 6   (27 seeds)
4. negative control — a deliberately fragile parser MUST be caught
  PASS  pcap: the flawed twin was caught … 1 finding(s)
  PASS  jose: the flawed twin was caught … 13 finding(s)
  PASS  forensic-pf: the flawed twin was caught … 10 finding(s)
  FAIL  web-triage: the flawed twin was caught (nested quantifier …) SURVIVED — the harness
        cannot tell a robust parser from a fragile one, so its clean runs mean nothing
```

**This is an unexplained failure mode and is recorded as one.** Three things are known and
one is not:

- **Known:** the run failed its negative control — the `web-triage` flawed twin **survived**,
  which the harness itself describes as meaning its clean runs mean nothing.
- **Known:** the source warns about exactly this budget sensitivity
  (`fuzz-lab/tools/loop.mjs:57-65`).
- **Known:** the 33.10 s run finished in **1/20th** the time of the others, which
  `w1-toolperf.md:537-538` says *"suggests it short-circuited rather than ran fully"*.
- **Not known:** why. The 1038.27 s spread across four runs of an identical command is not
  explained, and a 33.10 s outlier that is also the only non-zero exit is not explained by
  a slower host.
- **Consequence, and it is the consequence that matters:** the documented floor of 40 **is
  not a reliable floor** (`w1-toolperf.md:535`). A harness whose clean runs can mean
  nothing and whose failure is not reproducible is not a regression gate at any cadence.

**Recorded, not patched** — this is a harness-reliability finding outside the measuring
agent's brief.

---

## 6. Disk cost, and the two claims that did not reproduce

### 6.1 Per-run disk deltas are flat

`w1-toolperf.md:408-423`, after ~25 probe runs:

| location | size |
|---|---|
| `out/` | 0.58 MiB, 8 files |
| `crackme-corpus/out/` | 12.57 MiB, 5285 files |
| `fuzz-lab/out/` | 0.02 MiB, 1 file |
| `fuzz-lab/crashes/` | 4.99 MiB, 101 files (gitignored) |
| `headless-lab/out/` | 0.21 MiB, 8 files |
| `managed-lab/out/` | 1.33 MiB, 437 files |
| `mobile-lab/out/` | 4.33 MiB, 41 files |

Per-run deltas: `crackme-corpus` **+2 bytes/run**, `fuzz-lab/out` **+2.2…+4.7 KB/run**,
everything else **0 bytes**. Every lab rewrites its output in place. `fuzz-lab/crashes` grew
97 → 101 files across the runs — the only directory trending upward, gitignored by design.

### 6.2 Did `E:` grow? **No — it did not move by a single unit.**

`w1-toolperf.md:425-434`:

```
Start of session : E: 28.014 GiB free  (28686.8 MiB)
After 14 Ghidra runs, contention trials, 5 crackme runs: E: 28.014 GiB free (28686.8 MiB)
```

Command: `Get-Volume -DriveLetter E | Select-Object SizeRemaining` — identical to the byte
before and after ~25 probe executions. **Why:** Ghidra projects go to `%TEMP%` on **C:**,
not `E:` (`w1-toolperf.md:436-444`).

**And the number I re-measured today, with its date and command, because a recorded number
decays.** This dossier's `E:` figure appears in at least three source reports and is worth
pinning:

```
$ powershell -NoProfile -Command 'Get-Volume -DriveLetter E,D | Select DriveLetter,@{n="SizeGiB";e={[math]::Round($_.Size/1GB,2)}},@{n="FreeGiB";e={[math]::Round($_.SizeRemaining/1GB,2)}}'
DriveLetter SizeGiB FreeGiB
----------- ------- -------
          D  640.12  165.13
          E   33.67   28.01
```
(measured 2026-10-02 by this dossier, `docs/research/cost-matrix.md`)

`E:` free agrees with `w1-toolperf.md:428` and with the parent's figure. `D:` does **not**
agree with `w1-agentworkflow.md:46`, which recorded `168.42` free of 640.12 measured the
same day; today it is **165.13**. **Three capacity figures have gone stale in this project
before** (73.7, 20.17/15.19, ~14), and this is now a fourth: the same command, the same day,
a 3.29 GiB difference, because the disk is live. Any figure about disk in this dossier
carries its date for that reason.

### 6.3 The handoff's leak claim — not reproducible

`HANDOFF.md:254` claims *"18.1 MB of stale `%TEMP%\ghidra-proj-*` on `E:` — 5 directories
that hold data."* Measured (`w1-toolperf.md:446-467`):

```
BEFORE  ghidra-proj count=1  bytes=586
run 1: exit=0 wall=20.7s files=520 bytes=671991  -> ghidra-proj count=1 bytes=586
run 2: exit=0 wall=21.9s files=520 bytes=671991  -> ghidra-proj count=1 bytes=586
AFTER   ghidra-proj count=1  bytes=586
E:\ count=0   (no ghidra-proj-* on E: at all)
```

There is no `ghidra-proj-*` on `E:` (count 0); on `C:` there is **one** directory holding
**586 bytes**, not 5 holding 18.1 MB. Two further headless runs left the count and byte
total unchanged, so the leak is fixed for *new* runs — but the 5-directory/18.1 MB cleanup
item describes a state this box is not in, and `HANDOFF.md:235`'s "the VHDX never returns
bytes" is consistent with `E:` never having been touched by these probes at all.

**That open item can likely be closed. Nothing was deleted** — deleting is an Owner
decision.

---

## 7. Two probes whose "exit 0" does not mean what it looks like

Recorded here because a cost table that does not carry this invites a false capability
claim, which is the standard this dossier holds (`README.md:20-21`).

**`emulation-probe.ps1` exits 0 while printing `fail:1`** (`w1-toolperf.md:156-172`):

```
PCODE EMULATION BLOCKED -- recorded, not claimed.
  steps executed   : 15
  decoded          : null
  expected         : FLAG{c01_string_table_xor}
  output non-zero  : False
  error            : emulator halted at PC=0x0
  DEPRECATION ... EmulatorHelper and DefaultEmulator are deprecated and marked for removal.
JSON-SUMMARY {"total":1,"pass":0,"fail":1}
```

Correct by design — `smoke-all.ps1:62` gates on the `PCODE EMULATION BLOCKED` token, not on
the count — but it means **"exit 0" from that probe does not mean "capability works"**. It
is also the second-heaviest RAM item in the estate for a verdict recorded as `blocked`.

**`fuzz-lab --budget 40` is not reliably green** — §5.

---

## 8. What is UNVERIFIABLE here

Carried from `w1-toolperf.md:549-558` without softening, because a cost model that hides
its bounds is a claim.

| item | what is missing | what would measure it |
|---|---|---|
| **Python peak RSS baseline** | `python -c print(1)` returns in 0.033 s — faster than the 20–50 ms sampler interval, so `psutil` recorded **0.0 MB**. The 0.033 s *time* is real; the RSS is not measured. | sampler at ≤5 ms, or `Get-Process -Id $pid` immediately after start |
| **Aggregate `smoke-all.ps1` total** | forbidden by the brief | run it on an idle box; it prints per-probe seconds (`smoke-all.ps1:141`, printed at `:149`) and a `JSON-SUMMARY` with `total`/`pass`/`fail`. Per-probe medians here sum to ~**1,050 s** with fuzz-lab, ~**360 s** without, against the recorded ~270 s aggregate — **but that aggregate ran a different probe set, so the two numbers are not comparable and they are not reconciled here** |
| **Idle-box wall times** | host at 81.9–88.7 % RAM throughout; spreads are wide (crackme 26.5 s, fuzz 1038 s) | re-run the matrix on an idle host; expect medians to fall and spreads to collapse |
| **`fuzz-lab` at budget 90** | 12–18 min per run | `node fuzz-lab/tools/loop.mjs --budget 90` × 3 on an idle box |
| **Per-probe `E:` attribution** | `E:` never moved, so there is nothing to attribute. Ghidra writes to `C:` `%TEMP%` | nothing to measure — this is a settled negative |
| **20+ PowerShell lab wrappers** | the underlying `tools/loop.mjs` entry points were measured; the wrappers add an untimed layer | `measure2.py --file powershell.exe --arg -File scripts/<lab>.ps1 --arg loop --reps 3` per wrapper |

**Dependencies on siblings, not fetched** (`w1-toolperf.md:560-570`): a `portFree()` guard
for `crypto-lab` (parity with `native-lab`) belongs at `crypto-lab/lab/server.mjs:318`;
`manifests/capabilities.json` has no cost fields, and adding measured `wall_s` /
`peak_rss_mb` per capability would let `gate.ps1` refuse an over-budget mission.

---

## 9. Reproduction

```bash
# any matrix row (harness: %USERPROFILE%/AppData/Local/Temp/w1perf/)
D:/Software/Developer/Python314/python.exe \
  %USERPROFILE%/AppData/Local/Temp/w1perf/measure2.py \
  --label <probe> --cwd D:/Software/Tool/WorkStation/debugger \
  --file <interpreter> --arg=<flag> ... \
  --reps 3 --watch D:/Software/Tool/WorkStation/debugger/out --interval 0.1

# the refuted contention claim (§3.1)
D:/Software/Developer/Python314/python.exe \
  %USERPROFILE%/AppData/Local/Temp/w1perf/contend.py --spec spec-ghidra3.json \
  --cwd D:/Software/Tool/WorkStation/debugger --timeout 1800 --interval 0.2

# the port collisions (§4) — allPassed:false is the assertion
#   2 x crypto-lab (8791) and 2 x native-lab (8745)

# the stale-number check (§6.2)
powershell -NoProfile -Command 'Get-Volume -DriveLetter E,D | Select DriveLetter,@{n="SizeGiB";e={[math]::Round($_.Size/1GB,2)}},@{n="FreeGiB";e={[math]::Round($_.SizeRemaining/1GB,2)}}'
```

---

## 10. The one sentence

The handoff's contention claim is **refuted** — three concurrent Ghidra probes cost **103.47 s**
against a **161.93 s** serial sum, all pass, and the batch is bounded by the longest; the real
hazards are **peak RSS** (3.4 GB / 61 procs for three Ghidra JVMs) and **fixed loopback
ports**, where a second concurrent `crypto-lab` or `native-lab` does not run slowly, it
**exits 1 on `EADDRINUSE`** — and one probe in the estate, `fuzz-lab --budget 40`, spans
**33.10 s to 1071.37 s** across four runs with **one of them exiting 9** on a negative
control that survived, which is a failure mode this document records rather than explains.
