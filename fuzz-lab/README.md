# fuzz-lab — mutation fuzzing with a differential oracle

Self-authored mutation fuzzer, in Node, with **zero dependencies and zero install**. It
points at this repository's own parsers and it found four real robustness defects in them,
all fixed, all now guarded by a regression case that runs on every invocation.

This is **not** a state-of-the-art fuzzer and does not claim to be. There is no AFL here,
no honggfuzz, no coverage instrumentation, no dictionary, no `-x` cross-over, no
persistent corpus, no fork server. What it is: mutation fuzzing with a differential
oracle, and the discipline that comes with it. The honest-limits section says exactly
what that costs.

```
powershell -File scripts\fuzz-lab.ps1 loop
# or, from this directory:
node tools\loop.mjs
```

Exit `0` means the whole chain held on this machine, in that run. Exit `9` means an
assertion failed and the table says which. **Exit 0 is not available to a run that found
nothing**: the negative control fails any run where a deliberately fragile parser
survived, because a fuzzer that cannot catch a parser with no bounds checks has not
demonstrated that it can catch anything.

## The one thing worth teaching

Fuzzing "feeds bytes to a tool and watches for crashes". The part that actually matters
to an analyst is narrower and harder:

> **A parser that meets hostile input must produce a decision, not a corpse.**

Concretely, when you point a parser at a file from an evidence seizure, one of four things
happens, and only three of them are acceptable:

| outcome | meaning | verdict |
|---|---|---|
| `parsed` | the input is in the accepted region | fine |
| `rejected` | refused, in a way the parser *declares* | **fine — this is the correct answer** |
| `uncaught` | threw something nobody intended (RangeError, TypeError, stack overflow) | **finding** |
| `hang` | did not return within the ceiling | **finding** |
| `memory` | aborted at the heap ceiling | **finding** |

The line between `rejected` and `uncaught` is the whole lab. A parser that catches
everything and refuses everything is not robust, it is useless — and a fuzzer that
reports only crashes will call it clean. So each target here declares what it considers a
refusal, and anything outside that declaration is a finding even though it is technically
an exception too.

## What was fuzzed

Four targets, in priority order. Three are pre-existing parsers from other lanes that had
never been fuzzed; one is a reader this lab had to write.

| # | target | parser | kind | seeds |
|---|---|---|---|---|
| 1 | `pcap` | `fuzz-lab/lab/pcap-reader.mjs` (**written for this lab** — see below) | binary | 6 |
| 2 | `jose` | `crypto-lab/lab/jose.mjs` + `crypto-lab/tools/analyze.mjs` | text | 5 |
| 3 | `forensic-pf` | `forensics-lab/tools/triage.mjs: parsePrefetch` | binary | 7 |
| 4 | `web-triage` | `web-reverse/static/lib/triage.mjs: triage + residuals` | text | 6 |

**On target 1, stated plainly because it would be easy to hide:** the station had a pcap
*writer* (`net-reverse/lab/pcap-writer.mjs`) and no pcap *reader* in JavaScript — net-reverse
reads captures by shelling out to tshark, and a third-party dissector is not a target this
lab is entitled to claim. So `fuzz-lab/lab/pcap-reader.mjs` is a new in-tree parser, written
for the fuzzer. A finding in it is a real finding about this repository, but it was written
knowing a fuzzer was coming, which is not the situation of the other three. The other three
are the interesting ones, and they are where the unpredicted findings were.

## The corpus

Every seed is a real artifact another lab in this tree already produces, rebuilt from its
deterministic generator — never random bytes, because a mutation fuzzer spends nearly all
of its budget on structurally hopeless inputs and a random seed set is the definition of
that. A seed the real parser already accepts means mutations start one edit away from the
accepted region instead of one edit away from nothing.

27 seeds, and the loop builds the corpus **twice** and requires identical hashes, so
"deterministic" is measured rather than asserted:

```
network   pcap/dns-basic                       436 B   9bae23b350aaf821…
network   pcap/http-basic                     1783 B   8bfe86dacc753588…
network   pcap/tls-clienthello                1554 B   3ad72cbff6ac0f30…
network   pcap/odd-port                       2450 B   feb1c0cfbfcb090d…
network   pcap/dns-txt                         517 B   87cd733158befe3b…
network   pcap/self-authored                   110 B   8355e623973f378f…
forensic  pf/SYSTEM.EXE-9E4F9A14               140 B   54d02af62439e0ed…   (x7 records)
forensic  tsv/amcache                          959 B   a0d0d3f580bd228f…
forensic  tsv/srum                             477 B   f1225ff8812e92e3…
forensic  image/d12-lab-image                151552 B   35a6a51d5cc607af…
crypto    jose/{strong,none-alg,weak-claims,jku-header,jwe-shape}      99–218 B
web       6 committed JS sources, 9–39 KB, named by repo path
```

The `web` seeds are committed files read as text, **not** the obfuscated artifacts
`web-reverse/static/gen-obf.mjs` produces. That generator is not byte-deterministic —
javascript-obfuscator draws from an internal RNG its `--seed` flag does not reach, and two
runs with the same seed gave different bytes (measured: `signer-obf.js` `877ac287…` vs
`6672d330…`). `assertDeterministic` caught it, which is the only reason that assertion earns
its place. The committed sources turned out to be the better seed anyway: `triage.mjs` is
handed plain JS text in production, and a 39 KB real ESM source exercises the line/byte
heuristic, the transpiler hints and the residual regexes far harder than a 4 KB minified
file does.

## The mutator

Twelve named strategies, all seeded from the run id, all recorded as a recipe:

| strategy | what it attacks |
|---|---|
| `bitFlip` | single-byte field-width mistakes |
| `byteSet` | `==` / `<` against 0 and 0xff |
| `intInject` | **length and count fields** — a 2/4/8-byte window overwritten with a boundary integer, LE or BE |
| `truncate` | **the over-read** — cut the file, biased to just past a header boundary |
| `chunkDelete` / `chunkDuplicate` / `chunkInsert` / `chunkZero` | structure reshaping around declared counts |
| `byteSplice` / `alphabetSplice` | substituting format-legal bytes for arbitrary ones |
| `textRun` / `textRepeat` | **ReDoS** — a long run of identifier/email characters, and one character repeated tens of thousands of times |

`intInject` and `truncate` are the two that found the bugs. `textRepeat` found two more.
That is the honest shape of it: this is not a uniform random walk, it is a short list of the
mutations that break parsers, aimed at the fields that parsers trust.

## The driver

One process per input. Not for isolation — for **enforcement**.

A hang is not an exception. A regex engine backtracking through a 400 KB claim does not
return control to the event loop, does not check a deadline, and cannot be interrupted from
inside. The only way to bound it is to give up on the process. So each input runs in a child
with:

- a **hard wall-clock ceiling** (4 s default, `--hard-ms`); the parent kills and records `hang`
- a **hard heap ceiling** (`--max-old-space-size`, 192 MB default); V8 aborts rather than grows,
  and the abort is recorded as `memory`

`worker.mjs` deliberately has **no self-abort timer**. An earlier draft had one, on the
theory that a worker should be able to notice its own overrun. It cannot, for the reason
above, and it would have looked like a safety net while being dead code.

## Findings

Four real defects in this repository's own parsers. Every one was found from a mutated
seed, reproduced from its recipe, delta-debugged to a reduced case, fixed, and added to the
regression corpus.

### 1. `forensics-lab/tools/triage.mjs` — `parsePrefetch` reads past the end of the file

`uncaught` · **fixed**

The guard was `b.length < 16`, and the parser then read a `u32` at offset **72** and a
`u64` at offset **76**. A 20-byte file with the right 4-byte magic passed the guard and died
in `readUInt32LE` with `ERR_OUT_OF_RANGE`. `Math.min(n, 64)` capped the *count* but not the
*file*: with `n = 8` declared and a 76-byte file, the loop read 8 bytes at offset 76 through
140, and every one of those was past the end.

The failure mode is the wrong kind, which is what makes it a real defect: an **uncaught
exception**, not a refusal. A forensics tool that dies with a stack trace on a truncated
prefetch record has told the analyst nothing about the artefact.

Fix: the bounds are derived from the record layout (`PF_COUNT_OFF` / `PF_TABLE_OFF`) and
truncation is *reported* — `truncated: true` plus a `truncation` string saying how many of
the declared slots actually fit. That follows the rule the rest of that file already
follows: a corrupt artefact must produce a finding about the artefact, never a dead tool.
All 7 real fixture records still parse identically.

### 2. `crypto-lab/tools/analyze.mjs` — `EMAIL_VALUE_RE` is quadratic

`hang` · **fixed**

```
/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/
```

Measured on a single claim value, and it is clean n²:

| input | 50 k | 100 k | 200 k | 400 k |
|---|---|---|---|---|
| wall clock | 0.7 s | 3.6 s | 15.8 s | **54.0 s** |

A JWS payload is attacker-controlled text and a token is meant to be a few hundred bytes. The
analyzer whose entire job is telling you a token is suspicious was the thing that hung — and
it hung silently, with no exception and no output, which is the worst way for a triage tool
to fail.

Fix: anchor the local part to a non-atom character so there is exactly one way to enter the
match, and bound every quantified run. 400 k is now 11 ms; 1.6 MB is 14 ms. The matched
address set is unchanged, verified in both directions.

### 3. `web-reverse/static/lib/triage.mjs` — `residuals.tableAccessorCalls` is quadratic

`hang` · **fixed**

```
/[_$\w]+\s*\(\s*0x[0-9a-fA-F]+\s*\)/g
```

`[_$\w]+` and the `\w` reachable past the group are ambiguous, so the backtracker explores
the overlap. A 300 KB run of identifier characters took `residuals()` **22 seconds**; the
input is untrusted JS text, because it is the thing being triaged.

Fix: anchor the identifier start to a non-identifier character, bound both runs. 300 k is now
1 ms. Match counts identical on a fixed positive/negative set and on a real obfuscated
artifact.

### 4. `web-reverse/static/lib/triage.mjs` — `TRANSPILER_HINTS[nullish-lowering]` is quadratic

`hang` · **fixed** — *found by the fuzzer, not by reading*

```
/\w+ !== null && \w+ !== void 0 \? \w+ :/
```

Three unbounded `\w+` runs with literals between them; on a long identifier run the engine
retries every start position and every split of the first run. A 200 KB run took `triage()`
**8.7 seconds**.

This one is worth dwelling on, because it is the finding that justifies the whole exercise.
Findings 2 and 3 are `residuals`/analyzer regexes — the kind of thing you find by staring at
a regex. This one sat in a *different function* in the *same file*, was not in any list, and
was found because the fuzzer appends 400 000 copies of a random character and waits to see
whether anything comes back. The neighbouring `optional-chaining-lowering` hint has the same
shape and was left alone: its first branch is anchored on a literal `===`, so it never enters
the quadratic path (measured 0 ms on the same input).

Fix: bound each run to 64 characters — longer than any identifier Babel emits for this
construct. 200 k is now 18 ms, 1.6 MB is 145 ms, matched set unchanged against real lowered
output.

## The negative control

This is what separates a capability from a random crash generator. Every target has a
**deliberately flawed twin**: the same parser with one specific guard removed, written to be
the mistake an analyst actually makes when they write their own version.

| target | the flaw | caught |
|---|---|---|
| `pcap` | reads `incl_len` straight into `subarray` with no bounds check, no captured-length cap, no record-count cap | yes |
| `jose` | no ceiling on segment length or claim-value length; `JSON.parse` straight onto attacker bytes | yes |
| `forensic-pf` | loops `n` times where `n` is a `u32` from the file, no cap, no per-iteration bounds check | yes |
| `web-triage` | nested quantifier `[_$\w]+(\s*\(\s*0x[0-9a-fA-F]+\s*\))+` | yes |

The pcap twin is the clearest illustration of why this matters, because its defect is
**silent** rather than loud:

```
hostile record: incl_len = 1000, 4 bytes of frame actually present
  reference : 0 packets, truncated: true
  flawed    : 1 packet, capturedLength: 1000, data.length: 4   <-- the report lies
```

`Buffer.subarray` clamps, so the flawed reader does not crash — it returns a frame that is
4 bytes long while reporting it as 1000. An analyst reading that report would believe they
had a kilobyte of captured traffic. A fuzzer that only watches for exceptions sees nothing
here. This is the argument for a differential oracle over a crash-counting fuzzer, and it is
why the lab asserts on *behaviour under the same input* rather than on crashes.

**A surviving twin fails the run.** If the harness cannot tell a robust parser from a
fragile one, its clean results on the other three targets mean nothing, and the loop says so
instead of printing a green line. That check has already earned its place once: an early run
reported `web-triage: the flawed twin SURVIVED`, and the cause was that `textRepeat` topped
out at 60 000 characters — below the 4 s ceiling for a quadratic regex, so the flaw was
genuinely unreachable. That was a false negative that read exactly like a real one, and the
fix was to widen the strategy until the flaw is reachable, not to weaken the assertion.

## Reproducing a crash without storing it

The reproducer **bytes are gitignored**. What is recorded is the recipe: run id, target,
variant, seed sha256, the ordered strategy chain, the reduced length and the reduced hash.
That is a complete description of the input, so the input is reconstructible without being
stored.

```bash
node fuzz-lab/tools/replay.mjs                                  # list every recorded crash
node fuzz-lab/tools/replay.mjs web-triage reference a1b2c3d4e5f6 # re-derive and re-run one
```

`replay.mjs` rebuilds the seed from the generators, replays the recipe, and requires the
bytes to hash to what the crash record says. It exits `5` on a hash mismatch.

Real transcript, trimmed to the summary. `--budget 60` is 480 child processes, one per
input-variant pair, which is the price of a real per-input ceiling.

```
$ node tools/loop.mjs --budget 60
  seeds                27 across 4 groups, all hashes stable across two builds
  inputs executed      480 (60/target x 2 variants x 4 targets), one process each
  reference outcomes   parsed 160 · rejected 79 · uncaught 1 · hang 0 · memory 0
  flawed-twin outcomes parsed 198 · rejected 0 · uncaught 37 · hang 5 · memory 0
  reference findings   1  (jose:uncaught)
  flawed-twin findings 12  (the negative control)
  regressions holding  6/6
  elapsed              682.3s

  PASS  two consecutive builds produce byte-identical seeds          27 seeds, all hashes match
  PASS  pcap: every input was executed against both variants         120/120
  PASS  jose: every input was executed against both variants         120/120
  PASS  forensic-pf: every input was executed against both variants  120/120
  PASS  web-triage: every input was executed against both variants   120/120
  PASS  every triaged finding reproduced from its recipe, minimised, and re-verified
                                                                    13/13 sampled (43 found, 30 same-class)
  PASS  pcap: the flawed twin was caught                             4 findings — first: uncaught at #3, 16 B
  PASS  jose: the flawed twin was caught                             21 findings
  PASS  forensic-pf: the flawed twin was caught                      12 findings
  PASS  web-triage: the flawed twin was caught                       5 findings — first: hang at #8, 369027 B
  PASS  every recorded finding now rejects cleanly (each fix holds) 6/6 regressions hold

LOOP CLOSED
```

Three numbers in that block are worth reading twice.

**`uncaught 1` on the reference column.** Not zero. The run still finds a live defect in a
pre-existing parser and reports it rather than hiding it. The four findings documented
above are fixed, so that column is nearly clean — but "nearly" is a measurement, not a
promise, and the loop prints it every time.

**`hang 5` on the flawed column.** The ReDoS twin, caught as a hang. Under a
crash-counting fuzzer those five score as "no crash", and the summary line would read the
same as a clean run.

**`13/13 sampled (43 found, 30 same-class)`.** Triage is bounded to 3 findings per
target/variant/outcome class. Triaging all 43 took 26 minutes, almost all of it
re-minimising variants of the same `RangeError`. The **finding count is complete**; only
the reduction work is sampled, and the loop prints both numbers so the sample is never
mistaken for the total.

Replay, from the recipe alone:

```
$ node tools/replay.mjs forensic-pf flawed 0bb5fb9e
crash        forensic-pf-flawed-0bb5fb9e3ec2
reduced      16 B  sha256 0bb5fb9e3ec25fd6b97c4cd9a136657482ddab655b28c59db8a6a45c31b0ad2e
re-derived   16 B  sha256 0bb5fb9e3ec25fd6b97c4cd9a136657482ddab655b28c59db8a6a45c31b0ad2e  MATCH
recipe chain 47a8c3f68d5c59ce556cd376985b3069…  matches the original run
outcome      uncaught  RangeError: The value of "offset" is out of range. It must be >= 0 and <= 12. Received 72
reproduces   YES
```

## One failure mode worth recording

Delta-debugging a **hang** removes bytes, and removing bytes makes a *threshold*
measurement unstable. A case sitting at 4.01 s during a predicate call comes back at
3.98 s during verification, with no change to the input. Five of 61 triages failed with
`minimisation lost the failure` and nothing was wrong: the reduced case was still a hang,
just under the line.

The fix is not to loosen the check. A hang whose runtime is *near the ceiling* is
inherently marginal, so it is recorded **un-reduced**, with the reduced size and the reason
in the crash note and `MARGINAL` in the transcript. Recording the original case is
strictly better than recording a smaller case that does not replay. A crash (`uncaught`)
is deterministic and never takes this path.

Why gitignore them: a reproducer is hostile input against the parsers this repository ships.
Committing it would mean putting the thing that breaks those parsers next to the parsers, in
a repository whose root `.gitignore` already excludes `*.pcap` and `*.pf` for exactly this
reason. The recipe is a text file, so it is reviewable and diffable — which a `.bin` is not.

The recipe mechanism cost three runs to get right, and each failure is worth recording
because the guard that caught it is the guard that still catches it:

1. **The strategy-selection draw was not replayed.** `mutate` picks a name off the pool with
   one `rng.pick`; the replay skipped it and was one draw behind for every step. 58 of 58
   triages failed on a hash mismatch.
2. **The step-count draw was not replayed.** It was drawn by the *caller*, so the replay's
   fresh stream never consumed it.
3. **The alphabet was recorded as a size, not as values.** The replay rebuilt `0..n-1`, which
   is not the target's alphabet. 122 of 800 round-trips mismatched, every one a recipe ending
   in `alphabetSplice`.

`replayRecipe` now replays the count draw and the selection draw and **checks** the recorded
name against what the stream picks, so pool drift throws instead of returning
plausible-looking wrong bytes. 2400/2400 round-trips now reproduce exactly.

## The regression guard

A fix with no test is a fix that gets reverted by the next reader who thinks the guard is
redundant. So each finding is stored in `tools/regressions.mjs` as a reduced input, and the
loop re-runs all of them every time. Six cases, three for the prefetch over-read, two for
the analyzer ReDoS, two for the web triage ReDoS.

The assertion is deliberately narrow:

> the reduced case must no longer be an **uncaught** exception

Not "must parse" — most of these are still malformed and *should* be rejected. Not "must not
hang" — a hang and a throw are different defects, and lumping them would let a fix that
converts a 54-second stall into a 3-second one pass. The property under test is exactly the
one the defect violated: hostile input produces a declared outcome instead of an uncaught
one. The two ReDoS cases additionally carry a 1.5 s ceiling, so a fix that made the regex
linear-but-slow would still fail.

The reduced bytes live in `tools/regressions.mjs` as constructed buffers rather than as a
binary file, for the reason `.gitignore` gives: they are hostile input, and the construction
is a readable sentence about what the input *is* (`pfTruncatedHeader()`,
`webAccessorRun(300_000)`) rather than an opaque blob.

## Honest limits

**This is mutation fuzzing with a differential oracle. It is not a state-of-the-art fuzzer,
and the gap is not small.**

- **No coverage guidance.** No instrumentation, no edge counters, no feedback loop. AFL,
  honggfuzz and libFuzzer all steer by coverage; this engine can only apply a fixed list of
  mutations blind. That is the single largest difference from a real fuzzer and it caps what
  a run can reach. The compensating advantage — no build step, no compiler, no sanitizer
  runtime, `node tools/loop.mjs` and it runs — is why this lab exists at all on a box with no
  native toolchain.
- **No native or C targets.** Everything here is JavaScript. No ASAN, no UBSAN, no
  heap-overflow or use-after-free detection, because there is no instrumented binary to
  detect them in. The memory ceiling is a V8 heap cap, not a sanitizer: it catches *an
  allocation that is too large*, and nothing else. A 1-byte out-of-bounds read inside a
  Buffer is invisible to it and to this whole engine.
- **No AFL features.** No dictionary, no custom mutator, no `-x` cross-over, no persistent
  corpus across runs, no fork server, no `AFL_NO_UI`/`__AFL_SHM_ID` anything, no
  `libFuzzer`-style `-max_len`/`-timeout` split, no crash deduplication by coverage (crashes
  are deduplicated by input hash only). There is no sanitizer output and no triage of a stack
  trace, because there is no stack to triage.
- **One process per input is expensive.** Roughly 2N spawns per target per budget. The
  default budget of 90 inputs/target keeps the whole proof around 20 s; raising it costs
  roughly linearly. This is the price of a real per-input ceiling, and it is a price paid
  knowingly, not an oversight.
- **The corpus is the ceiling on coverage.** 27 seeds, all of them text or small binary
  records. A parser surface reachable only from a large or structurally unusual input is not
  reachable from here. The first four targets were the brief's priority order and they closed,
  but nothing here establishes that the *station's parsers* are fuzzed — only that these
  four are.
- **The `pcap` reader was written for the fuzzer.** Stated in the targets table and repeated
  here because it is the weakest claim in the lab: it is a new parser, authored knowing a
  fuzzer was coming. Its findings are real and its twin is caught, but "we fuzzed our pcap
  reader" means something different from "we fuzzed a pcap reader we had been running for a
  year".
- **The text targets are JavaScript-only.** `triage.mjs` and `analyze.mjs` take text, so the
  fuzzer hands them text. The `findSourceMap` data-URL path, `decodeURIComponent`, and
  `Buffer.from(..., 'base64')` are all reachable, and all three are inside a `try`, so
  malformed input there is correctly a rejection. That is a place where no finding is
  *possible*, not merely a place where none was found.
- **A `rejected` outcome is not a correctness claim.** The lab proves the parser returned a
  decision. It does not prove the decision was the *right* one — a parser that rejects
  everything passes every reference-target assertion here. Catching that needs a
  differential oracle over *answers*, not over crash behaviour, and that is a different tool.
- **Nothing is fuzzed that this repository did not write.** tshark, Wireshark, jadx, Volatility
  and DiE are all installed and all are real parsers of untrusted input, and none of them is
  in scope: a finding in a third-party binary is not a finding about this tree, and a crash
  in one is not this lab's to fix. If you want to know whether tshark survives a malformed
  pcap, that is a different project with a different authority.
- **The two ReDoS fixes bound identifier length at 64 characters.** That is a policy choice,
  not a proof: a transpiler that emitted a 200-character identifier for the nullish-lowering
  shape would now be missed. It is recorded here rather than buried because it is the one
  place where a fix trades a class of detection for a bound.

## Stop lines

- **Self-authored targets only.** Every parser under test was written in this repository.
  Nothing here was downloaded, and no third-party binary is executed or committed.
- **No exploit payloads, no malware, no evasion, no third-party targeting.** The stop
  condition is a parser in our own code misbehaving on our own input. Not a working exploit;
  not a crash in anything we do not own.
- **No hostile input in git.** `crashes/` is gitignored, and the reasons are in
  `fuzz-lab/.gitignore`. The recipe is committed; the bytes are not.
- **Loopback only, and nothing is executed.** The lab runs no server, opens no socket, and
  launches no target code. `web-reverse/static/gen-obf.mjs` is invoked to *generate* text to
  parse, and even that turned out to be unnecessary (see the corpus section) — its output
  seeds were dropped as non-deterministic.
- **Synthetic everything.** Every seed is a fixture this tree generated. No capture from a
  network, no image of anyone's machine, no token from anyone's service. The forged JWS
  strings in `tools/regressions.mjs` are signed with a published, obviously-fake constant and
  are inputs to a *parser*, not credentials to anything.
- **The heap ceiling is a safety rail, not a licence.** 192 MB per input exists so a hostile
  length field cannot take the machine down. It is not a tuning knob to raise until the box
  copes.

## Layout

```
lab/rng.mjs            xoshiro128** over a splitmix32 seed expanded from the run id
lab/corpus.mjs         27 seeds from other labs' generators; builds twice, compares hashes
lab/mutate.mjs         12 named strategies; the recipe is the inverse of the mutation
lab/pcap-reader.mjs    the pcap reader, plus the deliberately flawed twin
lab/targets.mjs        target registry: reference parser, flawed twin, rejection contract
lab/worker.mjs         one input, one process, one JSON line in and out
lab/driver.mjs         the parent: hard time and heap ceilings, the campaign, the tally
lab/triage.mjs         delta-debug minimisation, the crash store, the whole triage flow
tools/loop.mjs         the one self-judging command
tools/replay.mjs       rebuild a crash from its recipe; list the index
tools/regressions.mjs  the six reduced cases that guard the four fixes
```

Generated state lives in `%TEMP%\fuzz-lab` (corpus, scratch files for the forensic target,
`out/last-run.json`) and in the gitignored `crashes/`. Nothing is written inside the
repository except by the commands you run deliberately.
