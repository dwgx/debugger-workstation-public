# Atomic artifacts: what tells a FINISHED artifact from a TRUNCATED one

Produced by `scripts/verify-atomic-artifacts.py`. Every number below was measured by that
script at run time, or is a reading of producer source with the line number given. Nothing
here is estimated.

**Scope.** This file reports. It fixes nothing. No producer was modified.

---

## The question

`scripts/assert-probes.py` binds a capability to its bytes by recording
`(size, mtime_ns, sha256)` before a probe run and comparing after (`assert-probes.py:228`
`snapshot_produces`, `:248` `check_produces`). That is the right mechanism and it is not
being replaced. It answers one question:

> did this run touch this file?

It cannot answer the question a reader of a crash-leftover actually has:

> did this run **finish**?

Those are different questions. On this filesystem, with the write mechanisms surveyed below,
the second is not implied by the first — and control C2 shows the binding answering "yes,
produced" for a run that was killed mid-flight.

---

## 1. Producer survey

Read from source. `writes-directly` is the write mechanism; `completion-marker` is what, if
anything, says the producer finished.

| # | producer (path) | writes-directly | completion-marker | verdict |
|---|---|---|---|---|
| 1 | `net-reverse/lab/gen-pcaps.mjs` | yes (L392, L399) | manifest-last (`corpus.json` written after all 5 pcaps) | direct + marker |
| 2 | `net-reverse/lab/pcap-writer.mjs` | yes (L134) | manifest-last (returns size to caller) | direct + marker |
| 3 | `net-reverse/tools/trustcheck.mjs` | yes (L98) | **none** | **UNGUARDED** |
| 4 | `net-reverse/tools/replay.mjs` | n/a | n/a | reader |
| 5 | `net-reverse/tools/intercept.mjs` | n/a | n/a | reader |
| 6 | `fuzz-lab/tools/loop.mjs` | yes (L289) | schema-count (`ok`, `checks[]` inside the JSON) | direct + marker |
| 7 | `fuzz-lab/lab/triage.mjs` | yes (L130, L156) | index-last (`index.json` after the bytes, carries the sha256) | direct + marker |
| 8 | `fuzz-lab/lab/targets.mjs` | yes (L275) | **none** | **UNGUARDED** |
| 9 | `forensics-lab/lab/mkimage.mjs` | yes (L487, L490, L492, L494, L510) | manifest-last (`rm -rf` first, manifest last) | direct + marker |
| 10 | `forensics-lab/tools/analyze.mjs` | n/a | n/a | reader |
| 11 | `forensics-lab/tools/correlate.mjs` | yes (L89, L124) | **none** | **UNGUARDED** |
| 12 | `forensics-lab/tools/loop.mjs` | yes (L268, L324, L331) | **none** | **UNGUARDED** |
| 13 | `headless-lab/tools/authenticode.py` | yes (L88) | **none** | **UNGUARDED** |
| 14 | `native-lab/tools/disasm.py` | yes (L194) | **none** | **UNGUARDED** |
| 15 | `scripts/assert-probes.py` | yes (L171) | header-first (header carries the sha256) | direct + marker |
| 16 | `scripts/mission.ps1` | yes (L1280, L1303, L1716, L1717) | `termination.reason` in `artifact.json` | direct + marker |
| 17 | `scripts/gate.ps1` | yes (L740, L825, L1219) | sealed hash over its own canonical identity | direct + marker |
| 18 | `scripts/ghidra/ExportDecompile.java` | yes (L96) | **sentinel-exists** (`summary.json` written last; gated on at `ghidra-headless.ps1:130`) | direct + marker |
| 19 | `scripts/mobsf-agent.ps1` | yes (L56, L111) | sentinel-exists (`summary.json` last, re-read immediately) | direct + marker |
| 20 | `scripts/check-requires-tools.py` | yes (L516) | **none** | **UNGUARDED** |
| 21 | `scripts/reachability-report.py` | yes (L479, L546, L585, L603) | n/a — writes only inside its own `mkdtemp` fixture | direct + marker |
| 22 | `scripts/sync-wiki-figures.py` | yes (L174) | **none** | **UNGUARDED** |
| 23 | `mobile-lab/tools/loop.mjs` | **staged** (L109 `copyFileSync` → L110 `renameSync`) | staged + rename | **ATOMIC** |
| 24 | `mobile-lab/lab/build/build-apk.mjs` | yes (L204, L219, L231, L293, L321, L327) | self-verification (all intermediates in a pid-scoped `%TEMP%`) | direct + marker |
| 25 | `managed-lab/tools/loop.mjs` | yes (L126) | content-hash (the stamp *is* the DLL's sha256) | direct + marker |
| 26 | `crackme-corpus/tools/build-c.ps1` | yes (L59) | compiler exit (`.exe`/`.obj` written by `cl.exe`) | direct + marker |
| 27 | `web-reverse/tools/capture.mjs` | yes (`--out`) | **none** | **UNGUARDED** |
| 28 | `web-reverse/tools/recover.mjs` | yes (`--out`) | **none** | **UNGUARDED** |

**Totals: 28 producers. 1 ATOMIC. 8 UNGUARDED. 15 direct-with-marker. 4 readers.**

Every write goes to the **final path**. There is no temp-then-rename anywhere in the station
except row 23. There is no `.tmp` sentinel and no partial-file cleanup. There are **no
streaming writers at all** — a repo-wide search for `createWriteStream`, `appendFile`,
`writeSync` and `openSync` returns nothing.

Row 23 is the proof that the station already knows this is a real hazard. `mobile-lab/tools/loop.mjs:104`
says, in the source:

> Publish atomically. rename() within a volume is the one write here that another process
> cannot observe half-finished; writing straight to artifacts/mobilelab.apk is how a parallel
> reader gets a truncated ZIP and reports "not a ZIP" about a perfectly good APK.

That reasoning is correct and it was applied in exactly one place out of 28.

Row 18 is the second place the station got it right, independently: `ExportDecompile.java`
writes `summary.json` **last**, and `scripts/ghidra-headless.ps1:130` gates on the file
**existing** rather than on an exit code. `scripts/ghidra-failopen.md:83` records the rule:
*"if `summary.json` exists, Ghidra got far enough to finish."* That is a genuine completion
marker, and it is why the `native.ghidra.decompile` entry is the best-bound of the three
entries that declare `probe.produces`.

---

## 2. What a reader would mistake a truncated artifact for

The eight UNGUARDED rows, one sentence each.

- **`net-reverse/tools/trustcheck.mjs`** — A reader mistakes a truncated trust baseline for a
  machine whose root store did not change: the next run prints *"unchanged since `<at>`"* about
  a baseline that was never finished being written. The `catch` at L94 turns an unparseable
  baseline into `baselineBefore = null`, which sends the code down the "no baseline yet" path
  and **silently overwrites** the real one.
- **`fuzz-lab/lab/targets.mjs`** — A reader does not mistake it for anything: a truncated
  scratch seed becomes a fuzz **input**, so the cost is a silent change in *what was tested*,
  not a false claim. Listed for completeness; it is the cheapest row in the table.
- **`forensics-lab/tools/correlate.mjs`** — A reader mistakes a half-written carved region for
  the carved region: the `.yar` rule written at L124 *after* the carving names the exact marker
  the `.bin` is supposed to contain, so a short `.bin` and a complete `.yar` disagree in a way
  nothing checks.
- **`forensics-lab/tools/loop.mjs`** — A reader mistakes the demonstration's mutation for the
  pristine corpus: L324 overwrites `Srum.txt` with a filtered copy and L331 restores it. A
  kill between the two leaves rows **deliberately removed** on disk permanently, and the next
  window reads the lab's own negative control as the lab's real output.
- **`headless-lab/tools/authenticode.py`** — A reader mistakes a half-written signed PE for a
  signed PE: the `SECURITY` data directory is patched in memory at L86 *before* the write at
  L88, so the file announces a certificate table it does not fully contain.
- **`native-lab/tools/disasm.py`** — A reader mistakes a truncated disassembly for a short
  function: the tool's own `--count` help says it *"truncates arbitrarily, so the count says
  NOTHING about the function's extent"*, and a killed write is indistinguishable from a small
  `--count`.
- **`scripts/check-requires-tools.py`** — A reader mistakes a truncated `--dump` for a complete
  one, and goes debugging the *tools* it names rather than the dump.
- **`scripts/sync-wiki-figures.py`** — A reader mistakes a half-rewritten wiki page for a page
  with stale figures: `doc-facts.py` then reports a claim as drifted when the file was cut
  mid-rewrite, and the next window edits prose that was never wrong. This is the only row that
  writes **tracked files outside `%TEMP%`**.
- **`web-reverse/tools/capture.mjs` / `recover.mjs`** — a truncated capture in, a truncated
  recovery out; `recover.mjs` reads `obf.json` and writes `recovered.json`, so the next tool
  reads the truncated recovery as its input.

---

## 3. Control transcript

Both controls run real producers from `%TEMP%` working copies and kill them mid-flight.
Reproduce with:

```
python scripts/verify-atomic-artifacts.py
```

### C1 — is a byte-truncated artifact reachable at all?

```
  writer              net-reverse/lab/gen-pcaps.mjs
  artifact            corpus.json   (registry glob: %TEMP%\net-reverse-lab\pcaps\corpus.json)
  uninterrupted run   53.7 ms -> 4956 bytes
  trials              20, of which 17 were killed mid-run

    complete    20 trial(s)

  truncated artifacts produced: 0 of 20
  write window  (one whole-file write of 4956 B)  0.146 ms
  kill latency  (taskkill /F /T to process death)               290.3 ms
  ratio: the kill is 1981.8x SLOWER than the window it would have to land inside.
```

The transcript above is one real run. The three measured quantities vary between runs and
are re-measured every time, so **a re-runner will get different figures** — observed ranges
across four runs: uninterrupted run 53.7–59.3 ms, write window 0.146–0.263 ms, kill latency
289–391 ms, ratio 1490×–1982×. The **verdict is stable at 0 truncated in 20 trials** and the
C2 result below was 6 of 6 in every run. Only the magnitudes move.

**Result: 0 truncated artifacts in 20 kills, and the reason is measured, not guessed.**

Wider sweeps run during this investigation, all with the same outcome:
**710 kill trials** across three delay sweeps (400 trials at 44.0–46.0 ms, 150 at
2.0–19.9 ms, 160 at 0.2–24.1 ms) produced **zero** truncated manifests and zero partial
artifact sets — every survivor was a complete, parseable 4921–4956 byte `corpus.json` with
all 5 `.pcap` files. `forensics-lab/lab/mkimage.mjs` was swept 240 times the same way with
the same result: always 11 files, `manifest.json` present, image always the full 151552 bytes.

The write window and the kill latency were measured separately and are the reason. A single
whole-file write at real artifact sizes:

| payload | median write |
|---|---|
| 4,896 B | 0.343 ms |
| 23,624 B (`fuzz-lab/out/last-run.json`) | 0.351 ms |
| 151,552 B (`d12-lab-image.raw`) | 0.382 ms |
| 1 MiB | 0.768 ms |
| 16 MiB | 5.222 ms |

`taskkill /F /T` to actual process death: **median 289–290 ms** over 20 measurements. The
kill is **~1980× too slow** to land inside a 0.146 ms window. Even at 16 MiB the ratio would
be 55×.

**So the truncation hazard, as this brief framed it, is NOT reachable on this box by killing
the producer.** It remains reachable by a full disk, a machine reset, or an antivirus scanner
truncating a file in flight — none of which a kill-midway control can simulate. That is stated
here rather than glossed over, and it is the outcome the brief explicitly allows as "a
legitimate and better result."

**But C2 is where the hazard actually is, and it is worse than truncation.**

### C2 — can the real binding tell a killed run from a finished one?

The command the registry **actually declares** for `net.pcap.analyse` is
`node net-reverse/tools/loop.mjs` — not `gen-pcaps.mjs`. That loop runs **six** steps
(`net-reverse/tools/loop.mjs:40-45`): generate corpus, answer 16 pcap questions with negative
controls, replay a captured POST, replay a binary stream, rewrite a request and response in
flight over CDP, and prove no certificate or proxy was installed. Only step 1 writes the
declared artifact.

Each run below was killed mid-flight and then judged by `assert-probes.py`'s own
`snapshot_produces()` and `check_produces()`, **imported by path, not reimplemented**.

```
    kill@ms  killed  exit  artifact   captures   check_produces  drift
  --------------------------------------------------------------------
        100    True     1   present          5            fresh      0
        150    True     1   present          5            fresh      0
        200    True     1   present          5            fresh      0
        250    True     1   present          5            fresh      0
        300    True     1   present          5            fresh      0
        400    True     1   present          5            fresh      0

  KILLED RUNS THE BINDING ACCEPTED AS PRODUCED: 6 of 6
```

**6 of 6 killed runs accepted as produced, exit code 1, zero DRIFT messages.**

This is the finding, and it is not the one the brief predicted. A truncated file would at
least fail `json.loads`. What the station produces instead is a file that is **complete,
parseable, and silent about five of the six steps the command performs**. `corpus.json`
describes the corpus; nothing in it records that the 16 questions, the replay, the CDP
interception or the trust isolation check ever ran. The binding hashes the artifact, sees the
identity changed, and records the sha256 of a corpus that a killed run produced — and the next
window treats that hash as ground truth.

The evidence log makes this worse, not better. `save_evidence` (`assert-probes.py:141-171`)
writes the header **first**: command, exit code, seconds, and every artifact's sha256. A
truncated log still shows a complete-looking hash and exit code with the body cut off
underneath.

### Mutation — proof that "fresh" is a verdict and not a default

A control that cannot fail proves nothing. The identical harness, the identical call into the
identical `check_produces()`, with the producer replaced by a two-line stub that prints a
plausible string and writes nothing — against a real artifact already on disk, so the stub is
judged on *identity* rather than on absence:

```
    identical harness, producer replaced by a stub that writes nothing
    binding_state      stale
    drift_messages     1
    goes RED           True
```

The mutation goes red. `fresh` in the C2 table is a verdict this harness earned. The binding
**does** catch a producer that touches nothing — the mechanism is load-bearing and I am not
proposing to replace it. What it cannot catch is a producer that writes its artifact and then
fails.

---

## 4. Ranked by how bad a truncation would be

Ranked by what a downstream reader would conclude from a half-written or half-finished
artifact, worst first. "Marker" is the column that decides whether the reader has any way to
notice at all.

| rank | producer | what a reader concludes from a half artifact | marker? |
|---|---|---|---|
| **1** | `scripts/sync-wiki-figures.py` | Four **tracked** wiki pages have half their figures rewritten. `doc-facts.py` reports the claims as drifted and the next window edits prose that was never wrong. Writes outside `%TEMP%`, into a repo with its own history. | **none** |
| **2** | `forensics-lab/tools/loop.mjs` | The lab's forensic image is the pristine one. L324/L331 overwrite and restore `Srum.txt`; a kill between them leaves the demonstration's own mutation on disk permanently, so every finding read off it is the mutated corpus's finding. | **none** |
| **3** | `mobile-lab/tools/loop.mjs` → published `mobilelab.apk` | A ZIP that is not a ZIP. Already fixed by copy-then-rename, and the reason is written at `:104`. Listed because it is the reference implementation, not because it is broken. | staged + rename |
| **4** | `scripts/assert-probes.py` → `evidence/probes/*.log` | The evidence binding's own record is truncated while still showing a valid exit code and valid artifact hashes. The next window's ground truth is the damaged file. | header-first (misleading) |
| **5** | `net-reverse/tools/loop.mjs` → `corpus.json` (**measured, 6/6**) | The pcap lane closed. It did not: 5 of 6 steps never ran, and the binding said `fresh` with zero DRIFT. | manifest-last, silent about the rest |
| **6** | `headless-lab/tools/authenticode.py` | A signed PE. The `SECURITY` directory is patched before the write, so the file claims a certificate table it may not fully contain — the exact failure mode its own header at L82-86 documents. | **none** |
| **7** | `scripts/mission.ps1` → `artifact.json` | A mission that ran to completion. Partially protected: `termination.reason` and `scope-baseline.txt` exist, and a kill before L1716 leaves no `artifact.json` at all. | `termination.reason` |
| **8** | `net-reverse/tools/trustcheck.mjs` | The machine's root store is unchanged. A truncated baseline is silently **overwritten** rather than reported. | **none** |
| **9** | `native-lab/tools/disasm.py` | A function that is genuinely that short, rather than a `--count` truncation or a killed write. | **none** |
| **10** | `forensics-lab/tools/correlate.mjs` | A carved region containing the marker. Short `.bin` plus complete `.yar` disagree, and nothing compares them. | **none** |
| **11** | `fuzz-lab/tools/loop.mjs` → `last-run.json` | A clean fuzz run. Mitigated only by JSON format: a truncated file fails `json.loads` instead of parsing as `ok: true`. Accidental, not designed. | schema-count |
| **12** | `fuzz-lab/lab/triage.mjs` | The reproducer that was found. `index.json` is written after the bytes and carries the reduced sha256, but a reader who trusts the index without re-hashing is misled. | index-last |
| **13** | `web-reverse/tools/capture.mjs`, `recover.mjs` | A truncated capture in, a truncated recovery out; the next tool reads the truncated recovery as its input. | **none** |
| **14** | `scripts/gate.ps1` → `grant.json` | A grant. Mitigated: `grant_sha256` covers its own canonical identity, so a truncated file fails the hash and is refused on read. | sealed hash |
| **15** | `scripts/ghidra/ExportDecompile.java` → `summary.json` | A completed Ghidra analysis. Correct by design — the file is written last and gated on by existence. The model the others should follow. | sentinel-exists |
| **16** | `scripts/check-requires-tools.py` → `--dump` | A complete tool dump. Cheap: `json.dumps` is materialised before the single write. Diagnostic only. | **none** |
| **17** | `fuzz-lab/lab/targets.mjs` | Nothing — a truncated scratch seed becomes a fuzz *input*. Cheapest row in the table: a silent change in what was tested. | **none** |
| **18** | `forensics-lab/lab/mkimage.mjs` | A partial corpus. Best-behaved direct writer: `rm -rf` runs first, manifest last, so a kill leaves the old complete target or a new partial one — never a mix. | manifest-last |
| **19** | `managed-lab/tools/loop.mjs` → `.stamp` | A valid cache stamp. Correct by accident of design: the stamp's content *is* the DLL's sha256, so a truncated stamp compares unequal and the cache rebuilds. | content-hash |
| **20** | `crackme-corpus/tools/build-c.ps1` | A valid corpus binary. A truncated PE from a killed link is a PE no downstream tool here checks the length of. | compiler exit |
| **21** | `scripts/mobsf-agent.ps1` → `summary.json` | A completed MobSF scan. Written last and immediately re-read, so a truncation surfaces as a parse error at the call site. | sentinel-exists |

---

## 5. Recommendation (not applied — another worker may be editing lab scripts)

Three shapes already exist in this repository and need no new invention:

1. **Staged write.** `mobile-lab/tools/loop.mjs:104-110` — `copyFileSync` to
   `<path>.<pid>.tmp` then `renameSync`. `rename()` within a volume is atomic on NTFS.
2. **Sentinel written last, gated on existence.** `scripts/ghidra/ExportDecompile.java:96` +
   `scripts/ghidra-headless.ps1:130`.
3. **Self-describing termination.** `scripts/mission.ps1:1716` — `artifact.json` carries
   `termination.state` and `termination.reason`, so an unfinished run says so.

The gap C2 exposes is not a write mechanism at all — it is that **no artifact records what
else the run was supposed to do.** `corpus.json` describes a corpus, and the probe command
that produced it also answered 16 questions, replayed two streams and checked trust
isolation. A manifest that listed the expected steps, with the ones that ran ticked, would
close it. That is the same argument `mission.ps1` already won for itself.

---

## 6. Limits of this evidence

- **C1 and C2 are the only measured parts.** Every other row is a reading of source, with
  the deciding line number given.
- **`[UNVERIFIED]`** — I did not test whether a full disk, a machine reset, or an antivirus
  scanner produces the byte-level truncation C1 could not reach. Those are the realistic
  paths to the hazard C1 rules out for *kill-midway*, and they are untested here.
- **`[UNVERIFIED]`** — the 710-trial and 240-trial wide sweeps were run during the
  investigation with ad-hoc scripts, not by `verify-atomic-artifacts.py`. The script's own
  C1 runs 20 trials by default. Both agree; only the 20-trial run is re-runnable from the
  delivered script.
- The registry declares `probe.produces` on only 3 of 27 capabilities
  (`net.pcap.analyse`, `fuzz.differential.parse`, `native.ghidra.decompile`). Rows for the
  other producers are surveyed because they are artifact-producing and a future window will
  bind them, not because anything binds them today.
- `tshark` is **not installed on this box** (`findTshark` throws), so C2's loop fails fast at
  step 2 in every trial. That does not weaken the finding — the artifact is written by step 1
  — but a box with `tshark` present would let the loop run longer, widening the window
  between "artifact written" and "run finished".