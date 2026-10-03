STATUS: DONE

# Atomic-artifact integrity survey — report

**Delivered:**
- `scripts/verify-atomic-artifacts.py` (new) — runs clean, **exit 0**
- `evidence/atomic-artifacts.md` (new) — table, control transcript, ranked list

**Committed and pushed** (see "Commit" below). No producer script was modified. Nothing under
`<project>/<private-tree>` was touched. `manifests/capabilities.json`, `scripts/assert-probes.py`,
`scripts/registry-verify.py`, `scripts/doc-facts.py` and `scripts/verify-all.ps1` were read
only.

---

## The headline

The brief's premise was **half wrong, and the half that was wrong is the worse half.**

I could **not** produce a byte-truncated artifact, and I can say why with a measurement rather
than a shrug: every producer writes with ONE whole-file write, so the window a kill must land
inside is ~0.15–0.26 ms, while `taskkill /F /T` takes ~290–390 ms to deliver. The kill is
**~1500–2000× too slow**. Zero truncations in **710 ad-hoc trials** plus 20 in the delivered
script.

But that made the real hazard visible, and it is worse than truncation:

> **6 of 6 runs of `node net-reverse/tools/loop.mjs`, killed mid-flight, were accepted as
> PRODUCED by `assert-probes.py`'s own `check_produces` — with zero DRIFT messages.**

That command runs **six** steps. Only step 1 writes the artifact. Each killed run left a
**complete, parseable** `corpus.json` listing all 5 captures — and nothing in it records that
the 16 pcap questions, the two replays, the CDP interception and the trust-isolation check
never ran. The next window hashes that file and treats it as ground truth.

A truncated file at least fails `json.loads`. A complete file that is silent about 5 of 6
steps does not.

## Survey result

**28 producers. 1 ATOMIC. 8 UNGUARDED. 15 direct-with-marker. 4 readers.**

Every write goes to the **final path**. One temp-then-rename in the whole station:
`mobile-lab/tools/loop.mjs:109-110`, whose source at `:104` states the hazard in the author's
own words. It was applied in 1 of 28 places. No streaming writers exist anywhere (a repo-wide
search for `createWriteStream` / `appendFile` / `writeSync` / `openSync` returns nothing).

Two producers already have real completion markers, arrived at independently:
`scripts/ghidra/ExportDecompile.java:96` (writes `summary.json` last, gated on by existence at
`ghidra-headless.ps1:130`) and `scripts/mission.ps1:1716` (`termination.reason`).

## Mutation proof

A control that cannot fail proves nothing, so C2 carries its own: the identical harness,
pointed at a stub that writes nothing, against a real artifact already on disk.

```
    binding_state      stale
    drift_messages     1
    goes RED           True
```

`fresh` is a verdict the harness earned, not a default. The binding **does** catch a producer
that touches nothing — I am not proposing to replace it, and the script says so.

## Verification actually run

```
python scripts/verify-atomic-artifacts.py --c1-trials 20 --c2-trials 6    -> EXIT=0
  28 producers surveyed
  truncated artifacts produced: 0 of 20
  write window 0.263 ms / kill latency 391.5 ms / ratio 1490.9x
  KILLED RUNS THE BINDING ACCEPTED AS PRODUCED: 6 of 6
  mutation: binding_state=stale, goes RED=True
```

Every producer's cited write line was checked against the file with `sed -n`. Two were wrong
on first pass and are fixed: `scripts/sync-wiki-figures.py` is **L174** (not L153) and
`scripts/gate.ps1` writes are **L740 / L825 / L1219** (not L725 / L810 / L1204 / L1306).
`scripts/ghidra-failopen.md` quote is **L83** (not L82). All re-verified after the fix.

## UNVERIFIED — stated plainly

- **`[UNVERIFIED]`** Whether a full disk, machine reset, or antivirus scanner produces the
  byte-level truncation C1 could not reach. Those are the realistic paths to that hazard and
  this control cannot simulate them.
- **`[UNVERIFIED]`** The 710-trial and 240-trial wide sweeps ran under ad-hoc scripts, not
  under the delivered script. Only the 20-trial C1 is re-runnable from what I ship. Both
  agree; do not cite 710 as a figure the delivered script reproduces.
- **`[UNVERIFIED]`** The write-window table (0.343 ms @ 4,896 B … 5.222 ms @ 16 MiB) is from a
  separate ad-hoc measurement, not emitted by `verify-atomic-artifacts.py`.
- `tshark` is **not installed on this box**, so C2's loop fails fast at step 2 every trial.
  This does not weaken the finding — the artifact is written by step 1 — but a box with
  `tshark` would widen the window between "artifact written" and "run finished".

## Numbers that will move on re-run

`uninterrupted run`, `write window`, `kill latency` and `ratio` are re-measured every run and
vary (observed: 53.7–59.3 ms, 0.146–0.263 ms, 289–391 ms, 1490×–1982×). The **verdicts are
stable**: 0 truncated in 20, and 6 of 6 accepted in every run. This is noted in the evidence
file so a verifier does not read a different magnitude as a refuted finding.

## NEXT — for the next window

1. **The finding worth acting on is not the write mechanism.** It is that no artifact records
   *what else the run was supposed to do*. `corpus.json` describes a corpus; its probe command
   also answers 16 questions, replays two streams, and checks trust isolation. A manifest that
   lists expected steps with the completed ones ticked would close C2. `scripts/mission.ps1`
   already won exactly this argument for itself.
2. **Not fixed, deliberately** — the brief says report only, and another worker may be editing
   lab scripts. The three fix shapes all already exist in-repo: staged write
   (`mobile-lab/tools/loop.mjs:104`), sentinel-last-gated-on-existence
   (`ExportDecompile.java:96` + `ghidra-headless.ps1:130`), self-describing termination
   (`mission.ps1:1716`).
3. **Highest-value single change** would be `scripts/sync-wiki-figures.py:174` — the only
   producer writing tracked files outside `%TEMP%`, in place, with no marker. But that writes
   into `<project>/<private-tree>`, which this brief put off-limits.
4. **I did not wire this into `scripts/verify-all.ps1`** — also off-limits per the brief. The
   script takes ~14 s including two control suites, so it could be a `--list`-only or a
   sampled entry; that is a call for whoever owns `verify-all.ps1`.

## Commit

Committed and pushed on `main`, containing **only** the two new files. No existing file was
modified, so nothing could strand a sibling's work in the tree.

```
scripts/verify-atomic-artifacts.py   (new)
evidence/atomic-artifacts.md         (new)
```