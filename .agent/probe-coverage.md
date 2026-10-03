STATUS: DONE

# Probe coverage audit — the STRING-ONLY gap, measured

**Question asked:** for how many of the 27 capabilities is `assert-probes.py`'s own OK verdict
("NOT a claim that the instrument ran. STRINGS only.") a hollow one?

**Answer, measured: 24 of 27.** For 6 of those 24 it is worse than hollow — the checker never
executes the probe at all. 0 are grade D.

## Files

- `scripts/verify-probe-coverage.py` — new, ~320 lines, exits 0 unless it cannot read the registry
- `evidence/probe-coverage.md` — new, the table, counts, ranked list, negative-test output
- This report: `.agent/probe-coverage.md`

Nothing else was created or modified. `git status --porcelain manifests/ scripts/assert-probes.py
scripts/registry-verify.py scripts/doc-facts.py scripts/gate.ps1 scripts/verify-all.ps1` is empty
after the sweep — verified, not assumed.

## Grades and counts

| grade | count | definition |
| --- | --- | --- |
| A | 3 | exit code AND output substring AND produced artifact |
| B | 24 | exit code AND output substring |
| C | 0 | output substring only |
| D | 0 | neither — asserts nothing about the run |
| E | 0 | outside the four-grade ladder (see below) |

All 27 declare both `expect_exit` and `expect`, which is why C and D are empty. The finding is not
that the registry is lax about declaring — it is that it is *uniform*, and uniformity hides the gap
because no entry looks like an exception. The whole A-vs-B distance is the `probe.produces` artifact,
and only 3 entries name one.

The 3 A: `net.pcap.analyse`, `native.ghidra.decompile`, `fuzz.differential.parse`.

## Ranking criterion (printed by the script, so it can be disagreed with)

Weakness score, higher = worse: base grade (D 400 · E 350 · C 300 · B 200 · A 100), **+100** the
harness never executes this probe, **+50** the negative control declares no runnable command,
**+20** not evidence-bound (no `run_log` + `sha256`), **+10** state is not `observed`. Ties break on
`id`, so the order is deterministic, and every term is printed per row.

Two deliberate choices, both stated in the output so a reader can reject them:

- The `SKIP` set is **imported** from `assert-probes.py`, not retyped. A second hand-typed copy
  drifts and then errs in the direction that flatters the table. If the import fails the script
  prints that it is using a narrower definition rather than quietly doing so.
- "Evidence-bound" reuses `doc-facts.py`'s existing derivation (`run_log` **and** `sha256`), rather
  than a second definition. Counting `evidence_binding.status == "unverified"` would return 3,
  because that key also sits on a `planned` entry — `doc-facts.py` records that difference already.

Worst first: `dynamic.device.frida` (380), `native.crosscompare.ghidra` (380),
`native.ghidra.emulate` (330), `native.il2cpp.symbols` (330), `native.ida.decompile` (320),
`native.ida.list_functions` (320), `web.js.cdp` (250). The two `native.ida.*` entries are the sharpest
case: `state: observed`, an honest `evidence_binding: unverified` naming the exact blocker, and
still no executed probe. Strongest: `native.ghidra.decompile` and `net.pcap.analyse` (100),
`fuzz.differential.parse` (150, A but plan-only control).

## The fifth label, E

The brief's four grades are not total over the eight `(exit, substring, artifact)` cells: an entry
with `expect_exit` + `produces` and no `expect` falls through all four. **The brief's own negative
test produces exactly that cell.** Folding it into D would falsely say it "expects neither"; into C,
falsely say it expects a substring. So it is counted and ranked separately. No live entry is E, so
the label is cosmetic on real data and load-bearing only in the mutation sweep.

## Acceptance

1. `python scripts/verify-probe-coverage.py` → **exit 0**, prints counts per grade. Run.
2. Negative test, actually run, on `%TEMP%` copies. The real registry was not edited.

```
baseline        dropped=[]                          -> net.pcap.analyse grade=A  A=3 B=24 C=0 D=0 E=0  exit=0
drop-expect     dropped=['expect']                  -> net.pcap.analyse grade=E  A=2 B=24 C=0 D=0 E=1  exit=0
drop-exit       dropped=['expect_exit']             -> net.pcap.analyse grade=C  A=2 B=24 C=1 D=0 E=0  exit=0
drop-produces   dropped=['produces']                -> net.pcap.analyse grade=B  A=2 B=25 C=0 D=0 E=0  exit=0
drop-all-three  dropped=['expect','expect_exit','produces'] -> net.pcap.analyse grade=D  A=2 B=24 C=0 D=1 E=0  exit=0
```

Each declared component is load-bearing: each single-key deletion drops the grade, and the count for
the destination grade rises. Deleting `produces` alone lands inside the brief's own ladder (A→B,
B 24→25) with no reliance on the E label; deleting `expect` lands on E, which is the uncovered cell.

3. Ranked list names every D-grade capability: **there are none**, and `evidence/probe-coverage.md`
   says so explicitly rather than inventing one. The "one paragraph per D-grade capability" section
   is therefore empty *because the measurement says so*, and the file states that in those words.

No speculation about whether anyone intends to strengthen these probes — that is not this audit's
call and it is not in either file.

## Notes for whoever picks this up

- `probe.produces` is the only thing separating A from B, and `assert-probes.py --require-produces`
  already reports `STRINGS ONLY` for every entry that omits it. The gate for a *new* entry therefore
  already exists; what is missing on the 24 older entries is the declaration itself, not a rule.
- 6 entries cannot be fixed by adding `produces` at all — the checker skips them by design. For
  those the fix is a runnable `probe.command`, which is a different and larger question.
- Do not read "24 of 27 hollow" as 24 false claims. 21 of those 24 are `state: observed` with a
  matching `run_log` + `sha256`, so the *observations* are evidenced; what is thin is the standing
  mechanism that would catch a regression without re-running a probe by hand.

## Not run, by contract

No lab loop, no `smoke-all.ps1`, no fuzz loop, no `mission.ps1 -Action Run`, nothing under
`E:/missions`. The script reads the registry and prints; it runs no probe and writes nothing back.
