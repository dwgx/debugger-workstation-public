# managed-lab — .NET / managed reverse engineering, known-answer corpus

Five self-authored C# samples, each teaching one managed-RE skill that is actually
different from the others, each with a solver that recovers the answer **from the
decompilation alone** and each checked against the sample's own output.

```
powershell -File managed-lab\tools\build.ps1     # build all five (+ the native half of m05)
node       managed-lab\tools\loop.mjs            # the whole proof, self-judging, exit 0 on success
```

Latest run on this machine: **27 checks, 27 pass, exit 0** (see
`notes/2026-09-30-managed-native-depth.md` for the transcript).

---

## The corpus

| id | technique | known answer |
|---|---|---|
| **m01** | string encryption — per-index keystream XOR + odd-index byte swap | `the quick brown fox jumps over the lazy dog` |
| **m02** | control-flow flattening, opaque predicates, a decoy block | `acc = dbb9c662`, order `0x1C → 0x07 → 0x4A → 0x35 → 0x11 → 0x2E → 0x59 → 0x41` |
| **m03** | base64 payload inside an embedded resource, seed derived from the resource name | `sha256 ae5ee44b…00f24`, 117 bytes, magic `M03P` |
| **m04** | hand-rolled 16-byte header + length-prefixed records, FNV-1a/32, 4-byte aligned | the 5-record table in `IL-READING.md` §m04 |
| **m05** | P/Invoke boundary — the key is in `labnative.dll`, not in the managed code | `M05-BRIDGE-KEY` (14 bytes) |

Each sample has a `samples/<id>/README.md` with the technique, the trap, and the
known answer in full.

## Why these five

They are five *different* skills, not five instances of one:

- **m01** teaches reading a decompilation and re-implementing a transform. The
  strings are not in the file. The trap is that one of the two layers is enough
  to produce plausible garbage.
- **m02** teaches dataflow, not reading. There is no straight line to read: the
  answer only exists after you build the successor graph, evaluate the opaque
  predicates, and reject a decoy block. The trap is trusting a dead edge, and the
  second trap is that the entry state is `Boot[1]`, not `Boot[0]`.
- **m03** teaches the two `ilspycmd` operations that have no C# equivalent —
  `--list-resources` and `--resource` — and shows that getting the *bytes* and
  reading the *bytes* are separate problems.
- **m04** is struct recovery in the managed column. The field map is derived from
  the writer, not guessed. The trap is that the integrity word looks like a CRC
  and is FNV-1a, so a wrong-but-plausible checksum never complains.
- **m05** is the one that ends the lab: the managed decompilation is complete and
  contains no answer at all. The analysis has to cross into a second binary with
  a different toolchain.

## How the loop judges itself

`tools/loop.mjs` runs four sections and prints one PASS/FAIL table.

1. **Tools + build.** Inventory; builds automatically if a sample is missing.
2. **Solve, then cross-check.** Every solver runs with `--expect <known answer>`.
   Then the result is compared against **the sample's own output** — a second
   source that never saw the decompilation. This is the loop's invariant 3 made
   mechanical: the static answer and the artifact's behaviour have to agree.
3. **Raw IL.** `ilspycmd -il` is asserted, not described: the ciphertext is an
   `ldstr`, the dead state `43` is a plain `ldc.i4.s`, the integrity constants are
   `ldc.i4` immediates, and the P/Invoke is one `pinvokeimpl` line. See
   `IL-READING.md`.
4. **Negative controls.** Every solver is re-run in the mode that breaks it, and
   the runner requires a non-zero exit each time. Without these, "PASS" would
   only mean "the solver returned something".

Solver exit protocol (`tools/clrlib.mjs`): `0` right answer, `4` the analysis ran
and the answer is wrong, `1` the analysis could not run. The split is what makes
the controls meaningful — a control that exits 4 and a solver that gives up
exiting 1 are different failures.

## Ground truth is not circular

Every known answer in this table was computed **before** the samples were written
(independently, in Python), and every solver reads its constants **out of the
decompilation** — no key, seed, length, offset multiplier or checksum prime is
hard-coded in a solver. If a sample changes, the solvers follow it. If a solver is
wrong, the comparison against the sample's output catches it. Both failure modes
are demonstrated by the controls.

## The rules this lab keeps

- Self-authored samples only. No third-party crackme, no malware, nothing
  downloaded.
- `managed-lab/out/` is build output and is gitignored; sources and known answers
  are committed by hand.
- Every solver is read-only against the artifact it analyses. m05 runs the
  managed program, but only to *confirm* a key recovered statically — never to
  search for one.

## Placement in the analysis loop

The lab is one column of the seven-phase loop
(`<private-tree>\wiki\methods\analysis-loop.md`), not a loop of its own.

| phase | what managed-lab does | which sample |
|---|---|---|
| **ACQUIRE** | the assembly, hashed; `.dll` and its PDB | all |
| **PRESERVE** | `out/` is disposable and gitignored; the sources and the known answers are the record | all |
| **TRIAGE** | `ilspycmd --list-resources`, `--list c,s`, `--dump-table`, `-il` — cheap metadata passes before anything is read closely | m03, IL facts |
| **NARROW** | the decompilation *is* the narrowing: the P/Invoke in m05 reduces the search space from "this program" to one 14-byte comparison in another binary | m05 |
| **INSTRUMENT** | headless only — no debugger, no breakpoints. The loop's own rule is static before dynamic | all |
| **VERIFY** | static answer vs. the sample's own output, plus the negative controls; for m05 the recovered transform is checked against a live call through `--selftest` | all |
| **DOCUMENT** | this file, the per-sample READMEs, `notes/2026-09-30-managed-native-depth.md` | all |

The three invariants map onto the runner directly:

1. **Provenance.** Every check names the artifact it came from; the m05 solver
   cross-checks the DLL's export table with `rabin2` before reading bytes out of it
   at an address it got from a decompilation.
2. **Static before dynamic, narrow the slice.** Nothing here needs a debugger.
   m05 is the case where "narrow the slice" means "change binaries".
3. **Test independently.** Section 2 of the runner *is* invariant 3, and section 4
   is the refusal to let the model author its own verdict — a check that cannot
   fail proves nothing.

## Honest limits

- **The solvers parse text.** They read decompiled C# with brace matching and
  regular expressions. That is what an agent does, and it is why the layer order
  and the branch selection are read from the source order rather than assumed. It
  is brittle against a different ILSpy version renaming locals; the shapes the
  solvers depend on (a `Reveal`-style helper, a `switch` dispatcher, a writer with
  `ms.Write` calls) are asserted to exist, and a missing one is a loud `exit 1`,
  not a wrong answer.
- **`m04` assumes little-endian**, because that is what the code says. A big-endian
  variant would need the reader, not just the writer, to be read.
- **m05's transform shape is recognised, not derived.** The multiplier, the mask
  key, the table address and the length all come out of the decompilation; the
  *shape* ("XOR per index, then swap pairs walking back") is the analyst's reading
  of the loop shape. That is why the solver checks it against a live call before
  it will report success — the shape is a hypothesis, the selftest is the test.
- **No obfuscator was used or installed.** The samples are obfuscated by hand, in
  the specific ways listed above, which is the point: a known-answer corpus has to
  know its own answer. A real deobfuscator (ConfuserEx-style) is a different piece
  of work and is not claimed here.
- **`-usepdb` is not used by default.** A Debug build ships a portable PDB, and
  `ilspycmd -usepdb` will use the original variable names from it. The solvers
  deliberately do not pass that flag, so they are proved against the *stripped*
  view an analyst usually gets. `IL-READING.md` covers when to turn it on.

## Files

```
managed-lab/
  README.md                     this file
  IL-READING.md                 the headless IL path: ildasm equivalent + the flags that matter
  samples/m01..m05/             C# sources (+ labnative.c for m05) and a README each
  tools/build.ps1               builds all five, and m05's native half through vcvars64
  tools/clrlib.mjs              shared: tool paths, decompiled-C# reader, safe C# expression eval
  tools/solve-m01..m05.mjs      one solver per sample, each with its negative controls
  tools/loop.mjs                the runner
  out/                          build output (gitignored)
```
