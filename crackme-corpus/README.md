# crackme-corpus

Self-authored reverse-engineering challenges. Six of the strongest tools on this
station — Ghidra, radare2, capa, FLOSS, DiE, ilspycmd — had **nothing to
analyse**. This corpus is the missing target set.

Every challenge is authored here. Nothing was downloaded.

## The one command

```powershell
python tools\loop.py
```

It builds every challenge, decompiles it, runs the solver, and checks the
recovered answer against the answer key. **It exits non-zero unless every
challenge is solved and every negative control fires.**

```
CORPUS CLOSED: 5 challenge(s), 20 checks, 5 negative controls, 110.5s
Every challenge solved from its binary, and every solver was shown to reject a wrong answer.
```

Useful flags: `--list` (the ramp, builds nothing), `--only c03`, `--no-build`,
`--no-ghidra`, `--json`.

## The design rule that makes these real

Three properties, and every challenge holds all three:

**1. The solver never reads the source.** It recovers the answer from the
compiled artifact — Ghidra decompile for structure, radare2 for bytes. The
source tree exists so a human can check the answer, never so the solver can
cheat.

**2. The artifact is the judge.** A recovered password is fed back to the
binary, which prints `ACCEPTED` only for the real one. So "the solver ran" and
"the solver solved it" are different claims, and only the second counts.

**3. Every challenge carries a decoy.** A shortcut that appears to work returns
a wrong answer:

| Trap | Consequence |
|---|---|
| c01 ships a **plaintext** fake `FLAG{...}` in `.rdata` | `strings \| grep FLAG` returns it and fails |
| c05 mixes **decoy records** into the live stream | not filtering them yields a wrong digest |
| c04 stores keys under an **opcode permutation** | reading the array order directly gives garbage |
| c03 guards the unsealer behind an **integrity check** | skipping the FNV-1a recheck leaves the seal closed |

## The ramp

| id | technique | diff | teaches | chain |
|---|---|---|---|---|
| **c01** stringobf | string table, byte rotation + XOR mask | 1 | never trust a `strings` hit; check the real decode | Ghidra → r2 → binary |
| **c02** cff-dispatch | control-flow flattening, dispatcher state machine | 2 | rebuild real control flow by walking the state graph | Ghidra graph walk → jump-table constants |
| **c03** antidebug | anti-debug guard + rolling-XOR seal + FNV-1a integrity | 3 | anti-analysis on a sample you own; recompute, never assume | Ghidra → r2 → FNV-1a recheck |
| **c04** dotnet-obfuscation | managed string encryption behind a VM opcode table | 2 | managed RE with no GUI at all | ilspycmd → invert the permutation |
| **c05** binary-format | magic header + packed 20-byte records | 3 | recover a record layout from bytes; derive the key from live data | Ghidra → r2 struct layout → FNV-1a |

## Answer key

Committed deliberately — the point of a textbook is that the answers are
published. **The solvers never read this table**; they recover the answers from
the binaries, and the binaries are the judge. This exists so the runner can
assert.

| id | password | flag |
|---|---|---|
| c01 | `C01-TABLE-XOR-9F2A` | `FLAG{c01_string_table_xor}` |
| c02 | `FL4T-STATE-7B` | `FLAG{c02_flattened_state_machine}` |
| c03 | `C03-ROLLING-KEY-7D` | `FLAG{c03_rolling_key_behind_guard}` |
| c04 | `C04-DOTNET-VM-3E91` | `FLAG{c04_managed_vm_string_keys}` |
| c05 | `C05-2FE18F60` | *(no flag; the key is derived from the live records)* |

## Why negative controls gate the result

Each challenge is solved twice: once with the correct expected answer, once
with a deliberately wrong one. The second run **must** exit non-zero.

A check that cannot fail proves nothing. If a solver ever started returning
success unconditionally, every PASS in the table above would still print — and
the corpus would silently stop being a corpus. The negative control is what
stops that.

## Layout

```
challenges/cNN-name/
  src/            the source (MSVC or dotnet); never read by the solver
  solve.py        the solve path: decompile -> recover -> feed to the binary
out/              build + decompiler output. GITIGNORED.
tools/
  build-c.ps1     MSVC build (vcvars64 + cl)
  labkit.py       shared helpers: r2, Ghidra output, run-sample, read-by-VA
  loop.py         the runner
```

`out/` is gitignored and must stay that way. It holds compiled binaries and
roughly 1500 machine-generated decompiled C files; exporting decompiled C into
git is forbidden by the station charter. The sources are the product.

## Build environment

MSVC 2022 Community. There is **no gcc on this machine**. `tools/build-c.ps1`
calls `vcvars64.bat` and then `cl`, so a caller never has to set the
environment by hand.

## Stop lines

- Every binary here is **ours**, built from source in this tree, for training.
- No third-party crackme, CTF binary, or malware sample was downloaded or is
  permitted.
- Anti-debug and integrity checks in c03 exist to be **analysed**, as practice
  on our own sample. Nothing here targets anti-cheat, DRM, or anyone's
  software.
- Nothing here reaches the network. Everything is local.

## Honest limits

- Five challenges, not a curriculum. They do not cover packers, VM protectors,
  anti-debugging beyond the naive guard, or real-world compiler output.
- The solvers are written **for these specific challenges**. c02's solver
  parses *its* state-machine shape; it is not a general CFF deflattening tool.
  Read them as worked examples of a method, not as reusable tooling.
- c03's anti-debug is a guard clause and an FNV-1a check, not a full
  anti-analysis suite.
- Difficulty ratings are relative to this corpus, not to public CTF material.
