# m01 — string encryption

**Technique.** Three strings that exist nowhere in the assembly as literals. The
ciphertext is base64 in a `const string`; the plaintext is reconstructed by
`Reveal` on every call, in two layers:

1. a position-dependent keystream XOR — `seed + index * 7 + index / 3`, seed `0x5A`
2. an in-place byte swap on the odd indices

**The trap.** A plausible single-layer XOR is *not* enough. Applying only layer 1
produces printable-looking garbage, and a solver that reports it is wrong. The
runner asserts the exact plaintext, so a half-solved answer is a failure, not a
near miss — and `solve-m01.mjs --wrong-order` demonstrates exactly that failure
live.

**Known answer.**

```
managed-lab :: sample m01 (string encryption)
the quick brown fox jumps over the lazy dog
part-two-of-the-decrypted-payload
```

**Solve.**

```powershell
node managed-lab\tools\solve-m01.mjs --asm managed-lab\out\m01\m01_stringobf.dll
node managed-lab\tools\solve-m01.mjs --asm ... --expect "the quick brown fox jumps over the lazy dog"
node managed-lab\tools\solve-m01.mjs --asm ... --wrong-order --expect "<the real answer>"   # exits 4
```

**Loop placement.** TRIAGE (base64 blobs in the string table, no plaintext) →
NARROW (`Reveal` is the only thing that touches them) → VERIFY (recovered strings
compared against the sample's own output).

**Skill.** Read a decompilation, re-implement a transform, get the *order* of two
layers right. The solver reads the keystream expression out of `KeyStream`'s
`return`, evaluates it as C# with its own parameter names, reads the seed out of
the call site, and reads the layer order off the source order of the two loops in
`Reveal`. No plaintext, no seed and no formula is hard-coded in the solver.
