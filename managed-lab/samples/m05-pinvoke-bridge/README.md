# m05 — the managed/native boundary

**Technique.** A managed program whose entire security decision is made in a DLL it
does not contain. The managed side marshals a byte array across, calls
`LabTransform`, then `LabCheck`. The key is nowhere in the managed assembly.

**The traps.**

1. **The DllImport name is not all of the contract.** The calling convention, the
   marshalling (`uint8[]` with a separate `int32 len` — LPArray, length passed by
   hand, not `SizeParamIndex`) and the load path are all part of it, and all of
   them are visible only if you read both halves. The sample uses
   `NativeLibrary.SetDllImportResolver`, so the DLL is beside the executable and
   not on `PATH`.
2. **The answer is the transform, inverted.** `LabCheck` compares against the
   secret *after* `LabTransform` with seed `0x2A`. The forward transform is
   XOR-then-swap, so the inverse is swap-then-XOR. Applying the forward transform
   twice is very plausible and yields a 14-byte answer that is simply wrong.
3. **The key is masked in `.rdata`.** `kMasked[14] ^ 0xA7`, so `strings` and a
   hexdump show nothing useful. The address of the table and the mask constant are
   both inline literals in the decompiled `LabCheck`.

**Known answer.**

```
key  M05-BRIDGE-KEY        (14 bytes, ASCII)
LabCheck  accepts key.len == 14 and the 14 bytes equal
          DAT_18000f300[i] ^ 0xA7  =  1d 67 1e 05 6b 74 7b 75 00 05 00 65 08 0b
LabTransform(buf, len, seed):  buf[i] ^= (seed + i*3) & 0xff   for i in 0..len-1
                               then swap pairs walking back from the end
```

**Solve.** This one is a two-toolchain solve and it is the reason the sample is in
the lab.

```powershell
node managed-lab\tools\solve-m05.mjs --expect "M05-BRIDGE-KEY"
node managed-lab\tools\solve-m05.mjs --forward --expect "M05-BRIDGE-KEY"   # exits 4
node managed-lab\tools\solve-m05.mjs --no-mask  --expect "M05-BRIDGE-KEY"   # exits 4
```

The solve is:

1. `ilspycmd` the managed assembly → DLL name, export names, signatures, seed,
   key length, and that an explicit load resolver is in play.
2. `rabin2 -Ej` the DLL → confirm both imports really are exports. The address is
   confirmed by a second tool before a single byte is read out of it.
3. The station's headless Ghidra (`scripts\ghidra-headless.ps1`) decompiles the
   DLL. From `LabCheck`: the comparison length (`0xe`), the mask constant
   (`0xa7`) and the table address (`DAT_18000f300`) are all inline literals in
   the decompilation, which is why this works without symbols.
4. `r2 pxj 14 @ 0x18000f300` reads the masked table through the loader.
5. The per-index multiplier comes out of the decompiled `LabTransform`; the
   key is the inverse transform, seeded with the value the managed side passes.
6. **Independent check.** The recovered transform is run against a probe and
   compared with `m05_bridge.exe --selftest <probe>`, which calls the *real*
   function. If they disagree the solver reports `valid: false` and refuses to
   publish a key.
7. The runner then runs the managed program with the recovered key and requires
   `verdict ACCEPT`, and with a 14-byte wrong key and requires `verdict REJECT`.

**Honest limit.** The *shape* of `LabTransform` ("XOR per index, then swap pairs
walking back") is the analyst's reading of the loop shape; the multiplier, the
mask, the length, the table address and the seed are all recovered from code. That
is why step 6 exists: the shape is a hypothesis, the live call is the test.

**Loop placement.** This is the sample that spans two columns. Managed: TRIAGE
(`pinvokeimpl` in the IL) → NARROW (the whole problem becomes one 14-byte
comparison in another binary). Native: ACQUIRE/PRESERVE the DLL, TRIAGE
(`rabin2` exports), INSTRUMENT (headless Ghidra decompile, no debugger), VERIFY
(static recovery against a live call, then against the managed program's verdict).

**Skill.** Knowing when the managed column has run out, and carrying the question
into a different toolchain without losing the thread.
