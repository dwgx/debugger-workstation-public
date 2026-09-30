# Reading IL headlessly — the `ildasm` equivalent on this box

An agent analysing a .NET binary needs one thing the GUI decompiler does not give
it: raw, greppable, reproducible IL. This is the path, and every claim on this
page is asserted by `managed-lab/tools/loop.mjs` section 3.

## The short version

| you want | run |
|---|---|
| C# (what a human reads) | `ilspycmd <asm.dll>` |
| **raw IL (the ildasm equivalent)** | `ilspycmd -il <asm.dll>` |
| IL with PDB line mappings | `ilspycmd -il --il-sequence-points <asm.dll>` |
| one type only | `ilspycmd -t Namespace.Type <asm.dll>` |
| one member only | `ilspycmd -m 0x06000005 <asm.dll>` |
| what is in this assembly | `ilspycmd -l c,s <asm.dll>` |
| what resources does it carry | `ilspycmd --list-resources <asm.dll>` |
| the raw bytes of one resource | `ilspycmd --resource <name> -o <dir> <asm.dll>` |
| a metadata table, row by row | `ilspycmd --dump-table TypeDef [--json] <asm.dll>` |

Tool: `Static-Reversing\ilspycmd\ilspycmd.exe` — **ilspycmd 11.0.0.9375 /
ICSharpCode.Decompiler 11.0.0.9375** on this box. Always pass
`--disable-updatecheck` in automation; ILSpy otherwise does a network update
check on every invocation, which is slow and makes a batch run non-hermetic.

## Why not `ildasm`

The old `ildasm.exe` shipped with the .NET Framework SDK and is **not** in the
.NET SDK 10.0.400 that this station has. Three replacements, in order of
preference here:

1. **`ilspycmd -il`** — already installed, already proven here, emits ildasm-shaped
   IL with `IL_xxxx:` offsets, `.method` headers, `.locals init`, and full
   signatures. This is the ildasm equivalent for a headless agent. No install.
2. **`dotnet tool install -g dotnet-ildasm`** — the community port. *Not
   installed on this box*: it is a third-party package, the station's stop lines
   say official sources only unless the owner asks, and option 1 already covers
   every operation this lab needs. Recorded here as the fallback if ILSpy ever
   stops shipping a usable `-il`.
3. **A `System.Reflection.Metadata` reader** — the zero-dependency route, and the
   one to write when you need IL the decompiler *normalises away*. ILSpy's `-il`
   shows you the decompiler's view of the method body, which is not byte-identical
   to what is in the PE. For obfuscation work, where the whole point is the
   un-normalised form, option 3 is the honest answer.

## What raw IL buys you over the C#

This is not academic. Three things the loop asserts came out of `-il` and would
have been awkward or invisible in the decompiled C#:

**m01 — the ciphertext is a literal, the algorithm is a call.**

```
IL_xxxx: ldstr      "NwYAEBHiG/igwf2IiuCDrruuu4mJltQ7MjAxU1NfXCNTNmwBNAkbCwjh77X7"
IL_xxxx: call       class [System.Runtime]System.Convert FromBase64String(string)
IL_xxxx: call       int32 M01.Program::KeyStream(int32, uint8)
```

`strings` on the DLL would find the base64 too. What IL adds is the certainty
that there is exactly one keystream helper and it is called with one constant, and
that nothing else touches the buffer.

**m02 — the flattening is not a `switch` opcode.** This is the fact that surprises
people, and it is why pattern-matching decompiled C# for a dispatcher table is a
trap. The C# compiler lowered the dense-ish case list to a comparison chain:

```
IL_00e4: ldc.i4.7
IL_00e5: call       bool M02.Program::Opaque2(int32)
IL_00ea: stloc.s 6
IL_00ec: ldloc.s 6
IL_00ee: brfalse.s IL_00fc          <- the guard, as a branch
IL_00f4: ldc.i4.s 43                <- the DEAD state, a plain literal
IL_00f6: stloc.1                    <- stloc.1 is the state variable
IL_00f7: br      IL_0213
IL_00fc: ldloc.2
IL_00fd: ldc.i4.s 17
IL_00ff: call       int64 M02.Program::Step(int64, int32)
```

So: the dead edge is a `ldc.i4.s 43` next to a `brfalse.s`, and the whole
dispatcher is a `stloc.1` / `br` chain. Reading IL you see the dead state sitting
there in plain sight; reading the decompiled C# you have to notice that one of two
`num = ...` assignments in the case body is inside a branch that cannot be taken.

**m03 — the payload is not in the IL at all.** The only payload-related literals
are the suffix and the seed:

```
IL_xxxx: ldstr      ".b64"
IL_xxxx: ldc.i4.s 90                <- 0x5A
```

If you go looking for the payload in the IL you will not find it, and the correct
next move is `--list-resources`, not more staring at opcodes.

**m04 — the integrity constants are immediates, and one of them is signed.**

```
IL_0001: ldc.i4     -2128831035     <- 0x811C9DC5, FNV-1a offset basis
IL_xxxx: ldc.i4     16777619        <- the FNV prime
```

`0x811C9DC5` does not fit in a signed 32-bit immediate, so IL prints it as
`-2128831035`. A grep for the hex you already know finds nothing. This is the
single most common reason a "constant is missing from the IL" conclusion is wrong.

**m05 — the managed/native boundary is one line.**

```
.method private hidebysig static pinvokeimpl("labnative" nomangle cdecl)
	int32 LabTransform (
		uint8[] buf,
		int32 len,
		uint8 seed
	) cil managed
```

`nomangle` means the export name is exactly `LabTransform`; `cdecl` is the calling
convention; `uint8[]` with a separate `int32 len` is LPArray marshalling with the
length passed by hand, not `SizeParamIndex`. All of that is the contract, and all
of it is in these two lines.

## `--dump-table` — the metadata-level pass

When the decompiler is lying to you (or has normalised too much), the tables are
one flag away:

```
ilspycmd --dump-table TypeDef        x.dll
ilspycmd --dump-table MethodSemantics x.dll
ilspycmd --dump-table 0x17 --json    x.dll      # 0x17 = MethodDef
```

Each row prints RID, token, names, heap offsets and coded indexes. This is the
managed equivalent of reading the PE headers directly, and it is the right tool
when the question is "what does the metadata actually say" rather than "what does
this code do".

## Workflow that works

1. `ilspycmd -l c,s` and `--list-resources` first. Cheap, and they tell you
   whether this is one type or a thousand.
2. `ilspycmd <asm>` to stdout. Read the decompilation; that is where the algorithm
   is.
3. `ilspycmd -il -t <the one type>` when the decompilation is ambiguous or you
   suspect the decompiler normalised something away. This is the
   invariant-2 "static before dynamic" move: exhaust the cheap static passes.
4. `--list-resources` / `--resource` to get bytes, rather than re-implementing a
   loader in your head.
5. `--dump-table` when you need the metadata's own account of something.
6. Only then consider running the thing. None of the five samples needed a
   debugger, and `managed-lab`'s loop runs all five headlessly.

## PDBs: when to turn on `-usepdb`

`ilspycmd -usepdb` uses the original variable names from a portable PDB. Debug
builds ship one next to the assembly; Release builds and stripped redistributables
usually do not.

- **Turn it on** when you want to map a decompiled name back to source you have.
- **Leave it off** when you want to practise the view you will usually get. Every
  solver in `managed-lab` runs without it, which is why they work on names like
  `array`, `num`, `flag` — the ones an analyst actually sees.

## Worked commands from this lab

```powershell
# the C# of one sample
ilspycmd out\m01\m01_stringobf.dll

# its raw IL
ilspycmd -il out\m01\m01_stringobf.dll

# the resource list, then the resource bytes
ilspycmd --list-resources out\m03\m03_resource.dll
ilspycmd --resource M03.ResourcePayload.payload.b64 -o out\m03\extracted out\m03\m03_resource.dll

# a whole assembly as a compilable project, one file per type
ilspycmd -p --nested-directories -o out\m02\project out\m02\m02_flatten.dll
```
