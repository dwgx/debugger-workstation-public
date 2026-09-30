# m04 — hand-rolled binary struct

**Technique.** A 16-byte header plus a chain of length-prefixed records, all
little-endian, all 4-byte aligned, each with its own integrity word. The file
carries no self-description; the only description is `WriteRecord`.

```
header   +0 magic[4] "MSTR"   +4 u16 version   +6 u16 count
         +8 u32 headerCheck (FNV-1a over bytes 0..7)   +12 u32 totalSize
record   +0 u8 kind   +1 u8 flags   +2 u16 id   +4 u32 valueLen
         +8 value[valueLen]   +8+len u32 valueCheck   then pad to 4
```

**The traps.**

1. **The integrity word looks like a CRC and is not one.** It is FNV-1a/32 —
   `0x811C9DC5` and the prime `16777619`, XOR-then-multiply. A solver that assumes
   CRC32 gets a plausible-looking layout and never notices, because a wrong
   checksum over a correctly-parsed record still "computes".
2. **Alignment padding is layout, not slack.** Record offsets are only derivable
   if you know where the next record starts.

**Known answer** — the exact table, which the solver must reproduce byte for byte
(it is compared against the artifact's own reader, not against a hard-coded
string on both sides):

```
MSTR v3 records=5 total=0x00000080 hdrcheck=0x59a863b9
[0] @0x0010 kind=1 flags=0x01 id=0x0001 len=27 check=0x3761b960 ascii="license-check: fails closed"
[1] @0x0038 kind=2 flags=0x00 id=0x0002 len=4 check=0x06ff67ff u32=0x000004d2
[2] @0x0048 kind=3 flags=0x02 id=0x0003 len=8 check=0x842f3f33 hex=0011223344556677
[3] @0x005c kind=1 flags=0x00 id=0x0100 len=7 check=0x50971b81 ascii="stage=2"
[4] @0x0070 kind=2 flags=0x03 id=0x0200 len=4 check=0xd7252efe u32=0xdeadbeef
```

**Solve.**

```powershell
node managed-lab\tools\solve-m04.mjs --dat managed-lab\out\m04\m04_records.dat
node managed-lab\tools\solve-m04.mjs --dat ... --crc32    # exits 1 -- every check fails
node managed-lab\tools\solve-m04.mjs --dat ... --no-align  # exits 1 -- record 1 overruns
```

Both controls fail **loudly and informatively** ("record 1 check … != … under
CRC32"), which is the point: the file's own integrity words are what catch a
mis-parsed layout, not a human squinting at it.

**Loop placement.** ACQUIRE (the `.dat`) → NARROW (`WriteHeader`/`WriteRecord` are
the format specification) → VERIFY (the listing compared byte-for-byte with the
artifact's own reader; the controls show the integrity words are load-bearing).

**Skill.** Struct recovery, the managed column. Every offset in the printed table
is computed from numbers read out of the decompiled writer — the field widths from
the `ms.Write(…, 0, n)` calls, the header check's position from the third argument
of its own `Fnv` call, the alignment from inside `AlignUp`, and the value-rendering
rules from the `Kind` comparisons inside `Canonical`.

**Where ReClass.NET fits.** ReClass.NET is a GUI tool and has no CLI, so it is not
in the loop. The honest division: use `/create_struct` on the station's headless
Ghidra surface (or ReClass.NET by hand) to author the same field map as a
`StructureDataType` so later decompilations are typed, and use this solver when you
need the answer in a script. The `.dat` is a 128-byte file, so loading it into
ReClass.NET or ImHex to eyeball the same offsets is a good cross-check, not the
primary path.
