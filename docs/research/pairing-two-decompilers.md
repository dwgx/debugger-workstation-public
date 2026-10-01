# Two decompilers, one function: what a pairing actually buys

Measured 2026-10-02. Both sides ran on the same binary, the same function, the same host. Every
number here came from a command in this repository; nothing is quoted from prose.

## Why this document exists

`E:\missions\` holds **eight mission artifacts and every one of them has the identical chain**:
`native.ida.list_functions → native.ida.decompile`. The orchestrator has never once chosen a
different pairing. So no pairing had ever been compared, and "which pair should I use" had no
answer backed by a run. This is that first comparison.

It is deliberately narrow: **one function, one binary, two instruments.** A single sample is
not a benchmark and this page does not claim to be one. What it establishes is a *qualitative*
difference — which instrument answers which kind of question — which a timing table cannot show.

## The subject

`crackme-corpus/out/c01-stringobf.exe`, sha256
`2d59a3c5d3281782e254ed84d14f43768251096240cb85c492f56018b56fbf09`, function `main` at RVA
`0x1080`. Self-authored, built by this repository.

## The measurement

| | IDA Pro 9.2 via `idalib-mcp` | Ghidra 12.1.3 headless |
|---|---|---|
| invocation | `node native-lab/tools/decompile.mjs %TEMP%\pair\t.exe main` | `analyzeHeadless.bat … -import … -postScript ExportDecompile.java <outdir> -scriptPath scripts\ghidra` |
| wall clock | **2.60 s** | **18.5 s** |
| output | JSON, `ok: true`, `code` + `refs[]` | per-function `.c` files + `functions.txt`, `strings.txt`, `summary.json` |

**Ghidra is 7.1× slower on this subject.** That number includes JVM start, import and full
auto-analysis, so it is an *import-to-answer* cost, not a decompiler-quality cost — a fair
comparison against IDA would reuse an existing database. Stated that way because the unfair
version of this number would mislead a planner.

## Where they agree — and this is real corroboration

Both recover the same structure, independently:

- the `argc == 2` guard, and the usage branch returning 2;
- **two** calls into `FUN_140001000` / `sub_140001000`, on the same two table addresses
  (`0x140017330`, `0x140017348`);
- `strlen(argv[1])` compared against a length, then `strcmp`;
- the **three-way** outcome: a decoy string `FLAG{c01_strings_gave_you_this_decoy}` → reject, a
  decoded string → accept, anything else → reject;
- the accepted branch prints both the `ACCEPTED` marker and the recovered flag.

For a claim of the form *"main performs a three-way password check using two XOR-decoded
strings"*, **Ghidra genuinely corroborates IDA.** That is the strongest statement available
here and it should not be understated.

## Where they differ — and it is the decisive part

The XOR key constants. IDA emits them as **inlined literals**:

```c
sub_140001000((unsigned int)&unk_140017330, 18, 11, 90, (__int64)Str2);
sub_140001000((unsigned int)&unk_140017348, 26,  5, 51, (__int64)v6);
```

Ghidra emits the first two as literals but leaves the last two as **unresolved global
references**:

```c
FUN_140001000(0x140017330,0x12,DAT_140017344,DAT_140017342,(longlong)local_60);
FUN_140001000(0x140017348,0x1a,DAT_140017364,DAT_140017343,(longlong)local_40);
```

**Checked rather than assumed.** Reading those four addresses out of the PE with `pefile`:

| address | IDA said | bytes | u32 | u8 |
|---|---|---|---|---|
| `0x17344` | 11 | `0b000000` | **11** | 11 |
| `0x17342` | 90 | `5a330b00` | 734042 | **90** |
| `0x17364` | 5 | `05000000` | **5** | 5 |
| `0x17343` | 51 | `330b0000` | 2867 | **51** |

**IDA is correct.** Ghidra is not *wrong* — the storage locations hold exactly those values.
It simply did not perform the constant propagation, leaving a reference to where a value lives
instead of the value.

**And the width matters, which is the trap.** The last two are **bytes**. Read as the natural
u32, `DAT_140017342` is `734042` and `DAT_140017343` is `2867` — both nonsense. A reader who
took Ghidra's output at face value and widened those references to 32 bits would derive a wrong
XOR key and be confidently wrong. This is the concrete reason a corroborating instrument can be
**more dangerous than none**: it supplies plausible text that must be second-guessed.

Naming follows the same split. IDA resolved `aAccepted` / `aRejectedThatIs` and typed the frame
(`char Str2[32]`); Ghidra emitted `s_ACCEPTED_140022038` and left the signature as
`undefined8 FUN_140001080(int, undefined8 *)`.

## What this settles, and what it does not

**Settles:** for **structural** claims, a second decompiler is real corroboration and worth
running. For **constant-value** claims, it is not — one instrument answered and the other did
not.

**Does not settle:** the `independence` gate. Both instruments are `evidence_source:
decompiler`, so under the charter's own rule — *a family is a property of the instrument* —
this pairing is **one opinion held twice** and cannot corroborate for verdict purposes. This
document does not change that, and must not be cited as if it did.

**Does not settle:** whether Ghidra's constant propagation can be turned on. It may simply be a
Ghidra configuration question, and if so the honest next step is to enable it and re-measure
rather than to record a permanent limitation. **Until that is tried, "Ghidra does not resolve
these constants" is a measurement, not a property of Ghidra.**

## The gap this exposed

`native.crosscompare.ghidra` is registered with `evidence_source: binary-similarity` — a family
that is *not* decompilation, and therefore the only registered route to genuine independence on
the native axis. Per a worker's finding it has **no `invoke` block**, so it is probeable but not
callable, and its `consumes` requires both programs in one Ghidra project first — a precondition
no registry field can express.

That is now the single highest-value structural gap in the arsenal: **the one instrument that
could legitimately corroborate native RE cannot be invoked by the planner.** It is recorded in
`composition-plan.md` §4a and remains open.

## Reproduce

```powershell
$t = Join-Path $env:TEMP 'pair'; New-Item -ItemType Directory -Force -Path $t | Out-Null
Copy-Item crackme-corpus\out\c01-stringobf.exe (Join-Path $t 't.exe')

# IDA
node native-lab\tools\decompile.mjs (Join-Path $t 't.exe') main

# Ghidra
& .\Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat `
  $t c01_pair -import (Join-Path $t 't.exe') `
  -postScript ExportDecompile.java (Join-Path $t 'ghout') `
  -scriptPath scripts\ghidra -deleteProject

# the four constants Ghidra left as references
python -c "import pefile,struct;pe=pefile.PE(r'<t.exe path>');[print(hex(r),struct.unpack('<I',pe.__data__[pe.get_offset_from_rva(r):pe.get_offset_from_rva(r)+4])[0],pe.__data__[pe.get_offset_from_rva(r)]) for r in (0x17344,0x17342,0x17364,0x17343)]"
```