# forensics-lab — memory / process forensics lane

**The target is synthetic and this lab says so everywhere.** There is no acquisition path
here, no driver, no kernel access, and no image of anyone's machine. What this is: a
deterministic, self-labelled memory-image fixture with a known ground truth, a
Volatility-equivalent plugin set that reads it, and — the part that matters — a
triangulator that refuses to call a single artifact a finding.

The station had the tools (Volatility 3, System Informer, Sysinternals, Wireshark) and no
method. This is the method, plus the proof that the method can fail.

| Path | What it is |
|---|---|
| `lab/spec.mjs` | **The ground truth, in one file.** 8 processes, 5 VADs, 4 sockets, 5 handles, 3 artifact sets, the frozen clock, and the record layout. Read only by `tools/loop.mjs`; the analyzer never sees it. |
| `lab/mkimage.mjs` | Writes the `D12IMG` container and the three independent artifacts. No wall clock, no randomness, no environment. |
| `lab/payload/d12payload.c` | The self-authored PE embedded in the injected region. Innocuous: one exported marker, no network, no injection, no persistence, no evasion. |
| `lab/payload/build.bat` | Builds it with MSVC 2022 (`cl /LD /O1 /Brepro`). Optional — see *Payload provenance*. |
| `tools/triage.mjs` | **The instrument.** `banners`, `pslist`, `psscan`, `malfind`, `netscan`, `handlescan`, plus one parser per artifact format. |
| `tools/analyze.mjs` | **The deliverable.** Triangulation, confidence tiers, and the decoy rejection. |
| `tools/correlate.mjs` | Carves the region to a real file, runs DiE and YARA-X on it, and probes real Volatility 3. |
| `tools/loop.mjs` | All of the above in one self-judging command. |

## The one command

```powershell
powershell -File scripts\forensics-lab.ps1 loop     # or: node forensics-lab/tools/loop.mjs
```

37 assertions. Exit `0` means the loop closed on this machine, in this run; exit `9` means
an assertion failed and the table says which.

```
  PASS  image built and hashed                                   151552 bytes
  PASS  regenerating the image produces identical bytes          35a6a51d5cc607af… == 35a6a51d5cc607af…
  PASS  two analyses of the same image are byte-identical        68f8a8bf03e97740…
  PASS  pslist reaches exactly the linked processes              7 == 7
  PASS  psscan finds strictly more than the list walk            8 > 7 (the DKOM signal)
  PASS  malfind keeps the executable+unbacked region             1 suspicious
  PASS  findings set matches the ground truth exactly            INJECTED_PRIVATE_RWX_REGION, OUTBOUND_CONNECTION:pid-4120, UNLINKED_PROCESS
  PASS  INJECTED_PRIVATE_RWX_REGION cites MEM+SRUM               support: MEM:malfind(pid 4120 0x7ff60000)  MEM:netscan(...)  SRUM:C:\Windows\System32\svchost.exe
  PASS  UNLINKED_PROCESS cites MEM+PF+AM                         support: AM:...  MEM:pslist(absent)  MEM:psscan(pid 6692)  PF:LSASS_HELPER.EXE-9C1FE432.pf  SRUM:...
  PASS  decoy C:\Users\Public\D12LabStage\stage-updater.exe      single source: SRUM
  PASS    ... is NOT in the findings set                         absent from findings
  PASS    ... is reported as UNCONFIRMED                         POSSIBLE, 1 source: SRUM
  PASS    ... names every source that does NOT have it           no process in the image runs this path; no Amcache execution record; no prefetch run history
  PASS  region 0x210000 in PID 744 is not reported as an injection   REJECTED: region is not executable
  PASS  region 0x7ff70000 in PID 4120 is not reported as an injection REJECTED: region is explained by a load-list module
  PASS  carved the injected region out of the image              pid 4120  0x7ff60000  104448 bytes  sha256 38b127a6c8108d91…
  PASS  diec agrees the carved bytes are the lab payload         exit 0  PE64
  PASS  yr agrees the carved bytes are the lab payload           exit 0  D12_LabPayload …
  PASS  real Volatility 3 was invoked on the image               vol.exe windows.pslist
  PASS  real Volatility 3 REFUSES pslist on a synthetic image    exit 1  "plugins.PsList.kernel.layer_name:"
  PASS  clean image yields NO injected-region finding            1 finding(s) total
  PASS  one-byte tamper changed the image                        0x2000: 4D 5A -> 41 41, sha256 now differs
  PASS  tampering REMOVES the injected-region finding            was a finding; now gone
  PASS  tampering leaves the unlinked-process finding intact     an independent finding is unaffected, as it should be
  PASS  removing SRUM demotes the injection to UNCONFIRMED       now POSSIBLE: only 1 independent source (MEM)
  PASS  analyze --expect <wrong set> exits non-zero              exit 4
  ...
LOOP CLOSED
```

## Invoking it

```powershell
powershell -File scripts\forensics-lab.ps1 status      # node + third-party tools, paths, source groups
powershell -File scripts\forensics-lab.ps1 doctor      # run the real tools; print what they actually say
powershell -File scripts\forensics-lab.ps1 generate    # build the target, print hashes, no analysis
powershell -File scripts\forensics-lab.ps1 analyze     # triage + triangulate + report
powershell -File scripts\forensics-lab.ps1 correlate   # carve, run DiE + YARA-X, probe Volatility

powershell -File scripts\agent-cli.ps1 forensics-lab loop
```

Tool flags go through `-NodeArgs`, because PowerShell binds bare `--out` to `-OutVariable`
before `$Rest` sees it (the same trap `web-reverse-lab.ps1` documents).

| exit | meaning |
|---|---|
| 0 | analysed / loop closed (findings are expected output, not failure) |
| 2 | unknown action |
| 3 | the target is missing, or is not a D12LAB container |
| 4 | `analyze --expect` mismatch: the finding set is not the one required |
| 9 | a loop assertion failed |

## The target

A single flat file, `D12IMG`, page-aligned, little-endian, built from `lab/spec.mjs`:

- **8 processes.** `System`, `smss`, `csrss`, `winlogon`, `lsass`, `svchost` (4120),
  `spoolsv`, and `lsass-helper.exe` (6692) — which is **spliced out of the
  `ActiveProcessLinks` chain**. Its neighbours point straight past it, so a list walk
  cannot reach it and a pool scan still can. That is the DKOM case, and it is why the lab
  runs two different walks of the same image.
- **5 VADs.** One private `EXECUTE_READWRITE` region in 4120 holding the payload PE
  (the finding). One `EXECUTE_READ` image region in 4120 that a load-list module backs
  (normal). One private `READONLY` region in `csrss` holding a structurally valid PE
  (the **detector-level decoy**). Plus two ordinary private/mapped regions.
- **4 sockets**, including 4120 → `203.0.113.23:8443`.
- **5 handles**, including a named section handle onto the injected region.
- **3 independent artifacts**, in three different formats: an Amcache-shaped TSV, seven
  binary MAM-like `.pf` files, and an SRUM-shaped TSV.

The image header carries the strings `D12LAB-SYNTHETIC-MEMORY-IMAGE` and
`NOT A REAL HOST. NOT A REAL CAPTURE. NOT A REAL USER.`, and `manifest.json` repeats the
warning. `banners()` refuses any file that does not carry the magic, and refuses an image
whose published record strides disagree with the parser's — so a layout change is a loud
failure, never a confidently misparsed table.

## The invariant, as code

> A single artifact lies. A conclusion needs two or more independent sources.

`tools/analyze.mjs` counts **source groups**, not files:

| group | what it is | in this lab |
|---|---|---|
| `MEM` | the image | `pslist`, `psscan`, `malfind`, `netscan`, `handlescan` |
| `AM` | registry-derived execution log | Amcache-shaped TSV |
| `PF` | per-image execution timing | seven `.pf` files |
| `SRUM` | per-app resource accounting | SRUM-shaped TSV |

Five `.pf` files are one source. One image read by six plugins is still one source — which
is why `psscan` alone does not convict the hidden process, even though it is a completely
different code path from `pslist`. `MEM + SRUM` does, because SRUM is a different
acquisition path entirely.

Tiers: **OBSERVED** (read out of a byte), **INFERRED** (≥ 2 independent groups),
**POSSIBLE** (one group), **REJECTED** (a signal that failed the predicate). The threshold
is one named constant, `MIN_INDEPENDENT_SOURCES`, so the rule can be argued with instead
of inferred from behaviour.

## What the lab finds, and what it refuses to find

**Confirmed (≥ 2 independent groups):**

- `INJECTED_PRIVATE_RWX_REGION` — a private RWX region in PID 4120 holding a PE that no
  load-list module explains, plus network attribution for the same PID from SRUM.
  Supported by `MEM` + `SRUM`.
- `OUTBOUND_CONNECTION:pid-4120` — 4120 → `203.0.113.23:8443`, with SRUM agreeing on who
  sent bytes and when. `MEM` + `SRUM`.
- `UNLINKED_PROCESS` — PID 6692 is in the pool and not on the list. `MEM` (two disagreeing
  walks) + `PF` + `AM` + `SRUM`.

**Refused (1 group):**

- `UNCORROBORATED_PATH:C:\Users\Public\D12LabStage\stage-updater.exe` — **the decoy.**
  SRUM says this path moved 44 MB. No process, no Amcache record, no prefetch trail, no
  socket. It is **reported** — a silent omission would be a hole in the report — and
  reported as `POSSIBLE` / `UNCONFIRMED`, never as a finding.

**The decoy is not special-cased.** There is no `if (decoy)` anywhere in the analyzer. It
falls out of one general rule: *any artifact that names a path no other artifact knows.*
A second decoy added tomorrow needs no code.

**Rejected signals (explained, not dropped):**

- PID 744 `0x210000` — a valid PE in a private region. **Not executable**, so it is a
  data buffer. A scanner that greps `MZ` in a private region calls this an injection.
- PID 4120 `0x7ff70000` — an executable region holding a valid PE, and
  `C:\Windows\System32\svchost.exe` is on the load list. Ordinary code.

## Negative controls

Four, each a real mutation of a real artifact. A forensics tool that cannot fail is
decoration.

| | control | what must happen |
|---|---|---|
| **A** | rebuild with the injection and the decoy removed | no injection finding, no decoy claim — and the unlinked process is **still** found, because it has its own cause |
| **B** | flip one byte: `4D 5A` → `41 41` at the region start | the injection finding **disappears** (it was about the bytes, not a label), the unlinked-process finding survives, and the region stops counting as a PE candidate |
| **C** | delete the `svchost.exe` rows from SRUM | the injection **demotes to POSSIBLE** on `MEM` alone; the unlinked process is unaffected because `PF`+`AM`+`MEM` still agree |
| **D** | `analyze --expect NOT_A_REAL_FINDING` | exit `4` |

Control A and B together are the one that matters: they are the same generator and the
same parser, differing only in the evidence, and they must give different answers.

## Correlation: tool agreement is not source independence

`tools/correlate.mjs` carves the injected region to a real file and hands the bytes to
implementations that are not this lab:

- **DieE 3.21** → `PE64`
- **YARA-X 1.20.0** with a lab rule → `D12_LabPayload` hit

That raises confidence in an **OBSERVED** value. It does **not** add a source group, and
the tool says so in its own output:

> Tool agreement raises confidence in an OBSERVED value. It does not add a source group:
> all three implementations are reading the same bytes of the same file, so no claim's
> independent-source count changes because of anything in this section.

Treating a second tool as a second source is precisely the mistake that makes
triangulation decorative.

## Volatility 3: the real boundary, recorded

Volatility 3.28.0 **is installed** at `System-Forensics/volatility3/vol.exe` — a frozen
PyInstaller build, so it needs no Python at all (verified: it runs on this box's Python
3.14.7 box without a venv, and also installs cleanly into a 3.10 venv if you want the
source). The lab invokes it for real, on the real image, and records what it says:

```
  ran     frameworkinfo.FrameworkInfo  exit 0
  ran     banners                      exit 0
  refused windows.pslist               exit 1  plugins.PsList.kernel.layer_name:
  refused yarascan.YaraScan            exit 1  plugins.YaraScan.primary: Memory layer for the kernel
```

`banners` needs no kernel and runs on any file. Every kernel-level plugin needs **KDBG plus
a matching PDB**, which only a real acquisition produces. Forcing a translation layer with
`-e`, `--single-location` and `--stackers` does not help — the stacker finds no banner, so
no layer is built. That refusal is asserted by `loop.mjs`, because "it cannot" is a claim
and this is the evidence. `scripts/forensics-lab.ps1 doctor` prints it on demand.

**So: real Volatility 3 does not analyse this image, and this lab never pretends it does.**
`tools/triage.mjs` implements the same plugin *techniques* against a container that can
actually be generated, and the README says which is which.

## Payload provenance

The bytes in the injected region come from one of two producers:

1. **MSVC** — `lab/payload/d12payload.c`, built by `lab/payload/build.bat`. Verified
   byte-reproducible across two runs (`cl /Brepro`):
   `38b127a6c8108d914e6c806351b9861066335e836e47290be3b5aebc8da5c75b`. The `.dll` is
   gitignored; no third-party binary is committed.
2. **Hand-built** — `lab/mkimage.mjs:buildMinimalPe()`, used automatically when the DLL is
   absent, so the loop closes on a box with no compiler. Structurally valid PE32+ (DOS
   header, DOS stub, `e_lfanew`, PE signature, optional header, one section, export
   directory). DieE still calls it `PE64` and YARA-X still hits the marker.

Two producers is a feature: it shows the detection is keyed to the PE *structure*, not to
one compiler's byte layout. The image hash changes with the producer, and the manifest
records which was used.

## Honest limits

- **No acquisition. At all.** No `WinPmem`, no `procdump`, no DMA, no hypervisor, no VM
  snapshot, no `vol.py -f /proc/kcore`. This lab analyses a file it generated. Every number
  in every report is about a fixture.
- **The container is not Windows.** `D12IMG` is a *simplification* of a Windows physical
  image: it has a pool, a list, VADs, sockets and handles, and the parser walks them the
  way Volatility walks them — but the record layouts are this lab's, not `EPROCESS` at any
  real offset. The technique transfers; the bytes do not.
- **Real Volatility 3 cannot read this image**, and neither can System Informer or
  Sysinternals. The lab uses them only as a *capability probe* and as independent
  implementations on the carved PE. Claiming a `pslist` run here would be a fabrication.
- **No live-host analysis.** Nothing in this lab enumerates the processes, handles,
  sockets or drivers of the machine it runs on. `procexp`, `handle`, `tcpview`,
  `SystemInformer`, `Procmon`, `sigcheck` and `Listdlls` are installed and are **not used**:
  running them would be analysis of a real user, which the brief forbids and which this
  lab has no reason to do.
- **No rootkit-level anti-forensics.** No kernel callbacks, no SSDT/IRP hooks, no
  hypervisor, no timestomping, no DKOM beyond the single spliced list node, and nothing
  that hides from *any* of the techniques above. A real rootkit defeats at least one of
  `pslist`/`psscan`/pool scanning; the fixture is defeated by none of them.
- **No encrypted-volume support.** Nothing here reads BitLocker, VeraCrypt, a VHD, a
  hibernation file, or a pagefile. A real lane would start at `malfind` on a decrypted
  image and would need the acquisition step this lab deliberately does not have.
- **No timeline reconstruction beyond what three artifacts happen to contain.** The lab
  joins SRUM, Prefetch and Amcache on timestamps, but there is no super-timeline, no
  TSK/E01 parsing, no EVTX, no `$UsnJrnl`, no MFT.
- **The "independent sources" are synthetic too.** They are three different *formats* with
  three different parsers, which is the property that matters for the invariant, but they
  were written by the same author in the same minute. Real independence would mean
  artifacts acquired by different means on a host nobody here controls.
- **The injected PE is 100 KB of MSVC-compiled C, and capa does not say what you might
  hope.** Measured on `d12payload.dll`: capa reports *write file on Windows (4 matches)*,
  *terminate process*, *enumerate files on Windows*, *link function at runtime*, and
  *reference analysis tools strings*. Every one of those comes from the MSVC C runtime that
  `DllMain` drags in, not from the three lines of lab source — the source is one exported
  marker string and one function returning `0xD12`, and the import table is
  `KERNEL32.dll` and nothing else (verified by parsing the PE). This is worth stating
  plainly: **capa reports on the binary, not on intent**, which is the same lesson the
  triangulation gate teaches, arriving from a different direction.
- **`pslist` is bounded, not proven.** The walk is capped at 4096 records and refuses a
  revisited offset, so a corrupt or hostile list terminates — but a list that loops through
  a cycle the parser has not seen would still truncate. `truncated: true` is reported when
  the cap or the cycle check fires; this fixture never sets it.

## Stop lines

- **Authorized use only.** This is a fixture-driven teaching lane. It analyses a file it
  created, on a machine its owner controls. It is not an acquisition tool, not a
  rootkit, and not a loader, and it must not be pointed at anyone else's host.
- **Nothing is executed.** The payload PE is never run, never loaded, never injected. It is
  written into a file, hashed, and read by static tools. The payload has no network
  capability, no injection capability, and no persistence.
- **No third-party target.** `203.0.113.23` is RFC 5737 TEST-NET-3 and `lab-c2.invalid`
  uses the RFC 2606 reserved TLD. Both are documentation-only and unroutable. There is no
  DNS lookup, no connection, and no callback anywhere in this lab.
- **No third-party binary in git.** The compiled payload is gitignored; the lab ships
  source, a generator, and tools. Generated artifacts live in `%TEMP%\d12-forensics-lab`
  and are deliberately not written into the repo.
- **No real user data.** There is no real user in any artifact here. Every path, PID,
  timestamp, and hash in the fixture is invented and the image says so in its own header.

## See also

- `../../wiki/methods/analysis-loop.md` — the 7-phase loop this lab is one column of, and
  the three invariants its gates enforce. This lab is the **memory forensics** column:
  acquire (not built), preserve (hashes, determinism), triage
  (`pslist`/`psscan`/`malfind`/`netscan`/`handlescan`), narrow (cross-view +
  triangulation), instrument (carve, then DiE + YARA-X), verify (ground truth + four
  negative controls), document (this file).
