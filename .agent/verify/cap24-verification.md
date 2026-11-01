# Independent verification of `observed` promotions — `manifests/capabilities.json`

Verifier: independent worker. I did not propose these promotions; my value is in re-deriving the
recorded evidence rather than agreeing with it. Registry `generated` field: `2026-09-30`.
Date of verification: 2026-10-02. cwd for every command: `<repo>`.

**Method.** For each sampled capability I read the recorded entry, then RAN `probe.command` and
`negative_control.command` myself and recorded the REAL exit code (read from `$LASTEXITCODE`
immediately after the process, never through a pipe) and the REAL output. Recorded strings are
quoted separately from observed output so the comparison is falsifiable.

**Two environment deviations, declared up front.**

1. `bash` here is WSL2 and cannot see `D:`. All commands were run through
   `powershell -NoProfile -ExecutionPolicy Bypass -File <temp .ps1>`.
2. `native.ida.list_functions` and `native.ida.decompile` both probe via `native-lab/tools/loop.mjs`,
   which spawns `idalib-mcp` directly against `crackme-corpus/out/c01-stringobf.exe`. IDA writes
   `.id0/.id1/.id2/.nam/.til` database files next to the binary — those already exist in the repo
   (`c01-stringobf.exe.i64` is 2,478,566 bytes, `.id0` dated Oct 2 09:20). My Non-Conflict is
   read-only on the repository, so I staged an isolated root under
   `%TEMP%/verify-obs/idaroot/` containing a byte copy of `c01-stringobf.exe` and the *unmodified*
   `loop.mjs` / `ida-client.mjs` / `decompile.mjs` / `list-funcs.mjs`, and ran the recorded probe
   script there. The probe script, the target bytes and the instrument are identical; only the
   write target for IDA's database differs. This is a deviation and is labelled as one.

---

## 1. native.pe.container  (observed; root_reason; invoke.argv populated)

**Probe — MATCHES-RECORDED.**

```
python -c "import pefile;pe=pefile.PE(r'crackme-corpus\out\c01-stringobf.exe');print(hex(pe.OPTIONAL_HEADER.ImageBase),hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),hex(pe.OPTIONAL_HEADER.DllCharacteristics))"
```
Real exit: `0`. Real stdout, verbatim:
```
0x140000000 0x15d0 0x8160
```
Recorded `probe.expect`: `"0x140000000 0x15d0 0x8160"`. Exact match, character for character.
Recorded `probe.expect_exit`: `0`. Matches.

**Negative control — REFUSED-AS-DECLARED.**

```
python -c "import pefile; pefile.PE('README.md')"
```
Real exit: `1`. Real output, verbatim tail:
```
  File "D:\Software\Developer\Python314\Lib\site-packages\pefile.py", line 3082, in __parse__
    raise PEFormatError("DOS Header magic not found.")
pefile.PEFormatError: 'DOS Header magic not found.'
```
Recorded `negative_control.expect_exit`: `1`. Recorded `expect_output`:
`PEFormatError: 'DOS Header magic not found.'`. Both match. The refusal is genuine: the identical
one-liner against `c01-stringobf.exe` exits `0`, so same interpreter, same shape, opposite exit.
This control fails because of the property it claims to guard (DOS magic absent), not because the
command was broken.

**FINDING 1 — `native.pe.container.negative_control.measured` contains a string that is false on
this host.** The exact wrong string is:

> `"the wrapper prints REFUSED and exits 2"`

`native-lab/tools/pe_probe.py` never prints the word `REFUSED`. I ran it against `README.md`:
```
PE_PROBE_EXIT / CTL_EXIT=2
{"ok": false, "exit": 2, "error": "not a PE: first two bytes are 2320, expected 4d5a ('MZ')", "first_bytes": "2320"}
```
Programmatic check: `contains_REFUSED=False`. The exit code `2` is real and the refusal is real;
only the literal token `REFUSED` is invented. Two consequences worth naming: (a) the recorded
`measured` describes a *different* command from the recorded `negative_control.command` — the
recorded command is the bare `python -c` one-liner (exit 1), the `measured` string describes the
wrapper (exit 2), and no recorded field tells a reader that two different commands are in play;
(b) a maintainer grepping `pe_probe.py` for `REFUSED` finds nothing and concludes the wrapper
changed. `expect_output` correctly describes the one-liner; `measured` does not describe the same
command. **Severity: documentation defect in the evidence field, not a behavioural defect.**

**`invoke.argv` routability — ROUTABLE.** `argv = ["native-lab/tools/pe_probe.py", "{target}"]`.
I ran it: exit `0`, `ok=true`, keys
`ok,exit,binary,sha256,size,machine,is_64bit,image_base,entry_rva,dll_characteristics,aslr,sections,security_directory,caveat`,
with `image_base=0x140000000 entry_rva=0x15d0 aslr={"dynamic_base":true,...}`. `{target}` is
substituted by `mission.ps1:812` from the mission target; it is the single declared input
`binary`/`target`. Every `fact_map` source key (`image_base`, `entry_rva`, `aslr`, `sections`)
exists and is non-null in the real output, so `mission.ps1:948-956` would record all four.

**`does_not_prove` check — CONSISTENT.** The entry forbids reading `pe.aslr` as behaviour and
forbids handing `pe.image_base` to a runtime hook. The observed output contains only header
values and an explicit `"caveat"` string; nothing in it claims execution or trust. No conflict.

---

## 2. native.pe.packer  (observed; root_reason; PRECONDITION-GATED; invoke.argv populated)

This is the precondition-gated sample: `invoke.gate_role = "precondition"`, honoured by
`mission.ps1:990-996`, which records `precondition_failed` and names what it blocks.

**Probe — MATCHES-RECORDED.**

```
powershell -NoProfile -ExecutionPolicy Bypass -File headless-lab\tools\triage-packer.ps1 -Target crackme-corpus\out\c01-stringobf.exe
```
Real exit: `0`. Real stdout, verbatim (one line, truncated here only where the tool's own `caveat`
runs long):
```
{"ok":true,"precondition":"PASS means it is safe to decompile. A packed target reports ok:false and the mission skips every downstream round rather than analysing a stub.","target":"<repo>\\crackme-corpus\\out\\c01-stringobf.exe","size":143872,"die_score":6.15091,"die_verdict":"not packed","packed":false,"caveat":"DERIVED FROM DIE'S OWN VERDICT, NOT FROM A NUMERIC THRESHOLD. ...","score_is_advisory":true}
```
Recorded `probe.expect`: `"packed": false`. Real output contains `"packed":false` — **the
whitespace differs.** `triage-packer.ps1` emits compact JSON; the recorded expect string has a
space after the colon. A literal substring match on the recorded `expect` string FAILS against the
tool's actual output. This is a recorded-string defect, not a behavioural one: the boolean is
`false` as declared and the exit is `0` as declared.

**Negative control — REFUSED-AS-DECLARED.**

```
powershell -NoProfile -ExecutionPolicy Bypass -File headless-lab\tools\triage-packer.ps1 -Target README.md
```
Real exit: `2`. Real output, verbatim:
```
{"ok":false,"exit":2,"error":"not a PE: first two bytes are 2320, expected 4d5a ('MZ'). Die would have scored this anyway and said 'not packed'.","first_bytes":"2320","size":7354}
```
Recorded `expect_exit`: `2`. Recorded `expect_output`: `not a PE: first two bytes are 2320`.
Both match. The refusal is the guarded property, not an accident.

**I also re-derived the control's own justification, because that is the load-bearing part.** The
registry claims raw `diec.exe` scores `README.md` as clean. I ran it (the tool lives at
`Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe` relative to the repo root, exactly as
`requires.tools[0].probe` is written):
```
RAW_DIEC_README_EXIT=0
  Total 5.26547: not packed
```
Confirmed independently: raw Die returns exit `0` and `Total 5.26547: not packed` on a markdown
file. The wrapper's refusal is the whole reason this entry exists, and the defect it fixes is real.

**FINDING 2 — `native.pe.packer.invoke.fact_map` maps to a fact key NO capability declares.**
Exact wrong strings, under key `native.pe.packer.invoke.fact_map`:
```
"die_verdict": "pe.packer_verdict",
"die_score":   "pe.die_score"
```
`pe.packer_verdict` is produced by **no capability in the registry**. `native.pe.packer`'s own
`produces.facts` declares `pe.packed`, `pe.die_score`, `pe.magic`. I enumerated every
`produces.facts[].key` across all 24 entries: `pe.packer_verdict` appears nowhere. Consequences,
which I confirmed by re-running the tool and applying `mission.ps1:948-956` by hand:
- `die_verdict` IS present and non-null in stdout, so the loop records a fact under key
  `pe.packer_verdict` — a key with no declared type and no declared producer.
- `packed` — the boolean this capability actually exists to produce, and the one
  `invoke.success_when` reasons about — is **not in `fact_map` at all**, so a mission never
  forwards `pe.packed` to any consumer. The fact the precondition decision rests on is the one
  fact the chain drops.

This is the exact class the registry's own `R11` rule exists to catch on the *consume* side
(`consumes.inputs[].from.field`), and `registry-verify.py` has **no rule** checking `fact_map`
*target* keys against `produces.facts[].key`. `python scripts/registry-verify.py` prints
`REGISTRY CLEAN` and exits `0` while this defect is live. I confirmed the validator's rule list by
reading its `r1`..`r19` function names: nothing constrains `fact_map` values. **Severity: real
defect, silently green.**

**FINDING 3 — `native.disasm.capstone.invoke.fact_map` has the same defect.** Exact wrong strings:
```
"insns":       "native.insn.stream",
"rip_operands": "native.insn.rip_operand"
```
`native.disasm.capstone` declares `produces.facts` keys `insn.stream`, `insn.rip_operand`,
`pe.section_exec` — **without** the `native.` prefix. Neither `native.insn.stream` nor
`native.insn.rip_operand` is produced by any capability; I checked all 24 entries. The two are the
same strings with a prefix added. Consequence confirmed by hand: a mission records the instruction
stream and the resolved-operand set under keys no consumer declares, while the declared keys
`insn.stream` / `insn.rip_operand` stay empty, and `pe.section_exec` is never bound at all.

The irony is not lost: `native.disasm.capstone.invoke.note` is the entry that warns "the registry
disagrees with itself is a registry nobody can reason about," and `schema.evidence_families`
concludes with the same sentence. The defect is in this very file.

**FINDING 4 — `native.pe.packer.probe.expect` will not substring-match.** Exact string:
`"packed": false` (with a space). The tool emits `"packed":false`. See probe section above.

**`invoke.argv` routability — ROUTABLE.** `argv = ["-NoProfile","-ExecutionPolicy","Bypass","-File","headless-lab/tools/triage-packer.ps1","-Target","{target}"]`,
`runner: powershell`. `{target}` is the mission target. Every fact_map *source* (`die_verdict`,
`die_score`) is present and non-null in the real output. Routable — with FINDING 2 attached: it
routes, and records the wrong keys.

**`does_not_prove` check — CONSISTENT.** The entry forbids treating `packed:false` as proof of
unpacking, forbids reading the score as a threshold, and — importantly — states outright that the
**positive branch has never run**: "no packer is available on this host to build a packed control".
I checked the host: `out/` holds no packed binary and no UPX. The observed output contains
`"score_is_advisory": true` and a `caveat` explicitly naming the 5.0-threshold mistake, so the
instrument carries its own honesty. The entry does not over-claim. **This entry is the best
discipline in the sampled set.**

---

## 3. native.disasm.capstone  (observed; NO root_reason; invoke.argv populated)

Sampled partly because it declares **no** `root_reason` — the only sampled entry that does not,
while producing three facts and consuming a declared edge. See FINDING 7.

**Probe — MATCHES-RECORDED.**

```
python native-lab/tools\disasm.py crackme-corpus\out\c01-stringobf.exe --rva 0x1080 --count 40
```
Real exit: `0`. Real output contains, verbatim from the `rip_operands` array:
```json
{ "at": "0x1400010e1", "text": "movzx r9d, byte ptr [rip + 0x16259]",
  "target": "0x140017342", "width": "byte", "byte": 90, "dword": 734042 },
{ "at": "0x1400010e9", "text": "mov r8d, dword ptr [rip + 0x16254]",
  "target": "0x140017344", "width": "dword", "byte": 11, "dword": 11 },
{ "at": "0x14000110b", "text": "movzx r9d, byte ptr [rip + 0x16230]",
  "target": "0x140017343", "width": "byte", "byte": 51, "dword": 2867 },
{ "at": "0x140001113", "text": "mov r8d, dword ptr [rip + 0x1624a]",
  "target": "0x140017364", "width": "dword", "byte": 5, "dword": 5 }
```
Recorded `probe.expect`: `0x140017342 width=byte`. **Exact match**: `target` is `0x140017342` and
`width` is `byte` on the same operand record. Recorded `expect_exit`: `0`. Matches.

I also re-derived the `run_log` claim independently rather than trusting it: `count 40`,
`file_offset 0x480`, `rva 0x1080`, `image_base 0x140000000`, 9 RIP-relative operands, and
`cmp dword ptr [rsp + 0xa0], 2` at `0x1400010a2`. All confirmed in the raw output. The recorded
`run_log` lists exactly those nine operands and they match one-for-one, including the values that
look wrong until you check the width (`0x140017342` as a natural u32 is `734042`; as a byte it is
`90`). **The entry's central and most interesting claim re-derives exactly.**

**Negative control — REFUSED-AS-DECLARED.**

```
python native-lab/tools\disasm.py crackme-corpus\out\c01-stringobf.exe --rva 0x17000
```
Real exit: `2`. Real output, verbatim:
```
{"ok": false, "exit": 2, "error": "RVA 0x17000 is in section '.rdata' (Characteristics 0x40000040), which is NOT executable. Decoding it yields plausible-looking instructions built out of data bytes; pass --force only if you know that section really holds code.", "section": ".rdata", "characteristics": "0x40000040"}
```
Recorded `expect_exit`: `2`. Recorded `expect_output`: `which is NOT executable`. Both match. This
is a strong control: it fails because of the guarded property (`.rdata` lacks
`IMAGE_SCN_MEM_EXECUTE`), not because the command broke.

**`invoke.argv` routability — ROUTABLE, and I ran the whole chain.** `argv` is
`["native-lab/tools/disasm.py","{target}","--hex","{input.function}","--count","48"]`.
`{input.function}` resolves via `invoke.consumes_fact = "native.func.addr"`, produced by
`native.ida.list_functions`. I ran `list-funcs.mjs` for real (exit `0`, `count: 362`,
`main` at `0x140001080`, size `0x17e`), took that address as the loop would via
`select.by_name="main"` + `select.element_path="addr"`, and fed it to the capstone argv:
```
node native-lab/tools/list-funcs.mjs ... --json   -> ok=True count=362 named_len=162 first_named=['main','printf','__GSHandlerCheck']
node native-lab/tools/disasm.py <exe> --hex 0x140001080 --count 48
   -> INVOKE_CAPSTONE_EXIT=0, ok=True rva=0x1080 file_offset=0x480 count=48 rip_ops=10
      insn0=0x140001080 mov qword ptr [rsp + 0x10], rdx
```
The wrapper correctly rebases `0x140001080` → RVA `0x1080` internally, exactly as
`invoke.note` claims, and `--count 48` matches the recorded argv. **Every placeholder resolves:
`{target}` to the mission target, `{input.function}` to a fact `native.ida.list_functions`
actually emits.** With FINDING 3 attached — it routes, and lands the facts under undeclared keys.

**`does_not_prove` check — CONSISTENT.** The entry forbids reading instructions as recovered logic
and states the acceptance mission still returns `unresolved`. The real output carries a `caveat`
key saying exactly that. No conflict.

**FINDING 5 — `native.disasm.capstone.does_not_prove` contains a stale, self-contradicting
claim.** The exact wrong string, under `native.disasm.capstone.does_not_prove[4]`:
> "**So four capabilities in this registry, including the only instrument in a genuinely different
> family, cannot be planned into a mission.**"

This is false in the registry as it stands. `native.disasm.capstone` **does** carry an `invoke`
block (`argv` populated, `success_when`, `fact_map`, `select`), and I executed that argv end to
end successfully. Its own `invoke.note` says "This is the consumer half of the arsenal's first
chain that spans TWO evidence FAMILIES," and the immediately following `does_not_prove[5]` entry
correctly describes the newer `by_name` selector. The paragraph was written when the entry had no
`invoke` block and was never updated; the two halves of the same entry now contradict each other.
A reader taking `does_not_prove[4]` at face value would conclude the capability is uncallable and
skip it. **Severity: documentation defect that inverts the capability's status.**

**FINDING 6 — `native.ida.list_functions.probe.last_summary` says 300 functions; the instrument
returns 362.** Exact recorded string: `"300 functions enumerated from c01-stringobf.exe"`. I
re-derived it two ways:
- via `loop.mjs --only=list_funcs`, which queries `{count: 300}` and prints `300 functions` — the
  **query cap**, not the population;
- via `list-funcs.mjs --json`, which queries `{count: 2000}` and returns **`count: 362`**.

The `300` in the recorded summary is the value of a `count` parameter that was deliberately set
low, presented as an enumeration result. The registry's own `native.disasm.capstone.does_not_prove[5]`
says "362 functions" — so the registry contradicts itself, and the `362` is the correct figure.
This is precisely the denominator error the registry repeatedly warns about, committed by the
registry. **Severity: real number defect. A mission that routed `list-funcs.mjs` would see 362;
the entry tells a reader 300.**

Useful by-product: I also checked the "no duplicate names" claim in `does_not_prove[5]`. Over the
362 returned functions, `collections.Counter` finds **no duplicate names at all**, and exactly one
`main` at `0x140001080`. That claim re-derives.

**FINDING 7 — `native.disasm.capstone` declares no `root_reason` while producing three facts and
consuming a declared edge.** It has `invoke.consumes_fact = "native.func.addr"` (a real edge) and
declares `insn.stream`, `insn.rip_operand`, `pe.section_exec`. `registry-verify.py` has `r14_no_island_capability`
precisely to catch this shape, and it passes — I read the rule at `registry-verify.py:613`: an
observed capability that produces a fact is either chained or says it is a root. This entry is
chained, so the rule is satisfied legitimately. But the two *sampled* entries that DO carry
`root_reason` (`native.pe.container`, `native.pe.packer`, `native.pe.authenticode`) each ship two
paragraphs explaining why the absence of a typed edge is "a decision rather than an oversight";
`native.disasm.capstone` ships no such statement while consuming an edge. **Severity: minor
inconsistency in an otherwise consistent convention. Not a defect the validator is wrong to pass.**

---

## 4. native.behaviour.capa  (observed; root_reason; invoke.argv populated)

**Probe — MATCHES-RECORDED.**

```
python native-lab\tools\capa_probe.py crackme-corpus\out\c01-stringobf.exe
```
Real exit: `0`. Elapsed: **31.8 s** (recorded: "~33 s" — within noise). Real stdout, verbatim head:
```
{"ok": true, "exit": 0, "binary": "crackme-corpus\\out\\c01-stringobf.exe", "capa_version": "(not reported in -j output)", "rules_matched": 14, "namespaces": {"linking/runtime-linking": 1, "(none)": 4, "load-code/pe": 1, "host-interaction/process/terminate": 1, "data-manipulation/compression": 1, "host-interaction/file-system/files/list": 1, "host-interaction/environment-variable": 2, "host-interaction/file-system/write": 1, "host-interaction/file-system/meta": 1, "anti-analysis": 1}, "matches": [{"rule": "link function at runtime on Windows", ...}, {"rule": "change memory protection", ...}, ...
```
Recorded `probe.expect`: `"rules_matched": 14`. **Exact match** — including the whitespace, because
`capa_probe.py` emits default-spaced JSON. Recorded `expect_exit`: `0`. Matches.

I re-derived the namespace histogram myself rather than accepting the recorded string: the ten
namespaces and their counts match the recorded `run_log` one-for-one (`(none):4`,
`host-interaction/environment-variable:2`, eight singletons). **10 namespaces, 14 rules, sum
verified.**

**Negative control — REFUSED-AS-DECLARED.**

```
python native-lab\tools\capa_probe.py README.md
```
Real exit: `2`. Elapsed: **0.05 s** (recorded: "in well under a second" — confirmed, and the
recorded contrast with capa's ~3 s engine start holds). Real output, verbatim:
```
{"ok": false, "exit": 2, "error": "not a PE: first two bytes are 2320, expected 4d5a ('MZ')", "first_bytes": "2320"}
```
Recorded `expect_exit`: `2`. Recorded `expect_output`: `not a PE`. Both match. The refusal names
the offending bytes rather than returning zero findings, which is the property the control exists
to guard — and this is the correct design: zero rules on a markdown file would be
indistinguishable from a clean binary.

**I re-derived the control's own justification.** The registry claims raw `capa.exe -j README.md`
exits `16` after ~3 s with a non-parseable banner. I ran it:
```
RAW_CAPA_README_EXIT=16 ELAPSED=1.6s
capa.exe : ERROR    capa:                                                   helpers.py:274
```
Exit `16` confirmed; elapsed `1.6 s` rather than the recorded "roughly three seconds" — the
registered path is `.\Static-Reversing\capa\capa.exe`, identical to the recorded one. Minor timing
discrepancy, no bearing on the claim.

**`invoke.argv` routability — ROUTABLE.** `argv = ["native-lab/tools/capa_probe.py","{target}"]`.
`{target}` resolves from the mission target; `{input.*}` placeholders: none. Both `fact_map` sources
(`matches`, `rules_matched`) are present and non-null in the real output, so
`mission.ps1:948-956` would record `behav.pattern` and `behav.count`. **This entry's `fact_map` is
correct** — the only one of the sampled populated ones that is.

**`does_not_prove` check — CONSISTENT.** The entry forbids calling a rule match maliciousness and
forbids reading absence of a match as safety. The observed output carries no such claim; it reports
a count and a namespace histogram. No conflict. The `"change memory protection"` match visible in
my raw output is precisely the example the `does_not_prove` text names as NOT proving behaviour, so
its presence does not violate anything — but note that a raw consumer of stdout could misread it,
which is what `gate_must_not_delegate` is for.

---

## 5. native.pe.authenticode  (observed; root_reason; NO invoke)

Sampled for `root_reason` and because it is one of only two sampled entries with **no `invoke`
block** — a routability question in its own right.

**Probe — MATCHES-RECORDED.**

```
python headless-lab\tools\authenticode.py crackme-corpus\out\c01-stringobf.exe
```
Real exit: `0`. Real output, verbatim:
```json
{
 "ok": true, "exit": 0, "binary": "crackme-corpus\\out\\c01-stringobf.exe", "file_size": 143872,
 "security_va_is_a": "FILE OFFSET (not an RVA) -- true for IMAGE_DIRECTORY_ENTRY_SECURITY",
 "security_offset": 0, "security_size": 0,
 "caveat": "THIS DOES NOT VERIFY ANYTHING. ...",
 "signed": false, "reason": "no certificate table: IMAGE_DIRECTORY_ENTRY_SECURITY is empty"
}
```
Recorded `probe.expect`: `"signed": false`. **Exact match, including whitespace** (this tool
pretty-prints). Recorded `expect_exit`: `0`. Matches. Recorded `run_log` claims
`security_offset 0, security_size 0` and the reason string — both confirmed verbatim.

**Negative control — REFUSED-AS-DECLARED.** The recorded control is a **three-stage chain**, and
I ran all three stages.

Stage 1 — build the positive fixture:
```
python headless-lab\tools\authenticode.py crackme-corpus\out\c01-stringobf.exe --make-control "%TEMP%\signed-fixture.exe"
STAGE1_EXIT=0
{"ok": true, "exit": 0, "fixture": "...\\signed-fixture.exe", "cert_offset": 143872, "cert_len": 48, "payload": "ARSENAL-FIXTURE-NOT-A-REAL-SIGNATURE "}
FIXTURE_EXISTS=True SIZE=143920
```
Stage 1b — re-read the fixture (the recorded `measured` positive case):
```
STAGE1B_EXIT=0   "signed": true, "security_offset": 143872, "security_size": 48
  "win_certificate": { "header_offset": 143872, "dwLength": 48, "wRevision": "0x200",
    "revision_is_2_0": true, "wCertificateType": "0x2", "type_is_pkcs_signed_data": true,
    "blob_offset": 143880, "blob_len": 40, "blob_sha256_prefix": "10a0c01118ca9b20",
    "blob_ascii_head": "ARSENAL-FIXTURE-NOT-A-REAL-SIGNATURE    " }
```
**Every single number in the recorded `measured` string re-derives exactly**: `signed true`,
`security_offset 143872`, `dwLength 48`, `revision_is_2_0 true`, `type_is_pkcs_signed_data true`.

Stage 2 — the actual control, truncate by 60 bytes and re-read:
```
orig 143920 trunc 143860
{"ok": false, "exit": 2, "error": "certificate table at file offset 0x23200 runs past the end of a 143860-byte file; the directory is pointing outside the file"}
CONTROL_REAL_EXIT=2
```
Recorded `expect_exit`: `2`. Recorded `expect_output`: `runs past the end of`. Both match. The
recorded `measured` says "truncated to 143860 bytes with the directory still at 143872" — I
measured exactly `orig 143920 trunc 143860` and the directory value `0x23200` is `143872` in hex.
**Two-sided control, and it is genuinely two-sided: signed:true on stage 1b, refused on stage 2,
from the same code.** That is what makes `signed:false` mean anything, and it is real.

The fixture files were created in `%TEMP%`, outside both repositories, and are removable; the
corpus original was copied, never modified (`--make-control` appends to a copy — I verified the
corpus `c01-stringobf.exe` is still 143,872 bytes after the run, matching the packer probe's
independent reading of the same file).

**`invoke` routability — NOT ROUTABLE, BY OMISSION.** This entry has **no `invoke` block at all**.
There is no `argv`, no `success_when`, no `fact_map`. A mission cannot call it with arguments; it
can only be re-probed by a human. Its three declared facts — `pe.signed`, `pe.cert_header`,
`pe.security_dir` — are produced by nothing and consumable by nothing. This is not a hidden
defect: the tool emits clean, parseable JSON on stdout with `ok`/`signed`/`win_certificate`
already in a usable shape, so a wrapper could be added cheaply. But the registry's own audit of
callable ratio (quoted in `native.pe.container.invoke.note` as "8 of 23") is now stale in the
other direction — this entry was written to expand coverage and remains uncallable.

**`does_not_prove` check — CONSISTENT, and the strongest in the sampled set.** The entry forbids
reading `signed:true` as trust or integrity, forbids reading `signed:false` as "never signed"
rather than possibly stripped, and forbids reading the PKCS#7 blob as well-formed. My observed
output carries `"caveat": "THIS DOES NOT VERIFY ANYTHING. 'signed: true' means 'there is a
WIN_CERTIFICATE here', NOT 'this binary is trusted' -- no chain is built, no revocation is checked,
and a self-authored fixture will read as signed."` The caveat travels **in the payload**, so a
consumer who only reads stdout cannot miss it. `blob_sha256_prefix` is presented as an identity
and the entry says so. No output supports a forbidden claim. **This is the entry the others should
be measured against.**

---

## 6. dynamic.win.frida.intercept  (observed; escalation_class = owner_word; invoke.argv populated)

Sampled as the `escalation_class: "owner_word"` sample — the only sampled entry at that level, and
the registry's `escalation_why` says this was raised from `none` deliberately because the
capability spawns **and executes** a binary.

**Environment first, because the registry's own `requires.tools[0].probe` says frida lives only
in the objection venv:**
```
FRIDA_PY_EXISTS=True
frida 17.17.0
FRIDA_IMPORT_EXIT=0
```
`17.17.0` as recorded. Bare system `python` would `ModuleNotFoundError`; the registry is right
about this and the `invoke.runner` correctly uses an absolute path rather than bare `python`.

**Probe — MATCHES-RECORDED.**

```
$py='...\Mobile-Android\objection\.venv\Scripts\python.exe'; $d=Join-Path $env:TEMP 'fridagate';
New-Item -ItemType Directory -Force -Path $d | Out-Null;
Copy-Item '...\crackme-corpus\out\c01-stringobf.exe' (Join-Path $d 'target.exe');
& $py '...\native-lab\tools\frida_spawn_gate.py' (Join-Path $d 'target.exe') positive
```
Real exit: `0`. Real output, verbatim (the `[stage]` line is stderr):
```
[stage] copied to %TEMP% %TEMP%\fridagate-8l7ovnaq\target.exe (143872 bytes); the repository original is never executed
[pe  ] {"magic": "0x20b", "entry_rva": 5584, "size_of_image": 163840}
[spawn] pid=29048 suspended=True
[js  ] {"kind": "module", "name": "target.exe", "base": "0x7ff7bd540000", "size": 163840, ...}
[js  ] {"kind": "rebase", "ok": true, "target": "0x7ff7bd5415d0", "inImage": true}
[js  ] {"kind": "attached", "target": "0x7ff7bd5415d0"}
[load] script loaded while main thread suspended
[resu] main thread resumed
[js  ] {"kind": "HIT", "at": "0x7ff7bd5415d0", "tid": 4856}
[end] hit count=1 at=0x7ff7bd5415d0
[end] verdict=INTERCEPT-PROVEN
ACCEPTED
FLAG{c01_string_table_xor}
{"ok": true, "exit": 0, "mode": "positive", "verdict": "INTERCEPT-PROVEN", "runtime_hook_hit": {"at": "0x7ff7bd5415d0", "count": 1, "tid": 4856}, "instrument_ordering": "spawn(suspended) -> create_script -> load -> resume. ...", "caveat": "SELF-BUILT CORPUS TARGETS ONLY, ..."}
```
Recorded `probe.expect`: `verdict=INTERCEPT-PROVEN`. **Exact match** — present twice, once in the
human log and once in the JSON. Recorded `expect_exit`: `0`. Matches.

The whole point of this entry is the ORDERING, and I verified it rather than trusting it:
`[load] script loaded while main thread suspended` **precedes** `[resu] main thread resumed`, and
the HIT follows the resume. That is spawn → attach → create_script → load → resume, as
`produces.facts[].instrument.ordering` claims. Also confirmed: `hit count=1` exactly, `inImage:
true`, target `= base + entry_rva` (`0x7ff7bd540000 + 0x15d0 = 0x7ff7bd5415d0` — I added it up),
and the `0x20b` PE magic with `entry_rva 5584 = 0x15D0`, which independently agrees with
`native.pe.container`'s `pe.entry_rva 0x15d0` measured by pefile. **Two instruments, two
code lineages, same entry RVA.**

Note the module base differs from the recorded run (`0x7ff7bd540000` observed vs `0x7ff79e010000`
recorded). This is expected and is exactly what the entry says: the base "varies ACROSS sessions
and is not safe to hardcode". The entry also carries a measured correction that the base did *not*
vary across five consecutive runs on the recording day. Both statements survive my observation.

**Negative control — REFUSED-AS-DECLARED, both stages.** The recorded control is deliberately a
two-stage chain with only ONE exit-code-bearing stage. I ran both and read each exit directly.

Stage 1 — `neg-badaddr` (must SUCCEED at detecting, exit 0):
```
[js  ] {"kind": "rebase", "ok": true, "target": "0x7ff6109c9000", "inImage": false}
[js  ] {"kind": "attach-error", "target": "0x7ff6109c9000", "message": "access violation accessing 0x7ff6109c9000"}
[end] verdict=NEGCTL-OK bad-address (distinguishable from rebase failure)
STAGE1_EXIT=0
```
Matches recorded `measured` exactly in shape: `rebase ok=true`, `inImage=false`, attach-error
`access violation`, verdict `NEGCTL-OK bad-address`, exit 0. The entry's reasoning for exit 0 here
is sound and I endorse it: detecting a bad address IS that mode's success.

Stage 2 — `neg-rebase` (this is the one that must fail):
```
[js  ] {"kind": "rebase", "ok": false, "base": "null", "reason": "target module not loaded: base is null"}
[js  ] {"kind": "compute-error", "message": "cannot read property 'base' of null"}
[end] failed while COMPUTING the address (no base): cannot read property 'base' of null
[end] attach never attempted: attach_error=None
[end] verdict=REBASE-FAILURE
STAGE2_EXIT=3
COMBINED_LASTEXIT=3
```
Recorded `expect_exit`: `3`. **Matches.** Recorded `expect_output`: `attach never attempted:
attach_error=None`. **Exact match**, verbatim. The failure is for the right reason: the module base
is null, so the failure occurs while COMPUTING the address and `Interceptor.attach` is never
called — which is precisely the distinction the entry claims is load-bearing.

I also note the entry's own warning about how exit codes must be read — "Exit codes were read
directly from the process, NOT through a pipeline — an earlier reading took $? from the tail of a
pipe and reported every mode as 0, which would have hidden the very failure the control exists to
prove." I read `$LASTEXITCODE` immediately after each invocation; stage 2 returned `3` while stage 1
returned `0`, in the same script, which is only possible if the codes are real.

**`invoke.argv` routability — ROUTABLE, with one real hazard I checked rather than assumed.**
`argv = ["native-lab/tools/frida_spawn_gate.py","{target}","positive"]`, `runner` = the absolute
venv python path. `{target}` resolves from the mission target; no `{input.*}` placeholder.
Both `fact_map` sources (`runtime_hook_hit`, `instrument_ordering`) are present and non-null in the
real JSON. `positive` is the only mode wired, and the entry explains why the negative modes are
deliberately excluded — "a mission must not be able to schedule its own failure mode as if it were
evidence." Correct, and confirmed by the source: `MODE = sys.argv[2]` at
`frida_spawn_gate.py:37`.

The hazard: `argv[0]` is a **relative** path (`native-lab/tools/frida_spawn_gate.py`) while the
`runner` is absolute. This works because `mission.ps1:93-94` does
`$RepoRoot = Split-Path -Parent $PSScriptRoot; Set-Location $RepoRoot` before any round, so cwd is
the repo root. I confirmed those two lines in the source. **Routable, and the relative path is
load-bearing on that `Set-Location`** — which is itself undocumented in the entry. If `argv[0]`
were ever executed from a different cwd the round would fail with a file-not-found, not with a
refusal. Worth a sentence in `invoke.note`; not a defect today.

I also verified the safety claim rather than taking it on faith. `frida_spawn_gate.py:256-265`
copies the target into a fresh `tempfile.mkdtemp(prefix="fridagate-")` and spawns the copy, and
`stage_copy` refuses anything not ending `.exe` with `sys.exit(2)`. My run shows the repository
original was never executed — the spawned path was
`%TEMP%\fridagate-8l7ovnaq\target.exe`. The corpus
`c01-stringobf.exe` remains 143,872 bytes and its `.i64` was untouched.

**`does_not_prove` check — CONSISTENT.** The entry forbids claiming the CLI sibling is wrong, forbids
generalising from one hit, and forbids any technique claim about a third party. The observed output
reports `count: 1` on the entry point and says nothing about reachability or calling convention.
The JSON `caveat` restates the self-authored boundary. No output supports a forbidden claim.

---

## 7. native.ida.list_functions  (observed; root_reason; invoke.argv populated)

Run in the staged TEMP root (deviation declared at the top). `idalib-mcp` is driven through its
loopback MCP interface by the probe script itself, exactly as recorded.

**Probe — MATCHES-RECORDED.**

```
node native-lab/tools/loop.mjs --only=list_funcs
```
Real exit: `0`. Real output, verbatim:
```
  PASS  port is free before we start                         http://127.0.0.1:8745/mcp was not answering before we spawned anything
  PASS  idalib-mcp serves MCP over POST on loopback          127.0.0.1:8745
  PASS  server exposes a decompile tool                      66 tools; serverInfo={}
  PASS  session opened on our own target                     e3019ddf -> c01-stringobf.exe
  PASS  list_funcs enumerates functions                      300 functions
  PASS  main is located by name                              0x140001080 size 0x17e

LOOP CLOSED: ...
JSON-SUMMARY {"total":6,"pass":6,"fail":0}
```
Recorded `probe.expect`: `list_funcs enumerates functions`. **Exact match** — the string is in the
output verbatim. Recorded `probe.exit`: `0`. Matches. Recorded `last_summary`: `300 functions
enumerated from c01-stringobf.exe` — the `300` here is the loop's own query cap and reproduces
exactly (see FINDING 6: the true figure is 362).

I also verified the recorded `distinct_probe_note` claim that `--only=list_funcs` runs **zero** of
the decompile assertions: the run above has exactly 6 checks and none of them mention decompilation.
Correct — the scoping is real and it does localise faults.

**Negative control — WEAK, and I have to be blunt about why.** The recorded control is:

```json
"negative_control": {
  "id": "native.ida.list_functions.no_session",
  "command": "list_funcs with no database bound",
  "expect_exit": 1,
  "why": "must refuse rather than answer from an unstated session"
}
```

Three problems, in increasing order of seriousness:

1. **`negative_control.command` is prose, not a runnable command.** `"list_funcs with no database
   bound"` cannot be pasted into a shell. Unlike `probe.command`, which the validator's `R2` rule
   explicitly polices for being prose (I read `r2_observed_needs_probe` at `registry-verify.py:151`),
   no rule polices `negative_control.command` for the same defect.
2. **`negative_control` has no `measured` field at all.** I checked across the registry: of the
   entries I sampled, `native.ida.list_functions` and `native.ida.decompile` are the only two whose
   controls lack `measured`. Every other sampled control carries a measured string.
3. **`expect_exit: 1` is not what the instrument does.** I drove the real refusal against the live
   server myself, calling `list_funcs` with no `database` argument:
   ```
   isError=true
   RAW={"error":"database is required. Pass database=<session_id> with every tool call. Open a session with idb_open or enumerate with idb_list."}
   ```
   The MCP layer reports `isError: true` with a clear error string — it refuses, correctly, for the
   right reason. But there is no process and therefore no exit code, so `expect_exit: 1` is a
   number nothing produces. The only executable form of this control is through the node wrapper,
   and `list-funcs.mjs` exits **2**, not 1, on its refusals — I measured both:
   ```
   node native-lab/tools/list-funcs.mjs                          -> NOARG_EXIT=2   {"ok": false, "error": "usage: list-funcs.mjs <binary> [--json]"}
   node native-lab/tools/list-funcs.mjs /tmp/nope-does-not-exist  -> NOFILE_EXIT=2   {"ok": false, "error": "binary not found: ..."}
   ```
   Those are file-argument refusals, which is not the property the control claims to guard (an
   unstated session), so they do not substitute for it.

**Verdict: WEAK.** It is not a control that exits 0 pretending to be a control, so it is not the
worst shape. But by the stated bar — "it must fail because of the property it claims to guard" —
there is no recorded executable command that exercises that property, and the one number recorded,
`expect_exit: 1`, matches no measured behaviour I could produce. The registry's own
`R5_control_must_fail` rule only checks that a control does not expect exit 0; it cannot catch this.

**`invoke.argv` routability — ROUTABLE.** `argv = ["native-lab/tools/list-funcs.mjs","{target}","--json"]`.
I ran it: exit `0`, `ok True`, `count 362`, `named_len 162`, `first_named ['main','printf','__GSHandlerCheck']`,
and `main = {'addr': '0x140001080', 'name': 'main', 'size': '0x17e'}`. `{target}` resolves from the
mission target. Both `fact_map` sources are present at the JSON root — and the entry's
`fact_map_note` is correct and important: `named` is a **sibling** of `functions`, not a field inside
it. Verified: `functions` and `named` are both top-level keys. This entry's `fact_map` targets
(`native.func.addr`, `native.func.named`) ARE declared in `produces.facts`. **Routable and correct —
unlike FINDING 2 and FINDING 3.**

I also re-derived the downstream contract that `native.disasm.capstone` depends on: exactly one
function named `main`, at `0x140001080`, no duplicate names across all 362. Both consumers'
`select.by_name="main"` and `select.element_path="addr"` therefore resolve deterministically.

**`does_not_prove` check — CONSISTENT.** The entry forbids reading the list as complete and forbids
reading a boundary as authorial intent. The output is a plain function list; no completeness or
intent claim. No conflict.

**Evidence-binding note, not a finding against this entry but material to `observed`.** This entry
carries `probe.evidence_binding.status = "unverified"` with a candid reason: the probe was run but
no artifact was retained. I re-ran it and it passes, so the claim is currently true — but the
registry is honest that "observed" here rests on a summary line, not on a retained artifact. I
counted this across the registry: **12 of 20 `observed` entries carry `evidence_binding: unverified`
with no `run_log` and no `sha256`** — including `web.js.cdp`, `crypto.jose.parse`,
`net.pcap.analyse`, `managed.il.decompile`, `native.ghidra.decompile`. The other 8 carry a
`run_log`. So the sampled set happens to be the well-evidenced half, and I want that on the record
rather than letting my sample imply the whole registry is equally bound.

---

## 8. native.ida.decompile  (observed; NO root_reason; invoke.argv populated)

**Probe — MATCHES-RECORDED.**

```
node native-lab/tools/loop.mjs --only=decompile
```
Real exit: `0`. Real output, verbatim (15 checks, all PASS):
```
  PASS  list_funcs enumerates functions                      300 functions
  PASS  main is located by name                              0x140001080 size 0x17e
  PASS  decompile returns real recovered C for main          867 chars
  PASS  the plaintext decoy flag is recovered from the decompilation FLAG{c01_strings_gave_you_this_decoy}
  PASS  the comparison logic is recovered, not just the strings strcmp present in recovered code
  PASS  decompile carries resolved refs alongside the code   12 refs
  PASS  NEGATIVE: a bogus address yields no code             code=null
  PASS  NEGATIVE: the failure is carried in an `error` field Decompilation failed at 0xdeadbeef
  PASS  CONTROL: isError is FALSE on that failure            isError=false while error is set — an isError-only wrapper logs a success
  PASS  NEGATIVE: a nonexistent symbol is refused by name    Not found: 'no_such_symbol_zzz'
  PASS  NEGATIVE: a missing required parameter is refused    isError=true from the schema layer
LOOP CLOSED: ...
JSON-SUMMARY {"total":15,"pass":15,"fail":0}
```
Recorded `probe.expect`: `LOOP CLOSED`. **Exact match.** Recorded `probe.exit`: `0`. Matches.
Recorded `last_summary`: `JSON-SUMMARY {"total":15,"pass":15,"fail":0}`. **Exact match, character
for character.**

This entry has the best negative-control *execution* of the sampled set, and it is worth naming
why. The `isError:false`-with-an-`error`-field hazard it asserts is real, and the loop asserts it
**from both sides**: it confirms a bogus address yields `code=null`, confirms an `error` string is
present, AND confirms `isError === false` on that same failure. The third assertion is the one that
keeps the documented hazard load-bearing instead of folklore — if a future server fixed the
inconsistency, that assertion would flip and the entry would be re-examined. That is the "control
on the control" pattern, and it is the strongest verification design I saw in this registry.

**Negative control — REFUSED-AS-DECLARED.** Recorded control: `decompile addr=0xDEADBEEF on the
open session`, `expect_exit: 1`, `why: "must yield code:null plus an error field, never code.
Asserted by native-lab/tools/loop.mjs."` The `command` field is again prose, and there is **no
`measured` field** — the second of the two entries lacking one. But unlike the sibling, the entry
points at where the control is actually asserted, and that assertion is machine-checked and passed
in my run (`code=null`, error `Decompilation failed at 0xdeadbeef`).

I additionally ran the control through the **executable** wrapper the entry's `invoke` declares,
which is the stricter test:
```
node native-lab/tools/decompile.mjs crackme-corpus/out/c01-stringobf.exe 0xDEADBEEF
NEG_DECOMPILE_EXIT=1
{
  "ok": false,
  "addr": "0xDEADBEEF",
  "error": "Decompilation failed at 0xdeadbeef"
}
```
Real exit `1`, matching `expect_exit`. **No `code` key is present at all**, and `error` is present
— exactly the property the control claims to guard. **Verdict: REFUSED-AS-DECLARED**, and stronger
than recorded, because I got a real exit code from a real process rather than a check line. I mark
this REFUSED rather than WEAK because the recorded `why` names the asserting code and that
assertion passed; the missing `measured` string is a bookkeeping gap, not a control that fails for
the wrong reason.

**`invoke.argv` routability — ROUTABLE.** `argv = ["native-lab/tools/decompile.mjs","{target}","{input.function}"]`.
`{input.function}` resolves via `invoke.consumes_fact = "native.func.named"`, produced by
`native.ida.list_functions`. I ran it with the value the loop would select — `select.index: 0`
into `native.func.named`, whose first element is `'main'` (I measured
`first_named ['main','printf','__GSHandlerCheck']`):
```
node native-lab/tools/decompile.mjs <exe> main
INVOKE_DECOMPILE_EXIT=0
ok=True  addr=0x140001080  code_len=867  refs=12
```
Every placeholder resolves: `{target}` from the mission target, `{input.function}` to a fact
`native.ida.list_functions` actually emits. Both `fact_map` sources (`code`, `refs`) are present
and non-null; both targets (`native.dec.code`, `native.dec.refs`) are declared in `produces.facts`.
**Routable and correct.**

**FINDING 8 — `native.ida.decompile.invoke.select.index: 0` is the positional-selection defect the
registry itself condemns two entries away.** The recorded `select.note`:
> "Takes the first recovered non-sub_ name. The first candidate is a hypothesis, not a conclusion."

That is a fair caveat, but the registry has already diagnosed this exact mechanism as
"a silent-wrong-answer machine". `native.disasm.capstone` moved off `index` to
`select.by_name="main"` + `element_path="addr"` and explains at length that positional selection
rests "on this binary" and cannot be trusted elsewhere — it calls the earlier `select.index=1` the
cause of "the first `confirmed` this arsenal produced" sitting on "exactly the wrong function, at
full confidence, every gate green". `native.ida.decompile` still uses a bare `index`, with no
`by_name`. On this binary `named[0]` is `main` and the round is correct — I confirmed it. But if a
future binary enumerates its functions in a different order, this round silently decompiles a
different function while every gate stays green. That is the failure mode the registry has
documented and then left in place in the sibling entry. **Severity: real inconsistency between an
entry's lesson and its neighbour's implementation.**

**FINDING 9 — `native.ida.decompile` produces a `native.dec.saved` artifact that is bound to
nothing and is correctly marked `unverified`.** Not a defect: I read the entry's own reasoning and
it is accurate — `decompile.mjs` writes no file (its whole output is stdout JSON), and the `*.c`
export belongs to the Ghidra path. The entry marks it `unbound` with a reason rather than binding
it to something that does not exist, which is the correct handling under `R15`. Recording it here so
it is not mistaken for a defect when read cold.

**`does_not_prove` check — CONSISTENT.** The entry forbids reading the decompilation as faithful,
forbids claims about unestablished provenance, and forbids any dynamic claim. The observed output
is C text and refs. No conflict. The `code_len=867` and `strcmp present` results support exactly the
recorded `proves` claims and none of the forbidden ones.

---

## Summary table

| capability | probe | control | invoke routable | findings |
|---|---|---|---|---|
| native.pe.container | MATCHES-RECORDED (exit 0, `0x140000000 0x15d0 0x8160`) | REFUSED-AS-DECLARED (exit 1, `PEFormatError: 'DOS Header magic not found.'`) | YES | 1 |
| native.pe.packer | MATCHES-RECORDED (exit 0, `"packed":false`) | REFUSED-AS-DECLARED (exit 2, `not a PE: first two bytes are 2320`) | YES | 2, 3*, 4 |
| native.disasm.capstone | MATCHES-RECORDED (exit 0, `0x140017342` + `width: byte`) | REFUSED-AS-DECLARED (exit 2, `which is NOT executable`) | YES — chain run end to end | 3, 5, 6, 7 |
| native.behaviour.capa | MATCHES-RECORDED (exit 0, `"rules_matched": 14`, 31.8 s) | REFUSED-AS-DECLARED (exit 2, `not a PE`, 0.05 s) | YES | — |
| native.pe.authenticode | MATCHES-RECORDED (exit 0, `"signed": false`) | REFUSED-AS-DECLARED (exit 2, `runs past the end of`) | **NO — no invoke block** | — |
| dynamic.win.frida.intercept | MATCHES-RECORDED (exit 0, `verdict=INTERCEPT-PROVEN`, hit count 1) | REFUSED-AS-DECLARED (stage2 exit 3, `attach never attempted: attach_error=None`) | YES | — |
| native.ida.list_functions | MATCHES-RECORDED (exit 0, `list_funcs enumerates functions`) | **WEAK** — prose command, no `measured`, `expect_exit:1` matches nothing executable | YES | 6 |
| native.ida.decompile | MATCHES-RECORDED (exit 0, `LOOP CLOSED`, `{"total":15,"pass":15,"fail":0}`) | REFUSED-AS-DECLARED (exit 1, `code` absent, `error` present) | YES | 8, 9 |

\* FINDING 3 is filed under `native.disasm.capstone`; FINDING 2 under `native.pe.packer`.

**8 of 8 sampled probes reproduce their recorded `expect` and exit code.** Every exit code in this
report was read from `$LASTEXITCODE` immediately after the process, never through a pipe — the
frida entry itself records a previous reading that took `$?` from a pipe tail and reported every
mode as `0`, which is exactly the error that would have hidden its own control.

**7 of 8 controls are REFUSED-AS-DECLARED. 1 is WEAK** (`native.ida.list_functions`).

---

## Findings, consolidated and ordered by severity

### F1 — `fact_map` targets that no capability declares (silent, and the validator cannot see it)

`native.pe.packer.invoke.fact_map`:
```
"die_verdict": "pe.packer_verdict"   <- produced by NO capability
```
`native.disasm.capstone.invoke.fact_map`:
```
"insns":        "native.insn.stream"       <- declared key is `insn.stream`
"rip_operands": "native.insn.rip_operand"  <- declared key is `insn.rip_operand`
```
I enumerated `produces.facts[].key` across all 24 entries; none of those three strings appears in
any of them. `mission.ps1:948-956` reads the map and writes `$facts[$dst]`, so a mission records
these under undeclared keys while the declared keys stay empty. In `native.pe.packer` the damage is
concrete: **`pe.packed` — the boolean the whole precondition decision rests on — is not in the
`fact_map` at all**, so it is never forwarded. `native.disasm.capstone` likewise never binds
`pe.section_exec`.

`python scripts/registry-verify.py` prints `REGISTRY CLEAN` and exits `0` with both defects live.
I read its rule list (`r1`..`r19`); `R11` checks the *consume* side (`consumes.inputs[].from.field`)
only, and no rule constrains `fact_map` values.

**Single next fix:** add a rule to `registry-verify.py` asserting every `invoke.fact_map` value
appears in that same capability's `produces.facts[].key` (or is deliberately exempted), then correct
the three keys and add `packed` to the packer map.

### F2 — a number with the wrong denominator, in the registry that warns about exactly this

`native.ida.list_functions.probe.last_summary` = `"300 functions enumerated from c01-stringobf.exe"`.
The `300` is `loop.mjs`'s query cap (`{count: 300}`); the real population measured through
`list-funcs.mjs` (`{count: 2000}`) is **362** — a figure the registry itself uses in
`native.disasm.capstone.does_not_prove[5]`. Same registry, two numbers, one is the cap.

### F3 — a stale `does_not_prove` that inverts a capability's status

`native.disasm.capstone.does_not_prove[4]` states four capabilities "cannot be planned into a
mission" because the planner "never routed this entry, because it has no `invoke` block". This
entry has a populated `invoke` block and I ran its `argv` successfully. `does_not_prove[5]` and
`invoke.note` both describe the newer, callable state, so the entry contradicts itself.

### F4 — positional selection surviving in the entry that documents its dangers

`native.ida.decompile.invoke.select.index: 0`, while `native.disasm.capstone` moved to
`select.by_name="main"` and explains at length why positional selection produces "the first
`confirmed` this arsenal produced" on "exactly the wrong function, at full confidence, every gate
green". Correct on this binary — `named[0]` is `main` — but unguarded on any other.

### F5 — a control that is prose, with an exit code nothing produces

`native.ida.list_functions.negative_control`: `command` = `"list_funcs with no database bound"`,
`expect_exit: 1`, **no `measured` field** (one of only two such entries; `native.ida.decompile` is
the other). The real refusal exists and is correct — I drove it and got
`isError=true` with `"database is required..."` — but it is an MCP-layer refusal with no process
and therefore no exit code, and the wrapper's own refusals exit `2`, not `1`. `R2` polices
`probe.command` for being prose; nothing polices `negative_control.command`.

### F6 — recorded strings that do not match observed output

- `native.pe.container.negative_control.measured` says "the wrapper prints REFUSED and exits 2".
  `pe_probe.py` never prints `REFUSED` (`contains_REFUSED=False`); it exits `2` with a JSON
  refusal. The `measured` string also describes a different command from the recorded
  `negative_control.command`.
- `native.pe.packer.probe.expect` is `"packed": false` (space); the tool emits `"packed":false`.
  A literal substring match on the recorded `expect` fails.

### F7 — a documented convention applied inconsistently

`native.disasm.capstone` declares no `root_reason` while producing three facts and consuming a
declared edge. `r14_no_island_capability` passes it legitimately (it is chained, not an island), so
this is not a validator failure — but the three sampled entries that do carry `root_reason` each
explain their absence of a typed edge, and this one neither explains nor omits.

### F8 — `invoke.argv[0]` is relative while `invoke.runner` is absolute

`dynamic.win.frida.intercept.invoke.argv[0]` = `native-lab/tools/frida_spawn_gate.py`. It resolves
only because `mission.ps1:93-94` does `Set-Location $RepoRoot`. True today and I verified both
lines, but the dependency is undocumented; from any other cwd the round fails with file-not-found
rather than a refusal.

---

## What I did NOT sample

The remaining **12 `observed`** capabilities were not sampled, and each still rests entirely on its
recorded evidence:

`web.js.cdp`, `crypto.jose.parse`, `net.pcap.analyse`, `forensics.memory.artefact`,
`managed.il.decompile`, `mobile.apk.static`, `re.corpus.solve`, `dynamic.win.frida`,
`fuzz.differential.parse`, `native.ghidra.decompile`, `ops.skill.security`,
`native.function.match`.

Of these, **`native.ghidra.decompile` is the one I would sample next**, for two reasons. It declares
`invoke.argv` with `{input.outdir}`, and `mission.ps1:2178` records a known problem with that
placeholder — "`native.ghidra.decompile` binds `{input.outdir}` and no capability publishes a ..." —
so its routability is questionable in the same way F1 is. And it is the second decompiler, meaning
it is the entry that most affects the independence gate, which `native.disasm.capstone` itself
records as still returning `tier=unresolved`.

Also worth sampling on a future pass, for the recorded evidence quality rather than the behaviour:
the 12 entries carrying `evidence_binding: unverified` with no `run_log` and no `sha256` (I counted
this across the registry; the 8 sampled here all carry a `run_log`). The sample I took is the
better-evidenced half of the registry, and that should not be mistaken for the whole.

---

## What I could NOT check

1. **IDA database isolation.** `loop.mjs` writes `.id0/.id1/.id2/.nam/.til` beside its target. I
   ran it against a staged copy in `%TEMP%`, so the repository's IDA databases were never touched —
   but that means the in-repo run remains unverified, and the in-repo `.id0` file dated Oct 2 09:20
   predates my work and was not produced by me.
2. **The packed branch of `native.pe.packer`.** The entry states it has never run and I found no
   packed binary or UPX on this host. That branch remains unmeasured — correctly declared as such by
   the entry itself, which is to its credit.
3. **`smoke-all.ps1`, lab loops, fuzz runs** — parent-owned and expensive; explicitly excluded by my
   Non-Conflict. The oracle verdicts, gate grants and independence-gate outcomes that a full mission
   would produce are therefore unverified by me.
4. **Raw-instrument comparisons under a different cwd.** `diec.exe` and `capa.exe` are only present
   at the relative paths `requires.tools[].probe` records; my first attempt with absolute paths
   failed with `CommandNotFoundException`, which is a cwd fact, not a missing tool.
5. **`git` state of either repository** — no git command was run, per Non-Conflict.

---

## Verdict

**ACCEPTED WITH REQUIRED CHANGES.**

Every one of the 8 sampled `observed` promotions is **behaviourally honest**: its probe reproduces
the recorded output and exit code from scratch on this host, 7 of 8 controls refuse for the guarded
reason, and every `invoke.argv` I tested routes end to end (I ran the
`list-funcs.mjs` → `disasm.py` and `list-funcs.mjs` → `decompile.mjs` chains for real, not on paper).
I found **no case** where an entry's `does_not_prove` is contradicted by the output it produces. The
registry's honesty discipline is real and, in `native.pe.authenticode` and `native.pe.packer`, better
than most self-describing systems I have audited.

But **`observed` currently means "the recorded probe text matches reality", not "this capability's
data is wired correctly"**, and F1 is the proof: two entries are `observed`, their probes pass, and
both silently write facts under keys nothing declares — in the packer's case dropping the very
boolean its precondition depends on. `registry-verify.py` reports `REGISTRY CLEAN` on that state.

**The single next fix:** teach `registry-verify.py` that an `invoke.fact_map` value must appear in
that capability's own `produces.facts[].key`, then correct `pe.packer_verdict` → `pe.packed` (and
add `packed` to the packer map), `native.insn.stream` → `insn.stream`, and
`native.insn.rip_operand` → `insn.rip_operand`. That is one rule and three strings, and it converts
the registry's loudest blind spot into a red run.

STATUS: DONE
