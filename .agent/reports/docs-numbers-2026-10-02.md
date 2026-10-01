# Station docs — number/id correction pass (2026-10-02)

Scope: `.agent/HANDOFF.md`, `.agent/RECOVERY-STATION.md`,
`docs/research/{orchestration-design,ghidra-capability-spec,mobile-js-skill-map,binary-mcp-map}.md`,
`notes/2026-09-30-mobile-lab.md`. Prose/number corrections only. Not committed.

## Commands actually run (verbatim tail)

```
> $ cd D:\Software\Tool\WorkStation\debugger\docs\research
> $ $files = Get-ChildItem -Filter *.md | Where-Object { $_.Name -ne "README.md" }
> $ total = 0; foreach ($f in $files) { $n = (Get-Content $f.FullName).Count; $total += $n }
> REPORTS=8 LINES=5634
```

```
> $ Get-Volume | Where-Object { $_.DriveLetter -in @("C","D","E","F") } | ForEach-Object { ... }
F: total 1863.01 GiB, free 1457.13 GiB
C: total 250 GiB, free 42.36 GiB
D: total 640.12 GiB, free 172.12 GiB
E: total 33.67 GiB, free 28.01 GiB
E free = 28682.2 MiB; /800 MiB = 35; /300 MiB = 95
```

```
> $ (Get-Content manifests\capabilities.json -Raw | ConvertFrom-Json).capabilities |
>   ForEach-Object { "{0,-34} {1}" -f $_.id, $_.state }
native.ida.decompile               observed
native.ida.list_functions          observed
web.js.cdp                         observed
crypto.jose.parse                  observed
net.pcap.analyse                   observed
forensics.memory.artefact          observed
managed.il.decompile               observed
mobile.apk.static                  observed
re.corpus.solve                    observed
dynamic.device.frida               absent
fuzz.differential.parse            observed
native.ghidra.decompile            observed
native.crosscompare.ghidra         observed
native.il2cpp.symbols              absent
native.ghidra.emulate              blocked
```

```
> $ Select-String -Path scripts\registry-verify.py -Pattern "RULES = "
RULES = (r1_not_empty, r_shape, r2_observed_needs_probe, r3_honesty_pair,
         r4_fact_types_agree, r5_control_must_fail, r6_reach_needs_escalation, r7_ids,
         r8_reach_must_be_declared, r9_batch_must_account, r10_invoke_must_runnable)
```
(11 rule functions; the `RULES` block is at `scripts/registry-verify.py:292-294`.)

## Acceptance

**1.** `Get-ChildItem -Recurse -Include *.md -Path .agent\HANDOFF.md,.agent\RECOVERY-STATION.md,docs\research,notes | Select-String -Pattern "13/13|8/8|14\.5 GB|14\.52 GB|15\.19 GB|20\.17 GB|station 41|\(11 entries\)|14 rules|six gates"`

```
.agent\HANDOFF.md:199: 7. Verdict gate list came back **empty**, so six gates passed vacuously.
docs\research\agent-craft-principles.md:251: ... `fp-check`'s six gates; `insecure-defaults`' `refuted: true`).
docs\research\orchestration-design.md:384: ... these are the station's own `fp-check` six gates (`plugins/fp-check/...`)
notes\2026-09-30-fuzz-lab.md:41:   13/13 sampled (43 found, 30 same-class)
notes\2026-09-30-fuzz-lab.md:202: `forensics-lab/tools/loop.mjs` LOOP CLOSED, `web-reverse/static/selftest.mjs` 8/8
TOTAL HITS: 5
```

Every surviving hit read in context; all five are correct as written:

- `HANDOFF.md:199` — the brief's named incident record ("Verdict gate list came back empty, so six gates passed vacuously"). Untouched, as instructed.
- `orchestration-design.md:384` / `agent-craft-principles.md:251` — both describe **`fp-check`'s** six gates, i.e. the upstream `trailofbits/skills` skill's own six-gate table, not a count of this station's verdict gates. Corroborated by `agent-craft-principles.md:172` ("`fp-check`'s six-gate table (`references/gate-reviews.md:5-17`) … TRUE POSITIVE iff all six pass"). Same class as the "web-reverse's own six-gate lab" exemption in the brief.
- `notes/2026-09-30-fuzz-lab.md:41` — `13/13 sampled` is fuzz-lab's own sampling count out of 43 triaged findings. Not the mission selftest. File is outside my write scope.
- `notes/2026-09-30-fuzz-lab.md:202` — `8/8` is **`web-reverse/static/selftest.mjs`**, not `gate.ps1`. File is outside my write scope.

**2.** `Get-ChildItem -Recurse -Include *.md -Path docs\research | Select-String -Pattern "native\.pcode\.emulate\.ghidra"`
→ no output. Pass.

**3.** `(Select-String -Path docs\research\mobile-js-skill-map.md -Pattern "31 checks").Count`
→ `3`. Pass.

## What changed, file by file

### `.agent/HANDOFF.md`
- L80 mission selftest `13/13` → `15/15`.
- L129-130 `# 18 rules` → `# 18 selftest cases across 11 rules`.
- L218-219 `18 rules` → `11 rules, exercised by 18 selftest cases`.
- L227 `18 validator rules` → `11 validator rules, 18 selftest cases`.
- L228 gate selftest `8/8` → `10 refusals and grants`.
- L229 mission selftest `13/13` → `15/15`.
- L234 `8 reports, 5,621 lines` → **`8 reports, 5,634 lines`**, with the command that produced it, cited inline.
- L235 `~14.5 GB free` → `28.01 GiB free of 33.67 GiB (measured 2026-10-02, Get-Volume -DriveLetter E)`.
- L237 `station 41` → `station 47`.
- L199 untouched.

### `.agent/RECOVERY-STATION.md`
- L52 `Each is the registry's probe.command` → dropped the blanket claim; the two rows that are **not** registry probes (`loop2.mjs` web AST deobf, `trustcheck.mjs` isolation) are marked `*(not a registry probe)*`. Verified against the real `probe.command` of all 15 shipped capabilities.
- L56 `18/18 rules fire` → `18 selftest cases across 11 rules, all fire`.
- L67 mobile `25 checks` → `31 checks`.
- L165 `(11 entries)` → `(15 entries)`.
- L168 + L170-178 `14 rules` + stale hand-copied rule block → `11 rules, exercised by 18 selftest cases`, block regenerated from the actual `RULES` tuple (`scripts/registry-verify.py:292-294`), all 11 rules named, `r_shape` and `r10_invoke_must_runnable` added (both were missing).
- L203 `E:` ≈ 14.5 GB free → `28.01 GiB free of 33.67 GiB (measured 2026-10-02)`.
- L272/273 commit counts `16` / `26` → `18` / `47`.
- L325-328 §13 table: `13/13`→`15/15`, `8/8`→`10 refusals and grants`, `13 capabilities`→`15 capabilities` (L57 said 15; this cell contradicted it), `18 rules`→`11 rules, 18 selftest cases`.

### `docs/research/orchestration-design.md`
- Disk cell: `E:` 14.52 GB free (and the retired `arsenal-inventory.md` 15.19 GB) → measured 2026-10-02 volumes for C/D/E/F.
- **Derived conclusion recomputed, not kept.** "roughly 15 full Ghidra rounds fit" was derived from the retired input. Recomputed from 28.01 GiB and the cell's own ~300–800 MB per-project figure: `28.01 GiB ÷ 800 MiB = 35`, `÷ 300 MiB = 95` → **35–95 full Ghidra rounds**, with the arithmetic shown in the cell and a "re-derive per run" instruction. The cell's "Tier-B containers are out of the question at 14.5 GB" claim does not follow from free space alone and is now flagged as needing its own measurement of the named image.
- L271 `fuzz.any → absent. D11 is the one genuine gap` → kept as dated history, marked **Closed**, with the shipped `fuzz.differential.parse` / `observed` / probe and the `--budget 40` floor.
- L475-476 §6.4 three-entry proposal and "six failure rules" → marked **Superseded** with the shipped 15 (12 observed / 2 absent / 1 blocked) and 11 rules / 18 cases. Design not deleted.

### `docs/research/ghidra-capability-spec.md`
- §1.5, §3.8 heading, §3.8 `"id"`, §4 coverage table, §5 id list, §7 summary — all five `native.pcode.emulate.ghidra` occurrences re-keyed to `native.ghidra.emulate`.
- `absent` → `blocked` throughout, with the correct diagnosis stated: API reachable and ran 15 p-code steps, returned to PC=0, 48-byte output buffer all zero, `FLAG{c01_string_table_xor}` NOT recovered; controlled-input setup is what fails.
- §3.8 and §5 blocks marked **PROPOSAL, superseded by `manifests/capabilities.json`**; the proposal JSON's own `"state": "absent"` is retained with an inline `jsonc` comment naming the shipped value, so the research record is not rewritten.
- §5 note states which of the nine proposed ids are not in the shipped registry.

### `docs/research/mobile-js-skill-map.md`
- L12 / L392 / L766 `25 checks` → `31 checks` (3 occurrences, matching acceptance 3).
- L14 / L612 / L779 `E:` 15 GB free → measured 2026-10-02 figure.

### `docs/research/binary-mcp-map.md`
- L374 / L385-386 `E:` 15 GB free → measured figure; `D:` 288 GB → 172.12 GiB of 640.12 GiB (also measured, same command, also retired).

### `notes/2026-09-30-mobile-lab.md`
- L46 `24/24 PASS` → `31 checks, all PASS, exit 0 (as of 2026-10-02; 24 when first built)`. Date and voice kept.

## Rows I was told to fix that were already correct — left alone

- `HANDOFF.md` L124 / L128 (15 capabilities; 12 observed, 2 absent, 1 blocked) — correct.
- `HANDOFF.md` L229 `**7** verdict gates` — correct, kept as-is in the rewritten row.
- `RECOVERY-STATION.md` L57 (`15 capabilities, CLEAN`) — correct; it was L320 that contradicted it, and L320 is now fixed.

## Deviations from the brief, flagged

1. **I edited four lines the brief listed as "already correct"** — `HANDOFF.md` L129, L218, L227 and `RECOVERY-STATION.md` L321. Each literally says "18 rules" / "18 validator rules", which is the category error the Ground Truth section names ("write '18 selftest cases across 11 rules' wherever a doc says '18 rules'"). Leaving them would also have made `HANDOFF.md:227` contradict the `RECOVERY-STATION.md` §6 block I was told to rewrite. The number 18 is unchanged everywhere; only the noun is corrected. Easy to revert if the brief meant those lines verbatim.
2. **I fixed three lines the brief did not list**, all the same retired `E:`/`D:` numbers inside my own files: `mobile-js-skill-map.md` L779, `binary-mcp-map.md` L374/L375. Leaving them would have contradicted the sibling rows I was told to fix.
3. **I annotated rather than rewrote two proposal bodies** in `ghidra-capability-spec.md` — the §3.8 JSON keeps its 2026-09-30 `"state": "absent"` with an inline comment, and the OSGi reachability measurement in §1.5 is kept. The shipped diagnosis is stated above each block. Rewriting the proposal would have destroyed the research record the brief said to keep.

## Numbers I did NOT write because I have no command for them

- None introduced. Every number I wrote traces to a command in this report or to the parent-supplied ground truth. The one number the brief flagged as unfounded (5,621) now has a command and a real value.
- `orchestration-design.md` L381 / §5.2 enumerates **six** verdict gates and omits `discharged`, while the shipped `mission.ps1` has seven. The brief did not list this line and the `six gates` in it is a correct attribution to `fp-check`, so I left it — but it is a real gap and the next window should reconcile the §5.2 list with the shipped seven. **Left unchanged, reported here.**