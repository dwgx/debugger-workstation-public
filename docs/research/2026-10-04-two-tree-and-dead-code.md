# 2026-10-04 — the wiki tree had no gate, and 342 lines that never ran

Two findings from one session, both measured, both re-runnable from the commands printed here.
The first closes a gap the board had open since 2026-10-04 19:5x. The second is a false green
in this repository's own gate suite.

---

## 1. What the three waves actually were

Measured from history rather than from a handoff, because a handoff is a summary and the
question was "what did the previous sessions build".

```
cd <repo> && git log --date=short --format="%ad" | sort | uniq -c
      1 2026-09-01        5 2026-09-02        1 2026-09-08
     40 2026-09-30       55 2026-10-02       62 2026-10-03
```

Grouped by what each wave added (`git log --diff-filter=A` over `scripts/`):

| wave | date | added | what it was for |
|---|---|---|---|
| **build** | 09-30 | `registry-verify.py`, `gate.ps1`, `mission.ps1`, `manifests/capabilities.json`, 9 lab runners, `smoke-all/-mcp/-tools` | make the arsenal exist |
| **verify** | 10-02 | `assert-probes.py`, `doc-facts.py`, `check-requires-tools.py`, `reachability-report.py`, `verify-all.ps1`, `arsenal_mcp_server.py` | make the arsenal's claims checkable |
| **verify the verifiers** | 10-03 | `verify-tools-manifest.py`, `verify-atomic-artifacts.py`, `verify-clone-freshness.py`, `verify-probe-coverage.py`, `scan-unread-keys.py`, `sync-wiki-figures.py`, `mcp-probe.py` | make the checks themselves trustworthy |

The arc is coherent and worth keeping: each wave's stated lesson became the next wave's subject.
Two things this session found sit outside it, and they are the same shape of defect — a
surface that exists and is not exercised.

---

## 2. Finding A — the wiki tree contained no gate at all

### The gap

Both trees are coupled mechanically, but the coupling ran **one way**.

```
cd <project>/<private-tree> && find . -path ./.git -prune -o \( -name "*.py" -o -name "*.ps1" \) -print | wc -l
0
```

Every rule about wiki prose was enforced by a script living in the **station** tree
(`doc-facts.py` reads numbers out of `manifests/capabilities.json` and compares them to the
prose). So: change the station, the wiki can go red. Change the wiki, **nothing can**.
That is the literal reading of the board's standing note that Owner said 「需要一起进行」 had
only half delivered.

### What it found on its first run

`scripts/arsenal-two-tree-check.py`, first execution against the live tree:

```
arsenal-two-tree-check: 165 wiki pages, 156 reachable from INDEX.md
  UNREACHABLE  literature/CARD-TEMPLATE.md
  UNREACHABLE  literature/survey-2026-10-02/01-star-mined-survey.md
  ... (6 survey pages)
  UNREACHABLE  methods/arsenal-clone.md
  DANGLING     methods/repo-discovery-method.md -> survey-2026-10-02/
arsenal-two-tree-check: 8 unreachable, 1 dangling.
```

Two of these are worth naming separately because they are not hypothetical:

**`methods/arsenal-clone.md` was added by `bd841bd` — the wiki tree's own most recent commit —
and is linked from nowhere.** `grep -c arsenal-clone wiki/INDEX.md` returns **0**.
`wiki/INDEX.md` line 3 states the rule in its own words: *"Register a row here when you add
anything under `wiki/`."* The last commit on this tree broke that rule and the suite stayed
green.

**`methods/repo-discovery-method.md` line 7** read `](survey-2026-10-02/)`, which resolves
against *that file's* directory to `wiki/methods/survey-2026-10-02/` — a directory that has
never existed. The six survey pages are at `wiki/literature/survey-2026-10-02/`. The missing
`../literature/` made all six unreachable from the page that cites them as its evidence.

### The measurement that shaped the implementation

The first thing written was the naive version — every `.md` under `wiki/` must appear in a
link in `wiki/INDEX.md`. It reported **91 orphans**. The true number is 9.

```
naive direct-link check   -> 91 files "unreferenced"
transitive closure        ->  9 files unreferenced
```

91 is wrong. `policy/targets/*.md` is registered by `policy/00-index.md`, the literature
cards by `literature/README.md`, the notes by `notes/INDEX.md` — none appear in
`wiki/INDEX.md` directly and all are properly filed. **82 false positives would have taught
the next reader to ignore the output**, which is the exact failure `doc-facts.py` records
about its own second version ("a gate that cries wolf gets switched off"). So reachability is
computed by following links from the index, the way a reader actually navigates.

Two more implementation details that exist because of a measured failure rather than taste:

- **Targets resolve against the linking file, never the wiki root.** The same relative string
  means different things from different pages; root-relative resolution is what makes a
  checker report a page's own siblings as missing.
- **A directory target counts as resolved when the directory exists.** The live defect above
  *is* a directory link, so a checker that only stats files would report a real page missing.
- **Fenced blocks and inline code are stripped before links are harvested.** A wiki page
  routinely shows the markdown syntax itself inside a fenced example; the first version
  reported 2 phantom violations on `methods/START.md`, both backticked syntax examples. A
  gate that reports the documentation of a feature as a violation of that feature gets closed,
  correctly.

### The rules, and why there are two

```
R1  every .md under wiki/ is reachable from wiki/INDEX.md by following links
R2  every relative link in every wiki .md resolves to a real file or directory
```

Neither is redundant: R1 alone passes on a wiki whose only orphan is the one you just added;
R2 alone passes on a wiki that links nothing at all. A gate that sees one half of a two-sided
contract has a greenness that is a property of which half you checked.

Scope boundary, stated in the file itself: `doc-facts.py` keeps owning **number** drift and
this file must not restate it. If a future wiki number needs checking it becomes a `claim()`
in doc-facts.py.

### Controls

```
python scripts/arsenal-two-tree-check.py --selftest
SELFTEST OK: 5 controls each fire -- C1 an unregistered page trips R1; C2 a link to nothing
trips R2 and names its source page; C3/C4 two correctly filed pages stay green, one of them
reachable only through a sub-hub; C2b a link to an existing directory stays green.
```

C4 is the control the naive implementation would fail, and it is the one that matters: it
pins the sub-hub traversal that turns 91 into 9.

State after the wiki-side repairs:

```
python scripts/arsenal-two-tree-check.py --count
reachable: 164  unreachable: 0  dangling: 0  total: 165
```

---

## 3. Finding B — 342 lines that never ran, behind a green suite

### The parser error

The uncommitted work in `scripts/mission.ps1` (+342 lines, pure insertion) contained:

```powershell
foreach ($part in ($span -split '\s+AND\s+' -CaseSensitive)) {
```

`-split` has **no** `-CaseSensitive` switch, in Windows PowerShell 5.1 or pwsh 7.6.6. This is
a `ParserError` at load time, not a runtime failure:

```
At D:\...\scripts\mission.ps1:1348 char:49
+     foreach ($part in ($span -split '\s+AND\s+' -CaseSensitive) {
+                                                 ~~~~~~~~~~~~~~
Unexpected token '-CaseSensitive' in expression or statement.
```

Both `mission selftest` and `mission ablate` were exiting 1 because the file would not load.
The author's own comment at `mission.ps1:1174` had already stated the correct fix —
*"`[regex]::Split` defaults to case-sensitive, which is what a conjunction marker needs"* — and
the same file then used the invalid form 174 lines later. Fixed to `[regex]::Split`, which is
case-sensitive by default and matches the documented intent.

After the fix: `MISSION SELFTEST OK: 71 controls behaved.` (exit 0, ~20 s) and
`ABLATE: 7 load-bearing, 0 unproved` / `ROUTING ABLATE: 7 load-bearing, 0 unproved` (exit 0,
~237 s).

### The dead code

The parse fix is the small half. The substantive finding is that **the 342 lines never
execute**:

```
cd <repo>
grep -rn "Get-SuccessWhenVerdict" scripts/
scripts/mission.ps1:1332:function Get-SuccessWhenVerdict {
```

One hit — the definition. **Zero call sites in the tree.** The value that decides whether a
round is recorded as a success is still set by the two old literals:

```
scripts/mission.ps1:1894:  if ($cap.invoke.success_when -match 'ok == true'      -and $parsed.ok -ne $true) { $declaredOk = $false }
scripts/mission.ps1:1895:  if ($cap.invoke.success_when -match 'code is non-null' -and $null -eq $parsed.code) { $declaredOk = $false }
```

And the diff added **no selftest controls at all**:

```
git diff -U0 scripts/mission.ps1 | grep -c "^+.*C '"     ->  0
```

Control count before the change and after it: **71 and 71**.

So `MISSION SELFTEST OK: 71 controls behaved` is a **false green**: the suite passes, and it
passes identically with the 342 lines deleted. This is the failure mode this repository
exists to eliminate — a surface that exists, is never called, and is never tested — occurring
inside the gate suite that was built to detect it.

### Why it was left unwired, deliberately

Wiring it is not a mechanical fix. `$declaredOk` feeds three places at once (the evidence
record, the precondition gate, and fact forwarding), and the change would replace a
two-literal check with a 12-pattern clause parser whose behaviour has never been observed
outside a unit fixture. Connecting unverified logic to the path that decides what counts as
evidence is a worse outcome than leaving a documented, measured, reproducible dead function.

The next window should treat it as: write the controls first, watch them fail against the
current literal path, then wire it.

---

## 4. A drift this session measured and did not fix

The wiki asserts `mission.ps1` **51** controls in four places — `wiki/INDEX.md:5`,
`wiki/INDEX.md:92`, `wiki/CHARTER-ARSENAL.md:164`, `wiki/CHARTER-ARSENAL.md:254`. Measured
today: **71**. That is a 40% drift, live, in the most-read documents in the tree.

`doc-facts.py` reports `OK, every live numeric claim matches the registry`, because it has
**no claim for selftest control counts at all** — its `runnable negative controls` and
`declared plan controls` claims are both derived from the registry, not from running a
selftest.

The fix follows the existing pattern: a `claim()` that reads the number by *running* the
selftest, the way `_validator_number` reads the validator's counts, because a pinned constant
never moves and so the check stays green forever. The cost is that `doc-facts.py` would grow
by the selftest's runtime (~20 s) on a path that runs inside `verify-all.ps1`.

**Not done unilaterally.** Adding 20 s to the hot path of every gate run is a real tradeoff,
and the alternative — recording the figure in a machine-written artifact that `verify-all`
already produces — is a different design. That choice belongs to the owner.

The same class of drift exists for the gate: the wiki says `gate.ps1` has **24** controls in
one revision line and **33** in another (`wiki/INDEX.md:5`, `:19`, `:117`), and
`powershell -File scripts/gate.ps1 -Action Selftest` printed **`GATE SELFTEST OK: 56
refusals and grants all behaved.`** today. So both selftest-derived figures are unchecked, and
both are wrong, in the same way, for the same reason.

Full measured selftest counts as of this session, all three from one command:

```
registry-verify.py --selftest   -> 104 cases each fire
gate.ps1 -Action Selftest       -> 56 refusals and grants all behaved
mission.ps1 -Action Selftest    -> 71 controls behaved
```
---

## 4b. Measured state of both trees, 2026-10-04

Every row is a number this session produced, with the command that produces it. No row is
quoted from a handoff, because the handoff is where the drift in §4 came from.

| Fact | Command | Result |
|---|---|---|
| Registry | `python scripts/registry-verify.py` | **27** capabilities · 23 `observed` · **7** typed edges · 21 bound to a retained artifact · 23 runnable negative controls · 4 declared plans |
| Validator selftest | `python scripts/registry-verify.py --selftest` | **104** cases, **34** numbered rules (35 in `RULES`) |
| Wiki number drift | `python scripts/doc-facts.py` | 119 files scanned, **34** live numeric claims, all matching — but see §4 for the class it does not cover |
| Tools manifest | `python scripts/verify-tools-manifest.py` | **62** declared · **12** invoked · **0** undeclared · **2** dead (18 url + 15 escaped-spelling + 1 no-launch candidates excluded) |
| Probe shape | `python scripts/assert-probes.py --list` | **20** runnable of **27**; **7** SKIP, named individually (2 need IDA, 1 needs adb, 3 are documentation-only reproductions, 1 needs a live device) |
| Mission selftest | `powershell -File scripts/mission.ps1 -Action Selftest` | **71** controls, exit 0, ~20 s |
| Mission ablation | `powershell -File scripts/mission.ps1 -Action Ablate` | **7** verdict gates + **7** routing rules load-bearing, **0** unproved, exit 0, ~237 s |
| Wiki tree structure (new) | `python scripts/arsenal-two-tree-check.py` | 165 pages · 164 reachable · **0** unreachable · **0** dangling, ~1 s |
| Cold-start tool latency | `Stopwatch` around `--version` | 7-Zip **13 ms** · YARA-X **24 ms** · FLOSS **588 ms** · capa **882 ms** |

**The latency row has a caveat that cost this session a wrong number.** The first timing pass
ran `./Static-Reversing/die/diec.exe --version`, reported `MISSING`, and would have been
written up as a missing tool. The path in the board's open item ④ is the wrong one: the real
location is `Static-Reversing/die_win64_portable_3.21_x64/die/diec.exe`, and
`Static-Reversing/die/` does not exist at all. The same pass then **hung for 300 s** on
`ReClass.NET.exe`, which is a GUI binary that blocks when launched headless.

⇒ Hand-rolled per-tool timing is the wrong instrument here. `docs/research/cost-matrix.md`
already measures cost per probe, and `verify-tools-manifest.py` already proves which binaries
the code actually launches by absolute path. Use those; a timer written fresh in a shell is
how the `die/` path got invented.

---
---

## 5. Commands

Every figure in this file, re-runnable from the station root:

```
python scripts/arsenal-two-tree-check.py --selftest      # 5 controls
python scripts/arsenal-two-tree-check.py --count         # reachable / unreachable / dangling
grep -rn "Get-SuccessWhenVerdict" scripts/               # 1 hit == dead, >1 == wired
git diff -U0 scripts/mission.ps1 | grep -c "^+.*C '"     # 0 == no control covers the new code
powershell -File scripts/mission.ps1 -Action Selftest    # control count, exit code
powershell -File scripts/mission.ps1 -Action Ablate      # load-bearing gates and routing rules
powershell -File scripts/verify-all.ps1                  # the one command, both trees
```

`verify-all.ps1` now runs the two wiki-tree steps and reports its own wall clock, so the
number this document cites is produced by the same command that judges it.