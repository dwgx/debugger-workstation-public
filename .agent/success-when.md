STATUS: BLOCKED

# success_when evaluation in `scripts/mission.ps1`

Paused by Owner mid-investigation. **No code change was made.** `scripts/mission.ps1` is
byte-identical to `e4da839` (confirmed: `git status --short` listed no `scripts/mission.ps1`
entry before and after this agent's work). Nothing was staged, nothing to revert. The tree is
clean with respect to my assignment.

No patch was produced, because no edit was produced. Nothing is lost.

---

## 1. Re-derived count — the brief's 4 is wrong, the true figure is 5

Walked every `success_when` key in `manifests/capabilities.json` mechanically
(`python`, walking both `invoke` and `envelope` on all 27 capabilities):

```
total 20   invoke 16   envelope 4
```

20 total and the 16/4 split in the brief are **correct**.

Where the brief is wrong: it counts *text-unmatched* declarations (4) and calls them the
*unevaluated* ones. Those are different sets, and the difference is exactly the shape defect
the brief itself names.

- `TEXT-UNMATCHED` — the declaration's text matches neither `'ok == true'` nor
  `'code is non-null'`: **4**. These are the four the brief lists:
  `native.ida.list_functions/envelope`, `mobile.apk.static/invoke`,
  `native.ghidra.decompile/envelope`, `native.ghidra.emulate/envelope`.
- `UNEVALUATED` — nothing in the file reads it: **5**. The fifth is
  `native.ida.decompile/envelope` = `'body.code is non-null AND body.error is absent'`.
  Its **text** matches the `'code is non-null'` regex, but the regex reads
  `$cap.invoke.success_when`, so the envelope copy of that declaration is never the string
  tested. The brief's own "doubly invisible — wrong key AND unmatched text" is real, and it
  applies to this entry for the *wrong-key* half alone.

**5 of 20 declarations are evaluated by nothing. The brief says 4. My number wins.**

### The two lines, verbatim (`scripts/mission.ps1:1552-1553`)

```powershell
if ($cap.invoke.success_when -match 'ok == true'      -and $parsed.ok    -ne $true) { $declaredOk = $false }
if ($cap.invoke.success_when -match 'code is non-null' -and $null -eq $parsed.code)  { $declaredOk = $false }
```

Both read the `invoke` key. Both run only inside `if ($cap.invoke.stdout -eq 'json')`
(:1534). No occurrence of the string `envelope` exists anywhere in `scripts/mission.ps1`
(verified by grep over the whole file) — the envelope section is not read by this file at all,
which is a stronger statement than "wrong key": the envelope half of the schema has no
reader in the mission layer.

---

## 2. Baseline measured

```
powershell -NoProfile -ExecutionPolicy Bypass -File 'scripts/mission.ps1' -Action Selftest
EXIT=0
...
MISSION SELFTEST OK: 71 controls behaved. N4 -- our own known failure mode, aimed here -- returned unresolved as it must.
```

**BEFORE count = 71 controls**, exit 0. The brief predicted 71 + 8 = 79.

---

## 3. Design settled before the pause (implementation not started)

### 3a. Predicate vocabulary (parse the declaration text into clauses)

Ten predicates, each demanded by at least one of the 20 real declarations. Every one of the
20 must parse to zero unrecognised clauses or the round fails closed.

| predicate | clause shape in the registry | declaration that needs it |
|---|---|---|
| `field_equals(f, v)` | `f == v` / `f is v` | `ok == true`, `verdict is INTERCEPT-PROVEN`, `verdict == MATCHES_GROUND_TRUTH` |
| `field_present(f)` | `f is non-null`, `f present`, `f is present` | `code is non-null`, `aslr is present`, `manifest present`, `pinning present`, `claims present`, `image_base is non-null`, `the rip_operands array is present` |
| `field_present(f)` + negate → `not field_present(f)` | `f is absent` | `body.error is absent`, `error is absent` |
| `field_length_equals(f, g)` | `f.length == g.length` | `result.length == queries.length` |
| `field_gt(f, n)` | `f > n` | `count > 0`, `runtime_hook_hit.count > 0` |
| `field_nonempty(f)` | `f non-empty` | `stdout non-empty` |
| `file_exists(name)` | `<file>.json EXISTS` / `exists` | `summary.json EXISTS`, `emulation.json exists` |
| `field_is_integer(f)` | `f is an integer` | `rules_matched is an integer` |
| `every_item_present(f)` | `every <x> has a result object` | `every requested query has a result object` |
| `object_carries(f, a, b)` | `a <f> <noun> carrying <x> and <y>` | `an image block carrying arch and bintype` |

Normalisation before clause matching, each rule forced by a real string:
- the **evaluable span** ends at the first `;`, ` -- `, `, ` or `. ` — every one of the 20
  uses those marks to separate the requirement from registry commentary, and none uses a
  comma or period inside a requirement;
- backticks stripped (`` its `ok` is true `` → `its ok is true`);
- leading boilerplate stripped per clause: `parsed JSON has `, `parsed JSON with `,
  `parsed JSON `, `its `, `an `, `the `, `every `.

### 3b. Fail-closed, not silently-passing

A clause no pattern matches is **collected and named**, appears in the artifact under
`success_when_unrecognised`, sets `$declaredOk = $false` for that round, and trips a new
`Get-Verdict` gate. This is the whole point: the defect is a declaration that matches nothing
and the round passes anyway.

**Partial recognition is also failure.** A sentence that is half understood is NOT a pass.
Each declaration records every clause it evaluated and every clause it could not parse; the
unparsed ones are named in `success_when_unrecognised`, set `$declaredOk = $false` and trip
the new `Get-Verdict` gate — whether the sentence matched zero clauses or all but one.
This is the second-order half of the defect, see §3f.

### 3c. Key-aware

`Get-SuccessWhenVerdict -Capability $cap -Section invoke|envelope -Subject <obj>` evaluates
each declaration against its OWN section's object:
- `invoke.success_when` → `$parsed`;
- `envelope.success_when` → the envelope object.

Every clause is recorded with its originating key (`invoke` / `envelope`) and the source
string, so a reader of the artifact can see which key each declaration came from and that
nothing was skipped.

### 3d. Where the envelope object comes from — RESOLVED by measurement

The two greps that were in flight at the pause came back. They change the answer: the
envelope subject is **not** `$parsed` for every envelope declaration.

Measured from the runner sources, not inferred:

- `native-lab/tools/list-funcs.mjs` prints `{ ok, count, functions, binary }`. The `queries`
  and `result` arrays exist only INSIDE `call('list_funcs', { queries: [...] })` (:34) and
  are flattened away before the wrapper prints. So `native.ida.list_functions/envelope`
  (`result.length == queries.length`) describes the MCP TRANSPORT envelope, and mission.ps1
  never sees a transport envelope — it shells out and reads stdout. **Not evaluable against
  anything mission.ps1 holds.** This is a registry-scope finding to REPORT, not to fix.
- `mobile-lab/tools/analyze.mjs` sets `report.manifest` (:393) and `report.pinning` (:581) as
  top-level fields, so `mobile.apk.static/invoke` (`manifest present AND pinning present`)
  **is** evaluable against `$parsed`. Field names match the declaration text.
- `scripts/ghidra-headless.ps1` writes `$summary = Join-Path $OutDir 'summary.json'` (:102)
  and on failure prints `reason = 'no summary.json'` and `exit 1` (:140-146). So
  `file_exists(summary.json)` **is** checkable, against the `{scratch:ghidra-out}` directory
  the loop already creates. The registry's own comment at :144 calls this exact point
  "deliberately gated on the artifact, not the exit code".
- `native.ghidra.emulate/envelope` (`emulation.json exists AND verdict == ...`) —
  **[UNVERIFIED]**. I did not read `scripts/emulation-probe.ps1` before the pause, so
  whether `verdict` is a top-level field of the parsed JSON is unknown.

So of the four invisible declarations: **2 are evaluable against what the loop holds**
(`native.ghidra.decompile` via `file_exists`, `mobile.apk.static` via `field_present`), and
**1 provably is not** (`native.ida.list_functions`, because the transport envelope is
flattened before the loop can see it). That asymmetry is the honest headline, and it is why
the fail-closed rule matters: an evaluator that could not evaluate that one must say so by
name rather than skip it.

The correct subject map, per measured shape:
- `file_exists(name)` → `Join-Path <resolved {scratch:*} dir> name`, `Test-Path`;
- `field_*` predicates → the section's parsed object.

### 3e. Where it plugs in

- `:1552-1553` replaced by a call into the new evaluator; `$ev` gains a `success_when` block
  carrying per-section `ok` / `clauses` / `unrecognised` / `key`.
- `Get-Verdict`: a new gate that fails when any evidence record carries a non-empty
  `success_when_unrecognised`.
- `Invoke-Ablate`'s `$names` (`:3423`) gains that gate name so it is **ablatable** — a gate
  no ablation row can reach is a sentence in a comment, which is the exact doctrine already
  written into this function at `:3384`. This changes the `ABLATE:` summary line from
  `7 load-bearing` to `8 load-bearing`; acceptance criterion 2 will show 8/8, 0 unproved.
- `Invoke-Selftest`: **8 new controls** (4 declarations × TRUE / FALSE), plus 1 control
  pinning the new gate.

### 3f. The second-order half: 15 fire on ONE clause of a multi-clause sentence

Measured, and it is the same defect one level up. Of the 15 declarations that DO match a
regex today, only the `ok` clause is evaluated — the second conjunct of each multi-clause
sentence is read by nothing:

- `capabilities.json:2599` — `ok == true AND verdict is INTERCEPT-PROVEN AND runtime_hook_hit.count > 0`
- `capabilities.json:3321` — `... AND the rip_operands array is present`
- `capabilities.json:401`  — `... AND count > 0`
- `capabilities.json:1147` — `manifest present AND pinning present` (and `claims present`, `stdout non-empty`, `image_base is non-null AND aslr is present`, `rules_matched is an integer`, `an image block carrying arch and bintype`)

Honest statement of today's behaviour: **15 fire on one clause; 5 fire on nothing.** A round
can satisfy `ok == true` while violating `count > 0` and the mission calls it a success.

Therefore the evaluator's contract is per-clause visibility, not per-sentence pass/fail:
`clauses_evaluated` and `clauses_unrecognised` are both recorded, and a sentence with ANY
unrecognised clause fails closed — including a sentence that is half understood. Per the
Main correction: do not close four and believe it closed five, and do not ship a gate that
looks complete while half of each sentence is invisible.

---

## 4. Not done

- [ ] The evaluator is not written.
- [ ] The 8 selftest controls are not written.
- [ ] The neutralised-evaluator mutation has not been run — **[UNVERIFIED]**, no output exists.
- [ ] `-Action Ablate` has not been re-run since the pause. The 8-gate change to
      `:3423` is not in the file, so the baseline is still 7 gates; no new summary line exists.
- [ ] Post-change count of unevaluated declarations: **[UNVERIFIED]**. Baseline is 5; it is
      not 0 today and nothing I did moved it.

---

## NEXT

1. [DONE — the greps ran] `list-funcs.mjs`, `ghidra-headless.ps1` and `analyze.mjs` were
   read; results are in §3d. The outcome is that `native.ida.list_functions/envelope` is
   **not evaluable from mission.ps1's position** because the wrapper flattens the transport
   envelope before printing. Decide with the Owner whether that entry's envelope text should
   be re-pointed at the flattened fields (`count`, `functions`) — `manifests/capabilities.json`
   is out of my scope, so it is a REPORT, not a fix.
   Still open: read `scripts/emulation-probe.ps1` to establish whether `verdict` is top-level
   in the parsed JSON. That decides whether `native.ghidra.emulate/envelope` is evaluable.
2. Write `Get-SuccessWhenVerdict` per §3a-3c, replacing `:1552-1553`.
3. Add the `success_when` gate to `Get-Verdict` and to `$names` in `Invoke-Ablate`.
4. Add the 8 TRUE/FALSE controls. **Write the FALSE ones first and watch them fail** — a
   control that cannot fail proves nothing.
5. Mutation: neutralise the evaluator to "always true", run `-Action Selftest`, capture all
   8 red, restore, re-run green.
6. Acceptance, in order: selftest (expect `79 controls`, before = 71), ablate (expect
   `8 load-bearing, 0 unproved` + `8 load-bearing, 0 unproved`), mutation output,
   unevaluated count = 0.

7. **State coverage honestly and do not round.** Report, per declaration, whether it is now
   evaluated IN FULL. The expected honest answer is not "all 20": `native.ida.list_functions/envelope`
   provably cannot be (see §3d). If the complete grammar is out of reach, the deliverable is the
   vocabulary, the fail-closed behaviour and per-clause visibility, plus this list of what a
   complete grammar would still need:
   - a general clause grammar beyond the ten predicates in §3a, so second conjuncts are
     machine-checked rather than merely named;
   - a declared subject map per envelope declaration, since `file_exists` and `field_*` need
     different objects and one entry cannot see its own transport envelope at all;
   - the five that motivated the work, named: `native.ida.list_functions/envelope`,
     `native.ghidra.decompile/envelope`, `native.ghidra.emulate/envelope`,
     `mobile.apk.static/invoke`, `native.ida.decompile/envelope`.

## Registry findings to REPORT, not to fix (`manifests/capabilities.json` is out of scope)

Both are text-shape issues the evaluator can survive, so neither blocks the work:
- `native.ida.decompile/envelope` and `native.ida.decompile/invoke` are near-duplicates that
  disagree in field scope (`body.code` vs `code`). If they ever disagree the envelope is the
  one that should win, and nothing in the registry says which is authoritative.
- `native.pe.authenticode/invoke` declares `ok == true` and then says in the same string that
  `ok` is true for an unsigned binary too. The evaluator reads the requirement, not the
  commentary, so it is consistent — but the string carries two claims and only one is
  machine-checkable.
