# `mission.ps1`: mechanisms with no ablate anchor and no selftest control

Written by the integrator from a read-only scout's report, which could not write to disk itself — its
brief named no report path and its tool surface had no filesystem write. Persisted here so the next
window has a file rather than a session transcript.

**`[UNVERIFIED]` — the scout ran ZERO commands against either tree.** Every finding below is a static
read of the anchors, the `$routing` table and the selftest control list. Each predicts green under its
own mutation. **Those are predictions, not measurements.**

## The numbers, corrected twice

`success_when` is declared 20 times in `manifests/capabilities.json`: 16 under `invoke`, 4 under
`envelope` (:230, :384, :1832, :2227).

`mission.ps1:1552-1553` reads it through exactly two regex literals, both against
`$cap.invoke.success_when`:

```powershell
if ($cap.invoke.success_when -match 'ok == true' -and $parsed.ok -ne $true) { $declaredOk = $false }
if ($cap.invoke.success_when -match 'code is non-null' -and $null -eq $parsed.code) { $declaredOk = $false }
```

- **15 fire.** Every `invoke.success_when` carrying the literal `ok == true`: :248, :401, :665, :799,
  :920, :1865, :2599, :2765, :3121, :3321, :3494, :3645, :3774, :3891, :4010.
- **5 fire on nothing.** `native.ida.decompile` envelope (:230), `native.ida.list_functions` envelope
  (:384), `native.ghidra.decompile` envelope (:1832), `native.ghidra.emulate` envelope (:2227), and
  `mobile.apk.static` invoke (:1147).
  :230 is doubly invisible — its text *would* match `'code is non-null'`, but both regexes read the
  `invoke` key. `grep envelope scripts/mission.ps1` returns zero matches.
  :1832 is a scar: "summary.json EXISTS and its `ok` is true -- NEVER the process exit code", written
  by someone who had already made that mistake.
- **AND, worse, only the first clause of the 15 is read.** The second conjunct of every multi-clause
  sentence is read by nothing: :2599 `AND verdict is INTERCEPT-PROVEN AND runtime_hook_hit.count > 0`,
  :3321 `AND the rip_operands array is present`, :401 `AND count > 0`, :1147 `AND manifest present AND
  pinning present`. A round can satisfy `ok == true` while violating `count > 0` and the mission will
  record success.

So the honest statement is **15 fire on one clause of a multi-clause sentence; 5 fire on nothing.**
`mobile.apk.static` is sharpest of the five: its `ok` token is absent entirely, so `declaredOk` reduces
to bare exit code plus "it parsed as JSON".

Blast radius: `$declaredOk` decides the evidence record, the precondition gate at :1582, and fact
forwarding at :1560-1564. A false `true` corrupts all three at once.

## Seven mechanisms, ordered by blast radius

`grep skip_exits`, `grep gate_role`, `grep by_name` and `grep -c required` in `scripts/` return only
the sites below — no `C '...'` control, no `$routing` row, no `ABLATE-ANCHOR` for any of them.

| # | site | what a control must assert |
|---|------|---------------------------|
| 1 | `:1552-1553` `success_when` tokens | a round exiting 0 with valid JSON but `ok:false` on an unrecognised `success_when` is recorded `ok:false` **and forwards no facts** |
| 2 | `:1448-1481` `select.by_name` / `element_path` | a name the producer did not emit yields `skipped_no_consumer` naming it, **not a positional fallback**. One carrier (`native.disasm.capstone`). The registry note claims the loud failure was measured; the suite never tests it. The mechanism replaced `select.index: 1` precisely because positional selection is "a silent-wrong-answer machine" |
| 3 | `:1593-1594` `skip_exits` | an exit **in** `skip_exits` → `precondition_not_applicable`, loop proceeds; an exit **not in** it → `precondition_failed`, halts. One carrier (`native.pe.packer`, `skip_exits: [3]`, :3130). Deleting this restores a recorded incident: the packer refusing an APK on exit 2 and gating off `mobile.apk.static`, which analyses APKs correctly |
| 4 | `:837-843` precondition-FIRST ordering | across every declared question type, a `gate_role: precondition` step appears at a strictly lower index than every step in its `invoke.gates` list. The control at :2974 checks order is *stable*, never that the gate is *in front* |
| 5 | `:756-783` rule-6 pull | a precondition not selected by question type, whose `gates` names a capability already in the route, IS added with `selected_by` naming the gate |
| 6 | `:328` `consumes.inputs[].required` | a `required: true` input the runner does not bind is **dropped or refused by name**, not planned as an unmet refinement. Computed, then never branched on — `Get-Route` filters on `hard` (:698) |
| 7 | `:1603` `$preconditionBlock`, `:1557` `$ev['evidence_source']` | **write-only.** No control is possible until something reads them. Flagged as write-only rather than dressed as a testable gap |

Excluded deliberately: `$v = "$val"` three times at :1481-1483 — redundancy, not a mechanism, nothing
branches on it.

## First command for whoever picks this up

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/mission.ps1 -Action Selftest
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/mission.ps1 -Action Ablate
```

Then confirm or refute item 1 in one pass: set `invoke.success_when` to an unrecognised shape on all
20 carriers and re-run Selftest. **Green confirms the finding.** The scout's prediction is green; the
measurement does not exist.

The cheapest fix per item is one `ABLATE-ANCHOR` plus one `$routing` row, in the shape R27 already
uses. Use the `-MaxSteps` deprecation block (:3172-3193) as the template: it refuses ambiguity rather
than guessing, warns once, records the spelling in the artifact, and has an end-to-end control through
the real entry point (:3279-3299).

## Open findings the scout did not fix (read-only mandate)

1. `success_when` read by two tokens — 5 declarations inert, 15 half-evaluated (item 1 above).
2. `skip_exits`, `gate_role` ordering, `by_name`, `required` — no anchor, no control (items 2-6).
3. `gate.ps1 -Lane` accepted and ignored on `Check` (:149, vs :847/:2036). No authority widens; a
   caller's mental model does.
4. `gate.ps1` exit 3 returned by nine unrelated failures (:752, 765, 774, 1025, 1034, 1057, 1142,
   1150, 1156, 1169, 1172, 1181). The payload discriminates; the code does not. Already cured for the
   biting case in `arsenal_mcp_server.py:570-584`.
5. `grant.note` written (:1191), never read, outside the seal by design (:705-707). Feeds no decision —
   prose in a data slot, the exact shape `gate_must_not_delegate_without_mechanism` (:487-491) refuses
   elsewhere.
6. `stop_note.ruled_out = @()` (:1713) — hardcoded empty in every artifact.

## The fork that is the Owner's, not a worker's

Whether the nine labs' exit codes should be **normalised** or merely **documented as five
conventions**. Normalising is a breaking change to `smoke-all.ps1` and to every recorded
`expect_exit`; documenting is free. `ExitCodeConventions` was dispatched to settle the collisions that
are defects regardless of which way this goes (one code meaning two things) and to leave the
divergence question open.

## Correction, recorded because the error is the reusable part

The scout first reported "18 of 20 declarations are never evaluated". The integrator's first
measurement said 4. The true figure is 5. The scout counted every declaration lacking `ok == true` as
unevaluated without checking whether the *other* token matched, and without separating the four
`envelope` keys from the sixteen `invoke` ones; the integrator then missed `:230` by trusting a
`walk()` that stopped at the key level. Both errors inflated or deflated a number that was about to be
written into a brief. **A short sure list beats a long wrong one**, and neither of us had one.