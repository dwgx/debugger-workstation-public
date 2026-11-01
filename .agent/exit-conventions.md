STATUS: OPEN — 2026-11-01. This file read `STATUS: BLOCKED` from 2026-10-03 until today; the label
was accurate about that session and misleading about the file. The defect it measures is STILL IN
THE TREE and the fix in §4 is still unapplied; §8 re-measures it and resolves the one item §1 left
[UNVERIFIED]. The session was paused by Owner 2026-10-03 before any implementation landed, so NO
CODE WAS WRITTEN OR EDITED then and the worktree held no change of mine except this report file.
What follows is the COMPLETE MEASUREMENT, so the next window does not re-read a single file to
start. Every file:line in §1-§6 was read directly from the tree at commit e4da839, not inferred;
those numbers have since drifted and §8 gives the current ones.

===============================================================================
0. WHAT EXISTS, WHAT DOES NOT
===============================================================================
DONE:
  - Full read of all nine lab loops, their exit sites, and their surrounding context.
  - The declared collision claims, re-derived from the source rather than inherited.
  - Every `expect_exit` in manifests/capabilities.json that refers to a code I would change.
  - A constraint discovery that would have broken another agent's gate (see §6).

NOT DONE (nothing exists on disk):
  - scripts/verify-exit-conventions.py      — NOT WRITTEN
  - evidence/exit-conventions.md            — NOT WRITTEN
  - the negative control run (planted collision in a %TEMP% copy) — NOT RUN
  - the three loop fixes                     — NOT APPLIED
  - no READMEs edited

[UNVERIFIED] on every line marked as such below. Nothing below is marked UNVERIFIED except where
stated; the rest is direct quotation from the files as they stand at commit e4da839 on `main`.

===============================================================================
1. MEASUREMENT — every exit site in the nine lab loops
===============================================================================
Counted by `grep -n -E "process\.exit|exit\("` per file, then each site was read in context.

--- crypto-lab/tools/loop.mjs ---
:298   process.exit(failures.length === 0 ? 0 : 1);
       inside `main()`, immediately after the summary is printed. `failures` is the array of
       named checks that did not hold. MEANING: the loop ran to completion and at least one
       ASSERTION WAS REFUTED. This is a legitimate, expected verdict about the lab's own claims.
:303   process.exit(1);
       inside `main().catch((e) => { ... })`. MEANING: the loop BROKE. An exception escaped
       before any assertion could be evaluated.
:295   (no exit; `JSON-SUMMARY` + counts are printed at :294 before either exit above)

  COLLISION: CONFIRMED. 1 = "a check was refuted" (:298) and 1 = "the tool broke" (:303).
  A caller reading exit 1 cannot tell a refuted claim from a crashed harness.

--- forensics-lab/tools/loop.mjs ---
:95    process.exit(64);
       unknown `--control=<name>`. MEANING: usage error. UNAMBIGUOUS.
:367   process.exit(4);
       reached only when `demand` is set AND `failed.length === 0`. The printed text says
       "CONTROL srum: PASS — SUCCESS IS EXIT 4". MEANING: THE CONTROL FIRED (success, non-zero).
:372   process.exit(9);
       `demand` set, at least one control step failed. MEANING: THE CONTROL DID NOT FIRE — the
       instrument could not be shown to fail, i.e. the guard is decorative.
:381   process.exit(0);
       no `demand`, `failed.length === 0`. Printed text: "CONTROL srum: PASS — exit 0, self-test
       shape." MEANING: control fired, self-test shape. SUCCESS.
:386   process.exit(9);
       no `demand`, at least one step failed. MEANING: control did not fire.
:404   process.exit(failed.length === 0 ? 0 : 9);
       full loop summary. 0 = LOOP CLOSED (success). 9 = one or more of the eleven loop
       STEPS/ASSERTIONS failed.

  >>> THE BRIEF'S CLAIM ABOUT THIS FILE IS REFUTED BY THE SOURCE. <<<
  The brief states "exit 4 at :367 ... and exit 4 at :381 ... One code, opposite meanings."
  There is only ONE `process.exit(4)` in the file, and :381 is `process.exit(0)`. A `4/4`
  collision does not exist here. Stated plainly because rule 1 is that a number I did not
  measure is worse than no number.

  WHAT IS ACTUALLY WRONG IN THIS FILE, measured:
  (a) POLARITY, not a duplicate number. 4 (:367) and 0 (:381) BOTH mean SUCCESS; 9 (:372, :386,
      :404) means FAILURE. So "non-zero" is not a verdict inside this one file: 4 is a pass and
      9 is a fail. That is a real defect and the registry already depends on it (see §3).
  (b) 9 CARRIES TWO DIFFERENT FACTS. At :372/:386 it means THE CONTROL DID NOT FIRE (the
      detector refused to fail, so nothing else this run established is trustworthy). At :404
      it means AN ASSERTION WAS REFUTED. Those are different facts about different subjects —
      the guard versus the claim. This IS a collision by the definition the brief states, and
      it is the one to fix here.
  (c) Note the loop's own header comment at :65-68 says the control feature was added because
      "the loop's exit code spoke for all eleven sections at once". The feature was built; the
      exit taxonomy was not.

--- mobile-lab/tools/loop.mjs ---
:119   process.exit(9);
       `if (!built) { console.log('\nBuild failed; nothing downstream can be judged.') }`.
       MEANING: A PREREQUISITE FAILED — javac/d8/aapt2/zipalign/apksigner could not produce an
       APK, so ZERO checks were evaluated. Nothing about the lab's claims was tested.
:572   process.exit(0);   every check ran and held, LOOP CLOSED. SUCCESS.
:580   process.exit(8);   nothing failed but >=1 cross-check was SKIPPED. "a skip is not an
                         agreement" — a third state, deliberately not 0 and not a failure.
:588   process.exit(9);   >=1 step FAILED. MEANING: AN ASSERTION WAS REFUTED.

  COLLISION: CONFIRMED. 9 = "the build never happened, nothing was judged" (:119) and
  9 = "checks ran and were wrong" (:588).
  THIS ONE IS DOCUMENTED AS A REAL BUG IN THE REPO ALREADY. .agent/HANDOFF.md:214-215 records
  the concurrent-run incident: a run that had done nothing wrong returned exit 9 "Build failed",
  i.e. exactly the collision above, caused by a shared scratch dir. The scratch isolation was
  fixed; the code collision that let that lie read as a refutation was not.

--- native-lab/tools/loop.mjs ---
:244   process.exit(failed.length === 0 ? 0 : 1);   0 closed / 1 assertion refuted
:249   process.exit(2);                            uncaught exception (main().catch)
  NO COLLISION. 0/1/2 is coherent. Leave alone — renumbering here buys nothing and would break
  recorded expect_exit values for nothing.

--- managed-lab/tools/loop.mjs ---
:328   process.exit(failed.length === 0 ? 0 : 1);   0 closed / 1 assertion refuted
:334   process.exit(2);                            uncaught exception (main().catch)
  NO COLLISION.

--- fuzz-lab/tools/loop.mjs ---
:74    process.exit(2);                            --budget below the MIN_BUDGET floor (40).
                                                    Usage/precondition refusal. Unambiguous.
:297   process.exit(failed.length === 0 ? 0 : 9);   0 closed / 9 assertion refuted
  NO COLLISION.

--- net-reverse/tools/loop.mjs ---
:57    process.exit(failed.length === 0 ? 0 : 9);   0 LANE CLOSED / 9 assertion refuted
  NO COLLISION.

--- web-reverse/tools/loop.mjs ---
:94    process.exit(failed.length === 0 ? 0 : 9);   0 LOOP CLOSED / 9 assertion refuted
  NO COLLISION.

--- crackme-corpus/tools/loop.py   (the ninth loop; Python, not .mjs) ---
:143   return 127, "ilspycmd not found (dotnet tool list -g)"   missing tool. Unambiguous.
:214   return 0
:219   return 2
:258   return 0 if not failed else 9                0 closed / 9 assertion refuted
:262   sys.exit(main())
  NO COLLISION.

--- web-reverse/tools/loop2.mjs (a TENTH file, a second loop in one lab; not in the brief's nine) ---
:107   process.exit(9);
:265   process.exit(failed.length === 0 ? 0 : 9);
  NOT YET READ IN CONTEXT. [UNVERIFIED] whether :107 is a different fact from :265. Flagged for
  the next window; it was not in the brief's scope.

SUMMARY OF THE MEASURED COUNTS (denominator stated, because a percentage needs one):
  3 genuine collisions, across 10 loop files carrying 30 exit sites:
    crypto-lab      1 collision (code 1)   across 2 sites
    mobile-lab      1 collision (code 9)   across 2 sites
    forensics-lab   1 collision (code 9)   across 3 sites, plus a polarity defect on code 4
  7 files clean. Every code collision found is one where a code means BOTH "an assertion was
  refuted" and "the instrument did not produce a verdict at all".

===============================================================================
2. THE crypto-lab README DEFECT (the brief's second bullet)
===============================================================================
crypto-lab/README.md:73-77 documents the ANALYZER's table:
    0 analysed | 2 usage error | 3 bad input | 4 --expect mismatch
while crypto-lab/tools/loop.mjs uses 0/1 and crypto-lab/tools/analyze.mjs uses 0/2/3/4
(measured: analyze.mjs:699 exit 0 on --help, :783 exit 4 on expect mismatch, :786 exit 0,
:793 exit(e.exitCode || 3)). Two conventions in one project directory, and the README table
sits under a heading that reads like it governs the whole lab. Confirmed by reading.

===============================================================================
3. EVERY expect_exit THAT REFERS TO A CODE I WOULD CHANGE  (the §4 deliverable)
===============================================================================
Whole-registry distribution of the 66 `expect_exit` values in manifests/capabilities.json:
    0 -> 29 entries      1 -> 14      2 -> 8      3 -> 3      4 -> 2      4294967295 -> 1
    NOT PRESENT ANYWHERE IN THE REGISTRY: 6, 8, 9, 10.
  [measured by `grep -o -E '"expect_exit": *[0-9]+' | sort | uniq -c`]

Capabilities whose probe.command or negative_control.command invokes one of the three loops:

  crypto.jose.parse
    probe.command            = `node crypto-lab/tools/loop.mjs`        expect_exit 0
    negative_control.command = `powershell ... -File headless-lab\tools\jose_expect_control.ps1`
                              expect_exit 4   <-- a DIFFERENT file. crypto loop's exit 1 is
                              NOT this control. Unaffected by any fix here.
    AFFECTED BY A CHANGE: only expect_exit 0, and 0 is not being touched.

  forensics.memory.artefact
    probe.command            = `node forensics-lab/tools/loop.mjs`    expect_exit 0
    negative_control.command = `node forensics-lab/tools/loop.mjs --control=srum
                                --expect INJECTED_PRIVATE_RWX_REGION`    expect_exit 4
    >>> THIS IS THE BINDING CONSTRAINT OF THE WHOLE TASK. <<<
    expect_exit 4 lands on forensics-lab/tools/loop.mjs:367 — the CONTROL-PASSED site. Therefore
    **exit 4 at :367 MUST NOT BE RENUMBERED.** Any fix to this file has to leave 4 exactly
    where it is and move something else. The entry's own `polarity` field says so in prose:
    "SUCCESS IS EXIT 4. The refusal IS the control passing". `manifests/capabilities.json` is
    read-only for this work, so if a fix ever did require moving 4, the correct action is to
    report capability `forensics.memory.artefact`, old 4 / new X, and STOP — not to edit.
    AFFECTED BY A CHANGE: expect_exit 4 (forbidden to move) and expect_exit 0 (:404 success,
    not being touched). The 9 sites (:372, :386, :404) have NO recorded expect_exit — 9 appears
    nowhere in the registry.

  mobile.apk.static
    probe.command            = `node mobile-lab/tools/loop.mjs`       expect_exit 0
    negative_control.command = `powershell ... -File mobile-lab/tools/apktool_refusal_control.ps1`
                              expect_exit 1   <-- a DIFFERENT file (a .ps1), NOT the loop.
                              The loop's exit 1 does not exist; its codes are 0/8/9.
    AFFECTED BY A CHANGE: only expect_exit 0, not being touched.

  Cross-check of the other two recorded 4s: crypto.jose.parse's control (jose_expect_control.ps1)
  and native.pe.packer's control (expect_exit 3, per the registry dump). Neither invokes any of
  the three loops. No recorded value anywhere in the registry refers to crypto loop exit 1,
  mobile loop exit 9, or forensics loop exit 9.

  CONSEQUENCE, stated so the next window does not have to re-derive it: **the three collisions
  can be fixed with ZERO recorded expect_exit changes**, provided forensics' 4 is left alone.
  The only cross-lab consumer, scripts/smoke-all.ps1:65/69/71, matches on stdout text
  ('JSON-SUMMARY' / 'LOOP CLOSED') and its :131 gate tests `$rc -eq 0` only — so it cannot see
  any of this, which is exactly why the brief calls it "the only cross-lab consumer and it
  tests `$rc -eq 0` and nothing else". A fix that moves a NON-ZERO success code onto a number
  smoke-all does not check would still be invisible there; the fix must be documented in the
  lab's own README/header, per the brief.

===============================================================================
4. THE FIX I WOULD APPLY (designed, not applied) — codes from a declared table
===============================================================================
Minimal, and every already-unambiguous code left alone. Codes chosen from station semantics
already in use: 2 = uncaught exception (native-lab:249, managed-lab:334), 8 = incomplete
(mobile-lab:580), 9 = assertion refuted (five labs already use it), 0 = success, 4 = frozen
by forensics.memory.artefact.

  crypto-lab/tools/loop.mjs
    :298  exit 1  KEEP  = assertion refuted (matches native-lab/managed-lab meaning of 1)
    :303  exit 1 -> 2  = uncaught exception (the tool broke). Aligns with native/managed.
    README table to add for the LOOP: 0 closed / 1 refuted / 2 uncaught exception,
    alongside the existing ANALYZER table 0/2/3/4, labelled as two different tools.

  mobile-lab/tools/loop.mjs
    :588  exit 9  KEEP  = assertion refuted (station-wide meaning)
    :119  exit 9 -> 6  = PREREQUISITE FAILED, nothing downstream judged. 6 appears nowhere in
                        the registry and nowhere in any lab, so it is free.
    Header comment at :14-18 already declares 0/8/9; it becomes 0/6/8/9 with 6 named.

  forensics-lab/tools/loop.mjs
    :367  exit 4  FROZEN — registry binds it.
    :381  exit 0  KEEP  = control fired, self-test shape (success)
    :404  exit 0  KEEP  = loop closed (success); its 9 side = assertion refuted, KEEP
    :372  exit 9 -> 3  = control did not fire (the guard is decorative)  [3 is free in this
                        file; forensics-lab/tools/analyze.mjs already uses 3 for "image cannot
                        be read", i.e. the same "the instrument produced no verdict" fact]
    :386  exit 9 -> 3  = same meaning as :372, both in summarizeControl
    Then 9 in this file means only "an assertion was refuted" (:404), 3 means only "the control
    did not fire", 4 means only "control fired, registry refusal shape", 0 means only "success,
    self-test or full-loop shape". Header comment :21-26 gets the table.
    STILL UNRESOLVED, and it is a real Owner-level decision: 4 stays a non-zero SUCCESS while
    0 is also success, so `$rc -eq 0` still misreads the control shape. Fixing THAT means
    moving 4, which breaks forensics.memory.artefact in a read-only manifest. RECOMMENDATION:
    leave 4, document the polarity at the exit site, and record the taxonomy debt in the lab
    README rather than breaking a recorded control.

===============================================================================
5. THE CHECKER'S SHAPE (specified, not written)
===============================================================================
scripts/verify-exit-conventions.py, written BEFORE any loop is touched, per the brief:
  - declared convention table at the top (the §4 table above);
  - extract every `exit N` / `process.exit(N)` / `return N` per file with file:line AND the
    enclosing function + the nearest preceding `console.log`/`print` string, because the
    MEANING is in the prose, not the number (measured: the meaning of :367 is only visible in
    the string 8 lines above it);
  - per lab: the code set, and for each code the set of distinct meanings → collision when a
    code has >1 meaning;
  - compare to the declared table, name every divergence;
  - exit NON-ZERO on COLLISION, exit 0 on mere divergence. NOT collapsed — the brief is right
    that "a different number for assertion failed" (native 1 vs fuzz 9) is untidy, and "one
    number for two facts" is a defect.
  - its own: exit 2 for "could not read a file" — never silently skip a missing lab.
  - Negative control, to be RUN and pasted: baseline exit 0, then plant `exit 7` in a %TEMP%
    copy of crypto-lab/tools/loop.mjs and show it goes RED naming that file:line. The real file
    is not edited for that step.

===============================================================================
6. CONSTRAINT DISCOVERED THAT WOULD HAVE BROKEN A SIBLING'S GATE
===============================================================================
scripts/verify-atomic-artifacts.py pins ABSOLUTE LINE NUMBERS for write sites:
    forensics-lab/tools/loop.mjs   write_lines [268, 324, 331]
    mobile-lab/tools/loop.mjs      write_lines [109, 110, 140]
  (measured at scripts/verify-atomic-artifacts.py:192 and :305)
Every edit proposed in §4 inserts lines into those two files, which shifts those pins and
silently invalidates another agent's verifier — whose owner is `AtomicArtifactIntegrity`,
currently running. Either (a) make every §4 edit LINE-COUNT NEUTRAL (change only the numeric
literal and the comment text on existing lines, add nothing), or (b) coordinate with that peer
first. I did not message it, because Owner paused the session before any edit existed to
coordinate about. [UNVERIFIED] whether that script re-derives or trusts the pinned numbers — I
read the PRODUCERS table but not the consumer function.
crypto-lab/tools/loop.mjs has no entry in that table, so edits there are free.

===============================================================================
7. NEXT — exact commands, in order, for the next window
===============================================================================
  cd <repo>
  1. Message peer AtomicArtifactIntegrity about the line pins in §6 BEFORE editing forensics or
     mobile. (roster id `AtomicArtifactIntegrity`; idle peers wake when messaged)
  2. Read the CONSUMER of write_lines in scripts/verify-atomic-artifacts.py (grep -n "write_lines"
     past line 358 — it is consumed in main(), past :699) and settle §6 option (a) vs (b).
  3. Write scripts/verify-exit-conventions.py FIRST. Run it on the untouched station: it must
     name the 3 collisions in §1 and exit non-zero. That is the pre-fix baseline.
  4. Negative control: copy crypto-lab/tools/loop.mjs to %TEMP%, change one `exit 1` to `exit 7`,
     point the checker at the copy, paste the RED output naming file:line. Never edit the real
     file for this.
  5. Apply the three fixes from §4, line-count neutral.
  6. Re-run the checker: must exit 0, print the declared table and the comparison.
  7. Re-enumerate expect_exit (the command is in §3) and confirm 0 recorded values need changing.
  8. Edit crypto-lab/README.md, forensics-lab/README.md, mobile-lab/README.md to state each lab's
     OWN loop exit table, keeping and striking the superseded ANALYZER/LOOP split prose per
     rule 6 — never delete it.
  9. Write evidence/exit-conventions.md with both command outputs pasted.
 10. Commit + push. No AI signature.

OPEN DECISION FOR OWNER (one, and only one): whether forensics-lab's non-zero SUCCESS (exit 4)
is allowed to keep existing next to exit 0 = success. It is bound by
forensics.memory.artefact.negative_control.expect_exit = 4 in a read-only manifest. My
recommendation is to keep 4 and document it; changing it requires a registry edit that this
work is not permitted to make.

===============================================================================
8. RE-MEASURED 2026-11-01 — the block is still real, and §1's one [UNVERIFIED] is closed
===============================================================================
Added when this file was reviewed for publication. Nothing in §1-§7 is retracted: the three
collisions it names are all still present, the fix is still not applied, and the two files §0
lists as NOT WRITTEN still do not exist (`scripts/verify-exit-conventions.py`,
`evidence/exit-conventions.md`).

Exit sites now, per file (`grep -n "process\.exit(\|sys\.exit(\|return [0-9]\+"`), with the
meaning read in context:

  crypto-lab/tools/loop.mjs       47:2 | 322:0/1 | 327:1            1 STILL MEANS TWO THINGS
  forensics-lab/tools/loop.mjs    83:2 | 144:64 | 416:4 | 421:9 |
                                  430:0 | 435:9 | 455:0/9           9 STILL MEANS TWO THINGS
  mobile-lab/tools/loop.mjs       50:2 | 143:9 | 598:0 | 608:8 |
                                  616:9                            9 STILL MEANS TWO THINGS
  web-reverse/tools/loop2.mjs    107:9 | 265:0/9                    9 STILL MEANS TWO THINGS (NEW)
  fuzz-lab/tools/loop.mjs         72:2 | 125:2 | 348:0/9            clean — both 2s are "refused to run"
  managed-lab/tools/loop.mjs      55:2 | 357:0/1 | 363:2            clean
  native-lab/tools/loop.mjs       40:2 | 337:0/1 | 343:2            clean
  net-reverse/tools/loop.mjs      37:2 | 81:0/9                     clean
  web-reverse/tools/loop.mjs      42:2 | 124:0/9                    clean
  crackme-corpus/tools/loop.py   143:127 | 214:0 | 219:2 |
                                  272:0/9 | 276:sys.exit(main())    clean

  TOTAL: 35 exit sites across 10 loop files, FOUR collisions. §1 measured 30 sites and 3
  collisions at e4da839. The fourth is the file §1 explicitly left [UNVERIFIED], now read:
  loop2.mjs:107 exits 9 when the sample factory left no known answer — NO VERDICT WAS PRODUCED —
  and loop2.mjs:265 exits 9 when a step was refuted. Same defect as mobile-lab:143, and it needs
  the same fix (a code that means "prerequisite failed" must not also mean "assertion refuted").

  The `stray argument` refusal on 2 in crypto/forensics/mobile/fuzz-lab is new since e4da839. It
  is not a collision anywhere it appears: 2 means only "refused to run on an argument it would
  otherwise have ignored", and no file gives 2 a second meaning.

§3's binding constraint still holds, re-read from `manifests/capabilities.json` today:
  forensics.memory.artefact.negative_control.command =
    `node forensics-lab/tools/loop.mjs --control=srum --expect INJECTED_PRIVATE_RWX_REGION`
  expect_exit = 4   ->   forensics-lab/tools/loop.mjs:416 MUST NOT BE RENUMBERED. Unchanged.
The registry around it has drifted: 28 capabilities and 60 `expect_exit` values now (27 and 66 at
e4da839), distributed 0x28 / 1x17 / 2x8 / 3x3 / 4x3 / 4294967295x1. 9 still appears nowhere, so
§3's consequence still holds — the collisions can be fixed with ZERO recorded expect_exit changes.
crypto.jose.parse's control has been repointed since (now `crypto-lab/tools/negative-gate.mjs`,
still expect_exit 4) and still does not touch the crypto loop.

§6 is still live and still unread: `scripts/verify-atomic-artifacts.py` pins ABSOLUTE line numbers
for write sites in forensics-lab and mobile-lab (`write_lines` entries in its PRODUCERS table), and
every §4 edit shifts them. Make those edits line-count neutral, or coordinate first.

§4's proposed table is unapplied and therefore still a proposal, not a convention. A reader who
wants the station's ACTUAL exit semantics should read the loops, not this file.
