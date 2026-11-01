# Audit A2 - false-green hunt in the four self-checking tools

Auditor: a2 (independent). Read-only except this file.
Date: 2026-10-02. cwd: <repo>.
Targets: scripts/assert-probes.py, reachability-report.py, doc-facts.py, registry-verify.py.

Method: for every tool, construct the cheapest input that would slip PAST it and actually run
it. No theorising.
Baseline: HEAD 173f147, registry 26 capabilities. Working tree is NOT clean as the session
claimed (?? .agent/audit/, ?? .agent/reports/, ?? .agent/verify/) - untracked only, no tracked
modifications.

Status: IN PROGRESS

---
# TOOL 3: doc-facts.py  (planted BOTH directions)

Fixture: throwaway wiki at `.agent/audit/a2/wiki/*.md` via `--wiki`, so the real wiki stayed
untouched. Registry truth: 26 capabilities, 22 observed, 7 typed edges.

## Baseline on the real wiki
    $ python scripts/doc-facts.py
    doc-facts: registry has 26 capabilities (22 observed, 7 typed edges)
    doc-facts: scanned 118 wiki files, 16 live numeric claims checked
    doc-facts: OK, every live numeric claim matches the registry.      EXIT=0

## Both directions tested in ONE run (false + true planted together)
Files: a-false-backtick.md, b-true-backtick.md, c-false-plain-prose.md, d-false-bold.md,
e-rows-not-caps.md, f-4digit.md, g-paren.md.

    $ python scripts/doc-facts.py --wiki .../a2/wiki
    scanned 7 wiki files, 5 live numeric claims checked
    2 STALE CLAIM(S)
      a-false-backtick.md:1: claims 99 capability count; registry says 26
      d-false-bold.md:1: claims 99 capability count; registry says 26
    EXIT=1

VERDICT, direction 1 (catch a false claim): PASSES. `` `capabilities: 99` `` and
`**99 capabilities**` are both caught. The original under-match bug (the session's own negative
control that returned OK) is genuinely fixed.

VERDICT, direction 2 (no false alarm on a correct claim): PASSES.
b-true-backtick.md carries `capabilities: 26`, 22 `observed`, 7 typed edges -- all three are
COUNTED among the 5 checked and none is flagged. e-rows-not-caps.md ("Fourteen of the sixteen
rows") is counted as 0 claims and not flagged, so the over-matching second version is also
genuinely fixed. The docstring's decision to keep only two forms is doing what it says.

## WHAT SLIPS PAST doc-facts (all actually run)

1. `There are 99 capabilities in the arsenal today.` / `The arsenal has 19 capabilities.`
   -> 0 claims matched, exit 1 came only from the other files. c-false-plain-prose.md contributed
   NOTHING to the check. Plain prose counts are invisible.
2. `The arsenal ships (99 capabilities) in total.` and `It reports "88 capabilities" per the
   upgrade.` -> invisible (g-paren.md matched nothing).
3. `The arsenal is **1234 capabilities** wide.` and `We carry `capabilities: 1234` in the registry.`
   -> INVISIBLE. `\\d{1,3}` cannot span 4 digits, and for the bold form the trailing
   `\\s+capabilit` fails to match because digit 4 intervenes. f-4digit.md matched nothing.
   This is the cheapest slip of all: a real over-count claim is unchecked purely by digit width.

## THE ONE THAT MATTERS: a live, currently-FALSE claim in the real wiki is invisible
`<project>/<private-tree>/wiki/methods/arsenal-inventory.md:51` (LIVE, not struck -- read `:raw`
to confirm) says:

    This is a different axis from the registry's 15 capabilities -- a domain can hold several ...

The registry has 26. `arsenal-inventory.md` IS in the scanned set (verified: SKIP set is
{.git,.agent,literature}, this file is wiki/methods/). But `15 capabilities` has no backtick and
no `**`, so claim 1's pattern cannot see it. Same file also carries "**Fourteen of the sixteen
rows**" and `charTER-ARSENAL.md:526` carries the italic `*12 of 24 capabilities are callable*`
(stale: it is 15 of 26 today) -- also invisible.

So doc-facts prints "OK, every live numeric claim matches the registry" while at least three
live stale capability counts sit in the very files it scans. The narrow-pattern decision is
defensible and honestly documented, but the SUCCESS MESSAGE overstates the guarantee: it says
"every live numeric claim", and the measured truth is "every live numeric claim in two
punctuations". The count it prints (16 claims over 118 files) is the honest number and the
prose message is the false green.

---
# TOOL 1: assert-probes.py  (the three claimed false verdicts)

## FIX 1 -- PowerShell handed to cmd.exe: GENUINELY FIXED (by code, lines 88-121)
`run()` no longer shell-sniffs. It writes `cmd + "\nexit $LASTEXITCODE\n"` to a .ps1 and runs
`powershell -NoProfile -ExecutionPolicy Bypass -File`, `shell=True`, cwd=REPO, stderr MERGED into
stdout. Byte-for-byte, no re-quoting. This is the right shape; the old `powershell -Command "..."`
wrapper that destroyed double quotes is gone.

## FIX 2 -- `powershell -File` discarding the exit code: GENUINELY FIXED, WITH A RESIDUAL HOLE
The wrapper appends `exit $LASTEXITCODE`. Measured directly (each body + `exit $LASTEXITCODE`,
run through the exact same powershell invocation run() uses):

    body                                 rc   verdict
    Write-Error "boom"                   0    *** LEAKS 0 ***
    throw "fatal"                        1    PROPAGATED
    Get-Item Z:\nope\zz.txt              0    *** LEAKS 0 ***
    python -c "1/0"                      1    PROPAGATED
    Get-Content nosuchfile.txt -EA Stop  1    PROPAGATED
    cmd /c exit 3                        3    PROPAGATED
    exit 7                               7    PROPAGATED
    python -c "import sys;sys.exit(4)"   4    PROPAGATED

Native commands and TERMINATING PowerShell errors propagate correctly -- the original
"every control exits 0" bug is dead. But `$LASTEXITCODE` is only set by NATIVE commands. A
NON-TERMINATING PowerShell error (Write-Error, a non-terminating cmdlet failure) leaves
$LASTEXITCODE unset, so `exit $LASTEXITCODE` exits 0.

This is a REAL slip-past, and it is the expensive direction: any control whose command is written
in PowerShell rather than delegating to a native exe will report rc=0. A negative_control with
expect_exit=1 is then checked against a real 0 -> DRIFT, fine. But a PROBE with expect_exit=0 that
actually FAILED non-terminatingly still reads as exit 0, and if its `expect` substring happens to
appear anywhere in the error text the probe is reported CLEAN. I could not exercise this against a
real registry entry (all 26 probes currently delegate to native exes or scripts), so it is a
latent hole, not an observed false green. It is cheap to close: `exit $LASTEXITCODE` should be
preceded by an explicit non-terminating-error trap.

## FIX 3 -- timeout reported as DRIFT: GENUINELY FIXED (measured, not read)
`run()` returns TIMEOUT_RC=-1 on TimeoutExpired; `tool_fault()` tests `rc == TIMEOUT_RC` FIRST and
returns a "THIS TOOL'S LIMIT ... A truncated run is not evidence" verdict. Forced a real timeout:

    timeout=1s -> rc=-1 blob='<timeout after 1s>' secs=22.4
       tool_fault -> "timed out after 22s, so no output was captured and NOTHING can be concluded
       about the expect string. THIS TOOL'S LIMIT: rerun with a larger --timeout."
    timeout=3s -> rc=-1 blob='<timeout after 3s>' secs=20.2   (same verdict)

Never DRIFT. Confirmed fixed.

## THE FALSE GREEN I FOUND: a timeout can produce ZERO verdicts, which reads as CLEAN
    $ python scripts/assert-probes.py native.pe.packer --timeout 1
    assert-probes: 1 checked, .            EXIT=0

`1 checked` and an EMPTY verdict list, exit 0. Instrumented: run() returned rc=0 in 0.53 s with
real output -- the probe genuinely completed inside 1 s, so this particular run was legitimate and
was in fact clean (expect + expect_exit both matched). But the presentation is the defect: the
summary line counts VERDICTS, not capabilities, so any capability whose probe passes cleanly and
whose control passes cleanly contributes zero lines and the run prints "N checked, ." with exit 0.
A reader scanning for problems sees an empty list and a green exit code. The count that would
catch this -- "N capabilities verified, M emitted no verdict" -- is not printed.

## CONFIRMED FALSE GREEN (the headline finding for assert-probes)
I replaced native.pe.packer's probe and control with a standalone script that runs NO packer at
all -- it echoes the expected JSON for the good case and prints "REFUSED: not a PE" + exit 3 for
the bad case (`.../fake/fakepe.ps1`). Everything the registry CLAIMS is internally consistent:

    probe.command    = powershell ... -File fakepe.ps1 good
    probe.expect     = '"packed":false'      (unchanged, real)
    probe.expect_exit= 0                     (unchanged, real)
    nc.command       = powershell ... -File fakepe.ps1 bad
    nc.expect_output = "not a PE"            (unchanged, real)
    nc.expect_exit   = 3                     (unchanged, real)

ACTUAL RESULT:
    verdicts: []
    summary would read: 1 checked, .
    main() would return: 0   <-- GREEN, exit 0

The tool cannot tell the difference between "the packer ran and reported packed:false" and "a
2-line script printed the same two strings". assert-probes verifies that the recorded CLAIM is
reproducible, which is genuinely valuable and is exactly what its docstring says it does. It is
NOT an independent check that the tool is the tool. The registry's integrity therefore still
depends on a human having pasted the right command once; the tool will thereafter certify that
paste forever. That limit is NOT stated in the docstring, which claims it exists because "all four
survived a registry that reported REGISTRY CLEAN".

## Other assert-probes notes (all run)
- 13 of 26 `negative_control` entries have `expect_output: None` (incl. crypto.jose.parse,
  forensics.memory.artefact, managed.il.decompile, mobile.apk.static, fuzz.differential.parse,
  all four ghidra/ida ones). Those controls are validated by EXIT CODE ALONE. I did not observe
  any of them wrongly pass -- but for a control whose expect_output is None, a tool that exits
  non-zero for an unrelated reason satisfies the check completely.
- `prose()` is a 5-word prefix heuristic {see, list_funcs, run, use, the}. A PROSE control whose
  first word is outside that set is executed as a shell command:
      "observe what the packer probe reports for a text file" -> prose()=False -> RUN
  and produced a DRIFT (real=0 vs expect_exit=3) -- caught, and the safe direction, but the tool
  is running English sentences. A prose control beginning with "see"/"run"/"use"/"the"/"list_funcs"
  is SKIPped in silence instead. Both are noise; neither is a false green today.
- Real run, targeted, two cheap caps:
      $ python scripts/assert-probes.py native.pe.packer native.pe.container
      assert-probes: 2 checked, .          EXIT=0
  i.e. genuinely clean: probe expect + expect_exit + control expect_output + expect_exit all
  matched. That is a TRUE green for those two, verified by instrumenting run() directly.

---
# TOOL 2: reachability-report.py

## Baseline (real E:/missions) — the dark axis IS printed, fix #1 is real
    per axis, DECLARED callable vs has actually produced a fact in a mission:
      Q1.identify      7/8
      Q2.locate        5/5
      Q3.behaviour     4/4
      Q4.data          2/4
      Q5.vuln-shape    0/0   <-- DARK: no callable capability declares it
      Q6.crypto        2/3
      Q7.origin        3/4
    1 of 7 axes have never produced a single fact in a mission: Q5.vuln-shape

All SEVEN axes print. The loop is `for c in caps:` over EVERY capability, so an axis declared
only by non-invoke capabilities is still counted (`declared: 0`) and still reported as DARK.
Confirmed by synthetic tree: with a missions root containing almost nothing, Q5 still prints
`0/0 <-- DARK` and the dark count rose to 2 of 7. The earlier version that hid dark axes is
genuinely fixed.

## Q4 — can a FAILURE count as SUCCESS? YES. CONFIRMED.
`scan()` does `if r.get("ok"): ok[cid] += 1`. `ok` is the mission's own boolean. It never looks
at `facts`, never at an exit code, never at an error field. A capability that ran, FAILED to
produce anything, and was recorded `ok: true` counts as a success.

ACTUALLY RUN. Synthetic artifact m2 with `ok: true` and an EMPTY/absent `facts` list:
    native.behaviour.capa                  2    2  worked (2x)
    native.pe.packer                       2    2  worked (2x)
    net.pcap.selfparse                     2    2  worked (2x)

capa's entry was `{"capability":"native.behaviour.capa","ok":true,"round":1}` — no `facts` key at
all, so ZERO facts were produced, and the report says "worked". The docstring's headline claim is
"four of twelve callable capabilities have never once produced a FACT in a mission" and the
per-axis text says "has actually produced a fact in a mission" — but `ok` is not the same
predicate as "produced a fact". The report measures something adjacent to what it says it
measures. Against real missions every `ok:true` entry does carry facts, so this does not corrupt
today's numbers, but the tool's own central claim is not what it computes.

Cheapest slip, stated exactly: give any chain entry `"ok": true` with `"facts": []`. Nothing in
this tool can tell that apart from a success.

## Q4b — is an unparseable axis skipped? Three distinct behaviours, all measured.
Fixture: one mission dir each, artifact at the depth the glob actually matches
(`<root>/*/artifact.json`; a file at the root itself is INVISIBLE to the glob, see below).

    badjson      ({not json)   -> exit 0, "read : 1   UNREADABLE: 1" + "!! could not parse"   REPORTED
    emptyfile    (0 bytes)     -> exit 0, "read : 1   UNREADABLE: 1" + "!! could not parse"   REPORTED
    jsondictnull ({})          -> exit 0, "read : 1", no warning, every axis reads as never-worked  SILENT
    chainnull    (chain: null) -> exit 0, "read : 1", no warning, SILENT
    jsonlist     ([])          -> CRASH, exit 1, AttributeError: 'list' object has no attribute 'get'
    chainnotlist (chain: {...})-> CRASH, exit 1, same AttributeError

So: unparseable JSON and empty files ARE reported (the docstring's claim holds for those two).
But three shapes are mishandled:
 * `[]` and a dict-valued `chain` CRASH the whole report. This is safe-ish (an error is not a
   zero, exit 1, no per-axis table printed at all) but it aborts the ENTIRE scan, so one bad
   artifact among 40 suppresses the whole measurement — the very omission the docstring condemns,
   reached by a different route. `a.get("chain")` assumes a dict.
 * `{}` and `{"chain": null}` are counted as read and contribute NOTHING, with no warning. An
   artifact whose chain is missing is indistinguishable from an artifact that recorded no
   invocations. The scan prints "mission artifacts read : 1" as if it were measured.

## Q4c — THE GLOB HIDES FILES (cheap, and it is a real false green)
`files = sorted(glob.glob(os.path.join(root, "*", "artifact.json")))` — exactly ONE level deep.
Anything deeper is never counted, never reported, never even listed as unreadable. Verified:

    glob E:/missions/*/artifact.json        -> 40 hits   (what the tool uses)
    glob E:/missions/*/*/artifact.json      ->  0 hits
    artifact.json placed at the missions root itself -> MISSED entirely

The E:/missions layout happens to be exactly one level deep, so the real number is right today.
A single extra nesting level (a dated subfolder, a per-round directory) silently zeroes the scan
and the report prints a clean, confident, entirely fictional table with exit 0. There is no
cross-check that the number of artifacts found is plausible and no `--recursive` escape.

## Also: the header count is not the denominator
`print(f"mission artifacts read : {len(files)}")` — `len(files)` is the number of glob HITS,
including unreadable ones. So "read : 1   UNREADABLE: 1" reads as one artifact successfully
read when zero were. The parenthetical does disclose it, but the noun "read" is wrong and the
"1" is the sort of number this project has been bitten by all session.

---
# TOOL 4: registry-verify.py  (22 rules, 59 selftest cases)

## Baseline
    $ python scripts/registry-verify.py --selftest
    SELFTEST OK: 59 cases each fire on a registry built to break them.   EXIT=0
All 59 pass. No `nocase` case is vacuous either — "R18 one instrument may have one family"
is `correctly silent`, so the negative-control direction is genuinely exercised.

## Q2 — IS THE FIXTURE A LEGAL REGISTRY? Structurally YES, materially NO.
Built `_good_entry()` x2 exactly as `case()` does, unmutated, and ran `validate()`:
    BASELINE FIXTURE problems: 0
So the fixture is not the "literal string false" failure the session hit before — it passes all
22 rules cleanly and every case's baseline is uncontaminated.

BUT every command it names is a file that does not exist in this repo:
    control command in fixture: 'python control.py --refuse'
    exists(scripts/example_selftest_probe.py)   = False
    exists(scripts/example_selftest_probe_b.py) = False
    exists(control.py)                           = False
So the fixture is legal only in the sense R21 enforces, which is a shape test. The fixture models
a registry whose probe and control would both fail if anyone ran them — which is exactly why the
R21/R2 gap below matters, and why the selftest cannot detect it.

## R21 IS LEXICAL ONLY — the cheapest slip-past, and it is by design
R21 accepts a control command if it contains any of `.mjs .js .cjs .py .ps1 .exe .bat .cmd .com`
or starts with node/python/powershell/cmd/uv/&. It never touches the filesystem. Measured:

    ACCEPTED  python scripts/example_selftest_probe.py      <- the fixture's own, does not exist
    ACCEPTED  python /nonexistent/path/totally_made_up.py
    ACCEPTED  powershell -File Z:\no\such\thing.ps1
    ACCEPTED  node ./does-not-exist.mjs
    ACCEPTED  python totally_absent.exe.py
    ACCEPTED  python fake.py

Pure English that merely MENTIONS a runnable-looking suffix walks straight through — this is the
same class of bug the session already fixed once in this very script (the first doc-facts regex
under-matching because of an unreachable alternation):

    SLIPPED PAST  'point the wrapper at a .txt file, see probe.py notes'
    SLIPPED PAST  'drop SRUM from the image and re-run probe.py'
    SLIPPED PAST  'oracle with alg=none and a swapped token, per probe.py'
    SLIPPED PAST  'run the .ps1 by hand'
    SLIPPED PAST  'we should test cmp.exe here'
    rejected     'list_funcs on the mjs'   (no suffix, no known head)

So R21 rejects the four prose examples quoted in its own docstring, but ANY of them with "see
probe.py" appended is a valid runnable control forever. The rule's stated purpose ("a control
nobody can execute cannot fail, so it passes forever") is defeated by the cheapest possible edit.
Mitigating: assert-probes would still try to run such a control and would likely produce a real
DRIFT. The two tools do not each cover the other's gap.

## THE ASYMMETRY: R10 checks the filesystem, R2 and R21 do not
Measured on the same missing path, three rules:

    R10 invoke argv=['python','scripts/definitely_missing.py']
      -> REJECTED "invoke names 'scripts/definitely_missing.py', which does not exist in this repo
                  (looked in D:\...\debugger\scripts\definitely_missing.py)"
    R2  probe.command   = python scripts/nonexistent_probe_xyz.py   -> ACCEPTED (no existence check)
    R21 control.command = python scripts/nonexistent_control_xyz.py -> ACCEPTED (no existence check)
    R10 invoke argv=['python','-c','pass'] + runner + success_when   -> ACCEPTED (correctly)

R10 already demonstrates the existence check is cheap and already implemented in this file — it
resolves the path and reports where it looked. Applying the same test to `probe.command` and
`negative_control.command` is a few lines and would have caught the selftest's own phantom files.
The inconsistency is the finding: the repo applies "must actually be runnable" to an invoke and
not to the probe or the control, while `assert-probes.py` exists to run exactly those two.

## R10 shape rejection (all REJECTED, safe direction — noted for completeness)
    invoke='python scripts/definitely_missing.py'  -> "invoke.argv must be a non-empty array"
    invoke='python -c print(1)'                     -> same
These reject the string form rather than the missing file, which is a false REASON on a true
finding. R10 wants `{argv, runner, success_when}`; the string form is the older shape. Not a
false green — R10 refused all four, including a real repo path — but the message can mislead
someone debugging a genuinely-present tool.

## Are the 59 selftest cases VACUOUS? Mostly NO — I tried and could not make them pass wrongly.
8 of 34 `case()` calls assert on a BARE rule prefix ("R2", "R5", "R14", "R17", "R22"). A bare
prefix is the exact shape the script's own comment warns about ("R1" is a substring of
"R10".."R17"), and only the R1 case was rewritten to match full message text. So this was the
most promising place to find a control green for the wrong reason.

I re-derived every one of the 8 by re-applying its mutation and listing WHICH RULES FIRED:

    R2: pop probe                      -> fired=['R17','R2']     <- R17 co-fires
    R5: control no expect_exit         -> fired=['R5']           alone
    R5: control missing                -> fired=['R5']           alone
    R14: producer no edge/root_reason  -> fired=['R14']          alone
    R14: registry shrank below pin     -> fired=['R14']          alone
    R17: nothing binds the run date    -> fired=['R17']          alone
    R22: requires_verdict false, no reason -> fired=['R22']      alone
    R22: with a reason recorded         -> silent                 (the nocase twin also holds)

The one co-firing case (R2/R17) is NOT vacuous: `must_contain="R2"` is tested with `in` against
the whole message, and R17's message begins "R17 a.one: ..." so the substring "R2" does not
occur in it. Checked explicitly:
    starts R2 : True   R2 a.one: state=observed but no probe.command. ...
    starts R17: False  R17 a.one: state=observed but probe.last_run is absent. ...
So the R2 case passes only because R2 fired. I could not construct a mutation that makes any of
these 8 green for an unrelated reason.

VERDICT: the selftest's case assertions are sound. The bare-prefix style is fragile-by-convention
rather than broken today, and the comment already names the hazard. Recording it as a latent risk,
not a finding.

---
# CROSS-CUTTING: repo state claims, independently verified
    HEAD 173f147  2026-10-02 12:32:49 +0900  "net.pcap.selfparse: ..."
    commits on 2026-10-02 : 47      <-- CLAIM CONFIRMED
    total commits          : 94
    unpushed vs origin/HEAD : 0     <-- CLAIM CONFIRMED
    tracked modifications    : none  (git diff --stat HEAD is empty)  <-- "tree clean" CONFIRMED
    untracked                : .agent/audit/, .agent/reports/observed-verify-2026-10-02.md,
                               .agent/verify/
So "47 commits today, 0 unpushed, tree clean" is accurate. The only imprecision is that three
untracked paths exist; no TRACKED file is modified. (My own .agent/audit/ is one of them.)

    $ python scripts/registry-verify.py
    capabilities: 26
    REGISTRY CLEAN: every capability declares what it proves, what it does not prove, a probe,
    and a negative control that must fail.    EXIT=0
The real registry is CLEAN under all 22 rules. That is a TRUE green — I re-derived it by running
the validator, and the fixture baseline is provably uncontaminated (0 problems).

---
# SUMMARY — what each tool can fail to detect

| tool | cheapest slip-past | actually run? | severity |
|---|---|---|---|
| assert-probes.py | a probe+control pair that runs no real tool but emits the recorded strings | YES, 0 verdicts, exit 0 | HIGH (certifies a wrong command forever) |
| assert-probes.py | PowerShell non-terminating error -> `exit $LASTEXITCODE` leaks 0 | YES, rc=0 | MEDIUM (latent, no live cap affected) |
| assert-probes.py | a fully-passing capability prints nothing; "N checked, ." reads clean | YES | LOW (presentation) |
| reachability-report.py | `"ok": true` with `"facts": []` counts as WORKED | YES, "worked (2x)" | HIGH (measures ≠ its stated claim) |
| reachability-report.py | glob is exactly 1 level deep; extra nesting -> silent empty table, exit 0 | YES, 0 files found | HIGH |
| reachability-report.py | `[]` or dict-valued `chain` -> AttributeError, whole report dies | YES, exit 1 | MEDIUM (error, not zero, but suppresses everything) |
| reachability-report.py | `{}` or `{"chain":null}` -> counted as read, contributes nothing, no warning | YES, exit 0 | MEDIUM |
| doc-facts.py | `**1234 capabilities**` / `capabilities: 1234` — `\d{1,3}` can't span 4 digits | YES, 0 matched | MEDIUM |
| doc-facts.py | plain prose / parenthesised / quoted counts ("There are 99 capabilities") | YES, 0 matched | MEDIUM |
| doc-facts.py | live stale claims DO exist in the scanned wiki and are not caught | YES | MEDIUM (message overstates coverage) |
| registry-verify.py | R21 is lexical: prose + "see probe.py" passes; nonexistent .py passes | YES, ACCEPTED | HIGH (the rule's stated purpose defeated) |
| registry-verify.py | R2/R21 do no filesystem check though R10 already implements one | YES | MEDIUM |
| registry-verify.py | selftest fixture is structurally clean but names 3 nonexistent files | YES | MEDIUM |

## The single pattern across all four
Every one of these is the same defect the session already named twice and then re-authored:
**a check that is satisfied by a shape rather than by the thing being checked.** R21 accepts a
string ending in `.py`. doc-facts accepts two punctuations and calls the result "every live
numeric claim". reachability counts `ok` and calls it "produced a fact". assert-probes verifies
a paste is reproducible and its docstring implies it verifies the tool. The repo has an explicit
rule about this — R21's own docstring, "a control nobody can execute cannot fail, so it passes
forever" — and the same sentence is true of each of these gates.

## THE SINGLE NEXT FIX
Add existence resolution to R2 and R21 using the code R10 already contains (it resolves the path
and reports where it looked). That one change catches the selftest's three phantom files, closes
the "any nonexistent tool passes forever" hole, and costs ~6 lines. Everything else on this list
is either a presentation fix or a scope decision the Owner should make.

## What I could NOT establish
- Whether the 13 prose controls moved to `control_plan` are all declared with `kind='plan'` +
  `plan_reason`; R21 passing on the real registry implies they are, but I did not enumerate them.
- Whether `E:/missions` artifacts will stay exactly one level deep. Today's 40 files are, which
  is why the numbers are right; nothing enforces it.
- Whether any live `ok:true` chain entry has empty `facts` today. On the real missions every
  ok:true entry carried facts, so today's numbers are correct; the predicate is still wrong.
- No lab loop, smoke-all.ps1, or fuzz run was executed, per brief. assert-probes full sweep was
  NOT run (~15 min); I used --list, two targeted ids, and direct instrumentation of run()/
  tool_fault()/check() instead. Every finding above was reproduced against the real code.

STATUS: DONE
