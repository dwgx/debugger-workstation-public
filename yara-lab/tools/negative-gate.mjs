#!/usr/bin/env node
/* negative-gate.mjs — native.yara.undefined_value NEGATIVE CONTROL. Added 2026-10-05.
 *
 * WHAT THIS CONTROLS, and why it is not the same shape as every other control in the station.
 *
 * crypto-lab's control asks the verifier to REFUSE two tokens. forensics-lab's asks the
 * correlator to refuse two coincidences. Both are "a well-formed thing must be turned down".
 *
 * This one cannot be built that way, and the reason is worth stating plainly: yara-x does
 * not get asked to refuse anything. It is handed rules and a file and reports which ones were
 * satisfied. A rule that does not match produces `"matches": []` and exit 0 — byte-for-byte
 * the same output as a rule that found nothing because the pattern is genuinely absent, and
 * the same output as a rule that was never capable of matching because its condition
 * references a value the engine never defined.
 *
 *      "found nothing"        and        "was never going to match"
 *
 * are indistinguishable from the outside. That is the whole hazard. A probe built on a
 * non-matching YARA rule reports "clean" for a rule that is syntactically perfect and
 * semantically incapable — and "clean" is exactly what a triage report wants to say.
 *
 * So the control cannot assert a refusal. It has to DEMONSTRATE a three-valued logic, and it
 * does that with a paired-rule construction whose two members are forced apart:
 *
 *      R_UNDEFINED      pe.entry_point > 0        on a NON-PE target
 *      R_NOT_UNDEFINED  not pe.entry_point > 0    on the SAME non-PE target
 *
 * MEASURED on yara-x 1.20.0, both are reported UNSATISFIED. If `pe.entry_point` were merely
 * `false` on a non-PE, then `not false` would be `true` and R_NOT_UNDEFINED would MATCH. It
 * does not. The value is a THIRD thing, and `not` does not collapse it to `true`.
 *
 * The contrast case is what makes the demonstration falsifiable rather than a claim. The same
 * file also gets:
 *
 *      R_ABSENT         $never            where $never is a string the file does not contain
 *      R_NOT_ABSENT     not $never
 *
 * and here R_NOT_ABSENT *DOES* match. So negation works exactly where the value was defined
 * and collapses nowhere near where it was undefined. One engine, one scan, two conditions, and
 * the results differ in precisely the way that distinguishes "found nothing" from "never
 * capable" — observed, not inferred from documentation.
 *
 * WHY --negate IS LOAD-BEARING. Without it, "a rule is absent from `matches`" has two causes:
 * the rule was evaluated and was not satisfied, or the rule was never evaluated at all.
 * `yr scan --negate` inverts the report to list the NON-SATISFIED rules. Running the same
 * ruleset both ways yields two sets that must PARTITION the rule list: every rule appears in
 * exactly one of them. If a rule appeared in neither, the engine had skipped it and this
 * control would be reading silence as a semantic result. If a rule appeared in both, the
 * accounting is broken. The balance is asserted, not assumed.
 *
 * EXIT POLARITY, same convention as crypto-lab/tools/negative-gate.mjs and for the same
 * reason: a control that must exit 0 proves nothing, because an instrument that had stopped
 * evaluating anything at all would also exit 0 and the harness would read that as a pass.
 *
 *      exit 1 = the semantics HELD. Undefined stayed undefined, negation collapsed the defined
 *               false, and the two sets partitioned cleanly. THE CONTROL WORKING. This is the
 *               non-zero code the registry declares (expect_exit: 1).
 *      exit 0 = the semantics did NOT hold, or the accounting did not balance. The control has
 *               found a real defect. Exiting 0 is the value the harness flags as DRIFT.
 *      exit 5 = the control's own premise failed (compile error, witness rule did not match,
 *               unbalanced partition). A control that cannot measure must say so rather than
 *               bank a result.
 *      exit 2 = a stray argument, or a run that could not be measured. Shared with the probe's
 *               refusal code and distinct from 0/1/5 above, so a harness can tell "you asked
 *               me something I refuse" from "I checked and it passed" from "I checked and it
 *               failed".
 *
 * THE TARGET IS GENERATED, not committed. A committed non-PE fixture is a file that can be
 * edited into a PE without the rule source changing, and then R_UNDEFINED starts matching for
 * reasons nobody intended. It is written into this run's temp directory and deleted in
 * `finally`.
 *
 * MUTATION HOOKS. `YARA_LAB_MUTATE` and `YARA_LAB_DISABLE_GUARD` exist so the control can be
 * mutation-tested in both directions without editing this file between runs — see the
 * mutation report. They are environment variables, not arguments, so the no-arguments contract
 * below is untouched. Both default to off, and with both off the control runs its real check.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATION = path.resolve(HERE, '..', '..');

const YR_REL = 'Static-Reversing\\YARA-X\\yr.exe';
const YR_ABS = path.join(STATION, 'Static-Reversing', 'YARA-X', 'yr.exe');

/* The string the generated target is guaranteed to contain, so R_WITNESS_MATCHES has something
 * real to find. Without it a scan of a file the engine could not read at all would produce the
 * same `"matches": []` as a correct one, and the control would be unfalsifiable. */
const WITNESS_STRING = 'yara-lab control witness 4f2b9c';

/* The string that is guaranteed ABSENT, used for the defined-false contrast. Fixed here rather
 * than derived from a hash so that a reader can grep the target and confirm its absence
 * independently of anything this file believes. */
const ABSENT_STRING = 'ZZQQXX-NOT-IN-TARGET-9F3A71C4';

/* ══ MUTATION SELECTION. Off by default; read once, at module scope, before anything is
 * created — so a mutated run leaves exactly as little behind as a clean one. */
const MUTATE = process.env.YARA_LAB_MUTATE || '';
const GUARD_DISABLED = process.env.YARA_LAB_DISABLE_GUARD === '1';
const KNOWN_MUTATIONS = new Set(['defined-false', 'none']);

/* An unrecognised mutation name is REFUSED, not ignored. A mutation harness that silently
 * runs the unmutated code on a typo would report "the mutation did not flip the case" as a
 * finding about the instrument, when it is really a finding about the harness. Same reasoning
 * as the argument guard two lines down, applied to the environment. Exits 2 — this is a
 * measurement request that cannot be honoured, not a control verdict. */
if (MUTATE && !KNOWN_MUTATIONS.has(MUTATE)) {
  console.error(`negative-gate: refusing an unknown YARA_LAB_MUTATE value: ${JSON.stringify(MUTATE)}`);
  console.error(`  known mutations: ${JSON.stringify([...KNOWN_MUTATIONS].sort())}`);
  console.error('  An unrecognised mutation name would run the UNMUTATED code and report');
  console.error('  "the mutation flipped nothing" as a fact about the instrument. It is a fact');
  console.error('  about the harness. Exiting 2.');
  process.exit(2);
}

/* ══ ARGUMENT REFUSAL — exit 2. Same house pattern as the probe: a control handed a flag it
 * does not understand and that silently ignores it can report a green it did not measure.
 * Nothing below reads argv. Refusing before any temp dir exists is what makes "nothing left
 * behind" countable. */
const stray = process.argv.slice(2);
if (stray.length) {
  console.error(`negative-gate: refusing an argument it would otherwise IGNORE: ${stray.join(' ')}`);
  console.error('  This control generates its own rules AND its own non-PE target. It has no --target.');
  console.error('  Accepting an argument silently would report a green it did not measure.');
  console.error('  Exiting 2 — distinct from 1 (the control working) and 0 (the control failing).');
  process.exit(2);
}

const line = (s = '') => console.log(s);

/* THE RULESET. Four rules in two pairs, plus a witness.
 *
 * `import "pe"` is mandatory — measured: every `pe.*` reference without it is E009 "unknown
 * identifier `pe`", with the compiler naming the missing import. That matters here because a
 * missing import produces a COMPILE ERROR (exit 1, empty stdout), which is a third state
 * entirely, and a control that reported it as "the rule did not match" would be making the
 * exact error it exists to catch. */
function ruleSource() {
  /* The undefined-value term. Under mutation `defined-false` this becomes a term that is
   * DEFINITIVELY false on this target — `uint16(0) == 0x5A4D` on a text file whose first two
   * bytes are not "MZ". Everything else in the file is left alone, so the mutation isolates
   * exactly one variable: is the value undefined, or is it false? */
  const undefinedTerm =
    MUTATE === 'defined-false' ? 'uint16(0) == 0x5A4D' : 'pe.entry_point > 0';

  return `import "pe"

/* Generated by yara-lab/tools/negative-gate.mjs at run time.
   ${MUTATE ? `MUTATION ACTIVE: ${MUTATE} — the undefined term was replaced with a DEFINED-FALSE term.` : 'No mutation active.'} */

rule R_WITNESS_MATCHES
{
  strings:
    $w = "${WITNESS_STRING}"
  condition:
    $w
}

/* THE PAIR UNDER TEST. */
rule R_UNDEFINED
{
  condition:
    ${undefinedTerm}
}

rule R_NOT_UNDEFINED
{
  condition:
    not (${undefinedTerm})
}

/* THE CONTRAST PAIR. A string the target does not contain evaluates to DEFINED false — the
 * ordinary two-valued case — and negation of it flips. If these two behaved like the pair
 * above, the pair above would prove nothing. */
rule R_ABSENT
{
  strings:
    $never = "${ABSENT_STRING}"
  condition:
    $never
}

rule R_NOT_ABSENT
{
  strings:
    $never = "${ABSENT_STRING}"
  condition:
    not $never
}
`;
}

/* The generated non-PE target. Plain text, no MZ header, contains the witness string, and does
 * NOT contain ABSENT_STRING. `pe.*` is undefined for every field here because the file is not
 * a PE image — that is the definition of the condition this control depends on. */
function targetSource() {
  return `${WITNESS_STRING}\nThis file is deliberately not a PE image.\npe.entry_point is undefined for it.\n`;
}

function runYr(rulesAbs, targetAbs, negate) {
  const neg = negate ? '--negate ' : '';
  const cmdline = `${YR_REL} scan ${neg}--output-format=json ${rulesAbs} ${targetAbs}`;
  const r = spawnSync('cmd.exe', ['/d', '/c', cmdline], {
    cwd: STATION,
    encoding: 'utf8',
    windowsVerbatimArguments: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    cmdline,
    negate,
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    spawnError: r.error ? r.error.message : null,
  };
}

let scratch = null;

/* Declared here, NOT inside the try. `exitCode` is assigned in the `catch` below, and a
 * declaration inside the `try` block is not in scope there — measured: the control ran to
 * completion, printed a correct NEGATIVE-CONTROL OK, and then died in `catch` with
 * "ReferenceError: exitCode is not defined". Node exits 1 on an uncaught throw, which is
 * THIS control's success code, so a crash would have been reported by a harness as a PASS.
 * A green that a crash can also produce is not a green. */
let exitCode = 2;

try {
  if (!existsSync(YR_ABS)) {
    throw Object.assign(new Error(`instrument not found: ${YR_ABS}. Must be invoked through cmd.exe /c; Git bash reports this same binary as "command not found".`), { unmeasurable: true });
  }

  scratch = mkdtempSync(path.join(os.tmpdir(), 'yara-lab-gate-'));
  const rulesAbs = path.join(scratch, 'undef.yar');
  const targetAbs = path.join(scratch, 'not-a-pe.txt');
  writeFileSync(rulesAbs, ruleSource(), 'utf8');
  writeFileSync(targetAbs, targetSource(), 'utf8');

  const SATISFIED = ['R_WITNESS_MATCHES', 'R_NOT_ABSENT'];
  const UNSATISFIED = ['R_UNDEFINED', 'R_NOT_UNDEFINED', 'R_ABSENT'];

  line('');
  line('native.yara.undefined_value — NEGATIVE CONTROL: prove the engine has THREE values, not two');
  line('='.repeat(96));
  line(`  instrument  ${YR_REL}  (yara-x-cli, invoked through cmd.exe /c)`);
  line(`  target      generated non-PE file in ${scratch}  (not committed: a fixture that gains a PE`);
  line(`              header would make R_UNDEFINED match for reasons nobody intended)`);
  line(`  witness     ${WITNESS_STRING}   (present in the target)`);
  line(`  absent      ${ABSENT_STRING}   (absent from the target)`);
  line(`  mutation    ${MUTATE ? MUTATE : '(none)'}`);
  line(`  guard       ${GUARD_DISABLED ? 'DISABLED by YARA_LAB_DISABLE_GUARD=1' : 'LIVE'}`);
  line('');
  line('  The hazard being controlled:');
  line('    "the rule found nothing" and "the rule was never capable of matching" both print');
  line('    {"matches": []} and exit 0. From the outside they are the same output. A triage');
  line('    report built on a non-matching rule would say "clean" either way.');
  line('');
  line('  The demonstration, and it is a comparison between two pairs in ONE engine:');
  line('    R_UNDEFINED / R_NOT_UNDEFINED   pe.entry_point > 0   on a NON-PE  -> UNDEFINED');
  line('    R_ABSENT    / R_NOT_ABSENT      $never                            -> DEFINED false');
  line('  If undefined were merely false, `not R_UNDEFINED_term` would MATCH. MEASURED: it does');
  line('  not, while `not R_ABSENT_term` does. One engine, one scan, two conditions, and the');
  line('  results differ in exactly the way that separates the two cases.');
  line('');

  /* ══ STATE 3 of 3: the ruleset did not compile. Exit 1 with EMPTY stdout and diagnostics on
   * stderr — the same exit code as a clean scan carries nothing, but empty stdout does. A
   * missing `import "pe"` or a typo'd field lands here, and reporting it as "no rules
   * matched" is the exact confusion this control exists to prevent, so it is a premise
   * failure, not a result. */
  const fwd = runYr(rulesAbs, targetAbs, false);

  if (fwd.spawnError) {
    throw Object.assign(new Error(`could not spawn yr.exe: ${fwd.spawnError}`), { unmeasurable: true });
  }

  let parsedFwd;
  try {
    parsedFwd = JSON.parse(fwd.stdout);
  } catch {
    line('  CONTROL PREMISE FAILED — the ruleset did not compile, so nothing below measured anything.');
    line(`    status   ${fwd.status}   stdout ${fwd.stdout.trim().length} bytes (a clean scan would print JSON here)`);
    line('    yr diagnostics on stderr:');
    for (const l of fwd.stderr.trim().split(/\r?\n/)) line(`      ${l}`);
    line('');
    line('  Note what this state looks like from the outside: non-zero exit and no output. A');
    line('  control that read it as "the rule found nothing" would report a pass for a ruleset');
    line('  that never ran. Exiting 5 — the control is broken, not the instrument.');
    /* Sentinels, not process.exit() — see the note at the single exit point below. */
    throw Object.assign(new Error('premise-failed'), { __exit: 5, alreadyReported: true });
  }

  const fwdMatched = parsedFwd.matches.map((m) => m.rule);
  const fwdSet = new Set(fwdMatched);

  /* --negate inverts the report to list NON-SATISFIED rules. Same ruleset, same target. */
  const neg = runYr(rulesAbs, targetAbs, true);
  let parsedNeg;
  try {
    parsedNeg = JSON.parse(neg.stdout);
  } catch {
    line('  CONTROL PREMISE FAILED — the --negate pass produced no parseable JSON.');
    line(`    status   ${neg.status}   stderr: ${neg.stderr.trim().slice(0, 500)}`);
    line('  Exiting 5.');
    throw Object.assign(new Error('premise-failed-negate'), { __exit: 5, alreadyReported: true });
  }
  const negMatched = parsedNeg.matches.map((m) => m.rule);
  const negSet = new Set(negMatched);

  const ALL = [...SATISFIED, ...UNSATISFIED];

  line('  PASS 1 — yr scan --output-format=json  (reports SATISFIED rules)');
  line(`    status ${fwd.status}   stdout ${fwd.stdout.trim().length} bytes   exit code carries no verdict: 0 on a match and on a clean scan alike`);
  line(`    payload top-level keys  ${JSON.stringify(Object.keys(parsedFwd))}`);
  line(`    SATISFIED   ${JSON.stringify(fwdMatched)}`);
  line('');
  line('  PASS 2 — yr scan --negate --output-format=json  (reports NON-SATISFIED rules)');
  line('    Without this, "absent from matches" has two causes: unsatisfied, or never evaluated.');
  line('    This pass is what makes "never evaluated" visible, so it cannot be read as silence.');
  line(`    status ${neg.status}   NON-SATISFIED   ${JSON.stringify(negMatched)}`);
  line('');

  const inBoth = ALL.filter((r) => fwdSet.has(r) && negSet.has(r));
  const inNeither = ALL.filter((r) => !fwdSet.has(r) && !negSet.has(r));

  /* ── The witness. Proves the engine actually read the generated file. Without it, a scan of
   * a file the engine could not open would yield the same empty result as a correct one. */
  const witnessOk = fwdSet.has('R_WITNESS_MATCHES');
  line(`  ${witnessOk ? 'ok  ' : 'FAIL'} witness R_WITNESS_MATCHES is satisfied`);
  line('       the engine really read the generated target, so an empty result below is a');
  line('       semantic outcome and not a failure to open the file');

  /* ── THE DISCRIMINATOR. The whole control. */
  const undefFails = !fwdSet.has('R_UNDEFINED');
  const notUndefFails = !fwdSet.has('R_NOT_UNDEFINED');
  const absentFails = !fwdSet.has('R_ABSENT');
  const notAbsentMatches = fwdSet.has('R_NOT_ABSENT');

  const semanticsHeld = undefFails && notUndefFails && absentFails && notAbsentMatches;

  line('');
  /* The term is interpolated, not hardcoded: under the `defined-false` mutation this text
   * must name the term that actually ran, or the report describes a ruleset nobody scanned. */
  const TERM = MUTATE === 'defined-false' ? 'uint16(0) == 0x5A4D  [MUTATED]' : 'pe.entry_point > 0';
  line(`  ${undefFails ? 'ok  ' : 'FAIL'} R_UNDEFINED       ${TERM}    ${undefFails ? 'unsatisfied' : 'MATCHED'}`);
  line(`       ${MUTATE === 'defined-false' ? 'MUTATED: this term is DEFINITIVELY false on a text file, not undefined.' : 'the module field is undefined on a non-PE target'}`);
  line(`  ${notUndefFails ? 'ok  ' : 'FAIL'} R_NOT_UNDEFINED   not (${TERM})   ${notUndefFails ? 'ALSO unsatisfied' : 'MATCHED — negation flipped it'}  <-- THE POINT`);
  line(`       negation ${notUndefFails ? 'did NOT' : 'DID'} flip it to true. ${notUndefFails ? 'This is only possible if the value is a third' : 'The value behaved as plain false, so the third'}`);
  line(`       ${notUndefFails ? 'thing, not false. If it were false, this rule would have matched.' : 'value this control claims does not exist on this engine.'}`);
  line(`  ${absentFails ? 'ok  ' : 'FAIL'} R_ABSENT          $never               ${absentFails ? 'unsatisfied' : 'MATCHED'}  (defined false)`);
  line('       the ordinary two-valued case: the string simply is not in the target');
  line(`  ${notAbsentMatches ? 'ok  ' : 'FAIL'} R_NOT_ABSENT      not $never              ${notAbsentMatches ? 'SATISFIED' : 'unsatisfied — negation did NOT flip'}  <-- THE CONTRAST`);
  line(`       negation ${notAbsentMatches ? 'DID' : 'did NOT'} flip here. Same engine, same scan, defined value. This is what makes`);
  line('       the pair above falsifiable rather than a claim: the engine negates fine.');
  line('');

  /* ── The partition. Proves no rule was silently skipped. */
  const balanced = inBoth.length === 0 && inNeither.length === 0;
  line(`  ${balanced ? 'ok  ' : 'FAIL'} the two passes PARTITION the ruleset`);
  line(`       in both passes (accounting broken): ${JSON.stringify(inBoth)}`);
  line(`       in neither pass (silently skipped, would read as a semantic result): ${JSON.stringify(inNeither)}`);
  line('       every rule was evaluated by the engine exactly once and reported one way or the');
  line('       other. A rule in neither list would mean the engine skipped it.');
  line('');

  /* ── The mutation-aware assertion. With YARA_LAB_DISABLE_GUARD=1 the semantic check is not
   * performed at all, so the control must report SUCCESS on a semantics-broken engine. That is
   * the "guard disabled -> control green" direction: it is what proves exit 1 is not reachable
   * by accident, and it is why the guard is worth having. */
  const guardActive = !GUARD_DISABLED;
  const verdictHeld = GUARD_DISABLED ? true : semanticsHeld;

  /* ── Accounting: a control that could not measure must not bank a result. */
  const premiseOk = witnessOk && balanced;
  let headline;

  if (!premiseOk) {
    headline = 'CONTROL BROKEN';
    exitCode = 5;
    line('CONTROL BROKEN — the premise did not hold, so no semantic claim below was measured.');
    if (!witnessOk) line('  The witness rule did not match: the engine may not have read the generated target at all.');
    if (!balanced) line('  The two passes do not partition the ruleset: a rule was skipped or double-counted.');
    line('  Exiting 5. Saying so is the only honest answer — a control that cannot measure must');
    line('  not report that it did.');
  } else if (verdictHeld) {
    headline = 'NEGATIVE-CONTROL OK';
    exitCode = 1;
    line('NEGATIVE-CONTROL OK — UNDEFINED IS A THIRD VALUE, demonstrated not asserted:');
    line('  undefined term   pe.entry_point > 0        unsatisfied');
    line('  its negation      not pe.entry_point > 0    unsatisfied   <- would MATCH if this were false');
    line('  absent string     $never                     unsatisfied');
    line('  its negation      not $never                SATISFIED     <- negation works fine here');
    line('');
    line('  The engine has three values, not two, and `not` does not collapse the third into');
    line('  true. That is what separates "the rule found nothing" from "the rule was never');
    line('  capable of matching" — which is the distinction a triage report cannot make for');
    line('  itself, since both print {"matches": []} and exit 0.');
    line('  Both passes partitioned the ruleset, so no rule was skipped and read as a result.');
    if (GUARD_DISABLED) {
      line('');
      line('  (MUTATED: the semantic guard was DISABLED, so the checks above were not performed.');
      line('   Exit 1 was reached WITHOUT the guard — see the mutation report. That is why the');
      line('   guard has to be there, and why this green is only meaningful with the guard live.)');
    }
    line('  Exiting 1, the non-zero code the registry declares: a control that must exit 0');
    line('  proves nothing, because an engine that stopped evaluating would also exit 0.');
  } else {
    headline = 'CONTROL FAILED';
    exitCode = 0;
    line('CONTROL FAILED — the engine does NOT have three-valued semantics, or the semantics');
    line('  changed under it. Reported, not repaired.');
    /* Printed as the OBSERVED state, not a re-negation of it. The first version wrote
     * `unsatisfied = ${!notUndefFails}`, which prints `unsatisfied = false` on the one case
     * where the rule MATCHED — i.e. it described the opposite of what happened, inside the
     * block whose entire job is to describe what happened. */
    line(`    R_UNDEFINED       matched?      ${fwdSet.has('R_UNDEFINED')}   (expected false)`);
    line(`    R_NOT_UNDEFINED   matched?      ${fwdSet.has('R_NOT_UNDEFINED')}   (expected false — this is the discriminator)`);
    line(`    R_ABSENT          matched?      ${fwdSet.has('R_ABSENT')}   (expected false)`);
    line(`    R_NOT_ABSENT      matched?      ${fwdSet.has('R_NOT_ABSENT')}   (expected true)`);
    if (!notUndefFails) {
      line('    R_NOT_UNDEFINED MATCHED, so `not <undefined>` evaluated true: the undefined value');
      line('    behaved as plain false. Any triage conclusion drawn from a non-matching rule in');
      line('    this build is unfounded, because "unsatisfied" no longer means "never capable".');
    }
    line('  Exiting 0 — the value R5 flags as DRIFT: an instrument that stopped enforcing would');
    line('  also exit 0, so 0 cannot be the control\'s success code.');
  }

  line('');
  line(`  ${headline}`);
  line('');
  /* No process.exit() inside this try/finally: it terminates immediately without unwinding,
   * so the cleanup below would be skipped. MEASURED — the first version of this control
   * called process.exit() on every path and left a `yara-lab-gate-*` directory holding its
   * generated ruleset and its generated target behind on every single run. */
  throw Object.assign(new Error('measured'), { __exit: exitCode, alreadyReported: true });
} catch (e) {
  if (e && typeof e.__exit === 'number' && e.alreadyReported) {
    exitCode = e.__exit;
  } else {
    line(`negative-gate: ${(e && (e.stack || e.message)) || String(e)}`);
    if (e && e.unmeasurable) line('  Unmeasurable run — exiting 2 rather than reporting a verdict.');
    exitCode = 2;
  }
} finally {
  if (scratch) {
    try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

/* The single exit point, outside every cleanup block. */
process.exit(exitCode);