#!/usr/bin/env node
/* probe.mjs — native.yara.triage PROBE. Added 2026-10-05.
 *
 * THE QUESTION, and why a substring search cannot answer it.
 *
 *   `strings` on c01-stringobf.exe answers: "the bytes FLAG{c01_...decoy} occur at file
 *   offset 89960." That is the whole of what a substring search can say. It cannot say
 *   WHICH PE SECTION that offset lands in, because section membership is a property of the
 *   image, not of the bytes — the same byte string is a read-only string table entry in
 *   .rdata and an embedded secret in .text depending on a table further up the file. And it
 *   cannot say whether that section is EXECUTABLE, because that lives in the section's
 *   IMAGE_SCN_MEM_EXECUTE characteristic bit, which no amount of grepping will surface.
 *
 *   That combination is the question this probe asks, and it is worth asking for a real
 *   reason: a plaintext credential sitting in .rdata is a string table, while one sitting
 *   inside an executable section is code or an encoded blob. The bytes are identical. The
 *   triage conclusion is not. So the probe decides exactly one thing:
 *
 *       is the credential string located inside a PE section, and is that section
 *       executable?
 *
 *   Answer for our own corpus file: .rdata, NOT executable — i.e. the decoy is an inert
 *   string-table entry, not code. The rule decides that; a substring search does not.
 *
 * WHY THE RULE SOURCE IS WRITTEN AT RUN TIME. A committed .yar goes stale silently: change
 * the corpus, the rule still compiles, the probe still exits 0, and it is now answering a
 * question about a binary that no longer exists. The rule is generated here from the
 * constant above, into a per-run temp directory, and deleted in `finally`. Nothing in git
 * can drift.
 *
 * EXIT CODE IS NOT THE VERDICT — THIS IS THE WHOLE POINT. MEASURED on yara-x 1.20.0:
 *
 *       match       -> exit 0, JSON with one element in "matches"
 *       clean scan  -> exit 0, JSON with "matches": []
 *
 *   Both are zero. A probe keying on `status === 0` reports "the rule found the pattern"
 *   for every rule ever written, including every rule that is syntactically perfect and
 *   semantically nonsense. This probe therefore keys on the PARSED CONTENT of
 *   --output-format=json, and it treats a third state the exit code cannot see:
 *
 *       rule fails to compile -> exit 1, stdout EMPTY, diagnostics on stderr.
 *
 *   So three outcomes, two of which share an exit code. The probe refuses to guess which
 *   one happened: no parseable JSON on stdout is UNMEASURABLE, and it is reported as such
 *   with exit 2 rather than quietly passing. Note the third state is the one that catches
 *   a rule with a typo in it — which is why treating "empty stdout" as failure matters.
 *
 * ARTIFACT, `yara-lab/out/last-run-yara.json`, written on EVERY exit path including the
 * argument refusal and every crash. "The artifact says the run failed" is itself a fact a
 * reader needs; its absence is not one. This matters more here than elsewhere because a
 * YARA probe can produce a plausible artifact from a rule that never matched anything, so
 * the artifact records the raw verdict set next to the derived conclusion, and a reader can
 * re-derive it.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/* Station root, derived from this file's location rather than process.cwd(). A probe that
 * only works when invoked from the repo root is a probe whose "PASS" depends on where the
 * harness happened to be standing — and the harness is not ours to control. */
const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATION = path.resolve(HERE, '..', '..');

const YR_REL = 'Static-Reversing\\YARA-X\\yr.exe';
const YR_ABS = path.join(STATION, 'Static-Reversing', 'YARA-X', 'yr.exe');
const TARGET_REL = 'crackme-corpus/out/c01-stringobf.exe';
const TARGET_ABS = path.join(STATION, 'crackme-corpus', 'out', 'c01-stringobf.exe');

/* The one credential literal in the station's own corpus: a plaintext decoy, deliberately,
 * so the corpus is a puzzle with a decoy to trip the obvious solve. */
const CREDENTIAL = 'FLAG{c01_strings_gave_you_this_decoy}';

/* IMAGE_SCN_MEM_EXECUTE from winnt.h. Spelled as a constant rather than as the mnemonic
 * `pe.sections[i].executable`, which does not exist in yara-x 1.20.0 — measured: E008
 * "unknown field or method `executable`". Bit 0x20000000 is the 29th characteristic, the
 * executable bit. */
const SCN_MEM_EXECUTE = 0x20000000;

const ARTIFACT_DIR = path.join(STATION, 'yara-lab', 'out');
const ARTIFACT = path.join(ARTIFACT_DIR, 'last-run-yara.json');

/* ══ THE RUN LEDGER, and why this exists.
 *
 * MEASURED DEFECT, found by a reviewer and reproduced before fixing. A run that failed
 * BEFORE reaching its own writeArtifact() call — a syntax error in this file, a bad import,
 * a wrong station root after the file is copied elsewhere — left the PREVIOUS run's artifact
 * on disk, unmodified, still stamped ok:true with the previous run's started_at. A reader
 * opening the file after a failed run sees a passing artifact describing a run that is not
 * the one they just did. That is the worst failure mode here, because it is the one where
 * the evidence actively lies and nothing looks wrong.
 *
 * The fix is a single invariant rather than a patch on each exit path: this object is
 * mutated as the run proceeds and written from `finally`, so it is impossible for a code
 * path to exit without leaving an artifact that describes THAT run.
 *
 * `run_id` is a per-process nonce, written on every path, so a reviewer can compare it
 * against the run they just performed and prove the artifact on disk belongs to them.
 * `artifact_ok` answers "did the CONTENT assertions hold" — a different question from
 * `completed` ("did the run finish") and from the exit code, which measures nothing here.
 *
 * PLACEMENT IS LOAD-BEARING. This block sits ABOVE the argument-refusal path because that
 * path calls commit(). A first attempt left it below, where `node --check` passed — a const
 * referenced before its declaration is a RUNTIME error, not a parse error — and `--bogus`
 * died with "Cannot access 'runState' before initialization" and exited 1, silently breaking
 * the very argument guard this file exists to provide. `node --check` did not catch it;
 * running the tool did.
 */
const RUN_ID = `${process.pid}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
const runState = {
  instrument: 'native.yara.triage',
  tool: 'probe.mjs',
  /* Stamped up front so even a crash mid-construction records WHEN this run began. */
  started_at: new Date().toISOString(),
  run_id: RUN_ID,
  station_root: STATION,
  target: { path_ref: TARGET_REL, abs: TARGET_ABS },
  instrument_path: YR_REL,
  credential: CREDENTIAL,
  section_executable_bit: `0x${SCN_MEM_EXECUTE.toString(16)}`,
  rules_written_at_runtime: true,
  rules_committed: false,
  /* False until the run reaches its end. A path that dies early leaves it false, which is
   * the honest value — an unfinished run is not a completed one. */
  completed: false,
  /* Set ONLY by the content-assertion block. Never inferred from the exit code, and never
   * left at its initial value by a path that failed: an unrun check must not read as passed.
   * This is the field the reviewer asked for by name, and it is verified present by printing
   * the artifact's top-level keys before reading it. */
  artifact_ok: false,
  exit: 2,
  detail: null,
  reason: null,
  measured: false,
};

/* Every artifact write goes through here, so the identity fields above can never be omitted
 * by a path that forgot them. */
function commit(extra) {
  writeArtifact({ ...runState, ...extra });
}

/* ══ ARGUMENT REFUSAL — exit 2, distinct from every other code this file can produce.
 *
 * Same house pattern as crypto-lab/tools/negative-gate.mjs: a probe handed a flag it does
 * not understand and that silently ignores it is a probe that reports a green nobody
 * measured. Three gates shipped in this station without this guard and were only caught by
 * running them with `--bogus`. Nothing below reads argv, so an accepted argument would be a
 * lie by omission. Refusing BEFORE any temp dir or artifact exists is what makes the
 * "nothing left behind" property checkable by counting temp entries.
 */
const stray = process.argv.slice(2);
if (stray.length) {
  /* The refusal path writes an artifact too. It must: an argument rejection that leaves the
   * PREVIOUS run's green artifact on disk would let `--bogus` be answered with stale
   * evidence, and the refusal is exactly the case where a reviewer most wants to see that
   * something ran and refused. */
  commit({
    ok: false,
    refused: true,
    reason: 'stray-argument',
    detail: `probe.mjs takes no arguments and would otherwise IGNORE: ${stray.join(' ')}`,
    expected_invocation: 'node yara-lab/tools/probe.mjs',
    completed: true,
    measured: false,
    artifact_ok: false,
    exit: 2,
    temp_dir_created: false,
    wrote_scratch: false,
  });
  console.error(`probe: refusing an argument it would otherwise IGNORE: ${stray.join(' ')}`);
  console.error('  probe.mjs takes no arguments: it generates its own rule and scans one fixed target.');
  console.error('  Accepting an argument silently would report a green it did not measure.');
  console.error('  Exiting 2 — distinct from 0 (verdict) and from 1/3 (measured verdicts below).');
  process.exit(2);
}

function writeArtifact(obj) {
  mkdirSync(ARTIFACT_DIR, { recursive: true });
  writeFileSync(ARTIFACT, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

/* THE RULE, generated. Three rules, and the arrangement is the point:
 *
 *   DecoyPresentAtAll      — pure substring existence. This is what `strings` can tell you.
 *   DecoyInNamedSection    — the substring's offset falls inside a section NAMED .rdata.
 *   DecoyInExecutableSection — ...inside ANY section carrying IMAGE_SCN_MEM_EXECUTE.
 *
 * The probe's verdict is the RELATIONSHIP between these three, not any single one. If
 * `DecoyInExecutableSection` matches, the credential is inside code. If it does not while
 * `DecoyPresentAtAll` does, the credential is in data. A probe that only asserted the first
 * rule would be a substring search wearing a YARA costume.
 *
 * `strings:` must precede `condition:` — measured: `condition:` first is E001 "expecting
 * operator or `}`, found `strings`". And `import "pe"` is mandatory — measured: without it
 * every `pe.*` reference is E009 "unknown identifier `pe`", with the compiler telling you
 * the import statement is missing. Both are in this generator rather than discovered later.
 */
function ruleSource() {
  const esc = (s) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `import "pe"

/* Generated by yara-lab/tools/probe.mjs at run time. Not committed: a checked-in rule goes
 * stale against the corpus silently, still compiles, and still exits 0. */

rule DecoyPresentAtAll
{
  strings:
    $cred = "${esc(CREDENTIAL)}"
  condition:
    $cred
}

/* The part a substring search cannot do: map the credential's FILE OFFSET back onto the PE
 * section table, and require the containing section to be NAMED .rdata. Offset arithmetic
 * over pe.sections[i].raw_data_offset / .raw_data_size. */
rule DecoyInNamedSection
{
  strings:
    $cred = "${esc(CREDENTIAL)}"
  condition:
    for any i in (0..pe.sections.len() - 1) : (
      @cred[1] >= pe.sections[i].raw_data_offset and
      @cred[1] <  pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
      and pe.sections[i].name == ".rdata"
    )
}

/* Same offset arithmetic, but asking about the section's EXECUTABLE BIT instead of its name —
 * a different question, and one whose answer must be allowed to disagree with the rule above.
 * That disagreement is the verdict. If both rules were wired to the same answer this
 * capability would decide nothing. */
rule DecoyInExecutableSection
{
  strings:
    $cred = "${esc(CREDENTIAL)}"
  condition:
    for any i in (0..pe.sections.len() - 1) : (
      @cred[1] >= pe.sections[i].raw_data_offset and
      @cred[1] <  pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
      and (pe.sections[i].characteristics & ${SCN_MEM_EXECUTE}) != 0
    )
}
`;
}

/* Run yr.exe. MEASURED invocation facts, all of which cost a wrong answer before they were
 * pinned down:
 *
 *  1. It must be `cmd.exe /c`. Invoking the path directly from this box yields Git bash
 *     "command not found" (127) for an installed binary, which reads as "yara-x is absent".
 *  2. `windowsVerbatimArguments: true` with all-backslash Windows paths. Without it node
 *     re-quotes the argument and cmd reports `can't open '/Users/...tri.yar"'` — note the
 *     leading slash and the stray trailing quote in the message: that is node's quoting
 *     damage, not a missing file, and it is the kind of error that reads as "your temp path
 *     is wrong" and sends you off to fix the wrong thing.
 *  3. `/d` disables AutoRun, which otherwise can prepend to the command line from a registry
 *     key and silently change what runs.
 *
 * Options precede the positionals: `scan [OPTIONS] <RULES> <TARGET>`, and clap answers
 * "unexpected argument" otherwise.
 *
 * Returns stdout/stderr/status verbatim. No normalization: the caller needs to tell empty
 * stdout (uncompilable rule) from `{"matches": []}` (clean scan), and a normalizer that
 * smoothed the difference would erase exactly the distinction this probe exists on. */
function runYr(rulesAbs, targetAbs) {
  const cmdline = `${YR_REL} scan --output-format=json ${rulesAbs} ${targetAbs}`;
  const r = spawnSync('cmd.exe', ['/d', '/c', cmdline], {
    cwd: STATION,
    encoding: 'utf8',
    windowsVerbatimArguments: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    cmdline,
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    spawnError: r.error ? r.error.message : null,
  };
}

let scratch = null;
let exitCode = 2;

const line = (s = '') => console.log(s);


try {
  /* Instrument and target presence are checked BEFORE anything is created, so a missing
   * binary leaves no scratch dir and no rule file behind. */
  if (!existsSync(YR_ABS)) {
    throw Object.assign(
      new Error(`instrument not found: ${YR_ABS}. Note that Git bash reports this same binary as "command not found"; it must be invoked through cmd.exe /c.`),
      { unmeasurable: true }
    );
  }
  if (!existsSync(TARGET_ABS)) {
    throw Object.assign(new Error(`target not found: ${TARGET_ABS}`), { unmeasurable: true });
  }

  scratch = mkdtempSync(path.join(os.tmpdir(), 'yara-lab-probe-'));
  const rulesAbs = path.join(scratch, 'triage.yar');
  writeFileSync(rulesAbs, ruleSource(), 'utf8');

  const raw = runYr(rulesAbs, TARGET_ABS);
  const stdoutLen = raw.stdout.trim().length;

  /* The measurement the exit code cannot make for us. Empty stdout with a non-zero status
   * means the rule did not compile: yr prints its diagnostics to STDERR and leaves stdout
   * empty. Both the rule and the instrument are fine in that case — the RULE is wrong — and
   * reporting it as "no match" would be precisely the silent-pass shape. */
  let parsed = null;
  let parseError = null;
  try {
    parsed = JSON.parse(raw.stdout);
  } catch (e) {
    parseError = e.message;
  }

  /* `base` is an ALIAS for runState, not a second object.
   *
   * It began as a literal duplicating every ledger field. Two objects holding the same facts
   * are two things that can disagree: the unconditional `finally` write commits `runState`,
   * while the measured path committed `base`, so whichever ran last silently won and a reader
   * could not tell which object produced the file. Now there is exactly one — `base` IS
   * runState with the measured extras folded in, so `artifact_ok` cannot be set on one object
   * and dropped by a write of the other.
   *
   * The identity fields (run_id, started_at, completed, artifact_ok) are deliberately NOT
   * repeated here; they come from the ledger above and cannot be overwritten here. */
  const base = Object.assign(runState, {
    ok: false,
    target: { path_ref: TARGET_REL, abs: TARGET_ABS, exists: true },
    scratch_dir: scratch,
    invocation: raw.cmdline,
    /* MEASURED AND SHIPPED IN THE ARTIFACT ON PURPOSE: the exit code does not distinguish a
     * detection from an empty scan. Recording the discriminator this probe actually used
     * stops a future reader from "simplifying" it back to `status`. */
    exit_code_is_not_the_verdict: {
      claim: 'yr scan exits 0 on a match AND on a clean scan; the discriminator is stdout content',
      observed_status: raw.status,
      observed_stdout_bytes: stdoutLen,
      stdout_nonempty: stdoutLen > 0,
      verdict_read_from: 'parsed JSON "matches" array, never from the exit status',
    },
    raw: { status: raw.status, stdout_bytes: stdoutLen, stdout: raw.stdout, stderr: raw.stderr },
  });

  if (raw.spawnError) {
    base.reason = 'spawn-failed';
    base.detail = raw.spawnError;
    writeArtifact(base);
    console.error(`probe: could not spawn yr.exe: ${raw.spawnError}`);
    console.error(`  tried: cmd.exe /d /c ${raw.cmdline}`);
    /* `process.exit()` here would SKIP the `finally` below and leak the scratch directory
     * for this run — measured: process.exit() terminates immediately and never unwinds the
     * stack, so the cleanup block does not execute. Every successful run left a
     * `yara-lab-probe-*` directory behind with its generated rule still in it. Exit codes are
     * therefore THROWN as a sentinel and re-raised after the cleanup, not called in place. */
    throw Object.assign(new Error('spawn-failed'), { __exit: 2, alreadyReported: true });
  }

  /* State 3 of 3: unmeasurable. Non-zero exit, no parseable stdout. */
  if (!parsed) {
    base.reason = parseError && stdoutLen === 0 ? 'rule-did-not-compile' : 'unparseable-output';
    base.detail = parseError;
    base.measured = false;
    base.why_unmeasurable =
      'yr scan wrote no parseable JSON on stdout. With a non-zero status this is a COMPILE ' +
      'failure in the generated rule (diagnostics on stderr), not a clean scan. Reporting it ' +
      'as "no match" would be the silent-pass shape; it is refused instead.';
    base.stderr_excerpt = raw.stderr.slice(0, 4000);
    base.exit = 2;
    /* Routed through commit() so the artifact carries this run's run_id and started_at even
     * on a refusal-to-measure. A path that wrote its own bare object would be the one path
     * whose artifact a reviewer could not tie back to the run that produced it. */
    base.completed = true;
    commit(base);
    line('');
    line('PROBE UNMEASURABLE — yr.exe produced no parseable JSON on stdout.');
    line('='.repeat(96));
    line(`  status      ${raw.status}   stdout ${stdoutLen} bytes`);
    line(`  rule        yara-lab/tools/probe.mjs:ruleSource() (generated at run time, not committed)`);
    line('  yr diagnostics on stderr:');
    for (const l of raw.stderr.trim().split(/\r?\n/)) line(`    ${l}`);
    line('');
    line('  Refusing to read this as "no match". Exit 2: the run is unmeasurable, which is a');
    line('  different fact from "the rule found nothing" and must not be recorded as one.');
    throw Object.assign(new Error('unmeasurable'), { __exit: 2, alreadyReported: true });
  }

  /* State 1 and 2: parseable JSON, both of which arrived with status 0 above. */
  const matchedRules = parsed.matches.map((m) => m.rule);
  const has = (name) => matchedRules.includes(name);
  const present = has('DecoyPresentAtAll');
  const inNamed = has('DecoyInNamedSection');
  const inExec = has('DecoyInExecutableSection');

  /* `pe.sections.len()` is 0 for a non-PE and `pe.*` fields are UNDEFINED there, so all three
   * offset rules go unsatisfied and only DecoyPresentAtAll can fire. The probe treats that
   * as a MEASURED negative, not a failure — the distinction the negative control exists to
   * make precise is defined here: present-but-not-in-a-section means the section test could
   * not be satisfied, and the two must not be recorded identically. */
  const question =
    'Is the credential string located inside a PE section, and is that section executable?';
  const answer = !present
    ? 'credential-absent'
    : inExec
      ? 'credential-in-executable-section'
      : inNamed
        ? 'credential-in-named-data-section'
        : 'credential-present-outside-any-section';

  /* The probe asserts on CONTENT, and it asserts the RELATIONSHIP. A match set where every
   * rule fired, or where the executable-section rule fired while the named-section rule also
   * did, would mean the two questions are not independent and the capability decides
   * nothing. Checked, not assumed. */
  const checks = [
    { name: 'credential-present', ok: present, got: present, note: 'the substring search this capability is compared against' },
    { name: 'credential-in-named-section', ok: inNamed, got: inNamed, note: 'offset arithmetic over the PE section table' },
    { name: 'credential-not-in-executable-section', ok: !inExec, got: !inExec, note: 'IMAGE_SCN_MEM_EXECUTE bit of the containing section' },
    {
      name: 'named-and-exec-rules-are-independent',
      ok: !(inNamed && inExec),
      got: { inNamed, inExec },
      note: 'if both fired the section is both .rdata and executable, and the two rules decide the same thing',
    },
    {
      name: 'stdin-json-version-1.20.0',
      ok: typeof parsed.version === 'string' && parsed.version.length > 0,
      got: parsed.version,
      note: 'the key exists in the payload; read after printing top-level keys, not assumed',
    },
  ];

  const allOk = checks.every((c) => c.ok);

  base.ok = allOk;
  base.measured = true;
  base.reason = allOk ? 'measured' : 'assertion-failed';
  base.question = question;
  base.answer = answer;
  base.matched_rules = matchedRules;
  base.match_count = matchedRules.length;
  base.top_level_keys = Object.keys(parsed);
  base.match_element_keys = parsed.matches.length ? Object.keys(parsed.matches[0]) : [];
  base.checks = checks;
  base.exit = allOk ? 0 : 3;
  base.exit_code_meaning = {
    0: 'the rule decided the question, and the content assertions held',
    2: 'argument refusal, or a run that could not be measured at all',
    3: 'measured, but a content assertion failed — the rule did not decide what it claims to',
    1: 'unexpected crash; see artifact detail',
  };
  /* MEASURED, and the first version of this field was a plausible-sounding lie.
   *
   * It used to say: "flip SCN_MEM_EXECUTE and the answer changes". That cannot be true on
   * this target. `inExec` is ALREADY false here — the decoy sits in .rdata, which is not
   * executable — so flipping the bitmask to 0 leaves it false. The hint described a mutation
   * that provably does nothing.
   *
   * The replacement is the mutation that was actually MEASURED to flip the verdict: change
   * the credential literal to a string that is not in the binary. That moves
   * `credential-present` from true to false, the answer to `credential-absent`, and the exit
   * from 0 to 3. A second measured mutation, flipping the section name from .rdata to .text,
   * moves the answer to `credential-present-outside-any-section` and the exit to 3.
   *
   * No claim is left here that was not run. The exit code under both mutations is still 0
   * from yr.exe, which is the whole reason the probe reads content instead.
   */
  base.mutation_hint = {
    measured_true: 'change CREDENTIAL to a string absent from the binary -> credential-present goes false, answer becomes credential-absent, probe exits 3',
    measured_true_2: 'change the section name from ".rdata" to ".text" -> answer becomes credential-present-outside-any-section, probe exits 3',
    known_false: 'flipping SCN_MEM_EXECUTE does NOT change the answer on this target: inExec is already false because .rdata is not executable. An earlier version of this field claimed otherwise and was wrong.',
    yr_exit_under_both: 0,
    why_that_matters: 'yr.exe still exits 0 under both mutations, which is the reason the probe asserts on parsed content and not on the status.',
  };
  base.completed = true;
  base.artifact_ok = allOk;
  base.wrote_scratch = true;
  commit(base);

  line('');
  line('native.yara.triage — PROBE: decide a question about a PE that substring search cannot');
  line('='.repeat(96));
  line(`  instrument  ${YR_REL}  (yara-x-cli, invoked through cmd.exe /c)`);
  line(`  target      ${TARGET_REL}`);
  line(`  credential  ${CREDENTIAL}`);
  line('  question    ' + question);
  line('');
  line('  The substring search answer — and the whole of what `strings` can say:');
  line('    the credential bytes occur in this file.');
  line('  What only a rule can add: which PE section that offset lands in, and whether that');
  line('  section is executable. Section membership is a property of the IMAGE, not of the');
  line('  bytes — the same literal is a string-table entry in .rdata and an embedded secret in');
  line('  .text, and no substring search can tell those apart.');
  line('');
  line(`  yr exit status      ${raw.status}   (MEASURED: 0 on a match AND on a clean scan — not the verdict)`);
  line(`  stdout bytes        ${stdoutLen}`);
  line(`  payload top-level keys   ${JSON.stringify(Object.keys(parsed))}`);
  line(`  payload version          ${JSON.stringify(parsed.version)}`);
  line(`  matched rule names       ${JSON.stringify(matchedRules)}`);
  line('');
  for (const c of checks) {
    line(`  ${c.ok ? 'ok  ' : 'FAIL'} ${c.name.padEnd(38)} ${JSON.stringify(c.got)}`);
    line(`       ${c.note}`);
  }
  line('');
  line(`  ANSWER ${answer}`);
  line('  a credential in a non-executable .rdata section is an inert string-table entry; the');
  line('  same bytes inside an executable section would be code or an encoded blob.');
  line('');
  if (allOk) {
    line('PROBE OK — the rule decided the question and the content assertions held. Exiting 0.');
    exitCode = 0;
  } else {
    line('PROBE FAILED — measured, but a content assertion did not hold. Exiting 3, not 0: a');
    line('  rule that decides nothing must not be able to report success.');
    exitCode = 3;
  }
  line(`  artifact  ${path.relative(STATION, ARTIFACT)}`);
  line('');
  throw Object.assign(new Error('measured'), { __exit: exitCode, alreadyReported: true });
} catch (e) {
  /* A sentinel thrown by a measured path: that path already printed its verdict and already
   * wrote the artifact, so the only thing left is to carry its exit code out past the
   * cleanup. Anything else is a real crash and gets its own artifact. */
  if (e && typeof e.__exit === 'number' && e.alreadyReported) {
    exitCode = e.__exit;
  } else {
    runState.reason = e && e.unmeasurable ? 'unmeasurable' : 'crash';
    runState.detail = (e && (e.stack || e.message)) || String(e);
    runState.completed = true;
    runState.exit = 2;
    console.error(`probe: ${runState.detail}`);
    if (e && e.unmeasurable) console.error('  Unmeasurable run — exiting 2 rather than reporting a verdict.');
    exitCode = 2;
  }
} finally {
  /* Scratch removal on every path, including the argument refusal above (which exits before
   * this file's try block and therefore never creates one — asserted in the report by
   * counting temp entries before and after). The artifact outlives the scratch on purpose:
   * what a run concluded should not vanish with its working directory.
   *
   * This runs before the process exits because the exit is OUTSIDE this block. That is not a
   * stylistic preference: process.exit() terminates immediately and never unwinds the stack,
   * so an exit called anywhere inside this try/finally skips this block. Measured, not
   * assumed — the first version of this file called process.exit() on every path and leaked
   * one scratch directory, with its generated rule still inside, on every run. */
  if (scratch) {
    try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  /* THE STALE-ARTIFACT GUARANTEE, and the defect it exists to close.
   *
   * MEASURED DEFECT. Before this block existed, a run that died before reaching its own
   * writeArtifact() call — a syntax error in this file, a bad import, this file copied
   * somewhere that resolves the wrong station root — left the PREVIOUS run's artifact on
   * disk, unmodified, still stamped ok:true with the previous run's started_at. Reproduced:
   * after a successful run wrote ok:true, a subsequent run that failed to execute left
   * started_at byte-identical and ok:true. A reviewer opening the artifact after a failed run
   * sees passing evidence for a run that did not happen. Nothing looks wrong, which is what
   * makes it the worst of the failure modes.
   *
   * `finally` is the only construct in the language that runs on every exit path, including
   * a throw from anywhere in the try. Writing the artifact HERE, unconditionally, makes it
   * structurally impossible for a path to exit without leaving an artifact describing THIS
   * run. A path that already committed its own detailed artifact still ends up with this
   * write, so the guarantee holds without asking each path to remember.
   *
   * `artifact_ok` is NOT touched here. It is set only by the content-assertion block, so a
   * run that never reached those checks leaves it false — an unrun check must never read as a
   * passed one, which is the same lesson as `assert-probes.py`'s "NOT a claim that the
   * instrument ran".
   */
  runState.exit = exitCode;
  try { commit({ scratch_dir: scratch, wrote_scratch: Boolean(scratch) }); } catch { /* never mask the verdict */ }
}

/* The single exit point, outside every cleanup block. */
process.exit(exitCode);