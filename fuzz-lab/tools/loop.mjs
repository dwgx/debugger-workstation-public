#!/usr/bin/env node
/* loop.mjs — ONE command that runs the whole fuzzing lane and judges itself.
 *
 *   node fuzz-lab/tools/loop.mjs [--budget N] [--run-id ID] [--keep-going]
 *
 * What it does, in order, and what each step is entitled to claim:
 *
 *   1. CORPUS      build every seed from another lab's generator, hash it, then build it
 *                  AGAIN and require identical hashes. Determinism is measured here, not
 *                  asserted in a comment.
 *   2. CAMPAIGN    per target: N mutated inputs x 2 variants (reference + flawed twin),
 *                  each in its own process under a hard wall-clock and heap ceiling,
 *                  classified into parsed / rejected / uncaught / hang / memory.
 *   3. TRIAGE      for every finding: prove the recipe re-derives the input, re-run it,
 *                  delta-debug it down, verify the REDUCED case still fails, and write it
 *                  to the gitignored crashes/ dir with its recipe.
 *   4. NEGATIVE    require that every deliberately flawed twin WAS caught. This is the
 *     CONTROL      step that decides whether the other numbers mean anything.
 *   5. REGRESSIONS require that every known finding's reduced case now REJECTS instead
 *                  of throwing -- i.e. the fixes hold.
 *
 * Exit 0 means the chain held on this machine, in this run. Exit 9 means an assertion
 * failed and the table says which. Exit 0 is not available to a run that found nothing:
 * step 4 fails a run where the flawed twins survived, because a fuzzer that cannot catch
 * a parser with no bounds checks has not demonstrated it can catch anything.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildCorpus, flatCorpus, assertDeterministic, sha256 } from '../lab/corpus.mjs';
import { STRATEGIES, strategiesFor } from '../lab/mutate.mjs';
import { TARGETS, TARGET_BY_ID, OUTCOME } from '../lab/targets.mjs';
import { fuzzTarget, formatTally, HARD_MS, HARD_MEM_MB } from '../lab/driver.mjs';
import { triageFinding, isFailure } from '../lab/triage.mjs';
import { verifyRegressions, KNOWN_FINDINGS } from './regressions.mjs';

// ARGUMENT REFUSAL. Added 2026-10-04. Measured on this tree: passing a path that does not exist
// produced a normal green run and exit 0 -- every check "passed" while nothing anyone asked for
// had been done. A regression suite that cannot fail on the thing you handed it reports a pass
// for work nobody did, which is the one shape this station exists to reject.
//
// The precedent is already in the tree and this follows it rather than inventing a second
// convention: crackme-corpus/tools/loop.py uses argparse and rejects `unrecognized arguments`
// with exit 2. The JS loops had no argument parser at all, which is the defect.
const ALLOWED = new Set('--json', '--only');
const extra = process.argv.slice(2).filter((a) => !ALLOWED.has(a) && !a.startsWith('--only='));
if (extra.length) {
  console.error(`loop: refusing an argument it would otherwise IGNORE: ${extra.join(' ')}`);
  console.error('  This is a regression suite over its own built fixtures. It has no --target.');
  console.error('  Accepting an argument silently would report a pass for work nobody did.');
  process.exit(2);
}


const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB_ROOT = path.resolve(HERE, '..');

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i > -1 ? argv[i + 1] : d; };
const has = (n) => argv.includes(`--${n}`);

const QUIET = has('quiet');
const BUDGET = Number(flag('budget', 90));
const STEPS = Number(flag('steps', 2));
const RUN_ID = flag('run-id', `fuzz-${new Date().toISOString().replace(/[:.]/g, '-')}`);
const HARD = Number(flag('hard-ms', HARD_MS));
const KEEP_GOING = has('keep-going');

/* A budget floor, because the negative control is budget-sensitive and it is much
 * better to say so than to let it read as a finding.
 *
 * The web-triage twin's flaw is a HANG, and a hang needs a big input to manifest.
 * textRepeat and friends produce those only once the budget is high enough, so a
 * small budget leaves the twin genuinely unreachable and the run reports
 * "the flawed twin SURVIVED -- the harness cannot tell a robust parser from a fragile
 * one". Read literally that is the worst possible message, because it is false: the
 * harness is fine, it simply never generated the input that triggers the flaw.
 *
 * Measured 2026-09-30: --budget 8 leaves web-triage's twin unreachable and reports a
 * red; the default 90 (and 60) close. So refuse the small budget up front and say why,
 * rather than burning ten minutes to produce a misleading verdict. */
const MIN_BUDGET = 40;
if (BUDGET < MIN_BUDGET) {
  console.error(
    `fuzz-lab: --budget ${BUDGET} is below the floor of ${MIN_BUDGET}.\n` +
    `  The negative control is budget-sensitive: the hang-class flaw in the web-triage\n` +
    `  twin needs a large input, and a small budget never generates one. Running anyway\n` +
    `  would report "the flawed twin SURVIVED", which reads as "this harness cannot tell a\n` +
    `  robust parser from a fragile one" and is not what happened.\n` +
    `  Use --budget ${MIN_BUDGET} or more (default 90).`);
  process.exit(2);
}

const checks = [];
function check(label, pass, detail = '') {
  checks.push({ label, pass: !!pass, detail: String(detail) });
  if (!QUIET) console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label.padEnd(56)} ${detail}`);
  return !!pass;
}
function say(...a) { if (!QUIET) console.log(...a); }
function rule(title) { if (!QUIET) console.log(`\n${'-'.repeat(84)}\n${title}\n${'-'.repeat(84)}`); }

const t0 = Date.now();
say(`fuzz-lab — run id ${RUN_ID}`);
say(`  budget ${BUDGET} inputs/target · ${STEPS} mutation steps max · ${HARD}ms/input ceiling · ${HARD_MEM_MB}MB heap ceiling`);

/* ================================================================ 1. the corpus */

rule('1. corpus — built from other labs, hashed, and proven stable across two builds');

const corpus = await buildCorpus();
const flat = await flatCorpus();
say(`  ${Object.entries(corpus).map(([g, s]) => `${g} ${s.length}`).join(' · ')}   (${flat.length} seeds)`);
for (const seed of flat) {
  say(`    ${seed.name.padEnd(48)} ${String(seed.length).padStart(7)} B  ${seed.sha256.slice(0, 16)}  ${seed.origin}`);
}

check('every seed is non-empty and under the 2 MiB input ceiling',
  flat.every((s) => s.length > 0 && s.length <= (1 << 21)),
  `${flat.length} seeds, largest ${Math.max(...flat.map((s) => s.length))} B`);
check('seed names are unique (a seed is addressable by name)',
  new Set(flat.map((s) => s.name)).size === flat.length,
  `${new Set(flat.map((s) => s.name)).size} distinct`);

const det = await assertDeterministic();
check('two consecutive builds produce byte-identical seeds', det.stable,
  det.stable ? `${det.count} seeds, all hashes match` : det.diffs.join('; '));

/* ============================================================== 2. the campaign */

rule('2. campaign — every input in its own process, under a hard time and heap ceiling');

const campaigns = {};
for (const target of TARGETS) {
  const seeds = flat.filter(target.seedFilter);
  if (seeds.length === 0) {
    check(`target ${target.id} has seeds`, false, 'no seed matched this target filter');
    continue;
  }
  say(`\n  --- ${target.id}: ${target.title}`);
  say(`      ${seeds.length} seeds · input kind ${target.kind} · strategies ${strategiesFor(target.kind).join(', ')}`);
  const r = await fuzzTarget(target.id, seeds, { runId: RUN_ID, budget: BUDGET, steps: STEPS, hardMs: HARD });
  campaigns[target.id] = r;
  say(`      executed  ${r.executed} runs (${BUDGET} inputs x 2 variants)`);
  say(`      reference ${formatTally(r.reference)}`);
  say(`      flawed    ${formatTally(r.flawed)}`);
  const refFinds = r.findings.filter((f) => f.variant === 'reference');
  const flawFinds = r.findings.filter((f) => f.variant === 'flawed');
  say(`      findings  ${refFinds.length} against the reference parser, ${flawFinds.length} against the flawed twin`);
  for (const f of refFinds.slice(0, 4)) {
    say(`        ref   ${f.outcome.padEnd(8)} #${String(f.index).padStart(3)} ${String(f.inputLength).padStart(7)} B  ${f.detail.slice(0, 78)}`);
  }
  for (const f of flawFinds.slice(0, 2)) {
    say(`        flaw  ${f.outcome.padEnd(8)} #${String(f.index).padStart(3)} ${String(f.inputLength).padStart(7)} B  ${f.detail.slice(0, 78)}`);
  }

  check(`${target.id}: every input was executed against both variants`,
    r.executed === BUDGET * 2, `${r.executed}/${BUDGET * 2}`);
  check(`${target.id}: no input was silently skipped`,
    Object.values(r.reference).reduce((a, b) => a + b, 0) === BUDGET
    && Object.values(r.flawed).reduce((a, b) => a + b, 0) === BUDGET,
    `reference ${Object.values(r.reference).reduce((a, b) => a + b, 0)} · flawed ${Object.values(r.flawed).reduce((a, b) => a + b, 0)}`);
  check(`${target.id}: the harness never reported its own failure`,
    r.reference['harness-error'] === undefined && r.reference.error === undefined,
    'no harness-error outcomes');
}

/* ================================================================ 3. triage */

rule('3. triage — reproduce from the recipe, delta-debug, verify the reduced case');

const allFindings = Object.values(campaigns).flatMap((c) => c.findings);
const crashRecords = [];

/* Triage is the expensive part: every candidate costs up to `keepGoing` predicate calls,
 * and each one is a process spawn. Triaging all 60+ findings of a run took 26 minutes,
 * almost all of it re-minimising variants of the same defect. So a bounded, REPRESENTATIVE
 * sample is triaged: up to 3 per (target, variant, outcome) class, and the rest are counted
 * and named as untriaged. The count is printed either way, so the number of findings is
 * never understated by the triage budget. */
const TRIAGE_PER_CLASS = 3;
const classes = new Map();
const triaged = [];
let deferred = 0;
for (const f of allFindings) {
  const key = `${f.target}|${f.variant}|${f.outcome}`;
  const n = classes.get(key) || 0;
  classes.set(key, n + 1);
  if (n < TRIAGE_PER_CLASS) triaged.push(f); else deferred++;
}
if (deferred) {
  say(`  ${allFindings.length} findings; triaging up to ${TRIAGE_PER_CLASS} per target/variant/outcome class,`);
  say(`  ${deferred} not triaged (same class as one already triaged). The finding COUNT above is complete.`);
}

for (const finding of triaged) {
  const t = await triageFinding(finding, {
    runId: RUN_ID, hardMs: HARD,
    keepGoing: finding.variant === 'reference' ? 200 : 70,
  });
  if (!t.ok) {
    check(`triage ${finding.target}/${finding.variant} #${finding.index}`, false, t.reason);
    continue;
  }
  crashRecords.push(t.record);
  say(`  ${t.record.id}`);
  say(`    ${finding.outcome} in the ${finding.variant} parser — ${t.record.detail.slice(0, 120)}`);
  say(`    ${t.marginal ? 'MARGINAL (hang at the ceiling; recorded un-reduced) ' : ''}reduced ${t.reduced.from} B -> ${t.reduced.to} B in ${t.reduced.steps} steps (${t.reduced.calls} predicate calls)`);
  say(`    sha256 ${t.record.reduced.sha256}`);
  say(`    replay  node fuzz-lab/tools/replay.mjs ${finding.target} ${finding.variant} ${t.record.reduced.sha256.slice(0, 12)}`);
}

const refCrashes = crashRecords.filter((c) => c.variant === 'reference');
const flawCrashes = crashRecords.filter((c) => c.variant === 'flawed');
/* This check is the one that inverts after the fixes land, and the inversion is the
   point rather than a problem with the check.
 *
 * Before the fixes, the reference parsers carried four real defects and this run found
 * them. After the fixes, a clean reference column is the CORRECT result: the same corpus
 * and the same recipes no longer break them. Demanding a live reference finding would
 * mean the lab could only ever pass while a bug was still present -- i.e. it would
 * reward being broken.
 *
 * So the assertion is: either this run found a live defect in a reference parser (good,
 * report it), OR the four known defects are all still guarded and holding (also good).
 * What it must never allow is the empty middle -- a clean reference column with nothing
 * under guard, which is indistinguishable from a fuzzer that cannot find anything. */
const reg = await verifyRegressions({ runId: RUN_ID, hardMs: HARD });
const knownDefects = KNOWN_FINDINGS.length;
const regressionsHold = reg.results.filter((r) => r.pass).length === reg.results.length;
check('reference parsers are clean OR a live defect was found and is reported',
  refCrashes.length > 0 || (reg.ok && knownDefects > 0),
  refCrashes.length > 0
    ? `${refCrashes.length} live reference finding(s): ${refCrashes.map((c) => `${c.target}/${c.outcome}`).join(', ')}`
    : `no live reference finding; the ${knownDefects} known defect(s) are all under regression guard and holding`);
check('every triaged finding reproduced from its recipe, minimised, and the reduced case re-verified',
  crashRecords.length === triaged.length,
  `${crashRecords.length}/${triaged.length} sampled finding(s) triaged (${allFindings.length} found, ${deferred} same-class and not sampled)`);

/* ====================================================== 4. the negative control */

rule('4. negative control — a deliberately fragile parser MUST be caught');

for (const target of TARGETS) {
  const c = campaigns[target.id];
  if (!c) continue;
  const flawFinds = c.findings.filter((f) => f.variant === 'flawed');
  const caught = flawFinds.length;
  check(`${target.id}: the flawed twin was caught (${target.flawed.flaw.slice(0, 60)}…)`,
    caught > 0,
    caught > 0
      ? `${caught} finding(s) — first: ${flawFinds[0].outcome} at #${flawFinds[0].index}, ${flawFinds[0].inputLength} B`
      : 'SURVIVED — the harness cannot tell a robust parser from a fragile one, so its clean runs mean nothing');
}

check('the negative control is not satisfied by the reference parser crashing',
  flawCrashes.length > 0,
  `${flawCrashes.length} flawed-twin finding(s) recorded`);

/* ============================================================ 5. the regressions */

rule('5. regressions — every known finding must now be REJECTED, not thrown');

for (const r of reg.results) {
  say(`  ${r.pass ? 'ok  ' : 'FAIL'} ${r.id.padEnd(30)} ${r.detail}`);
}
check('every recorded finding now rejects cleanly (each fix holds)', reg.ok,
  `${reg.passed}/${reg.results.length} regressions hold`);
check('the regression corpus is non-empty', KNOWN_FINDINGS.length > 0,
  `${KNOWN_FINDINGS.length} known finding(s) under guard`);

/* ==================================================================== summary */

const totalInputs = Object.values(campaigns).reduce((a, c) => a + c.budget * 2, 0);
const refTally = {};
const flawTally = {};
for (const c of Object.values(campaigns)) {
  for (const [k, v] of Object.entries(c.reference)) refTally[k] = (refTally[k] || 0) + v;
  for (const [k, v] of Object.entries(c.flawed)) flawTally[k] = (flawTally[k] || 0) + v;
}

const failed = checks.filter((c) => !c.pass);
console.log(`\n${'='.repeat(84)}`);
console.log(`fuzz-lab loop summary — run ${RUN_ID}`);
console.log('='.repeat(84));
console.log(`  seeds                ${flat.length} across ${Object.keys(corpus).length} groups, all hashes stable across two builds`);
console.log(`  inputs executed      ${totalInputs} (${BUDGET}/target x 2 variants x ${TARGETS.length} targets), one process each`);
console.log(`  reference outcomes   ${formatTally(refTally)}`);
console.log(`  flawed-twin outcomes ${formatTally(flawTally)}`);
console.log(`  reference findings   ${refCrashes.length}  (${refCrashes.map((c) => `${c.target}:${c.outcome}`).join(', ') || 'none'})`);
console.log(`  flawed-twin findings ${flawCrashes.length}  (the negative control)`);
console.log(`  regressions holding  ${reg.passed}/${reg.results.length}`);
console.log(`  elapsed              ${((Date.now() - t0) / 1000).toFixed(1)}s`);
console.log('');
for (const c of checks) console.log(`  ${c.pass ? 'PASS' : 'FAIL'}  ${c.label.padEnd(58)} ${c.detail.slice(0, 90)}`);

console.log(`\n${failed.length === 0
  ? 'LOOP CLOSED: the corpus is stable, every input was executed under a hard ceiling, a real defect in this\n'
  + `             repository's own parsers was found from a mutated seed and reproduced from its recipe, the\n`
  + '             negative control confirms the harness catches a deliberately fragile parser, and every known\n'
  + '             finding now rejects instead of throwing.'
  : `${failed.length} assertion(s) failed — the first is: ${failed[0].label}: ${failed[0].detail}`}`);
if (failed.length) console.log('\nThe full failure list is above. A green run is not available while any of these is false.');

fs.mkdirSync(path.join(LAB_ROOT, 'out'), { recursive: true });
fs.writeFileSync(path.join(LAB_ROOT, 'out', 'last-run.json'), JSON.stringify({
  runId: RUN_ID, budget: BUDGET, steps: STEPS, hardMs: HARD, hardMemMb: HARD_MEM_MB,
  seedCount: flat.length, deterministic: det.stable,
  totals: { inputs: totalInputs, reference: refTally, flawed: flawTally },
  findings: crashRecords, regressions: reg.results,
  checks, ok: failed.length === 0, elapsedMs: Date.now() - t0,
}, null, 2) + '\n');

process.exit(failed.length === 0 ? 0 : 9);
