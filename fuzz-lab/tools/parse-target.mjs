#!/usr/bin/env node
/* parse-target.mjs -- ONE parser target in, its differential findings out, as typed JSON.
 *
 * WHY THIS EXISTS. `fuzz.differential.parse` produces `fuzz.finding.outcome` and the
 * `fuzz.repro.bytes` artifact, but the only entry point was loop.mjs, a regression suite over
 * ALL FOUR targets whose machine-readable record goes to fuzz-lab/out/last-run.json rather
 * than to stdout -- so there was no stdout field for a fact_map to bind, and no argv that
 * selected one target. Both halves of that were measured, and both are fixed here:
 *
 *   * `--target` selects exactly one target from TARGET_BY_ID, the same table loop.mjs drives.
 *   * STDOUT IS ONE JSON OBJECT, so a fact_map has something to bind.
 *
 * It re-uses fuzzTarget / flatCorpus / triageFinding unchanged. It does NOT re-implement
 * mutation, the per-input process ceiling, or the outcome classification: those are the lab,
 * and a second copy of them would be a second place for "uncaught vs rejected" to drift.
 *
 * The BUDGET FLOOR is loop.mjs's, for loop.mjs's reason: below 60 the web-triage twin's hang
 * is unreachable and a red verdict would be an artefact of the budget rather than a finding.
 * Refusing up front is cheaper than a misleading number.
 *
 *   node fuzz-lab/tools/parse-target.mjs --target pcap
 *   node fuzz-lab/tools/parse-target.mjs --target jose --budget 60 --no-triage
 *
 * Exit: 0 campaign ran and every input was accounted for, 1 refused, 2 could not run,
 *       9 the campaign's own accounting failed (a silently skipped input).
 */
import { TARGETS, TARGET_BY_ID } from '../lab/targets.mjs';
import { flatCorpus, sha256 } from '../lab/corpus.mjs';
import { fuzzTarget, HARD_MS } from '../lab/driver.mjs';
import { triageFinding } from '../lab/triage.mjs';

const MIN_BUDGET = 60;

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const VALUE_FLAGS = new Set(['--target', '--budget', '--run-id', '--triage-max', '--hard-ms']);
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (VALUE_FLAGS.has(a)) { i += 1; continue; }
  if (a === '--no-triage' || a === '--keep-going') continue;
  emit({ ok: false, exit: 2, error: `unrecognised argument: ${a}`,
         note: 'An argument this wrapper ignores would report a campaign nobody ran.' }, 2);
}

const targetId = get('--target', null);
if (!targetId) {
  emit({ ok: false, exit: 2, error: 'usage: parse-target.mjs --target <id> [--budget N]',
         known_targets: TARGETS.map((t) => t.id) }, 2);
}
const def = TARGET_BY_ID[targetId];
if (!def) {
  emit({ ok: false, exit: 1, error: `unknown target: ${targetId}`,
         known_targets: TARGETS.map((t) => t.id) }, 1);
}

const budget = Number(get('--budget', MIN_BUDGET));
if (!Number.isFinite(budget) || budget < MIN_BUDGET) {
  emit({ ok: false, exit: 1, error: `--budget ${budget} is below the measured floor of ${MIN_BUDGET}`,
         note: 'Below 60 the web-triage twin\'s hang is unreachable, so a red verdict would be an ' +
               'artefact of the budget rather than a finding. The floor is loop.mjs\'s, not a new one.' }, 1);
}
const hardMs = Number(get('--hard-ms', HARD_MS));
const runId = get('--run-id', `parse-target-${targetId}-${Date.now().toString(36)}`);
const triageMax = has('--no-triage') ? 0 : Number(get('--triage-max', 3));

let flat;
try {
  flat = await flatCorpus();
} catch (e) {
  emit({ ok: false, exit: 2, error: `corpus build failed: ${e && e.message ? e.message : e}` }, 2);
}
const seeds = flat.filter(def.seedFilter);
if (seeds.length === 0) {
  emit({ ok: false, exit: 2, error: `no seed matched this target's filter (${targetId})` }, 2);
}

let r;
try {
  r = await fuzzTarget(def.id, seeds, { runId, budget, steps: 1, hardMs });
} catch (e) {
  emit({ ok: false, exit: 2, error: `campaign failed: ${e && e.message ? e.message : e}` }, 2);
}

/* The campaign's own accounting. `executed === budget * 2` is the assertion that makes a
 * clean run mean something: a harness that drops an input reports zero findings and looks
 * perfect, which is the failure mode this lab was built around. */
const refTotal = Object.values(r.reference).reduce((a, b) => a + b, 0);
const flawTotal = Object.values(r.flawed).reduce((a, b) => a + b, 0);
const accounted = r.executed === budget * 2 && refTotal === budget && flawTotal === budget;

const findings = r.findings.map((f) => ({
  variant: f.variant,
  class: f.outcome,
  index: f.index,
  input_sha256: f.inputSha256,
  input_length: f.inputLength,
  recipe_sha: sha256(Buffer.from(JSON.stringify(f.recipe))),
  detail: f.detail,
  recipe: f.recipe,
}));

/* The typed fact: one finding, chosen deterministically -- the first against the REFERENCE
 * parser (a defect in code this repository ships), else the first of any kind. A campaign
 * with NO finding still returns the fact SHAPE, with class 'none' and found:false, so a
 * caller binding `fuzz.finding.outcome` never has to handle a null it did not plan for. */
const firstRef = findings.find((f) => f.variant === 'reference');
const fact = firstRef || findings[0] || {
  target: def.id, variant: null, class: 'none', index: null,
  input_sha256: null, input_length: 0, recipe_sha: null,
  detail: `no finding at budget ${budget} against either variant; this is a statement about ` +
          'this budget and this seed set, not about the parser\'s robustness',
};

const repro = [];
if (triageMax > 0 && r.findings.length) {
  /* Triage is the expensive part (process spawns per predicate call), so it is bounded and
   * representative exactly as loop.mjs bounds it. This is also what WRITES the
   * `fuzz.repro.bytes` artifact -- crashes/<target>-<variant>-<hash>.bin -- so the invoke
   * leaves the file the registry says it leaves.
   *
   * TRIAGE TAKES THE RAW FINDING, NOT THE VIEW ABOVE. triageFinding reads inputSha256 /
   * inputLength / recipe in camelCase; handing it the snake_case object built for the caller
   * threw `Cannot read properties of undefined (reading 'slice')` on the very first run of
   * this wrapper. The two shapes are kept separate on purpose rather than renamed to match. */
  const rawFirstRef = r.findings.find((f) => f.variant === 'reference');
  const ordered = [rawFirstRef, ...r.findings.filter((f) => f !== rawFirstRef)]
    .filter(Boolean).slice(0, triageMax);
  for (const f of ordered) {
    const t = await triageFinding(f, {
      runId, hardMs, keepGoing: f.variant === 'reference' ? 200 : 70,
    });
    repro.push(t.ok
      ? { id: t.record.id, file: t.record.reduced.file, sha256: t.record.reduced.sha256,
          length: t.record.reduced.length, reproduce: t.record.reproduce[0] }
      : { ok: false, reason: t.reason });
  }
}

emit({
  ok: accounted,
  exit: accounted ? 0 : 9,
  target: def.id,
  title: def.title,
  run_id: runId,
  budget,
  hard_ms: hardMs,
  seeds: seeds.length,
  executed: r.executed,
  reference: r.reference,
  flawed: r.flawed,
  finding: fact,
  found: findings.length > 0,
  findings,
  repro,
  caveat: 'DIFFERENTIAL, NOT EXHAUSTIVE. The inputs are mutations of seeds this repository ' +
          'generates, so "no finding" means this budget and this seed set did not reach a ' +
          'defect -- not that the parser is robust. `reference` findings are defects in code ' +
          'this tree ships; `flawed` findings are the negative control firing and are expected.',
}, accounted ? 0 : 9);

function emit(obj, code) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
  process.exit(code);
}
