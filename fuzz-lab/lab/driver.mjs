/* driver.mjs — the parent process: enforce the ceilings, count the outcomes, keep the run
 * reproducible.
 *
 * The contract with the worker is one line of JSON in, one line of JSON out, and a hard
 * wall-clock deadline on top. The deadline is enforced HERE and only here, because a
 * synchronous hang inside the worker cannot be interrupted from inside the worker. When
 * the deadline fires the parent kills the child and records a HANG -- a first-class
 * finding, recorded with the same weight as a crash, because "this parser takes 40
 * seconds on a 400 KB claim" is exactly the defect an analyst needs to know about before
 * pointing the tool at an evidence seizure.
 *
 * The heap ceiling is passed to the child as --max-old-space-size, so V8 aborts instead
 * of growing. A child that dies on the OOM abort is classified MEMORY; that
 * classification is inferred from the exit signal plus the absence of a result line,
 * which is stated here because it is an inference and not a direct observation.
 *
 * Cost note, because it changes what a run means: one process per input is expensive.
 * 4 targets x N inputs x 2 variants is 2N process spawns per input budget. The driver
 * therefore runs the two variants in one pass over the same mutated input, and the loop
 * uses a per-input budget small enough that the whole proof stays under a couple of
 * minutes. Everything is parallel across a small worker pool.
 */
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { mutate, rngFor } from './mutate.mjs';
import { OUTCOME, TARGET_BY_ID } from './targets.mjs';
import { sha256 } from './corpus.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'worker.mjs');

export const HARD_MS = Number(process.env.FUZZ_INPUT_HARD_MS || 4000);
export const HARD_MEM_MB = Number(process.env.FUZZ_INPUT_HARD_MEM_MB || 192);
const POOL = Math.max(1, Math.min(8, Number(process.env.FUZZ_POOL || os.cpus().length - 1 || 2)));

/* --------------------------------------------------------------- the child call */

/**
 * Run one input in one child process, with the ceilings applied.
 * Never rejects: every failure mode is a classified outcome, because a driver that
 * throws on a crash has lost the crash.
 */
export function runOne({ target, variant, input, hardMs = HARD_MS }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [`--max-old-space-size=${HARD_MEM_MB}`, WORKER], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });

    let out = '';
    let err = '';
    let settled = false;
    const started = Date.now();

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      resolve({
        outcome: OUTCOME.HANG,
        detail: `exceeded the ${hardMs}ms per-input ceiling and was killed`,
        wallMs: Date.now() - started,
      });
    }, hardMs);

    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ outcome: 'harness-error', detail: `spawn failed: ${e.message}` });
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const line = out.split('\n').find((l) => l.trim().startsWith('{'));
      if (line) {
        try {
          resolve({ ...JSON.parse(line), wallMs: Date.now() - started, exit: code });
        } catch (e) {
          resolve({ outcome: 'harness-error', detail: `unparseable worker line: ${line.slice(0, 200)}` });
        }
        return;
      }
      /* No result line. The child died on its own: either the heap abort or a hard
         crash below the harness. Both are distinguishable from a hang by the fact that
         the process EXITED rather than needing to be killed. */
      const oomAborted = /heap out of memory|Allocation failed|Array buffer allocation failed/i.test(err);
      resolve({
        outcome: oomAborted ? OUTCOME.MEMORY : OUTCOME.UNCAUGHT,
        detail: oomAborted
          ? `V8 aborted the allocation at the ${HARD_MEM_MB}MB ceiling`
          : `worker exited with code ${code} signal ${signal} and no result: ${err.trim().split('\n').slice(0, 2).join(' | ').slice(0, 240)}`,
        wallMs: Date.now() - started,
        exit: code,
        signal,
      });
    });

    child.stdin.end(JSON.stringify({ target, variant, input: input.toString('base64') }));
  });
}

/* --------------------------------------------------------------- the campaign */

/**
 * Run one target over a seed set, at both variants, and return everything needed to
 * reproduce any finding.
 *
 * The unit of work is (seed, index): `rngFor(runId, target, index)` derives a stream
 * from the run id alone, so input #N of a run is re-derivable without replaying #0..#N-1.
 * The recipe for each input records the seed hash and the strategy chain, which is a
 * complete description of the bytes.
 */
export async function fuzzTarget(target, seeds, { runId, budget, steps = 1, hardMs = HARD_MS, onProgress = null } = {}) {
  const targetDef = TARGET_BY_ID[target];
  if (!targetDef) throw new Error(`unknown target ${target}`);

  const jobs = [];
  for (let i = 0; i < budget; i++) {
    const seed = seeds[i % seeds.length];
    const rng = rngFor(runId, target, i);
    const { bytes, recipe } = mutate(seed.bytes, rng, {
      maxSteps: steps,
      kind: targetDef.kind,
      alphabet: targetDef.alphabet,
      salt: `${runId}|${target}|${i}`,
    });
    jobs.push({
      index: i,
      seedName: seed.name,
      seedSha256: seed.sha256,
      bytes,
      recipe: { ...recipe, seedSha256: seed.sha256, seedName: seed.name, target, index: i },
      inputSha256: sha256(bytes),
      inputLength: bytes.length,
    });
  }

  const results = { target, title: targetDef.title, runId, budget, reference: tally(), flawed: tally(), findings: [], executed: 0 };

  /* Each job produces two runs (reference + flawed). Interleave them across the pool so
     a slow target does not serialise behind a fast one. */
  const queue = [];
  for (const job of jobs) {
    queue.push({ job, variant: 'reference' });
    queue.push({ job, variant: 'flawed' });
  }

  let cursor = 0;
  const workers = Array.from({ length: Math.min(POOL, queue.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= queue.length) return;
      const { job, variant } = queue[i];
      const r = await runOne({ target, variant, input: job.bytes, hardMs });
      const bucket = results[variant];
      bucket[r.outcome] = (bucket[r.outcome] || 0) + 1;
      results.executed++;
      if (r.outcome === OUTCOME.UNCAUGHT || r.outcome === OUTCOME.HANG || r.outcome === OUTCOME.MEMORY) {
        results.findings.push({
          target, variant, outcome: r.outcome, detail: r.detail,
          wallMs: r.wallMs, ms: r.ms, code: r.code,
          index: job.index, inputSha256: job.inputSha256, inputLength: job.inputLength,
          recipe: job.recipe,
        });
      }
      if (onProgress && results.executed % 50 === 0) onProgress(results);
    }
  });
  await Promise.all(workers);

  results.findings.sort((a, b) => a.index - b.index);
  return results;
}

function tally() {
  return { [OUTCOME.PARSED]: 0, [OUTCOME.REJECTED]: 0, [OUTCOME.UNCAUGHT]: 0, [OUTCOME.HANG]: 0, [OUTCOME.MEMORY]: 0 };
}

/** The outcome breakdown as a single line, for the transcript. */
export function formatTally(t) {
  return `${OUTCOME.PARSED} ${t[OUTCOME.PARSED]} · ${OUTCOME.REJECTED} ${t[OUTCOME.REJECTED]} · `
    + `uncaught ${t[OUTCOME.UNCAUGHT]} · hang ${t[OUTCOME.HANG]} · memory ${t[OUTCOME.MEMORY]}`;
}
