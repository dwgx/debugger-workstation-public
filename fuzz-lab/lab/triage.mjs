/* triage.mjs — take a finding and make it small enough that a human can see why.
 *
 * A 140-byte pcap that throws a RangeError is a bug report. A 140-byte pcap where the
 * global header is intact, one record header declares `incl_len = 0x00000220` at offset
 * 32, and the file ends at offset 36 is a bug report somebody can fix on a Tuesday.
 *
 * Minimisation is delta debugging: try to remove a chunk, keep the removal if the failure
 * still reproduces, halve the chunk size, repeat. It is not clever and it does not
 * produce a minimal case in the strict sense -- it produces a case small enough that
 * reading it explains the bug, which is the only property actually needed.
 *
 * The predicate is "the target still throws uncaught", checked by re-running the real
 * subprocess with the real ceilings. Minimising against a cheaper predicate (say, an
 * in-process call with a longer timeout) would risk minimising to something that only
 * misbehaves under the in-process conditions, and then the reduced case would not
 * reproduce. That is a real failure mode, not a hypothetical one: the ReDoS findings
 * reproduce at 4 s and not at 40 s.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runOne, HARD_MS } from './driver.mjs';
import { replayRecipe } from './mutate.mjs';
import { sha256, flatCorpus, workDir } from './corpus.mjs';
import { TARGET_BY_ID, OUTCOME } from './targets.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LAB_ROOT = path.resolve(HERE, '..');

/** A finding is only worth minimising if it reproduces from its recipe. This is that check. */
export async function reproduces(recipe, { variant = 'reference', target, input, hardMs = HARD_MS } = {}) {
  if (input) return runOne({ target, variant, input, hardMs });
  const seed = await findSeed(recipe.seedSha256);
  if (!seed) return { outcome: 'harness-error', detail: `seed ${recipe.seedSha256.slice(0, 12)} not in the corpus` };
  const bytes = replayRecipe(seed.bytes, recipe, { kind: recipe.kind || 'binary' });
  return runOne({ target, variant, input: bytes, hardMs });
}

async function findSeed(seedSha) {
  const all = await flatCorpus();
  return all.find((s) => s.sha256 === seedSha) || null;
}

/* ------------------------------------------------------------- the minimiser */

/**
 * Delta-debugging minimisation.
 *
 * @param {Buffer} input        the reproducing input
 * @param {(buf:Buffer)=>Promise<object>} predicate  returns the runOne result
 * @param {{keepGoing?:number, verbose?:boolean}} opts
 * @returns {{bytes:Buffer, steps:number, from:number, to:number, predicateMs:number}}
 */
export async function minimise(input, predicate, { keepGoing = 220, verbose = false } = {}) {
  let current = Buffer.from(input);
  let steps = 0;
  let calls = 0;
  const startedAll = Date.now();

  const stillFails = async (candidate) => {
    if (calls >= keepGoing) return false;
    calls++;
    const r = await predicate(candidate);
    return isFailure(r);
  };

  /* Phase 1 -- coarse chunk removal. */
  let chunk = Math.max(1, Math.floor(current.length / 2));
  while (chunk >= 1) {
    let progressed = false;
    for (let off = 0; off + chunk <= current.length && calls < keepGoing; off += chunk) {
      const candidate = Buffer.concat([current.subarray(0, off), current.subarray(off + chunk)]);
      if (candidate.length === 0) continue;
      if (await stillFails(candidate)) {
        current = candidate;
        progressed = true;
        steps++;
        if (verbose) console.log(`  chunk=${chunk} removed bytes [${off},${off + chunk}) -> ${current.length}B`);
        break;
      }
    }
    if (!progressed) chunk = Math.floor(chunk / 2);
  }

  /* Phase 2 -- byte-wise minimisation of what is left. A file can be irreducible at the
     chunk level (every byte is load-bearing for reaching the bug) and still have bytes
     that are not; single-byte removal finds those. */
  for (let i = 0; i < current.length && calls < keepGoing; i++) {
    const candidate = Buffer.concat([current.subarray(0, i), current.subarray(i + 1)]);
    if (candidate.length === 0) continue;
    if (await stillFails(candidate)) {
      current = candidate;
      steps++;
      i--;
      if (verbose) console.log(`  byte  removed offset ${i} -> ${current.length}B`);
    }
  }

  return {
    bytes: current,
    steps,
    calls,
    from: input.length,
    to: current.length,
    ms: Date.now() - startedAll,
  };
}

export function isFailure(r) {
  return r && (r.outcome === OUTCOME.UNCAUGHT || r.outcome === OUTCOME.HANG || r.outcome === OUTCOME.MEMORY);
}

/* -------------------------------------------------------------- the crash store */

/**
 * Write a reduced case to the gitignored `crashes/` directory and record its recipe.
 *
 * The BYTES go to disk and the RECIPE goes to `index.json`. The recipe -- run id, target,
 * variant, seed hash, strategy chain, reduced length, reduced hash -- is what a reader
 * needs, and it is a text file, so it is safe to quote in a note. The bytes are hostile
 * input against parsers this repository ships, so they stay out of git; `replay.mjs`
 * re-derives them and proves the hash matches.
 */
export async function recordCrash(finding, reducedBytes, { runId, note = '' } = {}) {
  const dir = path.join(LAB_ROOT, 'crashes');
  fs.mkdirSync(dir, { recursive: true });
  const reducedHash = sha256(reducedBytes);
  const file = path.join(dir, `${finding.target}-${finding.variant}-${reducedHash.slice(0, 12)}.bin`);
  fs.writeFileSync(file, reducedBytes);

  const indexPath = path.join(dir, 'index.json');
  let index = { schema: 'fuzz-lab/crashes@1', note: 'reproducers are gitignored; rebuild with tools/replay.mjs', crashes: [] };
  if (fs.existsSync(indexPath)) {
    try { index = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch { /* rebuild below */ }
  }
  const entry = {
    id: `${finding.target}-${finding.variant}-${reducedHash.slice(0, 12)}`,
    target: finding.target,
    targetTitle: TARGET_BY_ID[finding.target]?.title,
    variant: finding.variant,
    outcome: finding.outcome,
    detail: finding.detail,
    runId,
    fromRun: { index: finding.index, inputLength: finding.inputLength, inputSha256: finding.inputSha256, wallMs: finding.wallMs },
    reduced: { length: reducedBytes.length, sha256: reducedHash, file: path.basename(file) },
    recipe: finding.recipe,
    minimised: { steps: finding.minimiseSteps, predicateCalls: finding.minimiseCalls, ms: finding.minimiseMs },
    note,
    reproduce: [
      `node fuzz-lab/tools/replay.mjs ${finding.target} ${finding.variant} ${reducedHash.slice(0, 12)}`,
    ],
  };
  index.crashes = index.crashes.filter((c) => c.id !== entry.id);
  index.crashes.push(entry);
  fs.writeFileSync(indexPath, JSON.stringify(index, null, 2) + '\n');
  return entry;
}

/* ------------------------------------------------------------- the whole flow */

/**
 * Reproduce a finding, minimise it, store it. Returns the crash record, or null when
 * the finding does not reproduce (which is itself a reportable outcome: a finding that
 * does not reproduce is not a finding).
 */
export async function triageFinding(finding, { runId, note = '', hardMs = HARD_MS, verbose = false, keepGoing = 220 }) {
  const seed = await findSeed(finding.recipe.seedSha256);
  if (!seed) {
    return { ok: false, reason: `seed ${finding.recipe.seedSha256.slice(0, 12)} is not in the corpus` };
  }
  const bytes = replayRecipe(seed.bytes, finding.recipe, { kind: finding.recipe.kind || 'binary' });
  if (sha256(bytes) !== finding.inputSha256) {
    return {
      ok: false,
      reason: `recipe did not re-derive the input: expected ${finding.inputSha256.slice(0, 12)}, got ${sha256(bytes).slice(0, 12)}`,
    };
  }

  const again = await runOne({ target: finding.target, variant: finding.variant, input: bytes, hardMs });
  if (!isFailure(again)) {
    return { ok: false, reason: `did not reproduce: the re-run classified as ${again.outcome}`, rerun: again };
  }

  const t0 = Date.now();
  const reduced = await minimise(bytes, (candidate) =>
    runOne({ target: finding.target, variant: finding.variant, input: candidate, hardMs }), { keepGoing, verbose });
  /* A HANG is a threshold measurement, and a case sitting near the ceiling is
     intrinsically flaky: the predicate call during minimisation may land at 4.01 s and
     the final verification at 3.98 s, with no change to the input. That is not a
     minimisation bug and not a parser change -- it is what "hangs at about the ceiling"
     means.

     So the reduced case is verified, and if it does not hold, the ORIGINAL input is
     verified instead. Recording the un-reduced case with an honest note is strictly
     better than recording a smaller case that does not reproduce, and far better than
     storing a case that cannot be replayed. An `uncaught` is deterministic and never
     takes this path. */
  let kept = reduced.bytes;
  let verify = await runOne({ target: finding.target, variant: finding.variant, input: kept, hardMs });
  let marginal = false;
  if (!isFailure(verify)) {
    const original = await runOne({ target: finding.target, variant: finding.variant, input: bytes, hardMs });
    if (!isFailure(original)) {
      return { ok: false, reason: `not reproducible: the reduced case classified as ${verify.outcome} and the original as ${original.outcome}` };
    }
    kept = bytes;
    verify = original;
    marginal = true;
  }

  const record = await recordCrash(
    { ...finding, minimiseSteps: reduced.steps, minimiseCalls: reduced.calls, minimiseMs: Date.now() - t0, marginalHang: marginal },
    kept,
    {
      runId,
      note: note || (marginal
        ? `${finding.outcome} in the ${finding.variant} ${finding.target} parser, MARGINAL at the ${hardMs}ms ceiling: `
          + `delta-debugging reduced it to ${reduced.to} bytes but the reduced case no longer exceeds the ceiling, so the `
          + `un-reduced ${kept.length}-byte case is recorded instead. ${finding.detail}`
        : describe(finding, reduced, verify)),
    },
  );
  return { ok: true, record, marginal, reduced: { from: reduced.from, to: marginal ? kept.length : reduced.to, steps: reduced.steps, calls: reduced.calls }, verify };
}

function describe(finding, reduced, verify) {
  return `${finding.outcome} in the ${finding.variant} ${finding.target} parser: ${finding.detail}. `
    + `Reduced from ${reduced.from} to ${reduced.to} bytes in ${reduced.steps} steps; `
    + `the reduced case reproduces as ${verify.outcome}.`;
}

/** The scratch dir the forensic target writes its temp files into. Kept here so a reader
 *  can find it, and so nothing in the lab writes inside the repository. */
export function scratchDir() {
  return path.join(workDir(), 'scratch');
}
