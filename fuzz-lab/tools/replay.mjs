#!/usr/bin/env node
/* replay.mjs — re-derive a crash from its recipe and prove it still crashes.
 *
 *   node fuzz-lab/tools/replay.mjs                      list every recorded crash
 *   node fuzz-lab/tools/replay.mjs <target> <variant> <hash-prefix>
 *
 * The reproducer BYTES are not in git. What is in git is the recipe: the run id, the
 * seed's hash, the ordered mutation chain, and the reduced input's hash. This tool
 * rebuilds the seed from the generators, replays the recipe, and checks that the bytes
 * it produced hash to what the crash record says they should.
 *
 * That is the whole reproducibility argument, and it is worth being precise about: the
 * recipe is a complete description of the input, so the input is reconstructible without
 * being stored. The alternative -- committing the hostile bytes -- would mean shipping
 * the thing that breaks the parsers in this repository, next to the parsers.
 *
 * Exit 0 = the reduced case re-derived, hashed as recorded, and still misbehaved.
 * Exit 5 = the hash did not match, or the case no longer reproduces (i.e. the fix works
 *          and the crash record is now historical).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { flatCorpus, sha256 } from '../lab/corpus.mjs';
import { replayRecipe } from '../lab/mutate.mjs';
import { runOne, HARD_MS } from '../lab/driver.mjs';
import { isFailure } from '../lab/triage.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB_ROOT = path.resolve(HERE, '..');
const INDEX = path.join(LAB_ROOT, 'crashes', 'index.json');

const args = process.argv.slice(2);
const jsonOut = args.includes('--json');

function loadIndex() {
  if (!fs.existsSync(INDEX)) return null;
  return JSON.parse(fs.readFileSync(INDEX, 'utf8'));
}

function list() {
  const index = loadIndex();
  if (!index || !index.crashes.length) {
    console.log('no crashes recorded. Run: node fuzz-lab/tools/loop.mjs');
    return 0;
  }
  console.log(`fuzz-lab crash index — ${index.crashes.length} recorded\n`);
  for (const c of index.crashes) {
    console.log(`  ${c.id}`);
    console.log(`    ${c.outcome.padEnd(8)} ${c.variant} ${c.target}`);
    console.log(`    reduced  ${c.reduced.length} B  sha256 ${c.reduced.sha256}`);
    console.log(`    from     ${c.fromRun.inputLength} B  sha256 ${c.fromRun.inputSha256.slice(0, 16)}  run ${c.runId} #${c.fromRun.index}`);
    console.log(`    detail   ${c.detail}`);
    console.log(`    recipe   ${c.recipe.applied.map((s) => s.strategy).join(' -> ')}`);
    console.log(`    replay   node fuzz-lab/tools/replay.mjs ${c.target} ${c.variant} ${c.reduced.sha256.slice(0, 12)}`);
    console.log('');
  }
  console.log('The bytes are gitignored. Replay rebuilds them from the recipe above.');
  return 0;
}

async function replay(target, variant, hashPrefix) {
  const index = loadIndex();
  if (!index) { console.error('no crash index; run the loop first'); return 2; }
  const hits = index.crashes.filter((c) =>
    c.target === target && (!variant || c.variant === variant) && c.reduced.sha256.startsWith(hashPrefix));
  if (hits.length === 0) {
    console.error(`no crash matches ${target} ${variant || '*'} ${hashPrefix}`);
    return 2;
  }
  if (hits.length > 1) {
    console.error(`${hashPrefix} is ambiguous: ${hits.map((h) => h.id).join(', ')}`);
    return 2;
  }
  const crash = hits[0];

  const seed = (await flatCorpus()).find((s) => s.sha256 === crash.recipe.seedSha256);
  if (!seed) { console.error(`seed ${crash.recipe.seedSha256.slice(0, 12)} is not in the corpus any more`); return 3; }

  /* Two derivations, and they must agree. The recipe replays the full mutation chain;
     the stored file is what triage actually reduced to. The reduced case is the one
     that is minimised, so that is what gets run -- but a hash mismatch on the recipe
     chain means the corpus or the mutator drifted, which is a lab bug worth failing on
     rather than papering over. */
  const fromRecipe = replayRecipe(seed.bytes, crash.recipe, { kind: crash.recipe.kind || 'binary' });
  const recipeHash = sha256(fromRecipe);

  const reducedFile = path.join(LAB_ROOT, 'crashes', crash.reduced.file);
  let reducedBytes = null;
  if (fs.existsSync(reducedFile)) reducedBytes = fs.readFileSync(reducedFile);
  const candidate = reducedBytes || fromRecipe;
  const candidateHash = sha256(candidate);

  const r = await runOne({ target, variant, input: candidate, hardMs: HARD_MS });

  const out = {
    crash: crash.id,
    target, variant,
    reducedSha256: crash.reduced.sha256,
    source: reducedBytes ? 'stored reproducer file' : 're-derived from recipe',
    hashMatches: candidateHash === crash.reduced.sha256,
    recipeChainHash: recipeHash,
    recipeChainMatchesRun: recipeHash === crash.fromRun.inputSha256,
    outcome: r.outcome,
    detail: r.detail,
    wallMs: r.wallMs,
    reproduces: isFailure(r),
  };

  if (jsonOut) { console.log(JSON.stringify(out, null, 2)); }
  else {
    console.log(`crash        ${crash.id}`);
    console.log(`target       ${target} (${variant})`);
    console.log(`reduced      ${crash.reduced.length} B  sha256 ${crash.reduced.sha256}`);
    console.log(`re-derived   ${candidate.length} B  sha256 ${candidateHash}  ${out.hashMatches ? 'MATCH' : 'MISMATCH'}`);
    console.log(`recipe chain ${recipeHash.slice(0, 32)}…  ${out.recipeChainMatchesRun ? 'matches the original run' : 'DIFFERS from the original run'}`);
    console.log(`outcome      ${r.outcome}  ${r.detail}`);
    console.log(`reproduces   ${out.reproduces ? 'YES' : 'no — the fix holds, or the ceiling changed'}`);
  }

  if (!out.hashMatches) { console.error('hash mismatch: the stored or re-derived bytes are not the recorded case'); return 5; }
  if (!out.reproduces) { console.error('the reduced case did not reproduce'); return 5; }
  return 0;
}

if (args.length === 0 || args[0] === 'list' || args[0] === '--help') process.exit(list());
process.exit(await replay(args[0], args[1] || null, args[2] || ''));
