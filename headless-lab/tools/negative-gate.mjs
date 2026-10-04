#!/usr/bin/env node
/* negative-gate.mjs -- native.crosscompare.ghidra NEGATIVE CONTROL. Added 2026-10-05.
 *
 * THE REGISTRY ASSERTION THIS MEASURES, quoted rather than paraphrased, because paraphrasing it
 * is how a control stops testing the thing it was written for
 * (manifests/capabilities.json, negative_control.native.crosscompare.same_binary):
 *
 *     why:          "a binary compared against itself must report zero changes. Anything else
 *                    means the correlator is scoring noise."
 *     control_plan: "run the tracker with the source and destination set to the SAME program"
 *     expect_exit:  1
 *
 * THAT IS THE WHOLE CONTROL. Arm A below is it, and it is the arm that decides the exit code.
 *
 * WHY THE PLAN THAT REPLACED IT WAS WRONG, in one line: it said "no runnable command exists to
 * check". Ghidra is installed twice over and scripts/ghidra-headless.ps1 already drives
 * analyzeHeadless against it -- measured here, not assumed: 399 functions decompiled, exit 0, ~21 s
 * per run. The plan's reason never asked whether the instrument was there.
 *
 * ------------------------------------------------------------------------------------------------
 * THE TRAP, AND WHAT IS DONE ABOUT IT
 * ------------------------------------------------------------------------------------------------
 * A cross-compare disagrees with itself constantly, and disagreement is NOT a finding. Two
 * independent analyses of one binary will differ in function naming, in local-variable spelling, in
 * how a cast is parenthesised, in the order of two independent statements. A gate that reports every
 * difference as a divergence is the noise equivalent of a broken gate: it is always red, so it is
 * never informative. The failure mode this file is built to avoid is that one.
 *
 * So every difference is put into exactly one of four buckets, and the bucket decides whether the
 * run is red:
 *
 *   1. SAME SUBSTANCE. Not a finding. Nothing to report.
 *   2. RENDERING DIFFERS, bytes identical. NOT a finding.
 *      The decompiled C differs but Ghidra's own body content-address (FunctionHashes.java,
 *      SHA-256 over the function body, truncated) is the same on both sides. Two decompilers
 *      rendering one body differently is a decompiler disagreement and NOTHING ELSE. The
 *      byte-level evidence is what separates this bucket from bucket 3, and it is read out of the
 *      binary rather than being either decompiler's opinion.
 *   3. BYTES DIFFER, AND A SOURCE BOTH SIDES NEVER SAW PREDICTS IT. EXPECTED, NOT A FINDING.
 *      native/core.c is compiled twice and never sees its own build flags, so it knows which
 *      functions are build-variant without having been told. This gate reads that knowledge out of
 *      the source rather than hard-coding a function name. A difference in such a function is the
 *      cross-compare working. Calling it a defect would be the noise mistake above.
 *   4. BYTES DIFFER, AND NOTHING EXPLAINS IT. THIS IS A FINDING.
 *      A function whose body changed between two builds, where the source has no build-time
 *      variation in it, means one side is describing something the other does not have. The gate
 *      names the side that produced the unexplained content-address and states which witness failed.
 *
 * A fifth outcome is a MISSED difference: a function the source says must vary, reported identical.
 * That is a correlator scoring nothing -- the same defect wearing the opposite mask -- and it is a
 * finding too.
 *
 * WHY THERE IS A WITNESS AT ALL. Without core.c the gate could only say "the two sides differ",
 * which is bucket 3 and bucket 4 indistinguishable and therefore worthless. The source is the third
 * party neither decompiler consulted; it is what makes "they differ" separable from "one of them is
 * wrong". The mask arithmetic goes further and does not merely predict THAT the seed-bearing body
 * differs but WHY, and WHICH build each side is: core.c computes it as 0x811c9dc5 ^ LAB_MASK, and
 * each side's own decompilation is checked for the constant that arithmetic produces.
 *
 * ------------------------------------------------------------------------------------------------
 * HOW THE INSTRUMENT IS DRIVEN
 * ------------------------------------------------------------------------------------------------
 * Through scripts/ghidra-headless.ps1 and nothing else. No second launch path is invented: this
 * wrapper already solves the analyzeHeadless invocation, the scratch project, the timeout and the
 * teardown, and scripts/ghidra-failopen-regress.ps1 is the suite that proves its fail-open property.
 * Every run here goes through it, so this gate cannot regress what that suite protects.
 *
 * TWO POSTSCRIPTS PER SIDE, and the reason is bucket 2 above. ExportDecompile.java writes the
 * decompiled C -- the decompiler's opinion. FunctionHashes.java writes a content-address per body
 * -- not an opinion, a fact about the bytes. Neither alone can tell rendering from substance.
 *
 * MEASURED, and load-bearing: the wrapper gates on summary.json, which only ExportDecompile.java
 * writes. A FunctionHashes.java run therefore exits 1 through the wrapper WHILE HAVING PRODUCED ITS
 * ARTIFACT CORRECTLY (14571 bytes of hashes). So this gate does not read the wrapper's exit code for
 * a hashes run -- it gates on the artifact it asked for, which is the same rule the wrapper states
 * for itself ("the only honest signal is the artifact the run was supposed to write"). This is not
 * a loosening of the fail-open property: the wrapper still refuses to exit 0 when its named artifact
 * is missing, which is what ghidra-failopen-regress.ps1 asserts and what that suite still confirms.
 *
 * WHY BOTH SIDES ARE THE SAME PROGRAM IN ARM A. Comparing one file to itself on disk would be
 * vacuous -- of course it matches itself. Arm A runs core_v1.dll through analyzeHeadless TWICE, as
 * two separate JVMs with two separate throwaway projects, and compares those two independent
 * analyses. A cross-compare that cannot reproduce itself on identical input is not usable on
 * differing input, which is why this is the arm that decides the exit code and Arm B is not.
 *
 * MEASURED TRAP, and it changed the code. FunctionHashes.java emits one line per function and
 * carries NO address column, so a function name is NOT a unique key. Measured on this box:
 * 399 function lines but only 387 distinct names -- `operator()<>`, `_malloc_base`,
 * `_guard_dispatch_icall`, `_calloc_base`, `uninitialize_environment<>` and `thunk_FUN_180006290`
 * each occur more than once, because they really are several distinct functions sharing a symbol.
 * An earlier draft of this file keyed bodies by name and silently compared 387 of 399 functions,
 * which would have let a real difference hide inside a collapsed duplicate. The comparison is
 * therefore a MULTISET over (name, size, content-address), which is exact whether or not names
 * collide, and the collision count is printed so the reader can see what the key covered.
 *
 * SCOPE LIMIT, MEASURED NOT ASSUMED. The brief for this gate describes "both decompilers" and the
 * box does have two: Static-Reversing/Ghidra/ghidra_12.1.2_PUBLIC and ghidra_12.1.3_PUBLIC. The
 * sanctioned wrapper cannot reach 12.1.2: it builds its path as
 * <InstallRoot>/Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC/support/analyzeHeadless.bat, so the
 * VERSION is baked into the wrapper and -InstallRoot only moves the tree root. Selecting 12.1.2
 * would need a parameter added to scripts/ghidra-headless.ps1, and scripts/ is outside this gate's
 * scope. So both sides here are 12.1.3, and independence comes from separate JVMs and separate
 * projects rather than from separate versions. That is a real limit on what this gate can claim and
 * it is stated here instead of being papered over with a hand-rolled second launcher.
 *
 * ------------------------------------------------------------------------------------------------
 * EXIT POLARITY. expect_exit is 1, and the polarity is the counter-intuitive one: a control that
 * must exit 0 proves nothing, because an instrument that had stopped working would also exit 0.
 *
 *   exit 1  CONTROL WORKING. Arm A reported zero changes on identical input, and every difference
 *           in Arm B was explained by a witness. This is the non-zero code the registry declares.
 *   exit 0  CONTROL FAILED. The instrument reported something it must not, or missed something it
 *           must find. By R5 this is the DRIFT value: indistinguishable from a control that never
 *           worked.
 *   exit 2  COULD NOT MEASURE. A stray argument, a missing prerequisite, or a run that produced no
 *           artifact. Deliberately distinct from 1 and 0, so "I could not check" can never be read
 *           as "I checked and it was fine".
 *   exit 3  THIS CONTROL'S PREMISE FAILED. The gate could not establish its own ground truth from
 *           core.c / build.ps1, or a side's decompilation does not contain the constant the mask
 *           arithmetic predicts. The instrument may be perfect; the control would be measuring
 *           nothing, and saying so is the only honest answer.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB = path.resolve(HERE, '..');
const REPO = path.resolve(LAB, '..');

const WRAPPER = path.join(REPO, 'scripts', 'ghidra-headless.ps1');
const CORE_C = path.join(LAB, 'native', 'core.c');
const BUILD_PS1 = path.join(LAB, 'tools', 'build.ps1');
const GHIDRA = path.join(REPO, 'Static-Reversing', 'Ghidra', 'ghidra_12.1.3_PUBLIC');
const RUN_TIMEOUT_MS = 600000;

const line = (s = '') => console.log(s);
/* Refuse loudly, and UNWIND rather than terminating.
 *
 * MEASURED BUG THIS FIXES. This used to end in `process.exit(code)`, which terminates the process
 * immediately and SKIPS the `finally` block that removes the scratch directory. So every
 * premise-failure exit -- code 2 and code 3, the paths that refuse to report a verdict -- leaked a
 * ~9 MB scratch tree, and the leak was worst exactly where correctness mattered most. Confirmed by
 * measurement rather than inspection: two runs that exited 3 left `xcompare-neg-dXa6ti` and
 * `xcompare-neg-smWmYb` behind, and the runs that exited normally left nothing.
 *
 * A control that refuses must refuse CLEANLY. Throwing unwinds through `finally`, so the refusal
 * path and the success path have identical cleanup and there is no path that skips it. The code
 * is carried on the thrown value rather than being passed to process.exit. */
class Refusal extends Error {
  constructor(code) { super('negative-gate refusal'); this.code = code; }
}
const die = (code, ...msg) => { line(); for (const m of msg) line(m); line(); throw new Refusal(code); };

/* ------------------------------------------------------------------ fault injection, for mutation
 * A control nobody has ever seen fail is decoration, and this one cannot be shown failing without
 * being able to make the instrument misbehave on demand. So it can be told to, and the ability is
 * INERT unless NGATE_FAULT is set in the environment.
 *
 * It is an environment variable and not a flag on purpose. The argument guard above refuses every
 * argument, so a fault cannot be switched on by a caller who would then also be able to pass a
 * target; and NGATE_FAULT unset -- which is every real run, every CI run and every invocation in
 * this file's own acceptance evidence -- takes the identical path through the code. There is no
 * `if (mutant) ... else <the real thing>` fork: the injected fault substitutes real values, so
 * the comparison, the adjudication and the exit-code arithmetic all run unchanged on corrupted
 * input. That is what makes the mutation evidence mean anything.
 *
 *   noise     One body on side A2 is given a content-address it does not have, simulating a
 *             correlator scoring noise on substance. Arm A must report an unexplained body change.
 *   blind     The content-address comparison is forced to always report "identical", simulating a
 *             correlator that scores nothing. Arm B must then report a MISSED DIFFERENCE for the
 *             one function the source says must move.
 *   spurious  One body is dropped from one side's multiset, so the correlator claims a function
 *             appeared or vanished when nothing did. Arm A must report a presence finding -- this
 *             is the registry's own "scoring noise" case in its purest form.
 *   any comma-separated combination, to show the detectors are independent of one another.
 *
 * Every run that uses it says so, loudly, in its own output, so a mutated result can never be
 * mistaken for a real one. */
const FAULTS = new Set((process.env.NGATE_FAULT || '').split(',').map((s) => s.trim()).filter(Boolean));
const faulted = FAULTS.size > 0;

/* ------------------------------------------------------------------ argument guard, FIRST thing
 * A control handed an argument it cannot honour and which it silently ignores reports a pass for
 * work nobody did -- the same defect scripts/assert-no-stray-args.ps1 exists to refuse in
 * PowerShell. This runs before any prerequisite check, any scratch directory and any child
 * process, so a refused invocation cannot leave anything behind by construction. */
if (process.argv.length > 2) {
  line('negative-gate: refusing argument(s) it would otherwise IGNORE: ' + process.argv.slice(2).join(' '));
  line('  This control takes no arguments. A control that silently accepts an argument it cannot');
  line('  honour can be made to report a green it did not measure.');
  line('  Refused BEFORE any prerequisite check, any scratch directory and any Ghidra process.');
  line('  exit 2 -- could not measure, which is deliberately not the control code 1.');
  process.exit(2);
}

/* --------------------------------------------------------------------------- ground truth
 * Read out of the two files that hold it, so the gate is not asserting a function name it decided
 * on by hand. If either stops parsing, the control's premise is gone and it says so (exit 3)
 * rather than quietly checking nothing. */
function readGroundTruth() {
  const c = fs.readFileSync(CORE_C, 'utf8');
  const b = fs.readFileSync(BUILD_PS1, 'utf8');

  const defM = c.match(/#define\s+LAB_MASK\s+(0x[0-9A-Fa-f]+)U?/);
  const baseM = c.match(/0x([0-9A-Fa-f]+)u?\s*\^\s*LAB_MASK/);
  if (!defM || !baseM) return { error: 'core.c no longer exposes LAB_MASK and 0x... ^ LAB_MASK' };
  const base = parseInt(baseM[1], 16);

  /* Which EXPORT functions read LAB_MASK. A function that does is build-variant BY CONSTRUCTION:
   * the source has no other reason to differ between the two builds. That is the whole witness, and
   * it is derived by reading the C rather than by naming checksum. */
  const variant = new Set();
  const fnRe = /^EXPORT\s+[\w ]+?\**\s*(\w+)\s*\([^)]*\)\s*\{/gm;
  let m;
  while ((m = fnRe.exec(c)) !== null) {
    const close = c.indexOf('\n}', fnRe.lastIndex);
    if (close < 0) continue;
    if (/LAB_MASK/.test(c.slice(fnRe.lastIndex, close))) variant.add(m[1]);
  }
  if (!variant.size) return { error: 'core.c exposes no EXPORT function that reads LAB_MASK' };

  /* build.ps1's variant table is the other half: which mask each dll was compiled with. Parsed so
   * that re-pointing the gate at another fixture needs no edit here. */
  const builds = [];
  const rowRe = /@\{\s*id\s*=\s*'([^']+)'\s*;\s*dll\s*=\s*'([^']+)'\s*;\s*def\s*=\s*'([^']*)'\s*\}/g;
  while ((m = rowRe.exec(b)) !== null) {
    const ov = m[3].match(/\/DLAB_MASK=(0x[0-9A-Fa-f]+)/);
    builds.push({ id: m[1], dll: m[2], mask: ov ? parseInt(ov[1], 16) : parseInt(defM[1], 16) });
  }
  if (builds.length < 2) return { error: 'build.ps1 no longer declares two build variants' };

  return { base, defaultMask: parseInt(defM[1], 16), variant, builds,
    seedOf: (mask) => (base ^ mask) >>> 0 };
}

/* --------------------------------------------------------------------------- instrument */
function powershell(args) {
  return spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ...args], {
    encoding: 'utf8',
    timeout: RUN_TIMEOUT_MS + 180000,
    windowsHide: true,
  });
}

/* One side = one binary through the sanctioned wrapper, both postscripts, each gated on the
 * artifact that postscript is contracted to write.
 *
 * NOTE the PostArgs value. ExportDecompile takes an outdir and creates <outdir>/decompiled/ inside
 * it, so PostArgs is the SIDE directory and the .c files land one level down from summary.json.
 * Passing the decompiled/ directory itself is the easy mistake and yields a side with a summary and
 * zero decompiled files, which is exactly the kind of empty measurement this file is supposed to
 * refuse rather than report. */
function analyse(binary, outDir) {
  fs.mkdirSync(outDir, { recursive: true });

  const d = powershell([WRAPPER, '-Sample', binary, '-OutDir', outDir,
    '-PostScript', 'ExportDecompile.java', '-PostArgs', outDir]);
  const summaryPath = path.join(outDir, 'summary.json');
  if (!fs.existsSync(summaryPath)) {
    return { ok: false, why: `ExportDecompile produced no summary.json (wrapper exit ${d.status})`, stderr: d.stderr };
  }
  let summary;
  try { summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8')); }
  catch (e) { return { ok: false, why: `summary.json unreadable: ${e.message}` }; }
  if (!summary.ok || !(summary.functions > 0)) {
    return { ok: false, why: `summary.json not ok / no functions: ${JSON.stringify(summary)}` };
  }

  const decompDir = path.join(outDir, 'decompiled');
  const cFiles = fs.existsSync(decompDir) ? fs.readdirSync(decompDir).filter((f) => f.endsWith('.c')) : [];
  if (!cFiles.length) return { ok: false, why: `no decompiled .c under ${decompDir}` };

  const hashDir = path.join(outDir, 'hashes');
  fs.mkdirSync(hashDir, { recursive: true });
  const h = powershell([WRAPPER, '-Sample', binary, '-OutDir', hashDir,
    '-PostScript', 'FunctionHashes.java', '-PostArgs', hashDir]);
  const table = fs.readdirSync(hashDir).find((f) => f.startsWith('hashes-') && f.endsWith('.txt'));
  if (!table) {
    return { ok: false, why: `FunctionHashes produced no manifest (wrapper exit ${h.status})`, stderr: h.stderr };
  }

  /* Bodies as a LIST, never a name-keyed map: see the header note on duplicate names. */
  const bodies = [];
  for (const ln of fs.readFileSync(path.join(hashDir, table), 'utf8').split(/\r?\n/)) {
    if (!ln || ln.startsWith('#')) continue;
    const f = ln.split('\t');
    if (f.length >= 3) bodies.push({ name: f[0], size: Number(f[1]), hash: f[2] });
  }
  if (!bodies.length) return { ok: false, why: 'function-hash manifest had no body rows' };

  return { ok: true, summary, bodies, decompDir, cFiles, name: path.basename(binary) };
}

/* Multiset helpers. A body is identified by (name, size, content-address); multiset equality is
 * exact whether or not two distinct functions share a name. */
const bodyKey = (r) => `${r.name} ${r.size} ${r.hash}`;
function bag(rows) {
  const m = new Map();
  for (const r of rows) m.set(bodyKey(r), (m.get(bodyKey(r)) || 0) + 1);
  return m;
}
const collisionCount = (rows) => {
  const n = new Map();
  for (const r of rows) n.set(r.name, (n.get(r.name) || 0) + 1);
  let dup = 0;
  for (const v of n.values()) if (v > 1) dup += v - 1;
  return { distinct: n.size, total: rows.length, collapsed: dup };
};

/* Grouped decompiled C by function symbol. ExportDecompile writes <name>_<address>.c after
 * sanitising the symbol, so grouping is by prefix; a symbol needing sanitising must not silently
 * blank the comparison, hence the explicit address-shaped suffix test. */
function cByName(side) {
  const m = new Map();
  for (const f of side.cFiles) {
    const k = f.match(/^(.*)_[0-9a-f]{6,}\.c$/i);
    if (!k) continue;
    if (!m.has(k[1])) m.set(k[1], []);
    m.get(k[1]).push(fs.readFileSync(path.join(side.decompDir, f), 'utf8'));
  }
  for (const v of m.values()) v.sort();
  return m;
}
const sameBag = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/* --------------------------------------------------------------------------------- comparison */
function compare(A, B, gt) {
  const ca = cByName(A);
  const cb = cByName(B);

  /* Group bodies by NAME first, then compare each group's multiset. Presence is a property of a
   * name, never of a content-address.
   *
   * MEASURED BUG THIS REPLACES. The first version compared whole-body multisets and called any
   * key missing from the other side a "presence" finding. But a body whose CONTENT changed is
   * missing from the other side by definition, so every genuine change was reported twice as
   * "a function one side has and the other does not" -- and the cross-build arm went red on
   * checksum, whose change core.c had already predicted and explained. A control that reports a
   * known-good difference as a defect is worse than no control: it trains the reader to ignore
   * it. Presence now means a NAME is missing, which is what the word means. */
  const byName = (side) => {
    const m = new Map();
    for (const r of side.bodies) {
      if (!m.has(r.name)) m.set(r.name, []);
      m.get(r.name).push(r);
    }
    return m;
  };
  const ga = byName(A);
  const gb = byName(B);
  const names = [...new Set([...ga.keys(), ...gb.keys()])].sort();
  const sameSubstance = (name) => {
    /* The `blind` fault: report "identical" no matter what is actually found. That is a
     * correlator scoring nothing, and it must surface as a MISSED DIFFERENCE for the function the
     * source says must move -- not as a quiet pass. */
    if (FAULTS.has('blind')) return true;
    const inA = ga.get(name) || [];
    const inB = gb.get(name) || [];
    return inA.length === inB.length
      && inA.every((r) => inB.some((s) => bodyKey(s) === bodyKey(r)));
  };

  /* The `spurious` fault: drop one body from side B's multiset for a name that genuinely exists
   * on both sides. That is a correlator over-reporting -- claiming a function appeared or vanished
   * when nothing did. It is the third direction, and it is the one the registry's own words single
   * out ("Anything else means the correlator is scoring noise"): a control that cannot catch an
   * invented change is not testing the thing it was written for. */
  if (FAULTS.has('spurious')) {
    const name = [...gb.keys()].find((n) => gb.get(n).length > 1) || [...gb.keys()][0];
    gb.get(name).pop();
  }

  const substance = [];   /* bucket 4a: a NAME one side has and the other does not */
  for (const name of names) {
    const inA = ga.get(name) || [];
    const inB = gb.get(name) || [];
    if (inA.length && !inB.length) {
      substance.push({ name, kind: 'presence', finding: true, only: 'A', count: inA.length,
        why: `${inA.length} body/bodies under this symbol on side A and none on side B` });
    } else if (!inA.length && inB.length) {
      substance.push({ name, kind: 'presence', finding: true, only: 'B', count: inB.length,
        why: `${inB.length} body/bodies under this symbol on side B and none on side A` });
    }
  }

  /* Bucket 2: bytes identical, rendering differs. Only meaningful for names whose SUBSTANCE
   * matched -- for a name whose bytes moved, a differing decompilation is the expected consequence
   * of the bytes moving, not a separate cosmetic disagreement to report on top of it. */
  const rows = [];
  for (const name of names) {
    if (!sameSubstance(name)) continue;
    if (!(ga.get(name) || []).length) continue;
    const renderedA = ca.get(name) || [];
    const renderedB = cb.get(name) || [];
    if (!sameBag(renderedA, renderedB)) {
      rows.push({ name, kind: 'render', count: Math.max(renderedA.length, renderedB.length),
        hashes: [...new Set((ga.get(name) || []).map((r) => `${r.size}b/${r.hash}`))] });
    }
  }

  /* Bucket 3: names the source says are build-variant. Did their substance move, and is the move
   * accounted for by the mask arithmetic? The caller checks each side's own decompiled C for the
   * constant its mask predicts, so a predicted difference is explained rather than merely allowed. */
  const predicted = [];
  for (const name of gt.variant) {
    const inA = ga.get(name) || [];
    const inB = gb.get(name) || [];
    if (!inA.length || !inB.length) continue;
    predicted.push({ name, moved: !sameSubstance(name),
      hashA: inA.map((r) => r.hash).join(', '), hashB: inB.map((r) => r.hash).join(', '),
      cA: renderedOf(ca.get(name)), cB: renderedOf(cb.get(name)) });
  }

  /* Bucket 4b: substance moved for a name the source gives no build-time variation for. */
  const unexplained = [];
  for (const name of names) {
    if (gt.variant.has(name)) continue;
    if (!(ga.get(name) || []).length || !(gb.get(name) || []).length) continue;
    if (sameSubstance(name)) continue;
    unexplained.push({ name, kind: 'unexplained-body-change',
      why: 'body content-address changed, and core.c gives this function no build-time variation',
      hashA: (ga.get(name) || []).map((r) => `${r.size}b/${r.hash}`).join(' '),
      hashB: (gb.get(name) || []).map((r) => `${r.size}b/${r.hash}`).join(' ') });
  }

  /* Bucket 5: the source says this must move and the correlator reported it still. */
  const missed = predicted.filter((p) => !p.moved).map((p) => p.name);

  return { rows, substance, predicted, unexplained, missed, ca, cb, names, ga, gb };
}
const renderedOf = (arr) => (arr && arr.length ? arr.join('\n') : null);

/* Did each side's OWN decompilation carry the seed its build's mask predicts? This is what makes
 * "the two sides differ" explainable rather than merely observed. */
function seedCheck(cmap, gt, build) {
  /* Read the constant out of THIS side's own decompilation. An earlier draft took the whole
   * comparison and pulled the text out of one side's map for both, so side C was checked against
   * side B's C and reported as missing a constant that was sitting in its own output. The witness
   * has to be each side's own, or it is not a witness. */
  const lit = '0x' + gt.seedOf(build.mask).toString(16);
  const mask = '0x' + build.mask.toString(16);
  const src = renderedOf(cmap.get('checksum'));
  if (!src) return { ok: false, lit, mask, why: 'no decompiled checksum on this side' };
  return { ok: new RegExp('\\b' + lit + '\\b', 'i').test(src), lit, mask,
    why: `${lit} is absent from this side's own decompiled checksum` };
}

/* -------------------------------------------------------------------------------------- main */
let scratch = null;
let exitCode = 1;
const summary = { control: 'native.crosscompare.same_binary', arms: {}, findings: 0, verdict: 'OK' };
if (faulted) summary.faults = [...FAULTS];

try {
  if (faulted) {
    line();
    line('='.repeat(100));
    line(`!!! MUTATED RUN -- NGATE_FAULT=${[...FAULTS].join(',')} -- NOT A MEASUREMENT !!!`.padEnd(100, ' '));
    line('!!! This run exists to show the control can fail. A real run leaves NGATE_FAULT      !!!');
    line('!!! unset and prints no banner. Do not read this output as a verdict on Ghidra.      !!!');
    line('='.repeat(100));
  }

  line();
  line('='.repeat(100));
  line('native.crosscompare.ghidra -- NEGATIVE CONTROL: a binary compared against itself');
  line('='.repeat(100));

  for (const [label, p] of [['wrapper', WRAPPER], ['core.c', CORE_C], ['build.ps1', BUILD_PS1], ['ghidra', GHIDRA]]) {
    if (!fs.existsSync(p)) die(2, `negative-gate: could not measure -- missing ${label}: ${p}`);
  }

  const gt = readGroundTruth();
  if (gt.error) {
    die(3, 'CONTROL PREMISE FAILED -- ' + gt.error,
      '  The gate could not read its own ground truth, so any verdict below would be unfounded.');
  }
  line('  witness      native/core.c + headless-lab/tools/build.ps1 -- read, not assumed');
  line(`    seed       0x${gt.base.toString(16)} ^ LAB_MASK; default LAB_MASK 0x${gt.defaultMask.toString(16)}`);
  line(`    variant    functions reading LAB_MASK: ${[...gt.variant].join(', ')}  (build-variant by construction)`);
  for (const b of gt.builds) {
    line(`    build      ${b.dll.padEnd(14)} mask 0x${b.mask.toString(16)} -> seed 0x${gt.seedOf(b.mask).toString(16)}`);
  }
  line('  instrument   scripts/ghidra-headless.ps1  (the ONE sanctioned launcher; no second launch path)');
  line(`    ghidra     ${GHIDRA}`);
  line('    postscripts ExportDecompile.java (the decompiler\'s opinion) + FunctionHashes.java (a fact about bytes)');
  line();

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'xcompare-neg-'));
  const out = (n) => path.join(scratch, n);

  /* ---------------------------------------------------------------- ARM A -- the registry's own
   * control. Two INDEPENDENT analyses of the SAME program. Must report zero changes. */
  line('-'.repeat(100));
  line('ARM A -- IDENTITY: core_v1.dll analysed twice, as two JVMs and two throwaway projects');
  line('-'.repeat(100));
  const A1 = analyse(path.join(LAB, 'out', gt.builds[0].dll), out('A1'));
  if (!A1.ok) die(2, `negative-gate: could not measure -- side A1: ${A1.why}`, A1.stderr || '');
  const A2 = analyse(path.join(LAB, 'out', gt.builds[0].dll), out('A2'));
  if (!A2.ok) die(2, `negative-gate: could not measure -- side A2: ${A2.why}`, A2.stderr || '');

  const kA = collisionCount(A1.bodies);
  const kB = collisionCount(A2.bodies);
  line(`  side A1  ${A1.summary.functions} functions, ${A1.summary.decompiled} decompiled, ${A1.cFiles.length} .c files`);
  line(`  side A2  ${A2.summary.functions} functions, ${A2.summary.decompiled} decompiled, ${A2.cFiles.length} .c files`);
  line(`  key       body = (name, size, content-address) as a MULTISET. Names are not unique in a`);
  line(`            FunctionHashes manifest: ${kA.total} bodies but ${kA.distinct} names on A1, so`);
  line(`            ${kA.collapsed} body/bodies share a symbol with another. A name-keyed map would`);
  line(`            have compared ${kA.distinct} of ${kA.total} and hidden any difference inside a`);
  line(`            collapsed duplicate. Multiset equality is exact either way.`);
  line();

  /* Arm A gets an empty variant set: with identical input the source predicts NOTHING moves, so
   * every observed movement is a finding rather than an expected difference. */
  /* The `noise` fault: give one body on side A2 a content-address it does not have. The file on
   * disk is untouched and Ghidra's answer was correct -- the corruption is to the comparison's
   * input, which is exactly what a correlator scoring noise looks like from the outside. */
  if (FAULTS.has('noise')) {
    const victim = A2.bodies.find((r) => r.name === 'classify');
    victim.hash = 'deadbeefdeadbeef';
    line(`  *** INJECTED FAULT (NGATE_FAULT=noise): side A2 classify forced to deadbeefdeadbeef ***`);
    line();
  }

  const armA = compare(A1, A2, { ...gt, variant: new Set() });
  const aFindings = [...armA.substance, ...armA.unexplained];

  for (const r of armA.rows) {
    line('  RENDERING DIFFERS, bytes identical -- NOT a finding');
    line(`    ${r.name}  (${r.count} decompiled file(s))`);
    line(`      body content-address on both sides: ${r.hashes.join('  ')}`);
    line('      the decompiled C differs but the BYTES do not. Two decompilers rendering one body');
    line('      differently is a decompiler disagreement; it says nothing about either being wrong.');
    line();
  }
  for (const r of aFindings) {
    line(`  FINDING -- ${r.kind}: ${r.name}`);
    line(`      ${r.why}`);
    if (r.hashA) line(`      side A1  ${r.hashA}\n      side A2  ${r.hashB}`);
    line('      Identical input must produce identical output. A correlator that cannot reproduce');
    line('      itself here is not usable on differing input, so nothing below could be trusted.');
    line();
  }
  if (!armA.rows.length && !aFindings.length) {
    line(`  ${kA.total} bodies compared as a multiset, 0 differences. Every content-address and all`);
    line(`  ${A1.cFiles.length} decompiled .c files reproduced exactly across two independent headless`);
    line('  analyses of the same program. Nothing was invented.');
    line();
  }
  line(`  ARM A VERDICT: ${aFindings.length
    ? `${aFindings.length} finding(s) -- the correlator does NOT reproduce itself on identical input`
    : 'zero changes on identical input, as the registry requires'}`);
  line();
  summary.arms.A = { bodies: kA.total, renderOnly: armA.rows.length, findings: aFindings.length };

  /* ------------------------------------------------------------- ARM B -- the discrimination
   * Two genuinely different builds. Differences are EXPECTED here, and the only question is which
   * of them the source predicts. */
  line('='.repeat(100));
  line('ARM B -- CROSS-BUILD: two builds of one source. Disagreement here is EXPECTED.');
  line('='.repeat(100));
  const B = analyse(path.join(LAB, 'out', gt.builds[0].dll), out('B'));
  if (!B.ok) die(2, `negative-gate: could not measure -- side B: ${B.why}`, B.stderr || '');
  const C = analyse(path.join(LAB, 'out', gt.builds[1].dll), out('C'));
  if (!C.ok) die(2, `negative-gate: could not measure -- side C: ${C.why}`, C.stderr || '');
  const armB = compare(B, C, gt);

  line(`  side B  ${B.name}  mask 0x${gt.builds[0].mask.toString(16)}   ${B.summary.functions} functions`);
  line(`  side C  ${C.name}  mask 0x${gt.builds[1].mask.toString(16)}   ${C.summary.functions} functions`);
  line('  neither side has seen core.c or build.ps1. The witness is a third party both sides could');
  line('  not have consulted, which is the only reason "they differ" is separable from "one of them');
  line('  is wrong".');
  line();

  const scB = seedCheck(armB.ca, gt, gt.builds[0]);
  const scC = seedCheck(armB.cb, gt, gt.builds[1]);
  if (!scB.ok || !scC.ok) {
    die(3, 'CONTROL PREMISE FAILED -- a side\'s decompilation does not carry the constant its mask predicts',
      `  B (${gt.builds[0].dll}, mask ${scB.mask}, predicts ${scB.lit}): ${scB.ok ? 'present' : scB.why}`,
      `  C (${gt.builds[1].dll}, mask ${scC.mask}, predicts ${scC.lit}): ${scC.ok ? 'present' : scC.why}`,
      '  The instrument may well be fine. This control would be attributing a difference it cannot',
      '  actually account for, so it refuses to guess rather than reporting a verdict it did not earn.');
  }
  line('  seed arithmetic, each side checked against its OWN decompiled C:');
  line(`    B ${gt.builds[0].dll.padEnd(14)} 0x${gt.base.toString(16)} ^ ${scB.mask} = ${scB.lit}   present: YES`);
  line(`    C ${gt.builds[1].dll.padEnd(14)} 0x${gt.base.toString(16)} ^ ${scC.mask} = ${scC.lit}   present: YES`);
  line(`  So the two sides DO differ, and the difference is fully accounted for by a compile-time`);
  line(`  constant declared in a file neither decompiler read. That is bucket 3: EXPECTED.`);
  line();

  let bFindings = 0;
  for (const p of armB.predicted) {
    if (!p.moved) continue;
    line(`  EXPECTED DIFFERENCE -- ${p.name}`);
    line('      produced by BOTH sides; neither is defective');
    line(`      side B content-address  ${p.hashA}`);
    line(`      side C content-address  ${p.hashB}`);
    line('      evidence this is a defect-free disagreement rather than merely a difference:');
    line(`        core.c computes this body's seed as 0x${gt.base.toString(16)} ^ LAB_MASK, and the two`);
    line(`        builds differ ONLY in that macro -- ${scB.lit} vs ${scC.lit}, each confirmed present`);
    line('        in that side\'s own decompiled C above. The BYTES differ, so this is substance,');
    line('        not a rendering artefact, AND the source predicted it. The cross-compare is');
    line('        doing its job, and a gate that flagged this would be the noise failure.');
    const la = (p.cA || '').match(new RegExp('\\b' + scB.lit + '\\b', 'i'));
    const lb = (p.cB || '').match(new RegExp('\\b' + scC.lit + '\\b', 'i'));
    if (la && lb) line(`      decompiled, side by side:  B ${scB.lit}   C ${scC.lit}   (the one differing operand)`);
    line();
  }
  for (const r of armB.rows) {
    line('  RENDERING DIFFERS, bytes identical -- NOT a finding');
    line(`    ${r.name}  (${r.count} decompiled file(s))  content-address identical on both sides: ${r.hashes.join('  ')}`);
    line();
  }
  for (const r of armB.substance) {
    bFindings++;
    line(`  FINDING -- ${r.kind}: ${r.name}`);
    line(`      ${r.why}`);
    line('      neither side was predicted to gain or lose a body here. One side has a function the');
    line('      other does not, and nothing in the source accounts for it.');
    line();
  }
  for (const r of armB.unexplained) {
    bFindings++;
    line(`  FINDING -- unexplained body change: ${r.name}`);
    line(`      ${r.why}`);
    line(`      produced by  side B: ${r.hashA}`);
    line(`                   side C: ${r.hashB}`);
    line('      THIS is bucket 4: bytes differ and no witness explains it. One side is describing a');
    line('      body the other does not have. Reporting a mere disagreement would be the noise');
    line('      mistake this gate exists to avoid; refusing to report THIS one would be worse.');
    line();
  }
  for (const n of armB.missed) {
    bFindings++;
    line(`  FINDING -- MISSED DIFFERENCE: ${n}`);
    line(`      core.c reads LAB_MASK inside ${n}, so its body MUST differ between these builds.`);
    line('      The correlator scored it identical: it is scoring nothing, which is the same defect');
    line('      as scoring noise, wearing the opposite mask.');
    line();
  }

  const sameCount = armB.predicted.filter((p) => !p.moved).length;
  const predCount = armB.predicted.filter((p) => p.moved).length;
  line(`  ARM B TALLY: ${armB.rows.length} rendering-only, ${predCount} predicted-and-explained,`);
  line(`              ${sameCount} variant-named function(s) correctly found still, ${bFindings} finding(s)`);
  line(`  ARM B VERDICT: ${bFindings
    ? `${bFindings} unexplained or missed difference(s)`
    : 'every difference was predicted by a witness neither side could see'}`);
  line();
  summary.arms.B = { renderOnly: armB.rows.length, predicted: predCount, findings: bFindings };

  /* ---------------------------------------------------------------------------------- verdict */
  const totalFindings = aFindings.length + bFindings;
  summary.findings = totalFindings;
  if (totalFindings > 0) {
    summary.verdict = 'DRIFT';
    line('CONTROL FAILED -- the correlator does not hold up under both directions of its own test.');
    line('  A cross-compare that cannot reproduce itself on identical input, or that reports a body');
    line('  change no source predicts, or misses one it does, is scoring rather than measuring.');
    line('  Exiting 0, which is the value R5 flags as DRIFT: an instrument that had stopped working');
    line('  entirely would produce exactly the same verdict.');
    exitCode = 0;
  } else {
    line('NEGATIVE-CONTROL OK -- the honest-refusal shape holds in both directions.');
    line(`  ARM A  ${kA.total} bodies, identical input, ZERO changes. Nothing was invented.`);
    line(`  ARM B  ${predCount} difference(s), every one predicted by core.c before it was read, and`);
    line(`         ${armB.rows.length} rendering-only difference(s) correctly dismissed as a`);
    line('         decompiler disagreement rather than a defect. Nothing was missed either.');
    line('  The distinction that makes this a control rather than a noise generator: a difference');
    line('  WITH a witness is reported as agreement-with-an-explanation, and a difference WITHOUT');
    line('  one is a finding. A gate that reported every difference would be red on every run and');
    line('  would therefore say nothing at all.');
    line('  Exiting 1 -- the non-zero code the registry declares, because a control that must exit 0');
    line('  proves nothing.');
    exitCode = 1;
  }
} catch (e) {
  /* A Refusal already printed its own explanation. Carrying its code here is what keeps the refusal
   * paths (2 = could not measure, 3 = premise failed) distinct from the control's own verdict, and
   * unwinding instead of exiting is what lets `finally` clean up. */
  if (e instanceof Refusal) {
    exitCode = e.code;
    summary.verdict = 'REFUSED';
  } else {
    summary.verdict = 'UNMEASURABLE';
    line();
    line('negative-gate: ' + (e && e.stack ? e.stack : e));
    line('  Could not complete the control. This is exit 2 -- NOT the control code 1, and NOT a pass.');
    exitCode = 2;
  }
} finally {
  /* Nothing of this gate's survives it. Re-checked rather than asserted, and reported either way. */
  if (scratch && fs.existsSync(scratch)) {
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* reported below */ }
  }
  if (scratch) line(`  scratch ${scratch} removed: ${fs.existsSync(scratch) ? 'NO -- LEFT BEHIND' : 'yes'}`);
  line('GATE-SUMMARY ' + JSON.stringify(summary));
}

process.exit(exitCode);
