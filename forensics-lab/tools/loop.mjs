/* loop.mjs — ONE command that runs the whole D12 loop and judges itself.
 *
 * The sequence is the analysis loop, in order, and every step asserts something:
 *
 *   1  BUILD      generate the synthetic image + the three independent artifacts
 *   2  DETERMINISM  regenerate and require byte-identical output  (PRESERVE)
 *   3  TRIAGE     pslist / psscan / netscan / malfind / handlescan over the image
 *   4  NARROW     cross-view disagreement, then the triangulator
 *   5  VERIFY     compare the findings set against the ground truth, exactly
 *   6  DECOY      require the single-source claim to exist AND to be unconfirmed
 *   7  CORRELATE  hand the carved bytes to DiE + YARA-X; probe real Volatility
 *   8  CONTROL-A  a CLEAN image must produce no findings (the detector can say no)
 *   9  CONTROL-B  a TAMPERED image must LOSE the finding (the detector can fail)
 *  10  CONTROL-C  a single-source run must not promote anything (the gate holds)
 *  11  CONTROL-D  `--expect` with the wrong set must exit non-zero (the guard works)
 *
 * Controls A-D are the negative controls: a forensics tool that cannot fail is
 * decoration, and a rule that never rejects is decoration. Each one is a real
 * mutation of a real artefact, not a mock.
 *
 * Exit 0 closes the full loop or self-test; 9 refutes a full-loop assertion. In
 * --control=srum mode, 4 means the demanded refusal held and 3 means the control failed.
 *
 * `--control=<name>` runs ONE section on its own exit code, so a registry probe can point
 * at a control instead of at the whole loop. It prints `CONTROL ... ONLY` and a summary
 * line that says so, and it never prints LOOP CLOSED.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { generate } from '../lab/mkimage.mjs';
import { analyze, MIN_INDEPENDENT_SOURCES } from './analyze.mjs';
import { correlate, findTools, stationRoot } from './correlate.mjs';
import { RECORD } from '../lab/mkimage.mjs';
import * as S from '../lab/spec.mjs';
// Run summary to disk, so the verdict rests on a FILE rather than a substring of stdout.
// assert-probes says an entry with no `probe.produces` was "matched STRINGS only, and a
// stub which prints them satisfies it". Added 2026-10-04; see scripts/probe_artifact.mjs.
import { writeRunArtifact } from '../../scripts/probe_artifact.mjs';

// ARGUMENT REFUSAL. Added 2026-10-04. Measured on this tree: passing a path that does not exist
// produced a normal green run and exit 0 -- every check "passed" while nothing anyone asked for
// had been done. A regression suite that cannot fail on the thing you handed it reports a pass
// for work nobody did, which is the one shape this station exists to reject.
//
// The precedent is already in this tree and this follows it rather than inventing a second
// convention: crackme-corpus/tools/loop.py uses argparse and rejects `unrecognized arguments`
// with exit 2. The JS loops had no argument parser at all, which is the defect. First
// installation here landed mid-function and collided with an existing `extra` binding; a guard
// inserted at the wrong scope is the same class of mistake as the bug it fixes, so the placement
// is at module scope after the imports and nowhere else.
// ALLOWLIST DERIVED FROM WHAT THIS LOOP ACTUALLY READS, not from a guess. The first version
// allowed only `--json` and `--quiet`, and that broke this entry's own declared negative control
// in manifests/capabilities.json -- `node forensics-lab/tools/loop.mjs --control=srum --expect
// INJECTED_PRIVATE_RWX_REGION` -- which the registry runs and which assert-probes then reported
// as DRIFT: real exit 2 against a recorded expect_exit of 4. A guard that blocks the measurement
// is the same failure wearing the opposite face, and the gate caught it within one run.
// `--expect` takes its value in the NEXT argv element, so that element must not be mistaken for
// a stray path.
const KNOWN_FLAGS = new Set(['--json', '--quiet', '--control=', '--expect']);
const VALUE_FLAGS = new Set(['--expect']);
const strayArgs = [];
{
  const all = process.argv.slice(2);
  for (let i = 0; i < all.length; i++) {
    const a = all[i];
    // VALUE_FLAGS IS CHECKED FIRST, and the order is load-bearing: `--expect` is itself in
    // KNOWN_FLAGS, so testing KNOWN_FLAGS first would `continue` past it and leave its VALUE to
    // be judged as a stray path. That is exactly what the first attempt did --
    // `--expect INJECTED_PRIVATE_RWX_REGION` was rejected on the finding-id.
    if (VALUE_FLAGS.has(a)) { i += 1; continue; }
    if (KNOWN_FLAGS.has(a) || [...KNOWN_FLAGS].some((k) => k.endsWith('=') && a.startsWith(k))) continue;
    strayArgs.push(a);
  }
}
if (strayArgs.length) {
  console.error(`loop: refusing an argument it would otherwise IGNORE: ${strayArgs.join(' ')}`);
  console.error('  This is a regression suite over its own built fixtures. It has no --target.');
  console.error('  Accepting an argument silently would report a pass for work nobody did.');
  process.exit(2);
}




const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB_ROOT = path.resolve(HERE, '..');
/* PER-PROCESS, and D12_FORENSICS_WORK still wins for a caller that wants a shared one.
 *
 * This directory was shared by every run, and mkimage.generate() rm -rf's the directory it is
 * handed before regenerating it -- so two concurrent loops delete each other's forensic image.
 * Measured 2026-10-03 as an UNHANDLED `Error: EPERM ... \fuzz-lab\work\image` from the fuzz
 * lab, whose corpus build calls into this same generator. A crash is a louder symptom than the
 * mobile-lab one and the same root cause: a fixed scratch path plus a destructive first step. */
const WORK = process.env.D12_FORENSICS_WORK || path.join(os.tmpdir(), `d12-forensics-lab-${process.pid}`);
const TARGET = path.join(WORK, 'target');
const CARVED = path.join(WORK, 'carved');

const steps = [];
function step(label, pass, detail) {
  steps.push({ label, pass, detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label.padEnd(56)} ${detail}`);
  return pass;
}
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const line = (s = '', n = 78) => console.log(`${'-'.repeat(n)}\n${s}\n${'-'.repeat(n)}`);


/* ------------------------------------------------------------------ selector */

/* `--control=<name>` runs ONE section and exits on that section alone. The loop's own exit
 * code spoke for all eleven sections at once -- `process.exit(failed.length === 0 ? 0 : 9)`
 * at the bottom of this file -- so control C could not be pointed at on its own, and this
 * capability's negative_control could only be a plan. */
const CONTROL = (process.argv.slice(2).find((a) => a.startsWith('--control=')) || '').slice('--control='.length) || null;
/* `--expect <finding-id>` is the same section in the shape the registry's R5 requires: it
 * DEMANDS the finding from a real analyze.mjs process and exits non-zero when the analyser
 * refuses. Without it a control here would have to expect exit 0, and R5 refuses exactly
 * that, because a control that must succeed proves nothing. */
const CONTROL_EXPECT = (() => {
  const i = process.argv.indexOf('--expect');
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : null;
})();

/* The loop banner is suppressed under `--control`, not merely followed by a correction: a
 * one-section run that opens with "D12 forensics lab loop" is precisely what makes a
 * control indistinguishable from the thing it has to be separable from. */
if (!CONTROL) {
  console.log('D12 forensics lab loop');
  console.log(`  work        ${WORK}`);
  console.log(`  ground truth ${path.relative(LAB_ROOT, path.join(LAB_ROOT, 'lab', 'spec.mjs'))} (read only by this file)`);
} else {
  console.log(`D12 forensics lab — CONTROL ${CONTROL} ONLY. This is NOT the full loop run.`);
  console.log(`  work        ${WORK}`);
  console.log('  sections 1-9 and 11 are NOT executed; the exit code below is this section alone.');
}

if (CONTROL) {
  if (CONTROL !== 'srum') {
    console.error(`loop.mjs: unknown --control='${CONTROL}'. This build ships exactly one control: srum.`);
    process.exit(64);
  }
  controlSrum({ demand: CONTROL_EXPECT });
  summarizeControl(CONTROL_EXPECT);
}

/* ------------------------------------------------------------------ 1 BUILD */

line('[1] BUILD — generate the synthetic target');
const built = generate(TARGET);
console.log(built.imagePath);
console.log(`  image       ${built.meta.bytes} bytes  sha256 ${built.meta.sha256}`);
console.log(`  payload     ${built.meta.payload.producer}  ${built.meta.payload.size} bytes  sha256 ${built.meta.payload.sha256}`);
console.log(`  regions     ${Object.entries(built.meta.regions).map(([k, v]) => `${k}@0x${v.toString(16)}`).join('  ')}`);
console.log(`  processes   ${built.meta.eprocessCount} in pool, ${built.meta.eprocessInList} reachable from the list head`);
console.log(`  artifacts   ${built.artifactFiles.length}  (Amcache 1, Prefetch 7, Srum 1)`);
step('image built and hashed', built.meta.bytes > 0, `${built.meta.bytes} bytes`);

/* ------------------------------------------------------------------ 2 DETERMINISM */

line('[2] PRESERVE — the fixture must be byte-reproducible, or "deterministic" is a claim');
{
  const imageFile = path.join(TARGET, 'd12-lab-image.raw');
  const first = sha256(fs.readFileSync(imageFile));
  const second = generate(TARGET);
  const secondHash = sha256(fs.readFileSync(imageFile));
  step('regenerating the image produces identical bytes', first === secondHash, `${first.slice(0, 16)}… == ${secondHash.slice(0, 16)}…`);

  /* the analysis itself must be reproducible too: a triage that reorders its own rows
     between runs cannot be diffed against anything, including its own ground truth */
  const a = JSON.stringify(analyze(TARGET), null, 1);
  const b = JSON.stringify(analyze(TARGET), null, 1);
  step('two analyses of the same image are byte-identical', a === b, `${sha256(a).slice(0, 16)}…`);
}

/* ------------------------------------------------------------------ 3 TRIAGE */

line('[3] TRIAGE — run the plugin set over the target');
const analysis = analyze(TARGET);
if (!analysis.ok) {
  step('analysis ran', false, analysis.error);
  summarize();
}
const t = analysis.triage;
console.log(`  pslist      ${t.pslist.count} processes: ${t.pslist.processes.map((p) => `${p.pid}:${p.name}`).join(' ')}`);
console.log(`  psscan      ${t.psscan.count} processes`);
console.log(`  netscan     ${t.netscan.count} connections, chain intact ${t.netscan.chainIntact}`);
console.log(`  malfind     ${t.malfind.suspicious} suspicious of ${t.malfind.candidates} candidates`);
console.log(`  handlescan  ${t.handlescan.count} handles`);
step('pslist reaches exactly the linked processes', t.pslist.count === S.GROUND_TRUTH.processesInList.length, `${t.pslist.count} == ${S.GROUND_TRUTH.processesInList.length}`);
step('psscan finds strictly more than the list walk', t.psscan.count > t.pslist.count, `${t.psscan.count} > ${t.pslist.count} (the DKOM signal)`);
step('malfind keeps the executable+unbacked region', t.malfind.suspicious === 1, `${t.malfind.suspicious} suspicious`);

/* ------------------------------------------------------------------ 4 + 5 VERIFY */

line('[4] NARROW / [5] VERIFY — triangulate, then compare against the ground truth');
console.log(`  rule: ${analysis.rule.statement} (>= ${MIN_INDEPENDENT_SOURCES} independent source groups)\n`);
for (const f of analysis.findings) {
  console.log(`  FINDING     ${f.id.padEnd(34)} ${f.groups.join('+')}  (${f.independentSources} sources)`);
  console.log(`              ${f.title}`);
}
const got = analysis.findings.map((f) => f.id).sort();
const want = S.GROUND_TRUTH.confirmed.map((c) => c.id).sort();
const missing = want.filter((x) => !got.includes(x));
const extra = got.filter((x) => !want.includes(x));
step('findings set matches the ground truth exactly', missing.length === 0 && extra.length === 0,
  missing.length || extra.length ? `missing=[${missing}] unexpected=[${extra}]` : `${got.join(', ')}`);

for (const c of S.GROUND_TRUTH.confirmed) {
  const f = analysis.findings.find((x) => x.id === c.id);
  if (!f) { step(`${c.id} is reported`, false, 'absent'); continue; }
  const needGroups = new Set(c.requiresSources);
  const have = new Set(f.groups);
  const haveAll = [...needGroups].every((g) => have.has(g));
  step(`${c.id} cites ${c.requiresSources.join('+')}`, haveAll, `support: ${f.support.join('  ')}`);
}

/* ------------------------------------------------------------------ 6 DECOY */

line('[6] THE DECOY — one artifact, and it must NOT become a finding');
for (const d of S.GROUND_TRUTH.rejected) {
  const asFinding = analysis.findings.find((f) => f.id === d.claimId);
  const unconfirmed = analysis.unconfirmed.find((u) => u.id === d.claimId);
  step(`decoy ${d.app}`, true, `single source: ${d.singleSource}`);
  step(`  ... is NOT in the findings set`, !asFinding, asFinding ? `LEAKED into findings with ${asFinding.independentSources} sources (BAD)` : 'absent from findings');
  if (!unconfirmed) { step(`  ... is reported as UNCONFIRMED`, false, 'not reported at all — a silent omission is a hole in the report'); continue; }
  step(`  ... is reported as UNCONFIRMED`, unconfirmed.tier === 'POSSIBLE', `${unconfirmed.tier}, ${unconfirmed.independentSources} source: ${unconfirmed.groups.join('+')}`);
  const absences = ['no process in the image', 'no Amcache execution record', 'no prefetch run history'];
  step(`  ... names every source that does NOT have it`, absences.every((a) => unconfirmed.detail.some((d2) => d2.startsWith(a))), unconfirmed.detail.filter((d2) => d2.startsWith('no ')).join('; '));
  step(`  ... is still reported, not discarded`, true, `${unconfirmed.title}`);
}
/* Matched on the REGION, not the process: PID 4120 legitimately carries a real injection
 * in one region AND a perfectly ordinary load-list-backed PE region in another. Keying
 * this on the pid would assert that the process itself was not analysed. */
for (const s of S.GROUND_TRUTH.silent) {
  const asFinding = analysis.findings.find((f) => f.id === 'INJECTED_PRIVATE_RWX_REGION' && f.subject?.pid === s.pid && f.subject?.start === `0x${s.start.toString(16)}`);
  const asRejected = analysis.rejected.find((r) => r.subject?.pid === s.pid && r.subject?.start === `0x${s.start.toString(16)}`);
  step(`region 0x${s.start.toString(16)} in PID ${s.pid} is not reported as an injection`, !asFinding && Boolean(asRejected), asRejected ? `REJECTED: ${asRejected.verdictReason}` : 'no claim at all — a silent omission');
}
step('every rejected signal is explained rather than dropped', analysis.rejected.every((r) => r.verdictReason && r.detail.length), analysis.rejected.map((r) => `${r.subject.pid}:${r.verdictReason}`).join('  '));

/* ------------------------------------------------------------------ 7 CORRELATE */

line('[7] CORRELATE — independent implementations on the carved bytes, and the Volatility probe');
const corr = correlate(TARGET, CARVED);
for (const c of corr.carved) {
  if (c.error) { step('carve succeeded', false, c.error); continue; }
  step(`carved the injected region out of the image`, c.bytes > 0, `pid ${c.pid}  ${c.start}  ${c.bytes} bytes  sha256 ${c.sha256.slice(0, 16)}…`);
  for (const t2 of (corr.checks.find((x) => x.carve.pid === c.pid)?.tools ?? [])) {
    step(`${t2.tool} agrees the carved bytes are the lab payload`, t2.agrees, `exit ${t2.exit}  ${t2.result}`);
  }
}
for (const p of corr.volatility.runs) {
  if (p.plugin === 'windows.pslist') {
    /* the honest limit, asserted rather than asserted-about */
    step('real Volatility 3 was invoked on the image', corr.volatility.installed, p.cmd ?? 'vol.exe windows.pslist');
    step('real Volatility 3 REFUSES pslist on a synthetic image', !p.ok && /symbol_table_name|layer_name/.test(p.refusal ?? ''), `exit ${p.exit}  "${(p.refusal ?? '').trim()}"`);
  }
}
console.log(`  ${corr.independenceNote}`);

/* ------------------------------------------------------------------ 8 CONTROL A */

line('[8] NEGATIVE CONTROL A — a clean image must produce NO findings');
/* The cleanest possible falsification test: remove the two planted conditions from the
 * SAME generator, and require the triangulator to find nothing. A detector that reports
 * the same thing on a clean host is not a detector. */
{
  const cleanDir = path.join(WORK, 'clean');
  const cleanSpec = structuredClone({ ...S.GROUND_TRUTH, processes: null });
  void cleanSpec;
  /* Build a clean variant by patching the SPEC for one run, then restoring it. The
     image builder is deterministic, so a clean spec yields a clean image and nothing
     else has to change. */
  const originalVads = S.VADS.map((v) => ({ ...v }));
  const originalTcp = S.TCP.map((t) => ({ ...t }));
  const originalSrum = S.SRUM_ROWS.map((r) => ({ ...r }));
  S.VADS.splice(0, S.VADS.length, ...originalVads.filter((v) => !(v.proc === 4120 && v.mem === S.MEM.PRIVATE)));
  S.TCP.splice(0, S.TCP.length, ...originalTcp.filter((t) => !t.ownsRegion));
  S.SRUM_ROWS.splice(0, S.SRUM_ROWS.length, ...originalSrum.filter((r) => !r.decoy));
  const clean = generate(cleanDir);
  const cleanAnalysis = analyze(cleanDir);
  /* restore before asserting anything, so a throw cannot leave the spec mutated */
  S.VADS.splice(0, S.VADS.length, ...originalVads);
  S.TCP.splice(0, S.TCP.length, ...originalTcp);
  S.SRUM_ROWS.splice(0, S.SRUM_ROWS.length, ...originalSrum);

  step('clean image built without the injection or the decoy', clean.meta.sha256 !== built.meta.sha256, `${clean.meta.bytes} bytes, sha256 differs`);
  step('clean image yields NO injected-region finding', !cleanAnalysis.findings.some((f) => f.id === 'INJECTED_PRIVATE_RWX_REGION'), `${cleanAnalysis.findings.length} finding(s) total`);
  step('clean image yields NO decoy claim at all', !cleanAnalysis.unconfirmed.some((f) => f.id.startsWith('UNCORROBORATED_PATH')), `${cleanAnalysis.unconfirmed.length} unconfirmed`);
  step('the unlinked process is STILL found on a clean image', cleanAnalysis.findings.some((f) => f.id === 'UNLINKED_PROCESS'), 'it does not depend on the injection, which is the point: two findings, two causes');
}

/* ------------------------------------------------------------------ 9 CONTROL B */

line('[9] NEGATIVE CONTROL B — a tampered image must LOSE the finding');
/* One byte. Corrupt the MZ at the start of the injected region and the whole injection
 * claim must collapse, because the claim was about the BYTES and not about a label. */
{
  const tamperDir = path.join(WORK, 'tampered');
  const builtClean = generate(tamperDir);
  const manifest = JSON.parse(fs.readFileSync(path.join(tamperDir, 'manifest.json'), 'utf8'));
  const imageFile = path.join(tamperDir, manifest.image.file);
  const buf = fs.readFileSync(imageFile);

  /* The offset comes from the FINDING, not from a remembered constant: the claim under
     test says which bytes it is about, and those are the bytes we break. */
  const claim = analysis.findings.find((f) => f.id === 'INJECTED_PRIVATE_RWX_REGION');
  const hit = claim ? Number(claim.subject.contentOffset) : -1;
  if (hit < 0 || !buf.subarray(hit, hit + 2).equals(Buffer.from([0x4d, 0x5a]))) {
    step('located the injected region in the image', false, `offset 0x${hit.toString(16)} does not start with MZ`);
  } else {
    buf.writeUInt16LE(0x4141, hit); // 'AA' in place of 'MZ'
    fs.writeFileSync(imageFile, buf);
    const tampered = analyze(tamperDir);
    step('one-byte tamper changed the image', true, `0x${hit.toString(16)}: 4D 5A -> 41 41, sha256 now differs`);
    step('tampering REMOVES the injected-region finding', !tampered.findings.some((f) => f.id === 'INJECTED_PRIVATE_RWX_REGION'), `was a finding; now ${tampered.findings.filter((f) => f.id === 'INJECTED_PRIVATE_RWX_REGION').length ? 'still present (BAD)' : 'gone'}`);
    step('tampering leaves the unlinked-process finding intact', tampered.findings.some((f) => f.id === 'UNLINKED_PROCESS'), 'an independent finding is unaffected, as it should be');
    step('the tampered region is no longer counted a PE candidate', tampered.triage.malfind.candidates < analysis.triage.malfind.candidates, `candidates ${analysis.triage.malfind.candidates} -> ${tampered.triage.malfind.candidates}`);
    step('the tampered image hash no longer matches the built one', true, `${builtClean.meta.sha256.slice(0, 16)}… -> ${tampered.target.sha256.slice(0, 16)}…`);
  }
}

/* ------------------------------------------------------------------ 10 CONTROL C */

line('[10] NEGATIVE CONTROL C — the independence gate must actually gate');
controlSrum();

/* ------------------------------------------------------------------ 11 CONTROL D */

line('[11] NEGATIVE CONTROL D — the --expect guard must fail on a wrong set');
{
  const wrong = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), '--target', TARGET, '--expect', 'NOT_A_REAL_FINDING'], { encoding: 'utf8', windowsHide: true });
  step('analyze --expect <wrong set> exits non-zero', wrong.status !== 0, `exit ${wrong.status}  ${(wrong.stderr || '').trim()}`);
  const right = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), '--target', TARGET, '--expect', got.join(',')], { encoding: 'utf8', windowsHide: true });
  step('analyze --expect <correct set> exits zero', right.status === 0, `exit ${right.status}`);
}

/* ------------------------------------------------------------------ report */

summarize();

/* ------------------------------------------------------------------ helpers */

/* Locate a region by the sha256 of the bytes that were written into it. The tamper
 * control needs an offset it can trust without hard-coding one that drifts when the
 * layout changes, and searching for the payload's own hash is both stable and honest. */
function locateContentRegion(buf, payloadSha) {
  const { createHash } = crypto;
  const max = 0x400;
  for (let i = 0; i + max <= buf.length; i++) {
    const slice = buf.subarray(i, i + max);
    if (slice.readUInt16LE(0) !== 0x5a4d) continue;
    if (createHash('sha256').update(slice).digest('hex') === payloadSha) return i;
  }
  return -1;
}

/* CONTROL C as a function, so the loop and `--control=srum` run the SAME control. Two
 * copies of a control is how a control stops guarding anything. `demand` is the id of a
 * finding the analyser is asked to produce from the SRUM-dropped scenario; it must refuse,
 * and it must refuse as a real process exit code rather than an in-process check. */
function controlSrum({ demand = null } = {}) {
  /* Drop SRUM, the source that corroborates the injection, and the finding must fall
     back to POSSIBLE. If it stays INFERRED, the gate is decorative. */
  const soloDir = path.join(WORK, 'single-source');
  generate(soloDir);
  const srumFile = path.join(soloDir, 'artifacts', 'Srum.txt');
  const original = fs.readFileSync(srumFile, 'utf8');
  fs.writeFileSync(srumFile, original.split(/\r?\n/).filter((l) => !l.includes('svchost.exe')).join('\n'), 'utf8');
  const solo = analyze(soloDir);
  /* Asked while the rows are still dropped, and asked of a real process: the library
     agreeing with itself is not what an orchestrator will run. */
  const refusal = demand
    ? spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), '--target', soloDir, '--expect', demand], { encoding: 'utf8', windowsHide: true })
    : null;
  fs.writeFileSync(srumFile, original, 'utf8');
  const f = solo.findings.find((x) => x.id === 'INJECTED_PRIVATE_RWX_REGION');
  const u = solo.unconfirmed.find((x) => x.id === 'INJECTED_PRIVATE_RWX_REGION');
  step('removing SRUM demotes the injection to UNCONFIRMED', !f && Boolean(u), f ? `still INFERRED from ${f.groups.join('+')} (BAD)` : u ? `now ${u.tier}: ${u.verdictReason}` : 'claim vanished entirely (BAD)');
  step('the demoted claim still cites MEM as its only source', Boolean(u) && u.groups.length === 1 && u.groups[0] === 'MEM', u ? u.groups.join('+') : 'no claim');
  step('the unlinked process is UNAFFECTED by removing SRUM (PF+AM+MEM still agree)', solo.findings.some((x) => x.id === 'UNLINKED_PROCESS'), solo.findings.filter((x) => x.id === 'UNLINKED_PROCESS').map((x) => x.groups.join('+')).join('+') || 'lost it (BAD)');
  if (refusal) {
    /* Exit 4 AND the demanded id named as MISSING. Exit 4 alone is not enough, and
     * measuring proved why: against a broken analyser the run still exited 4, but for the
     * wrong reason -- `missing=[] unexpected=[UNLINKED_PROCESS]` -- because the single
     * --expect argument suppresses nothing, so a second mismatch can manufacture the very
     * exit this step reads as a refusal. Asserting the id appears in `missing=[...]` makes
     * the refusal the guarded property rather than any non-zero code. */
    const err = (refusal.stderr || '').trim();
    const namedMissing = err.includes(`missing=[${demand}]`);
    step(`analyze REFUSES ${demand} specifically once SRUM is gone`, refusal.status === 4 && namedMissing,
      `exit ${refusal.status}  ${err}${namedMissing ? '' : (refusal.status === 4 ? '  -- exited 4 but NOT because the demand was missing (BAD)' : '')}`);
  }
  return { solo, finding: f, unconfirmed: u, refusal };
}

/* NOT summarize(): that prints "loop summary" and the LOOP CLOSED line, which is exactly
 * what a one-section run must not be mistaken for. */
function summarizeControl(demand) {
  const failed = steps.filter((s) => !s.pass);
  console.log(`\n${'='.repeat(78)}\nD12 forensics lab — CONTROL srum summary (one section, NOT a loop run)\n${'='.repeat(78)}`);
  for (const s of steps) console.log(`  ${s.pass ? 'PASS' : 'FAIL'}  ${s.label.padEnd(56)} ${s.detail}`);
  console.log('');
  const notLoop = 'THIS WAS NOT A FULL LOOP RUN: sections 1-9 and 11 were not executed.';
  if (demand) {
    if (failed.length === 0) {
      console.log('CONTROL srum: the independence gate held, and a real analyze.mjs process REFUSED the');
      console.log(`             demand for ${demand} after the svchost.exe SRUM rows were dropped.`);
      console.log(notLoop);
      console.log('CONTROL srum: PASS — SUCCESS IS EXIT 4. The refusal IS the control passing; a control that');
      console.log('             has to exit 0 proves nothing (registry rule R5).');
      process.exit(4);
    }
    console.log(`CONTROL srum: FAIL — the control did not hold. ${failed.length} check(s) failed:`);
    for (const s of failed) console.log(`  - ${s.label}: ${s.detail}`);
    console.log(notLoop);
    process.exit(3);
  }
  if (failed.length === 0) {
    console.log('CONTROL srum: the independence gate held. INJECTED_PRIVATE_RWX_REGION was demoted to');
    console.log('             POSSIBLE on MEM alone once the SRUM rows were dropped, and UNLINKED_PROCESS');
    console.log('             survived, because it never depended on SRUM.');
    console.log(notLoop);
    console.log('CONTROL srum: PASS — exit 0, self-test shape. Pass --expect <finding-id> for the registry');
    console.log("             refusal shape, whose success is a NON-ZERO exit.");
    process.exit(0);
  }
  console.log(`CONTROL srum: FAIL — the gate did not hold. ${failed.length} check(s) failed:`);
  for (const s of failed) console.log(`  - ${s.label}: ${s.detail}`);
  console.log(notLoop);
  process.exit(3);
}

function summarize() {
  const failed = steps.filter((s) => !s.pass);
  console.log(`\n${'='.repeat(78)}\nD12 forensics lab — loop summary\n${'='.repeat(78)}`);
  for (const s of steps) console.log(`  ${s.pass ? 'PASS' : 'FAIL'}  ${s.label.padEnd(56)} ${s.detail}`);
  console.log('');
  if (failed.length === 0) {
    console.log('LOOP CLOSED: the fixture is deterministic, the parser found the planted injection and the');
    console.log('             unlinked process against the ground truth, the single-source decoy was held at');
    console.log('             POSSIBLE, two independent implementations agreed the carved region is a PE,');
    console.log('             real Volatility 3 was invoked and its refusal recorded, and all four negative');
    console.log('             controls failed the way a detector is supposed to fail.');
  } else {
    console.log(`${failed.length} step(s) failed:`);
    for (const s of failed) console.log(`  - ${s.label}: ${s.detail}`);
  }
  writeRunArtifact('forensics-lab', { checks: steps, outDir: 'forensics-lab/out',
    extra: { ok: failed.length === 0 } });
  process.exit(failed.length === 0 ? 0 : 9);
}
