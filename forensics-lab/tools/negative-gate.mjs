#!/usr/bin/env node
/* negative-gate.mjs — THE EXECUTABLE NEGATIVE CONTROL for forensics.memory.artefact.
 * Added 2026-10-05.
 *
 * WHY THIS FILE EXISTS. `tools/analyze.mjs` holds the lab's one rule:
 *
 *     a single artifact lies; a conclusion needs two or more INDEPENDENT sources
 *
 * and the rule is enforced in one place, `tierFor()` in analyze.mjs. That rule is UNFALSIFIABLE
 * by running the happy path. `loop.mjs` proves the rule promotes things: INJECTED_PRIVATE_RWX_REGION
 * comes out INFERRED with two source groups. But a rule that always returns INFERRED produces
 * exactly that same output, forever, and a green loop. A capability whose rule has only ever been
 * observed on its agreeing input has not been tested at all.
 *
 * So this file runs the rule on the SAME evidence with ONE INDEPENDENT SOURCE REMOVED and demands
 * the verdict DEGRADE. That is the mutation the loop never made in this shape.
 *
 * WHAT "INDEPENDENT SOURCE" MEANS IN THIS LAB — read this before changing anything here.
 * It is NOT a file. It is not a timestamp, not a host, not an offset, not a hash. It is a source
 * GROUP, and `triage.mjs` names four of them: MEM (the image, read by pslist / psscan / malfind /
 * netscan / handlescan — five plugins, ONE source), AM (Amcache-shaped TSV), PF (the prefetch .pf
 * files — seven files, ONE source), SRUM (SRUM-shaped TSV). `tierFor()` collapses a claim's
 * `support` entries on the `<GROUP>:` prefix and counts DISTINCT groups. Two prefetch files are one
 * source; six tools reading one image are one source. That is the whole lesson of the lab, and it
 * is exactly what makes this gate able to fail: the baseline claim carries THREE support entries
 * that collapse to TWO groups, so an analyser counting entries instead of groups is caught by the
 * baseline assertion alone, before any mutation.
 *
 * WHAT IS ACTUALLY REMOVED. SRUM is dropped from the evidence for PID 4120's image path by
 * deleting the `svchost.exe` rows from the generated `artifacts/Srum.txt`. Nothing else is touched:
 * the image bytes, the Amcache TSV and all seven prefetch files are byte-identical between the two
 * runs, and this file PROVES that by hashing every artifact on both sides and comparing. That is
 * what "one independent source removed" has to mean to be worth measuring — if any other byte
 * differed, the verdict could have moved for a reason that has nothing to do with triangulation.
 *
 * EXIT POLARITY — read this too, it is the opposite of what it looks like. Rule R5 refuses a
 * negative control that expects exit 0, because an instrument that had stopped enforcing entirely
 * would also exit 0 and the harness would read that as a pass. So the refusal IS the control
 * passing:
 *
 *   exit 4 = the single-source artefact was REFUSED confirmation. THE CONTROL WORKING.
 *   exit 0 = the single-source artefact was still reported as confirmed. THE CONTROL FOUND A REAL
 *            DEFECT: an artefact corroborated by one source is claiming a conclusion it cannot
 *            support. This is the state that must be reachable, or the gate is decoration.
 *   exit 2 = the gate could not MEASURE (the analyser failed, the fixture changed shape, the
 *            subprocess would not run). Kept distinct from 4 on purpose: an unmeasurable gate must
 *            never be able to satisfy an `expect_exit: 4`, and must never be mistaken for the bug.
 *
 * The polarity is not a guess. `manifests/capabilities.json` already records this convention for
 * this capability ("SUCCESS IS EXIT 4"), web-reverse/tools/negative-gate.mjs set it first, and the
 * first version of THIS file had it the intuitive way round.
 *
 * RUN IT:  node forensics-lab/tools/negative-gate.mjs          (no arguments)
 * Guards:   D12_FORENSICS_NEGGATE_WORK overrides the scratch directory.
 *
 * WHAT IT DELIBERATELY DOES NOT CLAIM. Exit 4 means the corroboration rule demoted one artefact.
 * It does not mean the finding is wrong — UNLINKED_PROCESS is asserted to SURVIVE the same removal
 * precisely so this cannot be confused with a rule that simply deletes things when a file changes.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { generate } from '../lab/mkimage.mjs';
import { analyze, MIN_INDEPENDENT_SOURCES, TIER } from './analyze.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ANALYZE = path.join(HERE, 'analyze.mjs');

/* The claim under test. Named, not discovered, because a control that hunts for whichever claim
 * happens to degrade is measuring nothing: it would pass on a fixture where nothing degrates.
 * INJECTED_PRIVATE_RWX_REGION is the lab's canonical two-group claim (MEM + SRUM) whose whole
 * reason for existing is that SRUM corroborates what the image alone only suggests. */
const SUBJECT = 'INJECTED_PRIVATE_RWX_REGION';

/* The corroborating group that gets removed. SRUM, not AM or PF, because SRUM is the ONLY group
 * this claim draws on outside MEM: remove AM or PF and the claim is unaffected, so the gate would
 * measure nothing and pass for the wrong reason. */
const REMOVED_GROUP = 'SRUM';

/* Per-process scratch, never a fixed path — the mobile-lab lesson in this project's own memory:
 * a fixed scratch path plus a destructive first step is how two runs collide. */
const WORK = process.env.D12_FORENSICS_NEGGATE_WORK || path.join(os.tmpdir(), `d12-forensics-neg-gate-${process.pid}`);

/* ARGUMENT REFUSAL. Exit 2, deliberately DISTINCT from the 4 above.
 *
 * Measured 2026-10-05: this gate was shipped without a guard, and
 * `node forensics-lab/tools/negative-gate.mjs --bogus` produced output byte-identical to the
 * no-argument run apart from the random scratch-directory name — the argument was silently
 * ignored. That is the same defect this session removed from five lab loops, in mirror image:
 * those refused every legitimate flag, this one refuses no flag at all. Both fail in the
 * direction nobody tests, and both look correct to a reader who only checks the exit code.
 *
 * It must NOT exit 4 here. 4 means "the corroboration rule refused a genuine single-source
 * artefact" — a real finding. 2 means "I could not measure". Collapsing them would let an
 * unmeasurable gate read as a passing control, which is precisely what a negative control
 * must never do.
 */
const ALLOWED = new Set([]);   // no arguments are honoured; declared empty rather than omitted
const STRAY = process.argv.slice(2).filter((a) => !ALLOWED.has(a));
if (STRAY.length) {
  console.error(`negative-gate.mjs: refusing argument(s) it would otherwise IGNORE: ${STRAY.join(' ')}`);
  console.error('  This gate takes no arguments. A gate that quietly accepts one it cannot');
  console.error('  honour reports a pass for work nobody did.');
  console.error('  Its subject, the source group it removes and the threshold it tests are constants');
  console.error('  above, on purpose: a control whose inputs are caller-supplied can be aimed at');
  console.error('  evidence that trivially passes. It has no --target and no --expect of its own —');
  console.error('  it spawns a real analyze.mjs process to ask for the refusal, so the refusal cannot');
  console.error('  be aimed either.');
  process.exit(2);
}
const FULL = path.join(WORK, 'two-sources');
const SOLO = path.join(WORK, 'one-source');

const checks = [];
function check(label, pass, detail) {
  checks.push({ label, pass, detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label.padEnd(62)} ${detail}`);
}
const line = (s = '', n = 78) => console.log(`${'-'.repeat(n)}\n${s}\n${'-'.repeat(n)}`);
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

/* sha of every artifact file, keyed by name. Comparing the two maps is how "the SAME evidence set
 * with one independent source removed" stops being a claim and becomes a measurement: if anything
 * other than Srum.txt differs, the verdict movement is not attributable to triangulation. */
function artifactHashes(dir) {
  const adir = path.join(dir, 'artifacts');
  const out = new Map();
  for (const name of fs.readdirSync(adir).sort()) out.set(name, sha256(fs.readFileSync(path.join(adir, name))));
  return out;
}


console.log('D12 forensics lab — NEGATIVE GATE for the corroboration rule.');
console.log('  subject        ' + SUBJECT);
console.log(`  rule           >= ${MIN_INDEPENDENT_SOURCES} independent source GROUPS; tiers ${Object.values(TIER).join(', ')}`);
console.log(`  removal        source GROUP ${REMOVED_GROUP} (the only group this claim draws on outside MEM)`);
console.log(`  work           ${WORK}\n`);

let exitCode = 2; /* until a measurement exists at all */
let degraded = null; /* the verdict transition, or null if there was none to see */

try {
  /* ---------------------------------------------------------------- the two evidence sets */
  line('[1] BUILD — the same target twice, once whole and once with one source removed');
  generate(FULL);
  generate(SOLO);

  /* SRUM rows for PID 4120's image path are the corroboration. Deleting them removes the SRUM
   * GROUP from this claim's support without touching the image or any other artefact. This is the
   * same real mutation loop.mjs section [10] makes, done here as a standalone control that does not
   * depend on the loop's eleven sections all passing. */
  const srumFile = path.join(SOLO, 'artifacts', 'Srum.txt');
  const srumText = fs.readFileSync(srumFile, 'utf8');
  const kept = srumText.split(/\r?\n/).filter((l) => !l.startsWith('C:\\Windows\\System32\\svchost.exe'));
  const dropped = srumText.split(/\r?\n/).filter((l) => l.startsWith('C:\\Windows\\System32\\svchost.exe'));
  if (!dropped.length) {
    throw new Error(`fixture changed: no ${REMOVED_GROUP} row for the injected process in Srum.txt, so nothing was removed and this gate would pass without testing anything`);
  }
  fs.writeFileSync(srumFile, kept.join('\n'), 'utf8');
  console.log(`  removed ${dropped.length} SRUM row(s):`);
  for (const d of dropped) console.log(`    - ${d}`);
  console.log(`  ${kept.filter((l) => l && !l.startsWith('#')).length} SRUM rows remain\n`);

  /* ---------------------------------------------------------------- [2] the evidence really is the same, minus one source */
  line('[2] EVIDENCE — prove the two sets differ in one artefact and nothing else');
  const hFull = artifactHashes(FULL);
  const hSolo = artifactHashes(SOLO);
  const allNames = [...new Set([...hFull.keys(), ...hSolo.keys()])].sort();
  const changed = allNames.filter((n) => hFull.get(n) !== hSolo.get(n));
  const same = allNames.filter((n) => hFull.get(n) === hSolo.get(n)).length;

  check('exactly one artefact file differs between the two runs',
    changed.length === 1 && changed[0] === 'Srum.txt',
    `changed=[${changed.join(', ')}]  identical=${same}  (${allNames.length} total)`);
  /* The image lives outside artifacts/, so artifactHashes() cannot see it. Read its real name out
   * of the manifest rather than globbing: a hard-coded filename would silently compare "" to ""
   * and pass, which is the shape this whole file exists to reject. */
  const imgName = JSON.parse(fs.readFileSync(path.join(FULL, 'manifest.json'), 'utf8')).image.file;
  const imgFull = sha256(fs.readFileSync(path.join(FULL, imgName)));
  const imgSolo = sha256(fs.readFileSync(path.join(SOLO, imgName)));
  check('the memory image is byte-identical in both runs (same artefact, fewer sources)',
    imgFull === imgSolo,
    `${imgName}  sha256 ${imgFull.slice(0, 32)}...  identical=${imgFull === imgSolo}`);
  console.log(`  note  Amcache, all ${[...hFull.keys()].filter((n) => n.endsWith('.pf')).length} prefetch files and the image are byte-identical; only Srum.txt lost its svchost.exe rows.\n`);

  /* ---------------------------------------------------------------- [3] analyse both, in one process */
  line('[3] ANALYSE — same analyser, same run, two evidence sets');
  const fullRun = analyze(FULL);
  const soloRun = analyze(SOLO);
  if (!fullRun.ok) throw new Error(`analyze(${FULL}) refused: ${fullRun.error}`);
  if (!soloRun.ok) throw new Error(`analyze(${SOLO}) refused: ${soloRun.error}`);

  const pick = (r) => r.findings.find((c) => c.id === SUBJECT) ?? r.unconfirmed.find((c) => c.id === SUBJECT) ?? null;
  const before = pick(fullRun);
  const after = pick(soloRun);

  if (!before) throw new Error(`${SUBJECT} is not in the two-source run's findings or unconfirmed set — the fixture changed shape and this gate no longer tests anything`);
  if (!after) throw new Error(`${SUBJECT} VANISHED entirely once ${REMOVED_GROUP} was removed. A claim that disappears is not a claim that was demoted: a gate that called that a pass would be measuring the wrong property.`);

  console.log(`  BEFORE  ${before.verdict.padEnd(10)} ${before.tier.padEnd(9)} groups=[${before.groups.join(', ')}]  n=${before.independentSources}`);
  for (const s of before.support) console.log(`            support  ${s}`);
  console.log(`  AFTER   ${after.verdict.padEnd(10)} ${after.tier.padEnd(9)} groups=[${after.groups.join(', ')}]  n=${after.independentSources}`);
  for (const s of after.support) console.log(`            support  ${s}`);
  console.log();

  /* ---------------------------------------------------------------- [4] the rule, asserted */
  line('[4] THE RULE — what counts as independent, measured rather than assumed');

  /* The load-bearing assertion about the JUDGEMENT being tested. This claim is supported by THREE
   * entries — two from MEM, one from SRUM — and independence is 2. An analyser counting evidence
   * ENTRIES would report 3 here and the gate would fail on its baseline, before any mutation. This
   * is why "independent source" cannot mean "file" or "tool" in this lab. */
  check('independence counts source GROUPS, not evidence entries',
    before.independentSources === before.groups.length && before.independentSources < before.support.length,
    `${before.support.length} support entries collapse to ${before.groups.length} groups (${before.groups.join('+')}) — two MEM entries are ONE source`);

  check(`the two-source run CONFIRMS ${SUBJECT}`,
    before.verdict === 'FINDING' && before.tier === TIER.INFERRED && before.independentSources >= MIN_INDEPENDENT_SOURCES,
    `${before.verdict}/${before.tier} on ${before.independentSources} independent sources`);

  /* THE MEASUREMENT. confirmed -> possible. Not "the verdict changed": the specific transition the
   * capability's negative_control promises, with the specific group count that caused it. */
  degraded = before.tier === TIER.INFERRED && after.tier === TIER.POSSIBLE
    && after.independentSources === before.independentSources - 1
    && !soloRun.findings.some((c) => c.id === SUBJECT);

  check(`removing source GROUP ${REMOVED_GROUP} degrades ${SUBJECT} from confirmed to possible`,
    degraded,
    `${before.tier} (${before.groups.join('+')}, n=${before.independentSources})  ->  ${after.tier} (${after.groups.join('+')}, n=${after.independentSources})`);

  check(`the demoted claim still EXISTS and cites only ${after.groups.join('+')}`,
    after.groups.length === 1 && after.groups[0] !== REMOVED_GROUP && after.tier === TIER.POSSIBLE,
    `${after.verdict}: ${after.verdictReason}`);

  /* It must be demoted, not deleted. A rule that erases a claim when an artefact changes is not
   * triangulating, and a gate that cannot tell those apart is measuring the wrong property. */
  const survivor = soloRun.findings.find((c) => c.id === 'UNLINKED_PROCESS');
  check('an unrelated 4-group claim SURVIVES the same removal (triangulating, not deleting)',
    Boolean(survivor),
    survivor ? `UNLINKED_PROCESS still ${survivor.verdict} on [${survivor.groups.join(', ')}] n=${survivor.independentSources}` : 'UNLINKED_PROCESS was lost too — the rule is deleting claims, not triangulating them');

  /* ---------------------------------------------------------------- [5] a real process must refuse */
  line('[5] PROCESS — the same question asked of a real analyze.mjs process, not of the library');
  console.log('  A library agreeing with itself is not what an orchestrator runs. The demand below is');
  console.log(`  the capability's own: ask analyze.mjs to CONFIRM ${SUBJECT} while ${REMOVED_GROUP} is gone.\n`);

  const refusal = spawnSync(process.execPath,
    [ANALYZE, '--target', SOLO, '--expect', SUBJECT],
    { encoding: 'utf8', windowsHide: true });
  const err = (refusal.stderr || '').trim();
  console.log(`  $ node analyze.mjs --target <one-source> --expect ${SUBJECT}`);
  console.log(`  exit ${refusal.status}`);
  if (err) console.log(`  stderr  ${err}`);
  console.log(`  stdout  ${(refusal.stdout || '').trim().split(/\r?\n/).filter((l) => l.includes(SUBJECT)).join(' | ') || '(the demand is not restated; the id is absent from the findings)'}\n`);

  /* Exit 4 alone is NOT enough, and loop.mjs records why in its own comment: against a broken
   * analyser the run still exited 4 for the WRONG reason — `unexpected=[UNLINKED_PROCESS]` — because
   * a single --expect argument suppresses nothing, so a second mismatch can manufacture the very
   * exit this reads as a refusal. Asserting the id appears in `missing=[...]` makes the REFUSAL the
   * guarded property instead of any non-zero code. */
  const namedMissing = /missing=\[([^\]]*)\]/.exec(err);
  const missingIds = namedMissing ? namedMissing[1].split(',').map((s) => s.trim()).filter(Boolean) : [];
  const unexpectedIds = /unexpected=\[([^\]]*)\]/.exec(err)?.[1].split(',').map((s) => s.trim()).filter(Boolean) ?? [];

  check(`a real analyze.mjs process REFUSES to confirm ${SUBJECT}`,
    refusal.status === 4 && missingIds.includes(SUBJECT) && !unexpectedIds.includes(SUBJECT),
    `exit ${refusal.status}  missing=[${missingIds.join(', ')}]  unexpected=[${unexpectedIds.join(', ')}]` +
    (refusal.status === 4 && !missingIds.includes(SUBJECT) ? '  -- exited 4 but NOT because this demand was missing (BAD)' : ''));

  /* ---------------------------------------------------------------- verdict */
  line('[6] VERDICT');
  if (degraded && missingIds.includes(SUBJECT)) {
    console.log('NEGATIVE GATE: the corroboration rule is LIVE and it was shown refusing.');
    console.log(`  Fed the lab's own two-source evidence set for ${SUBJECT}, then removed ONE`);
    console.log(`  independent source group (${REMOVED_GROUP}) and nothing else — same image bytes, same`);
    console.log('  Amcache, same prefetch files. The claim fell from INFERRED (confirmed, on MEM + SRUM)');
    console.log('  to POSSIBLE (one source, MEM), and a real analyze.mjs process REFUSED to confirm it,');
    console.log(`  naming it in missing=[...] rather than failing on some other mismatch.`);
    console.log('');
    console.log('  The judgement under test: an independent source is a GROUP (MEM / AM / PF / SRUM),');
    console.log('  not a file, a tool, a timestamp, a host, an offset or a hash. The claim that');
    console.log('  degraded carried 3 evidence entries from 2 groups and stayed uncorroborated by one');
    console.log('  group — which is why five prefetch files and six plugins on one image are one source each.');
    console.log('');
    console.log('  SUCCESS IS EXIT 4. The refusal IS the control passing; a control that has to exit 0');
    console.log('  proves nothing. Exit 0 here means the rule did not refuse — either it confirmed a');
    console.log('  single-source artefact, or it never confirmed the two-source one. Both are defects;');
    console.log('  the verdict block below says which.');
    exitCode = 4;
  } else if (degraded === false) {
    /* Both ways of failing the measurement exit 0, because 0 is "the gate did not witness the rule
     * refusing", and this file's whole claim is that the refusal is the control. But the two
     * failure modes are DIFFERENT BUGS and an earlier version of this file reported both as "a
     * single-source artefact was still CONFIRMED" — which is false for the second one. A gate that
     * misreports which defect it found is the same defect wearing a message. */
    const stayedConfirmed = after.tier === TIER.INFERRED;
    console.log(stayedConfirmed
      ? 'NEGATIVE GATE FAILED: a single-source artefact was still CONFIRMED.'
      : 'NEGATIVE GATE FAILED: the rule never confirmed the two-source artefact, so the removal could not degrade it.');
    console.log(`  two-source run   ${before.verdict}/${before.tier} on [${before.groups.join(', ')}] n=${before.independentSources}`);
    console.log(`  one-source run   ${after.verdict}/${after.tier} on [${after.groups.join(', ')}] n=${after.independentSources}`);
    if (stayedConfirmed) {
      console.log(`  ${SUBJECT} kept INFERRED after ${REMOVED_GROUP} was removed. Either tierFor() no longer`);
      console.log(`  applies MIN_INDEPENDENT_SOURCES, or the threshold was lowered — a conclusion`);
      console.log('  corroborated by ONE source is claiming something its evidence cannot support.');
    } else {
      /* Count the groups from the PREFIXES, not from `before.groups` — under this very mutation
       * `groups` holds whole entries, so quoting it would print "3 entries should have collapsed
       * to 3 groups", a sentence that argues for the bug it is reporting. */
      const trueGroups = [...new Set(before.support.map((s) => s.split(':')[0]))].sort();
      console.log(`  the two-source run was fed ${before.support.length} evidence entries carrying`); 
      console.log(`  ${trueGroups.length} distinct GROUP prefixes [${trueGroups.join(', ')}], and independence`);
      console.log('  was not counted over those prefixes. tierFor() is counting evidence ENTRIES');
      console.log('  instead of GROUPS — the mistake this lab exists to reject, because it makes one');
      console.log('  image read by six plugins look like six independent sources. The rule is too STRICT');
      console.log('  to be measured here, which is a different defect from confirming an uncorroborated claim.');
    }
    console.log('');
    console.log('  EXIT 0 IS THE GREEN-FAILURE STATE, NOT A PASS. R5 requires the control to declare a');
    console.log('  non-zero expect_exit precisely so that "the instrument stopped enforcing" cannot read');
    console.log('  as a pass. This state has to be reachable, or the gate is decoration.');
    exitCode = 0;
  } else {
    console.log('NEGATIVE GATE COULD NOT MEASURE: the verdict moved, but a real analyze.mjs process did');
    console.log(`  not refuse ${SUBJECT} by name (exit ${refusal.status}, missing=[${missingIds.join(', ')}]).`);
    console.log('  The transition in [3] is real but unattributable to the rule, so no verdict is claimed.');
    exitCode = 2;
  }
} catch (e) {
  console.log(`\nNEGATIVE GATE COULD NOT MEASURE: ${e.message}`);
  console.log('  Exit 2 is deliberately distinct from 4: an unmeasurable gate must never satisfy an');
  console.log('  expect_exit: 4, and must never be mistaken for the bug it is looking for.');
  exitCode = 2;
} finally {
  console.log(`\n  work dir  ${WORK}`);
}

process.exit(exitCode);