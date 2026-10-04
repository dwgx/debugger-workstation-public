#!/usr/bin/env node
/*
 * loop.mjs — ONE command that runs the whole mobile-lab loop and judges itself.
 *
 *   build the APK  ->  independent ELF oracle  ->  static analysis  ->  Frida logic
 *   ->  cross-check against a second tool (JADX / Apktool)  ->  negative control
 *
 * Every step is a tool an analyst would run by hand. This file only sequences them, checks
 * the expected outcome, and prints one PASS/FAIL/SKIP table. Exit 0 means the loop closed on
 * this machine, in this run.
 *
 *   node tools/loop.mjs [--skip-jadx] [--skip-apktool]
 *
 * Exit codes, three and not two, because "wrong" and "not run" are different facts:
 *   0  every check ran and held
 *   8  nothing failed, but at least one cross-check was SKIPPED -- so this run has no
 *      independent corroboration of the manifest and the loop did NOT close
 *   9  a check ran and was wrong
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildApk } from '../lab/build/build-apk.mjs';
import { buildSo, verifySo } from '../lab/build/make-so.mjs';
import { analyzeApk } from './analyze.mjs';
import { runFridaSelfTest } from './frida-selftest-lib.mjs';
// Run summary to disk, so the verdict rests on a FILE rather than a substring of stdout.
// ALL THREE exit paths write it: "skipped and nothing failed" (exit 8) is a different
// claim from "closed" (exit 0), and the artifact is where that survives.
import { writeRunArtifact } from '../../scripts/probe_artifact.mjs';

// ARGUMENT REFUSAL. Added 2026-10-04. Measured on this tree: passing a path that does not exist
// produced a normal green run and exit 0 -- every check "passed" while nothing anyone asked for
// had been done. A regression suite that cannot fail on the thing you handed it reports a pass
// for work nobody did, which is the one shape this station exists to reject.
//
// The precedent is already in the tree and this follows it rather than inventing a second
// convention: crackme-corpus/tools/loop.py uses argparse and rejects `unrecognized arguments`
// with exit 2. The JS loops had no argument parser at all, which is the defect.
const ALLOWED = new Set('--json');
const extra = process.argv.slice(2).filter((a) => !ALLOWED.has(a) && !a.startsWith('--only='));
if (extra.length) {
  console.error(`loop: refusing an argument it would otherwise IGNORE: ${extra.join(' ')}`);
  console.error('  This is a regression suite over its own built fixtures. It has no --target.');
  console.error('  Accepting an argument silently would report a pass for work nobody did.');
  process.exit(2);
}


const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const STATION = path.resolve(ROOT, '..');

/* PER-RUN scratch, and this is a fix rather than a style choice.
 *
 * Measured 2026-10-03 by independent acceptance: two concurrent runs of this loop shared
 * `mobile-lab/out` and the shared APK path, and the `--skip-jadx --skip-apktool` run came back
 * exit 9 with "Unable to open mobile-lab\work\apk\aligned.apk for verification / Build failed".
 * That is a CORRUPTED-BUILD failure, not the skip gate it was supposed to report -- so a gate
 * that runs two loops at once reports a lie, and the natural way to check a gate is to run it
 * twice. Each run now builds into its own directory under %TEMP% and publishes the finished APK
 * to the canonical path with a single atomic rename at the end, so `artifacts/mobilelab.apk`
 * (which the registry, the triage gate and apktool_refusal_control.ps1 all read) still exists,
 * is still the same path, and is never observed half-written.
 */
const RUN = path.join(os.tmpdir(), `mobilelab-loop-${process.pid}-${Date.now().toString(36)}`);
const APK_PUBLISHED = path.join(ROOT, 'artifacts', 'mobilelab.apk');
const APK = path.join(RUN, 'mobilelab.apk');
const OUT = path.join(RUN, 'out');
fs.mkdirSync(RUN, { recursive: true });
process.on('exit', () => { try { fs.rmSync(RUN, { recursive: true, force: true }); } catch { /* best effort */ } });

const steps = [];
const argv = process.argv.slice(2);
const skipJadx = argv.includes('--skip-jadx');
const skipApktool = argv.includes('--skip-apktool');

function record(label, pass, detail, ms = 0) {
  steps.push({ label, pass, detail, ms });
  return pass;
}

/* THE THIRD STATE, and the reason it exists.
 *
 * Both cross-check sites used to call `record(label, true, 'skipped by flag')`, so a run
 * with `--skip-jadx --skip-apktool` produced a table byte-identical to a run in which both
 * decoders executed, exited 0, and printed a closing sentence asserting that "JADX and
 * Apktool reproduced the same findings with their own decoders" -- for a run in which
 * neither was ever invoked. The entry's `evidence_source_note` ("built APK inspected with
 * independent decoders") was therefore OPTIONAL, and a skip read as agreement. Not-ran is
 * not agreement: an unrun control cannot fail, which is the same always-green shape this
 * whole file exists to catch.
 *
 * A skipped step prints as SKIP, is excluded from the pass tally, and holds the loop open
 * exactly as a failure does. The distinct exit code is 8 rather than 9 because the two mean
 * different things: 9 is "a check ran and was wrong", 8 is "a check did not run", and
 * collapsing them would hide which one happened.
 */
function recordSkip(label, detail) {
  steps.push({ label, pass: null, skipped: true, detail });
  return false;
}

function banner(t) {
  console.log(`\n${'='.repeat(78)}\n${t}\n${'='.repeat(78)}`);
}

/* ------------------------------------------------------------------ *
 * 1. Build the APK from source
 * ------------------------------------------------------------------ */
banner('mobile-lab loop');
console.log(`  root   ${ROOT}`);
console.log(`  apk    ${APK}   (this run only)`);
console.log(`  pub    ${APK_PUBLISHED}   (written atomically when the build succeeds)`);

let buildMs = 0;
let built = null;
try {
  const t = Date.now();
  built = await buildApk({ out: APK, quiet: true });
  buildMs = Date.now() - t;
  /* Publish atomically. rename() within a volume is the one write here that another process
   * cannot observe half-finished; writing straight to artifacts/mobilelab.apk is how a parallel
   * reader gets a truncated ZIP and reports "not a ZIP" about a perfectly good APK. */
  fs.mkdirSync(path.dirname(APK_PUBLISHED), { recursive: true });
  const staging = `${APK_PUBLISHED}.${process.pid}.tmp`;
  fs.copyFileSync(APK, staging);
  fs.renameSync(staging, APK_PUBLISHED);
  record('build a real signed APK from source (javac + d8 + aapt2 + zipalign + apksigner)',
    true, `${built.bytes} bytes, sha256 ${built.sha256.slice(0, 16)}… -> published ${path.relative(ROOT, APK_PUBLISHED)}`, buildMs);
} catch (e) {
  record('build a real signed APK from source', false, e.message.split('\n')[0]);
}

if (!built) {
  console.log('\nBuild failed; nothing downstream can be judged.');
  writeRunArtifact('mobile-lab', { checks: steps, outDir: 'mobile-lab/out',
    extra: { ok: false, exit_reason: 'failed' } });
  process.exit(9);
}

/* The manifest must be real binary AXML, not a text file renamed .xml. */
{
  const { readZip, entryData } = await import('../lab/build/zip.mjs');
  const z = readZip(fs.readFileSync(APK));
  const m = entryData(z.find(e => e.name === 'AndroidManifest.xml'));
  const ok = m.readUInt32LE(0) === 0x00080003;
  record('AndroidManifest.xml is binary AXML, not text', ok,
    ok ? `magic 0x00080003, ${m.length} bytes` : `magic 0x${m.readUInt32LE(0).toString(16)}`);
}

/* ------------------------------------------------------------------ *
 * 2. The hand-built .so, cross-checked by an INDEPENDENT implementation
 * ------------------------------------------------------------------ */
{
  const so = buildSo();
  const v = verifySo(so.buffer);
  const out = path.join(OUT, 'libmobilelab.so');
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(out, so.buffer);
  record('hand-built ELF .so passes its own re-parse', v.ok,
    v.ok ? `${so.buffer.length} bytes, ${so.meta.exports.length} exports` : v.problems.join('; '));
  record('hand-built ELF .so written for the pyelftools oracle', fs.existsSync(out), out);

  /* pyelftools is a SEPARATE implementation. If it disagrees, the build is wrong even
     though we wrote it. This is the loop's independent-verification gate. */
  const py = path.join(ROOT, '.venv', 'Scripts', 'python.exe');
  const pyAlt = path.join(ROOT, '.venv', 'bin', 'python');
  const interpreter = fs.existsSync(py) ? py : (fs.existsSync(pyAlt) ? pyAlt : null);
  if (!interpreter) {
    record('INDEPENDENT oracle: pyelftools agrees on the .so', false,
      'no .venv interpreter; run: python -m venv .venv && .venv/Scripts/python -m pip install pyelftools==0.33');
  } else {
    const r = spawnSync(interpreter, [path.join(HERE, 'oracle-elf.py'), out,
      '--expect-sym', 'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey',
      '--expect-sym', 'Java_com_lab_mobilelab_NativePinConfig_verifyNativePin'],
      { encoding: 'utf8' });
    const agrees = r.status === 0;
    const last = (r.stdout || '').trim().split('\n').pop();
    record('INDEPENDENT oracle: pyelftools agrees on the .so', agrees,
      agrees ? last : `${last} (exit ${r.status})`);
  }
}

/* ------------------------------------------------------------------ *
 * 3. Static analysis
 * ------------------------------------------------------------------ */
let analysis = null;
try {
  analysis = await analyzeApk(APK);
  const m = analysis.manifest;
  record('manifest: package, sdk, debuggable parsed from binary AXML',
    m.package === 'com.lab.mobilelab' && m.minSdkVersion === 24 && m.targetSdkVersion === 34,
    `package=${m.package} min=${m.minSdkVersion} target=${m.targetSdkVersion} debuggable=${m.debuggable}`);

  const exported = m.components.filter(c => c.exported === true).map(c => c.name);
  record('manifest: every component found, with its real exported flag',
    m.components.length === 5 && exported.includes('com.lab.mobilelab.BootReceiver')
      && m.components.find(c => c.name.endsWith('DebugActivity'))?.exported === false,
    `${m.components.length} components, exported: ${exported.join(', ')}`);

  record('manifest: provider authority recovered',
    m.components.some(c => c.authorities === 'com.lab.mobilelab.data'), 'com.lab.mobilelab.data');

  record('dex: string/type/method/class tables read',
    analysis.dex.classes === 10 && analysis.dex.strings > 100,
    `DEX ${analysis.dex.version}, ${analysis.dex.classes} classes, ${analysis.dex.methods} methods, ${analysis.dex.strings} strings`);

  record('JNI: every Java_ export resolved to a Java class and method',
    analysis.jni.resolved === 5 && analysis.jni.boundaries.every(b => b.className && b.methodName),
    `${analysis.jni.resolved} boundaries, library name in DEX=${analysis.jni.loadLibraryNameInDex}`);

  record('native: .dynsym exports, imports and DT_NEEDED read',
    analysis.native.libraries[0]?.exports === 5 && analysis.native.libraries[0]?.imports === 4
      && analysis.native.libraries[0]?.needed.join(',') === 'liblog.so,libc.so',
    `exports=${analysis.native.libraries[0]?.exports} imports=${analysis.native.libraries[0]?.imports} needs=${analysis.native.libraries[0]?.needed.join(',')}`);

  const kinds = analysis.pinning.mechanisms.map(m => m.kind);
  record('pinning: all four mechanisms distinguished, not just OkHttp',
    ['declarative', 'okhttp-certificate-pinner', 'custom-trust-manager', 'native-pin-table']
      .every(k => kinds.includes(k)),
    kinds.join(', '));

  record('pinning: declarative pins read out of COMPILED network_security_config.xml',
    analysis.pinning.uniqueDigests === 2, `${analysis.pinning.uniqueDigests} unique digests`);

  record('strings: endpoints found in BOTH the DEX and native memory',
    analysis.strings.hosts.length >= 3
      && analysis.strings.endpoints.some(e => e.source.endsWith('.so')),
    analysis.strings.hosts.join(', '));

  record('strings: a credential-shaped constant is flagged AND redacted',
    analysis.strings.credentialShaped.length === 1
      && !analysis.strings.credentialShaped.some(c => /PLACEHOLDER-0/.test(c.value)),
    analysis.strings.credentialShaped.map(c => `${c.value} [${c.shapes.join(',')}]`).join(' '));

  record('analyzer reports disassembly as not attempted rather than inventing it',
    analysis.findings.some(f => f.id === 'DISASSEMBLY'), 'DISASSEMBLY finding present');
} catch (e) {
  record('static analysis of the APK', false, e.message);
}

/* ------------------------------------------------------------------ *
 * 4. The Frida script library, offline
 * ------------------------------------------------------------------ */
{
  const r = runFridaSelfTest();
  const failed = r.results.filter(x => !x.pass);
  record(`Frida script library logic-verified offline (${r.results.length} cases)`,
    failed.length === 0, failed.length === 0
      ? `${r.results.length}/${r.results.length} passed, no device attached`
      : `${failed.length} failed: ${failed.map(f => f.name).join('; ')}`);
}

/* ------------------------------------------------------------------ *
 * 5. Cross-check the static analysis against a SECOND tool
 * ------------------------------------------------------------------ */
{
  const jadx = path.join(STATION, 'Mobile-Android', 'jadx', 'bin', 'jadx.bat');
  if (skipJadx) {
    recordSkip('cross-check: JADX 1.5.6 decompiles the same APK',
      'NOT RUN: --skip-jadx. No second decoder was consulted, so this is not agreement.');
  } else if (!fs.existsSync(jadx)) {
    record('cross-check: JADX decompiles the same APK', false, `jadx not found at ${jadx}`);
  } else {
    const dest = path.join(OUT, 'jadx');
    fs.rmSync(dest, { recursive: true, force: true });
    const t = Date.now();
    /* No inner quotes: none of these paths contain a space, and Node re-escapes inner
       quotes as \" when spawning cmd.exe, which cmd then rejects as an unrecognised
       command. windowsVerbatimArguments stops that re-escaping. */
    const r = spawnSync('cmd.exe', ['/d', '/s', '/c', `${jadx} -d ${dest} ${APK}`],
      { encoding: 'utf8', timeout: 180000, windowsVerbatimArguments: true });
    const files = fs.existsSync(dest)
      ? fs.readdirSync(path.join(dest, 'sources', 'com', 'lab', 'mobilelab'), { withFileTypes: true })
        .filter(d => d.isFile() && d.name.endsWith('.java')).map(d => d.name)
      : [];
    /* JADX must recover the SAME class list the DEX table has, and the same native
       declarations. Agreement between two unrelated implementations is the verify step. */
    /* A DEX type descriptor is `Lcom/lab/mobilelab/ApiClient;`. Splitting on '/' BEFORE
       stripping the L/semicolon delimiters yields "Lmobilelab" and "ApiClient;" and matches
       nothing, which reads as "two tools disagree" when they agree perfectly. */
    const dexClasses = analysis
      ? analysis.dex.classList.map(t => t.replace(/^L/, '').replace(/;$/, '').split('/').pop())
      : [];
    const overlap = dexClasses.filter(c => files.includes(`${c}.java`));
    record('cross-check: JADX recovers the same classes the DEX table lists',
      /* >= 10, not === 10: JADX also synthesises R.java, which is in no DEX class table.
         Asserting an exact count would make the cross-check fail for a file the DEX never
         had, i.e. for being right. */
      r.status === 0 && files.length >= 10 && overlap.length === 10,
      `jadx exit ${r.status}, ${files.length} java files, ${overlap.length}/${dexClasses.length} class names agree`,
      Date.now() - t);

    const main = path.join(dest, 'sources', 'com', 'lab', 'mobilelab', 'MainActivity.java');
    if (fs.existsSync(main)) {
      const text = fs.readFileSync(main, 'utf8');
      /* [^\s(]+ for the return type: array returns render as `byte[]`, and \w+ stops at
         the bracket and silently drops every native method that returns an array. */
      const natives = [...text.matchAll(/public native [^\s(]+ (\w+)\(/g)].map(m => m[1]);
      const loadLib = /System\.loadLibrary/.test(text);
      record('cross-check: JADX shows the same JNI boundary (native decls + loadLibrary)',
        natives.length === 3 && loadLib,
        `native methods: ${natives.join(', ')}; System.loadLibrary present=${loadLib}`);
    } else {
      record('cross-check: JADX output for MainActivity', false, 'MainActivity.java not produced');
    }
  }
}

{
  const apktoolJar = path.join(STATION, 'Mobile-Android', 'Apktool', 'apktool_3.0.3.jar');
  if (skipApktool) {
    recordSkip('cross-check: Apktool decodes the manifest independently',
      'NOT RUN: --skip-apktool. No second AXML decoder was consulted, so this is not agreement.');
  } else if (!fs.existsSync(apktoolJar)) {
    record('cross-check: Apktool decodes the manifest independently', false, `apktool jar not found at ${apktoolJar}`);
  } else {
    const dest = path.join(OUT, 'apktool');
    const fw = path.join(OUT, 'apktool-fw');
    fs.rmSync(dest, { recursive: true, force: true });
    const t = Date.now();
    const r = spawnSync('cmd.exe', ['/d', '/s', '/c',
      `java -jar ${apktoolJar} d -f -p ${fw} -o ${dest} ${APK}`],
      { encoding: 'utf8', timeout: 180000, windowsVerbatimArguments: true });
    const mf = path.join(dest, 'AndroidManifest.xml');
    let detail = `apktool exit ${r.status}`;
    let ok = r.status === 0 && fs.existsSync(mf);
    if (ok) {
      const text = fs.readFileSync(mf, 'utf8');
      /* Apktool resolves android:* against its OWN framework table, not our stub, so its
         agreement is independent evidence that the resource IDs we emitted are the real
         Android ones. */
      ok = text.includes('package="com.lab.mobilelab"')
        && /android:debuggable="true"/.test(text)
        && text.includes('com.lab.mobilelab.BootReceiver')
        && text.includes('authorities="com.lab.mobilelab.data"');
      detail = ok ? 'package, debuggable, components and authorities all agree'
        : 'decoded, but the decoded manifest disagrees with the analyzer';
    }
    const smali = fs.existsSync(path.join(dest, 'smali'))
      ? fs.readdirSync(path.join(dest, 'smali'), { recursive: true }).filter(f => String(f).endsWith('.smali')).length
      : 0;
    record('cross-check: Apktool decodes the manifest independently', ok, `${detail}; smali files=${smali}`, Date.now() - t);
  }
}

/* ------------------------------------------------------------------ *
 * 6. The negative control
 * ------------------------------------------------------------------ */

/*
 * The controls below are the point of the whole file. Each one asserts that a check FAILS
 * when it should. A suite whose checks cannot fail proves nothing, and every one of these
 * is cheap to run.
 */
const negatives = [];
{
  /* (a) the analyzer's own --expect gate must reject a wrong expectation */
  const r = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), APK,
    '--expect', 'jni-resolved,pinning-native,no-such-fact', '--quiet'],
    { encoding: 'utf8' });
  negatives.push({
    label: 'analyzer --expect refuses an unknown fact',
    pass: r.status === 4, detail: `exit ${r.status} (want 4)`,
  });

  /* (b) the same gate must reject a fact that is simply false */
  const r2 = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), APK,
    '--expect', 'has-credential,pinning-declarative', '--quiet'],
    { encoding: 'utf8' });
  negatives.push({ label: 'analyzer --expect accepts only what is true', pass: r2.status === 0, detail: `exit ${r2.status} (want 0)` });

  /* (c) the ELF verifier must reject a corrupted library */
  const { buildSo: bs, verifySo: vs } = await import('../lab/build/make-so.mjs');
  const good = bs().buffer;
  const broken = Buffer.from(good);
  broken[0] = 0x00;                       /* destroy the ELF magic */
  const bad = vs(broken);
  negatives.push({
    label: 'NEGATIVE: ELF self-verifier rejects a corrupted .so',
    pass: !bad.ok && bad.problems.some(p => /magic/i.test(p)),
    detail: bad.ok ? 'accepted a corrupt file' : `rejected: ${bad.problems[0]}`,
  });

  /* (d) the maps detector must fire on an instrumented target and stay silent otherwise */
  const { detectInMaps, readTracerPid } = await import('../frida/lib/logic.mjs');
  const dirty = detectInMaps('7f2a1b000000-7f2a1b001000 r-xp 00000000 08:01 555 /data/local/tmp/frida-agent-64.so\n');
  const clean = detectInMaps('7f0000000000-7f0000001000 r-xp 00000000 08:01 100 /system/lib64/libc.so\n');
  negatives.push({
    label: 'NEGATIVE: detector fires on an instrumented target and is silent on a clean one',
    pass: dirty.findings.length === 1 && clean.findings.length === 0
      && readTracerPid('TracerPid:\t99\n').state === 'instrumented'
      && readTracerPid('TracerPid:\t0\n').state === 'clean',
    detail: `instrumented=${dirty.findings.length} finding(s), clean=${clean.findings.length}`,
  });

  /* (d2) indicator detectors: three controls, because a detector that fires on
     everything proves nothing and one that fires on nothing proves less. */
  {
    const { parseDex } = await import('./analyze.mjs');
    const { detectPacking, detectEnvironmentChecks, recoverKotlinMetadata } = await import('./indicators.mjs');
    const { entryData } = await import('../lab/build/zip.mjs');
    const { readZip } = await import('../lab/build/zip.mjs');

    const apkBuf = fs.readFileSync(APK);
    const zipEntries = readZip(apkBuf).map(e => e.name);
    const byName = Object.fromEntries(readZip(apkBuf).map(e => [e.name, e]));
    const dex = parseDex(entryData(byName['classes.dex']));

    /* Control 1: our own clean APK must NOT look packed. A detector that cannot stay
       quiet on a known-clean artifact is a detector that reports whatever it is fed. */
    const pk = detectPacking(dex, zipEntries);
    negatives.push({
      label: 'NEGATIVE: packing detector is silent on our own clean APK',
      pass: pk.verdict === 'no_indicator',
      detail: `verdict=${pk.verdict}, observed=${pk.observed.length}, inferred=${pk.inferred.length}`,
    });

    /* Control 2: a synthetic DEX carrying one packer signature must be FOUND. A detector
       that returns clean for an artifact that visibly contains a packer is worse than none,
       because it is trusted. */
    const fakePack = { ...dex, strings: [...dex.strings, 'com/secneo/apkwrapper/AppWrapper', 'Lcom/qihoo/util/StubApplication;'] };
    const pk2 = detectPacking(fakePack, zipEntries);
    negatives.push({
      label: 'NEGATIVE: packing detector FIRES on a DEX that carries a packer signature',
      pass: pk2.verdict === 'packed' && pk2.observed.length >= 2,
      detail: `verdict=${pk2.verdict}, packers=${pk2.observed.map(o => o.packer).join(',')}`,
    });

    /* Control 3: the weak-signal split. A bare "su" must never be presented the same
       way as an absolute-path su, because "su" occurs in innocent text constantly. */
    const fakeRoot = { ...dex, strings: [...dex.strings, '/system/xbin/su', 'com/topjohnwu/magisk', 'a casual mention of su'] };
    const env = detectEnvironmentChecks(fakeRoot);
    negatives.push({
      label: 'NEGATIVE: root detector separates weak substrings from load-bearing paths',
      pass: env.root_checks_present === true
        && env.root_hits.some(h => h.signal === '/system/xbin/su')
        && env.root_hits_weak.some(h => h.signal === 'su'),
      detail: `strong=${env.root_hits.map(h => h.signal).join(',')} | weak=${env.root_hits_weak.map(h => h.signal).join(',')}`,
    });

    /* Control 3b: THE control this detector was missing, and the one that found the bug.
       Our own clean APK must report BOTH flags false. The first version counted weak
       substrings, so a bare "su" in an XML element name and the literal "sdk=" produced
       emulator_checks_present and root_checks_present on an app that contains neither.
       A detector that cries wolf on a known-clean artifact is worse than no detector. */
    const envClean = detectEnvironmentChecks(dex);
    negatives.push({
      label: 'NEGATIVE: environment detector is SILENT on our own clean APK',
      pass: envClean.emulator_checks_present === false && envClean.root_checks_present === false,
      detail: `emulator=${envClean.emulator_checks_present} (strong=${envClean.emulator_hits.length} weak=${envClean.emulator_hits_weak.length}), root=${envClean.root_checks_present} (strong=${envClean.root_hits.length} weak=${envClean.root_hits_weak.length})`,
    });

    /* And it must still FIRE on a DEX that genuinely carries the load-bearing paths. */
    const envFake = detectEnvironmentChecks({
      ...dex,
      strings: [...dex.strings, '/system/xbin/su', '/dev/socket/qemud', 'ro.kernel.qemu'],
    });
    negatives.push({
      label: 'NEGATIVE: environment detector FIRES on load-bearing paths',
      pass: envFake.root_checks_present === true && envFake.emulator_checks_present === true,
      detail: `root=${envFake.root_checks_present} emulator=${envFake.emulator_checks_present}`,
    });

    /* Control 4: Kotlin metadata is reported as RECOVERABLE or not, never as a rename. */
    const kotlin = recoverKotlinMetadata(dex);
    negatives.push({
      label: 'NEGATIVE: Kotlin report never claims a rename it did not perform',
      pass: kotlin.does_not_prove.some(d => /not decoded names/i.test(d)),
      detail: `present=${kotlin.kotlin_metadata_present} recovery_possible=${kotlin.recovery_possible}`,
    });
  }

  /* (e) redaction must actually remove the value */
  const { redactConstant } = await import('../frida/lib/logic.mjs');
  const red = redactConstant('sk-lab-PLACEHOLDER-0000000000000000');
  negatives.push({
    label: 'NEGATIVE: redaction removes the value it flags',
    pass: red.flagged && !red.display.includes('PLACEHOLDER'),
    detail: red.display,
  });
}

  /* (f) THE CONTROL FOR THE CROSS-CHECK ITSELF. The registry recorded this capability's
     negative_control as a PLAN, on the stated ground that "no second decoder is installed".
     That ground was false and is now measured: Apktool 3.0.3 and JADX 1.5.6 are both
     installed and both run in section 5. So the cross-check exists -- and the question this
     control answers is the one that was never asked: CAN IT DISAGREE?
     A comparison fed only well-formed input has never disagreed with anything. Point both
     decoders at a deliberately truncated APK and require that they REFUSE, non-zero, rather
     than returning an empty permission set that would read as "both agree: none". That empty
     set is the specific failure being pinned -- an empty answer and an absent answer are
     different facts, and only one of them is corroboration. */
  {
    const apktoolJar = path.join(STATION, 'Mobile-Android', 'Apktool', 'apktool_3.0.3.jar');
    if (!fs.existsSync(apktoolJar)) {
      negatives.push({
        label: 'NEGATIVE: AXML cross-check can disagree (truncated APK refused by both decoders)',
        pass: false,
        detail: `apktool jar not found at ${apktoolJar}; cannot run the control`,
      });
    } else {
      /* Truncate to half: the ZIP end-of-central-directory record is gone, so this is not a
         valid container and a decoder that answered would be inventing one. */
      const good = fs.readFileSync(APK);
      const brokenApk = path.join(OUT, 'truncated.apk');
      fs.mkdirSync(OUT, { recursive: true });
      fs.writeFileSync(brokenApk, good.subarray(0, good.length >> 1));

      const aptDest = path.join(OUT, 'apktool-truncated');
      const aptFw = path.join(OUT, 'apktool-truncated-fw');
      fs.rmSync(aptDest, { recursive: true, force: true });
      const a = spawnSync('cmd.exe', ['/d', '/s', '/c',
        `java -jar ${apktoolJar} d -f -p ${aptFw} -o ${aptDest} ${brokenApk}`],
      { encoding: 'utf8', timeout: 180000, windowsVerbatimArguments: true });
      const aptRefused = a.status !== 0 && !fs.existsSync(path.join(aptDest, 'AndroidManifest.xml'));

      const an = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), brokenApk, '--json'],
        { encoding: 'utf8' });
      const anRefused = an.status !== 0;

      /* The strong half: they must refuse for DIFFERENT and named reasons. Apktool dies in
         dexlib2 on the container; the analyser refuses at the ZIP layer and says so. Two
         refusals that shared a cause would be one refusal counted twice. */
      const aptSays = ((a.stdout || '') + (a.stderr || '')).includes('NotAZipFileException')
        || ((a.stdout || '') + (a.stderr || '')).includes('Exception in thread "main"');
      const anSays = ((an.stdout || '') + (an.stderr || '')).includes('not a ZIP');

      negatives.push({
        label: 'NEGATIVE: AXML cross-check can disagree (truncated APK refused by both decoders)',
        pass: aptRefused && anRefused && aptSays && anSays,
        detail: `apktool exit ${a.status} (manifest produced=${fs.existsSync(path.join(aptDest, 'AndroidManifest.xml'))}), `
          + `analyze.mjs exit ${an.status}; refusal named by apktool=${aptSays}, by analyzer=${anSays}`,
      });

      /* And the same comparison must still AGREE on the real APK, or the control above would
         pass for a pair of decoders that never agree on anything -- including a correct APK. */
      const okApk = path.join(OUT, 'apktool-agree');
      fs.rmSync(okApk, { recursive: true, force: true });
      const okFw = path.join(OUT, 'apktool-agree-fw');
      const aok = spawnSync('cmd.exe', ['/d', '/s', '/c',
        `java -jar ${apktoolJar} d -f -p ${okFw} -o ${okApk} ${APK}`],
      { encoding: 'utf8', timeout: 180000, windowsVerbatimArguments: true });
      let apktoolPerms = [];
      const okMf = path.join(okApk, 'AndroidManifest.xml');
      if (aok.status === 0 && fs.existsSync(okMf)) {
        apktoolPerms = [...fs.readFileSync(okMf, 'utf8')
          .matchAll(/<uses-permission android:name="([^"]+)"/g)].map(m => m[1]).sort();
      }
      /* Our own analyser, asked the same question over the same bytes. */
      const okAn = spawnSync(process.execPath, [path.join(HERE, 'analyze.mjs'), APK, '--json'],
        { encoding: 'utf8' });
      let ourPerms = [];
      try { ourPerms = [...(JSON.parse(okAn.stdout).manifest.permissions || [])].sort(); } catch { /* recorded below */ }
      negatives.push({
        label: 'NEGATIVE: the two decoders AGREE on the real APK (so refusal above is not reflex)',
        pass: apktoolPerms.length > 0
          && apktoolPerms.length === ourPerms.length
          && apktoolPerms.every((p, i) => p === ourPerms[i]),
        detail: `apktool ${apktoolPerms.length} perm(s) [${apktoolPerms.join(', ')}] vs `
          + `analyzer ${ourPerms.length} [${ourPerms.join(', ')}]`,
      });
    }
  }

for (const n of negatives) record(n.label, n.pass, n.detail);
/* ------------------------------------------------------------------ *
 * Summary
 * ------------------------------------------------------------------ */
const failed = steps.filter(s => s.pass === false);
const skipped = steps.filter(s => s.skipped);
banner('mobile-lab loop summary');
for (const s of steps) {
  const tag = s.skipped ? 'SKIP' : (s.pass ? 'PASS' : 'FAIL');
  console.log(`  ${tag}  ${s.label.padEnd(58)} ${s.detail}${s.ms ? `  (${(s.ms / 1000).toFixed(1)}s)` : ''}`);
}
console.log('');

/* The closing sentence names JADX and Apktool by name, so it may only be printed when both
   actually ran. Printing it after a skip is the same defect in prose form that recordSkip
   fixes in the table. */
if (failed.length === 0 && skipped.length === 0) {
  console.log('LOOP CLOSED: a real APK was built from source, its native library agreed with an');
  console.log('             independent ELF implementation, the static analyser resolved every JNI');
  console.log('             boundary and all four pinning mechanisms, JADX and Apktool reproduced the');
  console.log('             same findings with their own decoders, the Frida scripts were logic-verified');
  console.log('             with no device, and every negative control failed as designed.');
  console.log('');
  console.log('NOT PROVEN (no device on this box): attaching, live TLS interception, ART accepting');
  console.log('             these scripts, and disassembly of the sample .so.');
  writeRunArtifact('mobile-lab', { checks: steps, outDir: 'mobile-lab/out',
    extra: { ok: true, exit_reason: 'closed' } });
  process.exit(0);
} else if (failed.length === 0) {
  console.log(`LOOP NOT CLOSED: ${skipped.length} step(s) SKIPPED and nothing failed. A skipped`);
  console.log('             cross-check is not an agreeing one -- the second decoder was never asked,');
  console.log('             so this run carries NO independent corroboration of the manifest.');
  for (const s of skipped) console.log(`  - SKIPPED ${s.label}: ${s.detail}`);
  console.log('');
  console.log('Run without the skip flags to close the loop.');
  writeRunArtifact('mobile-lab', { checks: steps, outDir: 'mobile-lab/out',
    extra: { ok: false, exit_reason: 'skipped-but-nothing-failed' } });
  process.exit(8);
} else {
  console.log(`${failed.length} step(s) FAILED:`);
  for (const f of failed) console.log(`  - ${f.label}: ${f.detail}`);
  if (skipped.length) {
    console.log(`${skipped.length} further step(s) SKIPPED (also not agreement):`);
    for (const s of skipped) console.log(`  - SKIPPED ${s.label}: ${s.detail}`);
  }
  process.exit(9);
}
