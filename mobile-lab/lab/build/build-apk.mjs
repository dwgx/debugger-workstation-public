#!/usr/bin/env node
/*
 * build-apk.mjs — build a real, signed, installable-shaped APK from the self-authored lab
 * sources, with no Android SDK, no Gradle, and no network.
 *
 * THE PIPELINE (every step is a real Google tool from build-tools 35.0.0)
 * ------------------------------------------------------------------------
 *   1. javac   compile lab/stubs + lab/app  -> stub-classes/ and app-classes/
 *   2. make-so emit lib/arm64-v8a/libmobilelab.so (hand-built ELF, no NDK)
 *   3. aapt2 compile  res/            -> compiled.flata
 *   4. aapt2 link     framework stub  -> framework.apk   (cached)
 *   5. aapt2 link     app             -> base-unsigned.apk (real AXML + resources.arsc)
 *   6. zip surgery   add classes.dex + lib/arm64-v8a/libmobilelab.so
 *   7. zipalign     4-byte align (required for an installable APK)
 *   8. apksigner    v1+v2 signature with a generated throwaway debug key
 *
 * WHY THE FRAMEWORK STUB
 * ----------------------
 * aapt2 link resolves `android:*` attributes against android.jar, which is not installed
 * here. lab/build/framework-res/ declares the ~10 framework attrs the sample's manifest uses
 * and marks them public, and aapt2 links THAT into a tiny framework.apk used as `-I`. The
 * result is a manifest whose resource IDs are the real Android framework IDs, so Apktool
 * and JADX decode it with their own framework tables rather than against our stub.
 *
 * THE ONE SUBSTITUTION, STATED PLAINLY
 * ------------------------------------
 * lib/native/mobilelab.c is NOT compiled: there is no NDK on this box. The .so is emitted
 * byte-by-byte by make-so.mjs. It is a real ELF64 AArch64 DYN object with a real .dynsym,
 * .dynamic, .hash and .rodata, and both our parser and pyelftools agree on it — but its
 * .text is a documented stub, not the compiled C. Static analysis of symbol tables, imports,
 * strings, JNI name mangling and .rodata pins is unaffected; DISASSEMBLY is not offered, and
 * tools/analyze.mjs reports `disassembly: not attempted` rather than inventing one.
 *
 * Usage:
 *   node lab/build/build-apk.mjs [--out <path.apk>] [--quiet] [--keep-work]
 * Exit:  0 = APK built and self-checks passed, 1 = a step failed, 2 = a tool is missing.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildSo, verifySo } from './make-so.mjs';
import { readZip, writeZip, entryData } from './zip.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB = path.resolve(HERE, '..', '..');          /* mobile-lab/            */
/* PER-PROCESS work dir, and this is a measured fix rather than tidiness.
 *
 * `WORK` used to be `mobile-lab/work` for every build, and line 160 does
 * `fs.rmSync(WORK, {recursive:true})` at the START of each build. Two concurrent builds
 * therefore deleted each other's aapt2/d8 output mid-flight: measured 2026-10-03 as
 * "Unable to open mobile-lab\work\apk\aligned.apk for verification / Build failed", exit 9,
 * from a run that had nothing wrong with it. A gate checked twice in parallel reported a build
 * failure instead of its own verdict. Keyed by pid, wiped on exit, no shared state. */
const WORK = path.join(os.tmpdir(), `mobilelab-build-${process.pid}`);
process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }); } catch { /* best effort */ } });
const FW_RES = path.join(HERE, 'framework-res');

/* ------------------------------------------------------------------ *
 * Tool discovery. Windows binaries are invoked through cmd.exe because
 * this lab runs under a POSIX shell layer that cannot exec them directly.
 * ------------------------------------------------------------------ */

const IS_WIN = process.platform === 'win32';

function findBuildTools() {
  const explicit = process.env.MOBILELAB_BUILD_TOOLS;
  const candidates = explicit
    ? [explicit]
    : (IS_WIN
        ? ['D:\\Software\\Android\\Sdk\\build-tools\\35.0.0',
           `${process.env.LOCALAPPDATA}\\Android\\Sdk\\build-tools\\35.0.0`]
        : ['$HOME/Android/Sdk/build-tools/35.0.0', '/opt/android-sdk/build-tools/35.0.0']);
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'aapt2.exe')) || fs.existsSync(path.join(c, 'aapt2'))) return c;
  }
  return null;
}

function run(cmd, args, { cwd, label, quiet, verbatim = false } = {}) {
  const started = Date.now();
  const r = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    /* windowsVerbatimArguments belongs to the cmd.exe path ONLY. Applied to a direct .exe
       spawn it disables Node's argument escaping, so an argument containing spaces
       (keytool's -dname) arrives split into several tokens and the tool prints its usage
       instead of running. cmd.exe, conversely, re-escapes every inner quote as \" unless
       this is on, and then reports the tool as unrecognised. */
    windowsVerbatimArguments: verbatim,
  });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`.trim();
  if (!quiet) {
    process.stderr.write(`  $ ${label ?? `${cmd} ${args.join(' ')}`}\n`);
    if (out) process.stderr.write(out.split('\n').map(l => `    ${l}`).join('\n') + '\n');
  }
  if (r.error) throw new Error(`${label}: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${label}: exit ${r.status}\n${out}`);
  return { out, ms: Date.now() - started };
}

/** Quote one argument for a cmd.exe command line. */
const q = a => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '""')}"` : a);

/** Run a Google/Android tool. On Windows these must go through cmd.exe. */
function runTool(bt, exe, args, opts = {}) {
  if (IS_WIN) {
    const line = `${q(path.join(bt, exe))} ${args.map(q).join(' ')}`;
    return run(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', line],
      { label: opts.label ?? exe, verbatim: true, ...opts });
  }
  return run(path.join(bt, exe), args, { label: opts.label ?? exe, ...opts });
}

/* ------------------------------------------------------------------ *
 * The framework resource stub: just enough android:* for the manifest.
 * ------------------------------------------------------------------ */

/* The framework attributes the sample manifest uses, with their REAL Android resource IDs
   and their real declared formats. The format matters: aapt2 type-checks the manifest
   value against it, and an inferred format silently turns versionName="1.0.0-lab" into a
   type error that reads like a bad manifest rather than a bad stub. */
const ANDROID_ATTRS = {
  theme:                   { id: 0x01010000, format: 'reference' },
  label:                   { id: 0x01010001, format: 'reference' },
  icon:                    { id: 0x01010002, format: 'reference' },
  name:                    { id: 0x01010003, format: 'string' },
  manageSpaceActivity:     { id: 0x01010004, format: 'boolean' },
  allowClearUserData:      { id: 0x01010005, format: 'boolean' },
  permission:              { id: 0x01010006, format: 'string' },
  protectionLevel:         { id: 0x01010009, format: 'string' },
  hasCode:                 { id: 0x0101000c, format: 'boolean' },
  debuggable:              { id: 0x0101000f, format: 'boolean' },
  exported:                { id: 0x01010010, format: 'boolean' },
  process:                 { id: 0x01010011, format: 'string' },
  authorities:             { id: 0x01010018, format: 'string' },
  enabled:                 { id: 0x0101001e, format: 'boolean' },
  minSdkVersion:           { id: 0x0101020c, format: 'integer' },
  targetSdkVersion:        { id: 0x01010270, format: 'integer' },
  versionCode:             { id: 0x0101021b, format: 'integer' },
  versionName:             { id: 0x0101021c, format: 'string' },
  networkSecurityConfig:   { id: 0x01010527, format: 'reference' },
};

/* ------------------------------------------------------------------ *
 * Build
 * ------------------------------------------------------------------ */

export async function buildApk({ out, quiet = false, keepWork = false } = {}) {
  const say = (...a) => { if (!quiet) console.log(...a); };
  const steps = [];
  const step = (name, ms) => { steps.push({ name, ms }); say(`  [ok] ${name}${ms ? `  (${ms}ms)` : ''}`); };

  const bt = findBuildTools();
  if (!bt) {
    throw new Error(
      'Android build-tools not found. Set MOBILELAB_BUILD_TOOLS to a build-tools directory ' +
      'containing aapt2/d8/zipalign/apksigner. This is what makes a real APK buildable ' +
      'without the full SDK.'
    );
  }
  say(`build-tools : ${bt}`);
  say(`work dir    : ${WORK}`);

  fs.rmSync(WORK, { recursive: true, force: true });
  for (const d of ['stub-classes', 'app-classes', 'res', 'apk', 'keys']) {
    fs.mkdirSync(path.join(WORK, d), { recursive: true });
  }

  /* --- 1. javac: stubs first (compile-only), then the app against them --- */
  const javac = process.env.JAVAC || 'javac';
  const stubSrc = path.join(LAB, 'lab', 'stubs');
  const appSrc = path.join(LAB, 'lab', 'app');
  const stubClasses = path.join(WORK, 'stub-classes');
  const appClasses = path.join(WORK, 'app-classes');

  const javaFiles = dir => fs.readdirSync(dir, { recursive: true })
    .filter(f => String(f).endsWith('.java'))
    .map(f => path.join(dir, String(f)));

  const stubFiles = javaFiles(stubSrc);
  const appFiles = javaFiles(appSrc);
  say(`javac       : ${stubFiles.length} stub sources, ${appFiles.length} app sources`);

  let t = Date.now();
  run(javac, ['-nowarn', '-d', stubClasses, ...stubFiles], { label: 'javac stubs' });
  step('javac: framework stubs (compile-only, not packaged)', Date.now() - t);

  t = Date.now();
  run(javac, ['-nowarn', '-cp', stubClasses, '-d', appClasses, ...appFiles], { label: 'javac app' });
  step('javac: com.lab.mobilelab app sources', Date.now() - t);

  /* --- 2. the hand-built native library --- */
  t = Date.now();
  const so = buildSo({ soname: 'libmobilelab.so' });
  const soCheck = verifySo(so.buffer);
  if (!soCheck.ok) throw new Error(`native library self-check failed: ${soCheck.problems.join('; ')}`);
  const soPath = path.join(WORK, 'apk', 'libmobilelab.so');
  fs.writeFileSync(soPath, so.buffer);
  step(`native .so built + self-verified (${so.buffer.length} bytes, ${so.meta.exports.length} exports)`, Date.now() - t);

  /* --- 3. aapt2 compile the app's resources --- */
  t = Date.now();
  const flata = path.join(WORK, 'res', 'compiled.flata');
  runTool(bt, 'aapt2.exe', ['compile', '--dir', path.join(LAB, 'lab', 'res'), '-o', flata], { cwd: WORK });
  step('aapt2 compile res/ -> compiled.flata', Date.now() - t);

  /* --- 4. the framework stub APK, built once and cached --- */
  t = Date.now();
  const fwApk = path.join(WORK, 'apk', 'framework.apk');
  const fwFlata = path.join(WORK, 'res', 'framework.flata');
  if (!fs.existsSync(fwFlata)) {
    fs.mkdirSync(path.join(FW_RES, 'values'), { recursive: true });
    fs.writeFileSync(path.join(FW_RES, 'values', 'attrs.xml'),
      '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n' +
      Object.entries(ANDROID_ATTRS).map(([n, a]) =>
        `  <attr name="${n}" format="${a.format}" />`
      ).join('\n') + '\n</resources>\n');
    fs.writeFileSync(path.join(FW_RES, 'values', 'public.xml'),
      '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n' +
      Object.entries(ANDROID_ATTRS).map(([n, a]) => `  <public type="attr" name="${n}" id="0x${a.id.toString(16)}" />`).join('\n') +
      '\n</resources>\n');
    runTool(bt, 'aapt2.exe', ['compile', '--dir', FW_RES, '-o', fwFlata], { cwd: WORK });
  }
  const fwManifest = path.join(WORK, 'res', 'framework-manifest.xml');
  fs.writeFileSync(fwManifest,
    '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android" />\n');
  runTool(bt, 'aapt2.exe', ['link', '-o', fwApk, '--manifest', fwManifest, fwFlata], { cwd: WORK });
  step('aapt2 link framework stub (android:* attribute IDs)', Date.now() - t);

  /* --- 5. aapt2 link the app: this is where real binary AXML is produced --- */
  t = Date.now();
  const baseApk = path.join(WORK, 'apk', 'base-unsigned.apk');
  runTool(bt, 'aapt2.exe', [
    'link', '-o', baseApk,
    '-I', fwApk,
    '--manifest', path.join(LAB, 'lab', 'AndroidManifest.xml'),
    '--java', path.join(WORK, 'res', 'gen'),
    '--min-sdk-version', '24', '--target-sdk-version', '34',
    flata,
  ], { cwd: WORK });
  const baseEntries = readZip(fs.readFileSync(baseApk)).map(e => e.name);
  if (!baseEntries.includes('AndroidManifest.xml')) throw new Error('aapt2 produced no AndroidManifest.xml');
  if (!baseEntries.includes('resources.arsc')) throw new Error('aapt2 produced no resources.arsc');
  const axml = entryData(readZip(fs.readFileSync(baseApk)).find(e => e.name === 'AndroidManifest.xml'));
  const axmlMagic = axml.readUInt32LE(0);
  if (axmlMagic !== 0x00080003) {
    throw new Error(`AndroidManifest.xml is not binary AXML: magic 0x${axmlMagic.toString(16)}`);
  }
  step(`aapt2 link app -> binary AXML (${axml.length} B) + resources.arsc`, Date.now() - t);

  /* --- 6. add classes.dex and the native library, preserving every other entry byte-for-byte --- */
  t = Date.now();
  const appClassFiles = fs.readdirSync(appClasses, { recursive: true })
    .filter(f => String(f).endsWith('.class'))
    .map(f => path.join(appClasses, String(f)));
  if (appClassFiles.length === 0) throw new Error('javac produced no class files');

  const dexDir = path.join(WORK, 'dex');
  fs.mkdirSync(dexDir, { recursive: true });
  /* d8 needs the stub classes on its class path so it can resolve android.* references
     without dexing the stubs themselves: the APK ships only com.lab.*. */
  runTool(bt, 'd8.bat', [
    `--output=${dexDir}`,
    '--min-api', '24',
    '--lib', stubClasses,
    '--classpath', stubClasses,
    ...appClassFiles,
  ], { cwd: WORK });
  const dexPath = path.join(dexDir, 'classes.dex');
  if (!fs.existsSync(dexPath)) throw new Error('d8 produced no classes.dex');
  const dexBuf = fs.readFileSync(dexPath);
  if (dexBuf.toString('latin1', 0, 4) !== 'dex\n') throw new Error('classes.dex has a bad magic');
  step(`d8 -> classes.dex (${dexBuf.length} B, DEX ${dexBuf[7] === 0x35 ? '035' : String(dexBuf[7])})`, Date.now() - t);

  const existing = readZip(fs.readFileSync(baseApk));
  const kept = existing.map(e => ({ ...e }));
  const added = [
    { name: 'classes.dex', data: dexBuf },
    /* A .so inside an APK must be STORED, not deflated: PackageManager maps it straight
       out of the zip rather than inflating to a temp file, which is what makes `zipalign -p`
       (page-align the .so payloads) meaningful. aapt2 does this for entries it packages
       itself; doing it here matches that behaviour for the one we inject. */
    { name: 'lib/arm64-v8a/libmobilelab.so', data: so.buffer, method: 0 },
  ];
  const merged = [...kept, ...added];
  const stagedApk = path.join(WORK, 'apk', 'staged-unsigned.apk');
  fs.writeFileSync(stagedApk, writeZip(merged));
  const stagedNames = readZip(fs.readFileSync(stagedApk)).map(e => e.name);
  for (const req of ['AndroidManifest.xml', 'resources.arsc', 'classes.dex', 'lib/arm64-v8a/libmobilelab.so']) {
    if (!stagedNames.includes(req)) throw new Error(`staged APK is missing ${req}`);
  }
  step(`zip surgery: +classes.dex +lib/arm64-v8a/libmobilelab.so (${stagedNames.length} entries)`, Date.now() - t);

  /* --- 7. zipalign --- */
  t = Date.now();
  const aligned = path.join(WORK, 'apk', 'aligned.apk');
  runTool(bt, 'zipalign.exe', ['-f', '-p', '4', stagedApk, aligned], { cwd: WORK });
  const alignCheck = runTool(bt, 'zipalign.exe', ['-c', '-v', '4', aligned], { cwd: WORK, quiet: true });
  step('zipalign -p 4 (verified with zipalign -c)', Date.now() - t);
  void alignCheck;

  /* --- 8. sign with a throwaway debug key --- */
  t = Date.now();
  const keytool = process.env.KEYTOOL || 'keytool';
  const ks = path.join(WORK, 'keys', 'debug.keystore');
  if (!fs.existsSync(ks)) {
    run(keytool, [
      '-genkeypair', '-v', '-keystore', ks, '-storepass', 'android', '-keypass', 'android',
      '-alias', 'mobilelab', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
      '-dname', 'CN=MobileLab Fixture, OU=Lab, O=Self, L=Lab, ST=Lab, C=ZZ',
    ], { label: 'keytool -genkeypair (throwaway debug key)' });
  }
  const finalPath = out || path.join(LAB, 'artifacts', 'mobilelab.apk');
  fs.mkdirSync(path.dirname(finalPath), { recursive: true });
  fs.copyFileSync(aligned, finalPath);
  runTool(bt, 'apksigner.bat', [
    'sign', '--ks', ks, '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
    '--ks-key-alias', 'mobilelab', '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
    '--out', path.join(WORK, 'apk', 'signed.apk'), aligned,
  ], { cwd: WORK });
  fs.copyFileSync(path.join(WORK, 'apk', 'signed.apk'), finalPath);
  step('apksigner v1+v2 signature (throwaway key, not a secret)', Date.now() - t);

  /* --- final self-checks on the artefact we are about to ship --- */
  const finalBuf = fs.readFileSync(finalPath);
  const finalEntries = readZip(finalBuf);
  const names = finalEntries.map(e => e.name);
  const manifestEntry = finalEntries.find(e => e.name === 'AndroidManifest.xml');
  const finalAxml = entryData(manifestEntry);
  if (finalAxml.readUInt32LE(0) !== 0x00080003) throw new Error('final APK manifest is not AXML');

  /* The real APK invariants, and only those.
     - resources.arsc must be STORED: the runtime mmaps it in place.
     - every .so under lib/ must be STORED: PackageManager maps it in place, no inflate.
     - AndroidManifest.xml has NO such requirement. aapt2 deflates it, real APKs ship it
       that way, and an earlier version of this file asserted STORED here and failed the
       build for asserting something untrue. Its method is now reported, not enforced. */
  const arsc = finalEntries.find(e => e.name === 'resources.arsc');
  if (!arsc) throw new Error('final APK has no resources.arsc');
  if (arsc.method !== 0) throw new Error(`resources.arsc must be STORED, got method ${arsc.method}`);
  for (const e of finalEntries.filter(x => x.name.startsWith('lib/') && x.name.endsWith('.so'))) {
    if (e.method !== 0) throw new Error(`${e.name} must be STORED in an APK, got method ${e.method}`);
  }

  const summary = {
    apk: finalPath,
    bytes: finalBuf.length,
    sha256: createHash('sha256').update(finalBuf).digest('hex'),
    entries: names,
    axml: { bytes: finalAxml.length, magic: '0x00080003', stored: manifestEntry.method === 0 },
    dex: { bytes: dexBuf.length, version: `${String.fromCharCode(dexBuf[4])}${String.fromCharCode(dexBuf[5])}${String.fromCharCode(dexBuf[6])}` },
    so: { bytes: so.buffer.length, exports: so.meta.exports, imports: so.meta.imports, needed: so.meta.needed },
    steps,
  };

  if (!keepWork) {
    /* work/ is machine state; artifacts/ holds the one durable artefact. */
    for (const d of ['stub-classes', 'app-classes', 'res', 'dex', 'keys', 'apk']) {
      fs.rmSync(path.join(WORK, d), { recursive: true, force: true });
    }
  }

  return summary;
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

/* fileURLToPath yields a native path, so compare natively. Normalising one side to
   forward slashes and not the other makes the check silently false, and the "CLI" then
   exits 0 having done nothing — which looks exactly like a passing build. */
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const opt = (name, dflt) => {
    const i = argv.indexOf(name);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
  };
  const quiet = argv.includes('--quiet');
  try {
    const s = await buildApk({ out: opt('--out'), quiet, keepWork: argv.includes('--keep-work') });
    if (!quiet) {
      console.log('');
      console.log(`APK        ${s.apk}`);
      console.log(`bytes      ${s.bytes}`);
      console.log(`sha256     ${s.sha256}`);
      console.log(`entries    ${s.entries.join(', ')}`);
      console.log(`AXML       ${s.axml.bytes} bytes, magic ${s.axml.magic} (real binary manifest)`);
      console.log(`DEX        ${s.dex.bytes} bytes, version ${s.dex.version}`);
      console.log(`.so        ${s.so.bytes} bytes, ${s.so.exports.length} JNI exports, needs ${s.so.needed.join('+')}`);
      console.log('');
      console.log('LIMITATION lib/native/mobilelab.c was NOT compiled (no NDK). The .so is a real ELF');
      console.log('           with a real .dynsym/.dynamic/.hash, hand-assembled by make-so.mjs, and its');
      console.log('           .text is a documented stub. Symbol/import/string/JNI analysis is valid;');
      console.log('           disassembly of these functions is not offered.');
    }
    process.exit(0);
  } catch (err) {
    console.error(`build-apk: ${err.message}`);
    process.exit(/not found/.test(err.message) ? 2 : 1);
  }
}

void execFileSync;
