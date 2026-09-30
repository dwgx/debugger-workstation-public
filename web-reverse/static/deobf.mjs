#!/usr/bin/env node
/* deobf.mjs — the static deobfuscation driver for the web-reverse lab.
 *
 * The order is deliberate and comes from the method (wiki/methods/web-reverse-method.md, Layer 0-1):
 *
 *   1. source map first — if the original sources are shipped, the answer is
 *      "read the source", not "deobfuscate". Nothing else is run.
 *   2. fingerprint the bundler and the obfuscator family from the bytes.
 *   3. webcrack — obfuscator.io string arrays / flattening / dead code, plus
 *      webpack / browserify / esbuild / metro module graphs.
 *   4. wakaru — transpiler artifacts (`?.`, `??`, `_asyncToGenerator`, ESM/CJS),
 *      and bundle unpacking when webcrack could not finish the job.
 *   5. measure: parse the result with three parsers, count the residual
 *      obfuscation markers, and assert whatever the caller asked for with
 *      --expect. "Deobfuscated" is a measurable claim or it is not made.
 *
 * Usage:
 *   node static/deobf.mjs --in <file|url> [--out recovered.js] [--report report.json]
 *        [--expect <substring>]... [--print] [--json]
 *        [--wakaru auto|always|never] [--allow-remote] [--artifacts <dir>]
 *
 * Exit codes: 0 ok, 2 usage, 3 input/stage failure, 4 --expect not satisfied.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { webcrack } from 'webcrack';
import { parse as babelParse } from '@babel/parser';
import * as acorn from 'acorn';
import * as meriyah from 'meriyah';
import { triage, residuals } from './lib/triage.mjs';

const require = createRequire(import.meta.url);
const ARTIFACTS_DEFAULT = path.join(os.tmpdir(), 'web-reverse-captures', 'static');

/* ------------------------------------------------------------------ args */
function parseArgs(argv) {
  const out = { expect: [], wakaru: 'auto', artifacts: ARTIFACTS_DEFAULT };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) fail(`missing value for ${a}`); return v; };
    switch (a) {
      case '--in': out.in = next(); break;
      case '--out': out.out = next(); break;
      case '--report': out.report = next(); break;
      case '--expect': out.expect.push(next()); break;
      case '--artifacts': out.artifacts = next(); break;
      case '--wakaru': out.wakaru = next(); break;
      case '--print': out.print = true; break;
      case '--json': out.json = true; break;
      case '--allow-remote': out.allowRemote = true; break;
      case '--help': case '-h': out.help = true; break;
      default: fail(`unknown flag ${a}`);
    }
  }
  return out;
}
function fail(message, code = 2) {
  console.error(`deobf: ${message}`);
  process.exit(code);
}

/* ------------------------------------------------------------------ input */
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

async function readInput(spec, { allowRemote }) {
  if (/^https?:\/\//i.test(spec)) {
    const url = new URL(spec);
    if (!LOOPBACK.has(url.hostname) && !allowRemote) {
      fail(`refusing to fetch ${url.hostname} (non-loopback). Pass --allow-remote if this host is yours and authorized.`, 2);
    }
    const res = await fetch(spec, { redirect: 'follow' });
    const text = await res.text();
    return {
      kind: 'url', source: spec, text, headers: Object.fromEntries(res.headers),
      httpStatus: res.status, contentType: res.headers.get('content-type') || ''
    };
  }
  const text = fs.readFileSync(spec, 'utf8');
  return { kind: 'file', source: path.resolve(spec), text, headers: {} };
}

function looksLikeHtml(text, contentType = '') {
  return /text\/html/i.test(contentType) || (/<script[\s>]/i.test(text) && /<\/html>|<body[\s>]/i.test(text));
}

function extractInlineScripts(html) {
  const found = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] || '';
    const code = m[2] || '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    if (/\btype\s*=\s*["']?(application\/(ld\+)?json|importmap|text\/template)/i.test(attrs)) continue;
    if (code.trim().length < 40) continue;
    found.push({ attrs: attrs.trim(), code, offset: m.index });
  }
  return found;
}

function scriptScore(code) {
  const t = triage(code);
  let score = t.obfuscatorFamilies.length * 10 + (t.bytes / 1000);
  if (t.obfuscatorFamilies.some(f => f.id === 'jsvmp')) score += 25;
  return { score: Math.round(score * 100) / 100, families: t.obfuscatorFamilies.map(f => f.id) };
}

/* ------------------------------------------------------------------ stages */
async function runWebcrack(code, { moduleDir }) {
  const started = Date.now();
  const result = await webcrack(code, { unpack: true, unminify: true, deobfuscate: true, jsx: true, mangle: false });
  const bundle = result.bundle;
  const bundleType = bundle && bundle.type ? String(bundle.type) : null;
  const moduleCount = bundle && bundle.modules instanceof Map ? bundle.modules.size : 0;
  let modules = [];
  let moduleError = null;
  if (moduleCount > 0) {
    /* webcrack's bundle modules carry an AST, not source; its own `save()` is the
       supported way to lay them out on disk (what the webcrack CLI uses). */
    fs.mkdirSync(moduleDir, { recursive: true });
    try {
      await result.save(moduleDir);
      modules = fs.readdirSync(moduleDir, { recursive: true, withFileTypes: true })
        .filter(d => d.isFile())
        .map(d => {
          const file = path.join(d.parentPath || moduleDir, d.name);
          return { name: path.relative(moduleDir, file).replace(/\\/g, '/'), file, bytes: fs.statSync(file).size };
        });
    } catch (e) {
      moduleError = String(e.message).slice(0, 200);
    }
  }
  return { code: result.code, ms: Date.now() - started, bundleType, moduleCount, modules, moduleError };
}

function runWakaru(code) {
  const bin = require.resolve('@wakaru/cli/bin/wakaru');
  return new Promise(resolve => {
    const started = Date.now();
    const child = spawn(process.execPath, [bin], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('error', e => resolve({ ok: false, error: String(e.message), ms: Date.now() - started }));
    child.on('close', (code) => {
      if (code !== 0 || !out.trim()) {
        resolve({ ok: false, error: err.trim() || `wakaru exited ${code}`, ms: Date.now() - started, code });
      } else {
        resolve({ ok: true, code: out, ms: Date.now() - started, warnings: err.trim() || null });
      }
    });
    child.stdin.end(code);
  });
}

/* ------------------------------------------------------------------ checks */
function parseChecks(code) {
  const checks = {};
  try { acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true }); checks.acorn = 'script'; }
  catch (e1) {
    try { acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true }); checks.acorn = 'module'; }
    catch (e2) { checks.acorn = `fail: ${e2.message.slice(0, 90)}`; }
  }
  try { meriyah.parseScript(code, { next: true }); checks.meriyah = 'script'; }
  catch (e1) {
    try { meriyah.parseModule(code, { next: true }); checks.meriyah = 'module'; }
    catch (e2) { checks.meriyah = `fail: ${e2.message.slice(0, 90)}`; }
  }
  try { babelParse(code, { sourceType: 'unambiguous', plugins: ['jsx'] }); checks.babel = 'unambiguous'; }
  catch (e) { checks.babel = `fail: ${e.message.slice(0, 90)}`; }
  checks.anyParses = Object.values(checks).some(v => v !== null && !String(v).startsWith('fail'));
  return checks;
}

function stringLiterals(code, min = 8, limit = 25) {
  const out = new Set();
  const re = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const v = m[2];
    if (v.length >= min && !/^\s+$/.test(v)) out.add(v);
    if (out.size >= limit * 4) break;
  }
  return [...out].slice(0, limit);
}

/* ------------------------------------------------------------------ main */
const args = parseArgs(process.argv.slice(2));
if (args.help || !args.in) {
  console.log(`deobf.mjs --in <file|url> [--out recovered.js] [--report report.json] [--expect <substring>]... [--print] [--json] [--wakaru auto|always|never] [--artifacts <dir>] [--allow-remote]`);
  process.exit(args.help ? 0 : 2);
}

const transcript = [];
const say = (line) => { transcript.push(line); if (!args.json) console.log(line); else console.error(line); };

const input = await readInput(args.in, args);
const html = looksLikeHtml(input.text, input.contentType);
let code = input.text;
let scriptInfo = null;

if (html) {
  const scripts = extractInlineScripts(input.text);
  if (scripts.length === 0) fail('input is HTML but contains no inline <script> body', 3);
  const scored = scripts.map((s, i) => ({ i, ...s, ...scriptScore(s.code) })).sort((a, b) => b.score - a.score);
  const chosen = scored[0];
  scriptInfo = {
    inlineScripts: scripts.length,
    chosen: { index: chosen.i, bytes: chosen.code.length, score: chosen.score, families: chosen.families },
    alsoPresent: scored.slice(1).map(s => ({ index: s.i, bytes: s.code.length, score: s.score, families: s.families }))
  };
  code = chosen.code;
}

const sourceMap = input.kind === 'url' ? (input.headers['x-sourcemap'] || input.headers['sourcemap'] || null) : null;
const triageReport = triage(code, { headers: input.headers });
say(`deobf: in ${input.source} (${Buffer.byteLength(code)} B of script${html ? ` extracted from ${scriptInfo.inlineScripts} inline script(s)` : ''})`);
say(`triage: verdict=${triageReport.verdict}  strategy=${triageReport.strategy}`);
say(`  source map : ${triageReport.sourceMap.sourceMappingURL || sourceMap || 'none'}`);
say(`  bundler    : ${triageReport.bundlers.join(', ') || 'none'}`);
say(`  families   : ${triageReport.obfuscatorFamilies.map(f => f.id).join(', ') || 'none'}`);
say(`  transpiler : ${triageReport.transpilerArtifacts.join(', ') || 'none'}`);

const artifacts = args.artifacts;
fs.mkdirSync(path.join(artifacts, 'stages'), { recursive: true });
const outFile = args.out || path.join(artifacts, 'recovered.js');
const reportFile = args.report || path.join(artifacts, 'deobf-report.json');
const stagesDir = path.join(artifacts, 'stages');
const stages = [];
const residualsBefore = residuals(code);

const report = {
  ok: false,
  tool: 'web-reverse/static/deobf.mjs',
  at: new Date().toISOString(),
  input: {
    kind: input.kind, source: input.source, httpStatus: input.httpStatus ?? null,
    contentType: input.contentType || null,
    html, script: scriptInfo,
    scriptBytes: Buffer.byteLength(code),
    sha256: crypto.createHash('sha256').update(code).digest('hex')
  },
  triage: triageReport,
  stages,
  residualsBefore,
  residualsAfter: null,
  parse: null,
  expects: null,
  recoveredStrings: null,
  output: null
};

/* --- 1. source map short-circuit ------------------------------------------------- */
if (triageReport.verdict === 'sourcemap-with-originals') {
  const originals = (await import('./lib/triage.mjs')).originalsFromMap(triageReport.sourceMap.map);
  const dir = path.join(artifacts, 'original');
  fs.mkdirSync(dir, { recursive: true });
  const written = originals.map((o, i) => {
    const name = `${String(i).padStart(2, '0')}-${path.basename(o.name).replace(/[^\w.-]+/g, '_') || 'source.js'}`;
    const file = path.join(dir, name);
    fs.writeFileSync(file, o.text);
    return { name: o.name, file, bytes: Buffer.byteLength(o.text) };
  });
  say(`sourcemap: inline map carries sourcesContent for ${written.length} original file(s) -> ${dir}`);
  say('sourcemap: the answer is "read the source". Deobfuscation was NOT run.');
  report.ok = true;
  report.verdict = 'sourcemap-originals';
  report.output = { kind: 'original-sources', dir, files: written };
  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
  console.log(args.json ? JSON.stringify({ ok: true, verdict: report.verdict, files: written.map(w => w.file), report: reportFile }) : `report: ${reportFile}`);
  process.exit(0);
}

/* --- 2. webcrack ----------------------------------------------------------------- */
let current = code;
let currentStage = 'input';
let modulesWritten = [];
try {
  const wc = await runWebcrack(code, { moduleDir: path.join(stagesDir, '1-webcrack-modules') });
  const parsed = parseChecks(wc.code).anyParses;
  fs.writeFileSync(path.join(stagesDir, '1-webcrack.js'), wc.code);
  modulesWritten = wc.modules;
  if (parsed) { current = wc.code; currentStage = 'webcrack'; }
  stages.push({
    name: 'webcrack', ok: parsed, ms: wc.ms, inBytes: Buffer.byteLength(code), outBytes: Buffer.byteLength(wc.code),
    bundleType: wc.bundleType, modules: modulesWritten.map(m => m.name), moduleError: wc.moduleError,
    artifact: path.join(stagesDir, '1-webcrack.js'),
    note: parsed
      ? `deobfuscate + unminify + unpack${wc.bundleType ? ` (${wc.bundleType}, ${modulesWritten.length} module file(s) extracted)` : ''}`
      : 'output did not parse; kept the previous stage'
  });
  say(`stage webcrack: ${Buffer.byteLength(code)} -> ${Buffer.byteLength(wc.code)} B in ${wc.ms} ms`
    + (wc.bundleType ? ` [${wc.bundleType}: ${modulesWritten.length} module file(s) -> ${path.join(stagesDir, '1-webcrack-modules')}]` : '')
    + (parsed ? '' : ' (unparsable output, discarded)'));
} catch (e) {
  stages.push({ name: 'webcrack', ok: false, error: String(e.message).slice(0, 300), inBytes: Buffer.byteLength(code), outBytes: 0 });
  say(`stage webcrack: FAILED (${String(e.message).slice(0, 160)})`);
}

/* Obfuscation hides the bundler: the browserify/webpack runtime is inside the
   string table before webcrack runs and readable after it. So the decision for
   the next stage is taken on the *unminified* bytes, not on the input. */
const triageAfterWebcrack = triage(current);
if (currentStage === 'webcrack' && triageAfterWebcrack.verdict !== triageReport.verdict) {
  say(`triage (post-webcrack): verdict=${triageAfterWebcrack.verdict}  bundler=${triageAfterWebcrack.bundlers.join(', ') || 'none'}  transpiler=${triageAfterWebcrack.transpilerArtifacts.join(', ') || 'none'}`);
}

/* --- 3. wakaru ------------------------------------------------------------------- */
const bundleEvidence = (stages.find(s => s.name === 'webcrack') || {}).modules?.length || 0;
const transpilerEvidence = triageReport.transpilerArtifacts.length + triageAfterWebcrack.transpilerArtifacts.length
  + triageReport.bundlers.length + triageAfterWebcrack.bundlers.length + bundleEvidence;
const wakaruWanted = args.wakaru === 'always'
  || (args.wakaru === 'auto' && transpilerEvidence > 0);
if (wakaruWanted) {
  const wk = runWakaru(current);
  const res = await wk;
  if (res.ok) {
    const parsed = parseChecks(res.code).anyParses;
    fs.writeFileSync(path.join(stagesDir, '2-wakaru.js'), res.code);
    if (parsed) { current = res.code; currentStage = 'wakaru'; }
    stages.push({
      name: 'wakaru', ok: parsed, ms: res.ms, inBytes: Buffer.byteLength(current), outBytes: Buffer.byteLength(res.code),
      artifact: path.join(stagesDir, '2-wakaru.js'),
      note: parsed ? 'un-transpile + ESM/CJS + unpack' : 'output did not parse; kept the previous stage'
    });
    say(`stage wakaru  : ${Buffer.byteLength(current)} -> ${Buffer.byteLength(res.code)} B in ${res.ms} ms${parsed ? '' : ' (unparsable output, discarded)'}`);
  } else {
    stages.push({ name: 'wakaru', ok: false, error: res.error, outBytes: 0 });
    say(`stage wakaru  : skipped/failed (${String(res.error).slice(0, 160)})`);
  }
} else {
  stages.push({ name: 'wakaru', ok: true, skipped: true, note: 'no transpiler artifacts and no bundler evidence (post-webcrack triage included); --wakaru always forces it' });
  say(`stage wakaru  : skipped (no transpiler artifacts or bundle evidence; --wakaru always forces it)`);
}
report.triageAfterWebcrack = triageAfterWebcrack;
report.modules = modulesWritten;

/* --- 4. measure + assert --------------------------------------------------------- */
const parse = parseChecks(current);
const residualsAfter = residuals(current);
fs.writeFileSync(outFile, current);
const expects = args.expect.map(e => ({ expect: e, found: current.includes(e) }));

report.ok = parse.anyParses && expects.every(e => e.found);
report.verdict = triageReport.verdict;
report.stageUsed = currentStage;
report.residualsAfter = residualsAfter;
report.parse = parse;
report.expects = expects.length ? { requested: args.expect, found: expects.filter(e => e.found).length, missing: expects.filter(e => !e.found).map(e => e.expect) } : null;
report.recoveredStrings = stringLiterals(current);
report.output = { file: outFile, bytes: Buffer.byteLength(current), sha256: crypto.createHash('sha256').update(current).digest('hex') };

const delta = (k) => `${residualsBefore[k]} -> ${residualsAfter[k]}`;
say(`residuals: hexIdentifiers ${delta('hexIdentifiers')} | tableAccessorCalls ${delta('tableAccessorCalls')} | dispatcherLoops ${delta('dispatcherLoops')} | eval ${delta('evalCalls')}`);
say(`parse: acorn=${parse.acorn} meriyah=${parse.meriyah} babel=${parse.babel}`);
say(`recovered: ${outFile} (${Buffer.byteLength(current)} B)  strings>=8ch: ${report.recoveredStrings.slice(0, 6).map(s => JSON.stringify(s.slice(0, 48))).join(', ')}${report.recoveredStrings.length > 6 ? ', …' : ''}`);
if (args.expect.length) {
  for (const e of expects) say(`expect: ${e.found ? 'FOUND  ' : 'MISSING'} ${JSON.stringify(e.expect)}`);
}
say(`report: ${reportFile}`);
fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));

if (args.print) process.stdout.write(current.endsWith('\n') ? current : current + '\n');
if (args.json) console.log(JSON.stringify({ ok: report.ok, verdict: report.verdict, stageUsed: currentStage, output: report.output, report: reportFile, expects: report.expects, parse }));
process.exit(report.ok ? 0 : (expects.some(e => !e.found) ? 4 : 3));
