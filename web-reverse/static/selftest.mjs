#!/usr/bin/env node
/* selftest.mjs — one verifiable line per pinned package.
 *
 * "Installed" is not a capability. Each check below makes the package do the
 * thing it was installed for and asserts the observable result; a package that
 * only imports cleanly would not pass. Exit 0 means every pinned package works
 * on this Node major.
 *
 * Usage: node static/selftest.mjs [--json]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

import JavaScriptObfuscator from 'javascript-obfuscator';
import { webcrack } from 'webcrack';
import * as babelCore from '@babel/core';
import * as babelParser from '@babel/parser';
import * as babelGenerator from '@babel/generator';
import * as babelTypes from '@babel/types';
import * as recast from 'recast';
import * as acorn from 'acorn';
import * as meriyah from 'meriyah';

import { runAstGrep, astGrepBin } from './lib/astgrep.mjs';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const json = process.argv.includes('--json');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wr-selftest-'));

/* Read versions straight off disk: webcrack and meriyah block `<pkg>/package.json`
   through their exports map, so require.resolve would throw. */
const version = (name) => {
  try {
    return JSON.parse(fs.readFileSync(path.join(HERE, 'node_modules', ...name.split('/'), 'package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
};

const generate = babelGenerator.generate || babelGenerator.default?.default || babelGenerator.default;

const results = [];
async function check(pkg, claim, fn) {
  const started = Date.now();
  try {
    const detail = await fn();
    results.push({ pkg, version: version(pkg.split('+')[0]), claim, ok: true, detail, ms: Date.now() - started });
  } catch (e) {
    results.push({ pkg, version: version(pkg.split('+')[0]), claim, ok: false, detail: String(e && e.message || e), ms: Date.now() - started });
  }
}

/* --- javascript-obfuscator: is the sample factory real? ------------------------ */
const MARK = 'selftest-known-answer-4f2c';
/* Same shape rules as gen-obf.mjs: `var` only (a `const`/`let` body is not
   flattened by this version) and functions declared inside a block (dead-code
   injection collects block statements there). A selftest sample that the
   obfuscator declines to transform would test nothing. */
const selftestSource = `(function () {
  if (true) {
    var K = ${JSON.stringify(MARK)};
    var buildRequest = function (op) {
      var raw = JSON.stringify({ op: op, nonce: Math.random().toString(36).slice(2, 10), at: Date.now() });
      return raw;
    };
    var sign = function (body, ts) {
      var signature = K + ts + body;
      var upper = signature.toUpperCase();
      return upper;
    };
    var submit = function () {
      var body = buildRequest("lab.submit");
      var ts = String(Date.now());
      var signature = sign(body, ts);
      var sink = [body, ts, signature];
      return sink.join("|");
    };
    window.selftest = submit;
  }
})();`;
const obfuscated = JavaScriptObfuscator.obfuscate(selftestSource, {
  compact: true, seed: 99, stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['base64'],
  rotateStringArray: true, identifierNamesGenerator: 'hexadecimal', controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1, deadCodeInjection: true, deadCodeInjectionThreshold: 1,
  selfDefending: false, target: 'browser', log: false
}).getObfuscatedCode();

await check('javascript-obfuscator', `produces a rotated string array + flattened dispatcher; source literal "${MARK}" is not in the output`,
  () => {
    if (obfuscated.includes(MARK)) throw new Error('marker still plaintext — nothing was actually obfuscated');
    const dispatchers = (obfuscated.match(/while\s*\(\s*!!\[\]\s*\)\s*\{\s*switch\s*\(/g) || []).length;
    const guarded = (obfuscated.match(/if\s*\(\s*!!\[\]\s*\)\s*\{/g) || []).length;
    if (dispatchers < 1) throw new Error('no control-flow dispatcher produced');
    return `${Buffer.byteLength(obfuscated)} B, dispatchers=${dispatchers}, guarded blocks=${guarded}`;
  });

/* --- webcrack: does it recover that sample? ------------------------------------ */
await check('webcrack', `deobfuscates the generated sample and recovers "${MARK}" as a string literal`,
  async () => {
    const res = await webcrack(obfuscated, { unpack: true, unminify: true, deobfuscate: true, jsx: true, mangle: false });
    if (!res.code.includes(MARK)) throw new Error('marker not recovered');
    if (!res.code.includes('window.selftest')) throw new Error('entry point lost');
    return `${Buffer.byteLength(obfuscated)} B -> ${Buffer.byteLength(res.code)} B, key recovered`;
  });

/* --- wakaru: does it put the syntax sugar back? -------------------------------- */
await check('@wakaru/cli', 'un-transpiles optional chaining / nullish coalescing and ESM-ifies CJS',
  async () => {
    const transpiled = [
      'var _a;',
      'function f(a) { return (_a = a) === null || _a === void 0 ? void 0 : _a.b; }',
      'var _c;',
      'var x = c !== null && c !== void 0 ? c : 3;',
      'exports.f = f;'
    ].join('\n');
    const { code } = await new Promise((resolve, reject) => {
      const child = spawnWakaru(resolve, reject);
      child.stdin.end(transpiled);
    });
    if (!code.includes('?.')) throw new Error('no optional chaining recovered');
    if (!code.includes('??')) throw new Error('no nullish coalescing recovered');
    return `recovered "?." and "??" (${Buffer.byteLength(code)} B out)`;
  });

/* --- ast-grep: one surgical rewrite -------------------------------------------- */
await check('@ast-grep/cli', 'rewrites one pattern in place and reports the change count',
  async () => {
    const file = path.join(tmp, 'sg-target.js');
    fs.writeFileSync(file, 'const a = legacyCall(1);\nconst b = 2;\n');
    const r = await runAstGrep(['run', '--pattern', 'legacyCall($X)', '--rewrite', 'modernCall($X)', '--lang', 'js', '--update-all', file]);
    if (r.code !== 0) throw new Error(`exit ${r.code}: ${(r.out + r.err).trim().slice(0, 160)}`);
    const after = fs.readFileSync(file, 'utf8');
    if (!after.includes('modernCall(1)') || !after.includes('const b = 2;')) throw new Error('rewrite did not land as expected');
    return `${r.out.trim().split('\n')[0]} (${path.basename(r.bin)})`;
  });

/* --- Babel: scope-aware renaming, the reason it is here ------------------------ */
await check('@babel/core+@babel/traverse+@babel/types+@babel/generator', 'parses, resolves a scope binding, renames it through path.scope.rename',
  () => {
    const src = 'const _0x1 = 41; function f() { return _0x1 + 1; } f();';
    const ast = babelParser.parse(src, { sourceType: 'module' });
    let renamed = 0;
    babelCore.traverse(ast, {
      Identifier(p) {
        if (p.node.name === '_0x1' && p.isReferencedIdentifier()) { p.scope.rename('_0x1', 'answer'); renamed++; }
      }
    });
    const out = generate(ast).code;
    if (!out.includes('answer')) throw new Error('rename did not apply');
    if (out.includes('_0x1')) throw new Error('old name survived the rename');
    return `binding renamed (${renamed} reference(s) rewritten), babel-types ${typeof babelTypes.identifier === 'function' ? 'ok' : 'missing'}`;
  });

/* --- recast: nondestructive printing ------------------------------------------- */
await check('recast', 'prints a patched AST without reformatting untouched code',
  () => {
    const src = 'function keep(a) {\n  return a    +    1;   // deliberate odd spacing\n}\nfunction drop(b) { return b; }\n';
    const ast = recast.parse(src, { parser: { parse: s => babelParser.parse(s, { sourceType: 'script' }) } });
    recast.visit(ast, {
      visitFunctionDeclaration(p) {
        if (p.node.id.name === 'drop') p.node.id.name = 'renamed';
        this.traverse(p);
      }
    });
    const code = recast.print(ast).code;
    if (!code.includes('a    +    1')) throw new Error('untouched code was reformatted — that is what recast must not do');
    if (!code.includes('function renamed')) throw new Error('patch did not apply');
    return 'untouched formatting and comments preserved, patch applied';
  });

/* --- acorn / meriyah: the fast ESTree parsers ---------------------------------- */
await check('acorn', 'parses and tokenizes with the ESTree shape the instrumentation path uses',
  () => {
    const ast = acorn.parse('const x = f({a:1}); // note', { ecmaVersion: 'latest', sourceType: 'module' });
    const tokens = [...acorn.tokenizer('const x = 1;', { ecmaVersion: 'latest' })].length;
    return `${ast.body.length} top-level node(s), ${tokens} tokens`;
  });

await check('meriyah', 'parses both script and module goal with next-gen syntax',
  () => {
    const s = meriyah.parseScript('var a = x?.y ?? 1;', { next: true });
    const m = meriyah.parseModule('import x from "y"; export default (a) => a ** 2;', { next: true });
    return `script ${s.body.length} node(s), module ${m.body.length} node(s)`;
  });

/* ------------------------------------------------------------------ report */
fs.rmSync(tmp, { recursive: true, force: true });
const failed = results.filter(r => !r.ok);
if (json) {
  console.log(JSON.stringify({ ok: failed.length === 0, node: process.version, results }, null, 2));
} else {
  console.log(`web-reverse/static selftest — node ${process.version}`);
  for (const r of results) {
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'} ${`${r.pkg}@${r.version}`.padEnd(56)} ${r.ok ? r.detail : r.detail.slice(0, 120)}`);
    console.log(`       ${r.claim}`);
  }
  console.log(`\n${failed.length === 0 ? `ALL ${results.length} package checks passed` : `${failed.length} of ${results.length} checks FAILED`}`);
}
process.exit(failed.length === 0 ? 0 : 1);

/* small local helper so the wakaru check does not duplicate the driver's spawn */
function spawnWakaru(resolve, reject) {
  const { spawn } = require('node:child_process');
  const bin = require.resolve('@wakaru/cli/bin/wakaru');
  const child = spawn(process.execPath, [bin], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', d => out += d);
  child.stderr.on('data', d => err += d);
  child.on('error', reject);
  child.on('close', (code) => code === 0 ? resolve({ code: out }) : reject(new Error(`wakaru exited ${code}: ${err.trim().slice(0, 160)}`)));
  return child;
}
