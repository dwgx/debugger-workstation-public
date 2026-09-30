#!/usr/bin/env node
/* gen-obf.mjs — the known-answer sample factory.
 *
 * A deobfuscator you cannot falsify is a claim, not a capability. This tool
 * generates obfuscated variants of a plaintext signer we wrote, using
 * javascript-obfuscator with the standard protections:
 *
 *   string array (base64) + rotation + control-flow flattening + dead-code
 *   injection + hexadecimal identifier mangling
 *
 * and writes, next to them, the plaintext they were generated from
 * (`known-answer.json`). The deobfuscation toolchain is then graded against code
 * the generator has never seen: every run reseeds the key material for the
 * non-page variants, so a hardcoded answer cannot pass.
 *
 * Self-authored samples only. Nothing is downloaded, and the page's key is the
 * lab's public constant (`lab/server.mjs`), which is not a credential.
 *
 * Usage:
 *   node static/gen-obf.mjs [--out-dir <dir>] [--page <file>] [--seed <n>] [--json]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { LAB_KEY } from '../lab/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DEFAULT = path.join(os.tmpdir(), 'web-reverse-captures', 'static');

/* ------------------------------------------------------------------ args */
const args = process.argv.slice(2);
const get = (flag, fallback) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : fallback;
};
if (args.includes('--help') || args.includes('-h')) {
  console.log('gen-obf.mjs [--out-dir <dir>] [--page <file>] [--seed <n>] [--json]');
  process.exit(0);
}
const jsonOut = args.includes('--json');
const seed = Number(get('--seed', 20260930));
const outDir = get('--out-dir', ARTIFACTS_DEFAULT);
const pageFile = get('--page', path.join(outDir, 'obf-gen.html'));
fs.mkdirSync(path.dirname(pageFile), { recursive: true });
fs.mkdirSync(outDir, { recursive: true });

/* ------------------------------------------------------- the sample plaintexts
 * Three shapes, so the pipeline is exercised on three different problems:
 *   page    — a browser page that signs a request (the gate proof target)
 *   signer  — a standalone script (known answer + executed back-to-back)
 *   bundle  — a browserify-shaped bundle carrying transpiled-out syntax, which is
 *             the case only the un-transpiling stage can fix
 */
/* Why the samples look like this (measured, not assumed — see the note in
 * web-reverse/README.md):
 *
 *   - `var` everywhere, never `const`/`let`: javascript-obfuscator 5.8.0 does not
 *     control-flow-flatten a function body that declares block-scoped bindings
 *     (verified: identical body, `const` -> 0 dispatchers, `var` -> 1 dispatcher).
 *   - the `if (true) { var f = function () {...} }` shape: dead-code injection
 *     collects block statements from that shape and produced nothing without it
 *     (verified against the README's own reference example).
 *
 * So this is what obfuscator.io actually eats: bundled, `var`-flavoured client
 * code. A sample factory that emits something the obfuscator silently declines to
 * transform would be a known-answer test for nothing.
 */
function plaintextPage(key) {
  return `/* Known-answer sample for the static toolchain. Generated, not hand-maintained. */
(function () {
  if (true) {
    var LAB_KEY = ${JSON.stringify(key)};
    var ENDPOINT = "/api/submit";
    var buildBody = function () {
      var raw = JSON.stringify({ op: "lab.submit", nonce: Math.random().toString(36).slice(2, 10), at: Date.now() });
      return raw;
    };
    var sign = function (body, ts) {
      var signature = LabCrypto.hmacSha256Hex(LAB_KEY, ts + "." + body);
      return signature;
    };
    var submit = function () {
      var body = buildBody();
      var ts = String(Date.now());
      var signature = sign(body, ts);
      var xhr = new XMLHttpRequest();
      xhr.open("POST", ENDPOINT, true);
      xhr.setRequestHeader("content-type", "application/json");
      xhr.setRequestHeader("x-lab-ts", ts);
      xhr.setRequestHeader("x-lab-sign", signature);
      xhr.onload = function () {
        var line = "HTTP " + xhr.status + " ts=" + ts + " sign=" + signature;
        document.getElementById("out").textContent = line;
      };
      xhr.send(body);
    };
    document.getElementById("go").addEventListener("click", submit);
    window.labSign = sign;
    window.labBuildBody = buildBody;
    window.labSubmit = submit;
  }
})();
`;
}

function plaintextSigner(key) {
  return `/* Known-answer sample: standalone signer. */
(function () {
  if (true) {
    var SIGN_KEY = ${JSON.stringify(key)};
    var buildRequest = function (op) {
      var raw = JSON.stringify({ op: op, nonce: Math.random().toString(36).slice(2, 10), at: Date.now() });
      return raw;
    };
    var signRequest = function (body, ts) {
      var signature = LabCrypto.hmacSha256Hex(SIGN_KEY, ts + "." + body);
      return signature;
    };
    window.labSignB = signRequest;
    window.labBuildB = buildRequest;
  }
})();
`;
}

function plaintextBundleModule(key) {
  return `"use strict";
(function () {
  if (true) {
    var DEFAULT_ALGORITHM = "sha256";
    var SIGN_KEY = ${JSON.stringify(key)};
    var pickAlgorithm = function (options) {
      var _options$algorithm;
      var algorithm = (_options$algorithm = options.algorithm) === null || _options$algorithm === void 0 ? void 0 : _options$algorithm.name;
      var chosen = algorithm !== null && algorithm !== void 0 ? algorithm : DEFAULT_ALGORITHM;
      return chosen;
    };
    var buildRequest = function (op) {
      var raw = JSON.stringify({ op: op, nonce: Math.random().toString(36).slice(2, 10), at: Date.now() });
      return raw;
    };
    var signRequest = function (body, ts) {
      var signature = LabCrypto.hmacSha256Hex(SIGN_KEY, ts + "." + body);
      return signature;
    };
    module.exports = { signRequest: signRequest, buildRequest: buildRequest, pickAlgorithm: pickAlgorithm };
  }
})();
`;
}

/* The real browserify preamble shape (compact), which is what the bundler
   fingerprint looks for — a self-authored sample must look like the thing it
   claims to be. */
function browserifyWrap(moduleSource) {
  return `(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
${moduleSource.trim()}
},{}]},{},[1]);`;
}

/* ------------------------------------------------------------- obfuscator config */
const OBFUSCATOR_OPTIONS = {
  compact: true,
  stringArray: true,
  stringArrayThreshold: 1,
  stringArrayEncoding: ['base64'],
  stringArrayWrappersCount: 1,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersType: 'function',
  rotateStringArray: true,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
  numbersToExpressions: true,
  simplify: true,
  transformObjectKeys: true,
  unicodeEscapeSequence: false,
  selfDefending: false,
  debugProtection: false,
  disableConsoleOutput: false,
  sourceMap: false,
  target: 'browser',
  log: false
};

function obfuscate(source, extra = {}) {
  const options = { ...OBFUSCATOR_OPTIONS, ...extra, seed };
  const code = JavaScriptObfuscator.obfuscate(source, options).getObfuscatedCode();
  if (code.includes('</script')) throw new Error('obfuscator produced a </script> sequence; refusing to embed it in HTML');
  return code;
}

/* ------------------------------------------------------------------ generate */
const freshToken = () => crypto.randomBytes(8).toString('hex');
const signerKey = `lab-static-signer-${freshToken()}-not-a-real-secret`;
const bundleKey = `lab-static-bundle-${freshToken()}-not-a-real-secret`;

const variants = [];

/* 1 — the page, signed with the lab's own key so the gate can accept what the
       recovered code produces. */
{
  const plaintext = plaintextPage(LAB_KEY);
  const code = obfuscate(plaintext, { seed: seed + 1 });
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>lab target — generated obfuscator.io variant</title>
<style>
  body { font: 14px/1.5 ui-monospace, Consolas, monospace; margin: 2rem; max-width: 46rem; }
  button { font: inherit; padding: .4rem .9rem; }
  pre { background: #f4f4f4; padding: .75rem; overflow: auto; }
  .hint { color: #666; }
</style>
</head>
<body>
<h1>lab target — generated obfuscator.io variant</h1>
<p class="hint">Generated by <code>web-reverse/static/gen-obf.mjs</code> with
javascript-obfuscator 5.8.0: base64 string array with rotation, control-flow flattening,
dead-code injection, hexadecimal identifier mangling. Same client and same key as
<a href="/plain">/plain</a> — that is the point: a known answer with a known gate.</p>
<p><button id="go">Sign and POST to /api/submit</button></p>
<pre id="out">idle</pre>
<script src="/js/sha256-pure.js"></script>
<script>
${code}
</script>
</body>
</html>
`;
  fs.writeFileSync(pageFile, html);
  variants.push({
    id: 'page', kind: 'html-page', file: pageFile, servedAt: '/obf-gen',
    key: LAB_KEY, entry: 'labSign', buildEntry: 'labBuildBody',
    expects: [LAB_KEY, 'hmacSha256Hex', 'labSign'],
    obfuscatedBytes: Buffer.byteLength(code), plaintext
  });
}

/* 2 — a standalone signer with a key this run invented. Nothing can be
       memorized from a previous run. */
{
  const plaintext = plaintextSigner(signerKey);
  const code = obfuscate(plaintext, { seed: seed + 2 });
  const file = path.join(outDir, 'signer-obf.js');
  fs.writeFileSync(file, code);
  variants.push({
    id: 'signer', kind: 'script', file,
    key: signerKey, entry: 'labSignB', buildEntry: 'labBuildB',
    expects: [signerKey, 'hmacSha256Hex', 'labSignB'],
    obfuscatedBytes: code.length, plaintext
  });
}

/* 3 — a browserify-shaped bundle whose module carries transpiled optional
       chaining and nullish coalescing. webcrack unpacks it; wakaru has to put the
       syntax sugar back. */
{
  const plaintext = browserifyWrap(plaintextBundleModule(bundleKey));
  const code = obfuscate(plaintext, { seed: seed + 3 });
  const file = path.join(outDir, 'bundle-obf.js');
  fs.writeFileSync(file, code);
  variants.push({
    id: 'bundle', kind: 'browserify-bundle', file,
    key: bundleKey, entry: 'signRequest', buildEntry: 'buildRequest',
    expects: [bundleKey, '?.', '??', 'hmacSha256Hex'],
    obfuscatedBytes: code.length, plaintext
  });
}

/* ------------------------------------------------------------- negative control
 * If the plaintext leaked into the obfuscated artifact, every downstream
 * "recovered the key" assertion would be vacuous — so check it here and refuse.
 * Then fingerprint the artifact with the same triage the deobfuscator uses, so
 * "this sample contains a rotated string array and a flattened dispatcher" is a
 * measured property of the bytes, not a claim about the options object. */
const REQUIRED_FAMILIES = ['string-array', 'control-flow-flattening', 'dead-code-injection'];
const { triage } = await import('./lib/triage.mjs');

for (const v of variants) {
  const bytes = fs.readFileSync(v.file, 'utf8');
  if (bytes.includes(v.key)) {
    console.error(`gen-obf: FATAL — the key is still plaintext in ${v.file}; the sample proves nothing`);
    process.exit(3);
  }
  v.leakedPlaintextKey = false;
  const t = triage(bytes);
  v.protections = {
    families: t.obfuscatorFamilies.map(f => f.id),
    hexIdentifiers: (bytes.match(/_0x[0-9a-fA-F]{4,6}/g) || []).length,
    dispatchers: (bytes.match(/while\s*\(\s*!!\[\]\s*\)\s*\{\s*switch\s*\(/g) || []).length,
    guardedBlocks: (bytes.match(/if\s*\(\s*!!\[\]\s*\)\s*\{/g) || []).length,
    stringArrayEntries: (bytes.match(/['"][A-Za-z0-9+/=]{8,}['"]/g) || []).length
  };
  v.protections.missing = REQUIRED_FAMILIES.filter(f => !v.protections.families.includes(f));
  if (v.protections.missing.length) {
    console.error(`gen-obf: WARNING — ${v.id}: javascript-obfuscator did not produce ${v.protections.missing.join(', ')} on this source shape;`);
    console.error(`gen-obf:           the known-answer test is weaker than it looks. Fix the sample, do not fake the option.`);
  }
}
const unprotected = variants.filter(v => v.protections.missing.length);

const manifest = {
  generator: 'web-reverse/static/gen-obf.mjs',
  at: new Date().toISOString(),
  obfuscator: {
    package: 'javascript-obfuscator',
    version: JavaScriptObfuscator.version,
    seed,
    options: OBFUSCATOR_OPTIONS
  },
  variants
};
const manifestFile = path.join(outDir, 'known-answer.json');
fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));

if (jsonOut) {
  console.log(JSON.stringify({
    ok: unprotected.length === 0,
    at: manifest.at,
    seed,
    outDir,
    manifest: manifestFile,
    variants: variants.map(v => ({
      id: v.id, kind: v.kind, file: v.file, obfuscatedBytes: v.obfuscatedBytes,
      expects: v.expects.length, protections: v.protections
    }))
  }, null, 2));
} else {
  console.log(`gen-obf: javascript-obfuscator ${JavaScriptObfuscator.version}, seed ${seed}`);
  for (const v of variants) {
    console.log(`  ${v.id.padEnd(7)} ${String(v.obfuscatedBytes).padStart(7)} B  ${v.file}`);
    console.log(`          protections: ${v.protections.families.join(', ')}  ` +
      `(dispatchers ${v.protections.dispatchers}, guarded blocks ${v.protections.guardedBlocks}, hex ids ${v.protections.hexIdentifiers})`);
  }
  console.log(`  known answer -> ${manifestFile}`);
  console.log(`  negative control: plaintext key absent from every generated artifact (checked)`);
  if (unprotected.length) console.log(`  WARNING: ${unprotected.length} variant(s) missing a protection family: ${unprotected.map(v => `${v.id}(${v.protections.missing.join('|')})`).join(', ')}`);
}
process.exit(unprotected.length ? 4 : 0);
