/* recover.mjs — recover the signing algorithm + key of the hardened (/obf) page.
 *
 * What it does, in analyst order:
 *   1. read the page source and locate the string-array indirection
 *        (array literal + <decoder>(i) + XOR constant)
 *   2. decode the table, locally, with plain Node
 *   3. (optional --runtime-probe) ask the *live page* to decode the same indices
 *      through Runtime.evaluate and require both paths to agree
 *   4. candidate the decoded literals as the signing key and verify each one by
 *      reproducing the CAPTURED signatures with node:crypto — an implementation
 *      wholly independent of the page's own crypto
 *   5. confirm the key a second time against the server's own keyId
 *      (sha256(key)[0:16] from GET /api/health), then reproduce every captured
 *      request, not just the first
 *
 * A recovered key that fails step 4 or 5 is not reported as recovered.
 *
 *   node tools/recover.mjs --capture <capture.json> [--page http://127.0.0.1:8787/obf]
 *                          [--out recovered.json] [--runtime-probe] [--top 12]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { CDP } from './cdp.mjs';
import { launchChrome } from './chrome.mjs';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const capturePath = get('--capture', path.join(os.tmpdir(), 'web-reverse-captures', 'obf.json'));
const outPath = get('--out', path.join(os.tmpdir(), 'web-reverse-captures', 'recovered.json'));
const topN = Number(get('--top', 12));

const capture = JSON.parse(fs.readFileSync(capturePath, 'utf8'));
const pageUrl = get('--page', capture.targetUrl);
const origin = new URL(pageUrl).origin;

const hmacHex = (key, msg) => crypto.createHmac('sha256', Buffer.from(key, 'utf8')).update(msg, 'utf8').digest('hex');
const sha256Hex = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/* ------------------------------------------------------- 1. locate the obfuscator */
function extractTable(html) {
  const decM = /function\s+([A-Za-z_$][\w$]*)\s*\(\s*i\s*\)\s*\{\s*var\s+s\s*=\s*([A-Za-z_$][\w$]*)\s*\[\s*i\s*\][^}]*\^\s*(\d+)/.exec(html);
  if (!decM) throw new Error('no string-array decoder found in page source (obfuscator family not recognised)');
  const [, decoder, arrayVar, xorKey] = decM;
  const arrM = new RegExp(`var\\s+${arrayVar}\\s*=\\s*\\[([\\s\\S]*?)\\]\\s*;`).exec(html);
  if (!arrM) throw new Error(`array variable ${arrayVar} used by ${decoder} was not found`);
  const literals = [...arrM[1].matchAll(/'((?:[^'\\]|\\.)*)'/g)].map(m => m[1]);
  const unescape = s => s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\'/g, "'").replace(/\\\\/g, '\\');
  const x = Number(xorKey);
  const table = literals.map(l => [...unescape(l)].map(c => String.fromCharCode(c.charCodeAt(0) ^ x)).join(''));
  return { decoder, arrayVar, xorKey: x, encodedCount: literals.length, table };
}

/* --------------------------------------------------------- 2/3. decode the table */
async function decodeViaRuntimeProbe(pageUrl, decoder, indices) {
  const chrome = await launchChrome({ headless: true, tag: 'recover', url: 'about:blank' });
  try {
    const browser = await CDP.connect(chrome.wsUrl);
    const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
    await browser.send('Page.enable', {}, sessionId);
    await browser.send('Runtime.enable', {}, sessionId);
    const loaded = browser.waitFor('Page.loadEventFired', { sessionId, timeoutMs: 15_000 });
    await browser.send('Page.navigate', { url: pageUrl }, sessionId);
    await loaded;
    const expr = `[]${indices.map(i => `.concat([${decoder}(${i})])`).join('')}`;
    const res = await browser.send('Runtime.evaluate', { expression: expr, returnByValue: true }, sessionId);
    if (res.exceptionDetails) throw new Error(res.exceptionDetails.exception?.description || 'runtime probe failed');
    browser.close();
    return res.result.value;
  } finally {
    await chrome.close();
  }
}

const tableInfo = extractTable(await (await fetch(pageUrl)).text());
console.log(`page            ${pageUrl}`);
console.log(`obfuscator      array=${tableInfo.arrayVar} decoder=${tableInfo.decoder}() xor=0x${tableInfo.xorKey.toString(16)} entries=${tableInfo.encodedCount}`);
console.log('decoded table:');
tableInfo.table.forEach((s, i) => {
  const printable = /^[\x20-\x7e]+$/.test(s);
  console.log(`  [${String(i).padStart(2)}] ${printable ? JSON.stringify(s) : '<non-printable>'}`);
});

if (has('--runtime-probe')) {
  const indices = tableInfo.table.map((_, i) => i);
  const live = await decodeViaRuntimeProbe(pageUrl, tableInfo.decoder, indices);
  const agree = indices.every(i => live[i] === tableInfo.table[i]);
  console.log(`runtime probe   Runtime.evaluate(${tableInfo.decoder}(i)) agrees with local decode: ${agree}`);
  if (!agree) {
    console.error('runtime decode disagrees with the static decode — refusing to continue');
    process.exit(4);
  }
}

/* ------------------------------------------------------- 4. verify against capture */
const targets = capture.requests.filter(r => r.headers['x-lab-sign'] && r.body !== null);
if (targets.length === 0) throw new Error('capture has no signed request to verify against');

const tried = [];
let found = null;
for (const candidate of tableInfo.table) {
  const matches = targets.filter(t => hmacHex(candidate, `${t.headers['x-lab-ts']}.${t.body}`) === t.headers['x-lab-sign']);
  tried.push({ candidate, matched: matches.length });
  if (matches.length === targets.length && targets.length > 0) { found = { key: candidate, matches: matches.length }; break; }
}

if (!found) {
  console.error(`\nno decoded literal reproduced all ${targets.length} captured signature(s):`);
  for (const t of tried) console.error(`  ${t.matched ? 'partial' : '       '} ${JSON.stringify(t.candidate)}`);
  process.exit(5);
}

const keyId = sha256Hex(found.key).slice(0, 16);
let serverKeyId = null;
try { serverKeyId = (await (await fetch(`${origin}/api/health`)).json()).keyId; } catch { /* server down; step 5 is skipped, step 4 already passed */ }
const keyIdConfirmed = serverKeyId !== null && serverKeyId === keyId;

console.log(`\nrecovered key   ${JSON.stringify(found.key)}`);
console.log(`signature       x-lab-sign = hex(HMAC-SHA256(key, "<x-lab-ts>.<raw body>"))`);
console.log(`reproduces      ${found.matches}/${targets.length} captured signature(s) with node:crypto`);
console.log(`keyId           sha256(key)[0:16] = ${keyId} vs server ${serverKeyId ?? 'unreachable'} -> ${keyIdConfirmed ? 'CONFIRMED' : 'not confirmed'}`);

const recovered = {
  recoveredAt: new Date().toISOString(),
  page: pageUrl,
  capture: path.resolve(capturePath),
  algorithm: {
    headerNames: ['x-lab-ts', 'x-lab-sign'],
    signature: 'hex(hmac-sha256(key, `${ts}.${rawBody}`))',
    encoding: 'utf8 in, lowercase hex out'
  },
  obfuscation: { arrayVar: tableInfo.arrayVar, decoder: tableInfo.decoder, xor: tableInfo.xorKey, entries: tableInfo.encodedCount },
  key: found.key,
  keyId,
  serverKeyId,
  keyIdConfirmed,
  verifiedAgainst: targets.map(t => ({ url: t.url, ts: t.headers['x-lab-ts'], sign: t.headers['x-lab-sign'], body: t.body }))
};
fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(recovered, null, 2));
console.log(`written         ${path.resolve(outPath)}`);
if (!keyIdConfirmed) process.exitCode = 6;
