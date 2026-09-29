/* replay.mjs — prove the recovered algorithm by minting a valid request OUTSIDE the browser.
 *
 * No Chrome, no page, no copied session: plain node:http plus the recovered key and
 * the recovered algorithm. Two modes, and the contrast between them is the whole point:
 *
 *   verbatim  resend the captured bytes untouched   -> the server must REJECT it
 *             (the signature is stale or already spent; a copy is worthless)
 *   recompute sign the same body with a fresh ts    -> the server must ACCEPT it
 *   --new-body forge a body the page never sent     -> the server must ACCEPT it
 *
 *   node tools/replay.mjs --capture <capture.json> --key-file <recovered.json>
 *                         [--url http://127.0.0.1:8787] [--new-body]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const capturePath = get('--capture', path.join(os.tmpdir(), 'web-reverse-captures', 'obf.json'));
const keyFile = get('--key-file', path.join(os.tmpdir(), 'web-reverse-captures', 'recovered.json'));
const capture = JSON.parse(fs.readFileSync(capturePath, 'utf8'));
const recovered = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
const key = get('--key', recovered.key);
const origin = get('--url', new URL(capture.targetUrl).origin);
const endpoint = new URL(capture.targetUrl).pathname.replace(/\/(plain|obf|fingerprint)$/, '') + '/api/submit';

const sign = (body, ts, k = key) => crypto.createHmac('sha256', Buffer.from(k, 'utf8')).update(`${ts}.${body}`, 'utf8').digest('hex');

function post(headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(endpoint, origin);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
      headers: { ...headers, 'content-length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

const signed = capture.requests.filter(r => r.headers['x-lab-sign'] && r.body !== null);
if (signed.length === 0) throw new Error(`${capturePath} has no signed request`);
const sample = signed[signed.length - 1];
const results = {};

console.log(`capture         ${path.resolve(capturePath)}`);
console.log(`recovered key   ${JSON.stringify(key)}  (keyId ${recovered.keyId ?? '?'})`);
console.log(`endpoint        ${new URL(endpoint, origin)}`);

/* --- 1. verbatim copy: must fail ------------------------------------------------ */
{
  const ts = sample.headers['x-lab-ts'];
  const sig = sample.headers['x-lab-sign'];
  const res = await post({ 'content-type': 'application/json', 'x-lab-ts': ts, 'x-lab-sign': sig }, sample.body);
  results.verbatim = res;
  console.log(`\n[1] verbatim      resend the captured bytes (ts=${ts}, sign=${sig.slice(0, 16)}…)`);
  console.log(`    -> HTTP ${res.status} ${res.body.trim()}`);
  console.log(`    copy-alone works: ${res.status === 200 ? 'YES (bad: the gate is not a gate)' : 'NO (as designed)'}`);
}

/* --- 2. recompute with the same body, fresh timestamp --------------------------- */
{
  const ts = String(Date.now());
  const sig = sign(sample.body, ts);
  const res = await post({ 'content-type': 'application/json', 'x-lab-ts': ts, 'x-lab-sign': sig }, sample.body);
  results.recompute = { ts, sig, ...res };
  console.log(`\n[2] recompute     same body, fresh ts=${ts}, signature minted in plain Node`);
  console.log(`    sign ${sig}  ${sig === sample.headers['x-lab-sign'] ? '(same as captured)' : '(differs from captured — the signature tracks the timestamp)'}`);
  console.log(`    -> HTTP ${res.status} ${res.body.trim()}`);
}

/* --- 3. forge a body the page never sent --------------------------------------- */
if (has('--new-body')) {
  const body = JSON.stringify({ op: 'lab.forge', nonce: crypto.randomBytes(4).toString('hex'), at: Date.now() });
  const ts = String(Date.now());
  const sig = sign(body, ts);
  const res = await post({ 'content-type': 'application/json', 'x-lab-ts': ts, 'x-lab-sign': sig }, body);
  results.forge = { body, ts, sig, ...res };
  console.log(`\n[3] forge         body never sent by any client`);
  console.log(`    body ${body}`);
  console.log(`    -> HTTP ${res.status} ${res.body.trim()}`);
}

const ok = results.verbatim.status !== 200
  && results.recompute.status === 200
  && (!results.forge || results.forge.status === 200);
console.log(`\nverdict         ${ok ? 'PASS — the signature was reproduced, not copied' : 'FAIL'}`);
if (!ok) process.exitCode = 7;
