/* loop.mjs — ONE command that runs the whole web-reverse loop and judges itself.
 *
 *   negative gate -> capture /plain -> capture /obf -> recover key from the obfuscated
 *   page -> replay outside the browser -> bot-detection report
 *
 * Every step is the same tool an analyst would call by hand; this file only sequences
 * them, checks the expected outcome, and prints one PASS/FAIL table. Exit code 0 means
 * the loop closed on this machine, in this run.
 *
 *   node tools/loop.mjs
 */
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, keyId } from '../lab/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ART = path.join(os.tmpdir(), 'web-reverse-captures', 'loop');
const steps = [];

/* Children run ASYNC on purpose: the lab server lives in this process, so a
   synchronous spawn would block the very event loop that has to answer the
   browser's requests. (First version used spawnSync and deadlocked exactly so.) */
function run(label, script, args, { expectStatus = 0, echo = true } = {}) {
  const started = Date.now();
  return new Promise(resolve => {
    const child = spawn(process.execPath, [path.join(HERE, script), ...args], { encoding: 'utf8' });
    let out = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => out += d);
    child.on('close', code => {
      if (echo) { console.log(`\n${'-'.repeat(78)}\n$ node tools/${script} ${args.join(' ')}\n${'-'.repeat(78)}\n${out.trimEnd()}`); }
      const pass = code === expectStatus;
      steps.push({ label, pass, detail: pass ? `exit ${code}` : `expected exit ${expectStatus}, got ${code}`, ms: Date.now() - started });
      resolve({ code, out, pass });
    });
  });
}

const server = createServer({ log: () => {} });
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const origin = `http://127.0.0.1:${port}`;
const plainCapture = path.join(ART, 'plain.json');
const obfCapture = path.join(ART, 'obf.json');
const recovered = path.join(ART, 'recovered.json');
const fingerprintReport = path.join(ART, 'fingerprint.json');

console.log(`web-reverse lab loop`);
console.log(`  server        ${origin} (in-process, loopback, binds port 0)`);
console.log(`  keyId         ${keyId()}`);
console.log(`  artifacts     ${ART}`);

/* 1 — the gate must reject an unsigned request, or nothing below means anything. */
{
  const res = await fetch(`${origin}/api/submit`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op: 'unsigned-probe' })
  });
  const body = await res.text();
  console.log(`\n${'-'.repeat(78)}\n[1] unsigned POST /api/submit\n${'-'.repeat(78)}\n-> HTTP ${res.status} ${body}`);
  steps.push({ label: 'unsigned request rejected by the gate', pass: res.status === 401, detail: `HTTP ${res.status}`, ms: 0 });
}

/* 2/3 — capture the signed request from both the readable and the hardened page. */
await run('capture /plain (1 signed request, HTTP 200)', 'capture.mjs',
  ['--url', `${origin}/plain`, '--clicks', '1', '--out', plainCapture]);
await run('capture /obf (2 signed requests, HTTP 200)', 'capture.mjs',
  ['--url', `${origin}/obf`, '--clicks', '2', '--out', obfCapture]);

/* 4 — recover the algorithm + key from the hardened page alone. */
await run('recover key from /obf and reproduce the captures', 'recover.mjs',
  ['--capture', obfCapture, '--page', `${origin}/obf`, '--out', recovered, '--runtime-probe']);

/* 5 — mint a valid request outside the browser. */
await run('replay: copy rejected, recomputed signature accepted', 'replay.mjs',
  ['--capture', obfCapture, '--key-file', recovered, '--url', origin, '--new-body']);

/* 6 — what the target can see of us. */
await run('bot-detection report', 'fingerprint.mjs',
  ['--url', `${origin}/fingerprint`, '--out', fingerprintReport]);

server.close();

const failed = steps.filter(s => !s.pass);
console.log(`\n${'='.repeat(78)}\nweb-reverse loop summary\n${'='.repeat(78)}`);
for (const s of steps) console.log(`  ${s.pass ? 'PASS' : 'FAIL'}  ${s.label.padEnd(52)} ${s.detail}${s.ms ? `  (${(s.ms / 1000).toFixed(1)}s)` : ''}`);
console.log(`\n${failed.length === 0 ? 'LOOP CLOSED: signature captured, algorithm recovered, request minted outside the browser, gate accepted it.' : `${failed.length} step(s) failed`}`);
process.exit(failed.length === 0 ? 0 : 9);
