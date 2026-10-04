/* loop.mjs — ONE command that runs the whole protocol lane and judges itself.
 *
 *   node tools/loop.mjs [--quiet]
 *
 *   generate corpus -> answer every corpus question (with negative controls)
 *   -> re-inject captured traffic into a loopback listener -> rewrite a request and
 *   a response in flight over CDP -> prove no certificate or proxy was installed
 *
 * Exit 0 means the lane closed on this machine, in that run. Every step is the same
 * tool an analyst would call by hand; this file only sequences them and checks exit
 * codes, so a failure names the exact command that failed.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ARGUMENT REFUSAL. Added 2026-10-04. Measured on this tree: passing a path that does not exist
// produced a normal green run and exit 0 -- every check "passed" while nothing anyone asked for
// had been done. A regression suite that cannot fail on the thing you handed it reports a pass
// for work nobody did, which is the one shape this station exists to reject.
//
// The precedent is already in the tree and this follows it rather than inventing a second
// convention: crackme-corpus/tools/loop.py uses argparse and rejects `unrecognized arguments`
// with exit 2. The JS loops had no argument parser at all, which is the defect.
// `new Set('--json', '--quiet')` was wrong twice over: Set takes ONE argument, so the
// second was silently discarded, and the first is a STRING, so it iterated into
// Set{'-','j','s','o','n'}. BOTH flags were therefore refused by the guard meant to allow
// them. Found 2026-10-05: I had verified these guards refuse a bogus argument and pass with
// none, but never that they ACCEPT a real one. A guard that refuses everything looks exactly
// like a guard that works until you try to use it.
const ALLOWED = new Set(['--json', '--quiet']);
const extra = process.argv.slice(2).filter((a) => !ALLOWED.has(a) && !a.startsWith('--only='));
if (extra.length) {
  console.error(`loop: refusing an argument it would otherwise IGNORE: ${extra.join(' ')}`);
  console.error('  This is a regression suite over its own built fixtures. It has no --target.');
  console.error('  Accepting an argument silently would report a pass for work nobody did.');
  process.exit(2);
}


const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB = path.resolve(HERE, '..');
const QUIET = process.argv.includes('--quiet');
const steps = [];

function run(label, script, args, { expect = 0, timeoutMs = 300_000 } = {}) {
  const started = Date.now();
  return new Promise(resolve => {
    const child = spawn(process.execPath, [path.join(LAB, script), ...args], { encoding: 'utf8' });
    let out = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => out += d);
    const timer = setTimeout(() => { child.kill(); }, timeoutMs);
    child.on('close', code => {
      clearTimeout(timer);
      const tail = out.trimEnd().split(/\r?\n/).filter(Boolean).slice(-1)[0] || '';
      if (!QUIET) console.log(`\n${'-'.repeat(78)}\n$ node ${script} ${args.join(' ')}\n${'-'.repeat(78)}\n${out.trimEnd()}`);
      steps.push({ label, pass: code === expect, detail: code === expect ? tail.slice(0, 96) : `exit ${code} (expected ${expect})`, ms: Date.now() - started, out });
      resolve(code);
    });
  });
}

await run('corpus generated (5 synthetic captures, hash-labelled)', 'lab/gen-pcaps.mjs', []);
await run('16 questions answered, negative controls held', 'tools/pcap-lab.mjs', ['verify']);
await run('captured POST re-injected byte-identically', 'tools/replay.mjs', ['--pcap', 'http-basic.pcap', '--message', '2']);
await run('captured binary stream re-injected byte-identically', 'tools/replay.mjs', ['--pcap', 'odd-port.pcap', '--stream', '1', '--raw']);
await run('request + response rewritten in flight over CDP', 'tools/intercept.mjs', []);
await run('no certificate in a root store, no system proxy', 'tools/trustcheck.mjs', []);

const failed = steps.filter(s => !s.pass);
console.log(`\n${'='.repeat(78)}\nnet-reverse loop summary\n${'='.repeat(78)}`);
for (const s of steps) console.log(`  ${s.pass ? 'PASS' : 'FAIL'}  ${s.label.padEnd(52)} ${s.detail}${s.ms > 2000 ? `  (${(s.ms / 1000).toFixed(1)}s)` : ''}`);
if (failed.length) {
  console.log(`\n${failed.length} step(s) failed. First failure output:\n`);
  console.log(failed[0].out.trimEnd());
}
console.log(`\n${failed.length === 0
  ? 'LANE CLOSED: captures generated, questions answered and falsified, traffic replayed into loopback, requests and responses rewritten in flight, isolation intact.'
  : `${failed.length} step(s) failed`}`);
process.exit(failed.length === 0 ? 0 : 9);
