#!/usr/bin/env node
/**
 * web.js.cdp — NEGATIVE CONTROL. Added 2026-10-04.
 *
 * WHY THIS FILE EXISTS. `assert-probes.py` prints, in its own verdict, that this capability
 * "declares no EXECUTABLE negative control, so nothing about its control was compared at all" —
 * and then counts it as a fifth SKIP rather than a pass. It was the only `observed` capability in
 * the registry in that state. A capability whose instrument has never been shown to REFUSE
 * anything is a capability whose "works" has only ever meant "did not crash".
 *
 * THE CONTROL. A signing scheme that accepts a forged request is not a signing scheme. This
 * script takes the lab's own recovered key, replaces it with a deliberately wrong one, replays a
 * correctly-formed request through the lab's own HTTP gate, and requires the gate to REJECT it.
 * If the gate accepts a bad signature, this control fails — which is the point: it must be able
 * to go red.
 *
 * It is the mirror image of what `loop.mjs` proves. The loop shows a valid signature is ACCEPTED;
 * this shows an invalid one is REFUSED. An instrument that only ever proves the first half is
 * measuring that the code runs, not that it works.
 *
 * EXIT POLARITY. Rule R5 requires a negative control to declare a NON-ZERO `expect_exit`, because
 * a control that must exit 0 proves nothing: an instrument that had stopped enforcing entirely
 * would also exit 0 and the harness would read that as a pass.
 *
 *   exit 1 = THE CONTROL WORKING. The gate refused the forged signature. This is the non-zero
 *            code the registry declares.
 *   exit 0 = the gate ACCEPTED the forged signature. The control found a real defect, and 0 is
 *            the value the harness flags as DRIFT.
 *   exit 2 = a stray argument, or a run that could not be measured. Deliberately DISTINCT from
 *            0 and 1, so a harness can tell "you asked me something I refuse" from "I checked
 *            and it held" from "I checked and it broke".
 *   exit 5 = the control's own premise failed (the lab would not start, or the forged request
 *            was not the shape it claimed to be). A control that cannot measure must say so
 *            rather than bank a result.
 *
 * POLARITY HISTORY, because it is the kind of thing a diff erases. The first version of this file
 * had the intuition backwards — the refusal exited 0 — and registry-verify.py caught it within
 * seconds of the declaration: "R5 web.js.cdp: negative_control expects exit 0. A control that
 * must SUCCEED proves nothing." The gate was right and the first version was wrong. The refusal
 * then lived at exit 2, which R5 also permits but which is now spoken for by "could not
 * measure"; the refusal is exit 1 and exit 2 is free to mean the thing it means everywhere else
 * in this tree. `manifests/capabilities.json` declares `expect_exit` and `expect_output` for this
 * control and must be read, not assumed: this file's output line "CONTROL WORKING" is the string
 * the harness matches, so it is reproduced verbatim below.
 *
 * THE FIXTURES ARE GENERATED, not read from disk, and that is load-bearing rather than tidy.
 * The 2026-10-05 incident this file was rewritten for: three sibling gates READ fixtures that
 * somebody else created earlier, so on a fresh machine they failed with `No such file` — and a
 * FileNotFoundError is indistinguishable, from outside, from a control that correctly detected
 * a broken instrument. Three verification attempts were wasted reading a refusal as a defect.
 * So everything this gate sends is built here, written under `os.tmpdir()` by `mkdtempSync`, and
 * deleted in `finally`. Nothing outside this file is required to exist, and a control that cannot
 * run on a clean machine measures nothing.
 *
 * NO BROWSER, deliberately. This control exercises the SIGNING GATE, which is a pure HTTP
 * boundary — a forged request, a refusal, a status code. Driving Chrome over CDP is what
 * `loop.mjs` does, and this gate does not do it: launching a browser here would make a signing
 * assertion depend on a Chrome install, a debug port, and a profile that must not be touched,
 * which is three ways for the control to stop measuring the thing it exists to measure. There is
 * therefore no browser portion to be BLOCKED on — see the note printed in the run, which says so
 * rather than leaving the reader to guess.
 *
 * The assertion itself is UNCHANGED by the rewrite: a well-formed request signed with the wrong
 * key must come back 401/403. What changed is where the inputs come from.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
/* The lab is imported DYNAMICALLY, inside the try, and that is a correctness fix rather than a
 * style choice. MEASURED: with a static top-level import, a missing or broken lab/server.mjs
 * killed the process at module-resolution time with Node's own exit 1 — which is now this
 * control's PASSING code. A gate that cannot find its instrument would have reported itself
 * green. Dynamic import moves that failure inside the try, where it becomes exit 2,
 * "could not measure", which is the honest answer. */
const LAB_MODULE = new URL('../lab/server.mjs', import.meta.url).href;

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ARGUMENT REFUSAL. Exit 2, before anything is created.
 *
 * MEASURED 2026-10-05 on this very file: `node web-reverse/tools/negative-gate.mjs --bogus`
 * printed output byte-identical to the no-argument run and exited with the same code, because
 * this gate had no guard at all. A control handed a flag it does not understand and silently
 * ignores it can report a green it did not measure. Refusing here — above every fixture this run
 * builds — is also what makes "nothing left behind in %TEMP%" countable: there is no path on
 * which an argument creates a scratch directory.
 *
 * ALLOWED is declared empty rather than omitted, so the no-arguments contract is visible in the
 * file instead of inferred from an absent filter. Nothing below reads argv.
 */
const ALLOWED = new Set([]);
const STRAY = process.argv.slice(2).filter((a) => !ALLOWED.has(a));
if (STRAY.length) {
  console.error(`negative-gate: refusing argument(s) it would otherwise IGNORE: ${STRAY.join(' ')}`);
  console.error('  This control generates its own request fixture. It has no --target and no --url.');
  console.error('  Accepting an argument silently would report a green it did not measure.');
  console.error('  Exiting 2 — distinct from 1 (the control working) and 0 (the control failing).');
  process.exit(2);
}

const line = (s = '') => console.log(s);

/* The generated work directory. `mkdtempSync`, never a fixed path: a fixed scratch path plus a
 * destructive first step is how two runs collide, and this control must be safe to run twice in
 * parallel. The parent is %TEMP% by construction — `os.tmpdir()` — never the repo. */
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'web-negative-gate-'));

/* THE REQUEST FIXTURE. A request shaped exactly like the ones the loop mints, but signed with a
 * key that is wrong. The wrong key is written to the fixture file and the signature is computed
 * from the bytes ON DISK, not from the in-memory string that produced them: that is what makes
 * the file a fixture rather than a log, and it is why a bug in the fixture writer would show up
 * as a refusal to POST rather than as a silent pass. */
const WRONG_KEY = 'this-is-not-the-recovered-key';
const REQUEST_FILE = path.join(WORK, 'forged-request.json');

const checks = [];
function check(label, pass, detail) {
  checks.push({ label, pass, detail });
  line(`  ${pass ? 'PASS' : 'FAIL'}  ${label.padEnd(58)} ${detail}`);
}

function post(port, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1', port, path: '/api/submit', method: 'POST', agent: false,
        headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      },
      (res) => {
        let b = '';
        res.on('data', (d) => { b += d; });
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

let exitCode = 2; /* until a measurement exists at all */
let server = null;

line('web.js.cdp negative control — forged signature, well-formed request');
line(`  scratch        ${WORK}   (generated this run, removed in finally)`);
line('  browser        NOT USED, and not missing. This control asks the signing gate — a pure');
line('                 HTTP boundary — to refuse a forged request. Driving Chrome over CDP is');
line('                 loop.mjs\'s job; a browser here would make a signing assertion depend on');
line('                 an install, a debug port and a profile. There is no BLOCKED portion.');
line('');

try {
  /* Dynamic, so a missing or broken lab is an exit-2 "could not measure" rather than Node's own
   * exit 1 — which is this control's passing code. See the note on LAB_MODULE above. */
  const { createServer, LAB_KEY, signBody } = await import(LAB_MODULE);

  /* ── 1. generate the fixture ────────────────────────────────────────────────────────────── */
  const nonce = crypto.randomBytes(4).toString('hex');
  const body = JSON.stringify({ op: 'lab.forge', nonce });
  const ts = String(Date.now());
  const sig = crypto.createHmac('sha256', Buffer.from(WRONG_KEY, 'utf8'))
    .update(`${ts}.${body}`, 'utf8').digest('hex');

  fs.writeFileSync(REQUEST_FILE, JSON.stringify({ key: WRONG_KEY, ts, sig, body }, null, 2));

  /* Read it back. Everything the request is built from now comes off disk. */
  const fixture = JSON.parse(fs.readFileSync(REQUEST_FILE, 'utf8'));
  const { key: fKey, ts: fTs, sig: fSig, body: fBody } = fixture;

  check('fixture written under %TEMP% by this run', fs.existsSync(REQUEST_FILE),
    path.relative(os.tmpdir(), REQUEST_FILE));
  check('fixture signature was computed with the WRONG key',
    fSig !== signBody(fBody, fTs, LAB_KEY),
    `used "${fKey}", lab key is ${LAB_KEY.slice(0, 12)}…`);
  check('request is otherwise well formed',
    fBody === body && fSig.length === 64 && Number.isFinite(Number(fTs)),
    `nonce ${nonce}, ${fBody.length} body bytes, ts ${fTs}`);

  /* ── 2. ask the gate ────────────────────────────────────────────────────────────────────── */
  server = createServer({ log: () => {} });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;

  const res = await post(port,
    { 'content-type': 'application/json', 'x-lab-ts': fTs, 'x-lab-sign': fSig },
    fBody);

  line(`  key    ${fKey}`);
  line(`  sig    ${fSig}`);
  line(`  -> HTTP ${res.status} ${res.body.trim()}`);

  /* ── 3. the assertion, unchanged: the refusal must happen ───────────────────────────────── */
  check('gate REFUSED the forged signature', res.status === 401 || res.status === 403,
    `HTTP ${res.status}`);

  /* ── 4. accounting: only a run that measured can report a verdict ───────────────────────── */
  const premiseOk = checks.slice(0, 3).every((c) => c.pass);
  const refused = checks[3].pass;

  if (!premiseOk) {
    line('');
    line('CONTROL BROKEN — its own premise did not hold, so the assertion below was not measured.');
    line('  Exiting 5. A control that cannot measure must not report that it did.');
    exitCode = 5;
  } else if (refused) {
    line('');
    line('CONTROL WORKING — the gate REFUSED a forged signature (HTTP ' + res.status + '). Exiting 1,');
    line("because R5 requires a negative control's expected exit to be non-zero: an instrument that");
    line('had stopped enforcing would exit 0, and 0 is the value the harness flags as DRIFT.');
    exitCode = 1;
  } else {
    line('');
    line(`CONTROL FAILED — the gate ACCEPTED a request signed with the wrong key (HTTP ${res.status}).`);
    line('  A signing scheme that accepts a forged request is not a signing scheme, and every');
    line('  "gate accepted it" line in loop.mjs is therefore meaningless. Exiting 0 so the');
    line('  harness reports DRIFT rather than a pass.');
    exitCode = 0;
  }
} catch (e) {
  line('');
  line(`negative-gate: could not measure — ${(e && (e.stack || e.message)) || String(e)}`);
  line('  Exiting 2. The lab would not start, or the request never reached it; neither is a');
  line('  statement about the gate refusing a forgery.');
  exitCode = 2;
} finally {
  /* No process.exit() in here: it terminates without unwinding, so this cleanup would be
   * skipped. MEASURED — a probe of exactly that claim showed the finally body never ran. Every
   * exit therefore leaves through the single process.exit() at the bottom of this file. */
  if (server) {
    try { server.close(); } catch { /* best effort */ }
  }
  try { fs.rmSync(WORK, { recursive: true, force: true }); } catch { /* best effort */ }
  const left = fs.existsSync(WORK);
  line('');
  line(`  scratch removed: ${left ? 'NO — ' + WORK + ' is still there' : 'yes'}` +
    `${left ? '  (this is a defect)' : ''}`);
  line(`  checks: ${checks.length}, failures: ${checks.filter((c) => !c.pass).length}`);
}

/* THE SINGLE EXIT POINT, outside every cleanup block. */
process.exit(exitCode);