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
 * correctly-formed request through `replay.mjs`, and requires the gate to REJECT it. If the gate
 * accepts a bad signature, this control fails — which is the point: it must be able to go red.
 *
 * It is the mirror image of what `loop.mjs` proves. The loop shows a valid signature is ACCEPTED;
 * this shows an invalid one is REFUSED. An instrument that only ever proves the first half is
 * measuring that the code runs, not that it works.
 *
 * EXIT POLARITY, and it is the opposite of what it looks like. Rule R5 requires a negative
 * control to declare a NON-ZERO `expect_exit`, because a control that must exit 0 proves nothing:
 * an instrument that had stopped enforcing entirely would also exit 0 and the harness would
 * read that as a pass. So the convention in this tree -- set by net.pcap.selfparse, whose control
 * feeds a README to the pcap reader and expects exit 2 -- is that the control reports the
 * instrument's REFUSAL as a failure.
 *
 *   exit 2 = the gate refused the forged signature. THE CONTROL WORKING. This is what R5 wants.
 *   exit 0 = the gate ACCEPTED it. The control found a real defect, and by R5's convention that
 *            is the value the harness will flag as DRIFT.
 *
 * The first version of this file had it the intuitive way round, and registry-verify.py caught it
 * within seconds of the declaration: "R5 web.js.cdp: negative_control expects exit 0. A control
 * that must SUCCEED proves nothing." The gate was right and the first version was wrong.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer } from '../lab/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const server = createServer({ log: () => {} });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const origin = `http://127.0.0.1:${port}`;

function post(headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1', port, path: '/api/submit', method: 'POST',
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

try {
  // A request shaped exactly like the ones the loop mints, but signed with a key that is wrong.
  const WRONG_KEY = 'this-is-not-the-recovered-key';
  const body = JSON.stringify({ op: 'lab.forge', nonce: crypto.randomBytes(4).toString('hex') });
  const ts = String(Date.now());
  const sig = crypto.createHmac('sha256', Buffer.from(WRONG_KEY, 'utf8'))
    .update(`${ts}.${body}`, 'utf8').digest('hex');

  const res = await post(
    { 'content-type': 'application/json', 'x-lab-ts': ts, 'x-lab-sign': sig },
    body,
  );

  console.log(`web.js.cdp negative control — forged signature, well-formed request`);
  console.log(`  key    ${WRONG_KEY}`);
  console.log(`  sig    ${sig}`);
  console.log(`  -> HTTP ${res.status} ${res.body.trim()}`);

  if (res.status === 401 || res.status === 403) {
    console.log(`\nCONTROL WORKING — the gate REFUSED a forged signature (HTTP ${res.status}). Exiting 2,`);
    console.log(`because R5 requires a negative control's expected exit to be non-zero: an instrument`);
    console.log(`that had stopped enforcing would exit 0, and 0 is the value the harness flags.`);
    process.exit(2);
  }

  console.log(`\nCONTROL FAILED — the gate ACCEPTED a request signed with the wrong key (HTTP ${res.status}).`);
  console.log(`  A signing scheme that accepts a forged request is not a signing scheme, and every`);
  console.log(`  "gate accepted it" line in loop.mjs is therefore meaningless. Exiting 0 so the`);
  console.log(`  harness reports DRIFT rather than a pass.`);
  process.exit(0);
} finally {
  server.close();
}

// Keep the import referenced so a future edit that drops it fails loudly rather than silently.
void spawnSync;
void fs;
void os;
void HERE;