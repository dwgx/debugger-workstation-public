#!/usr/bin/env node
// native-lab/tools/loop.mjs — prove the IDA capability, and prove the trap in it.
//
// The station has IDA Professional 9.2 and ida-pro-mcp 2.0.0 installed and licensed,
// and for a long time this repo claimed otherwise. A claim like that is only worth
// fixing if something re-checks it, so this loop re-checks it against our own
// self-built crackme and records the result.
//
// The second job of this file is more important. ida-pro-mcp reports a FAILED
// decompile with isError:false, a null `code` and an `error` string. A wrapper that
// trusts isError alone records the failure as a success. That is the
// complete-and-confident-and-wrong shape this whole station exists to reject, and
// here it arrives through a real tool rather than a hallucination. So this loop
// carries a control that asserts the hazard is real, which means a future wrapper
// that forgets the check will be caught by something other than luck.

import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

const HOST = '127.0.0.1';
const PORT = 8745;
const MCP = `http://${HOST}:${PORT}/mcp`;
const IDALIB = 'D:/Software/Developer/Python314/Scripts/idalib-mcp.exe';
const TARGET = 'crackme-corpus/out/c01-stringobf.exe';
const GROUND_TRUTH = 'FLAG{c01_strings_gave_you_this_decoy}'; // plaintext decoy in our own sample

const checks = [];
const say = (s) => process.stdout.write(`${s}\n`);
const add = (ok, name, detail) => {
  checks.push({ ok: !!ok, name, detail });
  say(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(52)} ${detail}`);
  return !!ok;
};

let rpcId = 0;
const HDRS = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };

async function rpcRaw(method, params) {
  rpcId += 1;
  const body = JSON.stringify({ jsonrpc: '2.0', id: rpcId, method, params: params || {} });
  const r = await fetch(MCP, { method: 'POST', headers: HDRS, body, signal: AbortSignal.timeout(180_000) });
  const text = await r.text();
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (t.startsWith('data:')) return JSON.parse(t.slice(5).trim());
  }
  return JSON.parse(text);
}

async function notify(method) {
  await fetch(MCP, { method: 'POST', headers: HDRS,
    body: JSON.stringify({ jsonrpc: '2.0', method }) }).catch(() => {});
}

// Returns parsed body plus isError SEPARATELY, because on this server isError is the
// wrong signal for a failed analysis and the loop has to be able to prove that.
async function call(tool, args) {
  const res = await rpcRaw('tools/call', { name: tool, arguments: args });
  const raw = (res?.result?.content || []).map((c) => c.text || '').join('');
  let body;
  try { body = JSON.parse(raw); } catch { body = { _raw: raw }; }
  return { isError: res?.result?.isError === true, body };
}

async function waitForPort(proc, budgetMs = 120_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < budgetMs) {
    if (proc.exitCode !== null) return false;
    try {
      const r = await fetch(MCP, { method: 'POST', headers: HDRS,
        body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} }),
        signal: AbortSignal.timeout(5000) });
      if (r.ok) return true;
    } catch { /* not listening yet */ }
    await sleep(1000);
  }
  return false;
}

// IDA does not list a session until its initial analysis finishes. Asking before that
// returns an empty list, which is indistinguishable from a failure to open — the same
// shape as a parser handed an error page and told "no rows".
async function waitForSession(budgetMs = 420_000) {
  const t0 = Date.now();
  let seen = 'no response';
  while (Date.now() - t0 < budgetMs) {
    const r = await call('idb_list', {}).catch((e) => ({ body: { err: e.message } }));
    const s = (r?.body?.sessions || [])[0];
    if (s) {
      if (!s.is_analyzing && !s.busy) return s;
      seen = `session ${s.session_id} still ${s.is_analyzing ? 'analyzing' : 'busy'}`;
    } else {
      seen = `no session yet (count=${r?.body?.count ?? '?'})`;
    }
    await sleep(2500);
  }
  process.stderr.write(`waitForSession gave up: ${seen}\n`);
  return null;
}
// A leftover idalib worker will happily hold the port, and then this loop would
// cheerfully attach to a server it did not start and report another run's session
// as its own evidence. Refuse to inherit a server rather than trust it — the same
// reason we re-probe instead of believing a recorded verdict.
async function portFree() {
  try {
    const r = await fetch(MCP, { method: 'POST', headers: HDRS,
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} }),
      signal: AbortSignal.timeout(4000) });
    return !r.ok;
  } catch {
    return true; // nothing listening
  }
}


async function main() {
  say('='.repeat(100));
  say('native-lab loop — IDA via idalib-mcp, against our own self-built crackme');
  say('='.repeat(100));
  say('');
  if (await portFree(PORT) === false) {
    add(false, 'port is free before we start', `something is already serving ${MCP}. Refusing to inherit another run's server — stop it and re-run.`);
    return finish();
  }
  add(true, 'port is free before we start', `${MCP} was not answering before we spawned anything`);

  if (!existsSync(IDALIB)) {
    add(false, 'idalib-mcp exists', `not found: ${IDALIB}`);
    return finish();
  }
  if (!existsSync(TARGET)) {
    add(false, 'our own target exists', `missing: ${TARGET} — rebuild with crackme-corpus/tools/loop.py`);
    return finish();
  }

  const proc = spawn(IDALIB, ['--host', HOST, '--port', String(PORT), TARGET],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d.toString(); });
  proc.stdout.on('data', () => {});

  try {
    const up = await waitForPort(proc);
    add(up, 'idalib-mcp serves MCP over POST on loopback',
      up ? `${HOST}:${PORT}` : `no port within budget; stderr tail: ${stderr.slice(-160)}`);
    if (!up) return finish();

    await rpcRaw('initialize', { protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'native-lab-loop', version: '1' } });
    await notify('notifications/initialized');

    const tools = await rpcRaw('tools/list');
    const names = (tools?.result?.tools || []).map((t) => t.name);
    add(names.includes('decompile'), 'server exposes a decompile tool',
      `${names.length} tools; serverInfo=${JSON.stringify(tools?.result?.serverInfo || {})}`);

    const sess = await waitForSession();
    const db = sess?.session_id;
    add(Boolean(db), 'session opened on our own target',
      db ? `${db} -> ${sess.filename}` : 'never became ready');
    if (!db) return finish();

    const lf = await call('list_funcs', { queries: [{ count: 300 }], database: db });
    const flat = Array.isArray(lf.body) ? lf.body : lf.body?.data || lf.body?.result || [];
    const funcs = flat.flatMap((g) => (Array.isArray(g) ? g : g?.data || []));
    add(funcs.length > 5, 'list_funcs enumerates functions', `${funcs.length} functions`);

    const mainFn = funcs.find((f) => f.name === 'main');
    add(Boolean(mainFn), 'main is located by name', mainFn ? `${mainFn.addr} size ${mainFn.size}` : 'no main in listing');
    if (!mainFn) return finish();

    const dec = await call('decompile', { addr: mainFn.addr, include_addresses: false, database: db });
    const code = dec.body?.code || '';
    add(code.length > 200, 'decompile returns real recovered C for main', `${code.length} chars`);
    add(code.includes(GROUND_TRUTH), 'the plaintext decoy flag is recovered from the decompilation', GROUND_TRUTH);
    add(/strcmp/.test(code), 'the comparison logic is recovered, not just the strings',
      /strcmp/.test(code) ? 'strcmp present in recovered code' : 'no strcmp in output');
    add(Array.isArray(dec.body?.refs) && dec.body.refs.length > 0,
      'decompile carries resolved refs alongside the code', `${dec.body?.refs?.length ?? 0} refs`);

    // --- the hazard, asserted as a control ---------------------------------
    const bogus = await call('decompile', { addr: '0xDEADBEEF', database: db });
    const codeNull = bogus.body?.code === null || bogus.body?.code === undefined;
    const errPresent = typeof bogus.body?.error === 'string' && bogus.body.error.length > 0;
    add(codeNull, 'NEGATIVE: a bogus address yields no code', `code=${JSON.stringify(bogus.body?.code)}`);
    add(errPresent, 'NEGATIVE: the failure is carried in an `error` field', String(bogus.body?.error).slice(0, 78));

    // The control on the control. If isError were true here the hazard would not
    // exist and wrappers could trust it. Asserting it is false keeps the documented
    // hazard load-bearing instead of folklore.
    add(bogus.isError === false, 'CONTROL: isError is FALSE on that failure',
      bogus.isError === false
        ? 'isError=false while error is set — an isError-only wrapper logs a success'
        : 'isError was true; the documented hazard is WRONG and every wrapper needs re-checking');

    const bogusSym = await call('decompile', { addr: 'no_such_symbol_zzz', database: db });
    add(typeof bogusSym.body?.error === 'string' && /not found/i.test(bogusSym.body.error),
      'NEGATIVE: a nonexistent symbol is refused by name', String(bogusSym.body?.error).slice(0, 68));

    const missing = await rpcRaw('tools/call', { name: 'decompile', arguments: { database: db } });
    add(missing?.result?.isError === true, 'NEGATIVE: a missing required parameter is refused',
      missing?.result?.isError === true ? 'isError=true from the schema layer' : `accepted: ${JSON.stringify(missing).slice(0, 100)}`);
  } finally {
    // proc.kill() trips a libuv assertion on Windows; taskkill is quieter.
    try { execFileSync('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore' }); } catch { /* already gone */ }
  }

  say('');
  return finish();
}

function finish() {
  const failed = checks.filter((c) => !c.ok);
  const summary = {
    ok: failed.length === 0,
    schema: 'native-lab/loop@1',
    target: TARGET,
    checks: checks.map(({ ok, name }) => ({ ok, name })),
    failed: failed.map((f) => f.name),
    counts: { total: checks.length, pass: checks.length - failed.length, fail: failed.length },
  };
  say('='.repeat(100));
  if (failed.length === 0) {
    say('LOOP CLOSED: IDA 9.2 is present and licensed, idalib-mcp decompiles our own');
    say('             sample, every negative control refused as it must, and the');
    say('             isError hazard is asserted rather than assumed.');
  } else {
    say(`LOOP OPEN: ${failed.length} check(s) failed -- ${failed.map((f) => f.name).join('; ')}`);
  }
  say('JSON-SUMMARY ' + JSON.stringify(summary.counts));
  process.stdout.write(`${JSON.stringify(summary)}\n`);
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`loop: ${e.stack || e.message}\n`);
  process.exit(2);
});
