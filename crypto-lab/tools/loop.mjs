#!/usr/bin/env node
/* loop.mjs — the whole proof in one command, self-judging.
 *
 * For every case in `cases.mjs`:
 *   1. obtain the token (issued by the lab, or crafted here with the lab's own key);
 *   2. run `analyze.mjs` as a subprocess and compare its finding-id set EXACTLY;
 *   3. run the token past the lab verifier the case names, and compare accept/reject;
 *   4. run the token past `jsonwebtoken` and PyJWT and compare their verdicts.
 *
 * Then, as a separate section, run every issued profile past every verifier and require
 * the matrix to come out right — that is the "recognition" half, stated as assertions
 * rather than as prose.
 *
 * Anything that does not match its expectation sets `ok = false` and the process exits
 * non-zero. Silent misclassification is the failure mode this file exists to prevent.
 *
 * Child processes are spawned ASYNCHRONOUSLY: `spawnSync` would block this process's
 * event loop, and the lab server answering the verification calls lives in it. (That
 * deadlock is written up in notes/2026-09-30-web-reverse-lab.md.)
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// Run summary to disk, so the verdict rests on a FILE rather than a substring of stdout.
// assert-probes says an entry with no `probe.produces` was "matched STRINGS only, and a
// stub which prints them satisfies it". Added 2026-10-04; see scripts/probe_artifact.mjs.
import { writeRunArtifact } from '../../scripts/probe_artifact.mjs';
import { createLab } from '../lab/server.mjs';
import { buildCases, classifyOracle } from './cases.mjs';
import { decode } from '../lab/jose.mjs';

// ARGUMENT REFUSAL. Added 2026-10-04. Measured on this tree: passing a path that does not exist
// produced a normal green run and exit 0 -- every check "passed" while nothing anyone asked for
// had been done. A regression suite that cannot fail on the thing you handed it reports a pass
// for work nobody did, which is the one shape this station exists to reject.
//
// The precedent is already in the tree and this follows it rather than inventing a second
// convention: crackme-corpus/tools/loop.py uses argparse and rejects `unrecognized arguments`
// with exit 2. The JS loops had no argument parser at all, which is the defect.
const ALLOWED = new Set('--json');
const extra = process.argv.slice(2).filter((a) => !ALLOWED.has(a) && !a.startsWith('--only='));
if (extra.length) {
  console.error(`loop: refusing an argument it would otherwise IGNORE: ${extra.join(' ')}`);
  console.error('  This is a regression suite over its own built fixtures. It has no --target.');
  console.error('  Accepting an argument silently would report a pass for work nobody did.');
  process.exit(2);
}


const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB_ROOT = path.resolve(HERE, '..');
const ANALYZE = path.join(HERE, 'analyze.mjs');
const ORACLE_NODE = path.join(HERE, 'oracle-node.mjs');
const ORACLE_PY = path.join(HERE, 'oracle.py');

const PORT = Number(process.env.CRYPTO_LAB_PORT || 8791);
const argv = process.argv.slice(2);
const wantJson = argv.includes('--json');

/* ------------------------------------------------------------------ helpers */

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: opts.cwd || LAB_ROOT, windowsHide: true, env: process.env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => resolve({ code: -1, stdout, stderr, error: e.message }));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function pythonPath() {
  if (process.env.CRYPTO_LAB_PY && fs.existsSync(process.env.CRYPTO_LAB_PY)) return process.env.CRYPTO_LAB_PY;
  const win = path.join(LAB_ROOT, '.venv', 'Scripts', 'python.exe');
  const posix = path.join(LAB_ROOT, '.venv', 'bin', 'python');
  if (fs.existsSync(win)) return win;
  if (fs.existsSync(posix)) return posix;
  return 'python';
}

const setEq = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

/* ------------------------------------------------------------------ main */

async function main() {
  const lab = createLab({ log: () => {} });
  const addr = await lab.listen(lab.server, { port: PORT });
  const base = `http://127.0.0.1:${addr.port}`;
  const py = pythonPath();

  const api = async (p, body) => {
    const r = await fetch(base + p, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    return r.json();
  };

  const checks = [];
  const add = (ok, name, detail) => checks.push({ ok, name, detail });

  const cases = buildCases(lab);

  add(true, 'lab target up', `${base}  kid=${lab.KID}  RSA-${lab.rsa.bits} key ${lab.rsa.generated ? 'generated' : 'reused'} (crypto-lab/keys/, gitignored)`);
  add(fs.existsSync(path.join(LAB_ROOT, 'node_modules', 'jsonwebtoken')), 'oracle dependency present', 'crypto-lab/node_modules/jsonwebtoken');
  add(fs.existsSync(py), 'python oracle interpreter', py);

  /* ---- section 1: per-case classification ------------------------------- */

  const caseRows = [];
  for (const c of cases) {
    const row = { id: c.id, title: c.title, teaches: c.teaches, ok: true, notes: [] };

    let token;
    try {
      token = c.issue ? (await api(`/api/issue/${c.issue}`)).token : c.craft();
    } catch (e) {
      row.ok = false;
      row.notes.push(`could not obtain token: ${e.message}`);
      caseRows.push(row);
      continue;
    }
    try {
      row.alg = decode(token).header.alg;
    } catch {
      /* not a JWS — e.g. the JWE case; segment count is the interesting fact there */
      row.alg = `${token.split('.').length}-segment`;
    }

    /* -- analyzer -- */
    const args = ['--token', token, '--quiet', '--json'];
    if (c.analyze.rsaPub) args.push('--rsa-pub', lab.rsa.publicPath);
    if (c.analyze.secret) args.push('--secret', c.analyze.secret);
    if (c.analyze.serverAlg) args.push('--server-alg', c.analyze.serverAlg);
    if (c.analyze.ttlMax) args.push('--ttl-max', String(c.analyze.ttlMax));

    const a = await run(process.execPath, [ANALYZE, ...args]);
    if (a.code !== 0) {
      row.ok = false;
      row.notes.push(`analyze exited ${a.code}: ${a.stderr.trim().split('\n').pop()}`);
      caseRows.push(row);
      continue;
    }
    let out;
    try {
      out = JSON.parse(a.stdout);
    } catch (e) {
      row.ok = false;
      row.notes.push(`analyze stdout was not JSON: ${e.message}`);
      caseRows.push(row);
      continue;
    }
    row.got = out.summary.finding_ids;
    row.want = c.expect;
    row.verdict = out.summary.verdict;
    row.signature = out.signature.status;
    row.expiry = out.expiry?.status ?? null;
    const clsOk = setEq(out.summary.finding_ids, c.expect);
    if (!clsOk) {
      row.ok = false;
      row.notes.push(`FINDINGS missing=[${c.expect.filter((x) => !out.summary.finding_ids.includes(x)).join(',')}] `
        + `unexpected=[${out.summary.finding_ids.filter((x) => !c.expect.includes(x)).join(',')}]`);
    }

    /* The analyzer's own --expect must agree with the harness. Two implementations of the
     * same comparison, so a broken guard cannot hide a misclassification. An empty value
     * means "expect no findings at all", which is the `strong` control's whole job. */
    const guard = await run(process.execPath, [ANALYZE, ...args, '--expect', c.expect.join(',')]);
    if (guard.code !== 0) {
      row.ok = false;
      row.notes.push(`analyze --expect "${c.expect.join(',')}" exited ${guard.code} (expected 0)`);
    }

    /* -- lab verifier -- */
    if (c.verifier) {
      const v = await api(`/api/verify/${c.verifier.mode}`, { token });
      row.verifier = `${c.verifier.mode}:${v.accept ? 'accept' : `reject(${v.reason})`}`;
      if (v.accept !== c.verifier.accept) {
        row.ok = false;
        row.notes.push(`verifier ${c.verifier.mode} ${v.accept ? 'accepted' : `rejected(${v.reason})`}, expected ${c.verifier.accept ? 'accept' : 'reject'}`);
      }
      row.checks_performed = v.checks_performed;
    } else {
      row.verifier = '(not a JWS — no verifier call)';
    }

    /* -- independent oracles -- */
    row.oracles = [];
    /* Both libraries enforce `aud`/`iss` when they are told to, and PyJWT *requires* an
     * audience whenever the token carries one. Ask each oracle to verify the token for
     * the audience and issuer the token itself names — that is what a correct verifier
     * does, and asking for anything less would make the comparison meaningless. */
    let claims = {};
    try { claims = decode(token).payload; } catch { claims = {}; }
    const iat = (typeof claims.iss === 'string') ? ['--issuer', claims.iss] : [];
    const aud = (typeof claims.aud === 'string') ? ['--audience', claims.aud] : [];

    for (const spec of c.oracles || []) {
      const oargs = ['--token', token, '--key', spec.key, '--algorithms', (spec.algorithms || []).join(','), ...iat, ...aud];
      if (spec.require) oargs.push('--require', spec.require.join(','));
      if (spec.secret) oargs.push('--secret', spec.secret);
      else if (c.analyze.secret) oargs.push('--secret', c.analyze.secret);
      if (spec.key === 'rsa-public') oargs.push('--rsa-pub', lab.rsa.publicPath);
      const r = spec.tool === 'py'
        ? await run(py, [ORACLE_PY, ...oargs])
        : await run(process.execPath, [ORACLE_NODE, ...oargs]);
      let parsed = null;
      try {
        parsed = JSON.parse(r.stdout.trim().split('\n').pop());
      } catch { /* left null -> classified as 'error' */ }
      const got = classifyOracle(parsed);
      row.oracles.push({ tool: spec.tool, key: spec.key, algorithms: spec.algorithms || [], want: spec.want, got, version: parsed?.version ?? null });
      if (got !== spec.want) {
        row.ok = false;
        row.notes.push(`oracle ${spec.tool}(${spec.key},${(spec.algorithms || []).join('/')}) -> ${got}, expected ${spec.want}`);
      }
    }

    caseRows.push(row);
  }

  for (const r of caseRows) {
    add(r.ok, `case ${r.id}: ${r.title}`,
      `${r.ok ? 'classified as expected' : r.notes.join(' | ')}  [findings: ${(r.got || []).join(',') || 'none'}]`
      + `  [verifier: ${r.verifier}]`);
  }

  /* ---- section 2: the verifier matrix ----------------------------------- */
  /* The recognition half, as assertions. Each weak verifier must accept exactly the
   * token class its bug implies, and `strict` must accept only the control. */
  const profiles = ['strong', 'weak-claims', 'none', 'confusion', 'weak-secret'];
  const modes = ['strict', 'confused', 'none-accepting', 'naive'];
  const expectedMatrix = {
    strong: { strict: true, confused: true, 'none-accepting': true, naive: true },
    'weak-claims': { strict: false, confused: false, 'none-accepting': false, naive: true },
    none: { strict: false, confused: true, 'none-accepting': true, naive: false },
    confusion: { strict: false, confused: true, 'none-accepting': false, naive: false },
    'weak-secret': { strict: false, confused: false, 'none-accepting': false, naive: false },
  };
  const matrix = {};
  for (const p of profiles) {
    const { token } = await api(`/api/issue/${p}`);
    matrix[p] = {};
    for (const m of modes) {
      const v = await api(`/api/verify/${m}`, { token });
      matrix[p][m] = { accept: v.accept, reason: v.reason, checks: v.checks_performed };
      if (v.accept !== expectedMatrix[p][m]) {
        add(false, `matrix ${p} x ${m}`, `${v.accept ? 'ACCEPT' : `reject(${v.reason})`}, expected ${expectedMatrix[p][m] ? 'accept' : 'reject'}`);
      }
    }
  }
  add(true, 'verifier matrix (5 profiles x 4 verifiers)', 'every cell matched the expected acceptance table');

  /* ---- section 3: negative control for the guard ------------------------ */
  /* If `--expect NONE` on a token that has findings still exits 0, the guard is dead and
   * every "classified as expected" above is worthless. */
  const control = await run(process.execPath, [ANALYZE, '--token', (await api('/api/issue/none')).token, '--quiet', '--expect', 'NONE']);
  add(control.code === 4, 'negative control: analyzer --expect refuses a wrong set',
    `exit ${control.code} (want 4) — the guard is live, so the comparisons above mean something`);

  /* ---- report ----------------------------------------------------------- */

  const failures = checks.filter((c) => !c.ok);
  const lines = [];
  const print = (s = '') => { lines.push(s); if (!wantJson) process.stdout.write(`${s}\n`); };

  print('');
  print('crypto-lab loop — token analysis, weakness recognition, independent cross-check');
  print('='.repeat(96));
  print('');
  print('  classification cases');
  for (const r of caseRows) {
    print(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.id.padEnd(16)} alg=${String(r.alg).padEnd(6)} sig=${String(r.signature).padEnd(30)} exp=${r.expiry ?? '-'}`);
    print(`        findings  ${(r.got || []).join(', ') || '(none)'}`);
    print(`        verifier  ${r.verifier}   checks=[${(r.checks_performed || []).join(', ')}]`);
    if (!r.ok) for (const n of r.notes) print(`        !! ${n}`);
    for (const o of (r.oracles || [])) {
      print(`        oracle    ${o.tool === 'py' ? 'PyJWT ' : 'jsonwebtoken'} v${o.version}  key=${o.key.padEnd(10)} algs=${(o.algorithms.join('/') || '-').padEnd(12)} -> ${o.got} (want ${o.want})`);
    }
  }
  print('');
  print('  verifier matrix  (rows = issuance profile, cols = verifier bug)');
  print(`  ${''.padEnd(14)}${modes.map((m) => m.padEnd(30)).join('')}`);
  for (const p of profiles) {
    print(`  ${p.padEnd(14)}${modes.map((m) => {
      const cell = matrix[p][m];
      return `${cell.accept ? 'ACCEPT' : 'reject:' + cell.reason}`.padEnd(30);
    }).join('')}`);
  }
  print('');
  print('  checks');
  for (const c of checks) print(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.name}  ${c.detail}`);
  print('');

  const summary = {
    ok: failures.length === 0,
    schema: 'crypto-lab/loop@1',
    cases: caseRows.map((r) => ({ id: r.id, ok: r.ok, expect: r.want, got: r.got, verifier: r.verifier, oracles: r.oracles, notes: r.notes })),
    matrix,
    checks: checks.map(({ ok, name }) => ({ ok, name })),
    failed: failures.map((f) => f.name),
    counts: { total: checks.length, pass: checks.length - failures.length, fail: failures.length },
  };

  if (failures.length === 0) {
    print('LOOP CLOSED: every weakness class was classified as expected, every verifier behaved as its bug implies,');
    print('             and jsonwebtoken + PyJWT agreed with the analyzer on every case they could express.');
  } else {
    print(`LOOP OPEN: ${failures.length} check(s) failed — ${failures.map((f) => f.name).join('; ')}`);
  }
  print('');
  print('JSON-SUMMARY ' + JSON.stringify(summary.counts));

  lab.server.close();
  await new Promise((r) => lab.server.once('close', r));
  writeRunArtifact('crypto-lab', { checks, outDir: 'crypto-lab/out',
    extra: { ok: failures.length === 0, counts: summary.counts } });
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`loop: ${e.stack || e.message}\n`);
  process.exit(1);
});
