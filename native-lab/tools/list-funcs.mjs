#!/usr/bin/env node
// native-lab/tools/list-funcs.mjs — enumerate functions and emit the registry's typed fact.
//
// This exists so the mission loop has something it can actually CALL with a typed
// result, rather than a probe it can merely re-run. The registry entry
// native.ida.list_functions declares it produces `native.func.addr`; this is the
// producer, and native.ida.decompile is the consumer.
//
//   node native-lab/tools/list-funcs.mjs <binary> [--json]
//
// Emits the same envelope as decompile.mjs: { ok, ... } or { ok:false, error }.
// The `ok` field uses the honest test -- an `error` string with a null body counts as
// failure -- because this server reports a failed analysis with isError:false.

import { withServer, waitForSession, call, ok, flattenFuncs } from './ida-client.mjs';
import { existsSync } from 'node:fs';
import { IDALIB } from './ida-client.mjs';

const [, , binary, ...rest] = process.argv;
const asJson = rest.includes('--json');

function die(msg, code = 2) {
  console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
  process.exit(code);
}

if (!binary) die('usage: list-funcs.mjs <binary> [--json]');
if (!existsSync(IDALIB)) die(`idalib-mcp missing: ${IDALIB}`);
if (!existsSync(binary)) die(`binary not found: ${binary}`);

try {
  const out = await withServer(binary, async () => {
    const sess = await waitForSession();
    const lf = await call('list_funcs', { queries: [{ count: 2000 }], database: sess.session_id });
    if (!ok(lf)) {
      return { ok: false, error: lf.body?.error || 'list_funcs returned no usable body' };
    }

    const funcs = flattenFuncs(lf.body)
      .filter((f) => f && f.name && f.addr)
      .map((f) => ({ addr: f.addr, name: f.name, size: f.size ?? null }));

    if (funcs.length === 0) {
      // An empty list is not a finding. Say so, rather than letting a caller read
      // "0 functions" as "this binary has no functions".
      return { ok: false, error: `no functions recovered from ${sess.filename}`, count: 0 };
    }

    return {
      ok: true,
      binary: sess.filename,
      session: sess.session_id,
      count: funcs.length,
      // The typed fact, in the shape the registry declares: native.func.addr
      functions: funcs,
      named: funcs.filter((f) => !f.name.startsWith('sub_')).map((f) => f.name),
    };
  });

  if (!out.ok) { console.log(JSON.stringify(out, null, 2)); process.exit(1); }

  if (asJson) {
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log(`${out.count} functions in ${out.binary}`);
    for (const f of out.functions.slice(0, 40)) console.log(`  ${f.addr.padEnd(14)} ${f.name}`);
    if (out.count > 40) console.log(`  ... ${out.count - 40} more`);
  }
  process.exit(0);
} catch (e) {
  die(e.message);
}
