#!/usr/bin/env node
// native-lab/tools/decompile.mjs — decompile one function and print JSON.
//
//   node native-lab/tools/decompile.mjs <binary> <function-name-or-address>
//
// Prints { ok, addr, code, refs } or { ok:false, error }. The `ok` field uses the
// honest test — an `error` string with a null body counts as failure — because
// this server reports a failed analysis with isError:false and a caller that
// trusts isError alone will print a success with no code in it.

import { withServer, waitForSession, call, ok, flattenFuncs } from './ida-client.mjs';
import { existsSync } from 'node:fs';
import { IDALIB } from './ida-client.mjs';

const [, , binary, fn] = process.argv;

function die(msg) {
  console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
  process.exit(2);
}

if (!binary || !fn) die('usage: decompile.mjs <binary> <function-name-or-address>');
if (!existsSync(IDALIB)) die(`idalib-mcp missing: ${IDALIB}`);
if (!existsSync(binary)) die(`binary not found: ${binary}`);

try {
  const out = await withServer(binary, async () => {
    const sess = await waitForSession();
    const db = sess.session_id;

    // Resolve a name to an address first, so the same code path serves both.
    let target = fn;
    if (!/^0x/i.test(fn)) {
      const lf = await call('list_funcs', { queries: [{ count: 2000 }], database: db });
      const hit = flattenFuncs(lf.body).find((f) => f.name === fn);
      if (!hit) {
        return { ok: false, error: `no function named '${fn}' in ${sess.filename}` };
      }
      target = hit.addr;
    }

    const dec = await call('decompile', { addr: target, include_addresses: false, database: db });
    if (!ok(dec)) {
      // Report the server's own words rather than paraphrasing them.
      return { ok: false, addr: target, error: dec.body?.error || 'decompile returned no usable body' };
    }
    return {
      ok: true,
      binary: sess.filename,
      session: db,
      addr: dec.body?.addr || target,
      code: dec.body?.code ?? null,
      refs: dec.body?.refs ?? [],
    };
  });

  console.log(JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: e.message }, null, 2));
  process.exit(2);
}
