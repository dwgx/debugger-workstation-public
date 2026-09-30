#!/usr/bin/env node
// native-lab/tools/list-tools.mjs — reflect the live MCP tool surface.
//
// The registry records "66 tools". That is a measurement, not a promise, and an
// upgrade to ida-pro-mcp would silently invalidate it. This prints what is actually
// exposed right now so the recorded number can be checked instead of trusted.

import { withServer, toolNames, ok } from './ida-client.mjs';
import { existsSync } from 'node:fs';
import { IDALIB } from './ida-client.mjs';

const SELF = 'crackme-corpus/out/c01-stringobf.exe';

try {
  if (!existsSync(IDALIB)) {
    console.log(JSON.stringify({ ok: false, error: `idalib-mcp missing: ${IDALIB}` }, null, 2));
    process.exit(2);
  }
  if (!existsSync(SELF)) {
    console.log(JSON.stringify({ ok: false, error: `target missing: ${SELF}` }, null, 2));
    process.exit(2);
  }

  const out = await withServer(SELF, async () => {
    const names = await toolNames();
    return { ok: true, count: names.length, tools: names.sort() };
  });

  console.log(JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: e.message }, null, 2));
  process.exit(2);
}
