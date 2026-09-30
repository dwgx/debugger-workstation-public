#!/usr/bin/env node
/* Quick self-check for the hand-built ELF. Run: node lab/build/check-so.mjs */
import { buildSo, verifySo } from './make-so.mjs';
import { writeFileSync } from 'node:fs';

const { buffer, meta, soname } = buildSo();
const v = verifySo(buffer);
writeFileSync(new URL('../../.out-test.so', import.meta.url), buffer);
process.stdout.write(
  `soname=${soname} size=${buffer.length} ok=${v.ok} problems=${JSON.stringify(v.problems)}\n` +
  `exports=${meta.exports.length} imports=${meta.imports.length} needed=${JSON.stringify(meta.needed)}\n` +
  `sha256=${v.sha256}\n`
);
process.exit(v.ok ? 0 : 1);
