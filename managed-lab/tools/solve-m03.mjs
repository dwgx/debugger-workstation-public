#!/usr/bin/env node
/* solve-m03.mjs -- extract and unmask m03's embedded resource payload.
 *
 * Two different tools, two different jobs, which is the point of the sample:
 *
 *   1. `--list-resources` finds the payload without decompiling anything. The
 *      suffix the loader looks for is read out of the decompilation
 *      (`ResourceSuffix`), so even the name is not hard-coded.
 *   2. `--resource <name>` hands over the raw bytes. No re-implementation needed
 *      to *get* them -- only to *read* them.
 *   3. The seed and the mask are read out of the decompiled `Unmask`: the seed
 *      expression is evaluated with the resource name's own length substituted,
 *      and the mask is the assignment expression taken verbatim from the loop.
 *
 * `--skip-mask` stops after step 2, which is where a lot of analyses actually
 * stop: the bytes are in hand, they are just still masked. It must not produce
 * the payload.
 *
 *   node tools/solve-m03.mjs --asm out/m03/m03_resource.dll
 *   node tools/solve-m03.mjs --asm ... --expect ae5ee44b7f198f47106fd52f1d17f72e804144598480c90ebe302d53d1300f24
 *   node tools/solve-m03.mjs --asm ... --skip-mask --expect <the real sha256>   # must exit 4
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { decompile, evalCsharp, finish, flag, ilspy, method, OUT } from './clrlib.mjs';

const asm = flag('asm') ? process.argv[process.argv.indexOf('--asm') + 1] : null;
if (!asm) {
  process.stderr.write('usage: solve-m03.mjs --asm <assembly> [--expect <sha256>] [--skip-mask] [--json]\n');
  process.exit(2);
}
const die = (m) => { process.stderr.write(`solve-m03: ${m}\n`); process.exit(1); };

const src = await decompile(asm);

/* ---- 1. which resource, decided by the suffix the loader asks for -------- */
const suffixConst = /const\s+string\s+(\w+)\s*=\s*"([^"]*)"\s*;/.exec(src);
if (!suffixConst) die('no string const in the decompilation to learn the resource suffix from');
const [, suffixName, suffix] = suffixConst;
const expectCount = /Count\s*!=\s*(\d+)/.exec(src);

const listing = (await ilspy(['--list-resources'], asm))
  .split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
const names = listing.filter((n) => n.endsWith(suffix));
if (names.length !== (expectCount ? Number(expectCount[1]) : 1)) {
  die(`expected ${expectCount ? expectCount[1] : 1} resource ending in "${suffix}", found ${names.length}`);
}
const name = names[0];

/* ---- 2. the raw resource, straight out of the assembly ------------------- */
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'm03-resource-'));
const extracted = path.join(tmp, name);
const got = await ilspy(['--resource', name, '-o', tmp], asm);
if (!fs.existsSync(extracted)) {
  die(`ilspycmd --resource produced nothing at ${extracted}${got ? ` (stdout: ${got.trim().slice(0, 120)})` : ''}`);
}
const raw = Buffer.from(fs.readFileSync(extracted, 'utf8').trim(), 'base64');

/* ---- 3. the seed and the mask, read out of the decompiled Unmask --------- */
const unmask = method(src, 'Unmask');
if (!unmask) die('no Unmask method in the decompilation');

const seedDecl = /\bint\s+(\w+)\s*=\s*([^;]+);/.exec(unmask);
if (!seedDecl) die('cannot find the seed declaration in Unmask');
const [, seedVar, seedExprRaw] = seedDecl;
const seedParam = /\bUnmask\s*\(([^)]*)\)/.exec(src)[1].split(',')[0].trim().split(/\s+/).pop();
const seedExpr = seedExprRaw
  .replace(new RegExp(`${seedParam}\\.Length`, 'g'), String(name.length))
  .replace(new RegExp(`\\b${seedParam}\\b`, 'g'), JSON.stringify(name));
const seed = evalCsharp(seedExpr) & 0xff;

// the mask: the assignment inside Unmask's loop, taken verbatim
const loop = /for\s*\([^)]*\)\s*\{([\s\S]*?)\n\s*\}/.exec(unmask);
if (!loop) die('cannot find the masking loop in Unmask');
const assign = /=\s*([^;]*);/.exec(loop[1]);
if (!assign) die('cannot find the assignment in the masking loop');
const loopVar = /for\s*\(\s*\w+\s+(\w+)\s*=/.exec(unmask)[1];

let maskExpr = assign[1]
  .replace(/^\(\s*(?:byte|sbyte|short|ushort|int|uint|long)\s*\)\s*/, '')
  .replace(/\b(\w+)\[\s*(\w+)\s*\]/g, 'b[$2]')
  .replace(new RegExp(`\\b${seedVar}\\b`, 'g'), String(seed))
  .replace(new RegExp(`\\b${loopVar}\\b`, 'g'), 'k');
if (/^[()]/.test(maskExpr)) maskExpr = maskExpr.slice(1, -1);
const mask = new Function('b', 'k', `"use strict"; return (${maskExpr}) & 0xff;`); // eslint-disable-line no-new-func

const skipMask = flag('skip-mask');
const plain = Buffer.from(raw);
if (!skipMask) for (let i = 0; i < plain.length; i++) plain[i] = mask(plain, i);

const sha = createHash('sha256').update(plain).digest('hex');
const magic = plain.subarray(0, 4).toString('latin1');

fs.rmSync(tmp, { recursive: true, force: true });

finish({
  ran: true,
  valid: !skipMask && /^[\x20-\x7e]*$/.test(plain.subarray(5).toString('utf8')),
  tool1: `ilspycmd --list-resources -> ${listing.length} resource(s), matched "${suffix}" (const ${suffixName})`,
  tool2: `ilspycmd --resource ${name} -> ${raw.length} bytes`,
  seedExpr: seedExpr.replace(/\s+/g, ' '),
  seed: `0x${seed.toString(16).padStart(2, '0')} (from ${seedParam}.Length = ${name.length})`,
  maskExpr: maskExpr.replace(/\s+/g, ' '),
  length: plain.length,
  magic,
  version: `0x${plain[4].toString(16).padStart(2, '0')}`,
  sha256: sha,
  body: plain.subarray(5).toString('utf8').trim(),
  answer: sha,
}, { expect: flag('expect') ? process.argv[process.argv.indexOf('--expect') + 1] : undefined });
