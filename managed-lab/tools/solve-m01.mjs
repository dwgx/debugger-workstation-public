#!/usr/bin/env node
/* solve-m01.mjs -- recover m01's encrypted strings from the decompilation alone.
 *
 * Nothing here is hard-coded. The ciphertexts are the string literals the
 * decompiled `Reveal` is called with; the keystream is the `return` expression of
 * the decompiled `KeyStream`, evaluated as C# with its own parameter names; the
 * seed is the literal the decompiled XOR loop hands to `KeyStream`; and the
 * order of the two layers is read off the source order of the two loops inside
 * `Reveal`.
 *
 * `--wrong-order` applies the layers the other way round. That is the negative
 * control: it is what a solver that "knows" the scheme instead of reading it
 * produces, and it must not reproduce the plaintext.
 *
 *   node tools/solve-m01.mjs --asm out/m01/m01_stringobf.dll
 *   node tools/solve-m01.mjs --asm ... --expect "the quick brown fox jumps over the lazy dog"
 *   node tools/solve-m01.mjs --asm ... --wrong-order --expect <the real answer>   # must exit 4
 */
import { decompile, evalCsharp, flag, finish, params, returnExpr, method } from './clrlib.mjs';

const asm = process.argv.includes('--asm')
  ? process.argv[process.argv.indexOf('--asm') + 1]
  : null;
if (!asm) {
  process.stderr.write('usage: solve-m01.mjs --asm <assembly> [--expect <plaintext>] [--wrong-order] [--json]\n');
  process.exit(2);
}

const src = await decompile(asm);
const die = (msg) => { process.stderr.write(`solve-m01: ${msg}\n`); process.exit(1); };

/* ---- the keystream, read out of the helper ------------------------------- */
const ksBody = method(src, 'KeyStream');
if (!ksBody) die('no KeyStream method in the decompilation');
const ksExpr = returnExpr(ksBody);
const ksParams = params(src, 'KeyStream');
if (ksParams.length !== 2) die(`KeyStream takes ${ksParams.length} parameters, expected 2`);
const keyStream = (index, seed) => evalCsharp(ksExpr, { [ksParams[0]]: index, [ksParams[1]]: seed }) & 0xff;

/* ---- the two layers, and the order they are applied in ------------------ */
const reveal = method(src, 'Reveal');
if (!reveal) die('no Reveal method in the decompilation');

// layer 2 -- the odd-index swap: for (int i = 1; i + 1 < a.Length; i += 2) {...}
const swap = /for\s*\(\s*\w+\s+(\w+)\s*=\s*1\s*;\s*\1\s*\+\s*1\s*<\s*[\w.]+\.Length\s*;\s*\1\s*\+=\s*2\s*\)/.exec(reveal);
if (!swap) die('no odd-index swap loop inside Reveal');

// layer 1 -- the XOR loop, and the seed literal it hands to the keystream
const xorCall = new RegExp(`${ksParams[0] ? 'KeyStream' : 'KeyStream'}\\s*\\(\\s*\\w+\\s*,\\s*(\\d+)\\s*\\)`).exec(reveal)
  || /KeyStream\s*\(\s*\w+\s*,\s*(\d+)\s*\)/.exec(reveal);
if (!xorCall) die('no KeyStream call inside Reveal -- cannot read the seed');
const seed = Number(xorCall[1]);

const swapFirst = swap.index < xorCall.index;
const inverted = flag('wrong-order');

function swapOddPairs(b) {
  for (let i = 1; i + 1 < b.length; i += 2) { const t = b[i]; b[i] = b[i + 1]; b[i + 1] = t; }
  return b;
}

function decrypt(blob) {
  const b = Buffer.from(blob, 'base64');
  if (swapFirst !== inverted) swapOddPairs(b);
  for (let i = 0; i < b.length; i++) b[i] = keyStream(i, seed) ^ b[i];
  if (swapFirst === inverted) swapOddPairs(b);
  return b;
}

/* ---- the ciphertexts: every literal handed to Reveal --------------------- */
const blobs = [...src.matchAll(/Reveal\(\s*"([A-Za-z0-9+/=]+)"\s*\)/g)].map((m) => m[1]);
if (blobs.length === 0) die('no ciphertext literals found');

const lines = blobs.map((b) => decrypt(b).toString('utf8'));
const printable = lines.length > 0 && lines.every((l) => /^[\x20-\x7e]+$/.test(l));

finish({
  valid: printable,
  technique: 'per-index keystream XOR + odd-index byte swap, both read from the decompilation',
  keystream: ksExpr.replace(/\s+/g, ' '),
  seed: `0x${seed.toString(16)}`,
  layerOrder: `${swapFirst ? 'swap-then-xor' : 'xor-then-swap'}${inverted ? '  [DELIBERATELY INVERTED]' : ''}`,
  ciphertexts: blobs.map((b) => `${b.length} b64 chars`),
  recovered: lines,
  answer: lines[1] ?? '',
}, { expect: argOf('expect') });

function argOf(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
