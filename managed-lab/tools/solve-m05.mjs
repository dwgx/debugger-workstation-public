#!/usr/bin/env node
/* solve-m05.mjs -- cross the managed/native boundary and recover m05's key.
 *
 * The managed half is read first, because that is what narrows the problem. From
 * the decompiled C# we learn: the DLL name, the two export names, their
 * signatures, the seed the managed side passes, and how long the accepted key
 * is. None of that is the answer -- it is the *address* of the answer, in another
 * binary.
 *
 * The native half is read with the station's headless Ghidra path
 * (scripts/ghidra-headless.ps1). From `LabCheck` we take the comparison length,
 * the mask constant, and the address of the masked table -- all three are inline
 * literals in the decompilation, which is why this works without symbols. The
 * bytes at that address come from r2 through the loader, and the export table is
 * cross-checked with rabin2, so the address is confirmed by a second tool before
 * anything is read out of it.
 *
 * The key is then the inverse of `LabTransform`, and the inverse is the subtle
 * part: the forward transform is XOR-then-swap, so the inverse is swap-then-XOR.
 * Applying the forward transform twice is a very plausible mistake and yields a
 * 14-byte answer that is simply wrong.
 *
 * Finally the recovered transform is checked against the real function, through
 * the managed side's own `--selftest`. That is the independent source: the
 * algorithm came from a decompilation, the confirmation comes from a call.
 *
 * Controls:
 *   --forward   apply LabTransform instead of its inverse (complete, wrong)
 *   --no-mask   read the masked table without unmasking it (complete, wrong)
 *
 *   node tools/solve-m05.mjs --expect "M05-BRIDGE-KEY"
 *   node tools/solve-m05.mjs --forward --expect "M05-BRIDGE-KEY"   # must exit != 0
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  OUT, decompile, exportsOf, finish, flag, method, readVa, run,
} from './clrlib.mjs';

const STATION = process.env.DEBUGGER_STATION || path.resolve(OUT, '..', '..');
const die = (m) => { process.stderr.write(`solve-m05: ${m}\n`); process.exit(1); };

const asm = flag('asm') ? process.argv[process.argv.indexOf('--asm') + 1] : path.join(OUT, 'm05', 'm05_bridge.dll');
const dll = flag('dll') ? process.argv[process.argv.indexOf('--dll') + 1] : path.join(OUT, 'm05', 'labnative.dll');
const exe = flag('exe') ? process.argv[process.argv.indexOf('--exe') + 1] : path.join(OUT, 'm05', 'm05_bridge.exe');
for (const p of [asm, dll, exe]) if (!fs.existsSync(p)) die(`missing ${p}`);

/* ---- 1. the managed half: where the answer is, not what it is ----------- */
const managed = await decompile(asm);
const libConst = /const\s+string\s+Lib\s*=\s*"([^"]+)"/.exec(managed);
if (!libConst) die('no DllImport library name in the decompilation');
const LIB = libConst[1];
const imports = [...managed.matchAll(/\[DllImport\("([^"]+)"[^\]]*\)\]\s*\r?\n\s*private static extern \w+ (\w+)\(([^)]*)\)/g)]
  .map((m) => ({ lib: m[1], name: m[2], args: m[3] }));
if (imports.length < 2) die(`expected at least two DllImport declarations, found ${imports.length}`);
const checkFn = imports.find((i) => /check/i.test(i.name));
const xformFn = imports.find((i) => /transform/i.test(i.name));
if (!checkFn || !xformFn) die('cannot identify the check and transform imports');
const keyLenConst = /const\s+int\s+KeyLen\s*=\s*(\d+)/.exec(managed);
const seedConst = /const\s+byte\s+Seed\s*=\s*(\d+)/.exec(managed);
if (!keyLenConst || !seedConst) die('cannot read KeyLen / Seed from the decompilation');
const SEED = Number(seedConst[1]);
const resolver = /SetDllImportResolver/.test(managed) ? 'SetDllImportResolver (explicit load path)' : 'default probing';

/* ---- 2. the native half, decompiled headlessly -------------------------- */
let ghidraDir = flag('ghidra-dir') ? process.argv[process.argv.indexOf('--ghidra-dir') + 1] : null;
if (!ghidraDir) {
  ghidraDir = fs.mkdtempSync(path.join(os.tmpdir(), 'm05-ghidra-'));
  const wrapper = path.join(STATION, 'scripts', 'ghidra-headless.ps1');
  if (!fs.existsSync(wrapper)) die(`no headless wrapper at ${wrapper}`);
  const g = await run('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', wrapper, '-Sample', dll, '-OutDir', ghidraDir], { timeout: 900000 });
  if (g.code !== 0) die(`ghidra-headless.ps1 exited ${g.code}: ${(g.stdout || g.stderr || '').trim().split('\n').slice(-3).join(' | ')}`);
}

const exportsList = await exportsOf(dll);
const exportNames = exportsList.map((e) => e.name);
for (const fn of [checkFn.name, xformFn.name]) {
  if (!exportNames.includes(fn)) die(`${fn} is imported by the managed code but not exported by ${LIB}`);
}

const decompDir = path.join(ghidraDir, 'decompiled');
if (!fs.existsSync(decompDir)) die(`no decompiled/ under ${ghidraDir}`);
const findDecompile = (name) => {
  const f = fs.readdirSync(decompDir).find((x) => x.startsWith(`${name}_`) && x.endsWith('.c'));
  return f ? fs.readFileSync(path.join(decompDir, f), 'utf8') : '';
};
const cCheck = findDecompile(checkFn.name);
const cXform = findDecompile(xformFn.name);
if (!cCheck || !cXform) die('Ghidra did not decompile both exports');

/* ---- 3. the masked table: length, mask key, and address ----------------- */
const lenTest = new RegExp(`param_\\d+\\s*!=\\s*(0[xX][0-9a-fA-F]+|\\d+)`).exec(cCheck);
if (!lenTest) die('cannot read the accepted key length out of the decompiled LabCheck');
const KEYLEN = Number(lenTest[1]);
const tableRef = /\(&DAT_([0-9a-fA-F]+)\)/.exec(cCheck);
const maskConst = /\^\s*(0[xX][0-9a-fA-F]+)\s*[);,]/.exec(cCheck);
if (!tableRef) die('cannot find the masked table reference (DAT_...) in the decompiled LabCheck');
if (!maskConst) die('cannot find the mask constant in the decompiled LabCheck');
const TABLE_VA = BigInt(`0x${tableRef[1]}`);
const MASK = Number(maskConst[1]);

if (KEYLEN !== Number(keyLenConst[1])) {
  die(`length disagreement: managed says ${keyLenConst[1]}, native decompile says ${KEYLEN}`);
}

const table = await readVa(dll, `0x${TABLE_VA.toString(16)}`, KEYLEN);
const wanted = Buffer.from(table);
if (!flag('no-mask')) for (let i = 0; i < wanted.length; i++) wanted[i] ^= MASK;

/* ---- 4. the transform, and its inverse ----------------------------------- */
const mult = /\*\s*'\\x([0-9a-fA-F]{2})'/.exec(cXform) || /\*\s*(\d+)\s*\+/.exec(cXform);
if (!mult) die('cannot read the per-index multiplier out of the decompiled LabTransform');
const MULT = parseInt(mult[1], 16);
const hasSwap = /=\s*\w+\s*\+\s*-2\s*;/.test(cXform);
if (!hasSwap) die('the decompiled LabTransform has no descending-by-2 swap; the shape changed');

const xform = (buf, seed) => {
  const b = Buffer.from(buf);
  for (let i = 0; i < b.length; i++) b[i] ^= (seed + i * MULT) & 0xff;
  for (let i = b.length - 1; i > 0; i -= 2) { const t = b[i - 1]; b[i - 1] = b[i]; b[i] = t; }
  return b;
};
const unxform = (buf, seed) => {
  const b = Buffer.from(buf);
  for (let i = b.length - 1; i > 0; i -= 2) { const t = b[i - 1]; b[i - 1] = b[i]; b[i] = t; }
  for (let i = 0; i < b.length; i++) b[i] ^= (seed + i * MULT) & 0xff;
  return b;
};

const forward = flag('forward');
const key = (forward ? xform : unxform)(wanted, SEED);
/* ---- 5. the independent check: ask the real function -------------------- */
const probe = 'probe-bytes';
const mine = xform(Buffer.from(probe, 'ascii'), SEED).toString('hex');
const selftest = await run(exe, ['--selftest', probe]);
const selftestHex = (/out\s+([0-9a-f]+)/.exec(selftest.stdout || '') || [])[1];
const selftestOk = selftestHex === mine;

finish({
  ran: true,
  valid: selftestOk,
  managed: `${LIB}!${checkFn.name}(${checkFn.args})  ${LIB}!${xformFn.name}(${xformFn.args})`,
  dllLoad: resolver,
  exports: `${LIB}.dll exports ${exportNames.filter((n) => !/^Ordinal_/.test(n)).join(', ')} (rabin2)`,
  keyLen: `${KEYLEN} (agreed by the managed const and the native comparison)`,
  seed: `0x${SEED.toString(16)} (passed by the managed side)`,
  table: `DAT_${tableRef[1]} -> ${table.toString('hex')} (r2), unmasked with 0x${MASK.toString(16)}`,
  wanted: wanted.toString('hex'),
  transform: `b[i] ^= (seed + i*${MULT}) & 0xff, then swap pairs walking back from the end`,
  direction: forward ? 'FORWARD (control: this is not the inverse)' : 'inverse = swap-then-xor',
  selftest: selftestOk
    ? `LabTransform("${probe}", 0x${SEED.toString(16)}) == ${mine} -- matches the live call`
    : `selftest mismatch: recovered ${mine}, live call ${selftestHex}`,
  key: key.toString('latin1'),
  answer: key.toString('latin1'),
}, { expect: flag('expect') ? process.argv[process.argv.indexOf('--expect') + 1] : undefined });
