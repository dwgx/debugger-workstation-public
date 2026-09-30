#!/usr/bin/env node
/* solve-m04.mjs -- recover m04's record layout from the writer and parse the file.
 *
 * This is struct recovery, in the managed column. The artifact on disk carries no
 * self-description, so every field of the field map is derived from the
 * decompiled `WriteHeader` / `WriteRecord` / `Fnv` / `Canonical`:
 *
 *   header widths    the `, 0, <n>)` of each ms.Write(...) in WriteHeader, in order
 *   header check     the third argument of the Fnv call in WriteHeader -- how many
 *                    leading bytes the integrity word covers, and therefore where
 *                    the word itself sits
 *   record prefix    the WriteByte(...) calls before the first width-bearing write
 *   record widths    the `, 0, <n>)` of the GetBytes writes, in order
 *   record payload   the first ms.Write(x, 0, x.Length)
 *   record check     the GetBytes whose argument contains the Fnv call, and that
 *                    call's own third argument for the span
 *   alignment        the arithmetic inside AlignUp
 *   checksum         Fnv's initial value, its prime, and the order of the two
 *                    statements -- FNV-1a, not CRC32, and the difference is the
 *                    whole trap
 *   value rendering  the Kind comparisons and the literal format strings inside
 *                    Canonical
 *
 * Nothing about the file is assumed. Every offset in the printed table is
 * computed from those numbers.
 *
 * Controls, both of which the runner asserts fail:
 *   --crc32     use CRC32 instead of the recovered algorithm. A solver that has
 *               the layout right but the integrity word wrong must be caught by
 *               the file's own check, not by a human noticing.
 *   --no-align  skip the padding, so every record after the first is misaligned.
 *
 *   node tools/solve-m04.mjs --dat out/m04/m04_records.dat --expect <listing>
 *   node tools/solve-m04.mjs --dat ... --crc32 --expect <listing>     # must exit != 0
 */
import fs from 'node:fs';
import path from 'node:path';
import { decompile, evalCsharp, finish, flag, method, OUT } from './clrlib.mjs';

const asm = flag('asm') ? process.argv[process.argv.indexOf('--asm') + 1] : path.join(OUT, 'm04', 'm04_struct.dll');
const dat = flag('dat') ? process.argv[process.argv.indexOf('--dat') + 1] : path.join(OUT, 'm04', 'm04_records.dat');
if (!fs.existsSync(dat)) { process.stderr.write(`solve-m04: no artifact at ${dat}\n`); process.exit(1); }
const die = (m) => { process.stderr.write(`solve-m04: ${m}\n`); process.exit(1); };

const src = await decompile(asm);

/* ---- the named layout constants ----------------------------------------- */
const consts = Object.fromEntries([...src.matchAll(/const\s+(?:int|ushort|uint)\s+(\w+)\s*=\s*(\d+)\s*;/g)]
  .map((m) => [m[1], Number(m[2])]));
const HEADER_SIZE = consts.HeaderSize;
const REC_HDR = consts.RecordHeaderSize;
const ALIGN = consts.RecordAlign;
const VERSION = consts.Version;
if (![HEADER_SIZE, REC_HDR, ALIGN, VERSION].every(Number.isInteger)) {
  die(`cannot read the layout constants (found ${JSON.stringify(consts)})`);
}
const magicDecl = /readonly\s+byte\[\]\s+\w+\s*=\s*new\s+byte\[\d+\]\s*\{([^}]*)\}/.exec(src);
if (!magicDecl) die('cannot read the magic bytes');
const MAGIC = magicDecl[1].split(',').map((s) => Number(s.trim())).map((c) => String.fromCharCode(c)).join('');

/* ---- the integrity word: initial value, prime, and which comes first ----- */
const fnv = method(src, 'Fnv');
if (!fnv) die('no Fnv method in the decompilation');
const seedConst = /=\s*(0[xX][0-9a-fA-F]+|\d+)u?\s*;/.exec(fnv);
const primeConst = /\*=\s*(\d+)u?\s*;/.exec(fnv);
if (!seedConst || !primeConst) die('cannot read the checksum seed/prime out of Fnv');
const XOR_FIRST = fnv.indexOf('^=') < fnv.indexOf('*=');
const xorThenMul = XOR_FIRST ? 'XOR-then-multiply' : 'multiply-then-XOR';

function fnv1a(buf, off, len) {
  let h = Number(seedConst[1]) >>> 0;
  for (let i = 0; i < len; i++) {
    h ^= buf[off + i];
    if (XOR_FIRST) h = Math.imul(h, Number(primeConst[1])) >>> 0;
    else h = (h >>> 0) % Number(primeConst[1]);
  }
  return h >>> 0;
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();
function crc32(buf, off, len) {
  let c = 0xffffffff;
  for (let i = 0; i < len; i++) c = CRC_TABLE[(c ^ buf[off + i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const useCrc = flag('crc32');
const noAlign = flag('no-align');
const check = useCrc ? crc32 : fnv1a;
const alignUp = (n) => (noAlign ? n : Math.ceil(n / ALIGN) * ALIGN);

/**
 * Every `ms.Write(a, b, c)` in a body, with the argument list split at the top
 * level. A regex cannot do this: the record's integrity word is written as
 * `ms.Write(BitConverter.GetBytes(Fnv(d, off, 8 + value.Length)), 0, 4)` and the
 * nested commas defeat `[^,]*`. A naive parse drops exactly the one statement
 * that carries the layout fact we are after, and then reports "cannot find the
 * integrity word" as if the file were the problem.
 */
function writeCalls(body) {
  const out = [];
  for (let i = body.indexOf('ms.Write('); i >= 0; i = body.indexOf('ms.Write(', i + 1)) {
    const open = body.indexOf('(', i);
    let depth = 0;
    let close = -1;
    for (let j = open; j < body.length; j++) {
      if (body[j] === '(') depth++;
      else if (body[j] === ')' && --depth === 0) { close = j; break; }
    }
    if (close < 0) break;
    const inner = body.slice(open + 1, close);
    const args = [];
    let d = 0;
    let last = 0;
    for (let j = 0; j <= inner.length; j++) {
      const c = inner[j];
      if (c === '(') d++;
      else if (c === ')') d--;
      else if ((c === ',' && d === 0) || j === inner.length) { args.push(inner.slice(last, j).trim()); last = j + 1; }
    }
    const tail = args[args.length - 1];
    out.push({ args, text: inner, w: /^\d+$/.test(tail || '') ? Number(tail) : null });
  }
  return out;
}

/* ---- header layout, from the writer ------------------------------------- */
const wh = method(src, 'WriteHeader');
if (!wh) die('no WriteHeader method in the decompilation');
const hdrWrites = writeCalls(wh).filter((c) => c.w !== null);
if (hdrWrites.length === 0) die('cannot read the header field widths from WriteHeader');
let off = 0;
const hdrFields = hdrWrites.map((f) => { const o = off; off += f.w; return { ...f, off: o }; });
const hdrSpan = /\bFnv\([^,]+,\s*[^,]+,\s*([^)]+)\)/.exec(wh);
if (!hdrSpan) die('cannot read the header integrity span from WriteHeader');
const HDR_CHECK_SPAN = Number(evalCsharp(hdrSpan[1].trim()));
const CHECK_OFF = HDR_CHECK_SPAN;

/* ---- record layout, from the writer ------------------------------------- */
const wr = method(src, 'WriteRecord');
if (!wr) die('no WriteRecord method in the decompilation');
// The padding loop is also a WriteByte, so only the calls *before* the first
// width-bearing write are prefix fields.
const prefixBytes = (wr.slice(0, wr.indexOf('ms.Write(')).match(/ms\.WriteByte\(/g) || []).length;
const recCalls = writeCalls(wr);
const recWrites = recCalls.filter((c) => c.w !== null);
const recCheck = recWrites.find((w) => /\bFnv\(/.test(w.text));
if (!recCheck) die('cannot find the per-record integrity word in WriteRecord');
if (!recCalls.some((c) => c.args.length === 3 && c.args[2] === `${c.args[0]}.Length`)) {
  die('cannot find the value payload write in WriteRecord');
}
const recSpanExpr = /\bFnv\([^,]+,\s*[^,]+,\s*([^)]+)\)/.exec(recCheck.text);
if (!recSpanExpr) die('cannot read the per-record integrity span from WriteRecord');
const spanFor = (len) => Number(evalCsharp(recSpanExpr[1].trim().replace(/(\w+)\.Length\b/g, String(len))));

/* ---- how the artifact itself renders a value ---------------------------- */
const canon = method(src, 'Canonical');
if (!canon) die('no Canonical method in the decompilation');
const asciiKind = Number((/\.Kind\s*==\s*(\d+)/.exec(canon) || [])[1]);
const u32Test = /\.Kind\s*==\s*(\d+)\s*&&\s*\w+\.Value\.Length\s*==\s*(\d+)/.exec(canon);
const asciiTag = (/\.Append\("([^"]*ascii[^"]*)"\)/.exec(canon) || [])[1] || 'ascii=';
const u32Fmt = /"([^"]*\{0:x8\}[^"]*)"/.exec(canon);
const hexTag = (/\.Append\("([^"]*hex[^"]*)"\)/.exec(canon) || [])[1] || 'hex=';

/* ---- parse -------------------------------------------------------------- */
const all = fs.readFileSync(dat);
const problems = [];
if (all.subarray(0, MAGIC.length).toString('latin1') !== MAGIC) problems.push(`magic is ${all.subarray(0, 4).toString('hex')}, expected ${MAGIC}`);

const version = all.readUInt16LE(4);
const count = all.readUInt16LE(6);
const hdrCheckStored = all.readUInt32LE(CHECK_OFF);
const hdrCheckWanted = check(all, 0, HDR_CHECK_SPAN);
if (hdrCheckStored !== hdrCheckWanted) {
  problems.push(`header check ${hex32(hdrCheckStored)} != ${hex32(hdrCheckWanted)} under ${useCrc ? 'CRC32' : 'FNV-1a/32'}`);
}
const total = all.readUInt32LE(CHECK_OFF + 4);
if (total !== all.length) problems.push(`total size field ${total} != file length ${all.length}`);

const records = [];
let cursor = HEADER_SIZE;
for (let i = 0; i < count && i < 4096; i++) {
  if (cursor + REC_HDR + 4 > all.length) { problems.push(`record ${i} header overruns the file`); break; }
  const kind = all[cursor];
  const flags = all[cursor + 1];
  const id = all.readUInt16LE(cursor + 2);
  const len = all.readUInt32LE(cursor + 4);
  if (cursor + REC_HDR + len + 4 > all.length) { problems.push(`record ${i} value overruns the file`); break; }
  const value = all.subarray(cursor + REC_HDR, cursor + REC_HDR + len);
  const stored = all.readUInt32LE(cursor + REC_HDR + len);
  const wanted = check(all, cursor, spanFor(len));
  if (stored !== wanted) problems.push(`record ${i} check ${hex32(stored)} != ${hex32(wanted)} under ${useCrc ? 'CRC32' : 'FNV-1a/32'}`);
  records.push({ off: cursor, kind, flags, id, value, check: stored });
  cursor = alignUp(cursor + REC_HDR + len + 4);
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
function hex32(n) { return n.toString(16).padStart(8, '0'); }
function render(r) {
  if (r.kind === asciiKind) return `${asciiTag}"${r.value.toString('latin1')}"`;
  if (u32Test && r.kind === Number(u32Test[1]) && r.value.length === Number(u32Test[2])) {
    return (u32Fmt ? u32Fmt[1] : 'u32=0x{0:x8}').replace('{0:x8}', hex32(r.value.readUInt32LE(0)));
  }
  return hexTag + hex(r.value);
}

const listing = [
  `${MAGIC} v${version} records=${count} total=0x${hex32(total)} hdrcheck=0x${hex32(hdrCheckWanted)}`,
  ...records.map((r, i) => `[${i}] @0x${r.off.toString(16).padStart(4, '0')} kind=${r.kind} flags=0x${r.flags.toString(16).padStart(2, '0')} id=0x${r.id.toString(16).padStart(4, '0')} len=${r.value.length} check=0x${hex32(r.check)} ${render(r)}`),
].join('\n');

finish({
  ran: problems.length === 0,
  valid: problems.length === 0 && records.length === count && cursor === all.length,
  problems: problems.length ? problems : undefined,
  header: `${REC_HDR}-byte record header, ${ALIGN}-byte alignment, version ${VERSION}, magic ${MAGIC}`,
  headerWidths: hdrFields.map((f) => `+${f.off} u${f.w * 8}`).join(' '),
  headerCheck: `u32 @${CHECK_OFF}, covers ${HDR_CHECK_SPAN} leading bytes`,
  recordWidths: [`+0 u8`.repeat(0) || `${prefixBytes}x u8`, ...recWrites.map((f) => `u${f.w * 8}`)].join(' '),
  recordCheck: `u32 @${REC_HDR}+len, covers ${REC_HDR}+len bytes`,
  checksum: `${useCrc ? 'CRC32 (--crc32)' : `FNV-1a/32, seed 0x${(Number(seedConst[1]) >>> 0).toString(16)}, prime ${primeConst[1]}, ${xorThenMul}`}`,
  records: `${records.length} parsed, cursor ends at 0x${cursor.toString(16)} of 0x${all.length.toString(16)}`,
  answer: listing,
}, { expect: flag('expect') ? process.argv[process.argv.indexOf('--expect') + 1] : undefined });
