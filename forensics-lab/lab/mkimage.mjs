/* mkimage.mjs — build the synthetic analysis target from `spec.mjs`.
 *
 * This is a FIXTURE, not an acquisition. There is no acquisition path in this lab and
 * there never will be one: see README "Honest limits". What this produces is a flat,
 * little-endian, page-aligned blob in which every structure sits at a known file offset,
 * so a parser has to do the same work Volatility does — walk a doubly-linked list of
 * physical offsets, read a VAD tree, chase a socket list, then read strings out of the
 * image — rather than reading a JSON convenience object.
 *
 * Determinism: no wall clock, no randomness, no environment. Same input, same bytes.
 * `--print-header` dumps the self-describing header for the transcript.
 *
 * Record layout is fixed-stride and documented in RECORD below, and every field offset
 * is asserted against the stride before a single byte is emitted. A parser that guesses
 * an offset is a parser that will read a plausible wrong number.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as S from './spec.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ layout */

const PAGE = S.PAGE_SIZE;
const REGION_ORDER = ['HEADER', 'STRINGS', 'CONTENT', 'POOL', 'VADS', 'OBJECTS'];

/* Every structure is fixed-stride. The `at` entries are the authoritative field
 * offsets; `tools/triage.mjs` imports the same table, so a layout change breaks the
 * parser and the generator at the same time instead of silently producing garbage. */
export const RECORD = {
  eprocess: {
    stride: 64,
    at: { sig: 0x00, pid: 0x04, ppid: 0x08, flags: 0x0c, flink: 0x10, blink: 0x18, nameOff: 0x20, pathOff: 0x28, createFT: 0x30, exitFT: 0x38 },
  },
  tcp: {
    stride: 64,
    at: { sig: 0x00, pid: 0x04, state: 0x08, local: 0x0c, lport: 0x10, pad0: 0x12, remote: 0x14, rport: 0x18, pad1: 0x1a, createFT: 0x20, flink: 0x28, blink: 0x30 },
  },
  vad: {
    stride: 80,
    at: { sig: 0x00, pid: 0x04, start: 0x08, end: 0x10, prot: 0x18, mem: 0x1c, backing: 0x20, content: 0x28, size: 0x30, flink: 0x38, blink: 0x40, poolTag: 0x48 },
  },
  handle: {
    stride: 64,
    at: { sig: 0x00, proc: 0x04, value: 0x08, access: 0x0c, nameOff: 0x10, type: 0x18, refCount: 0x28 },
  },
};

/* In-band fixture marker. NOT a real DKOM artefact — a real rootkit leaves no flag.
 * It exists so the fixture's own self-check and the ground truth can name the case, and
 * `tools/triage.mjs` never reads it. The parser detects the unlink by DISAGREEMENT
 * between the list walk and the pool scan, which is the actual technique. */
export const FLAG_FIXTURE_UNLINKED = 0x1;

for (const [name, r] of Object.entries(RECORD)) {
  const widest = Math.max(...Object.values(r.at).map((o) => o + 8));
  if (widest > r.stride) throw new Error(`RECORD.${name}: fields exceed stride ${r.stride} (need ${widest})`);
}

/* ------------------------------------------------------------------ writer */

/* A growable little-endian byte buffer. Single backing store, so patching a field that
 * was reserved earlier is a plain write at an offset — the alternative (append-only
 * chunks) forces every pointer field to be a second pass and invites off-by-one bugs. */
class Image {
  constructor(cap = 1 << 20) { this.buf = Buffer.alloc(cap); this.length = 0; }
  _need(n) {
    if (this.length + n <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.length + n) cap *= 2;
    const next = Buffer.alloc(cap);
    this.buf.copy(next, 0, 0, this.length);
    this.buf = next;
  }
  align(n = PAGE) { const pad = (n - (this.length % n)) % n; if (pad) { this._need(pad); this.length += pad; } return this.length; }
  skip(n) { this._need(n); this.length += n; return this.length; }
  u8(v) { this._need(1); this.buf.writeUInt8(v & 0xff, this.length); return ++this.length; }
  u16(v) { this._need(2); this.buf.writeUInt16LE(v & 0xffff, this.length); this.length += 2; return this.length; }
  u32(v) { this._need(4); this.buf.writeUInt32LE(v >>> 0, this.length); this.length += 4; return this.length; }
  u64(v) { this._need(8); this.buf.writeBigUInt64LE(BigInt(v), this.length); this.length += 8; return this.length; }
  ascii(s, bytes) { this._need(bytes); this.buf.fill(0, this.length, this.length + bytes); this.buf.write(s, this.length, 'ascii'); this.length += bytes; return this.length; }
  utf16le(s, bytes) {
    this._need(bytes);
    this.buf.fill(0, this.length, this.length + bytes);
    const units = Math.min(Math.floor(bytes / 2), s.length);
    for (let i = 0; i < units; i++) this.buf.writeUInt16LE(s.charCodeAt(i), this.length + i * 2);
    this.length += bytes;
    return this.length;
  }
  bytes(b) { this._need(b.length); b.copy(this.buf, this.length); this.length += b.length; return this.length; }
  /* patch a previously reserved field */
  patch(off, write) { write(this.buf, off); }
  patchU64(off, v) { this.buf.writeBigUInt64LE(BigInt(v), off); }
  patchU32(off, v) { this.buf.writeUInt32LE(v >>> 0, off); }
  patchU16(off, v) { this.buf.writeUInt16LE(v & 0xffff, off); }
  out() { return this.buf.subarray(0, this.length); }
}

const msToFiletime = (ms) => (BigInt(Math.round(ms)) + 116_444_736_000n) * 10_000n;
/* IPv4 as a real stack stores it: network byte order, big-endian in reading order.
   Anything else and netscan renders a reversed address — the kind of bug that makes an
   IOC wrong in a way nobody notices until it is published. */
const ipToU32 = (s) => {
  const parts = s.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    throw new Error(`bad IPv4 literal: ${s}`);
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
};
const u32ToIp = (v) => `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`;
const filetimeToMs = (ft) => Number(ft / 10_000n - 116_444_736_000n);

/* ------------------------------------------------------------------ payload PE */

/* The injected region must hold bytes a REAL third-party tool identifies as a PE, or
 * "the injected region contains a PE" is an unfalsifiable claim. Two producers:
 *
 *   1. `lab/payload/d12payload.dll` — a real, self-authored MSVC build (see
 *      `lab/payload/d12payload.c`). Byte-reproducible with /Brepro.
 *   2. `buildMinimalPe()` below — a hand-built PE, so the loop still closes on a box
 *      with no compiler. Structurally valid: DOS stub, PE signature, PE32+ optional
 *      header, one section, export directory. diec still calls it PE64.
 *
 * Either way the payload is INNOCUOUS: no network, no injection, no persistence, no
 * evasion. It is a marker carrier so that "there is a PE here" is checkable by a tool
 * that is not this lab.
 */
export function resolvePayload() {
  const built = path.join(HERE, 'payload', 'd12payload.dll');
  if (fs.existsSync(built)) {
    const bytes = fs.readFileSync(built);
    return { bytes, producer: 'msvc', origin: 'forensics-lab/lab/payload/d12payload.c', note: 'self-authored; verified byte-reproducible with cl /Brepro' };
  }
  return { bytes: buildMinimalPe(), producer: 'handbuilt', origin: 'forensics-lab/lab/mkimage.mjs:buildMinimalPe', note: 'no compiler on this box; structurally valid PE, verified by diec' };
}

export function buildMinimalPe({ marker = 'D12LAB-PAYLOAD-v1', subsystem = 0x0003 } = {}) {
  /* Layout mirrors what link.exe produces: DOS header, DOS stub text, the e_lfanew
   * pointer at 0x3c, then the NT headers. The stub sits at 0x40 and the NT headers at
   * 0xf8, which is why e_lfanew is 0xf8. Writing the stub over the NT headers, or over
   * e_lfanew itself, yields a file whose first two bytes are a valid MZ and whose PE
   * claim is nonsense — which is exactly what a naive hand-rolled PE does, and exactly
   * the bug a "MZ in a private region" scanner is supposed to catch and this one did. */
  const DOS_STUB = 0x40;
  const NT = 0xf8;
  const OPT = 240, SECT_HDR = 40;
  const SECT_OFF = NT + 4 + 20 + OPT;
  const HDRS = SECT_OFF + SECT_HDR;
  const RVA = 0x1000, SIZE = RVA + 0x200;
  const buf = Buffer.alloc(SIZE);

  buf.write('MZ', 0, 'ascii');
  buf.writeUInt16LE(0x90, 0x02);              // e_cblp
  buf.writeUInt16LE(3, 0x04);                // e_cp
  buf.writeUInt16LE(4, 0x08);                // e_cparhdr
  buf.writeUInt16LE(0xb8ff, 0x0c);           // e_maxalloc
  buf.writeUInt16LE(0xb8, 0x12);             // e_sp
  buf.writeUInt32LE(NT, 0x3c);                // e_lfanew -> NT headers, not the stub
  buf.write('This program cannot be run in DOS mode.\r\r\n$', DOS_STUB, 'ascii');

  buf.write('PE\0\0', NT, 'ascii');
  buf.writeUInt16LE(0x8664, NT + 4);         // Machine: AMD64
  buf.writeUInt16LE(1, NT + 6);              // NumberOfSections
  buf.writeUInt16LE(OPT, NT + 16);           // SizeOfOptionalHeader
  buf.writeUInt16LE(0x0022, NT + 18);        // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  const o = NT + 24;
  buf.writeUInt16LE(0x20b, o);               // PE32+ magic
  buf.writeUInt8(14, o + 2);                 // LinkerMajor
  buf.writeUInt32LE(SIZE, o + 16);           // SizeOfImage
  buf.writeUInt32LE(HDRS, o + 20);           // SizeOfHeaders
  buf.writeUInt32LE(0x100000, o + 32);       // SectionAlignment
  buf.writeUInt32LE(0x200, o + 36);          // FileAlignment
  buf.writeUInt16LE(subsystem, o + 68);      // Subsystem
  buf.writeUInt32LE(16, o + 108);            // NumberOfRvaAndSizes
  const exp = o + 112;
  buf.writeUInt32LE(RVA + 0x100, exp);       // export directory RVA
  buf.writeUInt32LE(0x40, exp + 4);          // export directory size

  const s = SECT_OFF;
  buf.write('.text\0\0\0', s, 'ascii');
  buf.writeUInt32LE(0x200, s + 8);           // VirtualSize
  buf.writeUInt32LE(RVA, s + 12);            // VirtualAddress
  buf.writeUInt32LE(0x200, s + 16);          // SizeOfRawData
  buf.writeUInt32LE(RVA, s + 20);            // PointerToRawData
  buf.writeUInt32LE(0x6000_0020, s + 36);    // CODE | EXECUTE | READ

  /* export directory, one named export, then the marker */
  const ed = RVA + 0x100;
  buf.writeUInt32LE(RVA + 0x140, ed + 16);   // AddressOfNames
  buf.writeUInt32LE(RVA + 0x160, ed + 20);   // AddressOfNameOrdinals
  buf.writeUInt32LE(RVA + 0x180, ed + 28);   // AddressOfFunctions
  buf.write('D12LabNoop', RVA + 0x140, 'ascii');
  buf.write(marker, RVA + 0x180, 'ascii');
  return buf;
}

/* ------------------------------------------------------------------ builder */

export function buildImage() {
  const img = new Image();
  const regionBase = {};
  const vkey = (v) => `${v.proc}@${v.start.toString(16)}`;
  const tkey = (t) => `${t.pid}:${t.localPort}->${t.remotePort}`;

  /* --- HEADER: one page of self-description. A parser reads the magic and the version
     out of here before anything else, and refuses a file that does not carry them — the
     analogue of Volatility refusing to stack a layer on a file it does not recognise. */
  img.align();
  regionBase.HEADER = img.length;
  img.ascii(S.IMAGE_MAGIC, 8);
  img.u32(S.IMAGE_VERSION);
  img.u32(PAGE);
  img.utf16le('D12LAB-SYNTHETIC-MEMORY-IMAGE', 128);
  img.utf16le('NOT A REAL HOST. NOT A REAL CAPTURE. NOT A REAL USER.', 128);
  img.utf16le('FROZEN CLOCK 2026-03-14T02:17:33Z', 64);
  img.u64(S.FROZEN_EPOCH);
  const E = RECORD.eprocess.at;
  for (const name of REGION_ORDER) img.utf16le(name, 16);
  const regionTableOff = img.length;
  for (const _ of REGION_ORDER) img.u64(0);
  img.u32(REGION_ORDER.length);
  img.u32(S.PROCESSES.length);
  img.u32(S.VADS.length);
  img.u32(S.TCP.length);
  /* Header geometry comes from `spec.mjs` — the same place the reader gets it. Two
     hand-maintained copies of a header layout is exactly how a parser ends up reading a
     stride of 0 and sweeping the whole image, so there is one definition and the writer
     asserts it lands where the spec says it does. */
  const HEADER_FIELDS = S.HEADER;
  if (img.length !== HEADER_FIELDS.strides) throw new Error(`header drift: the stride block starts at ${img.length}, spec says ${HEADER_FIELDS.strides}`);
  img.u32(RECORD.eprocess.stride);
  img.u32(RECORD.tcp.stride);
  img.u32(RECORD.vad.stride);
  img.u32(RECORD.handle.stride);
  if (img.length !== HEADER_FIELDS.procListHead) throw new Error(`header drift: procListHead slot at ${img.length}, spec says ${HEADER_FIELDS.procListHead}`);
  const procListHeadSlot = img.length;
  img.u64(0);
  img.align();

  /* --- STRINGS: every path in the image lives here, UTF-16LE. Reading a process name
     is a pointer chase and a length scan, exactly like PEB->ImagePathName. */
  img.align();
  regionBase.STRINGS = img.length;
  const strOff = new Map();
  const put = (s) => {
    if (strOff.has(s)) return strOff.get(s);
    const off = img.length;
    img.utf16le(s, Math.max(32, (s.length + 1) * 2));
    strOff.set(s, off);
    return off;
  };
  for (const p of S.PROCESSES) { if (p.path) put(p.path); put(p.name); }
  for (const v of S.VADS) if (v.backing) put(v.backing);
  for (const h of S.HANDLES) put(h.name);
  for (const t of S.TCP) put(`${t.local}:${t.localPort}`); // netscan renders endpoints from these
  img.align();

  /* --- CONTENT: the bytes each VAD points at. Built before the VADs so a VAD can carry
     a real content offset instead of a promise to fill it in later. */
  img.align();
  regionBase.CONTENT = img.length;
  const payload = resolvePayload();
  const contentAt = new Map();
  for (const v of S.VADS) {
    const off = img.length;
    const bytes = v.content.kind === 'payload'
      ? payload.bytes
      : v.content.kind === 'peheader'
        ? buildMinimalPe({ marker: 'D12LAB-DATA-BUFFER-NOT-EXECUTABLE', subsystem: 0x0003 })
        : Buffer.alloc(0x400, 0);
    img.bytes(bytes);
    img.align();
    contentAt.set(vkey(v), { off, size: bytes.length });
  }
  img.align();

  /* --- POOL: the EPROCESS blocks and the socket list. Two independent walks, because
     the finding only exists if a list walk and a pool scan are able to disagree. */
  img.align();
  regionBase.POOL = img.length;
  const eproc = new Map();
  for (const p of S.PROCESSES) {
    img.align(RECORD.eprocess.stride);
    const off = img.length;
    eproc.set(p.pid, off);
    img.u32(S.SIG.eprocess);
    img.u32(p.pid);
    img.u32(p.ppid);
    img.u32(p.unlinked ? FLAG_FIXTURE_UNLINKED : 0);
    img.u64(0); // flink
    img.u64(0); // blink
    img.u64(strOff.get(p.name));
    img.u64(p.path ? strOff.get(p.path) : 0);
    img.u64(msToFiletime(S.FROZEN_EPOCH + p.createOffset));
    img.u64(0); // exitTime: still running
    img.skip(RECORD.eprocess.stride - 0x40);
  }
  const tcp = new Map();
  for (const t of S.TCP) {
    img.align(RECORD.tcp.stride);
    const off = img.length;
    tcp.set(tkey(t), off);
    img.u32(S.SIG.tcp);
    img.u32(t.pid);
    img.u32(S.tcpStateIndex(t.state));
    img.u32(ipToU32(t.local));
    img.u16(t.localPort);
    img.u16(0);
    img.u32(ipToU32(t.remote));
    img.u16(t.remotePort);
    img.u16(0);
    img.u64(msToFiletime(S.FROZEN_EPOCH + t.createOffset));
    img.u64(0); // flink
    img.u64(0); // blink
    img.skip(RECORD.tcp.stride - 0x38);
  }
  img.align();

  /* Patch the EPROCESS list. `unlinked` processes are spliced out: their neighbours
     point straight past them. That is what makes a list walk miss a process a pool scan
     can still find, and it is the whole DKOM case. */
  const listOrder = S.PROCESSES.filter((p) => !p.unlinked).map((p) => p.pid);
  for (let i = 0; i < listOrder.length; i++) {
    const cur = eproc.get(listOrder[i]);
    const next = eproc.get(listOrder[(i + 1) % listOrder.length]);
    const prev = eproc.get(listOrder[(i - 1 + listOrder.length) % listOrder.length]);
    img.patchU64(cur + E.flink, next);
    img.patchU64(cur + E.blink, prev);
  }
  img.patchU64(procListHeadSlot, eproc.get(listOrder[0]));
  for (let i = 0; i < S.TCP.length; i++) {
    const cur = tcp.get(tkey(S.TCP[i]));
    const nxt = tcp.get(tkey(S.TCP[(i + 1) % S.TCP.length]));
    const prv = tcp.get(tkey(S.TCP[(i - 1 + S.TCP.length) % S.TCP.length]));
    img.patchU64(cur + RECORD.tcp.at.flink, nxt);
    img.patchU64(cur + RECORD.tcp.at.blink, prv);
  }

  /* --- VADS: one block per region, chained per process. */
  img.align();
  regionBase.VADS = img.length;
  const V = RECORD.vad.at;
  const vad = new Map();
  for (const v of S.VADS) {
    img.align(RECORD.vad.stride);
    const off = img.length;
    vad.set(vkey(v), off);
    const c = contentAt.get(vkey(v));
    img.u32(S.SIG.vad);
    img.u32(v.proc);
    img.u64(BigInt(v.start));
    img.u64(BigInt(v.end));
    img.u32(v.prot);
    img.u32(v.mem);
    img.u64(v.backing ? strOff.get(v.backing) : 0);
    img.u64(c.off);
    img.u32(c.size);
    img.u64(0); // flink
    img.u64(0); // blink
    img.utf16le(v.poolTag, 16);
    img.skip(RECORD.vad.stride - (V.poolTag + 16));
  }
  for (const pid of new Set(S.VADS.map((v) => v.proc))) {
    const mine = S.VADS.filter((v) => v.proc === pid);
    for (let i = 0; i < mine.length; i++) {
      const cur = vad.get(vkey(mine[i]));
      const nxt = vad.get(vkey(mine[(i + 1) % mine.length]));
      const prv = vad.get(vkey(mine[(i - 1 + mine.length) % mine.length]));
      img.patchU64(cur + V.flink, nxt);
      img.patchU64(cur + V.blink, prv);
    }
  }
  img.align();

  /* --- OBJECTS: the handle table blocks. */
  img.align();
  regionBase.OBJECTS = img.length;
  const H = RECORD.handle.at;
  const hnd = new Map();
  for (const h of S.HANDLES) {
    img.align(RECORD.handle.stride);
    const off = img.length;
    hnd.set(h.value, off);
    img.u32(S.SIG.handle);
    img.u32(h.proc);
    img.u32(h.value);
    img.u32(h.access >>> 0);
    img.u64(strOff.get(h.name));
    img.utf16le(h.type, 16);
    img.u32(1);
    img.skip(RECORD.handle.stride - (H.refCount + 4));
  }
  img.align();

  /* --- patch the region base table --- */
  REGION_ORDER.forEach((name, i) => img.patchU64(regionTableOff + i * 8, regionBase[name]));

  const bytes = Buffer.from(img.out());
  return {
    bytes,
    meta: {
      bytes: bytes.length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      regions: regionBase,
      regionOrder: REGION_ORDER,
      procListHead: eproc.get(listOrder[0]),
      headerFields: HEADER_FIELDS,
      ipEncoding: 'IPv4 in network byte order (big-endian), as a real stack stores it',
      eprocessCount: S.PROCESSES.length,
      eprocessInList: listOrder.length,
      recordStrides: Object.fromEntries(Object.entries(RECORD).map(([k, v]) => [k, v.stride])),
      payload: {
        producer: payload.producer,
        origin: payload.origin,
        note: payload.note,
        size: payload.bytes.length,
        sha256: crypto.createHash('sha256').update(payload.bytes).digest('hex'),
      },
    },
  };
}

/* ------------------------------------------------------------------ artefacts */

/* Three independent sources. In the fiction of the lab they are three different
 * acquisition paths — a registry-derived execution log, per-image execution timing, and
 * per-app resource accounting. They are written in three different FORMATS on purpose:
 * if the triangulator only ever needs one parser, it is one source wearing three hats. */
function buildAmcache() {
  const rows = [
    '# Amcache-shaped execution log. D12LAB fixture. NOT a real Amcache hive.',
    '# sha256\tpath\tsize\texec_time_filetime',
  ];
  for (const r of S.AMCACHE_ROWS) {
    const h = crypto.createHash('sha256').update(r.path.toLowerCase()).digest('hex');
    rows.push([h, r.path, String(r.size), String(msToFiletime(S.FROZEN_EPOCH + r.execOffset))].join('\t'));
  }
  return { name: 'Amcache.txt', text: rows.join('\n') + '\n' };
}

function buildSrum() {
  const lines = [
    '# SRUM-shaped resource usage. D12LAB fixture. NOT a real SRUM database.',
    '# app_path\ttime_filetime\tnet_sent\tnet_recv\tcpu_ms',
  ];
  for (const r of S.SRUM_ROWS) {
    lines.push([r.app, String(msToFiletime(S.FROZEN_EPOCH + r.offset)), String(r.netSent), String(r.netRecv), String(r.cpuMs)].join('\t'));
  }
  return { name: 'Srum.txt', text: lines.join('\n') + '\n' };
}

function buildPrefetch() {
  /* A real .pf is a binary MAM container. This fixture uses the same idea — magic,
     version, run count, fixed-width name field, fixed-width run-time table — so a
     parser has to read binary rather than a JSON array. */
  const NAME = 60, TIMES = 8, ENTRIES = 8;
  const out = [];
  for (const e of S.PREFETCH) {
    const b = Buffer.alloc(4 + 4 + 4 + NAME + 4 + TIMES * ENTRIES);
    b.writeUInt32LE(S.SIG.prefetch, 0);
    b.writeUInt32LE(30, 4);
    b.writeUInt32LE(e.runs, 8);
    b.write(e.exe, 12, 'ascii');
    b.writeUInt32LE(ENTRIES, 12 + NAME);
    for (let i = 0; i < ENTRIES; i++) {
      const t = i < e.runs ? msToFiletime(S.FROZEN_EPOCH + (i === 0 ? e.firstOffset : e.lastOffset)) : 0n;
      b.writeBigUInt64LE(t, 16 + NAME + i * TIMES);
    }
    const hash = crypto.createHash('md5').update(e.exe).digest('hex').slice(0, 8).toUpperCase();
    out.push({ name: `${e.exe.replace(/[^A-Z0-9.]/g, '_')}-${hash}.pf`, bytes: b, exe: e.exe, runs: e.runs });
  }
  return out;
}

/* ------------------------------------------------------------------ main */

export function generate(outDir) {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(path.join(outDir, 'artifacts'), { recursive: true });

  const { bytes, meta } = buildImage();
  const imagePath = path.join(outDir, 'd12-lab-image.raw');
  fs.writeFileSync(imagePath, bytes);

  const am = buildAmcache();
  fs.writeFileSync(path.join(outDir, 'artifacts', am.name), am.text, 'utf8');
  const srum = buildSrum();
  fs.writeFileSync(path.join(outDir, 'artifacts', srum.name), srum.text, 'utf8');
  const pf = buildPrefetch();
  for (const f of pf) fs.writeFileSync(path.join(outDir, 'artifacts', f.name), f.bytes);

  const manifest = {
    schema: 'forensics-lab/target@1',
    generated_from: 'forensics-lab/lab/spec.mjs',
    warning: 'SYNTHETIC. Not a real host, not a real capture, not a real user.',
    frozen_epoch_utc: new Date(S.FROZEN_EPOCH).toISOString(),
    image: { file: path.basename(imagePath), ...meta },
    artifacts: { amcache: am.name, prefetch: pf.map((p) => p.name), srum: srum.name },
    sources: {
      MEM: 'the synthetic image (D12IMG): pslist, psscan, malfind, netscan, handlescan',
      AM: 'Amcache-shaped execution log',
      PF: 'Prefetch-shaped .pf run history',
      SRUM: 'SRUM-shaped per-app resource usage',
    },
  };
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return { outDir, imagePath, meta, artifactFiles: fs.readdirSync(path.join(outDir, 'artifacts')).sort() };
}

function main(argv) {
  if (argv.includes('--print-header')) {
    console.log(JSON.stringify(buildImage().meta, null, 2));
    return 0;
  }
  const i = argv.indexOf('--out');
  const outDir = (i >= 0 ? argv[i + 1] : null) || path.join(process.env.TEMP || process.cwd(), 'd12-forensics-lab', 'target');
  const r = generate(outDir);
  console.log(`target      ${r.outDir}`);
  console.log(`image       ${r.meta.bytes} bytes  sha256 ${r.meta.sha256}`);
  console.log(`payload     ${r.meta.payload.producer}  ${r.meta.payload.size} bytes  sha256 ${r.meta.payload.sha256}`);
  console.log(`regions     ${Object.entries(r.meta.regions).map(([k, v]) => `${k}@0x${v.toString(16)}`).join('  ')}`);
  console.log(`processes   ${r.meta.eprocessCount} in pool, ${r.meta.eprocessInList} reachable from the list head`);
  console.log(`artifacts   ${r.artifactFiles.length} files`);
  for (const f of r.artifactFiles) console.log(`            ${f}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
