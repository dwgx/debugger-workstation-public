/* triage.mjs — the Volatility-equivalent plugin set over the synthetic image.
 *
 * This is the instrument. It reads ONLY the image and the artifact files; it has no
 * access to `spec.mjs`'s PROCESSES/VADS/TCP tables and it never reads the fixture's
 * FLAG_FIXTURE_UNLINKED bit. If it could read the spec, the ground-truth comparison in
 * `loop.mjs` would be a tautology, and the whole lab would be a rounding error.
 *
 * Plugins, named after the Volatility 3 plugins whose technique they mirror:
 *   banners      -- refuse a file that is not an image this tool understands
 *   pslist       -- walk the EPROCESS list from its head (finds what is LINKED)
 *   psscan       -- scan the pool for EPROCESS signatures (finds what is PRESENT)
 *   malfind      -- private + executable + PE header, cross-checked against the load list
 *   netscan      -- walk the socket list
 *   handlescan   -- walk the handle blocks
 *
 * Every one of them returns `{ value, tier, source, method, artifact }` so that no
 * claim can leave this file without a provenance tag. That is invariant 1 as code.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { RECORD } from '../lab/mkimage.mjs';
import * as S from '../lab/spec.mjs';

/* The independence groups. Two artefacts in the same group are ONE source, however
 * many files they span. MEM is its own group; AM/PF/SRUM are three distinct acquisition
 * paths in the fiction of the lab and are deliberately NOT collapsed. */
export const SOURCE_GROUPS = { MEM: 'MEM', AM: 'AM', PF: 'PF', SRUM: 'SRUM' };

const STATE_NAMES = S.TCP_STATES;
const PROT_NAMES = ['NOACCESS', 'READONLY', 'READWRITE', 'WRITECOPY', 'EXECUTE', 'EXECUTE_READ', 'EXECUTE_READWRITE', 'EXECUTE_WRITECOPY'];
const MEM_NAMES = ['NONE', 'PRIVATE', 'MAPPED', 'IMAGE'];

/* IPv4 is stored in network byte order, so it renders in reading order. Getting this
   backwards produces an IOC that looks fine and is wrong. */
const ipText = (v) => `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`;
const ftToIso = (ft) => {
  const ms = Number(ft / 10_000n - 116_444_736_000n);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
};

/* Header geometry, imported from the same spec the writer used. The image also publishes
 * the strides it was written with, and `banners()` refuses to continue if they disagree
 * with the record table this parser was built against — a layout change must be a loud
 * failure, not a confidently misparsed table. */
const H = S.HEADER;

/* ------------------------------------------------------------------ the image */

export class LabImage {
  constructor(file) {
    this.file = file;
    this.bytes = fs.readFileSync(file);
    this.sha256 = crypto.createHash('sha256').update(this.bytes).digest('hex');
    this.size = this.bytes.length;
    this.hdr = null;
  }

  /* --- banners: identity + integrity of the container. A forensics tool that will
     analyse an arbitrary file without first saying what the file IS is how analysts end
     up reporting findings from the wrong artefact. Refusing is the correct behaviour. */
  banners() {
    /* The magic is a fixed 8-byte field, NUL-padded. Compare the trimmed text: a
       forensics tool must not reject a valid container over padding. */
    const magic = this.bytes.subarray(0, 8).toString('latin1').replace(/[\0 ]+$/, '');
    const version = this.bytes.readUInt32LE(H.version);
    const page = this.bytes.readUInt32LE(H.pageSize);
    if (magic !== S.IMAGE_MAGIC || version !== S.IMAGE_VERSION) {
      return {
        ok: false,
        error: `not a D12LAB image: magic=${JSON.stringify(magic)} version=${version} (expected ${JSON.stringify(S.IMAGE_MAGIC)} v${S.IMAGE_VERSION})`,
      };
    }
    const regionOrder = [];
    for (let i = 0; i < S.REGION_ORDER.length; i++) regionOrder.push(this.readUtf16(H.regionNames + i * 16, 16));
    const count = this.bytes.readUInt32LE(H.regionCount);
    if (count !== S.REGION_ORDER.length) throw new Error(`header region count ${count} != ${S.REGION_ORDER.length}`);
    const regions = {};
    for (let i = 0; i < count; i++) regions[regionOrder[i]] = Number(this.bytes.readBigUInt64LE(H.regionTable + i * 8));
    const strides = {
      eprocess: this.bytes.readUInt32LE(H.strides),
      tcp: this.bytes.readUInt32LE(H.strides + 4),
      vad: this.bytes.readUInt32LE(H.strides + 8),
      handle: this.bytes.readUInt32LE(H.strides + 12),
    };
    /* The image publishes the strides the writer used. If they disagree with the
       record table this parser was built against, every sweep below is wrong, so refuse
       rather than produce a confident, misparsed table. */
    for (const [k, v] of Object.entries(strides)) {
      if (v !== RECORD[k].stride) {
        return { ok: false, value: { strides }, error: `image was written with ${k} stride ${v}, this parser expects ${RECORD[k].stride}` };
      }
    }
    for (const [name, off] of Object.entries(regions)) {
      if (!this.inBounds(off, 0)) return { ok: false, value: { regions }, error: `region ${name} points outside the image (0x${off.toString(16)} of ${this.size})` };
    }
    this.hdr = {
      magic, version, page, regions, regionOrder, strides,
      label: this.readUtf16(H.label, 128),
      warning: this.readUtf16(H.warning, 128),
      clock: this.readUtf16(H.clock, 64),
      procListHead: Number(this.bytes.readBigUInt64LE(H.procListHead)),
    };
    return {
      ok: true,
      value: {
        magic, version, page, regions, strides, sha256: this.sha256, size: this.size,
        label: this.hdr.label, warning: this.hdr.warning, clock: this.hdr.clock,
      },
    };
  }

  /* --- primitive readers. Every one bounds-checks: a parser that reads past the end of
     an image and reports a plausible number is worse than one that refuses. */
  inBounds(off, len = 1) { return Number.isSafeInteger(off) && off >= 0 && off + len <= this.size; }
  u32(off) { if (!this.inBounds(off, 4)) return null; return this.bytes.readUInt32LE(off); }
  u64(off) { if (!this.inBounds(off, 8)) return null; return Number(this.bytes.readBigUInt64LE(off)); }
  u16(off) { if (!this.inBounds(off, 2)) return null; return this.bytes.readUInt16LE(off); }
  readUtf16(off, maxBytes = 512) {
    if (!this.inBounds(off, 2)) return null;
    const limit = Math.min(off + maxBytes, this.size - 1);
    let end = off;
    while (end + 1 < limit && !(this.bytes.readUInt16LE(end) === 0)) end += 2;
    return this.bytes.subarray(off, end).toString('utf16le');
  }
  readString(off, maxBytes = 512) {
    if (!off || !this.inBounds(off, 1)) return null;
    const limit = Math.min(off + maxBytes, this.size);
    let end = off;
    while (end < limit && this.bytes[end] !== 0) end++;
    return this.bytes.subarray(off, end).toString('latin1');
  }
  slice(off, len) { return this.inBounds(off, len) ? this.bytes.subarray(off, off + len) : null; }
}

/* ------------------------------------------------------------------ pslist / psscan */

function decodeEproc(img, off) {
  const A = RECORD.eprocess.at;
  return {
    offset: off,
    pid: img.u32(off + A.pid),
    ppid: img.u32(off + A.ppid),
    flink: img.u64(off + A.flink),
    blink: img.u64(off + A.blink),
    name: img.readUtf16(img.u64(off + A.nameOff)),
    path: img.readUtf16(img.u64(off + A.pathOff)),
    createTime: ftToIso(img.bytes.readBigUInt64LE(off + A.createFT)),
    exitTime: ftToIso(img.bytes.readBigUInt64LE(off + A.exitFT)),
  };
}

/* pslist: follow flink from the head. Bounded by both a record cap and a visited set —
 * a corrupt or hostile list must terminate, and the cap is reported when it bites. */
export function pslist(img) {
  if (!img.hdr) throw new Error('pslist: banners() must run first');
  const A = RECORD.eprocess.at;
  const MAX = 4096;
  const out = [];
  const seen = new Set();
  let cur = img.hdr.procListHead;
  let truncated = false;
  while (cur && out.length < MAX) {
    if (!img.inBounds(cur, RECORD.eprocess.stride) || img.u32(cur) !== S.SIG.eprocess) { truncated = true; break; }
    if (seen.has(cur)) { truncated = true; break; }
    seen.add(cur);
    out.push(decodeEproc(img, cur));
    const next = img.u64(cur + A.flink);
    if (!next) break;
    cur = next;
  }
  return {
    plugin: 'pslist',
    source: 'MEM',
    method: 'follow EPROCESS.ActiveProcessLinks.flink from the list head',
    tier: 'OBSERVED',
    truncated,
    count: out.length,
    processes: out,
  };
}

/* psscan: sweep the pool region for the EPROCESS signature. Independent of any list
 * pointer, which is the entire reason to run it: DKOM hides a process from the list
 * walk and cannot hide the pool allocation. */
export function psscan(img) {
  if (!img.hdr) throw new Error('psscan: banners() must run first');
  const start = img.hdr.regions.POOL ?? 0;
  const end = start + (img.hdr.regions.VADS - start || img.size - start);
  const stride = RECORD.eprocess.stride;
  const out = [];
  for (let off = start; off + 4 <= end && off + stride <= img.size; off += 4) {
    if (img.u32(off) !== S.SIG.eprocess) continue;
    const rec = decodeEproc(img, off);
    if (rec.pid === null || rec.pid === undefined) continue;
    out.push(rec);
  }
  return {
    plugin: 'psscan',
    source: 'MEM',
    method: 'sweep the pool region for the EPROCESS signature at a 4-byte stride',
    tier: 'OBSERVED',
    count: out.length,
    processes: out,
  };
}

/* ------------------------------------------------------------------ malfind */

/* The PE test, stated as a function so it can be read and argued with: DOS magic, the
 * e_lfanew pointer, a PE signature at the pointed-to offset, and a plausible machine
 * type. A "MZ" two-byte match is NOT a PE and this lab refuses to call one. */
export function looksLikePe(buf) {
  if (!buf || buf.length < 0x40) return { pe: false, why: 'shorter than a DOS header' };
  if (buf.readUInt16LE(0) !== 0x5a4d) return { pe: false, why: 'no MZ' };
  const lfanew = buf.readUInt32LE(0x3c);
  if (lfanew < 0x40 || lfanew + 24 > buf.length) return { pe: false, why: `e_lfanew ${lfanew} out of range` };
  if (buf.readUInt32LE(lfanew) !== 0x0000_4550) return { pe: false, why: 'no PE signature at e_lfanew' };
  const machine = buf.readUInt16LE(lfanew + 4);
  if (machine !== 0x014c && machine !== 0x8664 && machine !== 0xaa64) return { pe: false, why: `unknown machine 0x${machine.toString(16)}` };
  const magic = buf.readUInt16LE(lfanew + 24);
  const kind = magic === 0x20b ? 'PE32+' : magic === 0x10b ? 'PE32' : magic === 0x107 ? 'ROM' : 'unknown';
  if (kind === 'unknown') return { pe: false, why: `unknown optional-header magic 0x${magic.toString(16)}` };
  return { pe: true, kind, machine: `0x${machine.toString(16)}`, lfanew, why: `MZ + PE\\0\\0 at 0x${lfanew.toString(16)}, ${kind}` };
}

/* The load list. In a real image this is the PEB->Ldr module list; here the module set
 * is the set of VADs whose backing file is recorded. It exists so malfind can ask the
 * question that separates "injected" from "loaded": does anything on record explain
 * this region? */
function loadListFor(img, pid) {
  return img.vadsFor(pid).filter((v) => v.backing).map((v) => v.backing);
}

export function malfind(img) {
  if (!img.hdr) throw new Error('malfind: banners() must run first');
  const out = [];
  for (const pid of img.poolPids()) {
    const loads = loadListFor(img, pid);
    for (const v of img.vadsFor(pid)) {
      const executable = (v.prot & 0x4) !== 0;
      const privateMem = v.mem === S.MEM.PRIVATE;
      const head = img.slice(v.content, 0x400);
      const pe = looksLikePe(head);
      const explained = v.backing !== null;
      if (!executable && !privateMem) continue;          // not a candidate at all
      if (!pe.pe && !privateMem) continue;                 // private but no PE: not injection
      if (!pe.pe) continue;
      out.push({
        pid,
        start: v.start, end: v.end,
        prot: PROT_NAMES[v.prot] ?? `0x${v.prot.toString(16)}`,
        executable, private: privateMem,
        mem: MEM_NAMES[v.mem] ?? String(v.mem),
        backing: v.backing,
        loadList: loads,
        /* The decision. A PE header in a private region is a SIGNAL. It becomes a
           FINDING only when the region is executable AND nothing on record backs it.
           Both halves are needed: drop either and the csrss.exe decoy gets reported. */
        suspicious: executable && privateMem && !explained,
        reason: !explained
          ? `private ${PROT_NAMES[v.prot]} region holds a ${pe.kind} and no load-list module backs it`
          : `region is backed by ${v.backing}, which is on the process load list`,
        pe: { kind: pe.kind, machine: pe.machine, lfanew: pe.lfanew },
        contentOffset: v.content,
        contentSize: v.size,
        tier: 'OBSERVED',
        source: 'MEM',
      });
    }
  }
  return {
    plugin: 'malfind',
    source: 'MEM',
    method: 'private + executable + PE header, minus regions a load-list module explains',
    tier: 'OBSERVED',
    candidates: out,
    suspicious: out.filter((c) => c.suspicious),
  };
}

/* ------------------------------------------------------------------ netscan */

export function netscan(img) {
  if (!img.hdr) throw new Error('netscan: banners() must run first');
  const A = RECORD.tcp.at;
  const out = [];
  const seen = new Set();
  let cur = img.hdr.regions.POOL;
  /* The socket chain is located by signature, then walked. Walking first and scanning
     second is what lets a truncated chain hide a connection — so we sweep, then walk. */
  const start = img.hdr.regions.POOL;
  const limit = img.hdr.regions.VADS;
  for (let off = start; off + 4 <= limit && off + RECORD.tcp.stride <= img.size; off += 4) {
    if (img.u32(off) !== S.SIG.tcp) continue;
    const state = img.u32(off + A.state);
    out.push({
      offset: off,
      pid: img.u32(off + A.pid),
      state: STATE_NAMES[state] ?? `state-${state}`,
      local: `${ipText(img.u32(off + A.local))}:${img.u16(off + A.lport)}`,
      remote: `${ipText(img.u32(off + A.remote))}:${img.u16(off + A.rport)}`,
      remoteAddr: ipText(img.u32(off + A.remote)),
      remotePort: img.u16(off + A.rport),
      createTime: ftToIso(img.bytes.readBigUInt64LE(off + A.createFT)),
      flink: img.u64(off + A.flink),
    });
  }
  /* the walk, reported separately so a broken chain is visible rather than silent */
  let walk = 0;
  cur = out.length ? out[0].flink : 0;
  while (cur && walk < 4096 && !seen.has(cur)) { seen.add(cur); walk++; cur = img.u64(cur + A.flink); }
  return {
    plugin: 'netscan',
    source: 'MEM',
    method: 'sweep the pool for socket records, then walk the flink chain',
    tier: 'OBSERVED',
    chainWalkLength: walk,
    chainIntact: walk === out.length,
    count: out.length,
    connections: out,
  };
}

/* ------------------------------------------------------------------ handlescan */

export function handlescan(img) {
  if (!img.hdr) throw new Error('handlescan: banners() must run first');
  const A = RECORD.handle.at;
  const out = [];
  const start = img.hdr.regions.OBJECTS;
  const limit = start + (img.hdr.regions.POOL === 0 ? 0 : 0) || img.size;
  for (let off = start; off + 4 <= img.size && off + RECORD.handle.stride <= img.size; off += 4) {
    if (img.u32(off) !== S.SIG.handle) continue;
    out.push({
      offset: off,
      pid: img.u32(off + A.proc),
      value: `0x${img.u32(off + A.value).toString(16)}`,
      access: `0x${(img.u32(off + A.access) >>> 0).toString(16).padStart(8, '0')}`,
      type: img.readUtf16(off + A.type, 32),
      name: img.readUtf16(img.u64(off + A.nameOff)),
    });
  }
  return { plugin: 'handlescan', source: 'MEM', method: 'sweep the object region for handle records', tier: 'OBSERVED', count: out.length, handles: out };
}

/* ------------------------------------------------------------------ VAD access */

/* VADs are chained per process, but a tool that only ever walks a chain cannot find an
   orphan. The region is swept by signature and then walked, and both answers are kept. */
LabImage.prototype.vadsFor = function vadsFor(pid) {
  if (!this._vadCache) this._vadCache = null;
  if (!this._vadCache) {
    const A = RECORD.vad.at;
    const all = [];
    for (let off = this.hdr.regions.VADS; off + 4 <= this.size && off + RECORD.vad.stride <= this.size; off += 4) {
      if (this.u32(off) !== S.SIG.vad) continue;
      all.push({
        offset: off,
        pid: this.u32(off + A.pid),
        start: this.u64(off + A.start),
        end: this.u64(off + A.end),
        prot: this.u32(off + A.prot),
        mem: this.u32(off + A.mem),
        backingOff: this.u64(off + A.backing),
        backing: this.u64(off + A.backing) ? this.readUtf16(this.u64(off + A.backing)) : null,
        content: this.u64(off + A.content),
        size: this.u32(off + A.size),
        flink: this.u64(off + A.flink),
        poolTag: this.readUtf16(off + A.poolTag, 16),
      });
    }
    this._vadCache = all;
  }
  return this._vadCache.filter((v) => v.pid === pid);
};

LabImage.prototype.poolPids = function poolPids() {
  if (this._poolPids) return this._poolPids;
  const seen = [];
  for (let off = this.hdr.regions.POOL; off + 4 <= this.size && off + RECORD.eprocess.stride <= this.size; off += 4) {
    if (this.u32(off) !== S.SIG.eprocess) continue;
    const pid = this.u32(off + RECORD.eprocess.at.pid);
    if (pid !== null) seen.push(pid);
  }
  this._poolPids = [...new Set(seen)].sort((a, b) => a - b);
  return this._poolPids;
};

/* ------------------------------------------------------------------ artifacts */

/* Each artifact gets its OWN parser, reading its OWN format. A single generic reader
   would be one source wearing three hats, which is the exact failure this lab exists
   to make visible. */

export function parseAmcache(file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#'));
  const rows = lines.map((l) => {
    const [sha256, path, size, ft] = l.split('\t');
    return { sha256, path, size: Number(size), execTime: ftToIso(BigInt(ft)) };
  });
  return { source: 'AM', format: 'tsv, sha256/path/size/filetime', file: path.basename(file), count: rows.length, rows };
}

export function parseSrum(file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#'));
  const rows = lines.map((l) => {
    const [app, ft, netSent, netRecv, cpuMs] = l.split('\t');
    return { app, time: ftToIso(BigInt(ft)), netSent: Number(netSent), netRecv: Number(netRecv), cpuMs: Number(cpuMs) };
  });
  return { source: 'SRUM', format: 'tsv, app/filetime/net_sent/net_recv/cpu_ms', file: path.basename(file), count: rows.length, rows };
}

/* The record layout is fixed-offset, so every field is a read at a constant offset and
 * every one of those offsets is a place the file can stop short. `Math.min(n, 64)` caps
 * the COUNT but not the FILE: a 20-byte file with the right 4-byte magic passed the old
 * `length < 16` guard and then died in `readUInt32LE(72)` with a RangeError. Found by
 * fuzz-lab (crash `forensic-pf-reference-*`), and the failure mode was the wrong kind:
 * an uncaught exception, not a refusal.
 *
 * So the guard is derived from the layout rather than guessed, and truncation is
 * REPORTED rather than thrown -- which is the same rule the rest of this file follows:
 * a corrupt artefact must produce a finding about the artefact, never a dead tool. */
const PF_NAME = 60, PF_TIMES = 8, PF_MAX_ENTRIES = 64;
const PF_COUNT_OFF = 12 + PF_NAME;          // 72
const PF_TABLE_OFF = 16 + PF_NAME;          // 76

export function parsePrefetch(file) {
  const b = fs.readFileSync(file);
  const base = { source: 'PF', format: 'binary MAM-like', file: path.basename(file) };
  if (b.length < 16 || b.readUInt32LE(0) !== S.SIG.prefetch) {
    return { ...base, error: 'not a prefetch record', exe: null, runs: 0, runTimes: [] };
  }
  const version = b.readUInt32LE(4);
  const runs = b.readUInt32LE(8);
  const exe = b.subarray(12, 12 + PF_NAME).toString('ascii').replace(/\0.*$/, '');

  /* The name field is NUL-padded to 60 bytes, so a short read truncates the name rather
   * than failing -- correct, and worth saying, because it is the one field whose bounds
   * are handled by `subarray` clamping. */
  const truncated = [];
  if (b.length < PF_COUNT_OFF + 4) {
    truncated.push(`file is ${b.length} bytes: the entry count at ${PF_COUNT_OFF} is absent`);
    return { ...base, version, exe, runs, runTimes: [], truncated: true, truncation: truncated.join('; ') };
  }
  const n = b.readUInt32LE(PF_COUNT_OFF);

  /* The table is what is actually missing in a truncated file, so report how much of it
   * is real. `available` is derived from the file length, not from `n`, which is the
   * field an attacker controls. */
  const available = Math.max(0, Math.floor((b.length - PF_TABLE_OFF) / PF_TIMES));
  const wanted = Math.min(n, PF_MAX_ENTRIES);
  const usable = Math.min(wanted, available);
  if (usable < wanted) {
    truncated.push(`entry table declares ${wanted} slots but only ${usable} fit in ${b.length} bytes`);
  }
  const runTimes = [];
  for (let i = 0; i < usable; i++) {
    const ft = b.readBigUInt64LE(PF_TABLE_OFF + i * PF_TIMES);
    if (ft) runTimes.push(ftToIso(ft));
  }
  return {
    ...base,
    format: 'binary MAM-like (magic, version, runCount, 60B name, 8x8B run table)',
    version, exe, runs, runTimes,
    entriesDeclared: n,
    truncated: truncated.length > 0,
    truncation: truncated.join('; ') || null,
  };
}

/* ------------------------------------------------------------------ run */

export function triage(targetDir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(targetDir, 'manifest.json'), 'utf8'));
  const imageFile = path.join(targetDir, manifest.image.file);
  const img = new LabImage(imageFile);
  const banner = img.banners();
  if (!banner.ok) return { ok: false, error: banner.error, banner: banner.value };

  const artDir = path.join(targetDir, 'artifacts');
  const pfFiles = manifest.artifacts.prefetch.map((f) => parsePrefetch(path.join(artDir, f)));

  return {
    schema: 'forensics-lab/triage@1',
    target: {
      image: manifest.image.file,
      sha256: img.sha256,
      size: img.size,
      warning: manifest.warning,
      frozen_epoch_utc: manifest.frozen_epoch_utc,
    },
    plugins: {
      banners: { ...banner.value, tier: 'OBSERVED', source: 'MEM' },
      pslist: pslist(img),
      psscan: psscan(img),
      malfind: malfind(img),
      netscan: netscan(img),
      handlescan: handlescan(img),
    },
    artifacts: {
      amcache: parseAmcache(path.join(artDir, manifest.artifacts.amcache)),
      prefetch: pfFiles,
      srum: parseSrum(path.join(artDir, manifest.artifacts.srum)),
    },
    crossChecks: {
      /* pslist and psscan disagreeing is a FINDING, not a glitch. Stated here as data;
         `analyze.mjs` is what turns it into a confidence tier. */
      inListNotInPool: [],
      inPoolNotInList: [],
    },
  };
}

/* The cross-check, computed once, from the two independent walks. */
export function crossView(t) {
  const listPids = new Set(t.plugins.pslist.processes.map((p) => p.pid));
  const poolPids = new Set(t.plugins.psscan.processes.map((p) => p.pid));
  const inPoolNotInList = [...poolPids].filter((p) => !listPids.has(p));
  const inListNotInPool = [...listPids].filter((p) => !poolPids.has(p));
  const byPid = new Map(t.plugins.psscan.processes.map((p) => [p.pid, p]));
  t.crossChecks = {
    inListNotInPool,
    inPoolNotInList: inPoolNotInList.map((pid) => {
      const rec = byPid.get(pid);
      return { pid, name: rec.name, path: rec.path, createTime: rec.createTime, interpretation: 'resident in the pool but not reachable from the list head' };
    }),
  };
  return t;
}

export { PROT_NAMES, MEM_NAMES, STATE_NAMES, ipText, ftToIso };
