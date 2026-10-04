#!/usr/bin/env node
/* negative-gate.mjs — NEGATIVE CONTROL for the capability `fuzz.differential.parse`.
 *
 * WHAT THIS GATES. `loop.mjs` proves that a campaign can be *run*: seeds are stable,
 * inputs are executed under a ceiling, the flawed twins in `lab/targets.mjs` are caught.
 * What that cannot tell you is whether the oracle is load-bearing. A crash counter that
 * never fires reads exactly like a robust parser, and the registry already recorded the
 * failure mode on this very capability — see the probe's `load_sensitivity_note`: under
 * CPU contention the pcap twin "SURVIVED" and the run failed, which is honest but is not
 * the same as the twin being detectable in principle.
 *
 * THE CLAIM BEING TESTED. `fuzz.differential.parse` is a differential oracle: it compares
 * two implementations of the same parser and treats a disagreement as the finding. For an
 * oracle that claim has exactly one falsifiable form:
 *
 *     remove ONE guard from the parser -> the parser must behave DIFFERENTLY
 *
 * If a mutant behaves identically to the original, the guard it lost was not protecting
 * anything, and every "the oracle found it" claim for that guard was luck. So this gate
 * removes one guard at a time from the real production parser and requires a divergence.
 *
 * EXIT POLARITY, and it is deliberately the non-obvious one.
 *
 *     exit 1 = every mutant was caught. THE CONTROL WORKING. This is the registry's
 *              `expect_exit: 1` and rule R5's requirement, because a control that must
 *              exit 0 proves nothing: an instrument that had stopped enforcing entirely
 *              would also exit 0 and the harness would read that as a pass.
 *     exit 0 = at least one mutant survived, or the gate could not certify its own
 *              instrument. A surviving twin is a real defect and this is the value that
 *              makes the harness report DRIFT instead of a pass.
 *
 * WHY THE TWINS ARE GENERATED, NOT COPIED. The mutants are built by slicing
 * `lab/pcap-reader.mjs` and deleting one brace-matched `if` block from the real
 * `readPcapFile` source text. That is the whole design, for two reasons:
 *
 *   1. "exactly one guard removed" becomes a property of the construction rather than a
 *      claim in a comment. A hand-copied twin drifts from the parser the moment someone
 *      edits the parser, and a twin that no longer matches its original cannot fail for
 *      the reason it was written.
 *   2. It tests the parser this repository actually ships, not a transcription of it.
 *
 * A twin that changes behaviour for some *other* reason is worthless, so every mutant is
 * checked against an input that is proven — from the REFERENCE's own output — to exercise
 * the guard being removed. `p11-overrun-second-record` exists because the pcap overrun
 * guard only fires on the second record; fed the first-record case it would be measuring
 * the wrong guard.
 *
 * THE SILENT MUTANTS, and why they are the interesting ones. Four of the seven guards
 * removed below produce a twin that *returns a value*. Nothing throws, nothing hangs, and
 * the returned object is well-typed. G7 is the registry's own example and it is worth
 * restating exactly, because the whole argument for a differential oracle over a crash
 * counter is in this one line:
 *
 *     Buffer.prototype.subarray CLAMPS. Read a frame whose declared length runs off the
 *     end of the file and `subarray(off+16, off+16+captured)` hands back the short tail
 *     without an error, so the twin emits a packet whose `capturedLength` is the number
 *     the file *claimed* while its `data` holds the bytes that actually exist. A fuzzer
 *     counting crashes sees nothing. An analyst reading the report believes they hold a
 *     frame that is not there.
 *
 * A crash announces itself; a lie does not. That is why the gate classifies each mutant
 * LOUD (an undeclared throw, or no return at all — visible without an oracle) or SILENT
 * (a refusal for the wrong reason, or a plausible wrong value — visible only by
 * comparison), and prints which.
 *
 * ONE THING THIS GATE GOT WRONG THE FIRST TIME, recorded because the mistake is easy and
 * the correction is not obvious. G4 removes the record-count cap, and the first draft of
 * this file claimed that mutant HANGS — the reader's own comment calls the cap's absence a
 * "2-billion-iteration loop", so that is what a reader expects. It does not hang:
 * `off += RECORD_HEADER + captured` advances by at least 16 whatever the attacker sets, so
 * the loop always terminates. MAX_RECORDS bounds WORK, not termination, and removing it
 * costs a file with 200001 records the reference refuses at record 200000 while the twin
 * quietly materialises all 200001 packets. That is a smaller and duller defect than a hang
 * and it is the real one; the gate reports what happened rather than what the comment
 * promised.
 *
 * WHY EACH MUTANT RUNS IN A CHILD PROCESS ANYWAY. A guard this gate removes may bound time
 * or memory rather than a value, and a mutant that stops returning cannot be caught from
 * inside the process that is trying to report it. The parent therefore runs one child per
 * mutant under a wall clock and treats a timeout as the finding, which is how
 * `lab/worker.mjs` bounds a single fuzz input. Nothing in the current mutant set needs it,
 * and that is worth saying: the path exists because the alternative is a gate that hangs
 * the moment the parser is edited into something that can. Children write observations
 * synchronously to fd 1, so a mutant that stops returning still yields everything it
 * managed to produce first.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { readPcapFile } from '../lab/pcap-reader.mjs';

const SELF = fileURLToPath(import.meta.url);
const HERE = path.dirname(SELF);
const READER = path.join(HERE, '..', 'lab', 'pcap-reader.mjs');

/* ARGUMENT REFUSAL. Exit 2, deliberately DISTINCT from the control's own 1.
 *
 * Measured 2026-10-05: `--bogus` produced output byte-identical to the no-argument run and exited
 * 1 — the same answer as "all seven mutants were caught". A gate that cannot tell a stray
 * argument from a clean refusal is not measuring the thing it claims to.
 *
 * This is the third gate today that shipped without one; the forensics-lab gate had it added
 * after I ran it with a stray argument and got byte-identical output. The tell is always the
 * same — a control exercised in ONE direction only. It refuses by construction, so the refuse
 * direction is the one everybody tests.
 *
 * 1 = the control's verdict (every flawed twin caught). 2 = I could not measure, or you handed me
 * something I will not quietly ignore. Collapsing them would let an unmeasurable gate read as a
 * passing one.
 */
const ALLOWED = new Set([]);   // no arguments are honoured; declared empty rather than omitted
const STRAY = process.argv.slice(2).filter((a) => !ALLOWED.has(a));
if (STRAY.length) {
  console.error(`negative-gate.mjs: refusing argument(s) it would otherwise IGNORE: ${STRAY.join(' ')}`);
  console.error('  This gate takes no arguments. The mutants are GENERATED from the shipped parser,');
  console.error('  so there is no --target to aim and nothing here was meant to be aimed.');
  process.exit(2);
}

/** Wall clock for one mutant child. Long enough that the 3.2 MB record bomb reaches the
 *  reference's 200000-record cap in well under a second, short enough that this stays a
 *  gate. loop.mjs needs 400 s because it spawns 480 processes across four targets; this one
 *  spawns 8 and finishes in a second or two, which is the budget the brief asks for. */
const HANG_MS = 2500;

/** Raised by the construction helpers. Never caught inside a mutant child: a gate that
 *  cannot build its mutant must report that, not quietly count a divergence. */
class GateError extends Error {}

/* ============================================================ 1. slicing the real parser */

/**
 * Pull the parser and its dependencies out of `lab/pcap-reader.mjs` as TEXT, so a mutant
 * can be the shipped source minus one block rather than a hand-written imitation.
 *
 * The prelude is everything between `export class PcapFormatError` and the parser: the
 * error class, the two header sizes, the magic table, the linktype names and the two caps.
 * The body is everything from `export function readPcapFile` up to the twin banner — which
 * stops the slice from swallowing the existing hand-written `readPcapFileFlawed`.
 */
function extractParser() {
  const src = fs.readFileSync(READER, 'utf8');
  const preludeStart = src.indexOf('export class PcapFormatError');
  const bodyStart = src.indexOf('export function readPcapFile(buf) {');
  const bodyEnd = src.search(/\/\*\s*-+\s*the twin\s*\*\//);
  if (preludeStart < 0 || bodyStart < 0 || bodyEnd < 0 || bodyEnd < bodyStart) {
    throw new GateError(
      `cannot locate the parser in ${path.basename(READER)}: prelude@${preludeStart} ` +
      `body@${bodyStart} end@${bodyEnd}. The gate is anchored to this file's shape; if the ` +
      'reader was restructured, re-anchor it rather than deleting the check.');
  }
  const prelude = src.slice(preludeStart, bodyStart).replace(/^export /m, '');
  const body = src.slice(bodyStart, bodyEnd).replace('export function readPcapFile', 'function readPcapFile');
  return { prelude, body };
}

/** Net brace delta for one line, skipping quoted spans and `//`. Template literals count
 *  as quoted: `${...}` inside them is balanced, so skipping is both simpler and exact for
 *  the block shapes used here (`throw new PcapFormatError(\`... ${x} ...\`)`). */
function braceDelta(line) {
  let d = 0;
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '\\') { i++; continue; }
      if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '/' && line[i + 1] === '/') break;
    if (c === '{') d++;
    else if (c === '}') d--;
  }
  return d;
}

/**
 * Delete exactly one guard: the `if` block containing `guard.find`.
 *
 * `find` must occur exactly once in the parser, or the guard is ambiguous and the gate
 * refuses rather than guessing which one an analyst meant. `backTo` matches the opening
 * line, so a marker inside a nested statement still removes the guard and nothing else.
 */
function dropGuardBlock(body, guard) {
  const lines = body.split('\n');
  const hits = [];
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(guard.find)) hits.push(i);
  if (hits.length === 0) throw new GateError(`guard marker not present in the parser: ${JSON.stringify(guard.find)}`);
  if (hits.length > 1) throw new GateError(`guard marker is ambiguous, ${hits.length} occurrences: ${JSON.stringify(guard.find)}`);

  let start = -1;
  for (let i = hits[0]; i >= 0; i--) {
    if (guard.backTo.test(lines[i])) { start = i; break; }
  }
  if (start < 0) throw new GateError(`no guard header matching ${guard.backTo} above ${JSON.stringify(guard.find)}`);

  let depth = 0;
  let end = -1;
  for (let i = start; i < lines.length && end < 0; i++) {
    depth += braceDelta(lines[i]);
    if (depth === 0) end = i;
  }
  if (end < 0) throw new GateError(`guard opened at line ${start + 1} never closes; the reader is not shaped as this gate expects`);

  return {
    source: [...lines.slice(0, start), ...lines.slice(end + 1)].join('\n'),
    removed: lines.slice(start, end + 1),
  };
}

/* ==================================================================== 2. the feed corpus */

/**
 * Build a pcap byte string. Written rather than taken from the corpus builder because
 * every probe here has to hit one specific guard, and a fuzz seed hits guards by accident.
 */
function buildPcap({ major = 2, minor = 4, snaplen = 65535, linktype = 1, records = [], tail = null } = {}) {
  const w16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
  const w32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
  const parts = [w32(0xa1b2c3d4), w16(major), w16(minor), w32(0), w32(0), w32(snaplen), w32(linktype)];
  for (const r of records) {
    const data = r.data || Buffer.alloc(0);
    parts.push(w32(r.tsSec || 0), w32(r.tsFrac || 0), w32(r.captured ?? data.length), w32(r.original ?? data.length));
    if (data.length) parts.push(data);
    if (r.padTo) parts.push(Buffer.alloc(Math.max(0, r.padTo - data.length)));
  }
  if (tail) parts.push(tail);
  return Buffer.concat(parts);
}

/** The record-count bomb: MAX_RECORDS is 200000 and every zero header advances `off` by
 *  16, so reaching it needs 200001 of them. Built with `alloc` rather than 200001-way
 *  `Buffer.concat`, which would be the slowest line in the gate. */
function recordBomb(count) {
  const b = Buffer.alloc(24 + count * 16);   // every record header stays zero: captured = 0
  b.writeUInt32LE(0xa1b2c3d4, 0);
  b.writeUInt16LE(2, 4);
  b.writeUInt16LE(4, 6);
  b.writeUInt32LE(65535, 16);
  b.writeUInt32LE(1, 20);
  return b;
}

/** A frame body is just bytes; the reader never looks inside one, and that is the point. */
const FILL = (n, byte = 0x41) => Buffer.alloc(n, byte);

/** A 12-byte file that nonetheless opens with a valid magic and a valid version, so a
 *  parser that skips the length guard gets as far as reading snaplen at offset 16 — which
 *  is outside a 12-byte buffer. That is the mistake being modelled: the guard is what
 *  turns "read a field that is not there" into a refusal. */
const SHORT_FILE = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

const PROBES = [
  {
    id: 'p1-wellformed',
    note: 'two intact Ethernet frames — the input where nothing may differ',
    buf: buildPcap({ records: [{ data: FILL(60), tsSec: 1700000000, tsFrac: 123456 }, { data: FILL(20), tsSec: 1700000001, tsFrac: 999 }] }),
  },
  {
    id: 'p2-short-file',
    note: '12 bytes, valid magic, valid version — shorter than the 24-byte global header',
    buf: SHORT_FILE,
  },
  {
    id: 'p3-not-pcap',
    note: '64 bytes of 0x41 — a file whose magic is not one of the four',
    buf: FILL(64, 0x41),
  },
  {
    id: 'p4-version-9',
    note: 'valid magic, versionMajor 9 — a major version this reader does not implement',
    buf: buildPcap({ major: 9, minor: 0 }),
  },
  {
    id: 'p6-dangling-record-header',
    note: 'global header plus 9 bytes: a record header that runs off the end',
    buf: buildPcap({ tail: Buffer.alloc(9, 0x00) }),
  },
  {
    id: 'p7-oversize-capture',
    note: 'one record declaring 512 MiB of frame and supplying none of it',
    buf: buildPcap({ records: [{ captured: 0x20000000, original: 0x20000000 }] }),
  },
  {
    id: 'p8-overrun-first-record',
    note: 'first record declares 9000 captured bytes and carries 100',
    buf: buildPcap({ records: [{ captured: 9000, data: FILL(100) }] }),
  },
  {
    id: 'p9-dangling-second-header',
    note: 'one good record, then 6 bytes: truncation reached mid-stream',
    buf: buildPcap({ records: [{ data: FILL(20) }], tail: Buffer.alloc(6, 0x00) }),
  },
  {
    id: 'p11-overrun-second-record',
    note: 'one good record, then a record declaring 9000 captured bytes and carrying 100',
    buf: buildPcap({ records: [{ data: FILL(60) }, { captured: 9000, data: FILL(100) }] }),
  },
  {
    id: 'p5-record-bomb',
    note: '200001 zero-length records — more than MAX_RECORDS permits',
    buf: recordBomb(200_001),
  },
];

/** Order matters once, and only because a mutant may hang: every probe a mutant can
 *  complete is recorded before the bomb, so a hang costs one observation and not ten. */
const PROBE_ORDER = ['p1-wellformed', 'p2-short-file', 'p3-not-pcap', 'p4-version-9',
  'p6-dangling-record-header', 'p7-oversize-capture', 'p8-overrun-first-record',
  'p9-dangling-second-header', 'p11-overrun-second-record', 'p5-record-bomb'];

/* ============================================================ 3. the guards under test */

/** A refusal the reference made in its own words. */
const refusedWith = (re) => (obs) => obs.kind === 'throw' && obs.name === 'PcapFormatError' && re.test(obs.message);
/** Truncation reported by the reference, with the packet count the guard stopped at. */
const truncatedAt = (count) => (obs) => obs.kind === 'value' && obs.truncated === true && obs.count === count;

const GUARDS = [
  {
    id: 'G1',
    name: 'file-long-enough-for-a-global-header',
    find: 'shorter than the',
    backTo: /^\s*if \(buf\.length < GLOBAL_HEADER\) \{$/,
    probe: 'p2-short-file',
    exercises: refusedWith(/shorter than the 24-byte global header/),
    mistake: 'the length of the file is assumed rather than asked',
  },
  {
    id: 'G2',
    name: 'magic-is-one-of-four',
    find: 'not a pcap file',
    backTo: /^\s*if \(!spec\) \{$/,
    probe: 'p3-not-pcap',
    exercises: refusedWith(/not a pcap file: magic/),
    mistake: 'an unrecognised magic is left to fall through to the version check',
  },
  {
    id: 'G3',
    name: 'major-version-is-2',
    find: 'unsupported pcap version',
    backTo: /^\s*if \(versionMajor !== 2\) \{$/,
    probe: 'p4-version-9',
    exercises: refusedWith(/unsupported pcap version 9\.0/),
    mistake: 'the major version is read and then ignored',
  },
  {
    id: 'G4',
    name: 'record-count-cap',
    find: 'refusing to keep walking',
    backTo: /^\s*if \(packets\.length >= MAX_RECORDS\) \{$/,
    probe: 'p5-record-bomb',
    exercises: refusedWith(/more than 200000 records/),
    mistake: 'the record loop is bounded only by the length of the file — this cap bounds WORK, not termination, so removing it does not hang, it just accepts a file the reference refuses',
  },
  {
    id: 'G5',
    name: 'record-header-is-inside-the-file',
    find: 'off + RECORD_HEADER > buf.length',
    backTo: /^\s*if \(off \+ RECORD_HEADER > buf\.length\) \{$/,
    probe: 'p6-dangling-record-header',
    exercises: truncatedAt(0),
    mistake: 'the 16-byte record header is read without asking whether it is there',
  },
  {
    id: 'G6',
    name: 'per-record-capture-cap',
    find: 'captured bytes (cap',
    backTo: /^\s*if \(captured > MAX_CAPTURED\) \{$/,
    probe: 'p7-oversize-capture',
    exercises: refusedWith(/declares 536870912 captured bytes \(cap 2097152\)/),
    mistake: 'incl_len is trusted, so one record can claim 512 MiB of work',
  },
  {
    id: 'G7',
    name: 'declared-frame-fits-in-the-file',
    find: 'off + RECORD_HEADER + captured > buf.length',
    backTo: /^\s*if \(off \+ RECORD_HEADER \+ captured > buf\.length\) \{$/,
    probe: 'p11-overrun-second-record',
    exercises: truncatedAt(1),
    mistake: 'subarray is handed the declared length, and subarray clamps',
  },
];

/* ========================================================= 4. observing a parse, honestly */

/**
 * Everything about a parse a twin could get wrong and a reader would act on: the refusal
 * or the value, and inside the value the fields an analyst would quote — including the
 * pair this whole lab exists to disagree about, `capturedLength` against `dataBytes`.
 */
function observe(parse, buf) {
  try {
    return { kind: 'value', ...shape(parse(buf)) };
  } catch (e) {
    return {
      kind: 'throw',
      name: (e && e.name) || typeof e,
      code: (e && e.code) || null,
      message: String((e && e.message) || e).slice(0, 240),
    };
  }
}

/**
 * The first four and last two packets, not all of them. `count` and `consumed` are
 * already top-level fields, so a file with 200001 records is fully described without
 * shipping 200001 packet objects through a pipe — which matters, because the record-bomb
 * mutant is the one feed whose observation is megabytes long and the first version of
 * this file duly wrote a line that came back truncated.
 */
const PACKET_HEAD = 4;
const PACKET_TAIL = 2;

function shape(r) {
  const packets = r.packets || [];
  const shown = packets.length <= PACKET_HEAD + PACKET_TAIL
    ? packets
    : [...packets.slice(0, PACKET_HEAD), ...packets.slice(-PACKET_TAIL)];
  return {
    endian: r.endian ?? null,
    nanos: r.nanos ?? null,
    version: r.version ?? null,
    snaplen: r.snaplen ?? null,
    linktype: r.linktype ?? null,
    linktypeName: r.linktypeName ?? null,
    count: r.count ?? null,
    truncated: r.truncated ?? null,
    consumed: r.consumed ?? null,
    packetsShown: `${shown.length} of ${packets.length}`,
    packets: shown.map((p) => ({
      index: p.index ?? null,
      tsSec: p.tsSec ?? null,
      tsFrac: p.tsFrac ?? null,
      resolution: p.timestampResolution ?? null,
      claimedCapturedLength: p.capturedLength ?? null,
      originalLength: p.originalLength ?? null,
      snapped: p.snapped ?? null,
      dataBytes: p.data ? p.data.length : null,
      dataSha: p.data ? crypto.createHash('sha256').update(p.data).digest('hex').slice(0, 16) : null,
    })),
  };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * What an outcome means, in a sentence a non-reader can check. A twin that never came back
 * for a feed has no observation at all, which is a fact the report has to be able to say —
 * the first version of this function read `obs.kind` unconditionally and took the whole
 * gate down on exactly the mutant it existed to catch.
 */
function sayRefusal(obs) {
  if (!obs) return 'no observation — the twin never returned for this feed';
  if (obs.kind === 'throw') return `refused — ${obs.name}: ${obs.message}`;
  if (obs.kind === 'value') return `returned ${obs.count} packet(s), truncated=${obs.truncated}, consumed=${obs.consumed}`;
  return 'no observation';
}

/**
 * How a twin's defect presents. LOUD means a reader would notice without an oracle: an
 * exception the parser never declared, or no return at all. SILENT means everything the
 * parser hands back is well-typed and plausible — including a refusal, because a refusal
 * for the wrong reason looks exactly like a refusal for the right one until you read the
 * message. That distinction is the reason G2 is filed as silent and not as caught-loudly.
 */
function failureMode(obs, hung) {
  if (hung) return { loud: true, text: 'LOUD   (never returned — killed at the wall clock)' };
  if (obs && obs.kind === 'throw' && obs.name !== 'PcapFormatError') {
    return { loud: true, text: `LOUD   (uncaught ${obs.name})` };
  }
  if (obs && obs.kind === 'throw') return { loud: false, text: 'SILENT (refused — for the wrong reason)' };
  return { loud: false, text: 'SILENT (returned a plausible wrong value)' };
}

/** The one sentence that matters for a silent mutant: what it claims versus what it holds. */
function theLie(obs) {
  if (!obs || obs.kind !== 'value') return null;
  for (const p of obs.packets || []) {
    if (p.claimedCapturedLength !== null && p.dataBytes !== null && p.claimedCapturedLength !== p.dataBytes) {
      return `packet ${p.index} reports capturedLength=${p.claimedCapturedLength} while carrying ${p.dataBytes} byte(s)`;
    }
  }
  return null;
}

/* ============================================================ 5. the mutant child process */

async function runChild(guardId) {
  /* Loop the write. `fs.writeSync` on a pipe is a single `write(2)` and returns a short
     count rather than looping, so a long line comes back truncated — which reads as a
     mutant that produced no observation at all rather than as the I/O bug it is. */
  const emit = (o) => {
    const line = Buffer.from(JSON.stringify(o) + '\n', 'utf8');
    let off = 0;
    while (off < line.length) off += fs.writeSync(1, line, off, line.length - off);
  };
  try {
    const { prelude, body } = extractParser();
    const guard = GUARDS.find((g) => g.id === guardId);
    if (guardId !== '__none' && !guard) throw new GateError(`unknown mutant id ${guardId}`);

    /* The single line that decides what the twin is. Everything else in this file is
       measurement. A neutered copy of this gate replaces this line to disable the mutation
       for one guard, which is how the control is shown to fail in the dangerous
       direction. `__none` is the control on the control: the same path with nothing
       removed, whose output must equal the imported module's on every feed. */
    const MUTATED = guardId === '__none'
      ? { source: body, removed: ['(nothing removed — this is the slicing control, not a mutant)'] }
      : dropGuardBlock(body, guard);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzzlab-negative-gate-'));
    /* Announce the directory before anything that can hang. A child killed on the wall clock
       never reaches its own `finally`, so the parent is the only party left who can delete
       it, and it cannot delete what it was never told about. */
    emit({ tmpdir: dir });
    try {
      const file = path.join(dir, 'twin.mjs');
      fs.writeFileSync(file, `${prelude}\n${MUTATED.source}\nexport { readPcapFile as parse };\n`);
      const twin = (await import(pathToFileURL(file).href)).parse;

      emit({ removed: MUTATED.removed });
      for (const id of PROBE_ORDER) {
        const probe = PROBES.find((p) => p.id === id);
        emit({ probe: id, obs: observe(twin, probe.buf) });
      }
    } finally {
      /* `force: true` swallows ENOENT, not EPERM, and Windows hands out a lock on a file
         an imported module was just reading from. A gate that leaves a temp directory
         behind on every run is a gate nobody keeps, so a failed delete is reported rather
         than thrown: the mutant's results are already on fd 1 by this point. */
      try {
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
      } catch {
        emit({ cleanup: `could not remove ${dir}` });
      }
    }
  } catch (e) {
    emit({ fatal: `${(e && e.name) || 'Error'}: ${(e && e.message) || e}` });
    process.exit(3);
  }
  process.exit(0);
}

/* ======================================================================= 6. the parent */

function parseChild(result) {
  const timedOut = !!(result.error && result.error.code === 'ETIMEDOUT') || typeof result.signal === 'string';
  const lines = String(result.stdout || '').split('\n').filter((l) => l.trim());
  /* A child killed on the wall clock can have had its LAST write cut in half by the signal.
     Drop that line only if it genuinely does not parse — dropping the last line
     unconditionally threw away a complete one whenever a child hung on its very first feed,
     which is precisely when the `removed` block was still the only thing it had said. */
  let partial = null;
  if (timedOut && lines.length) {
    const last = lines[lines.length - 1];
    try { JSON.parse(last); } catch { partial = lines.pop(); }
  }

  const obs = {};
  const cleanup = [];
  let removed = null;
  let fatal = null;
  let tmpdir = null;
  for (const line of lines) {
    let o;
    try { o = JSON.parse(line); } catch { fatal = fatal || `unreadable child output: ${line.slice(0, 120)}`; continue; }
    if (o.fatal) fatal = fatal || o.fatal;
    else if (o.tmpdir) tmpdir = o.tmpdir;
    else if (o.removed) removed = o.removed;
    else if (o.cleanup) cleanup.push(o.cleanup);
    else if (o.probe) obs[o.probe] = o.obs;
  }
  return { obs, removed, fatal, timedOut, partial, cleanup, tmpdir };
}

function runMutant(guard) {
  const result = spawnSync(process.execPath, [SELF], {
    env: { ...process.env, FUZZLAB_GATE_CHILD: guard.id },
    encoding: 'utf8',
    timeout: HANG_MS,
    maxBuffer: 8 << 20,
  });
  const child = parseChild(result);
  /* Every feed with no observation is a feed the child never came back from. That is only
     true when the child produced output at all; a child that died before its first line
     failed to build, and calling its ten feeds "hung" would bury that under a hang. */
  child.hung = child.fatal || child.removed === null ? [] : PROBE_ORDER.filter((id) => !child.obs[id]);
  child.stderr = String(result.stderr || '').trim().slice(0, 400);
  /* Reap a directory the killed child could not. Absent this, every mutant that stops
     returning leaves a copy of the parser behind in %TEMP%, and a gate is the last thing
     that should accumulate litter. */
  if (child.timedOut && child.tmpdir) {
    try {
      fs.rmSync(child.tmpdir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    } catch {
      child.cleanup.push(`parent could not remove ${child.tmpdir} after killing the child`);
    }
  }
  return child;
}


const rule = (t) => console.log(`\n${'-'.repeat(78)}\n${t}\n${'-'.repeat(78)}`);

async function runParent() {
  const t0 = Date.now();
  console.log('fuzz.differential.parse — NEGATIVE CONTROL: one guard removed at a time');
  console.log(`  instrument   ${path.relative(path.join(HERE, '..', '..'), READER)} :: readPcapFile`);
  console.log('  claim        a twin with exactly ONE guard removed MUST behave differently');
  console.log('  feeds        10 hand-built pcaps, byte-identical to the reference and to every twin');
  console.log(`  budget       ${GUARDS.length} mutant children x <=${HANG_MS} ms wall clock`);

  /* -------------------------------------------------- the extraction control */
  rule('0. the gate checks its own slicing before it trusts any result');

  const { body } = extractParser();
  const refObs = {};
  for (const p of PROBES) refObs[p.id] = observe(readPcapFile, p.buf);

  const sliced = runMutant({ id: '__none' });
  const sliceAgrees = PROBE_ORDER.every((id) => !sliced.fatal && sliced.obs[id] && same(sliced.obs[id], refObs[id]));
  console.log(`  the parser re-assembled from ${path.basename(READER)} source text, with NOTHING removed,`);
  console.log(`  against the imported module over all ${PROBE_ORDER.length} feeds: ${sliceAgrees ? 'IDENTICAL' : 'DIFFERENT'}.`);
  if (!sliceAgrees) {
    console.log(`  ${sliced.fatal ? `child failed: ${sliced.fatal}` : `diverged on: ${PROBE_ORDER.filter((id) => !sliced.obs[id] || !same(sliced.obs[id], refObs[id])).join(', ')}`}`);
    console.log('  A mutant cannot be blamed for a difference it inherited from the slicing, so this gate');
    console.log('  reports what it cannot certify rather than grading mutants against a broken twin.');
  }

  /* ------------------------------------------------------------- the feeds */
  rule('1. what is fed, and what the reference does with it');
  for (const id of PROBE_ORDER) {
    const p = PROBES.find((x) => x.id === id);
    const preview = p.buf.subarray(0, 16).toString('hex');
    console.log(`  ${p.id.padEnd(28)} ${String(p.buf.length).padStart(9)} B  ${preview}…`);
    console.log(`  ${''.padEnd(28)} ${p.note}`);
    console.log(`  ${''.padEnd(28)} reference ${sayRefusal(refObs[id])}`);
  }

  /* -------------------------------------------------------------- the mutants */
  rule('2. mutants — one guard deleted from the shipped source, nothing else changed');

  const results = [];
  for (const guard of GUARDS) {
    const child = runMutant(guard);
    const exercises = !child.fatal && guard.exercises(refObs[guard.probe]);
    const diverged = PROBE_ORDER.filter((id) => child.obs[id] && !same(child.obs[id], refObs[id]));
    const hung = child.hung.includes(guard.probe);
    /* A mutant counts as caught when it differs from the reference ON THE FEED THAT
       EXERCISES ITS GUARD. Divergence on some other feed is corroboration, not proof: a
       twin can differ on p2 for a reason that has nothing to do with G5. */
    const caught = diverged.includes(guard.probe) || hung;
    const survived = !caught;
    const mode = failureMode(child.obs[guard.probe], hung);
    results.push({ guard, child, exercises, diverged, caught, survived, mode });

    console.log(`\n  ${guard.id}  ${guard.name}`);
    console.log(`      the mistake   ${guard.mistake}`);
    console.log(`      removed`);
    for (const l of child.removed || ['(the child failed before reporting — see below)']) console.log(`        ${l}`);
    console.log(`      probe         ${guard.probe}`);
    console.log(`      reference     ${sayRefusal(refObs[guard.probe])}`);
    console.log(`      twin          ${child.fatal ? `CHILD FAILED: ${child.fatal}` : sayRefusal(child.obs[guard.probe])}`);
    if (child.timedOut) {
      console.log(`      killed        the wall clock fired at ${HANG_MS} ms; ${child.obs ? Object.keys(child.obs).length : 0}/${PROBE_ORDER.length} observation(s) arrived first`);
      if (child.partial) console.log(`      cut mid-write ${JSON.stringify(child.partial.slice(0, 120))}`);
    }
    if (child.stderr) console.log(`      child stderr  ${child.stderr}`);
    const lie = theLie(child.obs[guard.probe]);
    if (lie) console.log(`      the lie       ${lie}`);
    console.log(`      guard fires?  ${exercises ? `yes — the reference behaved as ${guard.id} says on this feed` : 'NO — this feed does not exercise this guard'}`);
    console.log(`      diverged on   ${diverged.length ? diverged.join(', ') : 'nothing'}${child.hung.length ? `, no return on ${child.hung.join(', ')}` : ''}`);
    console.log(`      verdict       ${survived
      ? `SURVIVED — byte-identical to the reference on all ${PROBE_ORDER.length} feeds; the guard it lost protects nothing`
      : `CAUGHT — ${mode.loud ? 'LOUD' : 'SILENT'} on ${guard.probe}${hung ? ` (never returned; killed at ${HANG_MS} ms)` : ''}`}`);
  }

  /* --------------------------------------------------------------- the verdict */
  rule('3. verdict');

  const survivors = results.filter((r) => r.survived);
  const blind = results.filter((r) => !r.exercises && !r.child.fatal);
  const broken = results.filter((r) => r.child.fatal);
  const caughtResults = results.filter((r) => !r.survived);
  const loudCount = caughtResults.filter((r) => r.mode.loud).length;
  const silentCount = caughtResults.length - loudCount;

  console.log(`  ${'gu'.padEnd(4)}${'guard removed'.padEnd(38)}${'feed'.padEnd(32)}how the twin fails`);
  for (const r of results) {
    console.log(`  ${r.guard.id.padEnd(4)}${r.guard.name.padEnd(38)}${r.guard.probe.padEnd(32)}${r.survived ? 'SURVIVED (not load-bearing)' : r.mode.text}`);
  }
  console.log('');
  console.log(`  caught LOUDLY   ${loudCount}  (an undeclared throw, or no return at all — visible without an oracle)`);
  console.log(`  caught SILENTLY ${silentCount}  (a wrong refusal or a well-typed wrong value — visible only by comparison)`);
  console.log(`  survived        ${survivors.length}`);
  console.log(`  feeds whose reference never reached the guard under test: ${blind.length}`);
  console.log(`  mutants that could not be built: ${broken.length}`);
  console.log(`  slicing control: ${sliceAgrees ? 'the untouched re-assembly is identical to the imported module' : 'BROKEN'}`);
  console.log(`  temp dirs left behind: ${results.reduce((a, r) => a + r.child.cleanup.length, 0) + sliced.cleanup.length}`);
  console.log(`  elapsed ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const certified = survivors.length === 0 && blind.length === 0 && broken.length === 0 && sliceAgrees;

  console.log('');
  if (certified) {
    console.log('CONTROL WORKING — every guard this gate removed changed the parser\'s behaviour on the feed');
    console.log('that provably exercises it. The differential oracle can tell a hardened parser from an');
    console.log('unhardened one, including where the difference is a lie rather than a crash.');
    console.log('');
    console.log('Exiting 1. Rule R5 requires a negative control\'s expected exit to be non-zero: a control');
    console.log('that must exit 0 proves nothing, because an oracle that had stopped comparing would also');
    console.log('exit 0 and the harness would read that as a pass.');
    return 1;
  }

  if (survivors.length) {
    console.log(`CONTROL FAILED — ${survivors.length} twin(s) SURVIVED: ${survivors.map((s) => s.guard.id).join(', ')}.`);
    for (const s of survivors) {
      console.log(`  ${s.guard.id} (${s.guard.name}): on ${s.guard.probe} the twin returned`);
      console.log(`      ${sayRefusal(s.child.obs[s.guard.probe])}`);
      console.log(`    and the reference returned`);
      console.log(`      ${sayRefusal(refObs[s.guard.probe])}`);
      console.log(`    which is the same answer, on all ${PROBE_ORDER.length} feeds. Removing ${s.guard.id} changed nothing.`);
    }
    console.log('A guard that can be removed without changing a single output is not load-bearing, and every');
    console.log('"the oracle found it" claim resting on it was luck.');
  }
  if (blind.length) {
    console.log(`CONTROL INCONCLUSIVE — ${blind.length} feed(s) never reached the guard they were written for:`);
    for (const r of blind) console.log(`  ${r.guard.id}: ${r.guard.probe} did not make the reference refuse in ${r.guard.id}'s own words.`);
    console.log('A mutant cannot be credited with being caught on an input its guard never fired on.');
  }
  if (broken.length) {
    console.log(`CONTROL INCONCLUSIVE — ${broken.length} mutant(s) could not be built:`);
    for (const r of broken) console.log(`  ${r.guard.id}: ${r.child.fatal}`);
  }
  if (!sliceAgrees) {
    console.log('CONTROL INCONCLUSIVE — the re-assembled parser does not match the imported module, so the');
    console.log('slicing this gate depends on no longer reproduces lab/pcap-reader.mjs.');
  }
  console.log('');
  console.log('Exiting 0 so the harness reports DRIFT rather than a pass. A green run is not available while');
  console.log('the control has not actually failed.');
  return 0;
}

try {
  const childId = process.env.FUZZLAB_GATE_CHILD;
  process.exit(childId ? await runChild(childId) : await runParent());
} catch (e) {
  /* An unexpected throw must never land on exit 1, because exit 1 is the value that means
   * "the control worked". A gate that crashed on a stack trace has certified nothing, and
   * the only way to say that in this polarity is to exit 0. */
  console.error(`negative-gate: ${(e && e.stack) || e}`);
  console.error('The gate did not run to a verdict. Exiting 0 — exit 1 means "every mutant was caught",');
  console.error('and a gate that crashed has caught nothing.');
  process.exit(0);
}