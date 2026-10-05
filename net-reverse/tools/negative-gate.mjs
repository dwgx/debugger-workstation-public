#!/usr/bin/env node
/* negative-gate.mjs — NEGATIVE CONTROL for `net.pcap.selfparse`, the incl_len/orig_len guard.
 *
 *   node net-reverse/tools/negative-gate.mjs
 *
 * WHY THIS FILE EXISTS. `net.pcap.selfparse`'s only registered negative control was
 * `pcap_reader.py README.md` -> exit 2, "not a pcap": the header is garbage. That checks the
 * MAGIC and nothing else. Every declared guard inside the record loop had never been shown to
 * fire, and one of them did not exist at all. Measured 2026-10-05, on a generated capture whose
 * single record declared incl_len=100 / orig_len=40 with all 100 body bytes present:
 *
 *   {"ok": true, "bytes_on_wire": 40, "captured_bytes": 100}
 *
 * captured MORE bytes than were on the wire, and called it a success. `orig_len` is defined by
 * pcap-savefile(5) as the bytes that WOULD have been present had the packet not been
 * snaplen-truncated, so this header cannot be true. The truncation guard two lines below it
 * already refused, so the reader knew record headers could lie and checked only one of the ways.
 *
 * WHAT IS FED. Four captures, built here BYTE BY BYTE into a temp dir. No committed binary: a
 * .pcap in the tree is a fixture nobody can read the intent of, and the intent IS the test case.
 * The three from the brief, plus the legal baseline that says the refusal is not just "refuse
 * everything" -- a control that cannot tell a good capture from a bad one certifies nothing.
 *
 *   legal          incl=40  orig=40  body 40B   MUST be accepted, captured == wire
 *   incl>orig      incl=100 orig=40  body 100B  MUST be refused  (the guard under test)
 *   truncated      incl=512 orig=512 body 60B   MUST still be refused exactly as before
 *   incl<orig      incl=40  orig=60  body 40B   MUST be accepted -- a snaplen-shortened record
 *                                              is legal, and a guard that refused this too
 *                                              would be a guard that refuses captures
 *
 * MUTATION, BOTH DIRECTIONS, on the guard under test. A control nobody has seen fail is
 * decoration, so this gate builds the mutant the way fuzz-lab/tools/negative-gate.mjs does:
 * take the shipped reader's SOURCE TEXT, delete exactly one `if incl > orig:` block, write the
 * result to a temp dir, and run that.
 *
 *   guard live     the shipped reader REFUSES incl>orig -- so the fixture DOES exercise it.
 *   guard DISABLED the mutant ACCEPTS it, with captured_bytes > bytes_on_wire, exit 0.
 *                  That divergence is the proof: the control can tell the two readers apart,
 *                  so a green run means the guard is present rather than that nobody looked.
 *
 * A mutant that reproduces the original defect is measured, not asserted: the gate compares the
 * mutant's own stdout on the SAME bytes, and prints the two side by side.
 *
 * EXIT POLARITY.
 *   exit 1 = THE CONTROL WORKING. Every case behaved, and the mutant diverged. Non-zero because
 *            R5 requires it: a control that must exit 0 also passes when the harness has stopped
 *            asking. Same convention as the other six negative-gate.mjs in this tree.
 *   exit 0 = the reader ACCEPTED a header it must refuse, or the mutant was indistinguishable
 *            from the shipped reader. Both read as DRIFT, never as a pass.
 *   exit 5 = a case was not what it claimed to be (the fixture did not exercise its guard), so
 *            the control is broken rather than the reader. Saying so is the only honest answer.
 *   exit 2 = a stray argument (below).
 *
 * ARGUMENT REFUSAL. Exit 2, DISTINCT from the control's own 1. Same reason as every other gate
 * here: a control that silently ignores a flag can be made to report a green it did not measure.
 * The three gates that shipped without this were caught only by being run with `--bogus`.
 *
 * The mutants are GENERATED from the shipped reader, so there is no --target to aim and nothing
 * here was meant to be aimed.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const HERE = path.dirname(SELF);
const ROOT = path.resolve(HERE, '..', '..');
const READER = path.join(HERE, 'pcap_reader.py');
const SCRIPTS = path.join(ROOT, 'scripts');

/* ARGUMENT REFUSAL. Exit 2, deliberately DISTINCT from the control's own 1.
 *
 * ALLOWED is declared empty rather than omitted, so the intent is visible in the file instead of
 * inferred from the absence of a filter.
 */
const ALLOWED = new Set([]);
const STRAY = process.argv.slice(2).filter((a) => !ALLOWED.has(a));
if (STRAY.length) {
  console.error(`negative-gate.mjs: refusing argument(s) it would otherwise IGNORE: ${STRAY.join(' ')}`);
  console.error('  This gate takes no arguments. The mutants are GENERATED from the shipped reader,');
  console.error('  so there is no --target to aim and nothing here was meant to be aimed.');
  process.exit(2);
}

const line = (s = '') => console.log(s);
const rule = (t) => console.log(`\n${'-'.repeat(78)}\n${t}\n${'-'.repeat(78)}`);

/** Wall clock for one reader child. The reader is a small pure-python parse; this is generous. */
const HANG_MS = 20_000;

/* ============================================================ 1. the feed corpus */

/* Global header, byte by byte, little-endian, magic 0xa1b2c3d4, version 2.4, Ethernet.
 * Written as explicit octets rather than via struct on purpose: a reader of this file should be
 * able to see the 24 bytes the format actually specifies. */
const GLOBAL_HEADER = Buffer.from([
  0xd4, 0xc3, 0xb2, 0xa1,       // magic, little-endian
  0x02, 0x00,                   // version major 2
  0x04, 0x00,                   // version minor 4
  0x00, 0x00, 0x00, 0x00,       // thiszone, MUST be ignored by readers
  0x00, 0x00, 0x00, 0x00,       // sigfigs, MUST be ignored by readers
  0xff, 0xff, 0x00, 0x00,       // snaplen 65535, LE
  0x01, 0x00, 0x00, 0x00,       // linktype 1 = LINKTYPE_ETHERNET, LE
]);

/** One record: 16-byte header with `incl`/`orig` written as given, then `body` verbatim. */
function record({ incl, orig, body }) {
  const head = Buffer.alloc(16);
  head.writeUInt32LE(1700000000, 0);   // ts_sec
  head.writeUInt32LE(0, 4);            // ts_usec
  head.writeUInt32LE(incl, 8);
  head.writeUInt32LE(orig, 12);
  return Buffer.concat([head, body]);
}

/** An Ethernet frame carrying IPv4 and zero transport bytes. The reader only needs the ethertype
 *  to classify the frame; nothing below it is asserted, so the body is filler. */
function frame(len) {
  const f = Buffer.alloc(len, 0x41);
  Buffer.from([0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,   // dst MAC, locally administered
               0x02, 0x00, 0x5e, 0x00, 0x00, 0x02]).copy(f, 0);
  f.writeUInt16BE(0x0800, 12);         // ethertype IPv4
  f[14] = 0x45;                        // IPv4 version 4, IHL 5 words
  return f;
}

/* Each case: what it is, why, and what the reader MUST do. `must` is the whole assertion -- a case
 * with no assertion would be a case nobody is checking.
 *
 * `file` is a separate slug because `id` is a LABEL and labels are allowed to be readable:
 * `incl>orig` is the clearest possible name for the defect and is illegal in a Windows filename.
 * Measured on this box: fs.writeFileSync threw ENOENT on `incl>orig.pcap`, so the label is not
 * allowed anywhere near a path.
 */
const CASES = [
  {
    file: 'legal-incl-eq-orig.pcap',
    id: 'legal', incl: 40, orig: 40, bodyLen: 40,
    title: 'incl_len == orig_len: an ordinary, fully captured record',
    why: 'the two length fields agree, so nothing here may be refused. A guard that also refused ' +
         'this would be indistinguishable from one that refuses every capture.',
    must: 'accept',
  },
  {
    id: 'incl>orig', incl: 100, orig: 40, bodyLen: 100,
    file: 'defect-incl-gt-orig.pcap',
    title: 'incl_len (100) EXCEEDS orig_len (40), with all 100 body bytes present',
    why: 'THE GUARD UNDER TEST. orig_len is the length the packet would have had absent snaplen ' +
         'truncation, so a capture cannot hold more bytes than that. The body is fully present, ' +
         'which is what makes this distinct from the truncation case below: the truncation guard ' +
         'cannot fire here, so before the fix nothing fired at all and the reader reported ' +
         'captured_bytes=100 against bytes_on_wire=40 with ok:true.',
    must: 'refuse',
    expectIn: 'incl_len 100 > orig_len 40',
  },
  {
    id: 'truncated', incl: 512, orig: 512, bodyLen: 60,
    title: 'record declares 512 bytes, only 60 remain in the file',
    file: 'truncated-mid-packet.pcap',
    why: 'THE REGRESSION THIS MUST NOT CAUSE. trunc incl == orig, so the new guard does not fire ' +
         'on it and the pre-existing mid-packet refusal is still the one that answers.',
    must: 'refuse',
    expectIn: 'truncated mid-packet',
  },
  {
    id: 'incl<orig', incl: 40, orig: 60, bodyLen: 40,
    file: 'legal-incl-lt-orig.pcap',
    title: 'incl_len (40) BELOW orig_len (60): a snaplen-shortened record',
    why: 'LEGAL, and the direction most likely to be broken by a careless fix. orig_len records ' +
         'the untruncated length, so this is ordinary and MUST be accepted -- captured_bytes=40 ' +
         'against bytes_on_wire=60 is the correct reading, and captured < wire is not an anomaly.',
    must: 'accept',
  },
];

function buildPcap(c) {
  /* The body is `bodyLen` bytes, but for the truncated case the header must CLAIM 512 while the
   * file holds fewer -- which is exactly `incl`/`bodyLen` disagreeing. That is the fixture. */
  return Buffer.concat([GLOBAL_HEADER, record({ incl: c.incl, orig: c.orig, body: frame(c.bodyLen) })]);
}

/* ============================================================ 2. running a reader */

class GateError extends Error {}

/** Run one reader over one capture. Returns the exit code and the parsed JSON, or the raw
 *  stdout when it is not JSON -- an unparseable verdict is a fact, not something to hide. */
function observe(reader, pcapPath) {
  const started = Date.now();
  const r = spawnSync('python', [reader, pcapPath], { encoding: 'utf8', timeout: HANG_MS });
  if (r.error) throw new GateError(`could not spawn python for ${path.basename(reader)}: ${r.error.message}`);
  const stdout = (r.stdout || '').trim();
  const last = stdout.split('\n').filter(Boolean).pop() || '';
  let json = null;
  try { json = JSON.parse(last); } catch { /* kept as null; the caller reports the raw line */ }
  return { code: r.status, raw: last, json, stderr: (r.stderr || '').trim(), ms: Date.now() - started };
}

/** What an outcome means, in a sentence that does not require reading the source. */
function sayRefusal(o) {
  if (!o.json) return `NO JSON (exit ${o.code}): ${o.raw.slice(0, 160)}`;
  if (o.json.ok === false) return `refused, exit ${o.json.exit}: ${o.json.error}`;
  return `ACCEPTED, exit ${o.code}: packets=${o.json.packets} wire=${o.json.bytes_on_wire} captured=${o.json.captured_bytes}`;
}

/** The claim a reader makes about bytes, stated so the impossible one is visible at a glance. */
function byteClaim(o) {
  if (!o.json || o.json.ok === false) return '(no counts -- refused)';
  const w = o.json.bytes_on_wire, c = o.json.captured_bytes;
  const flag = c > w ? '   <== IMPOSSIBLE: captured MORE bytes than were on the wire' : '';
  return `captured ${c} vs wire ${w}${flag}`;
}

/* ============================================================ 3. the mutant */

/**
 * Delete exactly the `if incl > orig:` block from the reader's source TEXT and write the result
 * to a temp dir. Text-level rather than import-level, following fuzz-lab's negative-gate: the
 * point is that the only difference between reference and mutant is the bytes of one guard, so a
 * divergence cannot be blamed on anything else.
 *
 * The mutant is written to `<tmp>/net-reverse/tools/pcap_reader.py`, at the SAME DEPTH as the real
 * reader, because the reader bootstraps its own import path from its location:
 * `parents[2] / "scripts"`. `probe_artifact.py` is copied to `<tmp>/scripts` to satisfy it.
 * Measured: writing the mutant to `<tmp>/net-reverse/` instead made `parents[2]` land on the
 * system temp root, every mutant run died with ImportError and exit 1, and the gate correctly
 * reported INCONCLUSIVE rather than a pass -- but the cause was this path, not the mutation.
 */
function buildMutant() {
  const src = fs.readFileSync(READER, 'utf8');
  const lines = src.split('\n');

  /* Find the guard by its condition, not by line number: a gate that breaks when the reader is
   * reformatted is a gate that stops being run. */
  const start = lines.findIndex(l => /^\s*if incl > orig:\s*$/.test(l));
  if (start === -1) {
    throw new GateError(`no "if incl > orig:" guard found in ${path.relative(ROOT, READER)} -- ` +
      `this gate cannot build its mutant, and a gate that cannot build its mutant must say so ` +
      `rather than quietly report a pass`);
  }
  /* Python has no braces, so the block runs to the next line at or below the guard's own indent
   * that is not blank and not a continuation. The guard's body here is a single `die(...)` call
   * spanning several physical lines. */
  const indent = lines[start].match(/^\s*/)[0].length;
  let end = start + 1;
  while (end < lines.length) {
    const l = lines[end];
    if (l.trim() === '') { end += 1; continue; }
    const li = l.match(/^\s*/)[0].length;
    if (li <= indent) break;
    end += 1;
  }
  const removed = lines.slice(start, end);
  const mutated = [...lines.slice(0, start), ...lines.slice(end)];

  const dir = temp('pcap-selfparse-mutant-');
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'net-reverse', 'tools'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'net-reverse', 'out'), { recursive: true });
  fs.copyFileSync(path.join(SCRIPTS, 'probe_artifact.py'), path.join(dir, 'scripts', 'probe_artifact.py'));
  const reader = path.join(dir, 'net-reverse', 'tools', 'pcap_reader.py');
  fs.writeFileSync(reader, mutated.join('\n'), 'utf8');
  return { reader, removed, dir, guardLine: start + 1 };
}

/* ============================================================ 4. the parent */

function runParent() {
  const t0 = Date.now();
  const tmp = temp('pcap-selfparse-gate-');

  line('net.pcap.selfparse — NEGATIVE CONTROL: the incl_len/orig_len guard');
  line(`  instrument   ${path.relative(ROOT, READER)}`);
  line('  claim        incl_len > orig_len is a header that cannot be true, so the reader must REFUSE');
  line('             it -- while a legal incl == orig record and a legal snaplen-shortened');
  line('             incl < orig record must both still be accepted');
  line(`  feeds        ${CASES.length} captures built byte by byte into ${tmp}`);
  line('  built by     this file, from the format in pcap-savefile(5). No committed .pcap: the');
  line('               intent IS the test case, and a binary fixture hides it.');

  /* --------------------------------------------------------------- 1. the feeds */
  rule('1. what is fed, and what the SHIPPED reader does with it');
  const pcaps = {};
  for (const c of CASES) {
    const p = path.join(tmp, c.file);
    fs.writeFileSync(p, buildPcap(c));
    pcaps[c.id] = p;
    const obs = observe(READER, p);
    c.obs = obs;
    line(`  ${c.id.padEnd(11)} incl=${String(c.incl).padStart(4)} orig=${String(c.orig).padStart(4)} body=${String(c.bodyLen).padStart(4)}B  ${fs.statSync(p).size}B file`);
    line(`  ${''.padEnd(11)} ${c.title}`);
    line(`  ${''.padEnd(11)} must  ${c.must.toUpperCase()}`);
    line(`  ${''.padEnd(11)} why   ${c.why}`);
    line(`  ${''.padEnd(11)} got   ${sayRefusal(obs)}`);
    line(`  ${''.padEnd(11)} bytes ${byteClaim(obs)}`);
    line('');
  }

  /* ---------------------------------------------------------- 2. did each case hold */
  rule('2. the assertions');
  const results = [];
  for (const c of CASES) {
    const o = c.obs;
    const accepted = o.json && o.json.ok === true;
    const held = c.must === 'accept' ? accepted : (!accepted && o.code === 2);
    const named = c.expectIn ? new RegExp(c.expectIn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(o.raw) : true;
    results.push({ c, held, accepted, named, code: o.code });
    let why;
    if (c.must === 'accept') {
      why = accepted ? 'accepted, as it must be' : `REFUSED a legal capture (exit ${o.code})`;
    } else {
      why = accepted ? 'ACCEPTED a header that cannot be true'
        : named ? `refused with exit ${o.code}, and the refusal names the defect`
          : `refused with exit ${o.code} but not in the words this case expects`;
    }
    line(`  ${held ? 'HOLDS  ' : 'FAILS  '} ${c.id.padEnd(11)} ${why}`);
  }

  /* The new guard must not have been satisfied by refusing everything: the two accept cases are
   * what distinguish "this guard works" from "this reader refuses all captures". */
  const acceptsHeld = results.filter(r => r.c.must === 'accept').every(r => r.accepted);
  line('');
  line(`  a refusal-only reader would pass 2/4 of the cases above; the ${CASES.filter(c => c.must === 'accept').length} accept cases are what`);
  line(`  rule that out: ${acceptsHeld ? 'both legal captures were accepted' : 'AT LEAST ONE LEGAL CAPTURE WAS REFUSED -- the guard is too broad'}`);

  /* ----------------------------------------------------------- 3. the mutation */
  rule('3. MUTATION, both directions, on the guard under test');
  let mutant = null;
  let mutationOk = false;
  try {
    mutant = buildMutant();
  } catch (e) {
    line(`  MUTANT NOT BUILT: ${e.message}`);
  }

  if (mutant) {
    line(`  guard live     the shipped reader, on incl>orig:`);
    line(`                 ${sayRefusal(CASES.find(c => c.id === 'incl>orig').obs)}`);
    line(`  removed from ${path.relative(ROOT, READER)} (source text, nothing else changed):`);
    for (const l of mutant.removed) line(`    ${l}`);

    line('');
    line(`  guard DISABLED the same reader with that block deleted, on the SAME bytes:`);
    for (const c of CASES) {
      const obs = observe(mutant.reader, pcaps[c.id]);
      c.mutObs = obs;
      line(`    ${c.id.padEnd(11)} ${sayRefusal(obs)}`);
      line(`    ${''.padEnd(11)} ${byteClaim(obs)}`);
    }

    const refBad = CASES.find(c => c.id === 'incl>orig').obs;
    const mutBad = CASES.find(c => c.id === 'incl>orig').mutObs;
    /* The mutant must ACCEPT where the reference REFUSES. Anything else -- same answer, a crash,
     * a timeout -- means this control cannot tell the two readers apart on this fixture. */
    const refRefused = !(refBad.json && refBad.json.ok === true);
    const mutAccepted = mutBad.json && mutBad.json.ok === true;
    const reproduces = mutAccepted && mutBad.json.captured_bytes > mutBad.json.bytes_on_wire;
    mutationOk = refRefused && mutAccepted;

    line('');
    line(`  reference REFUSED incl>orig        ${refRefused ? 'yes' : 'NO — the fixture does not exercise the guard'}`);
    line(`  mutant    ACCEPTED incl>orig        ${mutAccepted ? `yes, exit ${mutBad.code}` : 'NO — the guard was not load-bearing'}`);
    line(`  mutant reproduces the original defect ${reproduces
      ? `YES — captured_bytes ${mutBad.json.captured_bytes} > bytes_on_wire ${mutBad.json.bytes_on_wire}, reported as ok:true`
      : 'no — the mutant did not print the impossible figure, so the gate is not measuring the defect'}`);
    line('');
    if (mutationOk) {
      line('  BOTH DIRECTIONS MEASURED. Guard live -> the reader refuses. Guard disabled -> the reader');
      line('  accepts, exit 0, and prints captured_bytes greater than bytes_on_wire. The divergence is');
      line('  the control: a green run above means the guard is PRESENT, not that nobody looked.');
    } else {
      line('  MUTATION INCONCLUSIVE. The reference and the mutant are not distinguishable on this');
      line('  fixture, so the assertions in section 2 cannot be credited with catching the defect.');
    }
  }

  /* ------------------------------------------------------------------ 4. verdict */
  rule('4. verdict');
  const failed = results.filter(r => !r.held);
  const tooBroad = !acceptsHeld;
  const eligible = CASES.filter(c => c.must === 'refuse');
  const namedAll = eligible.every(c => results.find(r => r.c === c).named);

  line(`  cases held     ${results.length - failed.length}/${results.length}`);
  line(`  legal captures refused by the new guard: ${tooBroad ? 'YES (see above)' : 'no'}`);
  line(`  refusals that name their defect:        ${namedAll ? 'yes, all of them' : 'NO'}`);
  line(`  mutation both directions measured:       ${mutationOk ? 'yes' : 'NO'}`);
  line(`  temp dir       ${tmp}`);
  line(`  elapsed        ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const certified = failed.length === 0 && !tooBroad && mutationOk && namedAll;

  line('');
  if (certified) {
    line(`NEGATIVE-CONTROL OK — ${results.length}/${results.length} cases held:`);
    line('  incl>orig  REFUSED (exit 2) naming both lengths -- the defect this gate exists for');
    line('  truncated  still REFUSED by its own pre-existing guard, in its own pre-existing words');
    line('  legal      incl == orig ACCEPTED, captured == wire');
    line('  incl<orig  snaplen-shortened record ACCEPTED, so the guard is not simply "refuse all"');
    line('  and the guard was shown load-bearing in BOTH directions before any of the above counted.');
    line('');
    line('Exiting 1. R5 requires a negative control\'s expected exit to be non-zero: a control that');
    line('must exit 0 also passes when the harness has stopped asking.');
    cleanup();
    return 1;
  }

  if (failed.length) {
    line(`CONTROL FAILED — ${failed.length}/${results.length} case(s) did not hold:`);
    for (const r of failed) line(`  ${r.c.id}: expected ${r.c.must}, reader exited ${r.code} saying ${r.c.obs.raw.slice(0, 200)}`);
  }
  if (tooBroad) line('CONTROL FAILED — a LEGAL capture was refused. The guard is too broad, and every');
  if (!namedAll) line('CONTROL FAILED — a refusal did not name the defect it refused, so a reader cannot');
  if (!mutationOk) line('CONTROL INCONCLUSIVE — the mutation did not measure both directions, so the green');
  if (!certified) {
    line('');
    line('Exiting 0 so the harness reports DRIFT rather than a pass. A green run is not available while');
    line('the control has not actually failed.');
  }
  cleanup();
  return 0;
}

/** Every temp dir this run created, cleaned on every exit path INCLUDING the crash path.
 *
 * Measured 2026-10-05: cleanup() was called from the two verdict returns, so the throw from a
 * bad filename left `pcap-selfparse-gate-*` behind in TEMP. A gate that leaks a directory every
 * time it fails is a gate whose failures get ignored, and the leak was invisible precisely
 * because nobody looks in TEMP. Tracking the dirs at module scope means the `catch` below can
 * clean up too. */
const TEMPS = [];
const temp = (prefix) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  TEMPS.push(d);
  return d;
};

function cleanup() {
  for (const d of TEMPS.splice(0)) {
    try { fs.rmSync(d, { recursive: true, force: true }); }
    catch (e) { console.error(`  (could not remove ${d}: ${e.message})`); }
  }
}


try {
  process.exit(runParent());
} catch (e) {
  /* An unexpected throw must never land on exit 1, because exit 1 means "the control worked". */
  console.error(`negative-gate: ${(e && e.stack) || e}`);
  console.error('The gate did not run to a verdict. Exiting 0 — exit 1 means every case held and the');
  console.error('mutation diverged, and a gate that crashed has certified neither.');
  cleanup();
  process.exit(0);
}
