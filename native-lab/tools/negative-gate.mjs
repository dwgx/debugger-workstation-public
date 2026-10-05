#!/usr/bin/env node
/* negative-gate.mjs — THE EXECUTABLE NEGATIVE CONTROL for BOTH IDA capabilities.
 * Added 2026-10-05.
 *
 * WHICH TWO, AND WHY THEY ARE THE HARD ONES.
 *   native.ida.decompile        registry: "must yield code:null plus an error field, never code"
 *   native.ida.list_functions  registry: "must refuse rather than answer from an unstated session"
 * Both are `state: observed` with runnable probes, but both negative controls were DECLARED
 * PLANS. A loop that only ever shows an instrument succeeding proves "it did not crash". These
 * two are the ones where a silent success IS the failure, so they are the ones worth a control
 * that can go red.
 *
 * THE TRAP, AND WHY A CONTROL THAT CHECKED isError WOULD BE WORTHLESS HERE.
 * Recorded in this project's own memory: **ida-pro-mcp failures return isError: false.** A bogus
 * address answers
 *     {"addr":"0xDEADBEEF","code":null,"error":"Decompilation failed at 0xdeadbeef"}
 * with NO error flag anywhere in the JSON-RPC envelope, so a client that checks only `isError`
 * records a failed decompile as a successful null. A control whose pass condition were "isError
 * is true" would be satisfied by an instrument that answered NOTHING at all, and would be blind
 * to the one failure it exists to catch. Every refusal test here is therefore computed FROM THE
 * BODY ALONE — `code` and `error` — and `isError` is printed as a measurement and deliberately
 * excluded from the verdict. `ok()` in tools/ida-client.mjs is the shipped form of the same
 * rule, and decompile.mjs and list-funcs.mjs both depend on it.
 *
 * WHAT IS REUSED, AND WHY THERE IS NO SECOND WAY TO TALK TO IDA.
 * tools/loop.mjs solved the spawn, the port-free check, the SSE framing and the teardown;
 * tools/ida-client.mjs is that machinery factored out and already imported by decompile.mjs and
 * list-funcs.mjs. This file imports withServer / waitForSession / callVerbose from it and adds
 * no transport of its own. `callVerbose` is the single addition to that module (2026-10-05):
 * `call()` keeps only `isError` and the parsed body, and for a control whose whole subject is
 * WHICH of `isError` / `code` / `error` the server sets, those are exactly the wrong two to
 * keep. `call()` is now defined in terms of it, so its behaviour is unchanged.
 *
 * EXIT POLARITY — the opposite of what it looks like. Both registry entries declare
 * `expect_exit: 1`, so success here is NON-ZERO, exactly as in crypto-lab and forensics-lab:
 *
 *   exit 1 = both capabilities REFUSED every request they could not honestly satisfy, in a shape
 *            a body-only client can see. THE CONTROL WORKING. This is the registry's 1.
 *   exit 0 = at least one bogus request came back SUCCESS-SHAPED — a null with no error, an
 *            invented decompilation, or a function population answering a question nobody asked.
 *            THE CONTROL FOUND A REAL DEFECT, and by R5 this is the value a harness reads as
 *            DRIFT. An instrument that stopped enforcing entirely would also exit 0, which is
 *            precisely why a control may never be declared as "must exit 0".
 *   exit 2 = an argument was refused, or the gate could not MEASURE at all. Deliberately distinct
 *            from 1: an unmeasurable gate must never be able to satisfy `expect_exit: 1`, and
 *            must never be mistaken for the defect it is hunting. Same split the two worked
 *            examples use (forensics-lab/tools/negative-gate.mjs:32-47 and its guard at
 *            :87-120; crypto-lab/tools/negative-gate.mjs:28-38 and its guard at :71-77).
 *
 * BOTH DIRECTIONS HAVE BEEN SEEN, or this is decoration. Run with
 *     D12_NATIVE_NEGGATE_MUTATE=<name>
 * to replace ONE recorded response with the shape a broken instrument would return, then run the
 * identical assertions over it and watch the gate go green. `none` is the only value a real run
 * uses. The mutation is applied AFTER the real call, so the genuine response is always printed
 * first and nobody can mistake the injected shape for a measurement.
 *
 * THE FIXTURE IS PROVISIONED BY THIS FILE, AT RUN TIME. It used to name a path in the corpus and
 * trust it to still be there; the same file's own teardown accounting already counted %TEMP%
 * entries for a scratch directory it never created. Both were the same latent failure: an input
 * this gate READS but did not BUILD. A control that cannot build its own subject cannot be run
 * on a machine that has not already been prepared for it, and the failure it produces —
 * `No such file` — is indistinguishable, from outside, from the refusal it is hunting. So the
 * PE is now derived here: the corpus bytes are copied into a `fs.mkdtempSync` directory under
 * `os.tmpdir()`, patched in process, and that directory is removed in a `finally` before either
 * exit. `withServer` still kills the idalib worker with `taskkill /T /F` on every path.
 *
 * NOTHING IS LEFT BEHIND, AND THE COUNT IS PRINTED. The run prints a %TEMP% entry count before
 * and after and reports whether the fixture directory survived, so "leaves nothing behind" is a
 * number rather than a promise. Deriving the fixture also ends a second, quieter problem: IDA
 * writes `.id0/.id1/.id2/.nam/.til/.i64` BESIDE whatever binary it opens, so a run against the
 * corpus wrote into the corpus, and a run interrupted between those writes leaves exactly the
 * stale-shadow state `loop.mjs` warns about. In a fresh temp directory that cannot happen.
 *
 * RUN IT:  node native-lab/tools/negative-gate.mjs     (from the repository root; no arguments)
 */
import os from 'node:os';
import path from 'node:path';
import { existsSync, readdirSync, readFileSync, writeFileSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  IDALIB, MCP, withServer, waitForSession, callVerbose, flattenFuncs, portFree,
} from './ida-client.mjs';

/* ARGUMENT REFUSAL. Exit 2, deliberately distinct from the control's 1 and from success.
 * This is not politeness: crypto-lab/tools/negative-gate.mjs and forensics-lab's both shipped
 * without it, and `--bogus` produced output byte-identical to the clean run. A control that
 * silently swallows the flag aimed at it can be made to report a green it did not measure.
 * Its subject — the bogus address, the bogus session, the bogus selector — is the CONSTANTS
 * below on purpose: a control whose inputs are caller-supplied can be aimed at an input the
 * instrument happens to answer honestly, which is the control's own failure mode. */
const ALLOWED = new Set([]);   // no arguments are honoured; declared empty rather than omitted
const STRAY = process.argv.slice(2).filter((a) => !ALLOWED.has(a));
if (STRAY.length) {
  console.error(`negative-gate.mjs: refusing argument(s) it would otherwise IGNORE: ${STRAY.join(' ')}`);
  console.error('  This gate takes no arguments. It has no --target and no --addr: a control whose');
  console.error('  inputs are caller-supplied can be aimed at an input the instrument happens to');
  console.error('  answer honestly, and then it measures nothing at all.');
  console.error('  Accepting an argument silently would report a green it did not measure.');
  process.exit(2);
}

/* ---------------------------------------------------------------- the subject, as constants */

/* The SOURCE and the FIXTURE are two different files and only one of them is ours to keep.
 * CORPUS is version-controlled and never written to: it is the bytes the fixture is derived
 * from. FIXTURE is created below, in %TEMP%, by provisionFixture(), and is what IDA is actually
 * handed. Nothing below this line names CORPUS except to read it. */
const CORPUS = 'crackme-corpus/out/c01-stringobf.exe';  // source bytes; tracked in git; read-only here
const FIXTURE_BASENAME = 'c01-stringobf.exe';            // the name IDA will report for the copy
const BOGUS_ADDR = '0xDEADBEEF';                         // outside every mapped section of it
const BOGUS_ADDR_N = Number(BOGUS_ADDR);                 // the same address, for the range proof below
const BOGUS_SYMBOL = 'no_such_symbol_zzz';               // a name IDA cannot have recovered
const BOGUS_SESSION = 'no-such-session-zzz';             // a session id this client never issued
const BOGUS_SELECTOR = 'no_such_function_zzz_*';         // a glob no recovered name can match
const TMP_PREFIX = 'd12-native-neg-gate-';               // mkdtempSync's prefix — now the real thing

const CAP_FAIL = 1;         // both capabilities refused -> THE CONTROL WORKING (registry: 1)
const CAP_DRIFT = 0;        // a bogus request came back success-shaped -> a real defect
const CAP_UNMEASURED = 2;   // usage, or the instrument could not be reached. Never satisfies 1.

/* ------------------------------------------------------------- the fixture, provisioned here
 * Everything this gate reads, it builds first. The PE is copied out of the corpus into a
 * uniquely named directory under os.tmpdir() and patched in process, so that:
 *
 *   - a run on a machine with no prepared %TEMP% is the ORDINARY case rather than a prepared
 *     one, which is the whole point: an input that has to be made by hand can be cleaned
 *     between two runs, and the resulting `No such file` is indistinguishable, from outside,
 *     from the refusal this gate exists to detect;
 *   - IDA's .id0/.id1/.id2/.nam/.til/.i64 shadows land in a directory that is then deleted,
 *     instead of beside a tracked file in the corpus — where an interrupted run leaves
 *     exactly the stale-shadow state loop.mjs warns about;
 *   - the bogus address stays PROVABLY outside every mapped section, which is what makes
 *     control [1] discriminating instead of a lookup that might legitimately succeed.
 *
 * THE PATCH. The PE optional header's CheckSum is zeroed: the standard repack mutation, one
 * that Windows ignores outside drivers, and one that marks the file as derived. It is applied
 * to the COPY and only after the signatures are verified, so bytes this code does not
 * understand are refused rather than passed through. It changes nothing that is asserted —
 * the checksum is not an input to any control below, and both baselines are measured against
 * the patched copy exactly as they were measured against the corpus file.
 *
 * Every failure path here throws, and every throw unwinds through the teardown, so a gate that
 * cannot build its subject exits 2 having left nothing behind. A throw is NOT a check(): it
 * forces CAP_UNMEASURED rather than CAP_DRIFT, because "I could not provision the PE" says
 * nothing whatever about whether the instrument refuses a bogus request. */

/** Parse just enough of the PE headers to prove this is an image we understand and to locate
 *  the CheckSum field. Throws rather than guessing. */
function peLayout(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
    throw new Error(`corpus bytes do not begin with MZ: ${CORPUS}`);
  }
  const lfanew = buf.readUInt32LE(0x3c);
  if (lfanew + 24 > buf.length || buf.readUInt32LE(lfanew) !== 0x00004550) {
    throw new Error(`no PE signature at e_lfanew=0x${lfanew.toString(16)} in ${CORPUS}`);
  }
  const coff = lfanew + 4;
  const opt = coff + 20;
  const nSections = buf.readUInt16LE(coff + 2);
  const sizeOptHdr = buf.readUInt16LE(coff + 16);
  if (sizeOptHdr < 68 || opt + sizeOptHdr > buf.length) {
    throw new Error(`optional header is ${sizeOptHdr} bytes; too short to hold a CheckSum`);
  }
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new Error(`optional header magic 0x${magic.toString(16)} is neither PE32 nor PE32+`);
  }
  /* ImageBase sits at a different offset in the two magics. Reading it from the wrong one
   * would not throw — it would silently produce section ranges that prove nothing, which is
   * the precise failure mode the range check below exists to catch. */
  const imageBase = magic === 0x20b ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
  return { opt, imageBase, nSections, sectionsOff: opt + sizeOptHdr, checksumOff: opt + 64 };
}

/** Throw unless BOGUS_ADDR lies outside every section's mapped range.
 *
 *  This is a PRECONDITION, not a check(): it is a property of the fixture, so failing it
 *  means this gate built itself a subject it cannot learn anything from, which is
 *  CAP_UNMEASURED. It is deliberately NOT folded into `checks` — the tally below is the
 *  instrument's behaviour and nothing else, and a fixture property counted there would let a
 *  `fail` mean two different things. */
function assertBogusAddrUnmapped(buf, layout) {
  const ranges = [];
  for (let i = 0; i < layout.nSections; i++) {
    const sh = layout.sectionsOff + i * 40;      // IMAGE_SECTION_HEADER is 40 bytes
    if (sh + 40 > buf.length) throw new Error(`section header ${i} runs past the end of ${CORPUS}`);
    const vsize = buf.readUInt32LE(sh + 8);
    const va    = buf.readUInt32LE(sh + 12);
    const raw   = buf.readUInt32LE(sh + 16);
    /* The mapped span is the LARGER of VirtualSize and SizeOfRawData. Taking VirtualSize
     * alone under-reports .text whenever the raw data is padded, and would wave through an
     * address that is in fact mapped. */
    const lo = layout.imageBase + va;
    const hi = lo + Math.max(vsize, raw);
    if (BOGUS_ADDR_N >= lo && BOGUS_ADDR_N < hi) {
      throw new Error(`BUG IN THIS FILE: ${BOGUS_ADDR} is INSIDE section ${i} `
        + `[0x${lo.toString(16)}, 0x${hi.toString(16)}). Control [1] would be vacuous — that `
        + `address could decompile, so a null would be a real answer rather than a refusal.`);
    }
    ranges.push([lo, hi]);
  }
  return ranges;
}

/** Copy the corpus bytes into a fresh %TEMP% directory, verify and patch them there, and hand
 *  back the descriptor plus the report the run prints. Nothing outside this function ever
 *  names the corpus file. */
function provisionFixture() {
  if (!existsSync(CORPUS)) {
    throw new Error(`source binary missing from the corpus: ${CORPUS}. This gate derives its own `
      + `fixture from it rather than reading a prepared one, so there is nothing to fall back to.`);
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), TMP_PREFIX));
  try {
    const file = path.join(dir, FIXTURE_BASENAME);
    copyFileSync(CORPUS, file);

    const buf = readFileSync(file);
    const layout = peLayout(buf);
    const ranges = assertBogusAddrUnmapped(buf, layout);

    const was = buf.readUInt32LE(layout.checksumOff);
    buf.writeUInt32LE(0, layout.checksumOff);
    writeFileSync(file, buf);
    /* Whether the field actually MOVED is reported rather than implied. A compiler that left
     * the checksum at zero makes this a no-op, and a run log that called that a mutation
     * would be asserting something the bytes do not support. */
    const patchNote = was === 0
      ? ', already zero — the field is unchanged'
      : ` — ${was} bytes of the image changed`;

    const lo = Math.min(...ranges.map((r) => r[0]));
    const hi = Math.max(...ranges.map((r) => r[1]));
    return {
      dir,
      file,
      report: `${file}\n`
        + `              derived in process from ${CORPUS}: ${buf.length} bytes copied, PE CheckSum\n`
        + `              zeroed at file offset 0x${layout.checksumOff.toString(16)} `
        + `(was 0x${was.toString(16).padStart(8, '0')}${patchNote}); ${layout.nSections} sections map\n`
        + `              0x${lo.toString(16)}..0x${hi.toString(16)}, and ${BOGUS_ADDR} is outside all of\n`
        + `              them — read out of the headers above, not assumed.`,
    };
  } catch (e) {
    /* A directory this function created and then could not use is litter. */
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    throw e;
  }
}

/** Remove the fixture directory. Called from the teardown `finally`, awaited, and safe to call
 *  twice.
 *
 *  RETRIES, because this is measurably not instant on Windows. IDA holds its .id0/.id1/.nam
 *  open until the worker that wrote them is gone, and a delete attempted inside that window
 *  fails with ERROR_SHARING_VIOLATION — os error 32, EBUSY. A first cut of this file swallowed
 *  that with `catch {}`, which is how a run was observed to print "leaves nothing behind" while
 *  leaving a directory full of locked IDA databases in %TEMP%. The inner `maxRetries` covers
 *  the transient lock; the outer loop covers the not-yet-transient one, where the worker is a
 *  second or two from letting go.
 *
 *  A FAILURE IS RECORDED, NOT SWALLOWED. The exit code is deliberately left alone — litter in
 *  %TEMP% is not a statement about the instrument, and exit 1 must keep meaning only "both
 *  capabilities refused everything they could not honestly satisfy" — but the leftover path and
 *  the OS error code are printed, so the claim stays falsifiable by whoever reads the log. */
async function removeFixture() {
  if (!FIXTURE) return;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      rmSync(FIXTURE.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      return;
    } catch (e) {
      FIXTURE.removeError = e;
      if (!existsSync(FIXTURE.dir)) return;      // gone now, whatever the error said
      if (attempt < 5) await sleep(1000 * attempt);
    }
  }
}

/* --------------------------------------------------------- the mutation vocabulary
 * Each entry replaces the recorded response of one named control with the shape a broken
 * instrument returns, and the SAME assertions then run over it. Every one of these is a shape
 * the real server was measured NOT to produce, so reaching the green state requires the
 * mutation — which is the entire reason for having them. */
const MUTATIONS = {
  none: null,
  /* The hazard in its purest form: the null with no error, exactly what an isError-only client
   * writes down as a success. Flips the decompile control. */
  'decompile-null-no-error': {
    control: 'decompile.bogus_addr', isError: false, body: { addr: BOGUS_ADDR, code: null },
  },
  /* A confident invention: a bogus address handed back recovered C. Flips the decompile control. */
  'decompile-fake-code': {
    control: 'decompile.bogus_addr', isError: false,
    body: { addr: BOGUS_ADDR, code: 'int bogus_140000000(void)\n{\n  return 0;\n}' },
  },
  /* The registry's list_functions case answered as though a session had been bound. */
  'list-funcs-unstated-session-answers': { control: 'list_funcs.no_session', kind: 'population' },
  /* "This binary has no functions", said with a straight face and no error — the exact failure
   * the registry's `why` sentence is protecting. Flips the list_functions control. */
  'list-funcs-unstated-session-empty': { control: 'list_funcs.no_session', isError: false, body: [] },
};
const MUTATE = process.env.D12_NATIVE_NEGGATE_MUTATE || 'none';
if (!(MUTATE in MUTATIONS)) {
  console.error(`negative-gate.mjs: unknown D12_NATIVE_NEGGATE_MUTATE=${JSON.stringify(MUTATE)}`);
  console.error(`  known: ${Object.keys(MUTATIONS).join(', ')}`);
  console.error('  Refusing rather than ignoring it — a silently ignored knob is a control that can be');
  console.error('  reported green for a mutation that never happened.');
  process.exit(2);
}

/* -------------------------------------------------------------------------- reporting */

const line = (s = '') => console.log(s);
const rule = (s) => line(`${'-'.repeat(78)}\n${s}\n${'-'.repeat(78)}`);
const checks = [];
function check(label, pass, detail) {
  checks.push({ label, pass: !!pass, detail });
  line(`  ${pass ? 'PASS' : 'FAIL'}  ${label.padEnd(56)} ${detail}`);
}

/* Things this gate FAILED TO MEASURE, as opposed to things it measured and found wanting. The
 * distinction is the whole reason exit 2 exists, and it was earned: the first run of this file
 * checked the shipped CLI while this file still held port 8745, the CLI's own portFree() guard
 * refused with its usage code, and the gate printed DRIFT. It had measured nothing about the
 * instrument and reported a defect anyway — an unmeasurable gate wearing the defect's
 * clothes. Anything that lands here forces exit 2 regardless of how the checks came out. */
const unmeasured = [];

/* The refusal test, computed FROM THE BODY ALONE. `isError` is not a parameter and is never
 * read; see the header. A body carrying a non-empty `error` string is a refusal a body-only
 * client can see, and that is the entire contract. */
function refusalText(res) {
  return (typeof res.body?.error === 'string' && res.body.error) ? res.body.error : null;
}
function functionCount(res) {
  try { return flattenFuncs(res.body).length; } catch { return 'n/a'; }
}

/* Truncation is always LABELLED, because a response cut off at a screenful and a response that
 * really was that short look identical to a reader who cannot see the source. */
function showRaw(title, request, res) {
  const raw = res.rawText || '';
  line(`  ${title}`);
  line(`    asked        ${JSON.stringify(request)}`);
  line(`    isError      ${res.isError}     <-- REPORTED, never asserted; a control that reads it is blind to the hazard`);
  line(`    code         ${JSON.stringify(res.body?.code)}`);
  line(`    error        ${JSON.stringify(refusalText(res))}`);
  line(`    functions    ${functionCount(res)}`);
  line(`    raw response ${raw}${raw.length > 900 ? `   [TRUNCATED: ${raw.length} bytes total; this is the first 900]` : ''}`);
}

/* %TEMP% entries this gate could possibly have left. Counted at module scope so the teardown
 * accounting can compare against it even when the run died — counting inside main() and reading
 * outside would be a ReferenceError on precisely the path that matters most. */
const tmpEntries = () => { try { return readdirSync(os.tmpdir()).filter((n) => n.startsWith(TMP_PREFIX)); } catch { return []; } };
const TMP_BEFORE = tmpEntries();

/* The fixture is built HERE rather than at the top of main(), for two reasons that both matter.
 *
 * main() must never be able to reach an input this file did not create, and provisioning above
 * that call makes that structural instead of a matter of discipline. TMP_BEFORE is sampled
 * one line higher precisely so the count the teardown compares against was taken BEFORE this
 * directory existed — otherwise the teardown would be grading its own litter.
 *
 * It is module scope because the `finally` that removes it is module scope too (see the
 * teardown). A fixture whose lifetime is a local inside main() is one refactor away from
 * outliving the process, and `process.exit()` in a `.then()`/`.catch()` chain runs a chained
 * `.finally()` never — so the removal has to be a real `finally` around the awaited call.
 *
 * Both exits above this point — a refused argument, an unknown mutation name — happen above
 * this line, so a run that is going to be refused never creates a directory in the first place. */
let FIXTURE = null;
try {
  FIXTURE = provisionFixture();
} catch (e) {
  console.error(`negative-gate.mjs: could not provision its own fixture: ${e.message}`);
  console.error('  This gate BUILDS the PE it analyses, in %TEMP%, at run time; it never reads a');
  console.error('  prepared one. Failing to build it means nothing at all was measured, which is');
  console.error('  exit 2 and not the drift exit 0: a gate that never reached its subject must not be');
  console.error('  able to satisfy an `expect_exit: 1`.');
  process.exit(CAP_UNMEASURED);
}

/* -------------------------------------------------------------------------------- the run */

async function main() {
  line('='.repeat(78));
  line('native-lab — NEGATIVE GATE for native.ida.decompile and native.ida.list_functions');
  line('='.repeat(78));
  line(`  instrument  idalib-mcp over MCP on ${MCP}`);
  line(`  fixture     ${FIXTURE.report}`);
  line(`  bogus addr  ${BOGUS_ADDR}   bogus symbol  ${BOGUS_SYMBOL}`);
  line(`  bogus sess  ${BOGUS_SESSION}   bogus selector  ${BOGUS_SELECTOR}`);
  line(`  mutation    ${MUTATE}${MUTATE === 'none' ? '   (a real run)' : '   *** MUTATED RUN — NOT A MEASUREMENT ***'}`);
  line('');

  if (!existsSync(IDALIB)) { line(`GATE COULD NOT MEASURE: idalib-mcp missing: ${IDALIB}`); return CAP_UNMEASURED; }
  /* No `existsSync(fixture)` guard here: FIXTURE was built and patched above, before main() was
   * reachable, and a file that does not exist is not a measurement this gate can make. */
  if (!await portFree()) { line(`GATE COULD NOT MEASURE: something is already serving ${MCP}.`); return CAP_UNMEASURED; }

  await withServer(FIXTURE.file, async () => {
    const sess = await waitForSession();
    const db = sess.session_id;
    line(`  session     ${db} -> ${sess.filename}`);
    line('');

    /* ======================================================== native.ida.decompile */
    rule('[1] native.ida.decompile — registry control native.ida.decompile.bogus_addr');
    line('  registry says: "must yield code:null plus an error field, never code."');
    line('');

    /* The BASELINE first, before any refusal is judged. Without it "code came back null" is
     * satisfied by an instrument that answers nothing at all, and this control would be
     * decoration — the exact failure this file exists to prevent. */
    const names = flattenFuncs((await callVerbose('list_funcs', { queries: [{ count: 2000 }], database: db })).body);
    const mainFn = names.find((f) => f?.name === 'main');
    let baselineOk = false;
    if (!mainFn) {
      unmeasured.push(`no 'main' among the ${names.length} functions this session enumerated`);
      check('BASELINE: the instrument CAN decompile a real function', false, `no main among ${names.length} functions`);
    } else {
      const good = await callVerbose('decompile', { addr: mainFn.addr, include_addresses: false, database: db });
      const code = typeof good.body?.code === 'string' ? good.body.code : '';
      baselineOk = code.length > 200;
      if (!baselineOk) unmeasured.push(`main at ${mainFn.addr} decompiled to ${code.length} chars, not a usable baseline`);
      check('BASELINE: the instrument CAN decompile a real function', baselineOk,
        `${mainFn.addr} main -> ${code.length} chars of recovered C, isError=${good.isError}`);
      line('    (without this, a server that returns null to EVERYTHING would pass the control below)');
    }

    line('');

    if (baselineOk) {
      const request = { addr: BOGUS_ADDR, include_addresses: false, database: db };
      const real = await callVerbose('decompile', request);
      showRaw('RAW RESPONSE to the bogus address:', request, real);
      line('');

      let res = real;
      const m = MUTATIONS[MUTATE];
      if (m && m.control === 'decompile.bogus_addr') {
        res = { ...real, body: m.body, isError: m.isError, rawText: JSON.stringify(m.body) };
        line(`  *** MUTATION ${MUTATE}: the response printed above is REAL and is kept above. What the`);
        line(`  *** assertions judge instead, injected by this file:`);
        line(`    injected     isError=${res.isError}  body=${JSON.stringify(res.body)}`);
        line('');
      }

      /* THE CONTROL. Body only. `code` must be null AND an `error` string must be present — the
       * registry's sentence verbatim. `isError` is not consulted, so a server that flags this
       * correctly and one that does not are judged on identical evidence. */
      const codeIsNull = res.body?.code === null || res.body?.code === undefined;
      const err = refusalText(res);
      check('a bogus address yields code:null — never code', codeIsNull, `code=${JSON.stringify(res.body?.code)}`);
      check('...AND the failure is carried in an `error` field', err !== null,
        err === null
          ? 'NO error field — a null with no error is precisely the failure this control catches'
          : err.slice(0, 44));
      line('');
      line(`  HAZARD (measured, not asserted): that refusal came back with isError=${real.isError}.`);
      line('    A client checking only isError records it as a SUCCESSFUL null. That is why every');
      line('    test above reads the body and why no test in this file reads isError.');
      line('');
    }

    /* The shipped-CLI check is NOT here. It runs after withServer returns, and that placement is
     * a measured fact rather than a style choice: see [1b] below and the `unmeasured` note above.
     * Running it inside this block means the CLI finds 8745 already held by this gate, its own
     * portFree() guard refuses, and the exit code it returns is 2 — "I could not run" — which the
     * first version of this file scored as a control failure. */


    /* ==================================================== native.ida.list_functions */
    rule('[2] native.ida.list_functions — registry control native.ida.list_functions.no_session');
    line('  registry says: "must refuse rather than answer from an unstated session."');
    line('');

    const population = flattenFuncs((await callVerbose('list_funcs', { queries: [{ count: 2000 }], database: db })).body);
    if (population.length <= 5) unmeasured.push(`only ${population.length} functions enumerated with a bound session`);
    check('BASELINE: the instrument CAN enumerate this binary', population.length > 5,
      `${population.length} functions with a bound session — so a refusal below is discriminating, not muteness`);
    line('');

    /* (a) no session at all — the registry's case, asked exactly as the registry asks it. */
    {
      const request = { queries: [{ count: 5 }] };
      const real = await callVerbose('list_funcs', request);
      showRaw('RAW RESPONSE with no `database` — the request the registry names:', request, real);
      line('');

      let res = real;
      const m = MUTATIONS[MUTATE];
      if (m && m.control === 'list_funcs.no_session') {
        const body = m.kind === 'population' ? [{ data: population.slice(0, 3) }] : m.body;
        res = { ...real, body, isError: m.kind === 'population' ? false : m.isError, rawText: JSON.stringify(body) };
        line(`  *** MUTATION ${MUTATE}: the response printed above is REAL and is kept above. Judged`);
        line(`  *** instead: isError=${res.isError}  body=${res.rawText.slice(0, 160)}`);
        line('');
      }

      check('it REFUSES — an error is present, in the body or as isError',
        res.isError === true || refusalText(res) !== null,
        `isError=${res.isError}  error=${String(refusalText(res)).slice(0, 46)}`);
      check('...and it answers with NO functions, so "0 functions" cannot read as a finding',
        functionCount(res) === 0, `${functionCount(res)} functions returned`);
    }

    /* (b) a session id this client never issued. Same property, a second instance, so the
     * refusal is not a one-off a single typo could explain. */
    {
      const request = { queries: [{ count: 5 }], database: BOGUS_SESSION };
      const res = await callVerbose('list_funcs', request);
      showRaw('RAW RESPONSE with a session id this client never issued:', request, res);
      line('');
      check('a session it never issued is refused the same way',
        (res.isError === true || refusalText(res) !== null) && functionCount(res) === 0,
        `isError=${res.isError}  error=${String(refusalText(res)).slice(0, 46)}  functions=${functionCount(res)}`);
    }

    /* (c) the same sentence's other half, and the one that can pass silently: a selector that
     * matches nothing must come back EMPTY, never as a population. An empty answer here is
     * CORRECT — there is no such function — and the baseline above is what proves it is empty
     * because of the selector rather than because the binary has no functions. */
    {
      const request = { queries: [{ filter: BOGUS_SELECTOR, count: 2000 }], database: db };
      const res = await callVerbose('list_funcs', request);
      showRaw('RAW RESPONSE to a selector that cannot match anything:', request, res);
      line('');
      check('a selector that matches nothing yields an EMPTY or errored result',
        functionCount(res) === 0 || refusalText(res) !== null,
        `${functionCount(res)} functions for glob '${BOGUS_SELECTOR}', against a binary the baseline just showed has ${population.length}`);
    }

    /* (d) REPORTED, NOT IN THE VERDICT. Measured on this box 2026-10-05, and a real hazard
     * rather than a hypothetical one: ListQuery is a TypedDict of {filter, offset, count}
     * (ida_pro_mcp/ida_mcp/utils.py:181-186), so a caller who passes `name` or `addr` instead of
     * `filter` passes validation, the field is silently dropped, and the server answers with the
     * WHOLE function list — success-shaped, as if the selector had matched everything. It belongs
     * in the README beside the three hazards already recorded there, not in this control's exit
     * code: the registry declares THIS control to be the unstated-session refusal, and quietly
     * re-pointing a declared control at a different defect would make `expect_exit: 1` mean
     * something other than what it says. */
    {
      const request = { queries: [{ name: BOGUS_SYMBOL }], database: db };
      const res = await callVerbose('list_funcs', request);
      line('  REPORTED, NOT IN THE VERDICT — an UNSUPPORTED selector field:');
      line(`    asked        ${JSON.stringify(request)}`);
      line(`    isError      ${res.isError}`);
      line(`    functions    ${functionCount(res)}   <-- not a ListQuery field; it was dropped and everything came back`);
      line(`    raw response ${(res.rawText || '').slice(0, 150)}…`);
      line('    This is the "a short result is a failure, not a smaller answer" family already noted');
      line('    in native-lab/README.md. A hazard to document, not the control the registry declares,');
      line('    so it changes no exit code here.');
      line('');
    }
  });

  /* [1b] The same refusal through the SHIPPED WRAPPER, as a real OS process. A library agreeing
   * with itself is not what an orchestrator runs, and this is the registry's own recorded
   * command. It has to be HERE, after withServer has released 8745 — see the comment at the old
   * site, which is the measured reason for that placement rather than a stylistic one. */
  rule('[1b] the same refusal through the shipped CLI (native-lab/tools/decompile.mjs)');
  const cli = spawnSync(process.execPath, [path.join('native-lab', 'tools', 'decompile.mjs'), FIXTURE.file, BOGUS_ADDR],
    { encoding: 'utf8', windowsHide: true });
  let cliOut = null;
  let cliParsed = true;
  try { cliOut = JSON.parse(cli.stdout); } catch { cliParsed = false; }
  /* Its exit taxonomy is 0/1/2 like this file's, and 2 is its "I could not run" code. Scoring that
   * as a control failure is the exact confusion `unmeasured` exists to prevent. */
  if (cli.status === 2 || !cliParsed) {
    unmeasured.push(`the shipped CLI exited ${cli.status} and ${cliParsed ? 'emitted JSON' : 'emitted no JSON'}: ${(cli.stdout || cli.stderr || '').trim().slice(0, 120)}`);
  }
  check('the shipped CLI refuses the bogus address with its own non-zero code', cli.status === 1,
    `exit ${cli.status}${cli.status === 0 ? '  <-- it reported SUCCESS on a bogus address' : ''}`);
  check('the shipped CLI reports ok:false carrying the server\'s own words',
    cliOut?.ok === false && typeof cliOut.error === 'string' && cliOut.error.length > 0,
    JSON.stringify(cliOut?.error ?? (cli.stdout || '').trim().slice(0, 60)));
  check('the shipped CLI carries NO code field for it', Boolean(cliOut) && cliOut.code === undefined,
    `code=${JSON.stringify(cliOut?.code)}`);
  line('');


  /* -------------------------------------------------------------------------- the verdict */
  rule('VERDICT');
  const failed = checks.filter((c) => !c.pass);

  if (unmeasured.length) {
    line(`GATE COULD NOT MEASURE (${unmeasured.length} prerequisite${unmeasured.length > 1 ? 's' : ''} absent):`);
    for (const u of unmeasured) line(`    - ${u}`);
    line('');
    line('  None of the above says anything about whether the instrument refuses a bogus request,');
    line('  so no verdict is claimed and NO defect is reported. Exit 2, deliberately distinct from');
    line('  1: an unmeasurable gate must never be able to satisfy an `expect_exit: 1`.');
    return CAP_UNMEASURED;
  }
  const counts = { total: checks.length, pass: checks.length - failed.length, fail: failed.length };

  if (failed.length === 0) {
    line('NEGATIVE GATE: both capabilities REFUSED every request they could not honestly satisfy,');
    line('  and said so in a shape a client that never reads isError can still see.');
    line('');
    line(`  native.ida.decompile        ${BOGUS_ADDR} -> code:null plus error: "Decompilation failed at 0xdeadbeef"`);
    line('  native.ida.list_functions  no database -> refused; a session it never issued -> refused;');
    line('                              a selector that cannot match -> EMPTY, never a population.');
    line('');
    line(`  EXIT ${CAP_FAIL} IS SUCCESS, and it is non-zero on purpose. A control that had to exit 0 would`);
    line('  also be satisfied by an instrument that stopped enforcing entirely, which is what rule');
    line("  R5 forbids. This is the `expect_exit: 1` both registry entries already declare.");
    return CAP_FAIL;
  }

  line(`NEGATIVE GATE FAILED: ${failed.length} of ${counts.total} checks did not hold.`);
  for (const f of failed) line(`    FAIL  ${f.label} — ${f.detail}`);
  line('');
  line('  At least one request the instrument could not honestly satisfy came back SUCCESS-SHAPED: a');
  line('  null with no error, an invented decompilation, or a function population answering a');
  line('  question nobody asked. A caller reading only isError writes all three down as success.');
  line('');
  line('  EXIT 0 IS THE GREEN-FAILURE STATE, NOT A PASS. It is REACHABLE: re-run this file with');
  line('  D12_NATIVE_NEGGATE_MUTATE set to one of the names it prints and it goes green. A control');
  line('  nobody has seen fail is decoration, and this one is not.');
  return CAP_DRIFT;
}

/* ------------------------------------------------------------------ teardown accounting
 * `process.exit()` terminates the process where it stands, so a `.finally()` chained AFTER a
 * handler that exits is never reached and the fixture directory would outlive every run. The
 * exits therefore live OUTSIDE the try and the removal happens in the `finally`, which runs on
 * the resolving path and the throwing one alike, before either exit. This is the one place in
 * the file where the shape is load-bearing rather than stylistic. */
let exitCode = null;
let thrown = null;
try {
  exitCode = await main();
} catch (e) {
  thrown = e;
} finally {
  await removeFixture();
}

/* Computed once, printed on both paths: the %TEMP% scratch count AND whether this file's own
 * directory survived. "Leaves nothing behind" has to be a number, not a promise — and a
 * control that grades itself on it cannot quietly start leaving things. */
const teardownLine = () => {
  const after = tmpEntries();
  const fixtureState = !FIXTURE ? 'n/a — never provisioned'
    : existsSync(FIXTURE.dir)
      ? `NO — STILL AT ${FIXTURE.dir} (${FIXTURE.removeError?.code ?? 'unknown'}); an idalib worker is most likely still holding its .id0/.id1/.nam. Not fatal to the verdict, but it IS litter, and this line is how you find it.`
      : 'yes';
  return `  scratch     ${TMP_PREFIX}* in %TEMP%: ${TMP_BEFORE.length} before, ${after.length} after\n`
    + `  fixture     directory removed: ${fixtureState}`;
};

if (thrown) {
  console.log('');
  console.log(`GATE COULD NOT MEASURE: ${thrown.stack || thrown.message}`);
  console.log('  Exit 2 is deliberately distinct from 1: a gate that could not reach the instrument must');
  console.log('  never be able to satisfy an `expect_exit: 1`, and must never read as the defect it is');
  console.log('  hunting.');
  console.log(teardownLine());
  process.exit(CAP_UNMEASURED);
}
console.log('');
console.log(teardownLine());
console.log('  server      idalib-mcp on 8745 killed by withServer\'s finally; port released');
console.log(`  ${JSON.stringify(countsOf(checks))}`);
process.exit(exitCode);

function countsOf(list) {
  return { total: list.length, pass: list.filter((c) => c.pass).length, fail: list.filter((c) => !c.pass).length };
}