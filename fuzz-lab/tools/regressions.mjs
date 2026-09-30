/* regressions.mjs — the fixed findings, as bytes, so they cannot come back silently.
 *
 * A fix with no test is a fix that gets reverted by the next person who reads the code
 * and thinks the guard is redundant. So each finding this lab produced is stored here
 * as a REDUCED INPUT — small, hand-checkable, and in the gitignore-safe form the rest
 * of the lab uses — and `loop.mjs` re-runs every one of them on every invocation.
 *
 * The assertion for each is deliberately narrow and deliberately behavioural:
 *
 *     the reduced case must no longer be an UNCAUGHT exception
 *
 * It is not "must parse", because most of these inputs are still malformed and SHOULD be
 * rejected. It is not "must not hang", because a hang and a throw are different defects
 * and lumping them would let a fix that converts a throw into a 3-second stall pass. The
 * property under test is exactly the one the defect violated: hostile input produces a
 * declared outcome instead of an uncaught one.
 *
 * The reduced bytes are built by the small constructors below rather than pasted in as
 * base64, for the reason `.gitignore` states: they are hostile input against parsers this
 * repository ships, and a named constructor is also a readable sentence about what the
 * input IS -- `pfTruncatedHeader()` is a 16-byte record whose entry-count field is absent
 * -- where a base64 blob is opaque in a diff.
 */

/* ------------------------------------------------------------------ the cases */

/** Build a 16-byte D12PF record: magic + version + runCount, nothing else. */
function pfTruncatedHeader() {
  const b = Buffer.alloc(16);
  b.writeUInt32LE(0x46504431, 0);   // SIG.prefetch
  b.writeUInt32LE(30, 4);           // version
  b.writeUInt32LE(1, 8);            // runCount
  return b;
}

/** A record with the count field present and the run table entirely absent. */
function pfTruncatedTable() {
  const b = Buffer.alloc(76);
  b.writeUInt32LE(0x46504431, 0);
  b.writeUInt32LE(30, 4);
  b.writeUInt32LE(1, 8);
  b.write('LSASS.EXE', 12, 'ascii');
  b.writeUInt32LE(8, 72);           // entry count, with no table behind it
  return b;
}

/** One declared slot, two bytes of table. The over-read is at 76+8=84, the file ends at 78. */
function pfHalfSlot() {
  const b = Buffer.alloc(78);
  b.writeUInt32LE(0x46504431, 0);
  b.writeUInt32LE(30, 4);
  b.writeUInt32LE(1, 8);
  b.write('SVCHOST.EXE', 12, 'ascii');
  b.writeUInt32LE(1, 72);
  /* A PARTIAL slot: two bytes of an 8-byte run time, and nothing after them. The two
     bytes are written individually because Buffer.writeBigUInt64LE range-checks all
     EIGHT regardless of what is in the buffer -- so there is no way to ask it for a
     short write, and the first two drafts of this line died in the test setup itself. */
  b[76] = 0x00; b[77] = 0x01;
  return b;
}

/* The outcome vocabulary, spelled out here rather than imported from targets.mjs so the
 * regression file reads as a specification instead of as a client. */
const OUTCOMES = {
  NOT_UNCAUGHT: 'not-uncaught',
  FAST_AND_NOT_UNCAUGHT: 'fast-and-not-uncaught',
};

/** A JWS whose payload claim is one long run of the EMAIL local-part alphabet. */
function joseLongClaimRun(n) {
  const b64u = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  const header = b64u({ alg: 'HS256', typ: 'JWT' });
  const payload = b64u({ iss: 'fuzz-lab', sub: 'u1', exp: 1788003600, note: 'a'.repeat(n) });
  return Buffer.from(`${header}.${payload}.sig`, 'utf8');
}

/** Source text: a long run of the identifier characters the accessor regex backtracked on. */
function webAccessorRun(n) {
  return Buffer.from(`var x = "${'a'.repeat(n)}";\n`, 'utf8');
}

/* -------------------------------------------------------------- the registry */

/**
 * Each entry: what broke, where the fix is, and the reduced input that used to break it.
 * `expect` is the outcome class the input must now land in.
 */
export const KNOWN_FINDINGS = [
  {
    id: 'pf-truncated-header',
    target: 'forensic-pf',
    parser: 'forensics-lab/tools/triage.mjs: parsePrefetch',
    defect: 'the length guard checked `b.length < 16` and then read a u32 at offset 72; a 16-byte record with the right magic died in readUInt32LE with ERR_OUT_OF_RANGE',
    fix: 'the guard is derived from the record layout (PF_COUNT_OFF/PF_TABLE_OFF) and truncation is reported as a field, not thrown',
    input: pfTruncatedHeader(),
    expect: OUTCOMES.NOT_UNCAUGHT,
  },
  {
    id: 'pf-truncated-table',
    target: 'forensic-pf',
    parser: 'forensics-lab/tools/triage.mjs: parsePrefetch',
    defect: 'the entry count was read and trusted, then readBigUInt64LE ran past the end of the file for each declared slot; `Math.min(n, 64)` capped the COUNT but not the FILE',
    fix: 'the usable slot count is derived from the file length, and the shortfall is reported in `truncation`',
    input: pfTruncatedTable(),
    expect: OUTCOMES.NOT_UNCAUGHT,
  },
  {
    id: 'pf-half-slot',
    target: 'forensic-pf',
    parser: 'forensics-lab/tools/triage.mjs: parsePrefetch',
    defect: 'a file ending 6 bytes into the first run-time slot read 8 bytes at offset 76',
    fix: 'same derived bound; the partial slot is not read',
    input: pfHalfSlot(),
    expect: OUTCOMES.NOT_UNCAUGHT,
  },
  {
    id: 'jose-claim-redos',
    target: 'jose',
    parser: 'crypto-lab/tools/analyze.mjs: EMAIL_VALUE_RE',
    defect: '/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/ is quadratic; a 400 KB claim value took the analyzer 54 seconds (measured 50k->0.7s, 100k->3.6s, 200k->15.8s, 400k->54s)',
    fix: 'the local part is anchored to a non-atom character and every quantified run is bounded; 400 KB is now under 15 ms and the matched address set is unchanged',
    input: joseLongClaimRun(400_000),
    expect: OUTCOMES.FAST_AND_NOT_UNCAUGHT,
    maxMs: 1500,
  },
  {
    id: 'web-accessor-redos',
    target: 'web-triage',
    parser: 'web-reverse/static/lib/triage.mjs: residuals.tableAccessorCalls',
    defect: '/[_$\\w]+\\s*\\(\\s*0x[0-9a-fA-F]+\\s*\\)/g is quadratic; a 300 KB identifier run took residuals() 22 seconds',
    fix: 'the identifier start is anchored and both runs are bounded; 300 KB is now under 5 ms with identical match counts',
    input: webAccessorRun(300_000),
    expect: OUTCOMES.FAST_AND_NOT_UNCAUGHT,
    maxMs: 1500,
  },
  {
    id: 'web-nullish-lowering-redos',
    target: 'web-triage',
    parser: 'web-reverse/static/lib/triage.mjs: TRANSPILER_HINTS[nullish-lowering]',
    defect: '/\\w+ !== null && \\w+ !== void 0 \\? \\w+ :/ has three unbounded \\w+ runs with literals between them, so a long identifier run backtracks quadratically; a 200 KB run took triage() 8.7 seconds. Found as a HANG rather than a crash: nothing threw, and the tool simply stopped answering.',
    fix: 'each run is bounded to 64 characters; 200 KB is now 18 ms and 1.6 MB is 145 ms, with an unchanged matched set',
    input: Buffer.from(`var x = 1;\n${'a'.repeat(200_000)}`, 'utf8'),
    expect: OUTCOMES.FAST_AND_NOT_UNCAUGHT,
    maxMs: 1500,
  },
];


/* ------------------------------------------------------------------ the check */

/**
 * Re-run every known finding's reduced case and require the fix to hold.
 * Returns `{ok, passed, results}`; each result names the finding and what it actually did.
 */
export async function verifyRegressions({ runId, hardMs, runOne }) {
  const { runOne: run } = await importRunner(runOne);
  const results = [];
  for (const f of KNOWN_FINDINGS) {
    const r = await run({ target: f.target, variant: 'reference', input: f.input, hardMs });
    const notUncaught = r.outcome !== 'uncaught';
    const fast = f.maxMs ? (r.wallMs ?? 0) <= f.maxMs : true;
    const pass = notUncaught && fast;
    results.push({
      id: f.id,
      target: f.target,
      pass,
      outcome: r.outcome,
      wallMs: Math.round(r.wallMs ?? 0),
      maxMs: f.maxMs ?? null,
      detail: pass
        ? `${r.outcome} in ${r.wallMs?.toFixed?.(1) ?? r.wallMs}ms${f.maxMs ? ` (ceiling ${f.maxMs}ms)` : ''}`
        : `${notUncaught ? '' : `still throws: ${r.detail} `}${fast ? '' : `too slow: ${r.wallMs?.toFixed?.(1)}ms > ${f.maxMs}ms ceiling`}`,
    });
  }
  return { ok: results.every((r) => r.pass), passed: results.filter((r) => r.pass).length, results };
}

/* `runOne` is injected by loop.mjs so this file does not own process spawning; the
 * default keeps the module usable on its own from a REPL or a one-off script. */
let injected = null;
async function importRunner(runOne) {
  if (runOne) return { runOne };
  if (!injected) {
    const m = await import('../lab/driver.mjs');
    injected = m.runOne;
  }
  return { runOne: injected };
}
