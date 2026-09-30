/* targets.mjs — the parsers under test, and the deliberately flawed twin of each.
 *
 * Two things live here and the distinction is the whole point of the lab.
 *
 * 1. A REFERENCE target: a real parser from this repository, called exactly as the rest
 *    of the station calls it. `reference.run(input)` is the code under test. When it
 *    throws something uncaught, that is a real robustness defect in a lab parser, and
 *    the finding is real.
 *
 * 2. A FLAWED twin: the same parser with one specific guard removed, written to be the
 *    plausible mistake an analyst makes when they write their own version -- trust the
 *    length field, trust the count, trust the character class. It exists so the
 *    negative control has something to catch.
 *
 * The negative control is the load-bearing part. A fuzzer that reports "0 findings"
 * against a parser that has no bounds checks at all has not demonstrated that it can
 * find anything; it has demonstrated that its corpus is too weak to reach a bug three
 * edits away. So the loop REQUIRES that every flawed twin be caught. If a flawed twin
 * survives the whole run, the lab fails and says so, rather than printing a green run
 * that means nothing.
 *
 * Every target declares what it accepts as a CLEAN REJECTION. A parser that returns
 * `{error: ...}` or throws a typed parse error has done its job on hostile input; that
 * is a pass, not a finding. The defect is an UNCAUGHT exception of any other kind -- a
 * RangeError from reading past a buffer, a TypeError from calling a method on null, a
 * stack overflow -- because that is what an analyst's tool would die on when pointed at
 * a file from an evidence seizure.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { workDir } from './corpus.mjs';
import { decode as joseDecode } from '../../crypto-lab/lab/jose.mjs';
import { analyze as joseAnalyze } from '../../crypto-lab/tools/analyze.mjs';
import { parsePrefetch as forensicsParsePrefetch } from '../../forensics-lab/tools/triage.mjs';
import { triage as webTriage, residuals as webResiduals } from '../../web-reverse/static/lib/triage.mjs';
import { readPcapFile, readPcapFileFlawed } from './pcap-reader.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------ outcome classes */

export const OUTCOME = {
  PARSED: 'parsed',            // returned a value: the input is in the accepted region
  REJECTED: 'rejected',        // refused, in a way the target declares: this is a PASS
  UNCAUGHT: 'uncaught',        // threw something the target never intended: a FINDING
  HANG: 'hang',                // exceeded the per-input wall clock: a FINDING
  MEMORY: 'memory',            // exceeded the per-input heap ceiling: a FINDING
};

const isFindingsClass = (o) => o === OUTCOME.UNCAUGHT || o === OUTCOME.HANG || o === OUTCOME.MEMORY;

/* ------------------------------------------------------------------ the targets */

/**
 * T1 -- the pcap reader.
 *
 * `fuzz-lab/lab/pcap-reader.mjs` is a reader written FOR this lab, because the pcap
 * writer in net-reverse only writes: a file format whose interesting surface is its
 * length fields, and the station had a writer and no reader to point a fuzzer at.
 *
 * That is worth stating rather than hiding. The reader is a new in-tree parser, so the
 * "real bug" it produces is a real bug in this repository -- but it was written knowing
 * a fuzzer was coming, which is not the same as the other three targets. The other
 * three are pre-existing code that had never been fuzzed, and those are where the
 * findings that were not predicted live.
 */
const pcapTarget = {
  id: 'pcap',
  title: 'pcap reader (fuzz-lab/lab/pcap-reader.mjs)',
  kind: 'binary',
  seedFilter: (s) => s.name.startsWith('pcap/'),
  alphabet: [0x00, 0x01, 0x02, 0x04, 0x08, 0x0a, 0x0d, 0x14, 0x15, 0x17, 0x1f, 0x20, 0x30, 0x39, 0x41, 0x61,
    0xd4, 0xc3, 0xb2, 0xa1, 0xff, 0xfe, 0x80, 0x7f],
  reference: {
    run: (buf) => readPcapFile(buf),
    isRejection: (e) => e && e.name === 'PcapFormatError',
  },
  flawed: {
    run: (buf) => readPcapFileFlawed(buf),
    isRejection: () => false,
    flaw: 'reads incl_len straight into a subarray with no bounds check, and loops on the record count with no cap',
  },
};

/**
 * T2 -- the JOSE/JWT parser.
 *
 * Two parsers, both pre-existing, neither previously fuzzed:
 *   `joseDecode`    crypto-lab/lab/jose.mjs        the lab's own decode()
 *   `joseAnalyze`   crypto-lab/tools/analyze.mjs   THE deliverable: a 780-line analyzer
 *                                                  that classifies 20 weakness classes
 * The analyzer is the interesting one. It takes a token from an untrusted source, walks
 * every claim, and runs six regexes over claim values. That is the shape of the problem
 * this lab exists for: the code is correct, and it still dies on a 400 KB claim.
 */
const joseTarget = {
  id: 'jose',
  title: 'JOSE/JWT parser (crypto-lab/lab/jose.mjs + crypto-lab/tools/analyze.mjs)',
  kind: 'text',
  seedFilter: (s) => s.name.startsWith('jose/'),
  alphabet: null,
  reference: {
    run: (buf) => {
      const token = buf.toString('utf8');
      /* Both entry points, because they fail differently: jose.mjs throws bare
         Errors by design, while analyze() throws coded ones. */
      let joseOutcome = 'ok';
      try { joseDecode(token); } catch (e) { joseOutcome = e; }
      const report = joseAnalyze(token, { now: 1788000000, ttlMax: 3600 });
      return { joseOutcome, findings: report.findings.length, claims: report.claims.length };
    },
    isRejection: (e) => e instanceof Error && typeof e.exitCode === 'number',
  },
  flawed: {
    /* The plausible naive version: decode the segments and hand the payload to JSON.parse
       with no length ceiling and no claim-value ceiling. A verifier written this way
       accepts whatever arrives; this is the shape of the bug the analyzer's own
       CLAIM_OVERSIZED rule exists to report. */
    run: (buf) => {
      const parts = buf.toString('utf8').split('.');
      if (parts.length !== 3) return { segments: parts.length };
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      let claims = 0;
      for (const [k, v] of Object.entries(payload)) {
        if (typeof v === 'string') { claims += v.length; }
        if (k === '__proto__') claims += 1;
      }
      return { alg: header.alg, claims };
    },
    isRejection: () => false,
    flaw: 'no ceiling on segment length, no ceiling on claim-value length, JSON.parse straight onto attacker bytes',
  },
};

/**
 * T3 -- the forensic artifact parsers.
 *
 * `parsePrefetch` is the priority: a binary record with a 60-byte fixed name field, a
 * count field, and a table of 8-byte run times. Every one of those is an offset the
 * parser reads without asking whether the file is long enough to contain it.
 */
const forensicTarget = {
  id: 'forensic-pf',
  title: 'forensic artifact parsers (forensics-lab/tools/triage.mjs: parsePrefetch)',
  kind: 'binary',
  seedFilter: (s) => s.name.startsWith('pf/'),
  alphabet: [0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x0a, 0x14, 0x1f, 0x20, 0x2e, 0x30, 0x39, 0x41, 0x5a,
    0xd1, 0x2f, 0x50, 0x46, 0x31, 0xff, 0xfe, 0x80, 0x7f, 0x10],
  reference: {
    run: (buf) => {
      /* parsePrefetch's signature takes a FILE, not a buffer. The fuzz input is bytes,
         so it goes to a file in a scratch dir. That is the honest shape of this
         target: the parser under test is fs.readFileSync + a fixed-offset read. */
      const p = writeTemp(buf);
      try { return forensicsParsePrefetch(p); } finally { fs.unlinkSync(p); }
    },
    isRejection: (e) => e && typeof e === 'object' && !e.code,
  },
  flawed: {
    /* The version an analyst writes when they trust the count field: loop `n` times
       with no cap and no per-iteration bounds check. `n` is a u32 read from the file. */
    run: (buf) => {
      if (buf.length < 16 || buf.readUInt32LE(0) !== 0x46504431) return { error: 'not a prefetch record' };
      const n = buf.readUInt32LE(72);
      const out = [];
      for (let i = 0; i < n; i++) out.push(buf.readBigUInt64LE(76 + i * 8).toString());
      return { entries: out.length };
    },
    isRejection: () => false,
    flaw: 'loops `n` times where n is a u32 from the file, with no cap and no bounds check per iteration',
  },
};

/**
 * T4 -- the obfuscation-fingerprint text parser.
 *
 * The cheapest target to fuzz and the one most likely to find something, because it is
 * nothing but regexes over untrusted text. `triage()` classifies; `residuals()` measures
 * the output. Both run.
 */
const webTarget = {
  id: 'web-triage',
  title: 'obfuscation fingerprint (web-reverse/static/lib/triage.mjs: triage + residuals)',
  kind: 'text',
  seedFilter: (s) => s.name.startsWith('web/'),
  alphabet: null,
  reference: {
    run: (buf) => {
      const source = buf.toString('utf8');
      const t = webTriage(source);
      const r = webResiduals(source);
      return { verdict: t.verdict, families: t.obfuscatorFamilies.length, residuals: r };
    },
    isRejection: (e) => e instanceof Error && e.name === 'Error',
  },
  flawed: {
    /* The version with the nested quantifier: `[_$\w]+` before a literal `(` is already
       ambiguous with the `\w` inside the group that follows, and V8's backtracker
       explores the ambiguity. This is THE classic ReDoS shape and the one every
       reviewer is supposed to catch by eye and nobody does. */
    run: (buf) => {
      const source = buf.toString('utf8');
      let n = 0;
      const re = /[_$\w]+(\s*\(\s*0x[0-9a-fA-F]+\s*\))+/g;
      let m;
      while ((m = re.exec(source)) !== null) n++;
      return { accessorCalls: n };
    },
    isRejection: () => false,
    flaw: 'nested quantifier: /[_$\\w]+(\\s*\\(\\s*0x[0-9a-fA-F]+\\s*\\))+/g backtracks quadratically on a long identifier run',
  },
};

export const TARGETS = [pcapTarget, joseTarget, forensicTarget, webTarget];
export const TARGET_BY_ID = Object.fromEntries(TARGETS.map((t) => [t.id, t]));

/* ------------------------------------------------------------------- the runner */

/**
 * Classify one input against one variant. Returns `{outcome, detail, ms}`.
 *
 * The distinction this function is responsible for: a target that DECLARES its
 * rejections has handled hostile input correctly, and that is `rejected`, not a
 * finding. A target that throws a RangeError from a buffer read has not, and that is
 * `uncaught`. Fuzzers that conflate the two report noise; fuzzers that only look for
 * the second under-report, because a parser that catches everything is also a parser
 * that rejects everything.
 */
export function classify(variant, input) {
  const started = process.hrtime.bigint();
  try {
    const value = variant.run(input);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    return { outcome: OUTCOME.PARSED, detail: summarise(value), ms };
  } catch (e) {
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    if (variant.isRejection(e)) {
      return { outcome: OUTCOME.REJECTED, detail: `declared rejection: ${e.message}`.slice(0, 200), ms };
    }
    return {
      outcome: OUTCOME.UNCAUGHT,
      detail: `${e && e.name ? e.name : typeof e}: ${e && e.message ? e.message : String(e)}`.slice(0, 300),
      code: e && e.code,
      ms,
    };
  }
}

function summarise(value) {
  if (value === null || value === undefined) return String(value);
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    return `{${keys.slice(0, 5).join(',')}${keys.length > 5 ? ',…' : ''}}`;
  }
  return String(value).slice(0, 60);
}

export { isFindingsClass };

/* -------------------------------------------------------- temp-file plumbing */


const SCRATCH = path.join(workDir(), 'scratch');
let scratchSeq = 0;

/**
 * parsePrefetch takes a path, so a buffer fuzz input has to land on disk. One scratch
 * dir, one file per call, deleted immediately. Nothing is written inside the repo.
 */
function writeTemp(buf) {
  fs.mkdirSync(SCRATCH, { recursive: true });
  const p = path.join(SCRATCH, `pf-${process.pid}-${scratchSeq++}.pf`);
  fs.writeFileSync(p, buf);
  return p;
}
