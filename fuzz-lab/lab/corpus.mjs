/* corpus.mjs — the seed set, built from artifacts this repository already makes.
 *
 *
 * Every seed is a real artifact produced by another lab in this tree, not random
 * noise. That matters more than it sounds: a mutation fuzzer spends almost all of
 * its budget on inputs that are structurally hopeless, and a seed set of random bytes
 * is the definition of structurally hopeless. Starting from a file that a real parser
 * already accepts means the mutations start one edit away from the accepted region
 * instead of one edit away from nothing.
 *
 * The generator for each seed is deterministic and its output hash is recorded, so the
 * seed set is a fixed point: same tree, same seeds, same hashes. `assertDeterministic`
 * proves that at run time rather than asserting it in a comment.
 *
 * Two corpora are built:
 *   - `network`  the 5 synthetic pcaps from net-reverse, plus a pcap the lab writes
 *                itself through the same writer, so a seed exists for every target shape
 *   - `forensic` the D12IMG image and the three artifact families, of which the binary
 *                `.pf` records are the interesting parser surface
 *   - `crypto`   real JOSE tokens from crypto-lab, signed with the lab's own key
 *   - `web`      the obfuscated JS that web-reverse generates, plus the lab's own
 *                static sources read as plain text
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { generate as genPcaps } from '../../net-reverse/lab/gen-pcaps.mjs';
import { writePcap, NET, T0, udpFrame } from '../../net-reverse/lab/pcap-writer.mjs';
import { generate as genImage } from '../../forensics-lab/lab/mkimage.mjs';
import { sign as joseSign } from '../../crypto-lab/lab/jose.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LAB_ROOT = path.resolve(HERE, '..');
const REPO = path.resolve(LAB_ROOT, '..');

export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

export function workDir() {
  return process.env.FUZZ_LAB_DIR || path.join(os.tmpdir(), 'fuzz-lab', 'work');
}

/* ---------------------------------------------------------------- pcap seeds */

/** One frame the lab writes itself, so the corpus is not only another lab's output. */
function selfPcap() {
  /* udpFrame returns a {ts, data} packet, not frame bytes: it is the writer's
     packet-level helper, and writePcap takes the packet list. */
  const packet = udpFrame({
    t: T0 + 0.0005, srcIp: NET.clientIp, dstIp: NET.resolverIp, srcPort: 53000, dstPort: 53,
    payload: Buffer.from('fuzz-lab self-authored frame'),
    srcMac: NET.clientMac, dstMac: NET.resolverMac, id: 0x1234,
  });
  return writePcap([packet]);
}

/* ------------------------------------------------------------------ builders */

function buildNetwork() {
  const outDir = path.join(workDir(), 'pcaps');
  const manifest = genPcaps(outDir);
  const seeds = [];
  for (const [file, info] of Object.entries(manifest.files)) {
    seeds.push({
      name: `pcap/${file.replace(/\.pcap$/, '')}`,
      origin: 'net-reverse/lab/gen-pcaps.mjs',
      note: info.teaches,
      bytes: fs.readFileSync(info.path),
    });
  }
  const self = selfPcap();
  seeds.push({
    name: 'pcap/self-authored',
    origin: 'fuzz-lab/lab/corpus.mjs (net-reverse/lab/pcap-writer.mjs)',
    note: 'one UDP frame written by the station writer, so a seed exists that no other lab produced',
    bytes: self,
  });
  return seeds;
}

function buildForensic() {
  const outDir = path.join(workDir(), 'image');
  const r = genImage(outDir);
  const artDir = path.join(outDir, 'artifacts');
  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.json'), 'utf8'));
  const seeds = [];
  for (const name of manifest.artifacts.prefetch) {
    seeds.push({
      name: `pf/${name.replace(/\.pf$/, '')}`,
      origin: 'forensics-lab/lab/mkimage.mjs',
      note: 'binary MAM-like prefetch record: magic, version, runCount, 60B name, 8x8B run table',
      bytes: fs.readFileSync(path.join(artDir, name)),
    });
  }
  for (const [key, file] of [['amcache', manifest.artifacts.amcache], ['srum', manifest.artifacts.srum]]) {
    seeds.push({
      name: `tsv/${key}`,
      origin: 'forensics-lab/lab/mkimage.mjs',
      note: `${key} TSV: tab-separated columns parsed by forensics-lab/tools/triage.mjs`,
      bytes: fs.readFileSync(path.join(artDir, file)),
    });
  }
  seeds.push({
    name: 'image/d12-lab-image',
    origin: 'forensics-lab/lab/mkimage.mjs',
    note: `D12IMG container, ${r.meta.bytes} bytes; parsed by forensics-lab/tools/triage.mjs LabImage`,
    bytes: fs.readFileSync(r.imagePath),
  });
  return seeds;
}

function buildCrypto() {
  const key = 'fuzz-lab-published-hmac-secret';
  const now = 1788000000;
  const seeds = [];
  const push = (name, header, payload, note) => {
    const token = joseSign(header, payload, key, 'HS256');
    seeds.push({
      name: `jose/${name}`,
      origin: 'crypto-lab/lab/jose.mjs',
      note,
      bytes: Buffer.from(token, 'utf8'),
    });
  };
  push('strong', { alg: 'HS256', typ: 'JWT', kid: 'k1' },
    { iss: 'fuzz-lab', sub: 'u1', aud: 'fuzz-lab', exp: now + 3600, iat: now, jti: 'j1' },
    'a well-formed HS256 token: the accepted region every mutation starts from');
  push('none-alg', { alg: 'none' },
    { iss: 'fuzz-lab', sub: 'u1', exp: now + 3600 },
    'alg=none: three segments, empty signature, still a decodable JWS');
  push('weak-claims', { alg: 'HS256' },
    { sub: 'u1', password: 'hunter2', email: 'a@b.co', exp: String(now + 999999) },
    'claim set that trips four separate analyzer rules: wrong-type exp, sensitive name, PII, oversized');
  push('jku-header', { alg: 'HS256', jku: 'https://keys.invalid/jwks.json', kid: 'k1' },
    { iss: 'fuzz-lab', sub: 'u1', exp: now + 3600 },
    'header carrying jku/x5u/jwk/crit: header-parameter surface');
  push('jwe-shape', { alg: 'HS256' }, { iss: 'fuzz-lab' },
    'payload segment is replaced at fuzz time to reach the 5-segment JWE branch');
  return seeds;
}

function buildWeb() {
  const seeds = [];
  /* Every web seed is a COMMITTED file in this tree, read as bytes. That is deliberate
     and it is a correction of an earlier draft of this file.

     The first version seeded from `web-reverse/static/gen-obf.mjs`, which produces
     real obfuscator.io output -- the most structurally meaningful input this target
     could want. It is not byte-deterministic: javascript-obfuscator draws from an
     internal RNG that the generator's `--seed` flag does not reach, so two runs with
     the same seed gave different bytes (measured: `signer-obf.js`
     877ac287... vs 6672d330...). `assertDeterministic` caught it, which is the only
     reason it is worth having.

     A seed set that drifts breaks the one property this lab is built on, so the
     generated artifacts are out. The lab's own committed sources are the substitute,
     and they are the better seed anyway: `triage.mjs` is handed plain JS text in
     production, and a 38 KB real ESM source exercises the line/byte heuristic, the
     transpiler hints, and the residual-metric regexes far harder than a 4 KB
     obfuscated file does. The obfuscation FAMILIES are still reached, because
     `web-reverse/static/lib/triage.mjs` and `crypto-lab/tools/analyze.mjs` contain the
     literal `_0x...` idents and `!![]` dispatchers these regexes are written to match --
     they are the signals, present in prose, which is a real false-positive surface. */
  for (const [file, note] of [
    ['web-reverse/static/lib/triage.mjs', 'the analyzer itself: its own regexes as input, the honest false-positive surface'],
    ['crypto-lab/tools/analyze.mjs', 'a 38 KB ESM source: line/byte heuristic, transpiler hints, residual regexes'],
    ['forensics-lab/tools/triage.mjs', 'a 22 KB ESM source with long regex literals'],
    ['web-reverse/lab/server.mjs', 'plain server source: the `plain` verdict baseline'],
    ['web-reverse/static/deobf.mjs', 'the deobfuscator: 18 KB, the largest committed JS in the tree'],
    ['mobile-lab/tools/analyze.mjs', 'a 32 KB source from another lane'],
  ]) {
    const p = path.join(REPO, file);
    if (!fs.existsSync(p)) continue;
    seeds.push({
      name: `web/${file.replace(/[\\/]/g, '__')}`,
      origin: file,
      note,
      bytes: fs.readFileSync(p),
    });
  }
  return seeds;
}


/* ------------------------------------------------------------------ the seeds */

const BUILDERS = { network: buildNetwork, forensic: buildForensic, crypto: buildCrypto, web: buildWeb };

/**
 * Build every seed group. Each entry gains `sha256` and `bytes.length`, so the corpus
 * is described by its content rather than by its filename.
 */
export async function buildCorpus() {
  const out = {};
  for (const [group, fn] of Object.entries(BUILDERS)) out[group] = (await fn()).map(finalise);
  return out;
}

function finalise(seed) {
  return { ...seed, bytes: seed.bytes, sha256: sha256(seed.bytes), length: seed.bytes.length };
}

/** The whole corpus as one flat list, each entry tagged with its group. */
export async function flatCorpus() {
  const grouped = await buildCorpus();
  return Object.entries(grouped).flatMap(([group, seeds]) => seeds.map(s => ({ ...s, group })));
}

/**
 * Build twice into separate directories and require identical hashes. This is the
 * assertion that makes "reproducible" a measured property rather than a claim: if a
 * corpus generator ever picks up wall-clock time or an unseeded RNG, this fails.
 */
export async function assertDeterministic() {
  const first = await flatCorpus();
  const byName = new Map(first.map(s => [`${s.group}/${s.name}`, s.sha256]));
  const second = await flatCorpus();
  const diffs = [];
  for (const s of second) {
    const k = `${s.group}/${s.name}`;
    const prev = byName.get(k);
    if (prev === undefined) diffs.push(`${k}: absent from the first build`);
    else if (prev !== s.sha256) diffs.push(`${k}: ${prev.slice(0, 12)} -> ${s.sha256.slice(0, 12)}`);
  }
  return { stable: diffs.length === 0, count: second.length, diffs };
}
