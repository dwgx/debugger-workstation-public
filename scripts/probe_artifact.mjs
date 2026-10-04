/**
 * probe_artifact.mjs — the JS mirror of `scripts/probe_artifact.py`.
 *
 * WHY IT EXISTS. `assert-probes.py` decides a capability is real by matching substrings against
 * captured stdout, and it says so in its own OK verdict: *"NOT a claim that the instrument ran: a
 * stub which prints them satisfies it."* A loop that leaves a file behind moves that verdict onto
 * the filesystem, which a stub has to also write to fake.
 *
 * WHY IT IS IN `scripts/` AND NOT IN A LAB. The nine labs are independent by design —
 * `managed-lab/tools/clrlib.mjs` is lab-local and no lab imports another lab's internals. Adding a
 * sixth copy of this to each loop would be duplication; putting it in a lab would couple them. A
 * station-level utility that labs *use* is the same shape as the Python probes importing
 * `scripts/probe_artifact.py`, so this is one more thing crossing that boundary rather than a new
 * convention.
 *
 * TWO SHAPES, because the loops have two shapes and normalising here beats editing nine call
 * sites: some push `{ label, pass, detail }`, others `{ ok, name, detail }`. Both are accepted.
 *
 * One artifact per tool name. Several capabilities run the same script with different flags, and
 * a single fixed path would let one tool's run satisfy another entry's `probe.produces` — which is
 * exactly the "a probe that cannot localise a fault is not much of a probe" failure.
 *
 * Never throws. A probe that fails because its bookkeeping failed has turned a measurement
 * problem into an outage, and the exit code would then say nothing about the instrument.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const STATION = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Normalise either loop's check shape to `{name, ok, detail}`. */
const norm = (c) => ({
  name: c.name ?? c.label ?? '?',
  ok: typeof c.ok === 'boolean' ? c.ok : !!c.pass,
  detail: c.detail ?? '',
});

export function artifactPath(tool, outDir) {
  const safe = String(tool).replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[._]+|[._]+$/g, '');
  if (!safe) throw new Error(`probe_artifact: unusable tool name ${JSON.stringify(tool)}`);
  return path.join(outDir, `last-run-${safe}.json`);
}

/**
 * Write this run's summary to disk.
 *
 * @param {string} tool    stable name; becomes the filename
 * @param {object} opts    { checks, extra, outDir }  — `outDir` is relative to the station root
 * @returns {string}       the repo-relative path, or '' if the write failed
 */
export function writeRunArtifact(tool, { checks = [], extra = {}, outDir = 'lab-out' } = {}) {
  const rel = artifactPath(tool, outDir);
  try {
    const full = path.join(STATION, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    const list = checks.map(norm);
    const doc = {
      schema: 'lab-run@1',
      artifact_version: 1,
      tool,
      ...extra,
      checks: list,
      counts: {
        total: list.length,
        pass: list.filter((c) => c.ok).length,
        fail: list.filter((c) => !c.ok).length,
      },
    };
    fs.writeFileSync(full, `${JSON.stringify(doc, null, 2)}\n`, 'utf-8');
    process.stdout.write(`ARTIFACT ${rel.replace(/\\/g, '/')}\n`);
    return rel.replace(/\\/g, '/');
  } catch (e) {
    process.stdout.write(
      `ARTIFACT WRITE FAILED: ${e.message} — the run happened but left nothing checkable\n`,
    );
    return '';
  }
}

export default writeRunArtifact;