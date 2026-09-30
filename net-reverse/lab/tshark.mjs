/* tshark.mjs — locate and run the station's tshark (zero dependencies).
 *
 * The station ships Wireshark portable under Network-HTTP/, so tshark is not on
 * PATH by design. One resolver, one runner, used by every net-reverse tool, so a
 * "which tshark did it use" question has exactly one answer — the tools print it.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');

const CANDIDATES = [
  process.env.TSHARK,
  'tshark',
  path.join(REPO_ROOT, 'Network-HTTP', 'Wireshark', 'portable', 'App', 'Wireshark', 'tshark.exe'),
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe'
].filter(Boolean);

let cached = null;

/** @returns {{path:string, source:string, version:string}} */
export function findTshark() {
  if (cached) return cached;
  for (const candidate of CANDIDATES) {
    const isPath = candidate.includes('/') || candidate.includes('\\') || candidate.endsWith('.exe');
    if (isPath && !fs.existsSync(candidate)) continue;
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8', timeout: 30_000 });
    if (probe.status === 0 && /^TShark/i.test(probe.stdout || '')) {
      cached = {
        path: candidate,
        source: candidate === 'tshark' ? 'PATH' : (candidate === process.env.TSHARK ? 'env TSHARK' : 'station portable build'),
        version: (probe.stdout.split('\n')[0] || '').trim()
      };
      return cached;
    }
  }
  throw new Error('tshark not found. Set TSHARK=<path to tshark.exe>, or install Wireshark. Tried: ' + CANDIDATES.join(' | '));
}

/** Run tshark with argv (no shell, so nothing is re-quoted by cmd.exe). */
export function runTshark(args, { timeoutMs = 120_000, cwd } = {}) {
  const ts = findTshark();
  const argv = [ts.path, ...args];
  const res = spawnSync(ts.path, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, cwd });
  if (res.error) throw res.error;
  return {
    argv,
    display: `tshark ${args.join(' ')}`,
    code: res.status,
    stdout: res.stdout || '',
    stderr: res.stderr || ''
  };
}

/** tshark prints FT_BYTES fields as hex; turn one back into a string. */
export function hexFieldToText(value, encoding = 'utf8') {
  const hex = String(value).replace(/[^0-9a-fA-F]/g, '');
  if (!hex || hex.length % 2) return '';
  return Buffer.from(hex, 'hex').toString(encoding);
}

/** Non-empty trimmed lines of a -T fields result. */
export const lines = stdout => stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
