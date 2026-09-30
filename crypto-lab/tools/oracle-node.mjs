#!/usr/bin/env node
/* oracle-node.mjs — cross-check the analyzer with `jsonwebtoken`, the most widely
 * deployed JWT library in the Node ecosystem.
 *
 * Why a second implementation exists at all: a decoder that agrees with itself proves
 * nothing. `analyze.mjs` is hand-written against node:crypto; this one is a different
 * author's code with its own opinions about algorithms, options and failure modes. When
 * the two disagree, one of them is wrong, and the loop stops.
 *
 * It is also the honest demonstration of the point the lab is making: jsonwebtoken does
 * NOT refuse to key an HMAC with a public key, and it does NOT refuse `alg: none` — it
 * only refuses when you pin `algorithms`. The library is not the control. The config is.
 *
 * Output is data, not an exit code: JSON on stdout, exit 0 unless the invocation itself
 * was wrong. The caller decides what the result means.
 *
 * usage: node oracle-node.mjs --token <jws> [--key none|secret|rsa-public]
 *                             [--secret <s>] [--rsa-pub <path|pem>]
 *                             [--algorithms HS256,RS256,none] [--require exp,aud]
 *                             [--issuer X] [--audience Y]
 */
import fs from 'node:fs';

function arg(name, def = undefined) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}
const has = (name) => process.argv.includes(name);

const token = arg('--token');
if (!token) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: 'usage: --token <jws>' })}\n`);
  process.exit(2);
}

const keyMode = arg('--key', 'none');
const algorithms = (arg('--algorithms', '') || '').split(',').map((s) => s.trim()).filter(Boolean);
const requireClaims = (arg('--require', '') || '').split(',').map((s) => s.trim()).filter(Boolean);
const issuer = arg('--issuer');
const audience = arg('--audience');

function resolveKey() {
  if (keyMode === 'none') return undefined;
  if (keyMode === 'secret') return arg('--secret', 'secret');
  if (keyMode === 'rsa-public') {
    const v = arg('--rsa-pub');
    if (!v) throw new Error('--key rsa-public needs --rsa-pub');
    return v.includes('-----BEGIN') ? v : fs.readFileSync(v, 'utf8');
  }
  throw new Error(`unknown --key ${keyMode}`);
}

const out = { oracle: 'jsonwebtoken', version: null, key_mode: keyMode, algorithms, require: requireClaims };

try {
  const jwt = (await import('jsonwebtoken')).default;
  out.version = JSON.parse(fs.readFileSync(new URL('../node_modules/jsonwebtoken/package.json', import.meta.url), 'utf8')).version;

  /* decode() is unconditional — a decoder that refuses nothing is exactly the point. */
  try {
    out.decoded = jwt.decode(token, { complete: true });
    out.decoded_alg = out.decoded?.header?.alg ?? null;
  } catch (e) {
    out.decoded_error = e.name;
  }

  const key = resolveKey();
  const opts = {};
  if (algorithms.length) opts.algorithms = algorithms;
  if (issuer) opts.issuer = issuer;
  if (audience) opts.audience = audience;

  try {
    const payload = jwt.verify(token, key, opts);
    out.verified = true;
    out.claims = payload;
    /* A verifier that only checks a signature is the bug we are hunting: report which
     * of the requested claims the library actually enforced, so "it verified" is never
     * mistaken for "it was validated". */
    if (requireClaims.length) {
      const missing = requireClaims.filter((c) => payload[c] === undefined);
      if (missing.length) {
        out.verified = false;
        out.error = { name: 'MissingRequiredClaim', message: `not enforced by default: ${missing.join(', ')}` };
      }
    }
  } catch (e) {
    out.verified = false;
    out.error = { name: e.name, message: e.message };
  }
} catch (e) {
  out.error = { name: e.name || 'LoadError', message: e.message };
}

process.stdout.write(`${JSON.stringify(out)}\n`);
process.exit(0);
