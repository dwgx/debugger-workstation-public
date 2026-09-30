/* keys.mjs — key material for the crypto-lab.
 *
 * STOP LINE: no real secrets live in git. Asymmetric keys are *generated at runtime*
 * into `crypto-lab/keys/`, which is gitignored. The only fixed material here is an
 * obviously-fake lab constant of the same species as `web-reverse`'s LAB_KEY: it is
 * published in the README, it signs nothing but tokens this lab issues to itself.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const LAB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const KEYS_DIR = path.join(LAB_ROOT, 'keys');

/* Public, obviously-fake. Never a real secret; see README stop lines. */
export const LAB_HMAC_SECRET = 'crypto-lab-hs-secret-published-not-a-real-secret-v1';
/* The classic guessable secret. Present so the lab can *demonstrate* the class
 * `weak key` against itself; it is the first entry of every JWT-tutorial dictionary. */
export const WEAK_HMAC_SECRET = 'secret';

export const RSA_BITS = 2048;

function read(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Generate-on-first-use RSA keypair, persisted under the gitignored keys/ dir.
 *  Idempotent: the second call reuses the pair, so tokens stay verifiable across runs. */
export function rsaKeypair({ dir = KEYS_DIR, bits = RSA_BITS, force = false } = {}) {
  const pub = path.join(dir, 'lab-rsa-2048.pub.pem');
  const priv = path.join(dir, 'lab-rsa-2048.key.pem');
  if (!force) {
    const havePub = read(pub);
    const havePriv = read(priv);
    if (havePub && havePriv) {
      return { publicPem: havePub, privatePem: havePriv, publicPath: pub, privatePath: priv, generated: false, bits };
    }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(priv, privateKey, { mode: 0o600 });
  fs.writeFileSync(pub, publicKey);
  return { publicPem: publicKey, privatePem: privateKey, publicPath: pub, privatePath: priv, generated: true, bits };
}
