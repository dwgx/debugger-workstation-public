/* jose.mjs — minimal JWS (JWT) sign/verify for the crypto-lab, zero dependencies.
 *
 * Deliberately small: base64url, JSON, HMAC, RSA-PKCS1, RSA-PSS. That is the whole
 * surface an analyst meets in practice. It is the lab's *encoder/verifier*, and it is
 * what makes `alg: none` and the HS/RS confusion reachable at all — both are legal
 * things to ask node:crypto for, which is exactly why they happen in the wild.
 *
 * This is NOT a hardened JOSE implementation. It has no JWE, no detached payloads, no
 * `crit` handling, no JWK thumbprints. `tools/analyze.mjs` reports those absences as
 * honest limits rather than pretending to cover them.
 */
import crypto from 'node:crypto';

export const HMAC_ALGS = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
export const RSA_PKCS1_ALGS = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512' };
export const RSA_PSS_ALGS = {
  PS256: { digest: 'sha256', saltLength: 32 },
  PS384: { digest: 'sha384', saltLength: 48 },
  PS512: { digest: 'sha512', saltLength: 64 },
};
export const ALL_ALGS = [
  ...Object.keys(HMAC_ALGS),
  ...Object.keys(RSA_PKCS1_ALGS),
  ...Object.keys(RSA_PSS_ALGS),
  'none',
];

export function b64u(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64url');
}

export function b64uJson(obj) {
  return b64u(Buffer.from(JSON.stringify(obj), 'utf8'));
}

/* Lenient decode: base64url is not padded and not validated by Buffer.from, so a token
 * with a mangled segment still decodes to *something*. That is a feature for an
 * analyzer (report the garbage) and a hazard for a verifier (do not accept it). */
export function decodeSegment(segment) {
  if (typeof segment !== 'string' || segment.length === 0) throw new Error('empty-segment');
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('segment-not-base64url');
  return Buffer.from(segment, 'base64url');
}

export function decodeJson(segment) {
  return JSON.parse(decodeSegment(segment).toString('utf8'));
}

export function decode(token) {
  const raw = String(token).trim();
  const parts = raw.split('.');
  if (parts.length !== 3) {
    throw new Error(`not-a-jws: expected 3 segments, got ${parts.length}`);
  }
  return {
    parts,
    header: decodeJson(parts[0]),
    payload: decodeJson(parts[1]),
    signature: parts[2],
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

/** Sign a JWS compact token. `none` produces an empty signature segment — the whole
 *  point of the class: a token that says "do not verify me" and a verifier that obeys. */
export function sign(header, payload, key) {
  const alg = header.alg;
  if (!ALL_ALGS.includes(alg)) throw new Error(`unsupported alg ${alg}`);
  const h = b64uJson({ typ: 'JWT', ...header });
  const p = b64uJson(payload);
  const input = `${h}.${p}`;
  if (alg === 'none') return `${input}.`;
  if (HMAC_ALGS[alg]) {
    return `${input}.${crypto.createHmac(HMAC_ALGS[alg], key).update(input).digest('base64url')}`;
  }
  if (RSA_PKCS1_ALGS[alg]) {
    const sig = crypto.sign(RSA_PKCS1_ALGS[alg], Buffer.from(input), {
      key,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });
    return `${input}.${sig.toString('base64url')}`;
  }
  const pss = RSA_PSS_ALGS[alg];
  const sig = crypto.sign(pss.digest, Buffer.from(input), {
    key,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: pss.saltLength,
  });
  return `${input}.${sig.toString('base64url')}`;
}

/** Pure signature check. No claim validation, no algorithm policy — the caller decides
 *  policy, and the lab's four verifier modes are the four policies that matter. */
export function verifySignature(token, key, alg) {
  const { signature, signingInput } = decode(token);
  if (alg === 'none') return signature === '';
  const sig = Buffer.from(signature, 'base64url');
  if (HMAC_ALGS[alg]) {
    const expected = crypto.createHmac(HMAC_ALGS[alg], key).update(signingInput).digest();
    return expected.length === sig.length && crypto.timingSafeEqual(expected, sig);
  }
  try {
    if (RSA_PKCS1_ALGS[alg]) {
      return crypto.verify(RSA_PKCS1_ALGS[alg], Buffer.from(signingInput), {
        key,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      }, sig);
    }
    const pss = RSA_PSS_ALGS[alg];
    return crypto.verify(pss.digest, Buffer.from(signingInput), {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: pss.saltLength,
    }, sig);
  } catch {
    return false;
  }
}

export function keyId(...parts) {
  return crypto.createHash('sha256').update(parts.join('.')).digest('hex').slice(0, 16);
}

/** JWKS document for a PEM public key — the *correct* way a verifier learns keys, and
 *  the contrast that makes `jku`/embedded-`jwk` findings legible. */
export function jwksFromPublicPem(pem, kid) {
  const jwk = crypto.createPublicKey(pem).export({ format: 'jwk' });
  return { keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid }] };
}
