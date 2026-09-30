#!/usr/bin/env node
/* analyze.mjs — the crypto-lab deliverable: read a JWT and say what it is and which
 * weakness classes are present in it.
 *
 * Design rules, in order of importance:
 *
 *  1. Zero dependencies. Only `node:crypto` and node builtins. This tool is meant to be
 *     pointed at any token, on any box, without an install step, and to stay auditable
 *     in one sitting. Nothing is vendored and nothing is imported.
 *  2. Every finding carries its evidence. A finding is an id, a severity, the bytes that
 *     triggered it, and *why it matters* — so a reader can disagree with the rule instead
 *     of guessing at it.
 *  3. Absence of a finding is not a clean bill of health. Findings are drawn from a
 *     catalogue; the catalogue is incomplete by construction and the summary says so.
 *  4. It never fetches anything. A `jku`/`x5u` header is *reported*, never dereferenced.
 *     Outbound reach during analysis is a stop line in this station, and a key URL in a
 *     token is attacker-controlled data.
 *
 * Exit codes: 0 analysed · 2 usage · 3 bad input · 4 `--expect` mismatch
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/* ------------------------------------------------------------------ the catalogue */

const SEVERITY_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

/* Class names map 1:1 onto the four questions the lab exists to teach. */
const CLASSES = {
  ALGORITHM: 'algorithm',
  SIGNATURE: 'signature-integrity',
  CLAIMS: 'weak-claim-validation',
  PROVENANCE: 'claim-provenance',
};

const HMAC_ALGS = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
const RSA_PKCS1_ALGS = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512' };
const RSA_PSS_ALGS = {
  PS256: { digest: 'sha256', saltLength: 32 },
  PS384: { digest: 'sha384', saltLength: 48 },
  PS512: { digest: 'sha512', saltLength: 64 },
};
const EC_ALGS = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
const KNOWN_ALGS = [...Object.keys(HMAC_ALGS), ...Object.keys(RSA_PKCS1_ALGS), ...Object.keys(RSA_PSS_ALGS), ...Object.keys(EC_ALGS)];
const ASYMMETRIC_ALGS = [...Object.keys(RSA_PKCS1_ALGS), ...Object.keys(RSA_PSS_ALGS), ...Object.keys(EC_ALGS)];

/* String-valued claim names that should never be inside a token anybody can read. */
const SENSITIVE_NAME_RE = /(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key|hash|salt|otp|totp|mfa[_-]?seed|recovery[_-]?code)/i;
const PII_NAME_RE = /^(email|e_mail|mail|phone|phone_number|mobile|msisdn|address|street|postal|zip|first_?name|last_?name|full_?name|display_?name|birth|birthdate|dob|ssn|national_?id|passport|tax_?id|iban|account_?number|credit_?card|card_?number)/i;

/* `EMAIL_VALUE_RE` used to be `/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/`. That is
 * quadratic, not linear, and a claim set is attacker-controlled text: a 400 KB claim
 * value took this analyzer 54 SECONDS (measured: 50k->0.7s, 100k->3.6s, 200k->15.8s,
 * 400k->54s -- clean n^2). A token is supposed to be a few hundred bytes; the parser
 * that exists to tell you a token is suspicious was the thing that hung.
 *
 * The fix is the standard one and it is not "add a timeout": anchor the local part to a
 * non-atom character so there is exactly one way to enter the match, and bound every
 * quantified run. A 400 KB value is now under 1 ms, and 1.6 MB is also under 1 ms.
 *
 * It matches the same addresses. Verified both directions on a fixed set of positives
 * and negatives; see fuzz-lab/README.md. */
const EMAIL_VALUE_RE = /(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/;
const CREDENTIAL_VALUE_RE = /(password|passwd|pwd|secret|api[_-]?key|bearer|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]\s*\S/i;
const CONTROL_VALUE_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]|\r|\n/;

const REGISTERED = {
  iss: 'Issuer — who minted the token. A verifier MUST pin this to a fixed value.',
  sub: 'Subject — who the token is about. Must be a stable identifier, not a display name.',
  aud: 'Audience — who the token is FOR. A verifier MUST reject a token minted for someone else.',
  exp: 'Expiration — numeric date after which the token MUST be rejected.',
  nbf: 'Not Before — numeric date before which the token MUST be rejected.',
  iat: 'Issued At — numeric date the token was minted.',
  jti: 'JWT ID — unique id, the only claim that makes replay detection possible.',
};
const COMMON = {
  scope: 'Space-separated OAuth scopes.', scopes: 'OAuth scopes.',
  azp: 'Authorized party (the client the token was issued to).',
  sid: 'Session id.', nonce: 'Replay-binding value (OIDC).',
  role: 'Roles — authorization data inside a bearer token.',
  roles: 'Roles — authorization data inside a bearer token.',
  groups: 'Group membership.', client_id: 'OAuth client identifier.',
  token_use: 'Intended use (id vs access).', auth_time: 'When the end user authenticated.',
  acr: 'Authentication context class.', amr: 'Authentication methods.',
  cnf: 'Confirmation — binds the token to a key (proof-of-possession).',
  kid: 'Key id (header, not a claim).', typ: 'Token type.',
};
const NUMERIC_DATE_CLAIMS = ['exp', 'iat', 'nbf', 'auth_time'];

/* The short list every JWT tutorial uses. Its presence here is the whole test for the
 * "weak key" class: if a token verifies under one of these, the signature conveys no
 * assurance of origin, because the key is guessable. Extend with --weak-secret for a
 * target-specific value; this is not a general cracker and does not try to be one. */
const GUESSABLE_SECRETS = [
  'secret', 'password', 'changeme', 'jwt', 'key', '123456', 'admin', 'test',
  'secretkey', 'private', 'supersecret', 'mysecret', 'jwt-secret', 'dev',
];

/* ------------------------------------------------------------------ helpers */

const fail = (code, message) => { const e = new Error(message); e.exitCode = code; return e; };

function b64uDecode(segment) {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new Error('segment is not base64url');
  return Buffer.from(segment, 'base64url');
}

function decodeJsonSegment(segment, what) {
  const buf = b64uDecode(segment);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    throw new Error(`${what} is not valid UTF-8`);
  }
  try {
    return { value: JSON.parse(text), text };
  } catch (e) {
    throw new Error(`${what} is not valid JSON: ${e.message}`);
  }
}

function readMaybePem(value, what) {
  if (!value) return null;
  if (value.includes('-----BEGIN')) return value;
  const p = path.resolve(value);
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  throw fail(2, `${what}: ${value} is neither a PEM string nor an existing file`);
}

function hmacVerify(alg, key, signingInput, signatureB64u) {
  const expected = crypto.createHmac(HMAC_ALGS[alg], key).update(signingInput).digest();
  let given;
  try {
    given = Buffer.from(signatureB64u, 'base64url');
  } catch {
    return false;
  }
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

function asymVerify(alg, key, signingInput, signatureB64u) {
  let given;
  try {
    given = Buffer.from(signatureB64u, 'base64url');
  } catch {
    return false;
  }
  try {
    if (RSA_PKCS1_ALGS[alg]) {
      return crypto.verify(RSA_PKCS1_ALGS[alg], Buffer.from(signingInput), {
        key, padding: crypto.constants.RSA_PKCS1_PADDING,
      }, given);
    }
    if (RSA_PSS_ALGS[alg]) {
      const pss = RSA_PSS_ALGS[alg];
      return crypto.verify(pss.digest, Buffer.from(signingInput), {
        key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: pss.saltLength,
      }, given);
    }
    return crypto.verify(EC_ALGS[alg], Buffer.from(signingInput), key, given);
  } catch {
    return false;
  }
}

const FAMILY = (alg) => {
  if (alg === 'none') return 'none (unsecured JWS)';
  if (HMAC_ALGS[alg]) return 'HMAC (shared secret)';
  if (RSA_PKCS1_ALGS[alg]) return 'RSA-PKCS1-v1.5 (public/private)';
  if (RSA_PSS_ALGS[alg]) return 'RSA-PSS (public/private)';
  if (EC_ALGS[alg]) return `ECDSA ${EC_ALGS[alg]} (public/private)`;
  return 'unknown';
};
const KEY_TYPE = (alg) => (HMAC_ALGS[alg] ? 'shared-secret' : alg === 'none' ? 'none' : ASYMMETRIC_ALGS.includes(alg) ? 'public' : 'unknown');

/* ------------------------------------------------------------------ the analysis */

export function analyze(token, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const ttlMax = opts.ttlMax ?? 3600;
  const findings = [];
  const add = (id, severity, cls, title, evidence, why) =>
    findings.push({ id, severity, class: cls, title, evidence, why });

  const raw = String(token).trim();
  const inputInfo = {
    source: opts.source || 'argument',
    length: raw.length,
    sha256: crypto.createHash('sha256').update(raw).digest('hex'),
    segments: raw.split('.').length,
  };

  if (!raw) throw fail(3, 'empty token');

  /* --- JWE is a different format and this tool does not pretend to read it. */
  if (inputInfo.segments === 5) {
    add('JWE_UNSUPPORTED', 'info', CLASSES.SIGNATURE,
      'five-segment token: this is a JWE, not a JWS',
      'segments=5 (header.encrypted_key.iv.ciphertext.tag)',
      'JWE payloads are encrypted, not merely base64url-encoded. Decoding one requires the recipient key; '
      + 'everything this tool can say about a JWS is unavailable here. Out of scope by design — see README limits.');
    return finish(raw, inputInfo, null, null, null, {
      status: 'not-applicable', material: 'none',
      detail: 'JWE: the payload is encrypted, so there is no readable claim set and no JWS signature to check',
    }, findings, now, ttlMax);
  }

  if (inputInfo.segments !== 3) {
    throw fail(3, `not a compact JWS: expected 3 dot-separated segments, got ${inputInfo.segments}`);
  }

  const [hSeg, pSeg, sigSeg] = raw.split('.');

  let header;
  let payload;
  let payloadText;
  try {
    const h = decodeJsonSegment(hSeg, 'header');
    header = h.value;
  } catch (e) {
    throw fail(3, `header: ${e.message}`);
  }
  try {
    const p = decodeJsonSegment(pSeg, 'payload');
    payload = p.value;
    payloadText = p.text;
  } catch (e) {
    throw fail(3, `payload: ${e.message}`);
  }

  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    throw fail(3, 'header decoded to a non-object');
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw fail(3, 'payload decoded to a non-object (a JWS payload of this shape is not a claim set)');
  }

  const algRaw = header.alg;
  const alg = typeof algRaw === 'string' ? algRaw : null;
  const signingInput = `${hSeg}.${pSeg}`;

  /* --- header-level algorithm findings ------------------------------------- */

  if (alg === null) {
    add('ALG_ABSENT', 'high', CLASSES.ALGORITHM,
      'no `alg` header parameter',
      'header.alg is missing or not a string',
      'RFC 7515 makes `alg` REQUIRED. A verifier that defaults to `none` or to a permissive branch here accepts anything.');
  } else if (alg.toLowerCase() === 'none') {
    add('ALG_NONE', 'high', CLASSES.ALGORITHM,
      'unsigned token: alg=none',
      `${JSON.stringify(alg)} (case-insensitive match on "none")`,
      'The token asserts that there is no signature to check. Correct behaviour is to reject it unless the caller '
      + 'explicitly opted in; the classic bug is a verifier that reads `alg` from this header and honours what it reads.');
  } else if (!KNOWN_ALGS.includes(algRaw)) {
    add('ALG_UNKNOWN', 'high', CLASSES.ALGORITHM,
      `unrecognised algorithm: ${JSON.stringify(algRaw)}`,
      `header.alg=${JSON.stringify(algRaw)} not in ${JSON.stringify(KNOWN_ALGS)}`,
      'Unknown algorithms cannot be assessed. Note the reverse hazard too: a verifier that keys its dispatch off this '
      + 'string may reach a default branch that verifies nothing.');
  }

  if (HMAC_ALGS[algRaw]) {
    add('ALG_SYMMETRIC', 'low', CLASSES.ALGORITHM,
      `symmetric algorithm: ${algRaw}`,
      `family=${FAMILY(algRaw)}`,
      'HS* means the verifying key is a shared secret. Report it as a fact, not a bug: it is only a finding when the '
      + 'same service also publishes, or accepts, an asymmetric key under this identifier — see ALG_CONFUSION_RISK.');
  }

  for (const [h, cls, why] of [
    ['jku', 'a URL the verifier is expected to FETCH the key from',
      'Set by whoever wrote the token. A verifier that honours it hands key selection to the attacker (and to SSRF). '
      + 'This tool deliberately does NOT fetch it — outbound reach during analysis is a stop line.'],
    ['x5u', 'a URL the verifier is expected to FETCH a certificate chain from',
      'Same class as `jku`, same refusal to dereference.'],
    ['x5c', 'an embedded certificate chain supplied by the token itself',
      'The token carries its own key material. Trusting it makes the signature check a tautology.'],
    ['jwk', 'an embedded JSON Web Key supplied by the token itself',
      'The token carries its own public key, so it can verify itself. The signature proves nothing about the issuer.'],
    ['crit', 'a list of header extensions the verifier MUST understand and MUST reject the token otherwise',
      'Almost no implementation processes `crit`. A verifier that ignores it silently accepts headers it should have refused.'],
  ]) {
    if (header[h] !== undefined) {
      add(`${h.toUpperCase()}_HEADER`, h === 'crit' ? 'medium' : 'high', CLASSES.ALGORITHM,
        `header carries \`${h}\`: ${cls}`,
        `${h}=${JSON.stringify(header[h]).slice(0, 200)}`, why);
    }
  }

  /* --- signature ----------------------------------------------------------- */
  const masterPem = readMaybePem(opts.rsaPub, '--rsa-pub');
  const secret = opts.secret ?? null;
  const isUnsigned = typeof algRaw === 'string' && algRaw.toLowerCase() === 'none';
  const signature = isUnsigned
    ? { status: 'unsigned', material: 'none', detail: 'alg=none — the token has no signature to check, by design' }
    : { status: 'unverified', material: 'none', detail: 'no key material supplied — signature not checked' };
  let confusionConfirmed = false;
  let weakSecretConfirmed = false;

  if (algRaw && !isUnsigned && KNOWN_ALGS.includes(algRaw)) {
    if (HMAC_ALGS[algRaw]) {
      if (secret !== null && hmacVerify(algRaw, secret, signingInput, sigSeg)) {
        signature.status = 'valid';
        signature.material = 'hmac-secret';
        signature.detail = `HMAC-${HMAC_ALGS[algRaw]} over the signing input matches the supplied secret`;
        weakSecretConfirmed = GUESSABLE_SECRETS.includes(secret) || (opts.weakSecret != null && secret === opts.weakSecret);
        if (weakSecretConfirmed) {
          add('SIG_WEAK_SECRET', 'high', CLASSES.SIGNATURE,
            'token verifies under a guessable secret',
            `HMAC-${HMAC_ALGS[algRaw]} matches the secret ${JSON.stringify(secret)}`,
            'The key is in a dictionary. Anyone who can guess it can mint tokens this service will accept, so the '
            + 'signature provides no assurance of origin.');
        }
      } else if (secret !== null) {
        signature.status = 'invalid';
        signature.material = 'hmac-secret';
        signature.detail = `HMAC-${HMAC_ALGS[algRaw]} over the signing input does NOT match the supplied secret`;
      }
    } else if (masterPem) {
      if (asymVerify(algRaw, masterPem, signingInput, sigSeg)) {
        signature.status = 'valid';
        signature.material = 'asymmetric-key';
        signature.detail = `${algRaw} signature verifies under the supplied public key`;
      } else {
        signature.status = 'invalid';
        signature.material = 'asymmetric-key';
        signature.detail = `${algRaw} signature does NOT verify under the supplied public key`;
      }
    }

    /* The confusion check in both directions: an HS* token that verifies with a PUBLIC
     * key, and an asymmetric token whose signature happens to be a valid HMAC. */
    if (masterPem) {
      if (HMAC_ALGS[algRaw] && hmacVerify(algRaw, masterPem, signingInput, sigSeg)) {
        confusionConfirmed = true;
        signature.status = 'valid-as-hmac-over-public-key';
        signature.material = 'public-key-used-as-hmac-secret';
        signature.detail = `HMAC-${HMAC_ALGS[algRaw]} verifies when the *public* key PEM is used as the shared secret`;
      } else if (ASYMMETRIC_ALGS.includes(algRaw)) {
        for (const h of Object.keys(HMAC_ALGS)) {
          if (hmacVerify(h, masterPem, signingInput, sigSeg)) {
            confusionConfirmed = true;
            signature.status = 'valid-as-hmac-over-public-key';
            signature.material = 'public-key-used-as-hmac-secret';
            signature.detail = `asymmetric header ${algRaw}, but the signature is a valid HMAC-${HMAC_ALGS[h]} keyed on the public key PEM`;
          }
        }
      }
    }
  }

  if (signature.status === 'invalid') {
    add('SIG_INVALID', 'high', CLASSES.SIGNATURE,
      'signature does not verify',
      signature.detail,
      'Either the token was modified after signing, or it was signed with a different key than the one supplied. '
      + 'If the caller was sure the key was right, treat the token as tampered.');
  } else if (signature.status === 'unverified') {
    add('SIG_UNVERIFIED', 'info', CLASSES.SIGNATURE,
      'signature not checked',
      'no --secret / --rsa-pub supplied',
      'Everything here is a statement about structure and claims, not about authenticity. Supply the verification key '
      + 'to turn this into a real integrity verdict. This is a limit of the run, not a property of the token.');
  }

  if (algRaw && typeof algRaw === 'string' && algRaw.toLowerCase() === 'none' && sigSeg !== '') {
    add('ALG_NONE_WITH_SIGNATURE', 'medium', CLASSES.ALGORITHM,
      'alg=none but the signature segment is not empty',
      `signature length ${sigSeg.length}`,
      'A malformed unsecured JWS. Some verifiers ignore the discrepancy; some crash; a few will still verify if the '
      + 'bytes happen to match another branch. It is a shape worth flagging on its own.');
  }

  /* --- configured-vs-presented algorithm ----------------------------------- */
  if (opts.serverAlg) {
    /* `none` gets ALG_NONE, which already says everything a mismatch would. */
    if (algRaw !== opts.serverAlg && !isUnsigned) {
      const isConfusion = HMAC_ALGS[algRaw] && ASYMMETRIC_ALGS.includes(opts.serverAlg);
      add(isConfusion ? 'ALG_CONFUSION_RISK' : 'ALG_MISMATCH_CONFIG', 'high', CLASSES.ALGORITHM,
        isConfusion
          ? `algorithm confusion risk: verifier is configured ${opts.serverAlg}, token presents ${algRaw}`
          : `token algorithm ${JSON.stringify(algRaw)} does not match the verifier's configured ${opts.serverAlg}`,
        `config alg=${opts.serverAlg}, token alg=${algRaw}`,
        isConfusion
          ? `The verifier is built for ${opts.serverAlg} — asymmetric, so its "secret" is public. This token asks it to `
            + 'use HMAC instead, keyed on that public material. If the verifier selects the key family from this header '
            + 'rather than from its own configuration, anyone holding the public key can mint tokens it will accept.'
          : 'Either the verifier is reading `alg` from the token rather than its own configuration (which is how '
            + 'confusion attacks start), or this token was minted for a different service. Both are worth a follow-up.');
    }
  }
  if (confusionConfirmed) {
    add('ALG_CONFUSION_CONFIRMED', 'high', CLASSES.ALGORITHM,
      'algorithm confusion confirmed: the signature is an HMAC keyed on the public key',
      signature.detail,
      'Not a risk assessment — a proof. This token verifies if, and only if, the verifier uses the published public '
      + 'key as an HMAC secret. Anybody holding that public key can produce tokens that pass such a verifier.');
  }

  /* --- claims: presence, expiry, provenance -------------------------------- */
  const claimsOut = [];
  for (const [name, value] of Object.entries(payload)) {
    const isRegistered = Object.prototype.hasOwnProperty.call(REGISTERED, name);
    const kind = isRegistered ? 'registered' : Object.prototype.hasOwnProperty.call(COMMON, name) ? 'common' : 'custom';
    const meaning = REGISTERED[name] || COMMON[name] || 'Not a registered claim — value is entirely issuer-defined; read it as data, not as a guarantee.';
    const flags = [];
    if (NUMERIC_DATE_CLAIMS.includes(name) && typeof value !== 'number') {
      flags.push(`NUMERIC_DATE_WRONG_TYPE: ${name} should be a NumericDate (JSON number), got ${Array.isArray(value) ? 'array' : typeof value}`);
    }
    if (typeof value === 'string') {
      if (SENSITIVE_NAME_RE.test(name)) flags.push('SENSITIVE_NAME');
      if (PII_NAME_RE.test(name) || EMAIL_VALUE_RE.test(value)) flags.push('PII_IN_CLAIM');
      if (CREDENTIAL_VALUE_RE.test(value)) flags.push('CREDENTIAL_IN_VALUE');
      if (CONTROL_VALUE_RE.test(value)) flags.push('CONTROL_CHARACTERS_IN_VALUE');
      if (value.length > 512) flags.push(`OVERSIZED_VALUE: ${value.length} chars`);
    }
    claimsOut.push({ name, kind, meaning, value: redact(name, value), flags });
  }

  for (const c of claimsOut) {
    for (const f of c.flags) {
      if (f.startsWith('NUMERIC_DATE_WRONG_TYPE')) {
        add('CLAIM_WRONG_TYPE', 'medium', CLASSES.CLAIMS,
          f.split(':')[0].trim(), `claim ${c.name} = ${JSON.stringify(c.value)}`,
          'Time claims must be numbers. A string that compares as false, or an array, silently disables the check that '
          + 'was supposed to bound the token.');
      } else if (f === 'SENSITIVE_NAME') {
        add('SENSITIVE_CLAIM', 'high', CLASSES.PROVENANCE,
          `credential-shaped claim: ${c.name}`,
          `${c.name} = ${JSON.stringify(c.value)}`,
          'A JWS payload is signed, not encrypted: base64url is an encoding, and anyone holding the token can read it. '
          + 'Secrets, hashes and keys belong in a lookup keyed by an opaque id, never in the claim set.');
      } else if (f === 'CREDENTIAL_IN_VALUE') {
        add('CREDENTIAL_IN_VALUE', 'high', CLASSES.PROVENANCE,
          `credential material inside claim value: ${c.name}`,
          `${c.name} = ${JSON.stringify(c.value)}`,
          'A claim whose *value* contains `password=...` / `api_key=...` / a private key block. Same reasoning as '
          + 'SENSITIVE_CLAIM: the payload is readable by every bearer.');
      } else if (f === 'PII_IN_CLAIM') {
        add('PII_CLAIM', 'medium', CLASSES.PROVENANCE,
          `personal data in claim: ${c.name}`,
          `${c.name} = ${JSON.stringify(c.value)}`,
          'Tokens travel through browsers, logs, proxies and referrers. Personal data in a claim leaks with the token.');
      } else if (f === 'CONTROL_CHARACTERS_IN_VALUE') {
        add('CLAIM_INJECTION', 'high', CLASSES.PROVENANCE,
          `control characters in claim value: ${c.name}`,
          `${c.name} = ${JSON.stringify(c.value).slice(0, 160)}`,
          'Newlines and NULs inside a claim are how claim values get re-parsed as something else downstream — a log line, '
          + 'a header, a JSON fragment inside a signature. Flag it even when this tool cannot name the sink.');
      } else if (f.startsWith('OVERSIZED_VALUE')) {
        add('CLAIM_OVERSIZED', 'low', CLASSES.PROVENANCE,
          `oversized claim value: ${c.name}`, `${c.name} is ${f.split(':')[1].trim()}`,
          'A large blob in a claim is often a smuggled payload or an accidentally embedded document.');
      }
    }
  }

  if (!Object.prototype.hasOwnProperty.call(payload, 'exp')) {
    add('MISSING_EXP', 'high', CLASSES.CLAIMS,
      'no expiry: the token never expires',
      'payload has no `exp` claim',
      'Nothing bounds this token\'s lifetime. A leaked copy is valid forever, which turns any single disclosure into a '
      + 'permanent credential.');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'aud')) {
    add('MISSING_AUD', 'medium', CLASSES.CLAIMS,
      'no audience: the token is valid anywhere the signing key is trusted',
      'payload has no `aud` claim',
      'A token minted for one service and accepted by another is the whole of the "token confusion" class. Without `aud` '
      + 'there is no field for the verifier to pin, so every service sharing the key accepts it.');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'iss')) {
    add('MISSING_ISS', 'low', CLASSES.CLAIMS,
      'no issuer claim', 'payload has no `iss` claim',
      'A verifier cannot pin who minted this token, so it cannot distinguish two issuers that share a key.');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'sub')) {
    add('MISSING_SUB', 'low', CLASSES.CLAIMS,
      'no subject claim', 'payload has no `sub` claim',
      'Nothing names the principal the token is about; authorization decisions have nothing stable to key on.');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'jti')) {
    add('MISSING_JTI', 'low', CLASSES.CLAIMS,
      'no jti: replay cannot be detected',
      'payload has no `jti` claim',
      'Without a unique id a verifier cannot tell a replayed token from a fresh one. Combine with a missing `exp` and '
      + 'the token is replayable forever.');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'nbf')) {
    add('MISSING_NBF', 'info', CLASSES.CLAIMS,
      'no nbf claim', 'payload has no `nbf` claim',
      'Optional. Absent `nbf` is not a defect by itself; it matters only when the verifier is expected to reject '
      + 'not-yet-valid tokens.');
  }
  if (header.kid === undefined) {
    add('NO_KID', 'low', CLASSES.ALGORITHM,
      'no kid header: key selection is ambiguous',
      'header has no `kid`',
      'Harmless with one key, a real problem with a rotation set or a JWKS: the verifier has to guess, and guessing is '
      + 'how a token ends up verified against the wrong key.');
  }
  if (JSON.stringify(payload).length > 4096) {
    add('PAYLOAD_LARGE', 'low', CLASSES.PROVENANCE,
      'payload is large for a claim set',
      `${payloadText.length} bytes of JSON`,
      'Size is not a vulnerability. It is a smell: tokens are meant to be small, and large ones usually mean the payload '
      + 'is being used as a data store.');
  }

  /* --- expiry block -------------------------------------------------------- */
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const exp = num(payload.exp);
  const iat = num(payload.iat);
  const nbf = num(payload.nbf);
  const expiry = {
    now,
    exp, iat, nbf,
    status: 'no-bounds',
    lifetime_seconds: null,
    age_seconds: null,
    seconds_remaining: null,
  };
  if (exp !== null) {
    expiry.lifetime_seconds = iat !== null ? exp - iat : null;
    expiry.seconds_remaining = exp - now;
    if (exp <= now) {
      expiry.status = 'expired';
      add('EXPIRED', 'high', CLASSES.CLAIMS,
        'token is expired',
        `exp=${exp} (${new Date(exp * 1000).toISOString()}), now=${now}, ${now - exp}s past`,
        'Reported because a token that is expired is not automatically rejected — plenty of verifiers never check. If '
        + 'this token was accepted by a service, the finding is the acceptance, not the expiry.');
    } else if (expiry.lifetime_seconds !== null && expiry.lifetime_seconds > ttlMax) {
      expiry.status = 'too-far';
      add('EXP_TOO_FAR', 'medium', CLASSES.CLAIMS,
        `lifetime exceeds the policy horizon (${expiry.lifetime_seconds}s > ${ttlMax}s)`,
        `iat=${iat} exp=${exp} -> ${expiry.lifetime_seconds}s (${(expiry.lifetime_seconds / 3600).toFixed(1)}h)`,
        'A long-lived bearer token widens the window in which one disclosure is useful. The horizon is a policy input '
        + '(--ttl-max), not a fact about the token.');
    } else {
      expiry.status = 'valid';
    }
  } else {
    expiry.status = 'absent';
  }
  if (nbf !== null && exp !== null && nbf > exp) {
    add('NBF_AFTER_EXP', 'medium', CLASSES.CLAIMS,
      'nbf is after exp: the token can never be valid',
      `nbf=${nbf} > exp=${exp}`,
      'A malformed window. Implementations differ on which bound wins, which makes the token\'s actual validity '
      + 'implementation-defined.');
  }
  if (iat !== null && exp !== null && exp < iat) {
    add('EXP_BEFORE_IAT', 'medium', CLASSES.CLAIMS,
      'exp is before iat', `iat=${iat} exp=${exp}`,
      'The token expired before it was issued. Usually a clock-skew bug in the issuer; occasionally deliberate.');
  }

  return finish(raw, inputInfo, header, payload, { alg: algRaw, family: FAMILY(algRaw), keyType: KEY_TYPE(algRaw), signed: !(typeof algRaw === 'string' && algRaw.toLowerCase() === 'none'), known: KNOWN_ALGS.includes(algRaw) }, signature, findings, now, ttlMax, {
    claims: claimsOut, expiry,
  });
}

function redact(name, value) {
  if (typeof value === 'string' && (SENSITIVE_NAME_RE.test(name) || CREDENTIAL_VALUE_RE.test(value))) {
    return value.length > 8 ? `${value.slice(0, 4)}…<redacted ${value.length} chars>` : '<redacted>';
  }
  return value;
}

function finish(raw, inputInfo, header, payload, algorithm, signature, findings, now, ttlMax, extra = {}) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  findings.sort((a, b) => (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) || a.id.localeCompare(b.id));
  /* The instance list keeps every occurrence with its own evidence; the id list is the
   * deduplicated set, because that is the unit `--expect` and the loop compare. */
  const ids = [...new Set(findings.map((f) => f.id))];

  const present = (cls) => findings.filter((f) => f.class === cls).map((f) => f.id);
  const idsFor = (list) => [...new Set(present(list))];
  const CONFUSION_IDS = ['ALG_CONFUSION_RISK', 'ALG_CONFUSION_CONFIRMED', 'ALG_MISMATCH_CONFIG', 'ALG_UNKNOWN', 'JKU_HEADER', 'X5U_HEADER', 'X5C_HEADER', 'JWK_HEADER', 'CRIT_HEADER'];
  const UNSIGNED_IDS = ['ALG_NONE', 'ALG_ABSENT', 'ALG_NONE_WITH_SIGNATURE'];
  const weaknessClasses = {
    'unsigned-none': {
      present: ids.some((x) => UNSIGNED_IDS.includes(x)),
      findings: idsFor(CLASSES.ALGORITHM).filter((x) => UNSIGNED_IDS.includes(x)),
      question: 'Does this token ask to be trusted without a signature, and is anything set up to honour that?',
    },
    'algorithm-confusion': {
      present: ids.some((x) => CONFUSION_IDS.includes(x)),
      findings: idsFor(CLASSES.ALGORITHM).filter((x) => !UNSIGNED_IDS.includes(x)),
      question: 'Is the key family, or the key itself, being chosen by the token instead of by the verifier\'s configuration? '
        + 'The `findings` list also carries algorithm hygiene (ALG_SYMMETRIC, NO_KID) that is worth reviewing but is not confusion on its own.',
    },
    'signature-integrity': {
      present: ids.some((x) => x.startsWith('SIG_') && x !== 'SIG_UNVERIFIED'),
      findings: idsFor(CLASSES.SIGNATURE),
      question: 'Given the key material supplied, does the signature actually stand up?',
    },
    'weak-claim-validation': {
      present: idsFor(CLASSES.CLAIMS).length > 0,
      findings: idsFor(CLASSES.CLAIMS),
      question: 'If a verifier checks only the signature, what does this token still let the bearer do, and for how long?',
    },
    'claim-provenance': {
      present: idsFor(CLASSES.PROVENANCE).length > 0,
      findings: idsFor(CLASSES.PROVENANCE),
      question: 'Does the payload carry what a signed-but-readable payload must never carry?',
    },
  };

  const highest = counts.high ? 'high' : counts.medium ? 'medium' : counts.low ? 'low' : 'info';

  return {
    ok: true,
    schema: 'crypto-lab/analysis@1',
    input: inputInfo,
    algorithm,
    signature,
    header,
    claims: extra.claims ?? null,
    expiry: extra.expiry ?? null,
    weaknessClasses,
    findings,
    summary: {
      counts,
      highest,
      finding_ids: ids,
      finding_instances: findings.length,
      verdict: counts.high > 0
        ? 'at least one high-severity weakness class is present'
        : counts.medium > 0
          ? 'no high-severity finding; medium findings present'
          : ids.length > 0
            ? 'only low/informational findings'
            : 'no finding from this catalogue — which is not a clean bill of health',
      catalogue_complete: false,
      note: 'Findings come from a fixed rule catalogue. A zero-finding result means "none of the known shapes", '
        + 'never "no weakness". Unverified signature and unhandled formats are reported as limits above.',
      ttl_max_used: ttlMax,
    },
  };
}

/* ------------------------------------------------------------------ CLI */

function usage(stream = process.stdout) {
  stream.write(`crypto-lab analyzer — read a JWT and report which weakness classes it carries.

  node crypto-lab/tools/analyze.mjs --token <jws> [options]
  node crypto-lab/tools/analyze.mjs --file <path>            (raw token, or JSON with .token)
  node crypto-lab/tools/analyze.mjs --stdin

options
  --secret <s>          HMAC secret candidate; verifies HS* tokens
  --secret-file <p>     read the HMAC secret from a file
  --rsa-pub <pem|path>  public key (PEM string or file); verifies RS*/PS*/ES*, detects confusion
  --server-alg <alg>    the algorithm the assessed verifier is CONFIGURED for
  --ttl-max <seconds>   lifetime policy horizon for EXP_TOO_FAR (default 3600)
  --now <epoch>         freeze the clock (deterministic tests)
  --expect <id,id>      require exactly this finding-id set; exit 4 otherwise
  --quiet               suppress the human-readable transcript on stderr

exit 0 analysed · 2 usage · 3 bad input · 4 --expect mismatch

Nothing is fetched. A jku/x5u header is reported and never dereferenced.
`);
}

function parseArgs(argv) {
  const o = { quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const take = () => {
      const v = argv[i + 1];
      if (v === undefined) throw fail(2, `${a} needs a value`);
      i += 1;
      return v;
    };
    switch (a) {
      case '--token': o.token = take(); break;
      case '--file': o.file = take(); break;
      case '--stdin': o.stdin = true; break;
      case '--secret': o.secret = take(); break;
      case '--secret-file': o.secret = fs.readFileSync(take(), 'utf8').trim(); break;
      case '--rsa-pub': o.rsaPub = take(); break;
      case '--server-alg': o.serverAlg = take(); break;
      case '--ttl-max': o.ttlMax = Number(take()); break;
      case '--now': o.now = Number(take()); break;
      case '--expect': o.expect = take().split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--quiet': o.quiet = true; break;
      /* stdout is JSON unconditionally; the flag exists so callers can be explicit and
       * so a scripted invocation reads the same as the other lab tools. */
      case '--json': o.json = true; break;
      case '-h': case '--help': case '/?': usage(); process.exit(0); break;
      default: throw fail(2, `unknown option ${a}`);
    }
  }
  return o;
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

function readInput(o) {
  if (o.token) return { token: o.token, source: '--token' };
  if (o.file) {
    const text = fs.readFileSync(o.file, 'utf8').trim();
    if (text.startsWith('{')) {
      const j = JSON.parse(text);
      if (typeof j.token !== 'string') throw fail(3, `${o.file}: JSON has no string .token`);
      return { token: j.token, source: `${o.file}:.token` };
    }
    return { token: text.split(/\r?\n/)[0].trim(), source: o.file };
  }
  return null;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  let input = readInput(o);
  if (!input && o.stdin) input = { token: (await readStdin()).trim(), source: '--stdin' };
  if (!input) { usage(process.stderr); throw fail(2, 'no token: pass --token, --file or --stdin'); }
  if (!input.token) throw fail(3, `${input.source}: empty`);

  const result = analyze(input.token, {
    now: o.now, ttlMax: o.ttlMax, rsaPub: o.rsaPub, secret: o.secret, serverAlg: o.serverAlg,
    weakSecret: o.secret === 'secret', source: input.source,
  });

  if (!o.quiet) {
    const s = result.summary;
    process.stderr.write(`\n${result.input.source}  ${result.input.length} bytes  sha256:${result.input.sha256.slice(0, 16)}\n`);
    if (result.algorithm) {
      process.stderr.write(`header     alg=${result.algorithm.alg}  family=${result.algorithm.family}  key=${result.algorithm.keyType}`
        + `${result.header && result.header.kid ? `  kid=${result.header.kid}` : ''}${result.header && result.header.typ ? `  typ=${result.header.typ}` : ''}\n`);
    }
    process.stderr.write(`signature  ${result.signature.status}  (${result.signature.detail})\n`);
    if (result.expiry) {
      const e = result.expiry;
      process.stderr.write(`expiry     status=${e.status}`
        + `${e.exp !== null ? `  exp=${new Date(e.exp * 1000).toISOString()}` : ''}`
        + `${e.lifetime_seconds !== null ? `  lifetime=${e.lifetime_seconds}s` : ''}`
        + `${e.seconds_remaining !== null ? `  remaining=${e.seconds_remaining}s` : ''}\n`);
    }
    if (result.claims) {
      process.stderr.write(`claims     ${result.claims.map((c) => c.name).join(', ')}\n`);
      for (const c of result.claims) {
        process.stderr.write(`  ${c.name.padEnd(18)} ${c.kind.padEnd(10)} ${JSON.stringify(c.value).slice(0, 72)}`
          + `${c.flags.length ? `   [!] ${c.flags.join(' ')}` : ''}\n`);
      }
    }
    process.stderr.write('\nweakness classes\n');
    for (const [name, v] of Object.entries(result.weaknessClasses)) {
      process.stderr.write(`  ${v.present ? 'PRESENT' : '  -    '}  ${name.padEnd(24)} ${v.findings.join(', ') || '(none)'}\n`);
    }
    process.stderr.write('\nfindings\n');
    if (!result.findings.length) process.stderr.write('  (none from this catalogue — which is not a clean bill of health)\n');
    for (const f of result.findings) {
      process.stderr.write(`  [${f.severity.padEnd(6)}] ${f.id.padEnd(24)} ${f.title}\n`);
      process.stderr.write(`             evidence: ${String(f.evidence).slice(0, 160)}\n`);
    }
    process.stderr.write(`\nverdict    ${s.verdict}  (high=${s.counts.high} medium=${s.counts.medium} low=${s.counts.low} info=${s.counts.info})\n\n`);
  }

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (o.expect !== undefined) {
    const got = new Set(result.summary.finding_ids);
    const want = new Set(o.expect);
    const missing = [...want].filter((x) => !got.has(x));
    const unexpected = [...got].filter((x) => !want.has(x));
    if (missing.length || unexpected.length) {
      process.stderr.write(`EXPECT MISMATCH (${o.expect.length} expected, ${got.size} found)\n`
        + `  missing:    ${missing.join(', ') || '(none)'}\n  unexpected: ${unexpected.join(', ') || '(none)'}\n`);
      process.exit(4);
    }
  }
  process.exit(0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((e) => {
    process.stderr.write(`analyze: ${e.message}\n`);
    process.exit(e.exitCode || 3);
  });
}
