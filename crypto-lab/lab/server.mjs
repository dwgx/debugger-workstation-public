/* server.mjs — crypto-lab loopback target: a token issuer plus four verifiers.
 *
 * This is a *teaching* target, and its whole value is that the four verifier modes are
 * real code, not labels. Each mode prints the checks it actually performed, so a claim
 * about a token ("this would be accepted by a `none`-trusting service") is checkable
 * against the service instead of asserted.
 *
 * |
 * | mode            | where `alg` comes from | signature key          | exp/nbf/aud/iss |
 * |-----------------|------------------------|------------------------|-----------------|
 * | strict          | config (pinned list)   | RSA public key         | all enforced    |
 * | none-accepting  | token header           | none when alg=none     | exp + aud only  |
 * | confused        | token header           | HMAC keyed on the RSA  | exp only        |
 * |                 |                        | public PEM (the bug)   |                 |
 * | naive           | config (pinned list)   | RSA public key         | none enforced   |
 * |
 *
 * Binds 127.0.0.1 only and refuses to start otherwise.
 */
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALL_ALGS, HMAC_ALGS,
  decode, jwksFromPublicPem, keyId, sign, verifySignature,
} from './jose.mjs';
import { LAB_HMAC_SECRET, WEAK_HMAC_SECRET, rsaKeypair } from './keys.mjs';

export const ISSUER = 'crypto-lab';
export const AUDIENCE = 'crypto-lab-api';
export const CONFIG_ALGORITHMS = ['RS256', 'PS256']; // the allowlist `strict` uses
export const DEFAULT_TTL_S = 300;

export function createLab({ log = () => {} } = {}) {
  const rsa = rsaKeypair();
  const KID = `lab-rsa-${keyId(rsa.publicPem)}`;
  if (rsa.generated) log(`generated RSA-${rsa.bits} keypair -> crypto-lab/keys/ (gitignored)`);

  /* ---------------------------------------------------------------- issuance */
  const now = () => Math.floor(Date.now() / 1000);

  function baseClaims(over = {}) {
    const iat = now();
    return {
      iss: ISSUER,
      aud: AUDIENCE,
      /* Opaque identifier, deliberately not an email address: the `strong` profile is
       * the negative control and must carry no provenance finding at all. */
      sub: 'usr_1f4c9a2b7e',
      role: 'analyst',
      iat,
      nbf: iat - 1,
      exp: iat + DEFAULT_TTL_S,
      jti: keyId(String(iat), String(Math.random())),
      ...over,
    };
  }

  const ISSUERS = {
    /* The control. Every claim a verifier could want, correct algorithm, real key. */
    strong: () => ({
      token: sign({ alg: 'RS256', kid: KID }, baseClaims(), rsa.privatePem),
      note: 'RS256, kid present, iss/aud/sub/exp/nbf/iat/jti all present, 5 min TTL',
    }),

    /* Class: missing / weak claim validation. Cryptographically fine, semantically
     * naked — no expiry, no audience, no jti, and the payload carries things that have
     * no business being in a claim. A verifier that only checks the signature accepts
     * this forever. */
    'weak-claims': () => {
      const p = baseClaims({ role: 'admin' });
      delete p.exp; delete p.aud; delete p.jti; delete p.nbf;
      const iat = p.iat;
      return {
        token: sign({ alg: 'RS256', kid: KID }, {
          ...p, iat,
          /* provenance problem: credentials and PII stuffed into a readable payload */
          sub: 'analyst@lab.invalid',
          password_hash: '5f4dcc3b5aa765d61d8327deb882cf99',
          api_key: 'lab-fake-api-key-0000-not-real',
          email: 'analyst@lab.invalid',
          internal_note: 'tier=staff; billing_exempt=true',
        }, rsa.privatePem),
        note: 'RS256 but no exp/aud/jti, and credentials + PII in the payload',
      };
    },

    /* Class: `none`. The token says "unsigned"; a verifier that reads `alg` from the
     * token and has no allowlist obeys. */
    none: () => {
      const t = sign({ alg: 'none', kid: KID }, baseClaims({ role: 'admin' }));
      return { token: t, note: 'alg=none, empty signature segment, admin role, valid claims' };
    },

    /* Class: algorithm confusion. The token is HS256; the HMAC secret is the service's
     * *public* key, which anybody holding the JWKS can produce. Nothing here is
     * "forged" in a cryptographic sense — HS256 is a correct HMAC. The bug is the
     * verifier choosing the key family from the token's `alg`. */
    confusion: () => ({
      token: sign({ alg: 'HS256', kid: KID }, baseClaims({ role: 'admin' }), rsa.publicPem),
      note: 'HS256 keyed on the RSA PUBLIC key PEM — accepted by `confused`, rejected by `strict`',
    }),

    /* Class: weak key. HS256 with a dictionary secret. */
    'weak-secret': () => ({
      token: sign({ alg: 'HS256', kid: KID }, baseClaims(), WEAK_HMAC_SECRET),
      note: `HS256 with the guessable secret "${WEAK_HMAC_SECRET}"`,
    }),
  };

  /* ---------------------------------------------------------------- verification */
  /* Each verifier returns the checks it RAN. An empty list is itself the finding. */
  function verifyStrict(token) {
    let t;
    try { t = decode(token); } catch (e) { return reject('malformed', `decode: ${e.message}`); }
    const checks = [];
    const alg = t.header.alg;
    checks.push('alg-from-config');
    if (!CONFIG_ALGORITHMS.includes(alg)) {
      return reject('alg-not-allowed', `alg ${alg} not in configured ${JSON.stringify(CONFIG_ALGORITHMS)}`, { alg });
    }
    checks.push('sig');
    if (!verifySignature(token, rsa.publicPem, alg)) return reject('bad-signature', 'signature does not verify', { alg });
    checks.push('exp', 'nbf', 'iss', 'aud', 'required-claims');
    const why = checkClaims(t.payload, { exp: true, nbf: true, iss: true, aud: true, required: true });
    if (why) return reject(why.code, why.message, { alg });
    return accept(alg, checks, t.payload);
  }

  /* The bug, verbatim: `alg` from the token, and when it says HS* we reach for a key
   * of the wrong family. */
  function verifyConfused(token) {
    let t;
    try { t = decode(token); } catch (e) { return reject('malformed', `decode: ${e.message}`); }
    const alg = t.header.alg;
    const checks = ['alg-from-token-header', 'exp'];
    if (!ALL_ALGS.includes(alg)) return reject('alg-unknown', `unsupported alg ${alg}`, { alg });
    /* One key handed to two key families: `verifySignature` reads the alg, so an HS*
     * header makes node:crypto HMAC the *public PEM bytes* as if they were a shared
     * secret. The confusion is not simulated — it is what this line actually does. */
    if (!verifySignature(token, rsa.publicPem, alg)) {
      return reject('bad-signature', 'signature does not verify under header alg', { alg });
    }
    const why = checkClaims(t.payload, { exp: true });
    if (why) return reject(why.code, why.message, { alg });
    return accept(alg, checks, t.payload);
  }

  /* No allowlist, no config: whatever the token asks for. `none` is honored. */
  function verifyNoneAccepting(token) {
    let t;
    try { t = decode(token); } catch (e) { return reject('malformed', `decode: ${e.message}`); }
    const alg = t.header.alg;
    const checks = ['alg-from-token-header'];
    if (alg === 'none') {
      checks.push('exp', 'aud');
      if (t.signature !== '') return reject('none-with-signature', 'alg=none but signature segment is not empty', { alg });
      const why = checkClaims(t.payload, { exp: true, aud: true });
      if (why) return reject(why.code, why.message, { alg });
      return accept('none', checks, t.payload, 'accepted UNSIGNED — nothing here proves who wrote these claims');
    }
    checks.push('sig', 'exp', 'aud');
    if (!ALL_ALGS.includes(alg)) return reject('alg-unknown', `unsupported alg ${alg}`, { alg });
    const key = HMAC_ALGS[alg] ? LAB_HMAC_SECRET : rsa.publicPem;
    if (!verifySignature(token, key, alg)) return reject('bad-signature', 'signature does not verify', { alg });
    const why = checkClaims(t.payload, { exp: true, aud: true });
    if (why) return reject(why.code, why.message, { alg });
    return accept(alg, checks, t.payload);
  }

  /* Correct crypto, no semantic validation — the "it's signed, ship it" verifier. */
  function verifyNaive(token) {
    let t;
    try { t = decode(token); } catch (e) { return reject('malformed', `decode: ${e.message}`); }
    const alg = t.header.alg;
    const checks = ['alg-from-config', 'sig'];
    if (!CONFIG_ALGORITHMS.includes(alg)) {
      return reject('alg-not-allowed', `alg ${alg} not in configured ${JSON.stringify(CONFIG_ALGORITHMS)}`, { alg });
    }
    if (!verifySignature(token, rsa.publicPem, alg)) return reject('bad-signature', 'signature does not verify', { alg });
    return accept(alg, checks, t.payload, 'signature checked; exp/aud/iss deliberately NOT checked');
  }

  function accept(alg, checks, claims, note) {
    return { accept: true, reason: 'accepted', alg, checks_performed: checks, claims, ...(note ? { note } : {}) };
  }
  function reject(code, message, extra = {}) {
    return { accept: false, reason: code, message, checks_performed: [], ...extra };
  }

  function checkClaims(p, opts) {
    const t = now();
    if (opts.exp) {
      if (typeof p.exp !== 'number') return { code: 'missing-exp', message: 'no exp claim; this token never expires' };
      if (p.exp <= t) return { code: 'expired', message: `exp ${p.exp} is ${t - p.exp}s in the past` };
    }
    if (opts.nbf) {
      if (typeof p.nbf !== 'number') return { code: 'missing-nbf', message: 'no nbf claim' };
      if (p.nbf > t + 60) return { code: 'not-yet-valid', message: `nbf ${p.nbf} is in the future` };
    }
    if (opts.iss && p.iss !== ISSUER) return { code: 'bad-iss', message: `iss ${JSON.stringify(p.iss)} != ${ISSUER}` };
    if (opts.aud) {
      const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
      if (!aud.includes(AUDIENCE)) return { code: 'bad-aud', message: `aud ${JSON.stringify(p.aud)} does not include ${AUDIENCE}` };
    }
    if (opts.required) {
      for (const c of ['sub', 'jti']) {
        if (typeof p[c] !== 'string' || !p[c]) return { code: `missing-${c}`, message: `required claim ${c} absent` };
      }
    }
    return null;
  }

  const VERIFIERS = {
    strict: { fn: verifyStrict, note: 'the correct implementation' },
    confused: { fn: verifyConfused, note: 'alg from token header; RSA public key used as the HMAC secret' },
    'none-accepting': { fn: verifyNoneAccepting, note: 'no allowlist; alg=none honored as unsigned-and-trusted' },
    naive: { fn: verifyNaive, note: 'correct signature check, zero claim validation' },
  };

  /* ---------------------------------------------------------------- HTTP */
  function send(res, code, body) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(payload);
  }

  function readBody(req, limit = 256 * 1024) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) { reject(new Error('body-too-large')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  function bearer(req, parsed) {
    const h = req.headers.authorization || '';
    const m = /^Bearer\s+(.+)$/i.exec(h.trim());
    if (m) return m[1].trim();
    return parsed?.token || null;
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const p = url.pathname.replace(/\/+$/, '') || '/';
    try {
      if (p === '/' || p === '/api/health') {
        return send(res, 200, {
          ok: true, service: 'crypto-lab', issuer: ISSUER, audience: AUDIENCE,
          kid: KID, configAlgorithms: CONFIG_ALGORITHMS, ttlSeconds: DEFAULT_TTL_S,
          iss: ['strong', 'weak-claims', 'none', 'confusion', 'weak-secret'],
          verifiers: ['strict', 'confused', 'none-accepting', 'naive'],
          keys: 'crypto-lab/keys/ (gitignored, generated at runtime)',
        });
      }
      if (p === '/api/jwks') {
        return send(res, 200, jwksFromPublicPem(rsa.publicPem, KID));
      }
      if (p === '/api/posture') {
        return send(res, 200, {
          issuer: ISSUER, audience: AUDIENCE, kid: KID,
          configAlgorithms: CONFIG_ALGORITHMS,
          verifiers: Object.fromEntries(Object.entries(VERIFIERS).map(([k, v]) => [k, {
            note: v.note,
            alg_source: k === 'confused' || k === 'none-accepting' ? 'token-header' : 'config',
            claim_checks: k === 'strict' ? ['exp', 'nbf', 'iss', 'aud', 'sub', 'jti']
              : k === 'naive' ? []
                : k === 'confused' ? ['exp'] : ['exp', 'aud'],
          }])),
        });
      }
      if (p === '/api/decode' && req.method === 'POST') {
        const body = JSON.parse((await readBody(req)) || '{}');
        const t = bearer(req, body);
        if (!t) return send(res, 400, { ok: false, error: 'no-token' });
        const d = decode(t);
        return send(res, 200, { ok: true, header: d.header, payload: d.payload, signature_b64u_length: d.signature.length });
      }

      let m = /^\/api\/issue\/([a-z-]+)$/.exec(p);
      if (m) {
        if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'use-POST' });
        const name = m[1];
        if (!ISSUERS[name]) return send(res, 404, { ok: false, error: 'unknown-issuer', issued: Object.keys(ISSUERS) });
        const out = ISSUERS[name]();
        log(`issue ${name.padEnd(12)} alg=${decode(out.token).header.alg.padEnd(6)} len=${out.token.length}`);
        return send(res, 200, { ok: true, issuer_profile: name, token: out.token, note: out.note });
      }

      m = /^\/api\/verify\/([a-z-]+)$/.exec(p);
      if (m) {
        if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'use-POST' });
        const name = m[1];
        if (!VERIFIERS[name]) return send(res, 404, { ok: false, error: 'unknown-verifier', verifiers: Object.keys(VERIFIERS) });
        const body = JSON.parse((await readBody(req)) || '{}');
        const t = bearer(req, body);
        if (!t) return send(res, 400, { ok: false, error: 'no-token' });
        const verdict = VERIFIERS[name].fn(t);
        log(`verify ${name.padEnd(15)} -> ${verdict.accept ? 'ACCEPT' : 'REJECT ' + verdict.reason}`);
        return send(res, 200, { ok: true, verifier: name, ...verdict });
      }

      return send(res, 404, { ok: false, error: 'not-found', path: p });
    } catch (e) {
      return send(res, 500, { ok: false, error: e.message });
    }
  });

  return { server, rsa, KID, ISSUERS, VERIFIERS, listen };
}

function listen(server, { port = 8791, host = '127.0.0.1' } = {}) {
  return new Promise((resolve, reject) => {
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      reject(new Error(`refusing to bind ${host}: this lab is loopback-only`));
      return;
    }
    server.once('error', reject);
    server.listen(port, host, () => resolve(server.address()));
  });
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const argPort = (() => {
    const i = process.argv.indexOf('--port');
    return i >= 0 && /^\d+$/.test(process.argv[i + 1] || '') ? Number(process.argv[i + 1]) : 8791;
  })();
  const stamp = () => new Date().toISOString().slice(11, 23);
  const lab = createLab({ log: (m) => console.log(`[${stamp()}] ${m}`) });
  const addr = await listen(lab.server, { port: argPort });
  console.log(`[${stamp()}] crypto-lab on http://127.0.0.1:${addr.port}  kid=${lab.KID}`);
  console.log(`[${stamp()}]   issue:  POST /api/issue/{strong|weak-claims|none|confusion|weak-secret}`);
  console.log(`[${stamp()}]   verify: POST /api/verify/{strict|confused|none-accepting|naive}`);
  console.log(`[${stamp()}]   GET  /api/health /api/jwks /api/posture`);
}
