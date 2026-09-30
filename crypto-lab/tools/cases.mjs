/* cases.mjs — the case table for the crypto-lab loop.
 *
 * One row per failure class. Each row states, up front, what the analyzer is REQUIRED to
 * say and what the lab's verifiers are REQUIRED to do, so the loop is a real test rather
 * than a demo that prints whatever happened.
 *
 * `expect` is the exact set of finding ids. Exact, not "contains": a rule that starts
 * firing where it should not is a regression, and a set comparison catches both
 * directions.
 *
 * `verifier` records the point of the exercise: the same token, judged by a verifier with
 * a different bug, gets a different answer. If `strict` ever accepts a weak token, the
 * lab's own control has failed.
 */
import { sign } from '../lab/jose.mjs';

const now = () => Math.floor(Date.now() / 1000);

export function buildCases(lab) {
  const { publicPem, privatePem } = lab.rsa;
  const KID = lab.KID;

  const header = (over = {}) => ({ typ: 'JWT', alg: 'RS256', kid: KID, ...over });
  /* A fully-formed, boring, correct claim set. Cases mutate exactly one thing from here,
   * so a finding can only have come from the mutation. */
  const claims = (over = {}) => {
    const iat = now();
    return { iss: 'crypto-lab', aud: 'crypto-lab-api', sub: 'usr_1f4c9a2b7e', iat, nbf: iat - 1, exp: iat + 300, jti: 'c-0001', ...over };
  };

  return [
    {
      id: 'strong',
      title: 'the control: correct algorithm, complete claims, real key',
      teaches: 'What a token with no weakness present looks like. Without this row, every '
        + 'other row could be a rule that fires on everything.',
      issue: 'strong',
      analyze: { serverAlg: 'RS256', secret: 'secret', rsaPub: true },
      expect: [],
      verifier: { mode: 'strict', accept: true },
      oracles: [
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' },
        { tool: 'py', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' },
      ],
    },

    {
      id: 'none',
      title: 'unsigned token (alg=none) honored by an allowlist-free verifier',
      teaches: 'The token says "do not check a signature". The finding is not the token, it is '
        + 'the verifier that reads `alg` from it. `none-accepting` accepts; `strict` cannot.',
      issue: 'none',
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['ALG_NONE'],
      verifier: { mode: 'none-accepting', accept: true },
      oracles: [
        { tool: 'node', key: 'none', algorithms: ['none'], want: 'verified' },
        /* Pinned to RS256, the same library refuses it — "jwt signature is required".
         * The algorithm allowlist is the control, not the library's default. */
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'signature-required' },
        { tool: 'py', key: 'rsa-public', algorithms: ['RS256'], want: 'alg-not-allowed' },
      ],
    },

    {
      id: 'confusion',
      title: 'algorithm confusion: HS256 keyed on the RSA public key',
      teaches: 'A verifier that picks the key family from the token\'s `alg` will HMAC the public '
        + 'PEM as if it were a shared secret. Nothing is forged — HS256 is computed correctly, on '
        + 'material the world can read. Both real libraries now REFUSE this outright (see the oracle '
        + 'rows: "must be a symmetric key" / "asymmetric key ... HMAC secret"); the class survives in '
        + 'hand-rolled verifiers that reach for the crypto primitives directly, which is what the '
        + 'lab\'s `confused` mode is.',
      issue: 'confusion',
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['ALG_CONFUSION_CONFIRMED', 'ALG_CONFUSION_RISK', 'ALG_SYMMETRIC'],
      verifier: { mode: 'confused', accept: true },
      oracles: [
        /* The hardened libraries refuse the key-type mismatch. */
        { tool: 'node', key: 'rsa-public', algorithms: ['HS256'], want: 'refused-key-type' },
        { tool: 'py', key: 'rsa-public', algorithms: ['HS256'], want: 'refused-key-type' },
        /* And when the algorithm is pinned to what the service actually is, the token is
         * rejected as an algorithm mismatch — the other half of the same guard. */
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'alg-not-allowed' },
      ],
    },

    {
      id: 'weak-claims',
      title: 'cryptographically valid, semantically naked',
      teaches: 'No exp, no aud, no jti — plus credentials and PII in a payload that is signed, not '
        + 'encrypted. `naive` (signature checked, nothing else) accepts it forever.',
      issue: 'weak-claims',
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['MISSING_AUD', 'MISSING_EXP', 'MISSING_JTI', 'MISSING_NBF', 'PII_CLAIM', 'SENSITIVE_CLAIM'],
      verifier: { mode: 'naive', accept: true },
      oracles: [
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' },
        /* The same token under an oracle that *requires* the claims it is missing: */
        { tool: 'py', key: 'rsa-public', algorithms: ['RS256'], require: ['exp', 'aud'], want: 'missing-claim' },
      ],
    },

    {
      id: 'weak-secret',
      title: 'HMAC token signed with a dictionary secret',
      teaches: 'The signature verifies, and it still means nothing: the key is guessable, so anyone '
        + 'can mint tokens this service accepts.',
      issue: 'weak-secret',
      analyze: { serverAlg: 'HS256', secret: 'secret' },
      expect: ['ALG_SYMMETRIC', 'SIG_WEAK_SECRET'],
      verifier: { mode: 'naive', accept: false },
      oracles: [
        { tool: 'node', key: 'secret', algorithms: ['HS256'], want: 'verified' },
        { tool: 'py', key: 'secret', algorithms: ['HS256'], want: 'verified' },
        { tool: 'node', key: 'secret', algorithms: ['HS256'], secret: 'wrong-secret', want: 'rejected' },
      ],
    },

    {
      id: 'expired',
      title: 'expired, but only a verifier that checks `exp` notices',
      teaches: 'Expiry is a claim, not a property of the signature. `naive` accepts this token '
        + 'because the signature is perfectly good.',
      craft: () => sign(header(), claims({ iat: now() - 7200, nbf: now() - 7200, exp: now() - 3600 }), privatePem),
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['EXPIRED'],
      verifier: { mode: 'strict', accept: false },
      oracles: [
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'expired' },
        { tool: 'py', key: 'rsa-public', algorithms: ['RS256'], want: 'expired' },
      ],
    },

    {
      id: 'exp-too-far',
      title: 'a 30-day bearer token',
      teaches: 'Nothing is malformed. The finding comes from a policy horizon (`--ttl-max`, default '
        + '1h), which is the honest way to report it: the token is not wrong, the lifetime is.',
      craft: () => { const iat = now(); return sign(header(), claims({ iat, nbf: iat - 1, exp: iat + 30 * 86400 }), privatePem); },
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['EXP_TOO_FAR'],
      verifier: { mode: 'strict', accept: true },
      oracles: [{ tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' }],
    },

    {
      id: 'jku-header',
      title: 'the token nominates where its own verification key lives',
      teaches: '`jku` hands key selection to whoever wrote the token. The analyzer reports the header '
        + 'and deliberately does NOT fetch it — outbound reach during analysis is a stop line.',
      craft: () => sign(header({ jku: 'https://127.0.0.1:1/.well-known/jwks.json' }), claims(), privatePem),
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['JKU_HEADER'],
      verifier: { mode: 'strict', accept: true },
      oracles: [{ tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' }],
    },

    {
      id: 'tampered',
      title: 'the payload was edited after signing',
      teaches: 'The one class a signature check does catch. `role` goes from analyst to admin and the '
        + 'signature no longer matches.',
      craft: () => {
        const t = sign(header(), claims({ role: 'analyst' }), privatePem);
        const [h, p, s] = t.split('.');
        const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
        payload.role = 'admin';
        return [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
      },
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['SIG_INVALID'],
      verifier: { mode: 'strict', accept: false },
      oracles: [
        { tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'rejected' },
        { tool: 'py', key: 'rsa-public', algorithms: ['RS256'], want: 'rejected' },
      ],
    },

    {
      id: 'claim-injection',
      title: 'control characters inside a claim value',
      teaches: 'A newline in a claim is how a value gets re-parsed as something else downstream — a log '
        + 'line, a header, a nested document. The analyzer cannot name the sink, so it flags the shape.',
      craft: () => sign(header(), claims({ note: 'line one\nSet-Cookie: lab=1\r\nline three' }), privatePem),
      analyze: { serverAlg: 'RS256', rsaPub: true },
      expect: ['CLAIM_INJECTION'],
      verifier: { mode: 'strict', accept: true },
      oracles: [{ tool: 'node', key: 'rsa-public', algorithms: ['RS256'], want: 'verified' }],
    },

    {
      id: 'unverified',
      title: 'no key material supplied: an explicit limit, not a verdict',
      teaches: 'The analyzer says so instead of guessing. Everything reported here is about structure, '
        + 'and the summary says the signature is unchecked.',
      craft: () => sign(header(), claims(), privatePem),
      analyze: {},                             // deliberately: no --rsa-pub, no --secret
      expect: ['SIG_UNVERIFIED'],
      verifier: { mode: 'strict', accept: true },
      oracles: [],
    },

    {
      id: 'jwe',
      title: 'an encrypted token (JWE), which this tool does not read',
      teaches: 'Five segments means the payload is ciphertext. Reporting that honestly is worth more '
        + 'than a decoder that guesses.',
      craft: () => {
        const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
        return [b64({ alg: 'RSA-OAEP', enc: 'A256GCM' }), 'AAECAwQFBgcICQoLDA0ODw', 'AAECAwQFBgcICQoLDA0ODw', 'AAECAwQFBgcICQoLDA0ODw', 'AAECAwQFBgcICQoLDA0ODw'].join('.');
      },
      analyze: {},
      expect: ['JWE_UNSUPPORTED'],
      verifier: null,
      oracles: [],
    },
  ];
}

/* Coarse outcome classifier, applied identically to both oracles so the two can be
 * compared without either library's exception taxonomy leaking into the assertions.
 *
 * Two of these outcomes are the interesting negative results:
 *   `refused-key-type`     — the library refuses to key an HMAC with a public key at all
 *   `signature-required`   — the library refuses an empty signature segment
 * Both mean the confusion/none classes are NOT reachable through these libraries, and
 * are only reachable in a verifier that reaches for the primitives directly. That is
 * exactly the verifier the lab ships as `confused` / `none-accepting`. */
export function classifyOracle(r) {
  if (!r) return 'error';
  if (r.verified === true) return 'verified';
  const name = r.error?.name || '';
  const msg = r.error?.message || '';
  if (/must be a symmetric key|asymmetric key or x509/i.test(msg)) return 'refused-key-type';
  if (/signature is required/i.test(msg)) return 'signature-required';
  if (/ExpiredSignature|TokenExpired/i.test(name) || /expired/i.test(msg)) return 'expired';
  if (/MissingRequiredClaim/i.test(name) || /missing the .+ claim/i.test(msg)) return 'missing-claim';
  if (/NotBefore/i.test(name)) return 'not-yet-valid';
  if (/InvalidAlgorithm/i.test(name) || /invalid algorithm/i.test(msg)) return 'alg-not-allowed';
  return 'rejected';
}
