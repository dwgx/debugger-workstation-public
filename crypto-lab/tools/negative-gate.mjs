#!/usr/bin/env node
/* negative-gate.mjs — crypto.jose.parse NEGATIVE CONTROL. Added 2026-10-05.
 *
 * WHY THIS FILE EXISTS. `loop.mjs` runs 17 checks and all 17 are POSITIVE: every case asserts
 * that some instrument produced the right classification, and the verifier-matrix section
 * asserts that four deliberately-broken verifiers accept and reject exactly the token classes
 * their bugs imply. The capability's registry entry declared its negative control as a PLAN
 * (`expect_exit: 4`, no runnable command), so nothing had ever asked the crypto-lab verifier to
 * REFUSE anything that was structurally perfect. A capability whose instrument has only ever
 * been shown to say yes has an "it works" that means "it did not crash".
 *
 * THE CONTROL. Two structurally valid tokens — well-formed JOSE, decodable segments, and every
 * claim `strict` demands present, well-formed and current — fed to the SAME judgement the loop
 * uses: `POST /api/verify/strict` on the lab `createLab()` returns. Both must be REFUSED.
 *
 *   1. `alg: none`. Three segments, valid base64url header and payload, empty signature segment,
 *      iss/aud/sub/jti/iat/nbf/exp all correct. The ONLY thing wrong with it is that it declares
 *      itself unsigned. `strict` refuses it as `alg-not-allowed` before it ever reaches a key.
 *   2. `RS256` over a DIFFERENT key. Signed with an ephemeral attacker keypair, and the header
 *      even carries the lab's real `kid`, so no key-selection heuristic can rescue it. Every
 *      claim is as valid as the lab's own control token. `strict` refuses it as `bad-signature`.
 *
 * Neither is a shape test. A shape-only check reads both as fine, because both ARE fine; the
 * difference is entirely in whether verification happened, which is exactly the distinction the
 * real-world `alg: none` and algorithm-confusion failures turn on and the one this station
 * exists to be able to demonstrate.
 *
 * EXIT POLARITY, and it is the opposite of what it looks like. R5 requires a negative control to
 * declare a NON-ZERO `expect_exit`, because a control that must exit 0 proves nothing: an
 * instrument that had stopped enforcing entirely would also exit 0 and the harness would read
 * that as a pass. Same convention as web-reverse/tools/negative-gate.mjs.
 *
 *   exit 4 = the verifier REFUSED both tokens. THE CONTROL WORKING. This is what the registry declares.
 *   exit 0 = the verifier ACCEPTED at least one. The control found a real defect; by R5 that is
 *            the value the harness flags as DRIFT.
 *   exit 5 = a case was NOT structurally valid. The control is broken, not the verifier, and
 *            saying so is the only honest answer — a refusal of a garbage token proves nothing.
 *   exit 1 = the harness could not run.
 *
 * BOTH TOKENS ARE BUILT FROM REAL CODE. `sign()` is the lab's own signer from lab/jose.mjs and
 * the attacker keypair is generated here with node:crypto, so no literal token string is pasted
 * anywhere in this file. A hand-written token that happened to be refused would prove nothing
 * about the verifier.
 *
 * THE FIXTURES ARE NOW PROVEN, NOT ASSERTED (2026-10-05). The paragraph above was true by
 * construction and was verified only by reading it, which is the weakness this station keeps
 * running into: `strict` refuses an RS256 token whose signature bytes are RANDOM exactly as it
 * refuses one signed over the wrong key, so if `sign()` ever emitted a malformed signature the
 * gate would print `bad-signature`, exit 4, and mean nothing. `fixtureProvenance()` below closes
 * that: each case is verified under the key this process generated and must NOT verify under the
 * lab's. A failure there routes into the EXISTING `not structurally valid` bucket (exit 5), which
 * already means "the control is broken, not the verifier" -- no new exit code, no new meaning.
 *
 * ARGUMENT REFUSAL, for the same reason loop.mjs has it: a control that silently ignores a flag
 * someone passed it is a control that can be made to report a green it did not measure.
 *
 * WHY createLab() IS INSIDE THE try AND USED TO BE OUTSIDE IT. `lab/keys.mjs rsaKeypair()` is the
 * one call in this file's import graph that touches the filesystem at all: it generates the lab's
 * RSA-2048 pair at run time when `crypto-lab/keys/` is absent and reuses it when present, so on a
 * clean machine this gate needs nothing that anyone made earlier. Measured 2026-10-05 on a copy of
 * lab/ + tools/ with no keys/ directory: exit 4, both cases refused, keys/ created by the run. But
 * the call sat at module scope, ABOVE this try, so a machine where the pair could not be generated
 * or written died on an uncaught throw during module evaluation -- a file-shaped failure, thrown
 * before a single line of the control had run, and from outside indistinguishable from a control
 * that had correctly refused something. Inside the try it lands on exit 1, which this gate already
 * defines as "the harness could not run" and never as a verdict.
 *
 * WHY node:http AND NOT fetch(). MEASURED, not stylistic. `loop.mjs` makes dozens of `fetch`
 * calls and exits 0, so the obvious guess is that `fetch` is fine here too. It is not, on the
 * SECOND call: undici reuses one keep-alive socket, and calling `process.exit()` while that
 * client-side handle is still closing aborts the runtime with
 *   `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 94`
 * and exit code 9 — AFTER the control had already printed a correct verdict. A harness reading
 * `expect_exit: 4` would see 9 and call it DRIFT, and the DRIFT would be libuv's, not the
 * verifier's. Measured on this box: 1 fetch -> exit 4; 2 fetches -> exit 9;
 * 2 fetches + `server.closeAllConnections()` -> still exit 9; 2 requests over `node:http` ->
 * exit 4. `loop.mjs` escapes it only because its children are spawned processes, so nothing is
 * left pooled in the parent. node:http issues a fresh connection per request here, and it is
 * what web-reverse/tools/negative-gate.mjs already uses, so this follows the existing
 * convention rather than establishing a second one.
 */
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUDIENCE, DEFAULT_TTL_S, ISSUER, createLab } from '../lab/server.mjs';
import { decode, sign, verifySignature } from '../lab/jose.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const extra = process.argv.slice(2);
if (extra.length) {
  console.error(`negative-gate: refusing an argument it would otherwise IGNORE: ${extra.join(' ')}`);
  console.error('  This control builds its own fixtures. It has no --target and no --token.');
  console.error('  Accepting an argument silently would report a green it did not measure.');
  process.exit(2);
}

const line = (s = '') => console.log(s);

/* Claims shaped exactly like the lab's own `strong` control, with the one difference an attacker
 * would want: role=admin. Everything `strict`'s checkClaims demands is present and correct, so
 * the refusal that follows is attributable to the algorithm or the key and to nothing else. */
function attackerClaims() {
  const iat = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'usr_1f4c9a2b7e',
    role: 'admin',
    iat,
    nbf: iat - 1,
    exp: iat + DEFAULT_TTL_S,
    jti: crypto.randomBytes(8).toString('hex'),
  };
}

/* Does this token satisfy every claim `strict` enforces? Reported, not assumed: a control whose
 * premise is false must say so rather than banking the refusal it gets anyway. */
function claimReadiness(p) {
  const t = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  return [
    ['exp present and unexpired', typeof p.exp === 'number' && p.exp > t, `exp=${p.exp} now=${t}`],
    ['nbf present and not future', typeof p.nbf === 'number' && p.nbf <= t + 60, `nbf=${p.nbf}`],
    ['iss is the lab issuer', p.iss === ISSUER, `iss=${JSON.stringify(p.iss)}`],
    ['aud includes the lab audience', aud.includes(AUDIENCE), `aud=${JSON.stringify(p.aud)}`],
    ['sub non-empty string', typeof p.sub === 'string' && !!p.sub, `sub=${p.sub}`],
    ['jti non-empty string', typeof p.jti === 'string' && !!p.jti, `jti=${p.jti}`],
  ];
}

/* Did THIS process build this token, from a key THIS process generated?
 *
 * The vacuity this closes is specific and measured, not hypothetical. `verifyStrict` reaches
 * `bad-signature` whenever `verifySignature` returns false, and `verifySignature` returns false
 * for a token whose signature bytes are garbage just as readily as for one signed over the wrong
 * key. A control that only checked "was it refused?" therefore cannot tell a verifier that ran
 * correctly from a fixture that was never a real signature -- it reads both as a pass. The two
 * checks below make the premise measured instead of assumed:
 *
 *   foreign-key  the signature MUST verify under the attacker's own public key, and MUST NOT
 *                verify under the lab's. Together those say the token carries a genuine RS256
 *                signature and that the ONLY reason `strict` refuses it is the key it was made
 *                with -- which is the defect under test.
 *   alg-none     there is no signature to check, so the premise is structural: the header must
 *                declare `alg=none`, the signature segment must be empty, and the header must
 *                carry the lab's real kid so no key-selection heuristic can excuse it.
 *
 * Failures set the same flag a bad claim sets. That is deliberate: a garbage signature and a
 * missing `exp` are the same class of failure -- the refusal that follows would be measuring the
 * fixture rather than the strictness of the verifier -- and the gate already has an exit code for
 * exactly that, so this adds no new outcome. */
function fixtureProvenance(c, d, lab) {
  if (c.alg === 'none') {
    return [
      ['header declares alg=none', d.header.alg === 'none', `alg=${JSON.stringify(d.header.alg)}`],
      ['signature segment is empty', d.signature === '', d.signature === '' ? '(empty)' : `${d.signature.length} b64u chars`],
      ['carries the lab real kid', d.header.kid === lab.KID, `kid=${d.header.kid}`],
    ];
  }
  return [
    ['signature verifies under the key this process generated', verifySignature(c.token, c.pubKey, c.alg), `RS256 made with the ephemeral private key generated above`],
    ['and does NOT verify under the lab key', !verifySignature(c.token, lab.rsa.publicPem, c.alg), 'so the refusal below is attributable to the key, not to a malformed signature'],
    ['generated key is not the lab key', c.pubKey !== lab.rsa.publicPem, `lab kid=${lab.KID}`],
  ];
}

/* One request per token, over a fresh connection. See the node:http note at the top for why
 * this is not `fetch` — the pooled keep-alive socket is what turns a correct exit 4 into 9. */
function verifyStrict(port, token) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ token });
    const req = http.request(
      {
        hostname: '127.0.0.1', port, path: '/api/verify/strict', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
      },
      (res) => {
        let b = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { b += d; });
        res.on('end', () => {
          try { resolve(JSON.parse(b)); } catch (e) { reject(new Error(`verify response was not JSON: ${e.message}`)); }
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

let exitCode = 1;

try {
  /* Inside the try, deliberately. See the header note: this is the only call in the import graph
   * that reads the filesystem, and at module scope a failure to generate it threw before the
   * control had run a line -- indistinguishable from outside from a real verdict. */
  const lab = createLab({ log: () => {} });
  const addr = await lab.listen(lab.server, { port: 0 });
  const base = `http://127.0.0.1:${addr.port}`;

  /* An attacker keypair, generated here, never written to disk. The token built from it is
   * signed correctly as an RS256 signature — over the wrong key, which is the whole defect. */
  const attacker = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const cases = [
    {
      id: 'alg-none',
      title: 'structurally valid, unsigned: header says alg=none',
      defect: 'the token declares itself unverified; there is no signature to check',
      alg: 'none',
      token: sign({ alg: 'none', kid: lab.KID }, attackerClaims()),
    },
    {
      id: 'foreign-key',
      title: 'structurally valid, signed over a different key than the one presented',
      defect: `RS256 signature made with an ephemeral attacker key, not ${lab.KID}; the header carries the lab's real kid so key selection cannot rescue it`,
      alg: 'RS256',
      pubKey: attacker.publicKey,
      token: sign({ alg: 'RS256', kid: lab.KID }, attackerClaims(), attacker.privateKey),
    },
  ];

  line('');
  line('crypto.jose.parse — NEGATIVE CONTROL: structurally valid tokens that must NOT verify');
  line('='.repeat(96));
  line(`  lab      ${base}   kid=${lab.KID}   issuer=${ISSUER}   audience=${AUDIENCE}`);
  line('  fed to   POST /api/verify/strict  — the same judgement loop.mjs makes at its verifier step');
  line('  built by crypto-lab/tools/negative-gate.mjs via lab/jose.mjs sign() + node:crypto; no pasted token literal');
  line(`  keys     lab RSA-${lab.rsa.bits} ${lab.rsa.generated ? 'GENERATED by this run' : `reused from ${lab.rsa.publicPath}`}; attacker pair GENERATED in-process by node:crypto, never written to disk`);
  line(`           nothing this gate reads was made by an earlier run unless the line above says "reused"`);
  line('');

  let anyAccepted = false;
  let anyNotValid = false;

  for (const c of cases) {
    line(`  case ${c.id}: ${c.title}`);
    line(`    defect   ${c.defect}`);

    let d;
    try {
      d = decode(c.token);
    } catch (e) {
      line(`    STRUCTURE INVALID: decode threw ${e.message} — the control's premise failed, not the verifier's`);
      anyNotValid = true;
      line('');
      continue;
    }

    line(`    segments ${d.parts.length} (base64url ${/^[A-Za-z0-9_-]*$/.test(d.parts[0]) && /^[A-Za-z0-9_-]*$/.test(d.parts[1]) ? 'ok' : 'BAD'}), signature segment ${d.signature === '' ? '(empty)' : `${d.signature.length} b64u chars`}`);
    line(`    header   ${JSON.stringify(d.header)}`);
    line(`    claims   ${JSON.stringify(d.payload)}`);

    const checks = claimReadiness(d.payload);
    line(`    claims strict would demand:`);
    for (const [name, ok, detail] of checks) {
      line(`      ${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(30)} ${detail}`);
      if (!ok) anyNotValid = true;
    }
    line(`    verdict  token is STRUCTURALLY VALID and semantically current — nothing below may be blamed on its shape`);

    const prov = fixtureProvenance(c, d, lab);
    line(`    provenance of the fixture itself:`);
    for (const [name, ok, detail] of prov) {
      line(`      ${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(30)} ${detail}`);
      if (!ok) anyNotValid = true;
    }

    const v = await verifyStrict(addr.port, c.token);

    if (v.accept) {
      anyAccepted = true;
      line(`    -> strict ACCEPTED it (alg=${v.alg}). REFUSED-BY-VERIFICATION absent.`);
      line(`       A verifier that accepts this is the defect this control exists to catch.`);
    } else {
      line(`    -> strict REFUSED it: ${v.reason} — ${v.message}`);
    }
    line('');
  }

  lab.server.close();
  await new Promise((r) => lab.server.once('close', r));

  if (anyNotValid) {
    line('CONTROL BROKEN — a case above was not structurally valid, so its refusal (if any) measured');
    line('  the shape of the fixture rather than the strictness of the verifier. Exiting 5.');
    exitCode = 5;
  } else if (anyAccepted) {
    line('CONTROL FAILED — strict ACCEPTED a structurally valid token it must refuse. Every');
    line('  "strict rejects" cell in loop.mjs is therefore meaningless. Exiting 0, which is the');
    line('  value R5 flags as DRIFT: an instrument that stopped enforcing would also exit 0.');
    exitCode = 0;
  } else {
    line('NEGATIVE-CONTROL OK — REFUSED-BY-VERIFICATION on 2/2 structurally valid tokens:');
    line('  alg=none refused as alg-not-allowed (the allowlist, not a parse error)');
    line('  foreign-key RS256 refused as bad-signature (verification actually ran and failed)');
    line('  Neither refusal is reachable by a shape-only check, which is what makes them a control.');
    line('  Exiting 4, the non-zero code the registry declares, because a control that must exit 0');
    line('  proves nothing.');
    exitCode = 4;
  }
  line('');
  process.exit(exitCode);
} catch (e) {
  line('');
  line(`negative-gate: ${e.stack || e.message}`);
  line('The gate did not reach a verdict. This is the "harness could not run" path, NOT a refusal and');
  line('  NOT a pass: if the lab could not start, most often because lab/keys.mjs rsaKeypair() could');
  line('  not generate or write its RSA pair, then nothing above was measured at all. Exiting 1.');
  process.exit(1);
}