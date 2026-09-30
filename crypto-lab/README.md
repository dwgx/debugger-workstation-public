# crypto-lab — JWT / token analysis lane

The station had no JWT tooling at all, against a curriculum that is JWT-centric. This is
the answer: a loopback service that issues tokens, four verifiers that each carry one real
bug, and **an analyzer that reads a token and names the weakness classes it carries**.

Loopback only. Self-authored. The analyzer has **zero dependencies** (`node:crypto` only);
the two third-party libraries are *oracles*, not requirements — they exist so a verdict is
never one implementation agreeing with itself.

| Path | What it is |
|---|---|
| `lab/jose.mjs` | ~130-line JWS core: base64url, HMAC, RSA-PKCS1, RSA-PSS, `none`. The lab's encoder/verifier. |
| `lab/keys.mjs` | RSA-2048 keypair generated **at runtime** into `keys/` (gitignored). Published fake HMAC constants. |
| `lab/server.mjs` | The target: 5 issuance profiles, 4 verifiers, `/api/health`, `/api/jwks`, `/api/posture`. |
| `tools/analyze.mjs` | **The deliverable.** Token in, structured analysis out. No imports but `node:crypto`. |
| `tools/oracle-node.mjs` | Cross-check implementation #1: `jsonwebtoken` 9.0.3. |
| `tools/oracle.py` | Cross-check implementation #2: PyJWT 2.15.1 (+`cryptography` 50.0.1). |
| `tools/cases.mjs` | The case table: per class, the exact findings required and the verifier behaviour required. |
| `tools/loop.mjs` | All of the above in one self-judging command (exit 0 = loop closed). |

## The one command

```powershell
powershell -File scripts\crypto-lab.ps1 loop     # or: node crypto-lab/tools/loop.mjs
```

It runs 12 classification cases, a 5×4 issuer×verifier acceptance matrix, the two-oracle
cross-check, and a negative control on the analyzer's own guard — then prints PASS/FAIL.

```
  PASS  strong           alg=RS256  sig=valid                          exp=valid
        findings  (none)
        verifier  strict:accept   checks=[alg-from-config, sig, exp, nbf, iss, aud, required-claims]
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=RS256   -> verified (want verified)
        oracle    PyJWT  v2.15.1  key=rsa-public algs=RS256        -> verified (want verified)
  PASS  confusion        alg=HS256  sig=valid-as-hmac-over-public-key  exp=valid
        findings  ALG_CONFUSION_CONFIRMED, ALG_CONFUSION_RISK, ALG_SYMMETRIC
        verifier  confused:accept   checks=[alg-from-token-header, exp]
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=HS256   -> refused-key-type (want refused-key-type)
        oracle    PyJWT  v2.15.1  key=rsa-public algs=HS256        -> refused-key-type (want refused-key-type)
  ...
  PASS  negative control: analyzer --expect refuses a wrong set  exit 4 (want 4)

LOOP CLOSED: every weakness class was classified as expected, every verifier behaved as its bug implies,
             and jsonwebtoken + PyJWT agreed with the analyzer on every case they could express.
```

## Using the analyzer on a token

```powershell
# whole report, human transcript on stderr, JSON on stdout
node crypto-lab/tools/analyze.mjs --token "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." --quiet

# with key material so the signature is actually checked
node crypto-lab/tools/analyze.mjs --file "%TEMP%\some.jwt" `
     --rsa-pub crypto-lab\keys\lab-rsa-2048.pub.pem --server-alg RS256

# self-check: exit 4 if the finding set is not exactly this
node crypto-lab/tools/analyze.mjs --file t.jwt --rsa-pub k.pem --expect 'ALG_NONE'
```

Through the station wrapper (first-class params, or `-NodeArgs` for anything else):

```powershell
powershell -File scripts\crypto-lab.ps1 analyze -TokenFile "%TEMP%\some.jwt" `
          -RsaPub crypto-lab\keys\lab-rsa-2048.pub.pem -ServerAlg RS256
powershell -File scripts\agent-cli.ps1 crypto-lab loop
powershell -File scripts\crypto-lab.ps1 status
powershell -File scripts\crypto-lab.ps1 serve    # blocking; not needed for `loop`
```

| exit | meaning |
|---|---|
| 0 | analysed (findings are expected output, not failure) |
| 2 | usage error |
| 3 | bad input — not a compact JWS, or undecodable header/payload |
| 4 | `--expect` mismatch: the finding set is not the one that was required |

Options: `--secret` / `--secret-file` · `--rsa-pub <pem|path>` · `--server-alg <alg>` ·
`--ttl-max <seconds>` (default 3600) · `--now <epoch>` (freeze the clock) ·
`--expect a,b,c` · `--quiet` · `--json`.

## What comes back

```jsonc
{
  "schema": "crypto-lab/analysis@1",
  "input":     { "source": "...", "length": 341, "sha256": "...", "segments": 3 },
  "algorithm": { "alg": "HS256", "family": "HMAC (shared secret)", "keyType": "shared-secret",
                 "signed": true, "known": true },
  "signature": { "status": "valid-as-hmac-over-public-key",
                 "material": "public-key-used-as-hmac-secret", "detail": "..." },
  "header":    { "typ": "JWT", "alg": "HS256", "kid": "lab-rsa-..." },
  "claims":    [ { "name": "iss", "kind": "registered", "value": "...", "meaning": "...", "flags": [] } ],
  "expiry":    { "now": 1759000000, "exp": 1759000300, "status": "valid",
                 "lifetime_seconds": 300, "seconds_remaining": 271 },
  "weaknessClasses": { "unsigned-none": { "present": false, "findings": [] }, "...": {} },
  "findings":  [ { "id": "ALG_NONE", "severity": "high", "class": "algorithm",
                   "title": "...", "evidence": "...", "why": "..." } ],
  "summary":   { "counts": {...}, "highest": "high", "finding_ids": ["ALG_NONE"],
                 "verdict": "...", "catalogue_complete": false }
}
```

Every claim is decoded and explained: registered claims carry their RFC meaning, common
ones (scope, azp, sid, roles, acr…) are noted as common, everything else is labelled
`custom` — *"value is entirely issuer-defined; read it as data, not as a guarantee"*.
Time claims that are not numbers, oversized values, and values containing credential or
PII shapes are flagged on the claim row as well as in `findings`.

## The weakness classes, and how each is detected

The four `weaknessClasses` keys map onto the four questions this lab exists to answer.

### 1. `unsigned-none` — `alg: none` acceptance

| finding | rule |
|---|---|
| `ALG_NONE` | `alg` matches `none`, case-insensitively |
| `ALG_ABSENT` | no `alg` header at all (RFC 7515 makes it REQUIRED) |
| `ALG_NONE_WITH_SIGNATURE` | `alg: none` but the signature segment is not empty |

The token is only half the story — the accepting verifier is the bug. The lab ships one
(`none-accepting`) that honours whatever the header asks for; `strict` rejects it because
its algorithm list comes from configuration.

### 2. `algorithm-confusion` — key family chosen by the token

| finding | rule |
|---|---|
| `ALG_CONFUSION_RISK` | token presents HS\*, the assessed verifier is configured `--server-alg RS256`/`PS256`/`ES256` |
| `ALG_CONFUSION_CONFIRMED` | proof: the signature verifies as HMAC keyed on the supplied **public** key PEM |
| `ALG_MISMATCH_CONFIG` | presented alg ≠ configured alg, and it is not the HS/RS shape |
| `ALG_SYMMETRIC` | token is HS\* (a fact, not a bug — until the same material is also published as a public key) |
| `ALG_UNKNOWN` | alg outside the known registry |
| `JKU_HEADER` / `X5U_HEADER` / `X5C_HEADER` / `JWK_HEADER` | the token nominates its own key material or where to fetch it |
| `CRIT_HEADER` | header extensions the verifier MUST understand — and almost never does |
| `NO_KID` | key selection is ambiguous in a rotation set |

**Finding it in code:** the bug is one expression — `algorithms = [header.alg]` instead of
a constant, or a verifier that reads `alg` before it decides which key to use. The token-side
tell is an HS\* token whose audience is a service that publishes a JWKS.

**Measured, and it is the most useful thing in this lab:** both real libraries now refuse
this outright. `jsonwebtoken` 9.0.3 raises *"secretOrPublicKey must be a symmetric key when
using HS256"*; PyJWT 2.15.1 raises `InvalidKeyError: The specified key is an asymmetric key
or x509 certificate and should not be used as an HMAC secret.` The class survives in
verifiers that reach for the crypto primitives directly — which is why `lab/server.mjs`
has a `confused` mode written that way, and why `loop.mjs` asserts both the acceptance
*and* the libraries' refusal.

### 3. `weak-claim-validation` — signed, therefore trusted

| finding | rule |
|---|---|
| `MISSING_EXP` | no `exp` — the token never expires |
| `EXPIRED` | `exp` in the past (a token nobody rejected is the real finding) |
| `EXP_TOO_FAR` | lifetime beyond `--ttl-max` (policy input, stated as such) |
| `MISSING_AUD` | no `aud` — accepted anywhere the key is trusted |
| `MISSING_ISS` / `MISSING_SUB` / `MISSING_JTI` | no issuer / subject / unique id |
| `MISSING_NBF` | informational only |
| `CLAIM_WRONG_TYPE` | a NumericDate claim that is not a number |
| `NBF_AFTER_EXP`, `EXP_BEFORE_IAT` | malformed windows |

The verifier-side demonstration is `naive`: correct algorithm, real signature check, **zero**
claim validation. It accepts the `weak-claims` token forever. `strict` rejects the same
token with `missing-exp` — and the loop asserts both.

### 4. `claim-provenance` — what must never be in a signed payload

A JWS payload is signed, not encrypted. base64url is an encoding; every bearer can read it.

| finding | rule |
|---|---|
| `SENSITIVE_CLAIM` | claim name matches `password`/`secret`/`api_key`/`hash`/`salt`/`otp`/`private_key`/… |
| `CREDENTIAL_IN_VALUE` | an innocuous claim name whose *value* contains `password=…`, `api_key=…`, `Bearer …`, or a `BEGIN … PRIVATE KEY` block |
| `PII_CLAIM` | name matches email/phone/address/name/dob/ssn/passport/iban/card… or the value looks like an email |
| `CLAIM_INJECTION` | control characters (NUL/CR/LF) inside a claim value |
| `CLAIM_OVERSIZED` | a value over 512 chars |
| `PAYLOAD_LARGE` | payload over 4 KB |

Matching values are redacted in the report (`pass…<redacted 32 chars>`) so the analyzer's
own output is safe to paste.

### Integrity

`SIG_VALID` / `SIG_INVALID` / `SIG_WEAK_SECRET` (verified against a dictionary secret) /
`SIG_UNVERIFIED` (no key supplied — reported as a **limit of the run**, never as a pass).
A `SIG_INVALID` token is the one class a signature check does catch.

## The verifier matrix

Rows are issuance profiles; columns are verifier bugs. Every cell is asserted by `loop.mjs`.

| | `strict` (correct) | `confused` (alg from header; public PEM as HMAC secret) | `none-accepting` (no allowlist) | `naive` (no claim checks) |
|---|---|---|---|---|
| `strong` | ACCEPT | ACCEPT | ACCEPT | ACCEPT |
| `weak-claims` | reject: missing-exp | reject: missing-exp | reject: missing-exp | **ACCEPT** |
| `none` | reject: alg-not-allowed | **ACCEPT** | **ACCEPT** | reject: alg-not-allowed |
| `confusion` | reject: alg-not-allowed | **ACCEPT** | reject: bad-signature | reject: alg-not-allowed |
| `weak-secret` | reject: alg-not-allowed | reject: bad-signature | reject: bad-signature | reject: alg-not-allowed |

Each verifier answers with the **checks it actually performed** (`checks_performed`), so a
claim about a verifier is checkable against the verifier instead of asserted:

```powershell
curl.exe -s -X POST http://127.0.0.1:8791/api/verify/naive -H "content-type: application/json" -d "{\"token\":\"...\"}"
# {"ok":true,"verifier":"naive","accept":true,"alg":"RS256",
#  "checks_performed":["alg-from-config","sig"],
#  "note":"signature checked; exp/aud/iss deliberately NOT checked"}
```

`GET /api/posture` returns the whole table machine-readably.

## Install / reproduce from scratch

The analyzer needs nothing. The **loop** needs both oracles, because a cross-check that
cannot run is not a cross-check.

```powershell
cd crypto-lab
npm install                                              # jsonwebtoken 9.0.3, pinned, ~15 packages
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt   # PyJWT 2.15.1, cryptography 50.0.1
```

Verified present on this box at build time: Node **v24.19.0**, npm **11.17.0**, Python
**3.14.7**; `jsonwebtoken` **9.0.3**, `PyJWT` **2.15.1**, `cryptography` **50.0.1**.
Packages were confirmed to exist before install (`npm view jsonwebtoken version`,
`pip index versions PyJWT`, `pip index versions cryptography`) — no version here is guessed.

`node_modules/`, `.venv/` and `keys/` are gitignored. Nothing in this tree is a committed
third-party binary.

## Honest limits

- **No JWE.** A five-segment token is reported as `JWE_UNSUPPORTED` with an explanation. The
  payload is ciphertext; pretending to read it would be worse than saying so.
- **No custom or unregistered JWS algorithms.** `ALG_UNKNOWN` is the honest answer for
  anything outside the registered set, including `crit`-declared extensions.
- **No key recovery.** `SIG_WEAK_SECRET` tests a short built-in list of published-in-every-
  tutorial secrets (extend with `--weak-secret`). This is not a cracker, and it does not try
  to be one.
- **No fuzzing of the verifier.** The matrix is 20 asserted cells, not a search. Nothing here
  mutates a verifier looking for an unhandled branch.
- **The analyzer is a static reader.** It never fetches `jku`/`x5u`, never calls the service
  that issued the token, and never confirms that a token would *actually* be accepted. The
  finding is "this shape is present", and `weaknessClasses[*].question` says which question
  the cluster is answering.
- **Findings come from a fixed catalogue and `catalogue_complete` is `false` on purpose.** A
  zero-finding result means *none of the known shapes*, never *no weakness*. Unverified
  signature and unhandled formats are reported as limits inside the same JSON.
- **Claim-name heuristics are heuristics.** `SENSITIVE_CLAIM` matches names, not semantics:
  a claim called `salt` that holds a UUID will flag, and a secret called `x9` will not.
- **No ES256/EdDSA end-to-end case.** The analyzer recognises and can verify them
  (`EC_ALGS`), but the lab issues and asserts RSA and HMAC only.

## Stop lines

- **This is not a forge, and it is not for anybody else's service.** The lab issues tokens
  to itself so that we can recognise the weaknesses in *our own* code. It ships no
  forgery toolkit, no credential stuffing, no token replay against a service we do not run.
  If you want to prove a real service accepts `alg:none`, that is a test authorization
  question, not a tooling question.
- **Loopback only.** `lab/server.mjs` refuses to bind anything other than `127.0.0.1`.
- **No secrets in git.** RSA keys are generated at runtime into the gitignored `keys/`; the
  HMAC constants are published fakes and are labelled as such in `lab/keys.mjs`.
- **No outbound reach during analysis.** A `jku`/`x5u` header is *reported*, never
  dereferenced. This is a station stop line, and a key URL in a token is attacker-controlled
  input — fetching it is the attack, not the analysis.
- **The oracles are pinned and isolated.** They live in this tree's own `node_modules`/
  `.venv`; nothing is installed globally, and no third-party binary is committed.
