---
date: 2026-09-30
mission: Close D9 (cryptography & tokens) — build the station's JWT/token analysis capability and prove it classifies every weakness class
status: verified
---

# After-action — crypto-lab (D9)

## Mission
`CHARTER-ARSENAL.md` lists D9 (cryptography & tokens) as a capability domain, and the
station had **no JWT tooling at all**. Build a loopback issuer + four deliberately-buggy
verifiers, and an analyzer that reads a token and names the weakness classes in it — with
one command proving it, per the North Star.

## Evidence
Run in one command, exit 0:

```
$ powershell -File scripts\crypto-lab.ps1 loop
  PASS  strong           alg=RS256  sig=valid                          exp=valid
        findings  (none)
        verifier  strict:accept   checks=[alg-from-config, sig, exp, nbf, iss, aud, required-claims]
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=RS256  -> verified (want verified)
        oracle    PyJWT  v2.15.1  key=rsa-public algs=RS256       -> verified (want verified)
  PASS  none             alg=none   sig=unsigned                       exp=valid
        findings  ALG_NONE
        verifier  none-accepting:accept   checks=[alg-from-token-header, exp, aud]
        oracle    jsonwebtoken v9.0.3  key=none       algs=none    -> verified (want verified)
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=RS256   -> signature-required (want signature-required)
        oracle    PyJWT  v2.15.1  key=rsa-public algs=RS256       -> alg-not-allowed (want alg-not-allowed)
  PASS  confusion        alg=HS256  sig=valid-as-hmac-over-public-key  exp=valid
        findings  ALG_CONFUSION_CONFIRMED, ALG_CONFUSION_RISK, ALG_SYMMETRIC
        verifier  confused:accept   checks=[alg-from-token-header, exp]
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=HS256   -> refused-key-type (want refused-key-type)
        oracle    PyJWT  v2.15.1  key=rsa-public algs=HS256       -> refused-key-type (want refused-key-type)
        oracle    jsonwebtoken v9.0.3  key=rsa-public algs=RS256   -> alg-not-allowed (want alg-not-allowed)
  PASS  weak-claims      alg=RS256  sig=valid                          exp=absent
        findings  MISSING_EXP, SENSITIVE_CLAIM, MISSING_AUD, PII_CLAIM, MISSING_JTI, MISSING_NBF
        verifier  naive:accept   checks=[alg-from-config, sig]
        oracle    PyJWT  v2.15.1  key=rsa-public algs=RS256       -> missing-claim (want missing-claim)
  PASS  weak-secret      alg=HS256  sig=valid                          exp=valid
        findings  SIG_WEAK_SECRET, ALG_SYMMETRIC
        oracle    jsonwebtoken v9.0.3  key=secret algs=HS256      -> verified (want verified)
  PASS  expired          ... EXPIRED ... expired (want expired) x2
  PASS  exp-too-far      ... EXP_TOO_FAR
  PASS  jku-header       ... JKU_HEADER
  PASS  tampered         ... SIG_INVALID ... rejected (want rejected) x2
  PASS  claim-injection  ... CLAIM_INJECTION
  PASS  unverified       ... SIG_UNVERIFIED
  PASS  jwe              ... JWE_UNSUPPORTED
  PASS  verifier matrix (5 profiles x 4 verifiers)  every cell matched the expected acceptance table
  PASS  negative control: analyzer --expect refuses a wrong set  exit 4 (want 4)

LOOP CLOSED: every weakness class was classified as expected, every verifier behaved as its bug implies,
             and jsonwebtoken + PyJWT agreed with the analyzer on every case they could express.
JSON-SUMMARY {"total":17,"pass":17,"fail":0}
```

The verifier matrix, real output:

```
              strict              confused            none-accepting      naive
strong        ACCEPT              ACCEPT              ACCEPT              ACCEPT
weak-claims   reject:missing-exp  reject:missing-exp  reject:missing-exp  ACCEPT
none          reject:alg-not-…    ACCEPT              ACCEPT              reject:alg-not-…
confusion     reject:alg-not-…    ACCEPT              reject:bad-signature reject:alg-not-…
weak-secret   reject:alg-not-…    reject:bad-signature reject:bad-signature reject:alg-not-…
```

Cold start (no `keys/` directory) verified: `RSA-2048 key generated (crypto-lab/keys/,
gitignored)`, new `kid`, loop still 17/17.

Toolchain: Node **v24.19.0**, npm **11.17.0**, Python **3.14.7**; `jsonwebtoken` **9.0.3**
(npm, 15 packages), `PyJWT` **2.15.1** + `cryptography` **50.0.1** (venv). All four version
numbers were confirmed to exist before install (`npm view jsonwebtoken version`,
`pip index versions PyJWT`, `pip index versions cryptography`); nothing was guessed.

Files: `crypto-lab/` (lab + 5 tools + README), `scripts/crypto-lab.ps1`, a catalog+map row
in `scripts/agent-cli.ps1`, `manifests/tools.json` category `crypto-lab`.

## Findings

1. **Both real JWT libraries now refuse algorithm confusion outright.** `jsonwebtoken`
   9.0.3: *"secretOrPublicKey must be a symmetric key when using HS256"*. PyJWT 2.15.1:
   `InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should
   not be used as an HMAC secret.` The class is therefore **not** reachable through a
   modern library call — it survives in verifiers that reach for `crypto.createHmac(...)`
   with a public PEM, which is exactly what the lab's `confused` mode is written as. This
   is the most useful thing the lab teaches, and it is why `loop.mjs` asserts the libraries'
   *refusal* as well as the hand-rolled verifier's acceptance. Telling an analyst to "try
   alg:none/confusion" without this fact sends them down a dead end on any modern stack.

2. **Both libraries also refuse `alg:none` under a pinned allowlist** — `jsonwebtoken` with
   *"jwt signature is required"* (HS\* pinned to RS256), PyJWT with `InvalidAlgorithmError`.
   The allowlist is the control; the library default is not.

3. **PyJWT requires an explicit `algorithms` list and enforces `aud` whenever the token
   carries one.** Two of the four initial loop failures were this: PyJWT raised
   `InvalidAudienceError` on a perfectly good token because the oracle had not been told the
   audience. The oracles now derive `--issuer`/`--audience` from the token's own claims,
   which is also what a correct verifier does. Captured because it is a real integration
   trap, not a lab quirk.

4. **`--expect` on an empty set is a real edge case.** The first loop run reported a false
   failure on the `strong` control because the harness passed `--expect NONE` to keep the
   argument non-empty, and the analyzer dutifully looked for a finding called `NONE`.
   Empty string is now meaningful ("expect no findings"), and the analyzer tests
   `o.expect !== undefined` rather than truthiness, because `[]` is truthy in JS.

5. **Windows PowerShell 5.1 decorates native stderr whenever it is redirected.** Both
   `2>&1 | Out-String` and `2> $file` turn every analyzer stderr line into a
   `NativeCommandError` record, and with `$ErrorActionPreference = 'Stop'` the run aborts
   before `$LASTEXITCODE` is read. `scripts/crypto-lab.ps1` therefore leaves the child's
   stderr unredirected (it inherits the console handle) and only captures stdout — two
   streams, no decoration, exit code intact. **`scripts/web-reverse-lab.ps1` still has the
   `2>&1` form**; it is a sibling's file, reported here rather than edited.

6. **Pre-existing defect fixed in a file this job had to touch:** `scripts/agent-cli.ps1`
   had no BOM and one em dash (byte `E2 80 94`), so PowerShell 5.1 decoded it as cp1252 and
   the catalog JSON was malformed for any UTF-8 consumer. The em dash is now `--` and the
   catalog output is 0 non-ASCII bytes and parses. (The web-reverse after-action had already
   reported this; this job needed the file, so it repaired it.)

7. **The claim-provenance class needed a value-side rule, not just a name-side one.** A
   claim named `note` holding `password=hunter2` passes every name heuristic. Added
   `CREDENTIAL_IN_VALUE`. Likewise `sub: analyst@lab.invalid` tripped `PII_CLAIM` on the
   *control* token, which was correct detection and the wrong control — the `strong`
   profile's `sub` is now an opaque `usr_1f4a…` id.

## What the next agent should do differently

- Reach for `scripts\crypto-lab.ps1 loop` before hand-analysing a token; it proves the
  toolchain and the classifier in ~4 s. For one token, `analyze` alone needs no installs.
- **When someone says "try alg:none / algorithm confusion", check the library version
  first.** On `jsonwebtoken` ≥ 9 and PyJWT ≥ 2.x both are refused by the library. The
  question to ask is not "does the library allow it" but "does this service hand-roll its
  verifier, and does it read `alg` from the token".
- `--server-alg` is not decoration. `ALG_CONFUSION_RISK` is a *config*-side finding and
  cannot fire without it; a token alone can only produce `ALG_CONFUSION_CONFIRMED` (given
  the public key).
- Passing tool flags through the wrapper: first-class params (`-TokenFile`, `-RsaPub`,
  `-ServerAlg`, `-Expect`, `-TtlMax`, `-Quiet`) or `-NodeArgs '<flags>'`. Bare `--flags` are
  eaten by the PowerShell binder, same as documented for `web-reverse-lab.ps1`.
- Do not add a JWE or "crack the HMAC key" feature without re-reading the stop lines. Both
  are named limits in `crypto-lab/README.md`; the second is a forge.

## Patches made
- New: `crypto-lab/` — `lab/{jose,keys,server}.mjs`, `tools/{analyze,oracle-node,oracle.py,cases,loop}`, `README.md`, `package.json`, `package-lock.json`, `requirements.txt`, `.gitignore`
- New: `scripts/crypto-lab.ps1` (status/loop/analyze/oracle/serve/catalog)
- Registered: `manifests/tools.json` category `crypto-lab` (5 entries); `notes/INDEX.md` row
- Modified: `scripts/agent-cli.ps1` (catalog row, map row, synopsis, em dash → `--`)
