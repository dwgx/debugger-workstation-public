# web-reverse — web/JavaScript reverse-engineering lane

Self-authored, in-tree, **zero npm dependencies** (Node ≥ 22 for the global `WebSocket`),
**loopback only**. This is the station's answer to the one capability domain it had none
of: a signed client request that can be captured, understood, and then reproduced
*outside the browser*.

Everything here is written for this station. Nothing is vendored, cloned, or copied from
the community "reverse-skill" projects, and no third-party binary is committed.

| Path | What it is |
|---|---|
| `lab/server.mjs` | Loopback target. Serves the pages and validates the signature gate. |
| `lab/pages/plain.html` | Readable signer: HMAC-SHA256 over `ts + "." + body`, key in source. |
| `lab/pages/obf.html` | Hardened signer: string array (XOR 0x17), mangled identifiers, flattened control flow. |
| `lab/pages/fingerprint.html` | Bot-detection surface: header + client signals, scored server-side. |
| `lab/pages/sha256-pure.js` | Dependency-free SHA-256/HMAC used by the readable page (a `crypto.subtle` call would leave nothing to reverse). |
| `tools/cdp.mjs` | ~90-line CDP client: JSON-RPC over one websocket, flat session ids, event waits. |
| `tools/chrome.mjs` | Launches a **disposable** lab Chrome (own `%TEMP%` profile, loopback-resolver-locked) or attaches to one you started. |
| `tools/capture.mjs` | Captures the signed request from a page without touching the page. |
| `tools/recover.mjs` | Deobfuscates, recovers the key, and refuses to report anything it could not reproduce. |
| `tools/replay.mjs` | Mints a valid request with plain `node:http`. The North Star proof. |
| `tools/fingerprint.mjs` | Reports what the target can see of us — including our own instrumentation. |
| `tools/loop.mjs` | All of the above in one self-judging command. |
| `antibot.md` | How anti-automation systems work, how to detect that we are being fingerprinted, and how to report it. |

## The one command

```powershell
powershell -File scripts\web-reverse-lab.ps1 loop     # or: node web-reverse/tools/loop.mjs
```

It runs the gate, both captures, the recovery, the replay and the fingerprint report, then
prints a PASS/FAIL table. Exit `0` means the loop closed on this machine, in that run:

```
  PASS  unsigned request rejected by the gate                HTTP 401
  PASS  capture /plain (1 signed request, HTTP 200)          exit 0  (0.9s)
  PASS  capture /obf (2 signed requests, HTTP 200)           exit 0  (0.9s)
  PASS  recover key from /obf and reproduce the captures     exit 0  (0.5s)
  PASS  replay: copy rejected, recomputed signature accepted exit 0  (0.1s)
  PASS  bot-detection report                                 exit 0  (1.4s)

LOOP CLOSED: signature captured, algorithm recovered, request minted outside the browser, gate accepted it.
```

## The loop by hand

```bash
# 1. target (loopback only; binds 127.0.0.1)
node web-reverse/lab/server.mjs --port 8787

# 2. negative control: the gate is not decoration
curl -X POST http://127.0.0.1:8787/api/submit -d '{"op":"probe"}'
#   -> HTTP 401 {"ok":false,"error":"missing-signature-headers"}

# 3. capture a signed request through CDP (disposable Chrome, no window)
node web-reverse/tools/capture.mjs --url http://127.0.0.1:8787/obf --clicks 2 --out "%TEMP%\wr-obf.json"
#   -> POST /api/submit -> HTTP 200, x-lab-ts / x-lab-sign / body, plus the XHR tap

# 4. recover the algorithm + key from the hardened page
node web-reverse/tools/recover.mjs --capture "%TEMP%\wr-obf.json" \
     --page http://127.0.0.1:8787/obf --out "%TEMP%\wr-recovered.json" --runtime-probe
#   -> decoded string table, recovered key, 2/2 signatures reproduced with node:crypto,
#      sha256(key)[0:16] == the server's keyId

# 5. replay outside the browser
node web-reverse/tools/replay.mjs --capture "%TEMP%\wr-obf.json" \
     --key-file "%TEMP%\wr-recovered.json" --url http://127.0.0.1:8787 --new-body
#   -> [1] verbatim copy 409 replayed-signature   (a copy is worthless)
#      [2] recomputed signature 200 accepted      (the algorithm was recovered)
#      [3] forged body 200 accepted               (the client's powers are now ours)

# 6. what the target sees of us
node web-reverse/tools/fingerprint.mjs --compare
```

Artifacts land in `%TEMP%\web-reverse-captures\` — captures, recovered key, fingerprint
report. They are machine state and deliberately **not** written into the repo.

## The signature gate

```
x-lab-ts   : epoch milliseconds
x-lab-sign : hex( HMAC-SHA256( key, "<ts>.<raw body>" ) )
```

The gate is real, which is what makes the loop falsifiable:

| Condition | Answer |
|---|---|
| missing headers | `401 missing-signature-headers` |
| signature does not match the body | `401 bad-signature` |
| timestamp outside ±300 s | `401 stale-timestamp` |
| that exact signature already accepted | `409 replayed-signature` |
| signature matches, fresh, unused | `200 accepted` |

So "I captured a request" and "I reproduced a request" are different claims, and the
second one is the only one that scores. The key in the lab is a public constant — stop
line: no real secrets in git, ever.

## CDP calls used

`capture.mjs`, in order (it prints this list itself):

```
Target.createTarget                     new tab
Target.attachToTarget {flatten:true}    session id for that tab
Page.enable / Network.enable / Runtime.enable
Runtime.addBinding {name:'__labTap'}    delivery channel for the injected tap
Page.addScriptToEvaluateOnNewDocument   XHR open/setRequestHeader/send tap, before page scripts
Page.navigate                           load the target page
Runtime.evaluate                        click the page's own submit button
Network.getResponseBody                 the gate's verdict body
```

`recover.mjs --runtime-probe` adds a second `Runtime.evaluate` path: it asks the live page
to run its own decoder over every index and requires the runtime answer to equal the
static decode. Two independent paths, one verdict.

**Why hand-rolled and not `chrome-remote-interface`:** it would work, but Node 24 already
ships a global `WebSocket` (verified: `node -e "typeof WebSocket"` → `function`), the lab
needs six CDP calls, and the station's standing rule is that third-party code does not go
into this tree. ~90 lines beats a dependency here. If the station ever needs full CDP
coverage, `chrome-remote-interface` is the upgrade path and this file is the seam.

**Why not an MCP backend:** the router's backends are vendored upstream servers and none of
them speaks CDP. This lane is a local, short-lived, self-authored CLI — it fits the
existing agent-CLI pattern (`scripts/agent-cli.ps1 web-reverse …`), which is where it is
wired. Nothing was added to `mcp/.mcp.json.template`.

## What "recovered" means here

`obf.html` is the same client as `plain.html` with three standard protections applied by
hand: every literal goes through a string array (`_0x2f7a(i)`, XOR 0x17), identifiers are
mangled, and the request flow is a flattened `while(true) switch(state)` machine.

`recover.mjs` does the three stages an analyst would, and **stops if any stage fails**:

1. **Locate** the indirection from the source: array literal, decoder name, XOR constant
   (this tool understands the obfuscator family we wrote; it is not a general deobfuscator).
2. **Decode** the table with plain Node, and — with `--runtime-probe` — require the live
   page to agree index by index.
3. **Verify** each decoded literal as a key candidate by reproducing the captured
   signatures with `node:crypto` (an implementation independent of the page's own crypto),
   then confirm against the server's `keyId = sha256(key)[0:16]`.

A key that fails stage 3 is not reported. `--runtime-probe` disagreement aborts with exit 4.

## Honest limits

- **Scope of the deobfuscator:** one hand-written obfuscator family. It is not
  `deobfuscator.io`/`obfuscator-io` compatible, does not handle VM-based or wasm-based
  protectors, and does not beautify real-world webpack bundles. Those are the next
  increments, not claimed capabilities.
- **No JS-engine-level instrumentation:** no `Debugger.setBreakpoint` on the signing
  function, no DevTools heap search for key material, no `Performance`/timing side channel.
  `recover.mjs` uses source + runtime evaluation + crypto verification only.
- **The `Error.prepareStackTrace` inspector probe did not fire** in this Chrome 154 /
  `Runtime.enable` configuration. It is kept, costed, and reported as a negative result
  rather than deleted, so nobody re-derives it as a working detector. See `antibot.md`.
- **Not measured:** TLS/JA3-class fingerprints (server-side only, invisible to our tools),
  behavioural biometrics, and commercial bot-management products.
- **`replay.mjs` needs the recovered key.** It is not a signature forgery tool: it proves
  the recovered algorithm+key by using them, on a target we run.

## Stop lines

- Lab target binds `127.0.0.1` only, and the lab server refuses to start on anything else.
- Browsers are **launched by these tools**, with a disposable `%TEMP%` profile and
  `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1` so a lab page cannot reach the
  internet while we drive it. The tools never attach to the daily Chrome, another user's
  session, `chrome.exe` you did not start, or the agent browser.
- Authorized work only: this machine, or an asset the owner owns or is authorized in
  writing to test. Never a third-party production site.
- No captcha/anti-bot **evasion** tooling, here or anywhere in this station. Recognising
  and reporting anti-automation interference on an authorized target is in scope;
  defeating someone else's gate is not. See `antibot.md`.
- No secrets in git: the lab key is a public constant, captures live in `%TEMP%`.
