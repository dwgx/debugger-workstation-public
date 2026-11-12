# web-reverse — web/JavaScript reverse-engineering lane

Self-authored, in-tree, **loopback only** (Node ≥ 22 for the global `WebSocket`).
This is the station's answer to the one capability domain it had none
of: a signed client request that can be captured, understood, and then reproduced
*outside the browser*.

The CDP runtime loop (`lab/`, `tools/`) is **zero npm dependencies**. The static
deobfuscation chain (`static/`) is not: it depends on the published tools an analyst
would actually reach for (webcrack, wakaru, acorn, meriyah, @babel/*, recast,
ast-grep, javascript-obfuscator). Those are pinned in `static/package.json` and
installed into the gitignored `static/node_modules/`. Nothing vendored is committed.

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
| `static/gen-obf.mjs` | Known-answer **sample factory**: obfuscates plaintext signers with `javascript-obfuscator`, and writes the answer key beside them. |
| `static/deobf.mjs` | The static deobfuscation driver: sourcemap-first triage → webcrack → wakaru → measure. |
| `static/rename.mjs` | Renames the bindings that survive deobfuscation (a name, not a control-flow change). |
| `static/selftest.mjs`, `static/sg.mjs` | Toolchain self-test and the `ast-grep` rule runner. |
| `static/lib/` | `triage.mjs` (fingerprints bundler / obfuscator family / transpiler artifacts from the bytes), `sandbox.mjs` (runs recovered client code in a bare V8 context), `astgrep.mjs`. |
| `tools/loop2.mjs` | The static chain in one self-judging command: generate → deobfuscate → grade against the known answer → sign → live gate. |
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

## Invoking it from the station

```powershell
powershell -File scripts\web-reverse-lab.ps1 loop        # whole proof, JSON + transcript
powershell -File scripts\web-reverse-lab.ps1 status      # node/chrome/server readiness
powershell -File scripts\web-reverse-lab.ps1 serve       # start the target (blocking)

# flags: PowerShell binds bare --out to -OutVariable before the script sees it, so tool
# flags go through -NodeArgs (verified form, -File safe):
powershell -File scripts\web-reverse-lab.ps1 capture -NodeArgs '--url http://127.0.0.1:8787/obf --clicks 2'
```

The wrapper prints the effective `nodeArgs` in its JSON, so a mangled invocation is visible
instead of silently falling back to defaults. In an interactive/`-Command` session an array
works too: `-NodeArgs @('--url','http://127.0.0.1:8787/obf')`. For anything else, call the
`.mjs` tool directly — that is always the ground truth.

Dispatched through the station CLI as well:

```powershell
powershell -File scripts\agent-cli.ps1 web-reverse loop
powershell -File scripts\agent-cli.ps1 web-reverse status
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

## The static deobfuscation chain

`loop.mjs` proves the *runtime* claim: capture a signed request, recover the key, mint a
request outside the browser. `loop2.mjs` proves the *static* claim, and it is a separate
deeper chain.

### The one command

```bash
cd web-reverse/static && npm install     # once; node_modules/ is gitignored
cd .. && node tools/loop2.mjs
```

Exit `0` means, in that run: a genuinely obfuscated sample was generated, it was
deobfuscated, the recovery was graded against a key the run itself did not know in
advance, and the recovered code signed a request the live gate accepted.

The explicit exits of `tools/loop2.mjs` are `0` for that completed static chain,
`6` when the sample factory left no generated known answer, and `9` when one or more
steps were refuted. Its success marker is `STATIC TOOLCHAIN PROVEN`; `LOOP CLOSED`
belongs to the runtime sub-loop and alone does not establish the static result.

### What it does, stage by stage

The order is the method (`wiki/methods/web-reverse-method.md`, Layer 0-1):

1. **Sourcemap first.** If the original sources ship, the answer is "read the source",
   not "deobfuscate". Nothing else runs.
2. **Triage** (`static/lib/triage.mjs`): fingerprint the bundler, the obfuscator family
   and the transpiler artifacts *from the bytes alone*, so the next stage is chosen by
   evidence rather than by habit.
3. **webcrack** — string arrays, control-flow flattening, dead code, and module unpacking
   for webpack/browserify/esbuild/metro.
4. **wakaru** — puts transpiled syntax back (`?.`, `??`, `_asyncToGenerator`, ESM/CJS).
   Skipped automatically when triage finds nothing for it to do.
5. **Measure, do not assert.** The output is parsed by three independent parsers, the
   residual obfuscation markers are counted before and after, and the caller names the
   exact strings that must be present with `--expect`.

### The known-answer part

A deobfuscator you cannot falsify is a claim, not a capability. So `static/gen-obf.mjs`
is a **sample factory**, not a fixture:

- it takes plaintext signers and obfuscates them with `javascript-obfuscator` 5.8.0
  (base64 string array + rotation, control-flow flattening, dead-code injection,
  hexadecimal identifier mangling);
- it writes `known-answer.json` next to the artifacts, recording the plaintext, the key,
  and what each sample is expected to yield;
- the page variant uses the lab's own public key, so the **live gate** can accept what
  the recovered code produces;
- the signer and bundle variants get a **fresh random key every run**, so a hardcoded
  answer cannot pass;
- it refuses to emit a sample whose plaintext key is still readable in the bytes, and it
  fingerprints each artifact with the same triage the deobfuscator uses — "this sample is
  genuinely obfuscated" is a measured property of the bytes, not a claim about an options
  object.

`loop2.mjs` then deobfuscates those artifacts, executes the recovered code in a bare V8
context (`static/lib/sandbox.mjs`, crypto from `node:crypto` — an implementation
independent of the page's own), and **posts to the live gate**. That is the strong form
of the proof: not "the recovered text contains the key" but "code recovered from
obfuscated bytes produced a signature the server independently accepted". A wrong-key
signature is posted alongside and must come back `401`.

### The parts by hand

```bash
# generate the samples and the known answer
node static/gen-obf.mjs --out-dir "%TEMP%\wr-static" --json

# deobfuscate one of them, and see it measure itself
node static/deobf.mjs --in "%TEMP%\wr-static\signer-obf.js" \
  --artifacts "%TEMP%\wr-static\art" --expect "<the key from known-answer.json>" --print

# the gate, then the generated page over it
node lab/server.mjs --port 8787
#   -> http://127.0.0.1:8787/obf-gen   (set WEB_REVERSE_GEN_PAGE to serve another dir)
```

Artifacts land in `%TEMP%\web-reverse-captures\` — machine state, deliberately not in the
repo. `deobf.mjs` exits `0` ok, `2` usage, `3` stage/parse failure, `4` `--expect` unmet.

### Why the sample is shaped the way it is

Both facts below were measured against `javascript-obfuscator` 5.8.0, not assumed, and
both are why the sample factory uses `var` inside an `if (true) { … }` block:

- a function body that declares block-scoped bindings (`const`/`let`) is **not**
  control-flow-flattened (verified: identical body, `const` → 0 dispatchers, `var` → 1);
- dead-code injection collects block statements from the `if (true) { var f = function… }`
  shape and produced **nothing** without it.

That is what obfuscator.io's engine actually eats: bundled, `var`-flavoured client code.

## Honest limits

- **Proven on the samples we generate, on obfuscator.io's engine.** `loop2.mjs` proves
  string-array + rotation, control-flow flattening, dead-code injection and hex identifier
  mangling — the exact protection set `gen-obf.mjs` turns on. It has **not** been run
  against a real-world target, and webcrack's coverage of any particular site is not
  guaranteed by anything here.
- **VM/JSVMP protectors are not supported, and triage says so out loud.** An opcode
  interpreter (`while(true) switch(op)` over a number array) is detected as the `jsvmp`
  family and labelled *not statically deobfuscatable*. Nothing in this lane lifts one. The
  correct move against a VM is to instrument the interpreter boundary at runtime
  (`tools/capture.mjs` + hooks), which is the other lane, not this one.
- **WASM is not supported.** There is no WASM parsing, no `wasm2c`-style lifting, and no
  decompilation of wasm bodies anywhere in `static/`. A target whose signing logic lives
  in a wasm module is out of scope; the chain will happily report on the JS around it and
  that is all it will do.
- **Anti-debug and self-defending are off in the sample factory** (`selfDefending:false`,
  `debugProtection:false`), so the chain is not exercised against infinite-debugger traps
  or `debugger` statement traps. webcrack handles some of these; we have not measured it
  and do not claim it.
- **Deobfuscation is not deobfuscation-to-original-source.** After the run there are still
  mangled bindings — `loop2.mjs` reports them (11 of 11 renameable in the current run) and
  `static/rename.mjs` is the tool for them. Recovered code is *semantically* the original,
  not textually identical to it. No step in this lane claims byte-equality with the
  pre-obfuscation source.
- **The known answer is known because we made it.** The page variant's key is the lab's
  public constant. The signer and bundle variants reseed a random key per run, so a
  hardcoded answer cannot pass, but the *structure* of the sample is still ours. This
  proves the toolchain recovers what these protections hide; it does not prove anything
  about a protector we did not test.
- **`deobf.mjs` greps for `--expect` substrings.** That is a deliberate, honest
  measurement, and it is exactly why `loop2.mjs` also executes the recovered code and
  requires the live gate to accept its signature, and why step [9] re-grades the same file
  against a wrong key to prove the assertion can fail. Substring presence alone would be
  theatre.
- **No JS-engine-level instrumentation in the static chain:** no breakpoint on the signing
  function, no heap search for key material, no timing side channel. `recover.mjs` and
  `static/` use source parsing, runtime evaluation in a bare context, and crypto
  verification only.
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
