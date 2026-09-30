---
date: 2026-09-30
mission: Close the web/JavaScript reverse-engineering gap — capture a signed request over CDP, recover the algorithm, replay it outside the browser
status: verified
---

# After-action — web-reverse lane

## Mission
The station had zero JS-reverse capability. Build a runnable local lab that proves the whole
web-reverse loop, register it, and wire it into the agent CLI — without vendoring third-party
code and without shipping anything that evades someone else's defences.

## Evidence
Run in one command, exit 0:

```
$ powershell -File scripts\web-reverse-lab.ps1 loop      # == node web-reverse/tools/loop.mjs
  PASS  unsigned request rejected by the gate                HTTP 401
  PASS  capture /plain (1 signed request, HTTP 200)          exit 0  (0.9s)
  PASS  capture /obf (2 signed requests, HTTP 200)           exit 0  (0.9s)
  PASS  recover key from /obf and reproduce the captures     exit 0  (0.5s)
  PASS  replay: copy rejected, recomputed signature accepted exit 0  (0.1s)
  PASS  bot-detection report                                 exit 0  (1.4s)
LOOP CLOSED: signature captured, algorithm recovered, request minted outside the browser, gate accepted it.
```

Key steps, real output (abridged):

```
recover:  obfuscator array=_0xa decoder=_0x2f7a() xor=0x17 entries=17
          runtime probe Runtime.evaluate(_0x2f7a(i)) agrees with local decode: true
          recovered key "lab-demo-signing-key-…"  reproduces 2/2 captured signature(s) with node:crypto
          keyId sha256(key)[0:16] = e38c1367b1f06675 vs server e38c1367b1f06675 -> CONFIRMED
replay:   [1] verbatim copy      -> HTTP 409 replayed-signature
          [2] recomputed signature -> HTTP 200 accepted
          [3] forged body          -> HTTP 200 accepted
```

Files: `web-reverse/` (lab, tools, README, antibot.md), `scripts/web-reverse-lab.ps1`,
`manifests/tools.json` (category `web-reverse`), dispatcher row in `scripts/agent-cli.ps1`.

## Findings
1. **Node 24's global `WebSocket` is enough for CDP** (`node -e "typeof WebSocket"` -> `function`).
   A six-call CDP client is ~90 lines; no npm dependency, nothing vendored.
2. **A real gate is what makes the loop falsifiable.** 401 missing / 401 bad / 401 stale /
   409 replayed / 200 accepted. "Captured a request" and "reproduced a request" are different
   claims, and only the second one scores.
3. **`spawnSync` in an orchestrator deadlocks an in-process HTTP server** — the parent's event
   loop is blocked, so the browser's requests are never answered. `loop.mjs` uses async `spawn`.
4. **`navigator.webdriver` is true purely because the browser is launched with
   `--remote-debugging-port`** (measured: same browser without the flag reports `false`).
   Our own instrumentation is visible to any target that checks, worth +40 on the lab detector.
5. **The `Error.prepareStackTrace` inspector probe did not fire** on Chrome 154 with
   `Runtime.enable`. Recorded as a negative result with its control, not deleted.
6. **Pre-existing defect in a sibling's uncommitted file:** `scripts/agent-cli.ps1` contains
   one em dash and no BOM, so Windows PowerShell 5.1 decodes it as cp1252 and the catalog
   JSON is malformed for any UTF-8 consumer (and even breaks the quoting). Not this job's
   file — reported, not touched. Fix is one character or a BOM.

## What the next agent should do differently
- Reach for `scripts/web-reverse-lab.ps1 loop` (or `agent-cli.ps1 web-reverse`) before
  hand-driving a browser; the loop proves the toolchain is intact in ~4 s.
- `recover.mjs` understands the one obfuscator family we wrote. Real-world bundles, VM
  protectors, and `Debugger.setBreakpoint`-based tracing are **not** covered yet.
- Passing tool flags through `agent-cli.ps1 -> web-reverse-lab.ps1` needs `-NodeArgs`
  (`-NodeArgs '--url http://127.0.0.1:8787/obf --clicks 2'`); bare `--flags` are eaten by the
  PowerShell binder (`--out` -> ambiguous with `-OutVariable`). The wrapper now echoes the
  effective `nodeArgs` so this cannot fail silently. Direct `.mjs` calls always work.
- If a target challenges an authorized automated client, write it up as interference
  (`web-reverse/antibot.md`) — do not reach for evasion, it is a stop line.

## Patches made
- New: `web-reverse/` tree (lab target + 6 tools + README + antibot.md), `scripts/web-reverse-lab.ps1`
- Registered: `manifests/tools.json` category `web-reverse`; `notes/INDEX.md` row; `scripts/agent-cli.ps1` catalog + map rows
