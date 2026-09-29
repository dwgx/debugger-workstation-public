# Anti-automation systems: how they work, how to tell you are being fingerprinted, how to report it

Scope, stated first because it decides every line below: this station **detects and
reports** anti-automation interference on targets the owner is authorized to test. It does
not build evasion, spoofing, or captcha-solving tooling, and it does not help anyone get
past a third party's gate. The lab surface in `lab/pages/fingerprint.html` implements a
detector — a miniature of what a real site runs — so the signals below can be *measured*
rather than asserted.

## 1. How these systems work

A bot-management gate is a scoring pipeline, not a boolean test:

```
collect signals -> score -> threshold -> action
```

**Signal classes**

| Class | Examples | Who sees it |
|---|---|---|
| Transport / header | `User-Agent`, `Accept-Language`, `Accept`, `Sec-CH-UA`, `Sec-Fetch-*`, header order and casing, TLS ClientHello (JA3/JA4), HTTP/2 frame ordering | edge, before any page runs |
| Environment (JS) | `navigator.webdriver`, `navigator.plugins`/`mimeTypes`, `window.chrome`, WebGL `UNMASKED_RENDERER`, `hardwareConcurrency`, fonts, canvas/audio hashes, timezone vs IP | page, after JS runs |
| Behavioural | pointer/keyboard cadence, scroll and dwell patterns, request pacing, navigation depth, form-fill timing | page + edge over a session |
| Challenge / token | JS challenge that mints a cookie (e.g. `cf_clearance`-style), CAPTCHA, invisible challenge, a request header the page computes from a per-session seed | page → edge on later requests |

**Actions** are graded, and the grades are the part that matters for a report: allow →
throttle/delay → serve a challenge → soft block (wrong content) → hard block → shadow ban
(answers that look normal but are degraded). A gate that *challenges* an authorized
automated client is behaving as designed; that is the observation, not a bug to defeat.

Two properties follow and both are load-bearing:

- **It is probabilistic.** Thresholds trade false positives (blocking real users) against
  false negatives. That is why the interesting report is which signal fired, not "I got
  blocked".
- **It is partly server-side.** TLS/HTTP fingerprints and IP reputation are invisible to
  anything running inside the page. We can measure our own JS-surface footprint exactly,
  and can only *infer* the transport layer (differential tests, below).

## 2. Detecting that we are being fingerprinted

Evidence to collect, in the order that is cheapest to gather:

1. **Status and shape.** `403`/`429`/`503`; a `200` whose body is HTML where the API returns
   JSON; `content-type` mismatches; meta-refresh or `<noscript>` interstitials; a redirect
   to `/challenge`, `/verify`, `/cdn-cgi/*`.
2. **Tokens the page suddenly owes.** New cookies with vendor-ish names, hidden form fields
   carrying a token, a JS bundle whose only job is to compute a header, a `POST` whose
   signature headers appear only after a challenge page. (This is exactly the shape of the
   lab's signed request — the lab exists to practise recognising it.)
3. **Differential test.** Send the same request from two clients — the instrumented browser
   and plain `curl`/`node:http` — and compare. The difference localises the signal: if
   `curl` passes and the browser fails, the gate is scoring the environment; if both fail,
   it is transport/IP/rate.
4. **Rate and timing.** Same request, spaced out, succeeds → throttle rather than ban.
5. **Our footprint inside the page.** Run `node tools/fingerprint.mjs --compare`.

## 3. This station's measured footprint

`tools/fingerprint.mjs --compare` runs four clients against the lab detector. Real output
from this machine (Chrome 154, 2026-09-30):

| client | score | verdict | fired |
|---|---|---|---|
| headless Chrome + CDP attached | 75 | bot | `ua-headless` +35, `navigator.webdriver` +40 |
| headless Chrome, no CDP | 35 | suspect | `ua-headless` +35 |
| windowed Chrome + CDP attached | 40 | suspect | `navigator.webdriver` +40 |
| windowed Chrome, no CDP | 0 | human | — |

Two findings worth keeping:

- **`navigator.webdriver` flips to `true` purely because we launch the browser with
  `--remote-debugging-port`.** Same browser, same page, no such flag → `false`. So our
  instrumentation is visible to the target for +40 points, and any "we were blocked" note
  that ignores this is wrong.
- **The `Error.prepareStackTrace` inspector probe did not fire** on this build with
  `Runtime.enable` active (`prepareStackTraceReadWithoutTouch: false`). It is implemented,
  costed, and reported as a negative result, so the next window does not re-derive it as a
  detector that works. The control (`prepareStackTraceReadOnTouch`) is `true` everywhere,
  which is why the page separates the two.

## 4. Reporting it (debugging lane)

Anti-automation interference on an authorized target is an observation, not an obstacle to
route around. It goes into the debugging-lane artifact as:

| Element | Content |
|---|---|
| Target | the endpoint/page, with the request that triggered it |
| Instrumentation | the exact client that was flagged (browser + flags + CDP attached?), tool and version |
| Observation | status, body shape, cookies/tokens newly required, which signals the gate could have used, and the differential result |
| Conclusion | interference confirmed / suspected / not observed, with the specific evidence — and explicitly what remains unknown (transport-layer scoring we cannot see) |
| STOP note | that no evasion was attempted, and that testing continued only on endpoints that kept answering |

The professional value is real: "your WAF/bot gate challenged an authorized automated
client at step N, evidence attached" is a finding a program can act on, and it is the same
evidence a developer needs to tune a false positive. Building a bypass would convert that
finding into an incident.

## 5. Stop lines

- No evasion, spoofing, patching, or fingerprint-laundering — for anyone's site, including
  in a lab dressed up as a third party's.
- No captcha or challenge solving/bypass tooling, and no importing projects that ship it.
- No third-party production target. Loopback, or an asset the owner owns / is authorized in
  writing to test.
- No test against a site that refuses authorized automation to "see if it works anyway".
- Recognizing, measuring, and reporting interference is in scope. Defeating it is not.
