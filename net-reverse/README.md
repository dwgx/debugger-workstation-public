# net-reverse

Self-authored network capture corpus, protocol-analysis driver, loopback replay,
and agent-drivable traffic interception. Zero new dependencies: tshark does the
decoding, the pcap writer is ours, and interception is the Chrome DevTools
Protocol's Fetch domain driven from the station's existing CDP client.

## The one command

```bash
node tools/loop.mjs
```

Exit 0 only when the corpus is generated, every question is answered, the
negative controls hold, replay is byte-identical, a request **and** a response
are rewritten in flight, and isolation still holds.

## What it proves

| Step | Result |
|---|---|
| corpus | 5 synthetic, hash-labelled captures written to `%TEMP%\net-reverse-lab\pcaps\` |
| questions | 16 protocol questions answered by tshark; 0 negative controls leaked |
| replay | a captured POST and a captured binary stream re-injected byte-identically |
| interception | `Fetch.continueRequest` rewrote a header **and** a body; `Fetch.fulfillRequest` replaced a response the origin did send |
| isolation | zero lab certificates in the machine or user root store, no system proxy |

The questions are not trivia. They cover DNS A/AAAA/TXT/CNAME, where a
credential actually lives in an HTTP exchange, server banners, TLS SNI, and
ClientHello fingerprint distinctness, plus decode-as reasoning for traffic on
non-standard ports — including a **decoy DNS TXT answer** that must be
separated from the real one, and a stream whose payload is only readable after
following it. An analyst who cannot tell a decoy from the answer will guess.

## Interception without a proxy and without a certificate

`tools/intercept.mjs` is the part that makes interception agent-drivable. Reqable
is a GUI; this is a CLI that a script can call.

Two patterns, both observed **server-side**, which is the only evidence that
matters:

1. **Request rewrite.** `Fetch.requestPaused` at `requestStage: Request` replaces
   a header and the body, then continues the request. The loopback recorder logs
   the modified values while the page sent the originals.
2. **Response rewrite.** `Fetch.requestPaused` at `requestStage: Response` plus
   `Fetch.fulfillRequest` replaces a response the origin *did* send with a body
   it never wrote. The page reads the fabricated body; the server log still
   shows its own.

No proxy, no CA, no trust store, no system proxy. The target is `127.0.0.1` and
the browser runs on a disposable `%TEMP%` profile with an egress-blocked
resolver map.

## Three defects found and fixed here — read these before changing the code

These are recorded because each one presented as a *working* result.

**1. `CDP#send` had no timeout, so a hang was undiagnosable.**
A `Runtime.evaluate {awaitPromise:true}` waiting on a fetch that was paused and
never continued never returned, and the pending slot stayed alive forever. The
tool produced no output at all, and the runner recorded it as `exit null`. Every
CDP command now settles or times out with a message naming the method and id.

**2. `content-length` in a rewritten header list deadlocks the page.**
Measured on Chrome 154: `Fetch.continueRequest` rejects the call with
`Unsafe header: content-length`. The call fails, the request stays paused, the
page's fetch never completes, and the evaluate never returns. This was invisible
because the handler's error was collected into a list that is only read *after*
the evaluate returns — a branch that could not be reached. CDP recomputes
framing headers from `postData`, so the correct move is to drop them.

**3. `postDataEntries` is accepted and silently ignored.**
This is the nastiest one, because it looks like success. With `postDataEntries`
the call returns OK, the **header** rewrite lands, and the body arrives at the
origin **unchanged** — a partial rewrite that reads exactly like a working
interceptor. `Fetch.continueRequest` takes `postData` as a base64 string;
`postDataEntries` belongs to a different CDP call.

And one more, in the checks themselves: the evidence selected
`recorder.records[0]`, which is the page-load GET, not the POST. The rewrite was
reported as failed while the page had already displayed the rewritten marker.
Evidence must name the request it is evidence for; it now selects by URL.

## Layout

```
lab/pcap-writer.mjs    minimal pcap writer, no scapy
lab/gen-pcaps.mjs      generates the labelled corpus
lab/echo-server.mjs    loopback recorder used as both target and replay sink
lab/tshark.mjs         tshark invocation helper
lab/questions.mjs      the 16 questions and their expected answers
tools/loop.mjs         the runner
tools/pcap-lab.mjs     corpus + question driver
tools/replay.mjs       re-injects a captured stream into a loopback listener
tools/intercept.mjs    CDP request/response rewriting
tools/trustcheck.mjs   the isolation control
```

## Honest limits

- The corpus is **synthetic**. It teaches filter construction, field
  extraction, follow-stream, and decode-as reasoning. It is not a capture of
  real traffic, and nothing here was sniffed from a network.
- No encrypted-traffic analysis beyond what the ClientHello exposes. There is
  no JA3/JA4 computation; the lab reads the fields tshark surfaces and counts
  distinct fingerprints, which is the analyst's first step rather than the last.
- Replay is byte-identical re-injection into **our own** loopback listener. It is
  not a traffic generator and not a redirector; pointing it at a real NIC is
  out of scope.
- Interception is proven over **plain HTTP**. The Fetch domain does not decrypt
  TLS, so an HTTPS interception path is not covered here — the lab TLS origin on
  `127.0.0.1:8443` exists for that, and the SPKI-pin trust model, not this tool,
  is what makes it work.
- Reqable remains the tool for GUI work. This exists so an agent can drive the
  same class of operation without a human clicking.

## Stop lines

- Loopback only. The recorder binds `127.0.0.1`.
- No certificate is installed anywhere, ever. `tools/trustcheck.mjs` is the
  control that proves it, and it runs on every invocation.
