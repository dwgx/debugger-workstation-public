# native-lab — native binary analysis via IDA

Runs IDA Professional 9.2 headlessly through `idalib-mcp` against binaries we own,
and records the result so the next window does not have to take our word for it.

```
node native-lab/tools/loop.mjs
```

Exit 0 only when the loop closes. Current: **15/15, LOOP CLOSED, ~2.4 s**.

## What it proves

- IDA Professional 9.2 is installed **and licensed** on this host, behind the
  `Static-Reversing\IDA` junction.
- `idalib-mcp` serves MCP over **POST** on loopback and exposes **66 tools**.
- It decompiles our own `c01-stringobf.exe` and recovers the two decoder calls with
  their constants, the `strcmp` comparison logic, and the plaintext decoy flag
  `FLAG{c01_strings_gave_you_this_decoy}` — the exact trap that sample was built to
  teach, recovered from the binary rather than read out of the source.

## What it deliberately does not prove

- Nothing about a binary we do not own. Every run in this lab uses
  `crackme-corpus/out/`, which we build from our own source, so provenance is
  checkable by file.
- Nothing about IDA's GUI plugin on 13337. `OWNER.md:13` makes `idalib` or `idat -A`
  the agent default; `AGENTS.md:123` forbids adding a second IDA server.
- Nothing about dynamic analysis. This is static only; a debugger run is a different
  capability with a different gate.

## The trap this lab exists to record

`ida-pro-mcp` reports a **failed** decompile like this:

```json
{ "addr": "0xDEADBEEF", "code": null, "error": "Decompilation failed at 0xdeadbeef" }
```

`isError` is **false**. A wrapper that trusts `isError` alone writes the failure down
as a success with a null body. That is the complete-and-confident-and-wrong shape the
rest of this station is built to reject, except that here it arrives through a real
tool rather than a hallucinated one.

So the loop asserts the hazard rather than documenting it:

```
PASS  CONTROL: isError is FALSE on that failure   isError=false while error is set
                                                  — an isError-only wrapper logs a success
```

That check is a control on the control. If a future version of the server starts
setting `isError` correctly, this check fails loudly and every wrapper in the repo has
to be re-examined — which is the point. **Any wrapper around this MCP must test the
`error` field and require non-null `code`.**

## Two controls that exist because they caught something

- **Port must be free before we start.** An orphaned `idalib` worker from an earlier
  run held 8745, and this loop cheerfully attached to a server it had not started,
  ready to report another run's session as its own evidence. It now refuses and exits
  1 instead. Verified: with a decoy listener bound, the loop fails on exactly that
  check and nothing else.
- **Session must stop analysing.** IDA does not list a session until its initial
  analysis completes. Asking early returns an empty list, which is indistinguishable
  from a failure to open — the same shape as a parser handed an error page and told
  "no rows". The loop waits for `is_analyzing` and `busy` to clear.

Both were found by running the thing, not by reading it.

## Notes for anyone extending this

- MCP is **POST** `/mcp`. A `GET` returns 405, which is the protocol, not a fault.
- Every tool call needs `database=<session_id>` from `idb_open` / `idb_list`.
- `list_funcs` takes `queries: [{count: N}]`, not `limit`.
- Kill with `taskkill /T /F`, not `proc.kill('SIGKILL')` — the latter trips a libuv
  assertion on Windows.
