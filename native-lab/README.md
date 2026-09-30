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

## Threat model — the server is not a security boundary

`--unsafe` looks like a safety switch. **It is a speed bump, and it was reversed
live on this host.**

On a worker started *without* `--unsafe` — `py_eval` absent from `tools/list` — one
unauthenticated loopback form POST was enough to make it callable:

```
POST /config   apply_profile=1&profile_text=py_eval     ->  py_eval returned 2
```

The mechanism, from the installed source:

- `http.py:93` snapshots `ORIGINAL_TOOLS` **at import time**, i.e. *before*
  `idalib_server.py:285-289` deletes the unsafe tools;
- `http.py:442-446` rebuilds `tools.methods` from that stale snapshot;
- `_check_api_request` (`mcp.py:303-328`) accepts any request carrying no `Origin`
  header, so **no token is required**;
- the result is persisted into the IDB netnode `$ ida_mcp.enabled_tools`
  (`http.py:447`), so **the policy travels inside the sample's `.i64`**.

Two more holes in the same story: `idb_open` / `idb_list` are `protected` from
`--profile` (`idalib_server.py:57-60`), and the supervisor never applies `--profile` to
its own registry (`idalib_supervisor.py:1498-1499` only forwards it to workers) — so a
profile described as "read-only" still grants arbitrary-path file access.

And the tag list itself is incomplete: 25 tools are marked unsafe, but **`idb_save`
is not**, and it writes a 2.7 MB file to an arbitrary path. For a static mission that
is a bigger hole than anything the tag covers. A related header,
`X-IDA-MCP-External-Base`, rewrites the download URL the agent is told to fetch —
measured `http://attacker.invalid:9999/output/….json`.

**Consequences for anything built on this server:**

1. Never pass `--unsafe`. Never send `POST /config`. Never trust `--profile`.
2. Our gate enforces authority; the server's flags do not. `gate_must_not_delegate`
   in the registry names the three mechanisms explicitly.
3. Treat reach as a declared effect, not a decorator tag — which is why the registry
   carries a `reach` field and `registry-verify.py` rule R8 fails when an entry's
   `requires` implies an effect the entry does not declare.

### Batches drop items silently

The batching is the reason to use this server, and it lies by omission. Measured, not
read:

- `normalize_dict_list` **silently drops** non-dict elements in a mixed list
  (`utils.py:704-706`) — 5 queries in, 4 results out, no index, no echo, no counter.
- An empty array becomes `[{}]` and returns one bogus failed item
  (`utils.py:694-695`).
- Past a 50,000-char cap (`rpc.py:20`) the whole result is replaced by a 10-item
  preview plus a truncation marker and a download URL. Measured: 6,000 `get_int`
  requests came back as 10 items and 417,213 characters truncated.

So the batch contract in the registry is `len(result) == len(queries)`. **A short
result is a failure, not a smaller answer.** Rule R9 fails any entry that consumes a
batch without saying how a short result is detected.

### Sessions are not durable handles

Observed live: a supervisor's `idb_open` adopted *another process's* `idalib` worker
through the shared discovery files, then lost the session on the very next call. Bind a
session to `sha256(object)` and re-derive it every round. This lab's `portFree()` guard
is the same instinct applied to the port.
## What the loop asserts, and why the assertion is the point

The `isError` check above is a control on the control. If a future version of the
server starts setting `isError` correctly, that check fails loudly and every wrapper in
the repo has to be re-examined — which is the point. **Any wrapper around this MCP must
test the `error` field and require non-null `code`.**

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
