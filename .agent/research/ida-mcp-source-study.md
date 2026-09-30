# ida-pro-mcp v2.0.0 — source study for the capability registry

**What this is.** A read of the *installed* `ida-pro-mcp` (not its README), plus a live probe of
the same build, to extract the design patterns the station's capability registry and mission
runner should adopt — and, more importantly, the ones it must refuse.

**Provenance of every claim below.** Source root
`D:\Software\Developer\Python314\Lib\site-packages\ida_pro_mcp\` (installed 2026-08-27, wheel
`ida_pro_mcp-2.0.0`, Hex-Rays `idapro` 0.0.10, IDA Professional 9.2). Every `file:line` is from
that tree. Live behaviour was measured against a throwaway idalib worker started on loopback
port 8792 over a scratch copy of `crackme-corpus\out\c02-cff-dispatch.exe` (Owner-authored corpus
binary, copied to `%LOCALAPPDATA%\Temp\re-research\ida-source-study\probe.exe` so no repo artifact
was touched); the worker and its discovery registrations were removed afterwards. Nothing was
installed, no git write, no vendoring, no Docker.

---

## 0. The map

```
ida_pro_mcp/
  ida_mcp.py                ~300        stdio proxy for the in-GUI plugin (a third surface)
  idalib_supervisor.py     1537 lines   the process an agent actually talks to (entry point `idalib-mcp`)
  idalib_server.py          348         the per-binary worker (entry point `python -m ida_pro_mcp.idalib_server`)
  idalib_session_manager.py  ~200        in-worker multi-session bookkeeping
  worker_lifecycle.py       ~160        idle-TTL self-shutdown watchdog
  ida_mcp/
    zeromcp/mcp.py         1408         MCP protocol, HTTP transport, schema generation
    zeromcp/jsonrpc.py      387         JSON-RPC dispatch, validation, error mapping
    rpc.py                 ~190         tool/unsafe/resource decorators + the output-size patch
    sync.py                354          @idasync: single-IDA-thread funnel, timeouts, cancellation
    profile.py               53          --profile whitelist parsing/filtering
    http.py                 456          /config.html, POST /config, /profile.txt, /output/<id>.json
    discovery.py            265          instance registry + GUI process launch
    trace.py                334          always-on call log written into the IDB netnode
    framework.py            731          in-IDA test framework (not the tool framework)
    api_core.py            1145   12 tools    utils.py            1414
    api_analysis.py        2475   14 tools    compat.py            350
    api_modify.py          1319   11 tools    trace_dump.py         ~60
    api_types.py           1145    9 tools
    api_debug.py           1003   22 tools  (all @unsafe, all ext "dbg")
    api_composite.py        657    4 tools    api_survey.py        444   1 tool
    api_memory.py           340    6 tools    api_stack.py         183   3 tools
    api_python.py           279    2 tools  (both @unsafe)
    api_sigmaker.py         347    4 tools  (+ _sigmaker.py 1662, the SigMaker library)
    api_resources.py        292   11 resources (ida://idb/*, ida://cursor, ida://struct/{name}, …)
  installer.py / _data / _tui  ~46k      installer + MCP client config generation
```

---

## 1. Tool declaration, registration, and schema generation

### 1.1 Registration is a decorator side-effect into a dict

There is no explicit tool table anywhere. A tool is a Python function with decorators; importing
the module *is* the registration.

- `rpc.py:146-156` — the three decorators, all three lines of "registry":
  ```python
  def tool(func):        return MCP_SERVER.tool(func)          # rpc.py:146-147
  def unsafe(func):      MCP_UNSAFE.add(func.__name__); return func   # rpc.py:154-156
  def ext(group):        ...MCP_EXTENSIONS.setdefault(group,set()).add(func.__name__)  # rpc.py:159-172
  ```
- `zeromcp/mcp.py:825-826` — `McpServer.tool` is a one-liner over `self.tools.method(func)`.
- `zeromcp/jsonrpc.py:113-115` — `JsonRpcRegistry.method` is `self.methods[name or func.__name__] = func`.

Consequence that matters to us: **the registry is a mutable dict reachable by name.** Gating is
therefore "delete keys from a dict", and *any* code holding a reference to the original dict can
put them back. Section 2.3 shows that happening over HTTP.

The `@unsafe` set is a plain `set[str]` of function names (`rpc.py:12`), decoupled from the
registry — which is exactly why the two can drift (they do, below).

### 1.2 Schema generation: type hints are the schema

`zeromcp/mcp.py:1352-1408` builds every tool's `inputSchema`/`outputSchema` from
`typing.get_type_hints(func, include_extras=True)` plus `inspect.signature`:

| Feature | Mechanism | Line |
|---|---|---|
| per-parameter type | `_type_to_json_schema` over the hint | `mcp.py:1362-1363` |
| `required` | parameter has no default | `mcp.py:1366-1368` |
| `default` | only if `json.dumps(default)` succeeds | `mcp.py:1370-1375` |
| per-parameter prose | `Annotated[T, "description"]` | `mcp.py:1291-1296` |
| optional keys | `NotRequired[T]` + TypedDict `__required_keys__` | `mcp.py:1299-1300`, `1337-1350` |
| unions | `{"anyOf": [...]}` | `mcp.py:1303-1304` |
| closed objects | `additionalProperties: false` on every TypedDict | `mcp.py:1349` |
| description | the **docstring**, verbatim | `mcp.py:1379` |
| output schema | return hint; non-object returns wrapped as `{"result": <schema>}` | `mcp.py:1388-1406` |

Two consequences our registry should copy:

1. **The docstring *is* the agent-facing contract.** `mcp.py:1379` ships whatever prose the author
   wrote, unedited, into `tools/list`. The project polices this with a test —
   `tests/test_tool_metadata.py:17` caps docstrings at `MAX_DOCSTRING_WORDS = 120` and
   `:75` fails any docstring mentioning `py_eval`. That is a *description budget* enforced in CI.
2. **`outputSchema` exists at all** — measured live: all 66 advertised tools carry one. An agent
   therefore has a machine-checkable return shape, not just prose. Every list-returning tool's
   schema root is `{"type":"object","properties":{"result":{...array...}},"required":["result"]}`,
   and the live response honours it (`structuredContent` is always `{"result": [...]}`).

### 1.3 The declared surface, measured

| Layer | Count | How |
|---|---|---|
| `@tool` functions in `ida_mcp/api_*.py` | **88** | AST walk of the installed tree |
| in `@unsafe` | **25** | AST walk + `MCP_UNSAFE` |
| in extension group `dbg` | **22** | `MCP_EXTENSIONS` (a strict subset of unsafe) |
| tools advertised by the **supervisor** (`idalib-mcp`, the agent-facing endpoint) | **66** | live `tools/list` |
| tools advertised by a bare **worker** (`-m ida_pro_mcp.idalib_server`) | **65** | live `tools/list` |

88 − 25 = 63, plus the supervisor's own `idb_open`/`idb_list`/`idb_close` = **66**. The bare
worker shows 65 because it carries only `idb_open`/`idb_list` (`idalib_server.py:57-60`).

Of the 66 advertised: **29 take an array and operate per element** (one round trip, N lookups),
**36 are single-shot**. That is a 45/55 split — see §4.1.

---

## 2. The batching contract

This is the part worth stealing, and the part with the sharpest edges.

### 2.1 The contract in five lines

1. A batch parameter is declared `list[X] | X` — a single object is always accepted
   (`api_analysis.py:1045-1048`, `api_memory.py:132-135`).
2. It is normalised to a list of dicts by `utils.normalize_dict_list`
   (`utils.py:673-728`), or by a hand-rolled `if isinstance(queries, dict): queries = [queries]`
   (`api_memory.py:138-139`, `api_analysis.py:1418-1419`, `api_types.py:343`).
3. The tool loops, and **each element gets its own result object carrying its own `error`
   field** — the loop never aborts on a bad element (`api_analysis.py:1054-1223`).
4. The envelope's `isError` stays **false** when every element merely failed
   (`zeromcp/mcp.py:1076`).
5. Above **50,000 serialized characters** the whole response is replaced by a 10-item preview plus
   a download URL (`rpc.py:20,45,94-134`).

### 2.2 What the results look like (measured)

`analyze_batch` with five queries — one valid, one unmapped address, one empty dict, one bare
string, one bad name — returned **four** items:

```
isError: False
structuredContent keys: ['result']            # the {"result": …} wrapper, mcp.py:1075
 [0] target='main'              addr='0x140001420'  error=None
 [1] target='0xDEADBEEFDEADBEEF' addr=None          error='Not a function: 0xDEADBEEFDEADBEEF'
 [2] target=''                   addr=None          error='addr is required'
 [3] target='nosuchfunc'         addr=None          error='Failed to resolve function: nosuchfunc'
```

The fourth input, the bare string `"0x140001000"`, **vanished**. Cause,
`utils.py:704-706`:

```python
else:
    # Mixed types - filter dicts only
    return [item for item in value if isinstance(item, dict)] or [{}]
```

There is **no index, no echo, no `dropped` counter**. The result list is shorter than the request
list and nothing says so. A client that maps results to inputs positionally misattributes every
subsequent answer. Two more silent-shape behaviours from the same function:

- `normalize_dict_list([])` → `[{}]` (`utils.py:694-695`), so an **empty batch returns one bogus
  item** with `error: "addr is required"` rather than an empty list. Measured.
- `normalize_dict_list("a,b")` splits on commas (`utils.py:718-725`), but the JSON-RPC validator
  rejects the bare string first: measured `analyze_batch {"queries":"main"}` →
  `isError: true, "Invalid params: expected list[AnalyzeBatchQuery] | AnalyzeBatchQuery for
  queries, got str"`. **The documented string path is unreachable over MCP.**

### 2.3 Three incompatible normalisation regimes in one server

| Regime | Tools | Bad input → |
|---|---|---|
| `normalize_dict_list` | `analyze_batch`, `func_query`, `entity_query`, `list_funcs`, `type_query`, `enum_upsert`, `set_comments`, `rename`, … | silently dropped elements |
| hand-rolled `isinstance(x, dict)` | `get_int` (`api_memory.py:138-139`), `put_int` (`:301-302`), `patch` (`:268-269`), `xrefs_to_field` (`api_analysis.py:1418-1419`) | **whole tool explodes** |
| jsonrpc type validation (`jsonrpc.py:245-371`) | everything, before the tool runs | `-32602 Invalid params` |

Measured: `get_int {"queries":["0x140001420"]}` → `isError: true`, and the text is a **full Python
traceback with installation paths** (`jsonrpc.py:190-199` → `map_exception` returns
`"\n".join(traceback.format_exception(e)) + "\n\nPlease report a bug!"`). A `list[str]` is
schema-invalid, but the validator's "try JSON-parsing str for object types" hack
(`jsonrpc.py:289-293`) let it through to crash the tool. That traceback is not behind `--unsafe`
and not behind `--profile`.

### 2.4 The response cap — the real batch limit

There is **no cap on N in a request**. The limit is on the response:

- `rpc.py:20` `OUTPUT_LIMIT_MAX_CHARS = 50000`; `rpc.py:45` `OUTPUT_LIMIT_PREVIEW_ITEMS = 10`.
- `rpc.py:94-134` patches `tools/call`: if the serialized response exceeds the cap, the result is
  replaced by a 10-item preview (`_truncate_value`, depth ≤ 5, strings cut at 1,000 chars —
  `rpc.py:49-69`) plus `_meta.ida_mcp` metadata.
- The full payload is kept in a **process-local dict of 100 entries** (`rpc.py:21-22, 87-91`) and
  served over `GET /output/<uuid>.json` (`http.py:137-141, 162-190`).

Measured, 6,000-entry `get_int`:

```
isError=False   _meta.ida_mcp = {output_truncated: true, total_chars: 417213,
  output_id: 70a7590f-…, download_url: "http://127.0.0.1:8792/output/70a7590f-….json",
  download_hint: "Output truncated. Run: curl -o .ida-mcp/70a7590f-….json http://…"}
structuredContent = {result: [ …10 items… ]}
```

A 2,000-entry `get_int` returned **10** items with no error and no visible count of what was lost
— the truncation flag lives in `_meta`, which a client that only reads `structuredContent` never
sees. `rpc.py:57-60` even documents *why* no sentinel is injected into lists ("many tool schemas
constrain list item shapes … sentinels can break structured output validation") — a defensible
choice that makes the loss quieter, not louder.

### 2.5 The one genuinely excellent thing here

`rename` returns aggregate counters (`api_modify.py:403`, live):

```json
{"func":[{"addr":"main","old":"main","name":"main_probe_renamed"}],
 "summary":{"total":1,"ok":1,"failed":0,"stopped":false}}
```

`ok`/`failed`/`stopped` at the batch level is exactly what `analyze_batch` lacks. Copy this;
do not copy the rest.

---

## 3. Sessions, workers, and concurrency

### 3.1 Two processes, two registries

- **`idalib-mcp` (supervisor, `idalib_supervisor.py:1468-1537`)** — the agent's endpoint. Exposes
  `idb_open` / `idb_list` / `idb_close` locally (`:1281-1349`) plus `ida://databases`
  (`:1352-1357`), and **proxies everything else to a worker** (`:1367-1411`).
- **Worker (`python -m ida_pro_mcp.idalib_server`)** — one process, one IDA main thread, one or
  more open sessions (`idalib_session_manager.py`), hosting the 65 real analysis tools.

The proxy injects a mandatory `database` argument into *every* forwarded tool schema
(`idalib_supervisor.py:1225-1234`, added to `required`) and strips it before forwarding
(`:1376-1379`). Measured: `idb_save`'s schema as advertised by the supervisor is
`{"required":["database"], …}` while the worker's own copy has no such key. This is a genuinely
good pattern — **the session handle is part of the type, not a convention**, so a client cannot
forget it.

### 3.2 Opening, listing, closing

- `idb_open(input_path, mode, run_auto_analysis, build_caches, init_hexrays, idle_ttl_sec,
  preferred_session_id)` — `idalib_supervisor.py:1281-1321`.
- `mode ∈ {prefer_headless, force_headless, prefer_gui, force_gui}` (`:1284-1290`).
- `idb_list` merges **adopted** sessions with **discovered** instances (`:1156-1204`).
- `idb_close(database, save=True)` — saves, unregisters, and terminates *owned* workers only;
  adopted instances are detached, not killed (`:1103-1141`, `:314-316`).

### 3.3 What `is_analyzing`, `busy`, `adopted` mean

| Field | Meaning | Line |
|---|---|---|
| `is_analyzing` | A **snapshot** copied from the worker's own `idb_list` at open time. Measured: `idb_open(..., run_auto_analysis: true)` returned `is_analyzing: false` while auto-analysis had, in fact, completed. It is a poll-time reading, never a promise. | `:919`, `:1012`, `:1194` |
| `busy` | Health probe says *alive but not answering* → mid tool call. Only `dead` justifies reaping. | `:601-685` |
| `adopted` | The session points at a worker/GUI this supervisor did **not** spawn (`owned: false`): it found the instance through the discovery files. | `:749-775`, `:1199` |
| `owned` | This supervisor spawned the process and may terminate it. | `:288`, `:315` |

Health is deliberately two-stage: `process_alive` → `tcp_connect` → JSON-RPC `ping`, each with its
own timeout (`:628-685`), because an adopted worker has no `Popen` handle (`:633-634`). A busy
worker is **not** an error: `resolve_session` forwards anyway (`:1060-1068`), and a
`socket.timeout` on the call becomes `isError: true` with `{"error": "…still busy…", "busy": true}`
(`:1394-1409`). That is a good contract: *busy is a distinct, non-destructive outcome.*

### 3.4 Concurrency: process-level only

- HTTP is threaded (`idalib_supervisor.py:1528-1530`: *"a call to one busy worker must not block
  requests aimed at a different, idle one"*), but **every tool body is serialised on IDA's single
  main thread**: `sync.py:76` `call_stack = queue.LifoQueue()`, `sync.py:157`
  `idaapi.execute_sync(runned, idaapi.MFF_WRITE)`, LIFO. A reentrant `@idasync` gets
  `IDASyncError("Call stack is not empty while calling …")` (`sync.py:114-131`).
- Real parallelism = N worker *processes*: `--max-workers`, default `4`, env
  `IDA_MCP_MAX_WORKERS`, `0` = unlimited (`idalib_supervisor.py:1482-1487`); enforced in
  `_allocate_worker_locked` (`:413-430`) with the error
  *"Maximum idalib worker count reached (N). Wait for an existing worker to be released or
  increase --max-workers."*
- Per-tool timeout: `IDA_MCP_TOOL_TIMEOUT_SEC`, default **60 s** (`sync.py:42-43`), overridden by
  `@tool_timeout(120.0)` on the heavy tools (`api_analysis.py:1043`, `api_composite.py:277`).
  Enforced by `sys.setprofile` line tracing (`sync.py:220-246`) — a real cancellation mechanism.
- Idle TTL: worker self-exits after `idle_ttl_sec` (default 600, min 10, poll 5)
  (`worker_lifecycle.py:23-25`); every dispatch bumps the watchdog
  (`idalib_server.py:175-185`).
- `tools/list` will **spawn a worker just to answer the schema question** (`_schema_or_idle_worker`,
  `:384-392`) — measured, this is the first thing that happens on a cold supervisor.

### 3.5 Two session-management defects observed live

1. **Cross-supervisor adoption.** Sessions are found through shared instance files under
   `%APPDATA%\Hex-Rays\IDA Pro\mcp\instances\` (`discovery.py:46-51`, written atomically at
   `:54-82`). Measured: my supervisor's `idb_open` on `c01-stringobf.exe` logged
   *"Adopted persistent worker 127.0.0.1:52872"* — a worker belonging to a **different** idalib-mcp
   process on the same box, which I neither spawned nor own.
2. **Session loss under contention.** The very next call against that adopted session returned
   `{"error":"Session not found: 65c893e2"}` with `isError: true`. Whatever removed it, the
   observable is: *a session that `idb_open` just returned can be gone on the next call, with no
   event.* Any mission runner must treat a session id as a cache, re-derivable via `idb_list`,
   never as a handle.

---

## 4. Part 2 — the findings that matter to us

### 4.1 Its design doctrine: fewer, fatter tools — and yes, it is token-economy-driven

The evidence for intent is structural, not a comment:

- **29 of 66 tools are arrays.** `analyze_batch` exists *specifically* so an agent can decompile N
  functions in one round trip; it is literally the fat version of `decompile` (`api_analysis.py:1044`
  vs `:756`). `entity_query` is one tool replacing five (`api_core.py:716`, `kind ∈ {functions,
  globals, imports, strings, names}` at `:728`). `xref_query` replaces direction/type filtering you
  would otherwise do client-side (`api_analysis.py:1290`).
- **Pagination is in the schema, not the prose**: `offset`/`count`/`next_offset` on every list tool
  (`utils.py:585-587` `Page` TypedDict), with a `next_offset` cursor so the agent never has to
  re-derive a page.
- **Docstrings are budgeted in CI** (`tests/test_tool_metadata.py:17`, ≤ 120 words) — a direct
  admission that `tools/list` output is a token cost paid on every single request.
- **Per-tool result caps** rather than raw dumps: `_DECOMPILE_LINE_CAP = 100`
  (`api_composite.py:27`), `_MAX_TRACE_NODES = 200` / `_MAX_TRACE_EDGES = 500`
  (`api_composite.py:548-549`), `_MAX_FUNC_ITER = 10_000` (`api_survey.py:99`), and every count is
  clamped by `_clamp_int` (`api_analysis.py:1099-1108`) with a paired `*_truncated` flag.

Doctrine in one sentence: **one tool per question, N inputs per call, every result bounded and
flagged as bounded.** That is also our doctrine — but §2 shows it is executed with three
different input-normalisation routines and one silent-drop bug, which is precisely the failure a
*program* (our registry) prevents and a *convention* (a docstring) does not.

### 4.2 Its safety story — a speed bump, not a boundary

There are three layers. Measured each.

**Layer 1 — `--unsafe`.** 25 tools are tagged; without the flag they are deleted from the registry
(`idalib_server.py:285-289`, `idalib_supervisor.py:1496-1497` forwards the flag to workers).

**The complete unsafe list** (AST walk; `@unsafe` at `api_python.py:115,224`,
`api_composite.py:450`, and 22× in `api_debug.py`):

| # | Tool | Line | Why it is dangerous |
|---|---|---|---|
| 1 | `py_eval` | `api_python.py:116` | `exec()` of arbitrary code in the IDA process (`api_python.py:157,176,189`); **globals persist across calls** (`:118-121`) |
| 2 | `py_exec_file` | `api_python.py:225` | `open(file_path)` + `exec()` of any local file (`:251-254`) |
| 3 | `diff_before_after` | `api_composite.py:453` | rename / set type / set comment — mutates the IDB |
| 4–25 | `dbg_start`, `dbg_status`, `dbg_exit`, `dbg_continue`, `dbg_run_to`, `dbg_step_into`, `dbg_step_over`, `dbg_bps`, `dbg_add_bp`, `dbg_delete_bp`, `dbg_toggle_bp`, `dbg_set_bp_condition`, `dbg_regs_all`, `dbg_regs_remote`, `dbg_regs`, `dbg_gpregs_remote`, `dbg_gpregs`, `dbg_regs_named_remote`, `dbg_regs_named`, `dbg_stacktrace`, `dbg_read`, `dbg_write` | `api_debug.py:373,457,466,478,492,509,523,542,551,581,605,638,741,755,785,796,826,837,857,878,930,976` | drive the debuggee's execution |

**And what is *not* in that list, while being strictly more dangerous to a static-analysis
mission**: `idb_save` (arbitrary-path file write, `api_core.py:861-890`), `patch` /
`put_int` (write into the database, `api_memory.py:266,294`), `rename`, `patch_asm`,
`declare_type`, `type_apply_batch`, `enum_upsert`, `make_data`, `define_func`, `undefine`,
`set_comments`, `append_comments` (all `api_modify.py` / `api_types.py`), and `idb_open` (opens
any path on the machine). Measured live with `--unsafe` **off**: `rename` renamed `main` →
`main_probe_renamed` and returned `ok: 1`; `set_comments` wrote a comment; `patch` wrote `0x9090`
at `0x140001420`; `idb_save` wrote a **2,711,619-byte `.i64` to an arbitrary path**.

So the unsafe/safe line is drawn at *"this executes code or drives the debuggee"*, **not** at
*"this changes state"*. For a mission runner that means `--unsafe` off buys you nothing against a
misbehaving agent.

**Layer 2 — `--profile PATH`.** One tool name per line, `#` comments
(`profile.py:11-23`); `apply_profile` keeps `whitelist | protected` and drops everything else
(`profile.py:36-53`), reporting `(kept, unknown)` so a typo is visible in the log
(`idalib_server.py:291-309`). Ordering is correct — unsafe removal happens *first*
(`:285-289`), so a profile cannot resurrect an unsafe tool **at startup**. Two holes:

- `IDB_MANAGEMENT_TOOLS = {"idb_open", "idb_list"}` is `protected` (`idalib_server.py:57-60`,
  passed at `:299`) — **a profile cannot remove them.** `idb_open` takes an arbitrary
  `input_path` (`:99-112`), so a "read-only" profile still hands the agent a file-open primitive
  and an auto-analysis launcher.
- The **supervisor never applies `--profile` to its own registry.** It only forwards the flag to
  workers (`idalib_supervisor.py:1498-1499`); there is no `apply_profile` call anywhere in that
  file. So at the layer the agent actually talks to, `idb_open` / `idb_list` / `idb_close` are
  unconditionally exposed no matter what the profile says.
- No profile files ship in the wheel (`tests/test_profile.py:152-156` references
  `profiles/readonly.txt` / `profiles/triage.txt` at the *repo* root — absent from site-packages).

**Layer 3 — `?ext=dbg`.** The debugger group is gated per request, not per process: tools/list
skips disabled groups (`mcp.py:1022-1029`) and `tools/call` refuses them
(`mcp.py:1043-1048`). Measured: `?ext=dbg` on the query string admits `dbg_start`; without it the
call returns `isError: true, "Tool 'dbg_status' requires extension 'dbg'"`. **This is the only
layer that held under every test I ran.**

**Verdict.** Layer 3 is a real gate (checked at call time, from the request, not from mutable
process state). Layers 1 and 2 are startup-time mutations of a dict, and layer 1 is
**demonstrably reversible**: measured on a worker started *without* `--unsafe` —

```
BEFORE  count=65  py_eval present: False
POST /config  (form: apply_profile=1, profile_text="py_eval\ndbg_start")   → 200
AFTER   count=1   py_eval present: True
tools/call py_eval {"code":"1+1"}  →  {"result":"2","stdout":"","stderr":""}   isError: false
```

The mechanism is `http.py:414-447`: `self.mcp_server.tools.methods` is rebuilt from
`ORIGINAL_TOOLS`, a snapshot captured at **import time** (`http.py:93`) — i.e. *before*
`idalib_server.py:285-289` deleted the unsafe tools. So the snapshot still holds `py_eval`. The
request carries **no authentication token**, and `_check_api_request` accepts any request without
an `Origin` header (`mcp.py:303-328`), so any local process or `curl` can do this. It is also
**persisted into the IDB** as netnode `$ ida_mcp.enabled_tools` (`http.py:26-49, 447`), so the
policy travels inside the sample's `.i64` file and is re-applied on the next open
(`http.py:51-74`).

**As a gate: no.** `--unsafe` and `--profile` are speed bumps — advisory defaults that any local
process can rewrite at runtime. The lesson for us is the inverse of the obvious one: *do not
delegate our authorization decision to the tool server's own flags.* The gate must be a program
outside the process being gated, and the tool server's flags are inputs to that program, never the
program.

### 4.3 What to port, what to refuse

**Port (5 patterns).**

1. **Schema derived from one declaration.** Type hints + docstring → `inputSchema` + `outputSchema`
   (`mcp.py:1352-1408`). One source, no drift. Our registry entry *is* the declaration; add
   `outputSchema` semantics — the shape a downstream capability is allowed to consume.
2. **Batch = array-or-single, one round trip, per-element result objects with their own `error`.**
   Adopt the *shape* (`api_analysis.py:1054-1223`), and adopt `rename`'s `summary`
   (`{total, ok, failed, stopped}`) as the **mandatory** aggregate — the one thing the upstream
   batch tools got wrong.
3. **Cursor pagination in the contract** (`Page{data, next_offset}`, `utils.py:585-587`) plus a
   paired `*_truncated` / `*_count` flag on every bounded list (`api_analysis.py:1116-1131`).
   Bounded output that *says* it is bounded.
4. **Session handle in the type.** `database` injected into `required` on every forwarded schema
   (`idalib_supervisor.py:1225-1234`). A capability cannot be invoked without naming its object.
5. **`busy` as a first-class, non-destructive outcome** (`:1394-1409`; health model `:601-685`),
   and **busy ≠ dead** — only `dead` reaps.

**Refuse (5 things).**

1. **Name-based unsafe tagging.** `@unsafe` is a `set[str]` decided by a decorator's position in a
   stack (`rpc.py:154-156`), and it missed `idb_save`, `patch`, `rename` — arbitrary file write and
   IDB mutation shipped as *safe*. Refuse: authority must be declared as **reach**
   (`fs.write:<glob>`, `net.connect`, `proc.spawn`, `dbg.exec`) and enforced by the gate. A tag on
   a decorator cannot be audited by a program; a declared reach can.
2. **`protected` names that survive the profile** (`idalib_server.py:57-60`). Refuse: our gate has
   no exemption list. `idb_open`'s arbitrary path is the reason.
3. **Startup-time mutable filtering.** `tools.methods` is a dict any code can rewrite, and was
   (`http.py:442-446`). Refuse: the gate decides *before* the process starts and re-checks *per
   invocation*; the child process gets no write access to the decision.
4. **Cross-process instance discovery as session identity** (`discovery.py:46-82`, measured
   cross-supervisor adoption, §3.5). Refuse: our registry binds a capability to a case-scoped
   artifact handle, never to a machine-global registry file.
5. **Environment-injected policy.** `IDA_MCP_*` env vars set timeouts, logging, CORS, the analysis
   prompt (`sync.py:42`, `jsonrpc.py:71`, `http.py:80-91`, `utils.py:37-42`). Refuse: policy that
   can be flipped by whoever launches the process is configuration, not control.

### 4.4 Where it leaks authority

Every place a tool can leave the target binary or the loopback host. This is the list our gate has
to be able to answer for.

| # | Capability | Reach | Evidence | Gated by `--unsafe`? |
|---|---|---|---|---|
| **A1** | `idb_open` | **opens any path on the machine**, runs auto-analysis, writes loose IDB files next to it; `mode=force_gui` **launches an IDA GUI process** | `idalib_server.py:99-160`; `idalib_supervisor.py:1281-1321`; `discovery.py:229-234` (`subprocess.Popen`, `DETACHED_PROCESS`) | no — and `protected` from `--profile` |
| **A2** | `idb_save(path)` | **writes a file to any caller-chosen path** (measured: 2.7 MB `.i64` written to an arbitrary directory) | `api_core.py:861-890` | no |
| **A3** | `py_exec_file` | reads + `exec()`s any local file | `api_python.py:225-254` | yes |
| **A4** | `py_eval` | arbitrary code; **persistent globals across calls** | `api_python.py:114-196` | yes (reversible, §4.2) |
| **A5** | `patch`, `put_int` | writes bytes into the database at any mapped address (measured OK) | `api_memory.py:266-340` | no |
| **A6** | `define_func`, `define_code`, `undefine`, `make_data`, `force_recompile` | mutates the IDB (code/data definitions, forces recompilation) | `api_modify.py:907,959,991,1243,1056` | no |
| **A7** | `rename`, `set_comments`, `append_comments`, `add_bookmark`, `set_op_type`, `patch_asm`, `declare_type`, `enum_upsert`, `type_apply_batch`, `set_type`, `infer_types`, `declare_stack`, `delete_stack` | mutates the IDB and the type library | `api_modify.py:116,164,244,403,1144`; `api_types.py:160,187,1029,1037,1069`; `api_stack.py:66,111` | no |
| **A8** | `POST /config` | **rewrites the live tool registry**, re-enables unsafe tools, persists the policy into the IDB netnode | `http.py:110-117, 414-447, 51-93` | **no — no auth** |
| **A9** | `GET /output/<uuid>.json` | serves any recent full tool payload to any caller that can reach the port; 100-entry in-memory cache | `rpc.py:83-91`; `http.py:137-141, 162-190` | no |
| **A10** | `X-IDA-MCP-External-Base` / `X-Forwarded-*` | **rewrites the `download_url` and the copy-paste `curl` hint** the agent is told to run. Measured: sending the header on a tool call produced `download_url: http://attacker.invalid:9999/output/….json` | `mcp.py:21, 132-137, 203-234`; `rpc.py:72-80` | no |
| **A11** | `dbg_start` / `dbg_read` / `dbg_write` / `dbg_continue` … | **executes the target on this machine** — the single largest reach in the server | `api_debug.py:373,930,976,…` | yes (and `?ext=dbg`) |
| **A12** | instance discovery + `force_gui` | writes/removes files under `%APPDATA%\Hex-Rays\IDA Pro\mcp\instances\`, deletes entries it judges corrupt/stale, spawns processes | `discovery.py:54-92, 138-175, 229-234` | no |
| **A13** | trace recorder | **always on**; appends every `tools/call` (arguments verbatim, including `@unsafe` payloads — asserted by `tests/test_trace.py:155-159`) into the IDB netnode `$ ida_mcp.trace` | `trace.py:1-13, 26`; `ida_mcp/__init__.py:48-49` | n/a — not optional |
| **A14** | exception mapping | returns **full Python tracebacks with installation paths** to any caller | `jsonrpc.py:190-199` | no |
| **A15** | `handle_large_output` | spills oversized results to `tempfile.mkstemp` | `utils.py:1378-1414` | no |

Three of these deserve naming as findings rather than rows:

- **A1 + A2 together mean the "safe" profile still grants arbitrary file read-through-IDA and
  arbitrary file write.** Neither is tagged.
- **A8 + A10 chain.** Even if our runner refuses to call `py_eval`, an attacker who can reach the
  port can *enable* it (A8) and then *steal* the oversized payload by pointing the download URL at
  a host they control (A10). Neither requires our cooperation.
- **A13 is a feature, not a bug, and it is worth stealing**: every call is recorded with its
  arguments, duration, `isError`, `structuredContent` and truncation metadata
  (`trace.py:296-320`). Our mission trace should be at least this
  faithful. Note it also means the IDB is no longer a pristine artifact — an `.i64` that has been
  opened by this server carries analysis state, tool-call history, and the tool policy.

---

## 5. Part 3 — specification: the IDA capability registry entry

Additive to `orchestration-design.md` §3.2. Field names already chosen there
(`requires.tools[].probe/expect`, `probe`, `negative_control{id,command,expect_exit,why}`,
`gate`, `state`, `proves`, `does_not_prove`) are kept verbatim. Four fields are added, each
forced by a specific finding above.

### 5.1 Added fields, and the finding that forces each

```jsonc
"reach": {
  // Forced by A1/A2/A5–A7: authority is declared as effect, not as a tag.
  // The gate computes allow/deny from THIS BLOCK ONLY. Tool-server flags
  // (--unsafe, --profile) are inputs to `requires`, never the authorization.
  "fs_read":  ["<case>/obj/<sha256>.exe", "<case>/obj/<sha256>.exe.i64"],
  "fs_write": ["<case>/obj/", "<case>/dynamic/"],
  "net":      "loopback-only",          // none | loopback-only | loopback:<port> | any
  "proc_spawn": ["ida_pro_mcp.idalib_server"],   // named argv[0]; no shell
  "exec_target": false,                  // true ONLY for dbg_* / anything that runs the sample
  "db_write":  "ida-only"                // none | ida-only   (patch/rename/type edits)
},
"envelope": {
  // Forced by §2.2/§2.3/§4.2: isError is not a verdict. The runner MUST parse this,
  // and MUST treat "envelope_ok && item.errors != {}" as FAILURE.
  "success_when": "envelope_ok AND every item has error == null AND summary.failed == 0",
  "item_error_field": "error",           // per-element failure lives HERE
  "batch": { "accepts": "array|single", "echo_field": "target",
             "max_items": 64, "aggregate": "summary{total,ok,failed,stopped}" },
  "response_cap_chars": 48000,           // < 50000: stay under the server's own truncation
  "on_cap": "refuse and re-page"         // never accept a silent 10-item preview
},
"session": {
  // Forced by §3.5: session ids evaporate. Bind to a content hash, re-derive each round.
  "bind": "sha256(object)", "rederive": "each_round", "on_missing": "idb_open"
},
"gate_must_not_delegate": [
  // Forced by §4.2 (measured POST /config re-enabling py_eval).
  "server:--unsafe", "server:--profile", "http:POST /config", "idb:py_eval", "idb:py_exec_file"
]
```

`registry-verify.py` gains three failure rules to match:

7. any entry whose `reach.fs_write` is not under `<case>/` **and** whose `gate.escalation_class` is
   not `owner_word` → non-zero;
8. any entry with `exec_target: true` and `state: "observed"` and no `negative_control` proving
   the target *did not* run → non-zero;
9. any entry naming a tool listed in `gate_must_not_delegate` → non-zero.

### 5.2 The three worked entries

#### `native.decompile.ida` — read-only, the workhorse

```jsonc
{
  "id": "native.decompile.ida",
  "version": 1,
  "title": "IDA Pro 9.2 (idalib, headless) decompile + xref + string extraction, batched",
  "domains": ["D3", "D10"], "question_types": ["Q2.locate", "Q3.behaviour"],

  "consumes": {
    "inputs": [
      { "name": "binary", "type": "file:pe|elf", "required": true,
        "note": "read-only copy at <case>/obj/<sha256>.exe; never the original" },
      { "name": "addrs", "type": "array<string>", "required": true,
        "from": { "capability": "native.triage.die", "field": "functions[].va" } }
    ],
    "context": ["mission.question.type", "gate.verdict"]
  },
  "produces": {
    "facts": [{ "key": "functions[]", "type": "ida.function",
      "fields": { "va": "uint64", "name": "string", "pseudocode": "string",
                  "callers": "array", "callees": "array", "strings": "array" } }],
    "artifacts": [],
    "invalidates_on": ["binary.sha256 != mission.object.sha256",
                       "ida.version != requires.tools[0].expect_version"]
  },

  "requires": {
    "runtime": "local", "net": "loopback:8792", "admin": false, "device": false,
    "disk_mb": 300, "ram_mb": 2048, "wall_minutes": 5,
    "tools": [
      { "name": "idalib-mcp", "probe": "idalib-mcp --host 127.0.0.1 --port <p> (no --unsafe)",
        "expect": "POST /mcp tools/list → 66 tools; py_eval and dbg_start absent" },
      { "name": "idapro", "probe": "python -c \"import idapro;print(idapro.__version__)\"",
        "expect": "0.0.10" },
      { "name": "hexrays", "probe": "tools/call server_health",
        "expect": "hexrays_ready == true && auto_analysis_ready == true" }
    ]
  },

  "proves": ["the pseudocode Hex-Rays derives for the exact bytes in <sha256>",
             "static call edges and string references at those addresses"],
  "does_not_prove": ["anything about runtime behaviour — no instruction executes",
                     "behaviour under inputs the batch did not exercise",
                     "correctness of Hex-Rays' reconstruction"],
  "falsifies": ["H?: the check is not in this function"],

  "side_effects": ["writes <case>/obj/<sha256>.exe.i64 next to the copy",
                   "appends every call to the IDB netnode $ ida_mcp.trace",
                   "loopback port bound on 127.0.0.1"],
  "gate": { "lane": "analysis", "requires_verdict": "ALLOW_LOCAL",
            "escalation_class": "owner_word" },

  "reach": { "fs_read": ["<case>/obj/"], "fs_write": ["<case>/obj/"],
             "net": "loopback:8792", "proc_spawn": ["idalib-mcp"],
             "exec_target": false, "db_write": "none" },
  "envelope": { "success_when": "isError==false AND items[].error==null AND count==len(addrs)",
                "item_error_field": "error",
                "batch": { "accepts": "array|single", "echo_field": "target",
                           "max_items": 64, "aggregate": "summary{total,ok,failed,stopped}" },
                "response_cap_chars": 48000, "on_cap": "refuse and re-page" },
  "session": { "bind": "sha256(object)", "rederive": "each_round", "on_missing": "idb_open" },
  "gate_must_not_delegate": ["server:--unsafe", "server:--profile", "http:POST /config"],

  "state": "observed",
  "probe": { "command": "node tools/capability-probe.mjs native.decompile.ida",
             "expect": "probe: OK ida=9.2 idapro=0.0.10 tools=66 unsafe_absent=3 hexrays=true",
             "exit": 0 },
  "negative_control": { "id": "unmapped-va", "command": "… --addr 0xDEADBEEFDEADBEEF",
                        "expect_exit": 3,
                        "why": "measured: the item returns error='Not a function: 0xDEADBEEFDEADBEEF' with isError=FALSE. A runner that trusts isError alone files a confident empty decompilation. Exit 3 = 'envelope ok but item failed'." },
  "provenance": { "source": "D:\\Software\\Developer\\Python314\\Lib\\site-packages\\ida_pro_mcp\\",
                  "record": ".agent/research/ida-mcp-source-study.md" }
}
```

#### `native.annotate.ida` — mutating, and therefore a different gate class

Same reach block **except** `"db_write": "ida-only"` and `"fs_write": ["<case>/obj/", "<case>/dynamic/"]`.
`gate.escalation_class: "owner_word"`. It is a *different* gate class from `native.decompile.ida`
even though both run the same process — the discriminator is `reach.db_write`, not the tool name.

#### `native.debug.ida` — the one that runs the sample

`"exec_target": true`, `requires.net: "loopback-only"`, `requires.admin: false`, `disk_mb: 50`,
and `gate.escalation_class: "owner_word"` **plus** a mandatory `state` that is `"absent"` until
`dbg_start` has been observed working with `--unsafe` off *and* `?ext=dbg` explicitly enabled per
request (`zeromcp/mcp.py:1043-1048`) — the one gate layer that survived every test in this study.
It may not be reachable by any default profile.

### 5.3 The negative controls — mandatory, and the one that matters most

Every IDA entry carries **at least one control that must fail**, and the mission-level `selftest`
(N1–N4 in `orchestration-design.md` §6.2) gains three IDA-specific ones. All must fail loudly;
a pass is a harness failure.

| # | Control | Must happen | Forced by |
|---|---|---|---|
| **N5 envelope** | decompile `0xDEADBEEFDEADBEEF` through `native.decompile.ida` | runner exits **3**, artifact records the item error. Measured: the server says `isError: false`. | §2.2 |
| **N6 batch loss** | request 5 items where one is a bare string | runner exits **3** on `len(results) != len(requested)`. Measured: the server silently returned 4. | §2.2 |
| **N7 gate integrity** | with the mission's *read-only* grant, (a) call `py_eval`, (b) `POST /config {apply_profile, profile_text:"py_eval"}`, then (a) again | all three refused by **our** gate, exit 4, naming the grant. Measured: step (b) genuinely re-enables `py_eval` on a server started without `--unsafe`; the refusal must come from the gate, never from the server's own flag. | §4.2 |
| **N8 no-object** | point `idb_open` at `C:\Windows\System32\kernel32.dll` | gate refuses before any process spawns — the MCP server would happily open it (`idalib_server.py:99-112`) and it is `protected` from `--profile`. | §4.2, A1 |
| **N9 response cap** | ask for 6,000 `get_int` reads | runner refuses and re-pages; it must **not** accept the 10-item preview. Measured: `_meta.ida_mcp.output_truncated` with `total_chars: 417213`. | §2.4 |
| **N10 reach drift** | run the mission with `reach.net: "loopback-only"`, then have the runner discover a tool whose schema offers a `file_path` argument | `registry-verify.py` exits non-zero naming the tool. Measured: `py_exec_file` takes `file_path`; `idb_save` takes `path`. | §4.4 |

**Rule for the registry, stated once:** a probe that cannot fail is not a probe. So every entry's
`probe` must be paired with a `negative_control`, `registry-verify.py` rejects an entry whose
`negative_control.expect_exit` is 0 (rule 5 already exists), and `capability-probe.mjs` runs both
on every window — because a capability that passes on everything is exactly the
`state: "observed"`-but-rotten entry `orchestration-design.md` §3.4 already warns about.

---

## 6. Verdict, in one paragraph

`ida-pro-mcp` is a well-engineered **interface** and a weak **boundary**. Its fat-tool,
schema-from-types, cursor-paginated, per-result-flagged design is the shape our registry should
take, and its `outputSchema` + `database`-in-`required` tricks are worth copying verbatim. Its
safety model is three layers of which exactly one — the per-request `?ext=` extension gate — held
under adversarial testing; `--unsafe` was reversed by a single unauthenticated `POST /config`
while I had it running, and `--profile` cannot remove the two `idb_open`/`idb_list` tools that
grant arbitrary-path file access. Its most transferable defect is the batching contract: silent
element loss (`utils.py:704-706`), three incompatible input-normalisation regimes, no aggregate
verdict, and a 50k response cap that turns a 6,000-item request into a 10-item preview that still
reports `isError: false`. **Do not build the gate on that server's flags. Build it outside the
process, on a declared `reach`, and make the negative controls part of the acceptance run.**

---

### Reproduction of every live claim in this document

```powershell
# throwaway worker over a scratch copy — no repo artifact is touched
Copy-Item crackme-corpus\out\c02-cff-dispatch.exe $env:TEMP\re-research\ida-source-study\probe.exe
python -m ida_pro_mcp.idalib_server --host 127.0.0.1 --port 8792 $env:TEMP\re-research\ida-source-study\probe.exe
# then, against http://127.0.0.1:8792/mcp  (POST, Accept: application/json):
#   tools/list                                   → 65
#   tools/call analyze_batch {"queries":[dict,dict,{},str,dict]}  → 4 items, isError false
#   tools/call get_int {"queries":["0x140001420"]}               → isError true + traceback
#   tools/call get_int {"queries":[6000 items]}                   → 10 items, _meta.ida_mcp.output_truncated
#   tools/call idb_save {"path":"<anywhere>/x.i64"}               → ok:true, 2,711,619 bytes on disk
#   tools/call rename {"batch":{"func":[{"addr":"main","name":"main_probe_renamed"}]}} → ok:1
#   POST /config  apply_profile=1&profile_text=py_eval            → py_eval callable, returns 2
# GET /mcp                                                              → 405 (protocol, not a fault)
```

Ports 8791/8792 and their `%APPDATA%\Hex-Rays\IDA Pro\mcp\instances\` registrations were removed
after the run; the scratch copy and its `.i64` remain under `%LOCALAPPDATA%\Temp\re-research\`.
Port 13337 (the GUI plugin path `OWNER.md` reserves) was never touched.
