# Offline tool laboratory

These commands generate owned fixtures, call installed MCP providers, and retain actual requests, responses, semantic assertions, source identities, and process cleanup observations. A catalog is a capability declaration. It is never a successful tool call.

## Runtime and boundaries

Use Python 3.10 or newer. Actual Windows provider runs require `pywin32` in the **client interpreter**, an installed provider, and its original station wrapper. The client creates each child suspended, assigns its own non-breakaway Job Object, observes membership, and resumes the owned primary thread. A missing supervisor dependency fails closed. No command installs dependencies, changes global MCP configuration, adopts an existing GUI session, or accepts an existing output directory.

Provider dependencies belong in their own environments. This package does not redistribute third-party tools, commercial licenses, API keys, memory dumps, captured traffic, private session logs, or generated executables. Supply `--station` explicitly and choose a new output directory outside that tree for every run. The portable tests exercise accounting and lifecycle counterexamples; they do not claim real provider acceptance.

```powershell
python scripts/tool_lab/catalog.py --station C:/Owned/WorkStation --backends ida,frida --output C:/Owned/results/catalog-001
python scripts/tool_lab/run_ida.py --station C:/Owned/WorkStation --output C:/Owned/results/ida-001
python scripts/tool_lab/run_reqable.py --station C:/Owned/WorkStation --output C:/Owned/results/reqable-001
python scripts/tool_lab/run_frida.py --station C:/Owned/WorkStation --output C:/Owned/results/frida-001
python scripts/tool_lab/run_volatility.py --station C:/Owned/WorkStation --output C:/Owned/results/volatility-001
python scripts/tool_lab/run_dnspy_nop.py --station C:/Owned/WorkStation --output C:/Owned/results/nop-001
```

The selected catalog backends must first be reviewed for startup effects. In particular, service-backed providers may read credentials, initialize storage, download components, or connect to a running application. The catalog runner does not infer that those effects are authorized. Source-only providers and unavailable catalogs retain an unknown runtime denominator.

## Fixtures and independent facts

| Runner | Authored input and oracle | Scope left open |
|---|---|---|
| IDA | A generated PE with `mov eax,42; ret`, no imports, and a fixed string; exact bytes, integer, string, conversion, owned headless session and close | Other catalog methods, GUI adoption, debugger execution, decompiler quality |
| Reqable | Two local HAR entries, exact SQLite URLs, one closed WebSocket with three known frames, repair dry-run and write, missing/malformed imports | Actual packet capture, third-party traffic, generated code execution |
| Frida | A freshly compiled 60-second sleeper; exact retained-handle image identity, forwarded argument, known JS result and queue, target termination | USB devices, unrelated process enumeration, unknown binaries, persistent host instrumentation |
| Volatility | An explicitly invalid-for-forensics placeholder, plugin list and upstream description, missing-file error flag | Real RAM-image analysis, OS detection, symbol acquisition and YARA analysis |
| dnSpy NOP | A compiled but unexecuted DLL; remove a balanced `ldstr` plus `WriteLine(string)` pair, inspect resulting NOP/RET IL and unchanged source/backup | Branch targets, exception handlers, arbitrary invalid IL, runtime execution |

Frida and dnSpy fixture compilation uses the existing .NET Framework C# compiler by default; `--csc` selects another explicit installed compiler. IDA always requests `force_headless`, then checks the actual owned Job membership. Reqable requires its wrapper to preserve a caller-provided `REQABLE_DATA_DIR`; the runner refuses a wrapper that would overwrite this isolation setting. Its listener uses only an owned loopback port and is checked closed after cleanup.

`fixtures.py --output NEW` can generate the PE, HAR, and sleeper source alone. The HAR timestamp is explicit and can be changed with `--timestamp`. The generated fixture manifest records its exact expected content and hashes. A model answer is never an oracle.

## Results and coverage

Each execution writes `PLAN.json`, raw `session/requests.jsonl`, `session/responses.jsonl`, `session/stderr.txt`, `session/RESULTS.json`, and `FINAL.json` when the run reaches finalization. A failed or interrupted run can have only the earlier evidence. Preserve it. Exit `2` denotes a semantic, protocol, identity, or cleanup failure; ordinary Python exceptions also fail the command. A negative test requires both the specific expected error and MCP `isError: true`.

The aggregator verifies raw hashes and request/response correspondence, then recomputes assertion equality and protocol flags. Non-JSON-RPC stdout is retained and reported with line numbers and hashes; an affected session fails strict transport acceptance even if its individual answer values are correct. A failed case cannot be overwritten by a later successful case. Repeated runs remain explicit inputs; it never chooses a newer result on the caller's behalf.

Current `LabSession` records also drain queued stdout after the supervisor joins its reader, retaining shutdown lines that arrived after the final response. Legacy evidence without that observation is explicitly limited to its captured raw lines; replay cannot reconstruct an uncaptured tail. The shared supervisor is unchanged.

```powershell
python scripts/tool_lab/coverage.py --catalog C:/Owned/results/catalog-001/CATALOG.json --session C:/Owned/results/ida-001/session/RESULTS.json --session C:/Owned/results/frida-001/session/RESULTS.json --output C:/Owned/results/coverage-001
```

`--source` optionally accepts an explicit static manifest with `backends`, each containing `backend`, `tools` with names/signatures or schemas, and a prerequisite `reason`. Those rows remain source declarations. `safe_inputs` contains only arguments from accepted positive observations; a missing entry is not an instruction to guess a target. Coverage rows retain route distinctions such as original wrapper versus isolated candidate. A successful metadata method does not prove the provider's uncalled methods.

The three-provider offline acceptance runner and fixture builder supplied alongside this package have their own recorded scenario matrix. Do not merge a worker's reported totals or a different result format into this aggregator without a reviewed adapter.

## Regression tests and patches

```bash
python -m unittest discover -s tests -p test_tool_lab_core.py -v
```

The tests run on Linux or Windows without launching providers. The `patches` directory contains small Frida and Reqable changes with their upstream MIT notices and exact source context. Apply them only to a matching reviewed source version and the package actually loaded by its wrapper. Back up both and record their hashes before applying. The Volatility bridge's local exception change is described separately because its bridge license was not established; no third-party Volatility bridge module is redistributed here.
