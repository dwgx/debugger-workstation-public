# Reproduce the workstation tool labs

This source release provides an installable station skeleton, portable Skills,
authored fixtures, bounded MCP clients, explicit test oracles, reviewed provider
patches and pinned download recipes. Start with a selected provider and retain its
actual result. The tool inventory, method catalog, successful calls and whole
product acceptance are separate measurements.

Start with the [one-command, provider-free first success](FIRST-SUCCESS.md) before selecting a complex MCP backend. It runs an actual synthetic PCAP parser and verifies a six-check frozen plan without commercial tools or keys.

The [APKTool original-wrapper build and decode roundtrip](APK_ROUNDTRIP.md) is a separate incremental positive fixture for the previously negative-only APK operations. Its new calls are not silently added to the 142-call historical snapshot.

The [complete 20-backend coverage table](TOOL_LAB_COVERAGE.md) records every configured slot, its exact prerequisites and the different evidence strengths.

## Start from a clean checkout

Clone [debugger-workstation-public](https://github.com/dwgx/debugger-workstation-public)
and follow [bootstrap](BOOTSTRAP.md). The package check verifies source closure
and the portable Skill contract without requiring every external tool:

```powershell
pwsh -NoProfile -File scripts/verify-all.ps1 -Scope Package
pwsh -NoProfile -File scripts/bootstrap.ps1 -InstallRoot 'C:/Owned/WorkStation'
pwsh -NoProfile -File scripts/bootstrap.ps1 -Apply -CloneMcp -InstallRoot 'C:/Owned/WorkStation'
```

The first bootstrap command prints a plan. The second copies the station, builds
the Router environment and clones declared backend repositories. Each selected
backend still needs its own documented build/dependencies and external tool.
Cloning a repository does not build or accept its runtime. `Station` and `Paired`
verification scopes have additional prerequisites; `Package` does not set those
scopes to passed.

Install the portable Skills using the installation reference linked from
[bootstrap](BOOTSTRAP.md). Verify the resolved canonical Skill directory and the
actual loaded bytes. A model's use of an explicit `skill://` URI proves that loader
path for that run; it does not prove autonomous Skill selection.

## Inventory and choose a real test

[Tool smoke](TOOL_SMOKE.md) reads all 63 tool-manifest entries and can run twelve
reviewed CLI version probes. Presence, version banners and application behavior
have different statuses. There are 20 configured backend slots; their individual
method denominators come from a successful runtime `tools/list`, with static
source declarations recorded separately.

The [tool-lab runner reference](../scripts/tool_lab/README.md) explains client
dependencies, owned process cleanup, source identities and evidence formats. Use
an existing Python interpreter with `pywin32` for actual Windows provider runs.
Run from the checkout and choose a fresh evidence directory outside the station:

```powershell
python -X utf8 -B scripts/tool_lab/offline_acceptance.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/offline-001'
python -X utf8 -B scripts/tool_lab/run_reqable.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/reqable-001'
python -X utf8 -B scripts/tool_lab/run_frida.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/frida-001'
python -X utf8 -B scripts/tool_lab/run_ida.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/ida-001'
python -X utf8 -B scripts/tool_lab/run_volatility.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/volatility-001'
python -X utf8 -B scripts/tool_lab/run_dnspy_nop.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/nop-001'
python -X utf8 -B scripts/tool_lab/run_apktool.py --station 'C:/Owned/WorkStation' --output 'C:/Owned/results/apktool-001'
```

The three-provider offline runner generates PCAP, archives, JavaScript and a tiny
PE, then calls Wireshark, 7-Zip and REA through their original wrappers. It records
each request, response, independent content check, complete fixture hash snapshot,
stdout audit and owned Job cleanup. The separate
[selected CLI profile](CURRENT-CLI-PROFILE.md) provides the PCAP receipt/provenance
workflow; it has a different evidence format and acceptance gate.

## What the selected executions established

The following observations were made on 2026-11-19 UTC, continuing into
2026-11-20 JST. They describe a tested source/environment combination. Re-running
the public code produces new evidence for the caller's own installation.

| Slice | Observed result | Remaining scope |
| --- | --- | --- |
| Wireshark / 7-Zip / REA original wrappers | 63 calls across 35 unique methods, including 14 expected negative scenarios; all scenario assertions, input hashes and three owned cleanups passed | The catalogs declared 192 methods: 31 passed, 3 partially exercised, 1 explicitly capability-blocked, 156 untested and 1 out of scope. A correctly observed capability refusal is not functional acceptance of that method. |
| Reqable original wrapper | 17 methods, 20 calls; exact owned HAR/SQLite/WebSocket facts and missing/malformed input rejection | No live traffic capture or generated code execution |
| Frida original wrapper | 10 methods, 12 calls; owned sleeper argument, exact image identity, JS result, queue and termination | No unrelated target or USB-device acceptance |
| Volatility original wrapper | 3 methods, 4 calls; missing-file rejection and plugin metadata | `memory_forensics_validated=false`; the placeholder is not a RAM image |
| IDA original wrapper | Selected generated-PE observations through an owned headless session | Other methods, GUI adoption, debugger execution and general decompiler quality remain separate |
| APKTool original wrapper | 12 calls across 11 methods: 5 positive metadata/version methods and 7 exact missing-input refusals; owned workspace and sources unchanged, stdout/cleanup accepted | Successful APK decoding/building and APK execution remain untested |
| dnSpy NOP | Balanced removal of a generated `ldstr`/`WriteLine(string)` pair, verified as IL | The generated DLL is not executed; an earlier unbalanced NOP fixture remains a rejected test design |

The initial Frida invocation returned correct method values while its noisy target
contaminated MCP stdout. That run failed strict transport acceptance. The corrected
spawn passes the program/argument list and pipes child stdio; the fresh original
wrapper run retains the deliberately noisy target and observes no non-JSON-RPC
stdout. The clients drain queued output after owned teardown and require a stopped
reader. Replaying older raw evidence cannot reconstruct an uncaptured shutdown
tail, so legacy observations retain that limitation.

The coverage aggregator validates raw hashes and exact request/response pairs,
recomputes checks and error flags, and retains failures. A negative scenario needs
the expected specific rejection and `isError: true`. A method catalog alone is
unexecuted coverage. Keep each run and its route; do not merge a worker's summary
totals into another runner format without an explicit reviewed adapter.

## Apply provider fixes in the documented order

- Wireshark: first the existing
  [decode/server repair](../patches/mcp-wireshark-0.5.0-errors/README.md), then the
  [handler-error increment](../patches/mcp-wireshark-0.5.0-handler-errors/SOURCE-PROVENANCE.md).
  The latter changes 27 existing explicit error returns in 12 handlers and retains
  successful/empty responses. Its 129-test unit/SDK suite includes mocked backend
  calls; original-wrapper evidence is the separate offline run above.
- APKTool: the [explicit-error repair](../patches/apktool-mcp-server-0.1.0-explicit-errors/README.md) supplies a pristine-upstream patch with Apache-2.0 notices. Its 42 SDK comparison pairs preserve 13 complete successful responses and correct 29 observed false error flags; the source edit covers 69 explicit branches without classifying arbitrary false-valued data.
- Frida and Reqable: [minimal source patches](../scripts/tool_lab/patches/README.md)
  include exact physical/LF source identities and original MIT notices. Check the
  preimage, retain a backup, and update both source and the package actually loaded
  by the wrapper, or rebuild that package from the reviewed source.
- The Volatility bridge's local error propagation repair is described in that
  patch reference. Its own redistribution license was not established, so the
  public package provides the repair/test recipe without copying that bridge.

The Reqable and APK wrappers preserve explicitly supplied isolated workspaces.
Their original default directories remain available when no override is supplied.
The lab requires those overrides before touching its owned fixture databases or
projects.

## Publish and acquire the reviewed sources

[Publication](PUBLICATION.md) maps every tool/backend to an upstream, license
observation and acquisition route. `manifests/publication-files.json` is the
explicit source allowlist. `scripts/publication.py` builds deterministic archives
from a Git revision and verifies both payload hashes and the matching source tree.
The fixed-hash downloader acquires bytes only; installation remains a separate
action described by each upstream.

The separately named
[YaraFlux preserved source release](https://github.com/dwgx/debugger-workstation-public/releases/tag/yaraflux-source-a4deb318d85c)
contains 116 reviewed source blobs with the original MIT notice and preservation
manifest. It is a downstream preservation of revision
`a4deb318d85cd2febe8b87695008444ee294dee7`; no service runtime acceptance is implied.
Licensed source patches and that source asset retain their upstream licenses.
Tool binaries, commercial licenses, private transcripts, captured traffic and
local credential values are not part of the station source bundle.

## Portable regression gates

```powershell
python -X utf8 -B -m unittest discover -s tests -p test_smoke_tools.py -v
python -X utf8 -B -m unittest discover -s tests -p test_tool_lab_core.py -v
python -X utf8 -B -m unittest discover -s tests -p test_tool_lab_offline_oracles.py -v
```

These tests cover meaningful counterexamples in process ownership, partial
acquisition, protocol/error handling, output identity and coverage accounting.
They run without starting external providers. CI reports them separately from
installation, cache, wiring and documentation checks. The source release remains
a preview while unexecuted provider capabilities and external prerequisites are
explicitly open.
