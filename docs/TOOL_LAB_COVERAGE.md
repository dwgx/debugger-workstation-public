# Tool lab coverage snapshot

Snapshot: 2026-11-19. This is a bounded fixture audit, not a certification of arbitrary targets or every tool in the station.

The registry contains **20 backends**. Actual runtime catalogs were observed for **10 backends / 331 methods**. The other backends have **408 unique source-declared names at 410 declaration sites**; their complete runtime catalogs are unknown. Source declarations do not establish successful startup or a working tool call.

The selected current original-wrapper evidence contains **142 calls across 101 unique backend/method pairs**. A separate historical APK source-entry run contains 17 calls. Those calls are not added to original-wrapper coverage.

## Backend matrix

A dash in the runtime column means unknown, not zero. `PASS` means the selected authored scenario succeeded. `NEGATIVE_ONLY` means refusal was demonstrated without a successful functional case. `PARTIAL` retains the stated semantic or evidence limitation. Uncalled methods remain `UNTESTED` even when another method in their backend passes.

| Backend | Runtime methods | Source-only unique names | Original methods called | Calls | Method outcomes |
|---|---:|---:|---:|---:|---|
| ghidra | — | 27 | 0 | 0 | 27 PREREQUISITE_MISSING |
| ida | 66 | — | 7 | 7 | 7 PASS; 59 UNTESTED |
| radare2 | — | 52 | 0 | 0 | 52 PREREQUISITE_MISSING |
| x64dbg | — | 48 | 0 | 0 | 48 PREREQUISITE_MISSING |
| jadx | — | 32 | 0 | 0 | 32 PREREQUISITE_MISSING |
| apktool | 16 | — | 11 | 12 | 5 PASS; 6 NEGATIVE_ONLY; 5 UNTESTED |
| frida | 13 | — | 10 | 12 | 10 PASS; 3 UNTESTED |
| imhex | — | 27 | 0 | 0 | 27 PREREQUISITE_MISSING |
| yaraflux | — | 19 | 0 | 0 | 19 PREREQUISITE_MISSING |
| mobsf | — | 1 | 0 | 0 | 1 PREREQUISITE_MISSING |
| ilspy | 8 | — | 8 | 9 | 8 PASS |
| dnspy | 10 | — | 10 | 15 | 9 PASS; 1 PARTIAL |
| wireshark | 14 | — | 12 | 16 | 11 PASS; 1 PARTIAL; 1 UNTESTED; 1 OUT_OF_SCOPE |
| reqable | 17 | — | 17 | 20 | 17 PASS |
| reclass | — | 16 | 0 | 0 | 16 PREREQUISITE_MISSING |
| sevenzip | 8 | — | 7 | 14 | 7 PASS; 1 UNTESTED |
| cheatengine | — | 175 | 0 | 0 | 175 PREREQUISITE_MISSING |
| volatility3 | 9 | — | 3 | 4 | 3 PASS; 6 UNTESTED |
| virustotal | — | 11 | 0 | 0 | 11 PREREQUISITE_MISSING |
| rea | 170 | — | 16 | 33 | 13 PASS; 2 PARTIAL; 1 BLOCKED; 154 UNTESTED |

The 331 runtime methods comprise 90 bounded PASS, 4 PARTIAL, 6 NEGATIVE_ONLY, 1 BLOCKED, 1 OUT_OF_SCOPE and 229 UNTESTED. The additional 408 source-only names retain missing-prerequisite status. No single success percentage is calculated across these different denominators.

ImHex declares `imhex_batch_search` and `imhex_batch_hash` twice: 29 declaration sites represent 27 unique names. The radare2 count is the union of 52 source names across mode and compile-time conditions, including optional SQL support; it is not an observed default runtime catalog.

## Evidence strength

These disjoint call counts describe what the saved evidence can prove. A later client improvement cannot reconstruct output that an earlier run did not save.

| Evidence retained | Calls | Scope |
|---|---:|---|
| Raw RPCs, stopped stdout reader, post-close queue drain and owned-process cleanup | 87 | Wireshark, 7-Zip, REA, final Frida and final APK runs. No non-JSON-RPC stdout was observed in the retained stream. |
| Raw RPCs and cleanup, with an unobserved legacy shutdown tail | 34 | Reqable, Volatility metadata, IDA headless and the balanced dnSpy NOP control. Saved lines were checked; full shutdown-stream cleanliness is not established. |
| Request strings and parsed response objects; full stdout unavailable | 21 | HY4's ILSpy/dnSpy observations. Authored semantic oracles and MCP flags were re-evaluated from retained responses; these are not strict complete-stream acceptance results. |

The three-provider offline runner contributes 63 calls / 35 called methods from 192 catalog methods. The registry's 20 backends, all observed catalogs' 331 methods, the offline runner's 63 calls, and the combined 142 calls are different denominators.

## Partial and blocked outcomes

- dnSpy `patch_replace_string_literal`: the patch receipt and follow-up decompilation agree, but the worker reused its output path across attempts. Fresh-before-call output is unproven. A separate fresh NOP test passed with stack-balanced IL; the earlier invalid-stack NOP refusal did not establish a provider defect.
- Wireshark `analyze_iec61850`: a no-match response was checked; a positive IEC 61850 packet fixture was not exercised.
- REA `trace_javascript_semantics` and `compare_javascript_export_shapes`: only the selected limited literal/shape scenarios were checked.
- REA `inspect_binary_layout`: the provider explicitly refused the selected capability. The expected refusal passes its scenario; the method remains BLOCKED for functional coverage.
- APK `get_resource_file`, `decode_apk`, `build_apk`, `clean_project`, `modify_smali_file` and `modify_resource_file`: only missing-input refusal is established in the final original-wrapper run. They remain NEGATIVE_ONLY.

## Prerequisites and fixture boundaries

- **ghidra**: Missing dedicated Python entry; requires GhidraMCP extension plus an explicitly owned Ghidra program/session. No current GUI was adopted.
- **ida**: Original wrapper observed; force_headless authored PE only. Uncalled methods need their own fixture/oracle; no debugger or existing GUI session adoption.
- **radare2**: Original r2pm wrapper cannot find r2mcp. radare2 6.2.2 CLI, headers and libraries exist, but the native r2mcp executable is absent. C build/install chain was outside this bounded closeout; a Python venv cannot supply it.
- **x64dbg**: Missing x64dbg-automate MCP console entry; requires matching debugger automation plugin and a newly owned debugger session/target. Existing sessions were not enumerated/adopted.
- **jadx**: Missing dedicated venv plus JADX-GUI AI plugin. Current bridge unconditionally health-pings port 8650 on startup; its methods use that plugin, not the installed CLI. No user GUI connection or endpoint substitution was performed.
- **apktool**: Dedicated venv restored; original wrapper preserves owned workspace. Five positive authored metadata/version methods and seven explicit missing-input refusals. Successful APK decode/build and APK execution remain untested.
- **frida**: Dedicated venv restored. Only a freshly compiled owned sleeper on explicit local device was spawned, attached, inspected and killed. USB and unrelated enumeration remain outside the authored fixture.
- **imhex**: Missing dedicated venv. Requires the ImHex plugin TCP server (default localhost:31337), an owned file/project, and explicit plugin identity before any call.
- **yaraflux**: Source registration observed, runtime not started: current wrapper/config initializes storage and services. An owned storage/database/rule scope must be established before scanning; no .env/auth values were read.
- **mobsf**: One source-declared upload/scan method. Requires built Node/TypeScript entry, an owned MobSF API service, authorization and an authored APK/IPA. No file was uploaded and no credential was read.
- **ilspy**: Original wrapper objects captured by HY4 on an authored C# assembly; complete stdout stream was not saved by that worker. The eight bounded semantic observations do not prove arbitrary decompilation correctness.
- **dnspy**: Original wrapper on authored unexecuted DLLs; new NOP control preserves IL stack balance. Branch-target and exception-handler edits remain untested; old invalid-stack control is retained separately.
- **wireshark**: Original wrapper tested on authored HTTP/DNS PCAP only. Live capture/driver capabilities are separately blocked or out of scope; no private traffic or third-party capture.
- **reqable**: Dedicated venv restored; original wrapper preserves owned database. Authored offline HAR and local owned listener only; no real capture, external request or generated-code execution.
- **reclass**: Missing dedicated venv. Requires ReClass.NET plugin (default localhost:27015) plus a new owned process/project. Existing attached process state was not queried.
- **sevenzip**: Original wrapper tested against owned reproducible files/archives. Functional, negative and malformed-input scenarios remain separately labeled.
- **cheatengine**: Missing dedicated venv plus running Cheat Engine bridge and an owned process. Driver/kernel/debugger-dependent operations were not enabled, and no existing user process was attached.
- **volatility3**: Dedicated venv restored. File-existence initialization and plugin metadata only; no legitimate RAM image supplied. OS detection, process/network/handle extraction and YARA forensics remain untested.
- **virustotal**: Built Node entry and API credentials/service access not established. Methods may query or submit third-party data; no credentials, API request or file submission was used.
- **rea**: Original wrapper observed with 170 methods; only root's selected authored PE/archive/XML/managed fixtures are exercised. Explicit unavailable capabilities and platform restrictions retain BLOCKED/PARTIAL labels.

## Reproduce the final APK check

Use the installed Windows client environment that already supports the shared Job Object supervisor, and a station whose original APK wrapper preserves the explicit workspace. The runner has only two required arguments:

```powershell
python scripts/tool_lab/run_apktool.py --station <station-root> --output <new-output-directory>
```

The command creates inert manifest, smali and YAML text under a new output directory. Five positive calls inspect that text, workspace membership, search results and the installed APKTool version. Seven negative calls require explicit MCP errors for absent owned inputs. Names and bytes are compared after every refused mutation, and source, wrapper, runtime metadata and client inputs are pinned. It does not execute an APK, perform a successful decode/build, attach a GUI or inspect an existing workspace.

The earlier APK `isError=false` refusals and Frida stdout contamination remain failed historical evidence. Current passing observations supersede their current-behavior status; they do not erase the older counterexamples. Successful Volatility metadata access does not establish memory forensics on a real RAM image.

See [TOOL_LAB.md](TOOL_LAB.md) and the [tool-lab runner guide](../scripts/tool_lab/README.md) for setup, public fixtures, patches and the executable acceptance boundaries.
