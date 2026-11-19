# APKTool MCP 0.1.0: explicit tool failures

This Apache-2.0 source patch makes the provider's existing explicit failures use the MCP error envelope. The tested environment is FastMCP 2.12.4, MCP 1.29.1 and Pydantic 2.13.4. The provider package metadata declares Python >=3.13; its script header has an older >=3.10 statement. Use the package requirement when reproducing this revision.

## What changes

The provider previously returned ordinary dictionaries from 69 explicit error branches. FastMCP serialized them as successful tool responses. These branches now raise `ToolError` with the same JSON error payload. The two command-execution failure exits in `decode_apk` and `build_apk` do the same. Six enclosing exception handlers pass an already-declared ToolError through without rewriting its payload.

This is not a text classifier or a global `success == false` conversion. Health-check availability is a successful diagnostic report even when APKTool is unavailable. Resource text containing `Error` or a JSON `success:false` object remains successful data. Tool names, input/output schemas, validation predicates, helper command behavior and successful return bodies are preserved.

The public patch also retains the five pre-existing local lines that direct startup prints to stderr. Those lines were present before the error-status repair and were not newly implemented or accepted by its in-memory tests. Including them lets a pristine upstream snapshot reproduce the reviewed final source without an undistributed predecessor patch.

## Source identities and application

Upstream: <https://github.com/zinja-coder/apktool-mcp-server>  
Revision: `12bb33134af905923a0a58643dcc35fd694ad6f6`  
Target: `apktool_mcp_server.py`

| Identity | SHA-256 |
|---|---|
| Pristine upstream Git blob / required LF public-patch preimage | `9b209c30e76a4a9f1f81c085d7d8c259fd77570f1daabe373278bfbcc46bccae` |
| Reviewed local baseline, CRLF and prior stderr correction | `18fe4473628db1df62ed37c46a0343f790df6cf1d8ffb65426dff27a659d7382` |
| Patched public source, LF | `2fda1eb5a3b984aa289a210dc557c08e9fbce1864ceee93e757dee926fef7811` |
| Tested Windows candidate, CRLF | `d219721f6efb461bb825d62d5a0d95acd25921e82be1819160e7b41bb5d40c4e` |

Read `manifest.json`. Use a new source checkout at the exact revision with LF working files, retain an unchanged baseline module for comparison, and require the public-patch preimage hash. From that checkout:

```text
git -c core.autocrlf=false apply --check <absolute-upstream-source.patch>
git -c core.autocrlf=false apply <absolute-upstream-source.patch>
```

Verify the patched LF hash. Do not use a force or skip-verification option when identities differ. A separate local minimal diff was used to review the existing Windows installation; this public patch deliberately starts from the recorded pristine upstream blob. `git apply --check` and an actual application to that exact blob both succeeded, and the resulting LF bytes exactly match the tested candidate after CRLF normalization.

## Reproduce the bounded regression

Use the provider's matching dedicated environment; do not change a global Python or MCP installation. The harness imports the two supplied modules, creates a new owned fixture directory, and calls both through the installed SDK's real in-memory MCP transport. It mocks `run_command`; it never launches APKTool, Java, a fixture executable or an external process.

```text
<provider-python> -X utf8 -B <patch-directory>/test_error_results.py --baseline <unchanged-baseline-module> --candidate <patched-module> --output <new-output-directory>
```

The observed denominator is **42 paired cases**: **29 errors** had `isError=false` on the old source and `isError=true` on the candidate while retaining the same decoded error payload; **13 successes** retained their complete MCP response. The 16-tool catalog, including schemas, was identical. All authored fixture bytes remained unchanged. This is not exhaustive execution of all 69 error branches.

The regression includes missing projects and files, workspace/traversal rejection, a binary resource rejected by a text reader, a controlled file-read exception, command failures, a controlled health exception, successful text containing error-like words, successful false-valued JSON resource data, zero-result/empty lists and unavailable-tool health reporting.

Original-wrapper stdio acceptance is a separate deployment check after guarded adoption. These tests do not establish actual APK decode/build execution, every filesystem failure, startup stdout behavior, another SDK version or complete Android-tool capability.

## License and rollback

Preserve the original module copyright and the complete [Apache-2.0 license](LICENSE.upstream). The reviewed upstream root had no NOTICE file. [NOTICE.downstream.txt](NOTICE.downstream.txt) identifies these downstream modifications; it is not represented as an upstream notice. Keep the patch with these files when redistributing it.

Before changing an installed source entry, back it up and require the exact preimage. The examined wrapper runs the module directly, so no separate installed Python package was modified. Roll back only the matching owned change from its retained preimage; do not overwrite unrelated user work.
