# mcp-wireshark 0.5.0: preserve MCP error status

The tested provider returned failure text from `decode_protocol` as an ordinary
content list. The low-level MCP SDK then represented that result as
`isError=false`. This patch returns an explicit `CallToolResult(isError=True)`
for decode validation/execution failures and shared outer routing failures.
Successful content and the 14-tool catalog are unchanged. Text containing the
word "Error" is not used as a status heuristic.

## Apply to a reviewed vendor checkout

Read [manifest.json](manifest.json) and verify all preimage SHA-256 values before
applying [error-results.patch](error-results.patch) from the vendor checkout root:

    git apply --check <absolute-path-to-error-results.patch>
    git apply <absolute-path-to-error-results.patch>

The patch changes two source files, adjusts three existing negative assertions,
and adds the regression module. Run the relevant tests with the vendor's existing
test dependencies and environment:

    python -m pytest tests/test_dissector_tools.py tests/test_error_results.py -k "decode or error_result"

The recorded result is 19 selected passing cases, not the full upstream suite.
The same three protocol-status regression assertions failed on the original
source. Tests include a successful payload containing "Error.example".

Verify the manifest's postimage hashes. A source checkout edit does not itself
update an installed wheel: inspect the original launcher's actual import paths.
When maintaining an already installed copy, back up the original two modules,
require matching preimages, and copy only the reviewed source modules into that
specific installation. Do not infer that a different environment was updated.

## Verification and boundaries

On 2026-11-19 the candidate passed three real stdio tool calls and 13 checks.
After applying the exact bytes, the original Windows .cmd launcher independently
passed eight checks: loaded source identity, unchanged catalog, positive status,
malformed-PCAP error status, both unchanged content arrays, observed owned-process
cleanup, and unchanged input files. The test environment used Python 3.14.7 and
MCP SDK 1.29.1. The Router's separate SDK upgrade does not describe this provider.

Other tools' internal error-list paths were not converted or accepted. This patch
does not claim provider-wide conformance or a complete dependency freeze.

For rollback, first verify the current postimage hashes and perform a reverse
`git apply --check` before reversing the patch. Restore only the two installed
modules from the matching backup when reverting an installed copy. Recheck the
original launcher with the same positive and malformed inputs.

Upstream copyright and MIT terms are retained in [LICENSE.upstream](LICENSE.upstream).
