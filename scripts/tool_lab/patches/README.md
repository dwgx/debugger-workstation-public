# Reviewed provider corrections

These are minimal diffs against locally reviewed upstream source, with the accompanying upstream MIT notices. `IDENTITIES.json` records both physical bytes and LF-normalized hashes so a CRLF checkout is not mistaken for a different source revision. The tested distributions were Frida MCP 0.1.1 and Reqable MCP 0.3.2; version strings alone do not establish source identity.

| Patch | Defect and change | Required regression |
|---|---|---|
| `frida.patch` | The wrapper passed an unrecognized `args` keyword into Frida's auxiliary options. Its child also inherited MCP stdout. Use the documented program/argument list and piped child stdio. | Observe a unique argument in the owned process command line and verify its exact image identity; complete attach/script/kill; ensure a deliberately noisy target does not emit a non-JSON-RPC line on MCP stdout. |
| `reqable.patch` | Missing paths and import exceptions were returned as successful MCP text. Completely unparsable NDJSON was treated as an empty successful import. Raise errors through the existing FastMCP layer and reject a fallback containing no parsed entries. | Keep valid HAR behavior, verify missing/malformed imports have `isError: true`, and observe the unchanged owned database record count. |

Apply only after checking the matching source context and expected hashes. Preserve both the repository source and the package actually imported by the wrapper. Update both explicitly, or rebuild the package from the reviewed source; changing only one allows a later reinstall to undo the repair. Keep preimages so rollback is an exact guarded copy. These commands and patches do not silently apply themselves to a running installation.

## Volatility bridge: local repair recipe only

The locally examined bridge caught initialization exceptions and returned an error string as an ordinary successful MCP result. The bounded local repair propagates an exception from that catch so the existing FastMCP layer emits the error flag. Successful initialization text remains unchanged. Test it with a missing owned path and with plugin metadata on an explicit placeholder, as in `run_volatility.py`.

The bridge's own redistribution license was not established. Its source and diff are therefore omitted from this public package. This does not affect the separately licensed Volatility framework, and the metadata checks do not establish genuine RAM-image analysis.
