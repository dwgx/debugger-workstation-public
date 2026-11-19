# Wireshark MCP source and patch provenance

- Upstream repository recorded by the source checkout: <https://github.com/khuynh22/mcp-wireshark>.
- Source checkout HEAD: `95d3497f47f1009dfb9ee812fd8a9e90714c949f`; the checkout was dirty because reviewed downstream fixes were already present. This is an observed local Git identity, not a claim that every baseline byte equals the pristine upstream commit.
- Package metadata: `mcp-wireshark` version `0.5.0`; author Khang Nguyen Huynh; Python package dependency declaration `mcp>=0.9.0,<2.0.0`.
- Upstream license notice: `MIT License`, `Copyright (c) 2025 Khang Nguyen Huynh`. The complete unmodified notice is supplied in `LICENSE-UPSTREAM.txt` (SHA-256 `54ba0a2b2d27919083f457010809baa3dd1b4907327e01ef6bfb9411fc36f3a2`). Preserve it with redistributed copies or substantial portions.
- Frozen `pyproject.toml` SHA-256: `9cb1decc9418fa7ecd61955eca309afc756ca1e7899bb6a79c8fad4f348b2c8f`.

## Incremental patch scope

`PATCH.diff` changes two source modules and three deterministic test files. It adds explicit `CallToolResult(isError=True)` at existing error returns while retaining successful and empty responses. It contains no private capture or original execution log.

This patch is incremental on a reviewed downstream baseline that already includes `decode_protocol` and server error-envelope fixes. Do not assume it applies directly to the pristine upstream commit. Its required production preimages are:

| Source | Required baseline SHA-256 | Patched SHA-256 |
|---|---|---|
| `src/mcp_wireshark/read_tools.py` | `2297b82642480e13949c14b04fdbc3c2b0adf65e167b3dc0ef517381fad93548` | `007315e72b39eadf583741213043332c6d72d917b178de66193e98a11d38788f` |
| `src/mcp_wireshark/write_tools.py` | `431ff2a78a183d1b59ca4b54ed105f0d0446585ffa7e7aedca07682a50b61ed1` | `d3cac744ece8a08b9a48f499ba51aefb4ecc8ea2df10ac7c315c932f47eca8c0` |

The existing `server.py` remains byte-for-byte unchanged at SHA-256 `aa9295d3f882555f11d62e2be8cbf561c40ed9167258885178f10ab9b0b3b708`. Publication against a pristine upstream snapshot requires including the preceding downstream repair as a separate ordered patch or producing a reviewed combined patch.

The local candidate suite passed 129 tests using MCP SDK 1.29.1. Backend calls in new tests are mocked; SDK routing is exercised in process. This does not substitute for provider wrapper acceptance or establish coverage for another SDK version.
