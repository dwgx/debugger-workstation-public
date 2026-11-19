# Preserved offline Router acceptance harness

These three source files close a publication gap in the original execution
pack. They are first-party, offline synthetic tests; no private conversation,
sample, capture, service token or installed backend is included.

| File | Original byte SHA-256 |
|---|---|
| `acceptance_harness.py` | `5bd84a57ee1ef9ac3d728d1e2d1cb4ecbb47469782413cc0b7d55c2310f92b37` |
| `fake_backend.py` | `75b089a64490e3ed79ece2462cf92694eeb5801e6fecf1d8b7d93361d92b1bd8` |
| `old_server.py` | `283873d4055498ff9ac755725816f3c736ce270426c212c0ed1f4e3ddb6b6f0d` |

`old_server.py` is the frozen defect baseline from commit
`cead32200a692d454b354a84562f619db0de1ef0`; it is a test input, not the runtime
router. The harness binds the old router and fake backend to the hashes above.
Candidate code is read from `mcp/debugger-router/server.py`. `ROUTER_PRODUCT_ROOT`
may point to another explicit candidate tree.

On Windows, use a Python environment with the station's real MCP SDK installed:

```powershell
python -X utf8 -B tests/router_acceptance/acceptance_harness.py --suite baseline
python -X utf8 -B tests/router_acceptance/acceptance_harness.py --suite r2
```

The harness creates its own temporary `.cmd` launcher and synthetic stdio
backend children. Cleanup uses only PIDs written by those fixtures. Baseline
and round-2 suites contain 11 and 7 cases respectively; the selected suite's
semantic verdict and exit status both matter. Missing SDK produces `not_run`,
not a fabricated pass. This publication change preserves the existing source
and its previous evidence; it does not claim these suites were rerun in the
publication lane or that this Windows launcher is portable to Linux.

`.gitattributes` preserves the frozen bytes. The related ten `v2-adv-*.json`
receipt fixtures are deliberately invalid inputs to the existing profile
validator, not historical successful runtime receipts.
