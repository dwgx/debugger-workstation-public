OWNER: researcher-q4 | setukou-20261111/v5/slices/q4-wrappers/

# Q4 — can any `TR:B-*` OWNER_GATED wrapper be downgraded to a local SYNTHETIC real run?

## Answer
**NO — none of the 23 `TR:B-*` wrappers can be downgraded to a backend-free local real verification; `promotions=0` is the honest result, all 23 stay `OWNER_GATED`.** Every wrapper's final line launches a real backend process (22 `LAUNCHES_REAL_BINARY` + 1 `SECURITY_GATED`), so a local check can only prove static facts (text, sha256, path presence, config consistency), never that the backend is installed-and-connectable. `as_of 2026-11-11`.

## Measured (recomputed from disk, not hard-coded)
- `tr_b_rows=23` (SATURATION.tsv `claim_id` prefix `TR:B-`; all `status=OWNER_GATED`) — matches parent correction `TR:B=23` and `PARENT-Q4-UPPER-BOUND.md` "23 files ALL `.cmd`".
- `wrappers_scanned=23`; kinds `{STATIC_ONLY:0, LAUNCHES_REAL_BINARY:22, SECURITY_GATED:1, UNKNOWN:0}`; `still_owner_gated=23/23`.
- `local_real_commands=4`, `receipts_real=4`, `promotions=0`, `claims_total_frozen_ok=YES` (295), `product_tree_writes=0`.
- G-004 unassigned prefixes (`TR:X/TR:N/TR:MB/TR:MC/TR:L/TR:K`) are NOT touched by Q4.

## Kind taxonomy (from literal wrapper text, receipt `LOCAL-WRAPPER-TEXT-DUMP`)
- `STATIC_ONLY` = only sets env / echoes, launches nothing. **0 found** — even the smallest (`apktool.cmd` = `java -jar apktool.jar`, `frida-mcp.cmd` = `frida-mcp.exe`) launch a real binary.
- `LAUNCHES_REAL_BINARY` = last line starts a server/exe/jar/python module (22). Examples: `apktool.cmd`→`java -jar apktool.jar`; `dnspy-mcp.cmd`→`DnSpyMcpServer.exe`; `virustotal-mcp.cmd`→`node build/index.js` (needs `VIRUSTOTAL_API_KEY` credential, value withheld); `yaraflux-http.cmd`→`yaraflux-mcp-server.exe ... --port 8000` (reads `.env`).
- `SECURITY_GATED` = `cheatengine-mcp.cmd` (`REM 安全:默认关闭 shell 执行能力 ... CE_MCP_ALLOW_SHELL=0`) — explicitly disables shell exec; even a non-shell start is a third-party backend session.
- `UNKNOWN` = 0.

## The 4 bounded REAL local commands (all `timeout.exe 30`, read-only, receipts in `receipts/`)
1. `LOCAL-WRAPPER-TEXT-DUMP` — dump all 23 `.cmd` texts (evidence for CLASSIFY.tsv).
2. `LOCAL-BACKEND-CONSISTENCY` — `check_backend_consistency.py` → `MCP backend consistency OK: 20 backends wired`. **This is config/code consistency, NOT 20 usable backends** (contract).
3. `LOCAL-WRAPPER-CHECKSUM-SCAN` — 23 files, sha256 each, `by_ext=.cmd:23`.
4. `LOCAL-TARGET-PATH-FIND` — probe referenced jar/exe paths; several `exists=False` (venv pythons/exes not installed), a few `exists=True` (e.g. `apktool.jar`, `DnSpyMcpServer.exe`, `server.py`). **Path existence ≠ backend usable.**

NEVER executed: `java -jar`, any `.exe`, `node`/`npx`/`tsx`, `r2pm`, any python MCP module, any `cmd /c *.cmd`, any HMC/third-party connect. No backend started, no credential value emitted, no product write, no push.

## Why `promotions=0` is honest (not a narrowed test)
A `DECLARED|MISSING|OWNER_GATED -> RUNNABLE_REAL_VERIFIED` promotion needs a REAL bounded run on OUR OWN scripts/SYNTHETIC fixtures with exit + literal success marker + a negative control that can go RED. For `TR:B-*` the "capability" IS a live MCP backend session (HMC/credential/third-party), which the hard floor forbids. The 4 local receipts explicitly carry `backend_usable UNVERIFIED`. `verify.py`'s `promotion_allowed()` rejects a `backend_usable=True` claim unless a receipt carries the literal `MCP_SESSION_CONNECTED` marker; no such receipt exists, so the fake is rejected and `PROMOTIONS.tsv` stays empty.

## Negative control (proves the gate can go RED)
Injecting a synthetic `FAKE-SESSION-INJECTION.txt` receipt containing `MCP_SESSION_CONNECTED` makes `promotion_allowed(fake_backend_usable=True, ...)` return True → `verify.py` prints `VERDICT=RED`, `EXIT=1`. The fixture was removed immediately. On the clean tree (no session receipt) the fake is rejected → `VERDICT=GREEN`, `EXIT=0`. Both controls exercised (red + green).

## New separately-IDed claim (allowed by upper-bound; `claims_total` frozen)
`LOCAL_WRAPPER_STATIC_CHECK` (in `research/Q4/claims.tsv`): a REAL bounded static check exists (4 receipts). It is a NEW claim with its own id, does NOT renumber/delete any of the 295, and is NOT a promotion of any `TR:B-*` row. `claims_total` stays 295 in `SATURATION.tsv`.

## What would falsify this
Any of: (a) an `TR:B-*` wrapper whose text sets only env/echoes and launches nothing (`STATIC_ONLY>0`) AND whose capability is therefore testable backend-free; (b) a REAL bounded run producing a `MCP_SESSION_CONNECTED` session receipt without HMC/credential/third-party; (c) `promotions>0` backed by such a receipt. None observed on disk `as_of 2026-11-11`.

## Gaps / open (real, not brainstorm)
- G-004 (parent): 126 `TR:X/N/MB/MC/L/K` claims unassigned to a Round-2 slice — frozen, for a later round. Q4 does not claim them.
- To promote any `TR:B-*` requires an Owner-authorized backend session (HMC/credential/third-party) — out of scope for Q4, remains `OWNER_GATED`.

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && "C:/Program Files/Git/usr/bin/timeout.exe" 30 python -X utf8 -B setukou-20261111/v5/slices/q4-wrappers/verify.py
```
