OWNER: researcher-q4 | research/Q4/ (ledger) + setukou-20261111/v5/slices/q4-wrappers/ (W artifacts)

# Q4 — 151 `OWNER_GATED` 里哪些可降级成本地 SYNTHETIC 真跑（不碰 HMC/凭据/第三方）？哪些必须留 `OWNER_GATED`？

## 1. Answer (one sentence)
For the owned prefix `TR:B-*` (`mcp/bin/*.cmd` backend wrappers), **NONE of the 23 can be downgraded to a backend-free local real run**: all 23 stay `OWNER_GATED`, `promotions=0` is the honest result, because every wrapper's final line launches a real backend process (22 `LAUNCHES_REAL_BINARY` + 1 `SECURITY_GATED`, 0 `STATIC_ONLY`) and a local check can only prove static facts — never that a backend is installed-and-connectable. `as_of 2026-11-11`.

## 2. Evidence (numbered, each tied to a source_id)
1. **23 `TR:B-*` rows, all `OWNER_GATED`** — recomputed from `v5/SATURATION.tsv` by `claim_id` prefix (lines 68–90); matches parent correction `TR:B=23` and `PARENT-Q4-UPPER-BOUND.md` "23 files ALL `.cmd`". `verify.py` prints `tr_b_rows=23 tr_b_status={OWNER_GATED:23}`. [S-Q4-01, S-Q4-02, S-Q4-11, S-Q4-14]
2. **Every wrapper launches a real process** — `CLASSIFY.tsv` (23 rows / 9 cols) derived from the literal `.cmd` text in receipt `LOCAL-WRAPPER-TEXT-DUMP`: kinds `{LAUNCHES_REAL_BINARY:22, SECURITY_GATED:1, STATIC_ONLY:0, UNKNOWN:0}`. Even the smallest wrappers launch a binary (`apktool.cmd`→`java -jar apktool.jar`, `frida-mcp.cmd`→`frida-mcp.exe`). `cheatengine-mcp.cmd` is `SECURITY_GATED` (`CE_MCP_ALLOW_SHELL=0`, `REM` disables shell exec). `still_owner_gated_YES_NO=YES` on 23/23. [S-Q4-04, S-Q4-05, S-Q4-09, S-Q4-12]
3. **4 bounded REAL local commands, read-only, no backend started** — all under `C:/Program Files/Git/usr/bin/timeout.exe 30`, exit 0, each with `started_utc/finished_utc/exit/stdout/stderr` receipt: `LOCAL-WRAPPER-TEXT-DUMP`, `LOCAL-BACKEND-CONSISTENCY`, `LOCAL-WRAPPER-CHECKSUM-SCAN`, `LOCAL-TARGET-PATH-FIND`. `verify.py`: `local_real_commands=4 receipts_real=4`. NEVER ran `java -jar`/`.exe`/`node`/`npx`/`tsx`/`r2pm`/python MCP module/`cmd /c *.cmd`; no HMC/third-party connect. [S-Q4-05, S-Q4-06, S-Q4-07, S-Q4-08, S-Q4-11]
4. **"20 backends wired" is config consistency, not 20 usable backends** — receipt stdout literal `MCP backend consistency OK: 20 backends wired (template == codex toml == bin/*.cmd == BACKEND_META)`. `ROUND2-CONTRACT.md` promotion gate explicitly says this is not a promotion. [S-Q4-03, S-Q4-06]
5. **Path existence is static** — `LOCAL-TARGET-PATH-FIND` found `exists=True` for `apktool.jar`/`DnSpyMcpServer.exe`/`server.py` but `exists=False` for 15+ venv pythons/exes; a path existing does not prove the backend starts or an MCP session connects. [S-Q4-02, S-Q4-08]
6. **`promotions=0` is honest, not narrowed** — `PROMOTIONS.tsv` has 0 data rows with the explicit note that a `.cmd` text parse / path existence / config consistency is NOT a backend-usable verification. `verify.py`'s `promotion_allowed()` rejects `backend_usable=True` unless a receipt carries a literal `MCP_SESSION_CONNECTED` marker; no such receipt exists. [S-Q4-02, S-Q4-03, S-Q4-10, S-Q4-11]
7. **Gate is RED-capable (not decoration)** — injecting a synthetic `FAKE-SESSION-INJECTION.txt` with `MCP_SESSION_CONNECTED` makes `verify.py` exit 1 / `VERDICT=RED` (negative control); the clean tree exits 0 / `VERDICT=GREEN`; an in-process synthetic session receipt is accepted (positive control). Both red + green exercised. [S-Q4-11, S-Q4-13]
8. **Frozen denominator + no product writes** — `claims_total_frozen_ok=YES` (295), `product_tree_writes=0`, `push_executed=NO`; Q4 never edits `SATURATION.tsv`. A NEW separately-IDed `LOCAL_WRAPPER_STATIC_CHECK` claim (4 static receipts) is added in claims.tsv but is NOT a promotion and does not renumber/delete any of the 295. G-004 unassigned prefixes (`TR:X/N/MB/MC/L/K` = 126) are untouched. [S-Q4-01, S-Q4-03, S-Q4-11, S-Q4-14]

## 3. Confidence
**High.** Every number is recomputed from disk bytes by a re-runnable `verify.py` (exit 0), all 4 receipts carry real UTC/exit/stdout, the classification is grounded in literal wrapper text (combined sha256 `5aa55358…`), and both negative (RED) and positive (GREEN) controls were executed. The only non-high items are explicitly labelled `[INFERENCE]` (a real promotion would need a forbidden backend session) and `[UNKNOWN]` (backend connectability was deliberately not tested).

## 4. What would falsify
- An `TR:B-*` wrapper whose text only sets env / echoes and launches nothing (`STATIC_ONLY>0`) whose capability is thus testable backend-free.
- A REAL bounded run producing a `MCP_SESSION_CONNECTED` session receipt WITHOUT HMC/credential/third-party.
- `promotions>0` backed by such a receipt, or `TR:B-*` statuses drifting from `OWNER_GATED`.
None observed on disk `as_of 2026-11-11`.

## 5. Real new subquestions / gaps only
- **G-004 (parent):** 126 `TR:X/N/MB/MC/L/K` claims are unassigned to any Round-2 slice — frozen for a later round; Q4 does not claim, delete, reclassify, or drop them.
- **Backend connectability:** to promote any `TR:B-*` requires an Owner-authorized live MCP backend session (HMC/credential/third-party). Out of Q4 scope; remains `OWNER_GATED` (not `MISSING`, not `REAL`).

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && "C:/Program Files/Git/usr/bin/timeout.exe" 30 python -X utf8 -B setukou-20261111/v5/slices/q4-wrappers/verify.py
```
