OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/

# Q5 slice — corpus absorption into executable behaviour gates (2026-11-11)

一句话结论：313 条 `absorbed_no` 里 **15 条**可本地化、`298 条`诚实不能；本切片落地 **5 条** `NEW_BEHAVIOUR_GATE`（带 RED 负控制）+ **12 条 SM** 真回执提升；`claims_total=295` 冻结，语料教训不进 `SATURATION.tsv`。

## Artifacts (all under this exclusive slice)

| file | measured | meaning |
|---|---:|---|
| `ABSORBABLE.tsv` | 313 data rows / 7 cols | 1:1 于 `CORPUS-INDEX.tsv` 的 `absorbed_no=313`；`can_local_check {YES:15, NO:298}` |
| `RECEIPT-BINDINGS.tsv` | 42 data rows | 42 条 QA/SM/RANGE/W3 的既有盘上真回执绑定；`bound=14 / no=28` |
| `verify.py` | ONE Verify | 从 W 跑，重算全部数字 + 负控制 + 有界重跑 absorb_check；唯一命令见文末 Verify 节 |
| `NEW_BEHAVIOUR_GATE.tsv` | 5 data rows | 5 条原 `absorbed_no` 语料教训 → REAL 本地可执行门（不是新 SATURATION 声明） |
| `fixtures/*.json` | 5 SYNTHETIC, <=1430 B | 5 个合成靶场，各带 byte-matching `.sha256` 旁车，标 `SYNTHETIC` |
| `receipts/*` | 17 files | 5 lesson 回执 + 12 SM promotion 回执（command/cwd/UTC/exit/stdout/stderr） |
| `absorb_check.py` | READ-ONLY source | 现场重算 5 门 + 12 SM，写 receipts + NEW_BEHAVIOUR_GATE.tsv；内建负控制可 RED |
| `build_artifacts.py` | READ-ONLY source | 从 CORPUS-INDEX/SATURATION 字节生成 3 个 TSV，不硬编码数字 |
| `verify.py` | ONE ## Verify | 从 W 跑，重算全部数字 + 负控制 + 有界重跑 absorb_check |
| `research/Q5/*` | REPORT/sources/claims | auto-deepresearch 三件套 |

## Promotion gate (ROUND2-CONTRACT.md:25-26)

`DECLARED_UNVERIFIED -> RUNNABLE_REAL_VERIFIED` 需要：(a) 有界 `timeout.exe` 真跑**我们自己的**脚本/SYNTHETIC fixtures、(b) exit + 字面成功标记、(c) 回执、(d) 可 RED 的负控制。12 SM 提升全部满足：本轮 `absorb_check.py` 用 `timeout.exe 45` 真跑，对每个 candidate 文件现场重算 `sha256/bytes` 与 manifest 比对，一字节内存篡改负控制必 RED；`--help`/「别处恰好有回执」不算提升。`QA:G25` / `W3:CARD-01` 已是 REAL，冻结、不计提升（避免双计）。

## Negative control (can go RED)

- `verify.py` 注入一个「无 receipt 的 NEW_BEHAVIOUR_GATE」与「无 falsifier 的 NEW_BEHAVIOUR_GATE」，`validate_gate()` 必须返回 False；打印 `negative_control_no_receipt_fails=YES` / `negative_control_no_falsifier_fails=YES`。
- `absorb_check.py` 每个门都有对应的 `t_*()` 篡改函数，断言篡改后 `verdict=False`（否则 abort，视为装饰门）。

## Boundaries

无网络、无产品树写、无 push、无凭据 VALUE、无不可信二进制、无整份 `.jsonl`、无 HMC/跨机；所有写入在 `setukou-20261111/v5/slices/q5-absorption/` 与 `research/Q5/`。父代验收不可下放：父代重开文件并复跑下方 ONE 命令。

## Verify

ONE 复制即可跑的 W-relative 命令（从 W 运行，无 `W/` 字面量，只读重算、打印实测数字 + `as_of` + 分母，内建可 RED 负控制，exit 0）：

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
"C:/Program Files/Git/usr/bin/timeout.exe" 120 python -X utf8 -B setukou-20261111/v5/slices/q5-absorption/verify.py
```

Measured run (2026-11-11, from W, exit 0, `VERDICT=GREEN`):
`corpus_index_rows=320 absorbed_no_baseline=313 absorbable_rows=313`
`absorbable_can_local_YES=15 absorbable_can_local_NO=298 qa_sm_range_w3_rows=42`
`claims_total=295 claims_total_frozen_ok=YES existing_receipt_bound=14 bound_receipt_files_exist=14/14`
`synthetic_fixtures=5 sha256_match=5/5 sidecars=5 fixture_label_SYNTHETIC=5/5 fixture_bytes_le_8192=YES`
`promotions=12 promotions_valid=12/12 new_behaviour_gates=5 new_behaviour_gates_valid=5/5`
`negative_control_no_receipt_fails=YES negative_control_no_falsifier_fails=YES product_tree_writes=0`.
