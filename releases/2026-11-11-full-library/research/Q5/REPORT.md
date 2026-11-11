OWNER: researcher-q5 | research/Q5/{REPORT.md,sources.tsv,claims.tsv} + setukou-20261111/v5/slices/q5-absorption/

# Q5 — 四份语料 absorbed_no=313 还有哪些「可教的行为」没转成可执行门？能补多少？

## 1. Answer (one sentence)

313 条 `absorbed_no` 里 **15 条**可转成本地可执行门、`298 条`诚实地不能（元数据/定位器/prose/OWNER_GATED）；本切片把其中 **5 条**做成了带 RED 负控制的 REAL 本地门（`NEW_BEHAVIOUR_GATE`），并把 42 条 QA/SM/RANGE/W3 中 **12 条 SM** 用本轮新生成的真回执从 `DECLARED_UNVERIFIED` 提升为 `RUNNABLE_REAL_VERIFIED`，`claims_total=295` 始终冻结、语料教训不新增 SATURATION 声明。

## 2. Evidence (numbered; each tied to a source_id in sources.tsv)

1. 基线：`v4/corpus-absorb/CORPUS-INDEX.tsv` 实盘 **320 行**、`absorbed_yes=7 / absorbed_no=313**，分布 `butler 108 / nb 60 / repo_reuse 134 / evidence 18`。`verify.py` 现场重算并打印这两个数，父代可对照原文件。[Q5-S01, Q5-S14]
2. 对 313 条逐行分组（按 `source` × `kind`）：`min_gate 4`、`root_correction 10`、`req+cor 62`、`requirement 17`、`correction 2`、`theme 38`、`role_enum 8`、`content_type_enum 13`、`repo_card 129`、`tree_count 6`、`lesson_theme 12`、`tool_call_kind 10`、`user_prompt 1`、`method 1`。`ABSORBABLE.tsv` **313 行 / 7 列**，`can_local_check {YES:15, NO:298}`。YES=15 的构成：`min_gate 4 + root_correction 4 + 可证伪 requirement/req+cor/correction 7`；NO=298 是枚举/主题/129 卡/798 文件/主题计数等「定位器化索引」，按 `ABSORPTION-V4.md:39-42` 三类 NO 原因与 Root C09「读过≠吸收」不算行为门。[Q5-S01, Q5-S02, Q5-S05, Q5-S14]
3. 42 条 `QA/SM/RANGE/W3` 声明：`SATURATION.tsv` 按 `claim_id` 前缀实测 `QA 26 + SM 12 + RANGE 3 + W3 1 = 42`（`claims_total=295` 冻结）。其中 `QA:G25`、`W3:CARD-01` 已是 `RUNNABLE_REAL_VERIFIED`（V4 回执 RV-P10 / RV-S03），冻结不计为提升。[Q5-S03, Q5-S04, Q5-S09, Q5-S10]
4. 既有回执绑定（只读，不重跑别的切片命令）：`v3/repo-qa/receipts/` 4 份 JSON、`v4/real-verify/receipts/RV-S02`(skill-package, `sha256_match=12 tamper_caught=1`)、`RV-S03`(w3)、`RV-P10`(repo-qa)、`RV-N01`(负控制)、`v2/range/receipts/` 15 份、`w3-adoption/receipts/` 8 份。`RECEIPT-BINDINGS.tsv` 42 行里 **14 行** `bound_YES_NO=YES`（12 SM + QA:G25 + W3:CARD-01），`bound_receipt_files_exist=14/14`；其余 28 行（含 12 OWNER_GATED QA、3 RANGE、13 DECLARED QA）诚实标 NO。[Q5-S06, Q5-S07, Q5-S08, Q5-S09, Q5-S10, Q5-S11, Q5-S14]
5. 为什么 12 SM 之前是 DECLARED：`generate.py:309-319` 明写「file presence / sha256 verified by staged verify.py, but V4 did NOT re-run it as a capability claim」。Q5 不靠重贴 RV-S02 标签，而是在 `absorb_check.py` 本轮对 12 个 candidate 文件**现场重算 sha256/bytes**、以一字节内存篡改作 RED 负控制，为每条生成一份新 REAL 回执（command/cwd/UTC/exit/stdout/stderr）。`PROMOTIONS.tsv` **12 行**，`promotions_valid=12/12`。[Q5-S06, Q5-S08, Q5-S12, Q5-S14]
6. 语料教训→可执行门：`absorb_check.py` 把 5 条原 `absorbed_no` 教训做成 REAL 本地门：`RR-GATE-1`(envelope 真调用+error 字段)、`RR-GATE-3`(正例/负例/NOT_EXECUTED 三态，screenshot 近似陷阱)、`BU-ROOT-C08`(hash 而非 mtime 判副本)、`BU-ROOT-C10`(四角色分离/冻结证据不覆盖)、`BU-ROOT-C07`(report-only ≠ blocking)。5 个门全 GREEN 且全部 `negative_control_red_capable=True`。`NEW_BEHAVIOUR_GATE.tsv` 5 行，`new_behaviour_gates_valid=5/5`。这些是语料教训，**不是**新 SATURATION 声明。[Q5-S01, Q5-S13, Q5-S14]
7. SYNTHETIC fixtures：5 个 `*.json`（均 ≤1430 bytes、标 `SYNTHETIC`）+ 5 个 byte-matching `.sha256` 旁车；`sha256_match=5/5`、`fixture_bytes_le_8192=YES`。[Q5-S14]
8. ONE `## Verify` 从 W 跑 `timeout.exe 120 verify.py` 退出 0、`VERDICT=GREEN`，打印 `as_of` + 全部分母；内建负控制 `negative_control_no_receipt_fails=YES` / `negative_control_no_falsifier_fails=YES`（无回执的 NEW_BEHAVIOUR_GATE 必 FAIL，可 RED）。`product_tree_writes=0`、无网络、无 push、无凭据值、无不可信二进制。[Q5-S14]

## 3. Confidence

**high**。所有数字由 `verify.py` 从盘上 TSV/JSON/receipt 字节现场重算，无硬编码常量；每条提升指向唯一一份本切片 `receipts/<claim_id>.txt`；合成靶场与 sha256 旁车可复跑；父代可独立重开文件并复跑同一条 `## Verify`。`[INFERENCE]` 仅用于 C13（剩余 298 条需第三方/联网/产品写/凭据的归类，依据 ABSORPTION-V4.md 三类 NO 原因与 owner_gated 标记，未逐条联网验证），其余为 `supported`。

## 4. What would falsify

- 父代重跑 `## Verify` 得不到 `VERDICT=GREEN` / exit 0，或 `absorbed_no_baseline` 与 `v4/corpus-absorb/CORPUS-INDEX.tsv` 的 313 不符；
- 任一 `PROMOTIONS.tsv` 行的回执缺 `exit 0`/UTC`/负控制`，或任一 `NEW_BEHAVIOUR_GATE` 行的回执缺失/负控制不能 RED（`negative_control_no_receipt_fails` 应仍为 YES）；
- `claims_total` 不等于 295，或 `SATURATION.tsv` 被本切片改动；
- 任一 fixture 的 sha256 与旁车不符、或其字节 >8 KiB、或含真实凭据/私有路径。

## 5. Real new subquestions / gaps only (no brainstorm)

- **G-Q5-1**：`ABSORBABLE.tsv` 标 YES 的其余 10 条（4 min_gate 中未做的 RR-GATE-2/4、4 可证伪 requirement、2 其他）本轮只给出 `proposed_command`、未落地成独立 REAL 门；`NEW_BEHAVIOUR_GATE.tsv` 只覆盖 5 条。是否把它们也转成本地门，属下一轮，本切片不伪装已完成。
- **G-Q5-2**：28 条 `bound_YES_NO=NO` 的 QA/SM/RANGE/W3（12 OWNER_GATED QA + 13 DECLARED QA + 3 RANGE）保持冻结状态；尤其 `RANGE:real-RE-binary / production-MCP / third-party-network` 必须 `OWNER_GATED`，需要真实 RE 二进制/后端/联网/HMC/凭据，本切片无权限、不假跑。
- **G-Q5-3**（父代 G-004 相关）：`TR:X/N/MB/MC/L/K` 共 126 条未分配声明与本切片无关；本切片未认领、未删除、未重分类。`claims_total=295` 冻结，父代后续轮决定归属。
- **G-Q5-4**：`absorbed_yes` 在 `CORPUS-INDEX.tsv` 中仍为 7（本切片不编辑 v4 文件）；本切片的 5 条新门记在 `NEW_BEHAVIOUR_GATE.tsv`，由父代决定是否把对应 5 行的 `absorbed_into_behaviour_YES_NO` 合并为 YES。本切片不越界改 v4 分母。
