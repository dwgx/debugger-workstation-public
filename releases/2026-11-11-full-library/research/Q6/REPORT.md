OWNER: researcher-q6 | research/Q6/REPORT.md

# Q6 — 多 subagent 独立评价审计（Q1/Q3/Q4/Q5 四个 ACCEPTED 切片）

**Answer (first prose line): 独立复跑 4 个 ACCEPTED 切片的 ONE `## Verify` 后，没有假 PASS、没有重复计数、没有分母漂移；唯一真发现是 Q3 的 `## Verify` 在父代 Q5 合并 12 条 `SM:*` 提升后退化为 `exit 1 / VERDICT=FAIL`（`verify.py:174` 硬编码 `declared_rows==120`，盘上已为 108）——父代确认为矛盾 X-001 并重开 researcher-q3；Q2 未交付，作为显式 GAP 记录，绝不审计其 2 个半成品 fixture、不写其文件、不声称通过。** `as_of 2026-11-11`。

## 1. Evidence (numbered; each tied to a source_id in sources.tsv)

1. Q6 是 **不同 actor**：`PARENT-Q6-AUDIT-CONTRACT.md:5` 规定「an author NEVER accepts its own artifact」。Q6 用 `rerun_driver.py`（v2 直接 argv，弃用会伪造 `exit=0` banner 的 `cmd /c`）从 W 有界 90s 复跑 Q1/Q3/Q4/Q5 的**原样** `## Verify`，回执落在 `receipts/<slice>-rerun.txt`，含 stdout/stderr/exit/UTC：退出码 `Q1=0 Q3=1 Q4=0 Q5=0`，`rerun_receipts_ok=True`。[S-Q6-03][S-Q6-05][S-Q6-06][S-Q6-07][S-Q6-08][S-Q6-13]
2. **分母冻结**：`SATURATION.tsv` 盘上重算 `claims_total=295 | RUNNABLE_REAL_VERIFIED=21 DECLARED_UNVERIFIED=108 OWNER_GATED=151 MISSING=15 blockers=274`；`results.tsv` 两行 `iter0 metric=9 baseline` + `iter1 metric=21 keep`，两行 `claims_total=295`，`denominator_drift=0`。父代把 Q5 的 12 条 SM 提升合并进 `SATURATION.tsv`（9→21 / 120→108 / 286→274），Q3/Q4 `promotions=0` 诚实。[S-Q6-01][S-Q6-02][S-Q6-13][S-Q6-17]
3. **无假 PASS**：`false_passes=0`。无 `--help` 当能力；Q4 明标 `20 backends wired` = 配置一致性、非 20 个可用后端（`Q4-C05`）；Q3/Q4 `promotions=0` 诚实；Q5 的 12 条提升每条有 `exit 0 + UTC + STDOUT` 的真回执 + 一字节内存篡改 RED 负控制；Q1 `COMPLETENESS_VERDICT=NOT_COMPLETE`。`PARENT-STOP-EXPECTATION.md:14`：任何没有 295/295 REAL 回执就报 GREEN/COMPLETE 的都是假 PASS——本次没有。[S-Q6-05][S-Q6-07][S-Q6-08][S-Q6-09][S-Q6-10][S-Q6-11][S-Q6-14]
4. **X-001（唯一真发现）**：`q3-rerun.txt` = `exit 1 VERDICT=FAIL declared_rows=108 path_resolves_real=86 logical_not_a_file=22`。根因 `q3-missing/verify.py:174` 断言 `declared_rows == 120`（合并前口径），父代合并后 GLOBAL DECLARED 变 108 → 断言失败。父代（Main IRC 2026-11-11）**立即复现并确认不是误报**，记为 MASTER-INDEX + LEDGER 的矛盾 **X-001**，同名重开 `researcher-q3` 从盘上重算；Q6 不改 Q3 文件、不声称 Q3 通过、不等修复。`AUDIT.tsv` Q3/A3 标为 `FAIL-found-X-001 / reopened`。[S-Q6-01][S-Q6-06][S-Q6-12][S-Q6-15]
5. **Q1 口径漂移（非失败）**：Q1 checker 现盘重算 `21/274/108`，但 `COMPLETENESS.md` prose 仍写 `9/286/120`（合并前）；`NOT_COMPLETE` 判定不变。记在 A3 证据里，不是分母变更、不是假 PASS。Q1/Q4/Q5 的 A3 = PASS，Q3 的 A3 = FAIL，Q2 的 A3 = GAP。[S-Q6-05][S-Q6-12][S-Q6-15]
6. **回执现实 + 前缀归属**：Q5 `PROMOTIONS.tsv` 12 行 `claim_id` **全部 `SM:`**（owned prefix）、12 unique，12/12 回执从 W 根解析且含 `command/cwd/started_utc/finished_utc/exit/STDOUT/STDERR/negative_control`（样本 `SM:candidate_BRIDGE.md.txt`）；本轮由有界 `absorb_check.py (timeout.exe 45)` 现场重生成。`QA:G25`/`W3:CARD-01` 已是 REAL，Q5 明确排除以避免双计。Q3/Q4 `PROMOTIONS.tsv` = 0 行。[S-Q6-09][S-Q6-10][S-Q6-11][S-Q6-13]
7. **无重复计数**：`duplicate_claims=0`，`measure.py duplicate_promoted_claim_ids=[]`；`status` 列单值故 `MISSING ∩ REAL = ∅`；`NEW_BEHAVIOUR_GATE` 行是语料教训、不是新 SATURATION 声明（无 id 碰撞）。G-004 = `TR:X36 TR:N32 TR:MB24 TR:MC21 TR:L11 TR:K2 = 126` 六前缀未被任何切片触碰、未删/未重编号/未重分类。[S-Q6-04][S-Q6-09][S-Q6-13][S-Q6-17]
8. **Q2 显式 GAP**：`QUESTION-TREE.md:9` + `LEDGER.md:56` = Q2 active ~27min、1 steer、2 fixtures；盘上 `q2-scripts/` 只有 `fixtures/{syn-negative.json,syn-positive.json,syn-wiki/}`，**无** `verify.py/PROMOTIONS.tsv/REPORT.md/receipts/`。按 auto-deepresearch resume 规则，Q6 只审 4 个 ACCEPTED 切片、把 Q2 未交付记为显式 GAP（`AUDIT.tsv` `Q2 GAP-NOT-DELIVERED` + `Q2 A3 gap: re-run IMPOSSIBLE, not a fail`），`q2_gap_recorded=YES`；不审其 fixture、不写其文件、不声称通过、不开 twin。[S-Q6-03][S-Q6-12][S-Q6-15][S-Q6-16]
9. **ONE `## Verify` + 负控制**：`v5/slices/q6-audit/verify.py` 从 W 运行 `exit 0 VERDICT=GREEN`，实测 `slices_audited=4 checks_run=40 checks_failed=1 false_passes=0 denominator_drift=0 duplicate_claims=0 q2_gap_recorded=YES product_tree_writes=0 claims_total_frozen_ok=YES research_contract_ok=True`。负控制把一个**无回执的伪 PROMOTIONS 行注入内存副本**（不写任何文件），checker 必返回 `checker_verdict=FAIL valid=12/13 caught=YES clean_path=GREEN`。`checks_failed=1` 是被记录的 X-001 发现，不是 Q6 harness 失败。[S-Q6-03][S-Q6-12][S-Q6-13]

## 2. Confidence

**high**。每个数字由 `q6-audit/measure.py` 与 `q6-audit/verify.py` 从盘上字节现场重算（非记忆、非 prose 转述），带 `as_of` + 分母；4 份独立复跑回执（含 exit + UTC）由不同 actor 产出；`SATURATION.tsv` 与 `results.tsv` 两条独立分母交叉核对（295 一致、9+21 一致）；`AUDIT.tsv` 40 行 A1–A10 可机读；负控制 RED + clean GREEN 双路径都真实跑过；父代确认 X-001 并会重跑本 `## Verify` 比对（本结论不靠 `completed` 状态）。`[INFERENCE]` 仅用于 C11（Q3 是口径回归而非能力回归的设计解读，依据同一次失败输出里 15 MISSING / 0 promotions / 295 frozen / 双控制仍正确），`[UNKNOWN]` 仅用于 C12（Q2 最终能交付多少 `TR:S-*` 提升未可知）。[S-Q6-01][S-Q6-06][S-Q6-13][S-Q6-17]

## 3. What would falsify this answer

- 父代从 W 重跑 `v5/slices/q6-audit/verify.py` 得不到 `VERDICT=GREEN`/exit 0，或实测数字与本报告不符 → 结论作废。
- 任一 `PROMOTIONS.tsv` 行被发现缺回执、或某个 `RUNNABLE_REAL_VERIFIED` 其实是 `--help`/`20 backends wired`/无负控制 → `false_passes` 应 >0，本结论作废。
- 发现任一 `claim_id` 被 2 个切片同时提升、或 `SATURATION.tsv` 行数 ≠295、或 G-004 126 被删/重编号/重分类 → `duplicate_claims`/`denominator_drift`/`claims_total_frozen_ok` 变化，作废。
- Q3 修复后重新复跑若 `verify.py:174` 改为从盘上重算 `declared_rows` 且父代把 X-001 结案，则本报告的「Q3 A3 = FAIL」需更新为新证据（Q6 不自行改 Q3 文件）。[S-Q6-03][S-Q6-06][S-Q6-13][S-Q6-14]

## 4. Real new subquestions / gaps only (no brainstorm)

- **Q2 未交付（本轮显式 GAP）**：Q2 仍是 active slow writer；`TR:S-*` 64 条（DECLARED 57 + REAL 7）尚无交付的 `## Verify`/`PROMOTIONS.tsv`/receipts；上界 `PARENT-Q2-UPPER-BOUND.md`（60 文件 / 17 selftest / 14 check）。Q6 按 resume 规则不阻塞整轮、不审半成品、不开 twin。[S-Q6-15][S-Q6-16]
- **G-004**：126 条 `TR:X/N/MB/MC/L/K` 未指派给任何 Round-2 切片，保持冻结；需后续轮次逐前缀判定或 Owner 显式 `OWNER_GATED` 裁决；MUST NOT 丢弃/重分类以藏 blocker。[S-Q6-04]
- **G-Q5-1**：`can_local_check=YES` 的 15 条里 10 条只有 `proposed_command`、未落地为独立 REAL 门；`NEW_BEHAVIOUR_GATE.tsv` 只覆盖 5 条。[S-Q6-14]
- **G-Q5-2**：28 条 `bound=NO` 的 QA/SM/RANGE/W3（12 OWNER_GATED QA + 13 DECLARED QA + 3 RANGE）保持冻结；3 条 RANGE 必须 `OWNER_GATED`。[S-Q6-14]
- **G-Q5-3**：G-004 126 条未认领/未删/未重分类（按契约 CORRECT），待后续轮指派。[S-Q6-04]
- **G-Q5-4**：`CORPUS-INDEX.tsv absorbed_yes` 仍为 7；5 条新门只活在 `NEW_BEHAVIOUR_GATE.tsv`，是否合并进主索引待父代决定。[S-Q6-14]
- **X-001 跟进**：父代已重开 `researcher-q3`；Q6 不等待修复、不改 Q3 文件、不接受自己作者的产物。Round 4 前沿 `[Q7]`（metric loop）→ `[Q8]`（最终 `RELEASE_GATE`）；`RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE` / `push_executed=NO` 不变。[S-Q6-03][S-Q6-06][S-Q6-14][S-Q6-15]

## Verify

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
"C:/Program Files/Git/usr/bin/timeout.exe" 90 python -X utf8 -B setukou-20261111/v5/slices/q6-audit/verify.py
```

Observed (2026-11-11, from W, exit 0): `slices_audited=4 checks_run=40 checks_failed=1
false_passes=0 denominator_drift=0 duplicate_claims=0 q2_gap_recorded=YES
product_tree_writes=0 claims_total_frozen_ok=YES research_contract_ok=True
negative_control ... checker_verdict=FAIL valid=12/13 caught=YES | clean_path=GREEN
| NO_FILE_WRITTEN VERDICT=GREEN`. 父代重跑此命令并比对即验收（不可下放）。
