OWNER: parent (main line) | C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation/SYNTHESIS.md

# SYNTHESIS — workstation-capability-saturation

**STOP condition: `STOP-EVIDENCE`** (2026-11-11). All 8 falsifiable questions answered + ACCEPTED; no dispatchable question remains; `295/295` proven unreachable in this loop by construction; synthesis budget reserved. A bounded evidence stop is a SUCCESSFUL run, NOT a failure.

## Root answer (first, honest)

**不是「全部都好了」。** 6 个 v4 波次全 ACCEPTED ≠ 全局完成。`claims_total=295` FROZEN，`RUNNABLE_REAL_VERIFIED=27`，`blockers=268`，`RELEASE_GATE=RED`，`COMPLETENESS_VERDICT=NOT_COMPLETE`，`push_executed=NO`。发布条件 (a) v4 REAL gate 仍 RED，决定性阻断；发布仍是 OWNER_GATED，需要 Owner 一句话（发全量 / 只发 learning-kit / 都不发），无决策 = 合法默认，保持本地 staged、不发布、不丢数据。

## Measured improvement (REAL, receipt-backed)

`real_verified` 9 → 27（delta +18）经 `results.tsv` 两次独立 keep（one-variable rule）：

| iteration | slice | promotions | metric | status | receipts |
|---|---|---|---|---|---|
| 0 | baseline | 0 | 9 | baseline | v4 REAL-VERIFY 295 rows |
| 1 | Q5 12 `SM:*` | 12 | 9→21 | keep | 12 REAL bounded + tamper RED |
| 2 | Q2 6 `TR:S-*` | 6 | 21→27 | keep | 6 REAL + 6 negatives + 47 probes |

Q3/Q4 `promotions=0` 是诚实 `no_change`（不是 crash/discard）；Q4 的 23 `TR:B-*` wrappers 启动真实 jar/exe，必须保持 OWNER_GATED。Q2 记录 6 个非零 exit 且从不抑制；`assert-probes-selftest exit 2` 与父侧 `PARENT-Q2-REAL-PROBES.md` 一致。

## Status (disk-derived, as_of 2026-11-11, denominator claims_total=295)

`DECLARED_UNVERIFIED 102` · `OWNER_GATED 151` · `MISSING 15` · `RUNNABLE_REAL_VERIFIED 27`。前缀 `TR 253 / QA 26 / SM 12 / RANGE 3 / W3 1` = 295。G-004 = 126 未指派 `TR:X/N/MB/MC/L/K`。

## Waves & research (all ACCEPTED, parent re-ran each ONE `## Verify` from W)

- W0–W5 sealed `6/6` `FINAL ALL_GREEN` exit 0；v2 `5/5`、v3 `5/5`、v4 `6/6` = `waves_accepted=16`。
- Q1 `COMPLETENESS_VERDICT=NOT_COMPLETE`；Q2 6 promotions；Q3 `promotions=0` honest；Q4 `promotions=0` honest；Q5 12 promotions；Q6 **different-actor 独立审计** `false_passes=0 / denominator_drift=0 / duplicate_claims=0`，抓到 X-001；Q7 `BOUNDED_RUN_OK`；Q8 `NOT_COMPLETE_RELEASE_GATE_RED_BOUNDED_STOP_OK`。
- `research/Q1..Q8`: `96+26=122 sources` / `83+19=102 claims`，每条 claim 都有 `source_ids`（no source, no claim）。

## Independent audit loop (this is what Owner asked for)

Q6（不同 actor）复跑 4 个已验收切片的 `## Verify`，发现 Q3 `exit 1 VERDICT=FAIL` = **X-001**（`verify.py:174` 硬编码 `declared_rows==120`，父侧合并 Q5 后盘上变 108）。父侧复现 → 同名 reopen Q3（无 twin）→ Q3 最小改 `verify.py`（从盘重算）→ 父侧复跑 exit 0。Q2 落地后 **G-Q3-1** 同样触发（`trs 57/7` → `51/13`），Q3 第二次改写成 `trs_partition_ok`/`trs_monotone_ok`（零陈旧常数）→ 父侧复跑 exit 0。Q6 已验收字节不重写；最终 synthesis 明确「Q3 在 Q6 审计时失败、现已绿」。Q7 拒绝硬编码 21（盘上已 27），保留明确标注的 `DISPATCH-SNAPSHOT` 行，两个分母不平均。

## 5-condition publication gate (Q8, all measured)

| cond | status | blocks release |
|---|---|---|
| (a) v4 REAL gate | **RED** (27/295) | **YES — decisive** |
| (b) private trees porcelain 11/2 | OK (7dfabdb/11 + 2c25f26/2) | no |
| (c) `git log origin/main..HEAD` | EMPTY / OK | no |
| (d) `git diff --stat` | EMPTY / OK | no |
| (e) rollback written + locally rehearsed | WRITTEN/REHEARSED, NOT remotely executed | does NOT unblock (a) |

`external_actions_executed=0/36`（`EXTERNAL-ACTIONS.md 16 + PUBLISH-DECISIONS.md 20`），`push_executed=NO`，36 项外部动作全部 UNEXECUTED。

## Red lines (re-scanned before synthesis)

`v5/` 125 files · `.pyc 0` · `token_like 0` · `literal_push_cmds 0` · `credential_value_files 0` · `product_tree_writes=0`。活产品树 `7dfabdb/11` + `2c25f26/2` 未变。`final_verify.py` → `FINAL ALL_GREEN` exit 0。凭据形状路径仅列路径、值不输出。

## Why 295/295 is unreachable HERE (evidence, not opinion)

- `OWNER_GATED 151` 需要 HMC/凭据/第三方决策，按定义不在本循环内。
- `MISSING 15` 是分类器口径误差（Q3: `REAL_MISSING=0 / LOGICAL_KEY=5 / PRESENT_BUT_UNVERIFIED=10`）；「目录存在」不等于「能力已验证」。
- `DECLARED_UNVERIFIED 102` 受 `scripts/` 上界约束（60 files / 17 `--selftest` / 14 `--check` / 37 neither）；Q2 已把 64 个 `TR:S-*` 中的 6 个转 REAL。
- G-004 126 未指派 claim 保持冻结。

## Publication fork (Owner-gated, NOT decided here)

A-topology 已定：`dwgx/workstation` PRIVATE + `dwgx/hackerone` PRIVATE + `dwgx/debugger-workstation-public` PUBLIC；不新建/嵌套/改名 repo、不改 visibility。17 文件 sanitized `learning-kit/` 可作 teaching package 发布，但两种读法分歧 + push 远程难回滚 → **需要 Owner 一句话**。无决策 = 合法默认，保持本地 staged。

## What would falsify this synthesis

任一 `RELEASE_GATE=GREEN` 而 `real_verified<295`，或 `push_executed=YES`，或某条 REAL receipt 无 exit+UTC，或 `claims_total≠295`，或活产品树 HEAD/porcelain 漂移。Q8 负例已证明 checker 会判 RED。

## Confidence

High：所有数字从盘重算、带 as_of+分母、父侧不可下放验收、Q6 不同 actor 独立审计。Medium [INFERENCE]：GREEN loop 仍不满足 (a)。[UNVERIFIED]：「从未远程写」的否定主张只有 4 状态面 + 0 产品写为证据，未做远程审计（也不该做）。

## Verify

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
python -X utf8 setukou-20261111/v5/slices/q8-release-gate/verify.py
```

Parent re-ran this from W: exit 0, `VERDICT=NOT_COMPLETE_RELEASE_GATE_RED_BOUNDED_STOP_OK`, `295/27/268/RED/NOT_COMPLETE/8-of-8/0-false-passes/0-of-36/NO-push`.
