# QUESTION-TREE — workstation-capability-saturation

Root (Q0): 但 v4 真验证只跑通了 9 条命令，20 backends wired 只是配置一致、不等于 20 个后端都装好能连。…… 所以现在是全部都好了吗 你认为呢 如果说真的 我们不能有没做完的 自己造和测试靶场都可以随便做 消耗token把全部能力点点满多subagents评价审计把每个工具榨干 我们学习的有那么多 也都得给榨干

Budget: rounds=8, minutes=240, tokens=1500000 (skill default; adapter inherits)
Concurrency: 6 (adapter; Owner order "unlimited fan-out", hard cap 8 respected)
Updated: 2026-11-11 (Round 3 in flight)

| ID | Question | Depends on | Status | Evidence | Owner | Notes |
|---|---|---|---|---|---|---|
| Q0 | <goal verbatim> | — | root | — | parent | framing node, never dispatched |
| Q1 | 什么证据能判定「现在是不是全部都好了」？ | — | answered | checker + 16 sources + 10 claims | researcher-q1 | ACCEPTED; `COMPLETENESS_VERDICT=NOT_COMPLETE`; C-001 fixed |
| Q2 | SYNTHETIC 靶场能把哪些 `TR:S-*` DECLARED 变 REAL？ | Q1 | answered | 8 sources / 11 claims / 6 REAL promotions | researcher-q2 | ACCEPTED (43m34s); `promotions=6` merged → `real_verified 21→27` |
| Q3 | 15 MISSING / 120 DECLARED 逐条重算 | Q1 | answered | 11 sources / 11 claims | researcher-q3 | ACCEPTED; `promotions=0` honest; X-001 + G-Q3-1 RESOLVED (disk-derived, no stale pins) |
| Q4 | 151 OWNER_GATED 哪些可降级本地真跑 | Q1 | answered | 14 sources / 12 claims | researcher-q4 | ACCEPTED; `promotions=0` honest (23 `TR:B-*` stay gated) |
| Q5 | 语料 absorbed_no=313 能补多少 | Q1 | answered | 14 sources / 14 claims | researcher-q5 | ACCEPTED; `promotions=12` merged → `real_verified 9→21` |
| Q6 | 多 subagent 独立评价审计 | Q1,Q3,Q4,Q5 (Q2 as GAP per resume rule) | answered | 17 sources / 13 claims / AUDIT 43 rows | researcher-q6 | ACCEPTED; X-001 found, `false_passes=0` |
| Q7 | `real_verified` 指标循环 results.tsv | Q6 | answered | 16 sources / 12 claims / METRIC-LEDGER 7 rows | researcher-q7 | ACCEPTED; disk-derived 9→27/+18/2 keeps; `VERDICT=BOUNDED_RUN_OK` |
| Q8 | 最终 `RELEASE_GATE` 判定 | Q7 | answered | 26 sources / 19 claims / RELEASE-GATE 5条件 | researcher-q8 | ACCEPTED; `VERDICT=NOT_COMPLETE_RELEASE_GATE_RED_BOUNDED_STOP_OK` |

Status vocabulary: root / open / active / answered / blocked / refuted / dropped.
Frontier (round 6 SYNTHESIS) = CLOSED at STOP-EVIDENCE. Q1–Q8 ALL answered and ACCEPTED (each parent re-ran ONE `## Verify` from W). No dispatchable question remains: `OWNER_GATED 151` needs Owner decisions, G-004 126 unassigned claims frozen, MISSING 15 are classifier口径 errors, DECLARED 102 bounded by scripts upper bound. Metric: `claims_total=295 FROZEN`, `real_verified=27`, `blockers=268`, `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, `push_executed=NO`, `results.tsv` 2 separate keeps (Q5 +12, Q2 +6). Publication = OWNER_GATED, ONE sentence needed.
