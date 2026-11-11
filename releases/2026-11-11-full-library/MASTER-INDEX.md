# MASTER-INDEX — workstation-capability-saturation
Updated: 2026-11-11 | Round: 2 | Stop: none

## Question index
| Q | Question | Status | Confidence | Claims (S/C/R/U) | Sources | Report | Last round |
|---|---|---|---|---|---|---|---|
| Q0 | root | root | — | — | — | — | 0 |
| Q1 | 什么证据判定「是否全部都好了」 | answered | high | 8/0/2/0 | 16 | `research/Q1/REPORT.md` | 1 |
| Q2 | SYNTHETIC 靶场能把哪些 TR:S-* DECLARED 变 REAL？ | Q1 | answered | high | 10/0/0/0 (+1 INFERENCE) | 8 | `research/Q2/REPORT.md` | 2 |
| Q3 | MISSING/DECLARED 逐条重算 | answered (X-001 + G-Q3-1 both RESOLVED) | high | 11/0/0/0 | 11 | `research/Q3/REPORT.md` | 2,4 |
| Q4 | OWNER_GATED 哪些可降级本地真跑 | answered | high | 10/0/0/0 (+1 INFERENCE +1 UNKNOWN) | 14 | `research/Q4/REPORT.md` | 2 |
| Q5 | 语料 absorbed_no=313 能补多少 | answered | high | 13/0/0/0 (+1 INFERENCE) | 14 | `research/Q5/REPORT.md` | 2 |
| Q6 | 多 subagent 独立评价审计 | Q1,Q3,Q4,Q5 (Q2 as GAP per resume rule) | answered | high | 11/0/0/0 (+1 INFERENCE +1 UNKNOWN) | 17 | `research/Q6/REPORT.md` | 3 |
| Q7 | `real_verified` 指标循环 results.tsv | Q6 | answered | high | 12/0/0/0 | 16 | `research/Q7/REPORT.md` | 4 |
| Q8 | 最终 RELEASE_GATE 判定 | Q7 | answered | high | 19/0/0/0 | 26 | `research/Q8/REPORT.md` | 5 |

## Claim ledger
| Claim | Q | Claim | Status | Confidence | Source ids | Contradicts |
|---|---|---|---|---|---|---|
| C-001 | — | baseline real_verified=9 / blockers=286 / RELEASE_GATE=RED | supported | high | S-001 | — |
| C-002 | Q1 | 「全部都好了」= NO；`COMPLETENESS_VERDICT=NOT_COMPLETE` | supported | high | S01,S02,S03,S04,S05,S14 | 「波次验收==全局完成」 |
| C-003 | Q1 | 36 外部动作 ALL UNEXECUTED / `push_executed=NO` | supported | high | S09,S10,S15,S16 | C-001-original |
| C-004 | Q1 | `external_actions_executed=1` (P09 negation-regex 误报) | refuted | high | S06,S15 | C-003 |


## Contradictions
| ID | Claim A | Claim B | Why incompatible | Evidence | Resolution |
|---|---|---|---|---|---|
| C-001 | checker `external_actions_executed=1` | 4 权威状态面 `push_executed=NO` / 36 UNEXECUTED | 否定句 `no git push was executed` 被正则误当已执行 | `w5-interface/EXTERNAL-ACTIONS.md:45`; `PARENT-PUSH-DETECTOR-FIXTURE.md` | **resolved-by-checker-fix** — Q1 `verify.py` 改用 4 权威状态面 + 假 `push_executed=YES` 负例，父侧重跑 `executed=0/36` exit 0 |
| X-001 | Q3 `## Verify` exit 0 at authoring / ACCEPTED | Q6 independent re-run exit 1 / `VERDICT=FAIL` | `verify.py:174` hard-codes `declared_rows == 120`; parent merged 12 Q5 promotions into `SATURATION.tsv` → `declared_rows=108`, `saturation_sha16=13d822dcc2a0574e` | `q6-audit/receipts/q3-rerun.txt` (DIFFERENT actor, exit 1, UTC 23:15:10Z); parent reproduced exit 1 | **RESOLVED** — Q3 same-name fix: `declared_rows` + `real_verified` recomputed from disk, no hardcode; parent re-ran `VERDICT=OK` exit 0, `claims_total=295` frozen, accepted TSV/research bytes unchanged. Q3 RE-ACCEPTED. |

## Gaps
| ID | Q | Gap | Missing evidence | Next action |
|---|---|---|---|---|
| G-001 | Q0 | 286 blockers 逐条可跑性 | Q2–Q5 的 REAL receipts + PROMOTIONS.tsv | Round 2 wave (active) |
| G-002 | Q0 | 20 NO 需求 / 313 未吸收语料的转化成本 | Q5 `ABSORBABLE.tsv` | Round 2 Q5 |
| G-003 | Q0 | 36 外部动作 + 发布读法分歧 | Owner 一句话 | parent, after stop |
| G-004 | Q0 | 126 claims `TR:X 36 / TR:N 32 / TR:MB 24 / TR:MC 21 / TR:L 11 / TR:K 2` unassigned to any Round-2 slice | per-prefix verdict + evidence commands for those 6 sub-prefixes | later round or explicit OWNER_GATED adjudication; MUST NOT be dropped/reclassified; `claims_total=295` frozen |
| G-Q5-1 | Q5 | 10 of `can_local_check=YES=15` lessons only have `proposed_command`, not landed as independent gates | 10 further `NEW_BEHAVIOUR_GATE` rows + receipts | later round |
| G-Q5-2 | Q5 | 28 `bound=NO` claims (12 OWNER_GATED QA + 13 DECLARED QA + 3 RANGE) stay frozen; 3 RANGE must stay OWNER_GATED | Owner decision / real backend | later round |
| G-Q5-3 | Q5 | G-004 126 unassigned `TR:X/N/MB/MC/L/K` claims unclaimed / undeleted / unreclassified (CORRECT per contract) | later-round assignment | later round |
| G-Q5-4 | Q5 | `CORPUS-INDEX.tsv absorbed_yes` still 7; 5 new gates live in `NEW_BEHAVIOUR_GATE.tsv` only | parent decision whether to merge | later round |

## Repeats
| ID | Conclusion | Seen in | Count | Action |
|---|---|---|---|---|
| — | — | — | 0 | — |

## Sources (Q1: 16 primary, see `research/Q1/sources.tsv` for full 8-col table)
| source_id | class | title | locator | date | hash_or_revision | quote | notes |
|---|---|---|---|---|---|---|---|
| S-001 | primary | V4RealVerify REAL-VERIFY.tsv | `setukou-20261111/v4/real-verify/REAL-VERIFY.tsv` | 2026-11-11 | bc547e6756cff980 (SATURATION copy) | 295 rows; 9 RUNNABLE_REAL_VERIFIED | baseline, frozen denominator |
| S01–S16 | primary_tsv/report/ledger/decision/surface | Q1 16 sources | `research/Q1/sources.tsv` | 2026-11-11 | sha16 each, all locators resolve | see file | parent audited `locators_not_resolved=0` |

## Q1 acceptance (parent, non-delegable)
Parent opened all 5 files (`REPORT.md` 4,698 B, `sources.tsv` 16 rows/8 cols, `claims.tsv` 10 rows/9 cols `{supported:8, refuted:2}`, `COMPLETENESS.md`, `verify.py` 12,701 B), all OWNER-headed, ONE `## Verify`. Parent FULL re-run from W exit 0: `COMPLETENESS_VERDICT=NOT_COMPLETE`, `295/9/286/RED`, `gap 28/8/20`, `absorbed 320/7/313`, `v2+v3+v4=16`, `external_actions_executed=0/36`, `push_executed=NO`, `porcelain 11/2`, negative+positive+fake-push controls, `CHECKER_SELFTEST=OK`. `researcher-q1` **ACCEPTED**. Round 2 wave [Q2,Q3,Q4,Q5] dispatched.
