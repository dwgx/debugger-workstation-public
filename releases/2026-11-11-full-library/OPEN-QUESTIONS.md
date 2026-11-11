OWNER: parent (main line) | C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation/OPEN-QUESTIONS.md

# OPEN-QUESTIONS — workstation-capability-saturation (STOP-EVIDENCE, 2026-11-11)

One row per UNRESOLVED gap. All are real, none hidden, none invented. `claims_total=295` FROZEN; `RELEASE_GATE=RED`; `COMPLETENESS_VERDICT=NOT_COMPLETE`; `push_executed=NO`.

| ID | Gap | Count / denom | Why unresolved in this loop | Owner of resolution | Evidence |
|---|---|---|---|---|---|
| G-001 | `OWNER_GATED` claims need REAL backends / credential / third-party decisions | 151 / 295 | 按定义需 HMC/凭据/第三方授权；本循环禁止在线利用、bounty 目标测试、凭据输出、第三方渗透 | **Owner** (ONE sentence per decision) | `SATURATION.tsv`; `research/Q4/REPORT.md`; `PARENT-Q4-UPPER-BOUND.md` (23 `TR:B-*` launch REAL jars/exes) |
| G-002 | `DECLARED_UNVERIFIED` (scripts upper bound) | 102 / 295 | `scripts/` 60 files, only 17 `--selftest` + 14 `--check` + 37 neither; 31 `.ps1`; Q2 already converted 6 of 64 `TR:S-*`; 35 `[GATED]` scripts need live RE/MCP/network backends (no SYNTHETIC substitute); `smoke-all.ps1 -Json` exit 124 under 45s | Later round or Owner | `research/Q2/REPORT.md`; `PARENT-Q2-UPPER-BOUND.md`; `PARENT-Q2-REAL-PROBES.md` |
| G-003 | `MISSING` classifier口径 errors | 15 / 295 | Q3 reclassifies: `REAL_MISSING=0 / LOGICAL_KEY=5 / PRESENT_BUT_UNVERIFIED=10`; directory existing ≠ capability verification | Later round (口径 fix, not capability) | `research/Q3/REPORT.md`; `MISSING-RECHECK.tsv` 18 rows |
| G-004 | Unassigned `TR:X/N/MB/MC/L/K` claims | 126 / 295 | Not assigned to any Round-2 slice; frozen as blockers | Later round or explicit Owner adjudication | `ROUND2-CONTRACT.md`; LEDGER G-004; `SATURATION.tsv` prefix `TR 253` |
| G-Q5-1 | 10 `can_local=YES` corpus lessons not landed as behaviour | 10 / 313 absorbable | Q5 landed 12 `SM:*` promotions + 5 `NEW_BEHAVIOUR_GATE` rows, but 10 can-local remain | Later round | `v5/slices/q5-absorption/verify.py`; `CORPUS-INDEX.tsv` |
| G-Q5-2 | 28 `bound=NO` claims (12 OWNER_GATED QA + 13 DECLARED QA + 3 RANGE) | 28 / 42 qa/sm/range/w3 | No REAL receipt bound; Q6 audit confirmed `false_passes=0` | Later round / Owner | `research/Q5/REPORT.md`; `research/Q6/REPORT.md` |
| G-Q5-3 | `CORPUS-INDEX.tsv absorbed_yes` still 7 | 7 / 320 | 313 `absorbed_no` remain; corpora sha-verified but not all converted to behaviour gates | Later round | `v4/corpus-absorb/CORPUS-INDEX.tsv`; `ABSORPTION-V4.md` |
| G-Q5-4 | G-004 untouched by Q5 | 126 | Q5 scope was `SM:*` + behaviour gates only | Later round | `research/Q5/REPORT.md` |
| G-PUB-1 | Publication fork: full library / only `learning-kit` / nothing | 3 options, 1 sentence | Two divergent readings of 「发布」; push is remote/hard-to-reverse; condition (a) RED | **Owner** — ONE sentence: 发全量 / 只发 learning-kit / 都不发. No-decision = legal default, keep local staged, do NOT publish, do NOT lose data | `v4/OWNER-DECISION-V4.md`; `v4/PARENT-GATE-STATUS.md`; `research/Q8/RELEASE-GATE.tsv` |
| G-PUB-2 | 36 external actions UNEXECUTED | 0 / 36 executed | All require Owner decision; `push_executed=NO`, `gh`/git write forbidden | **Owner** | `w5-interface/EXTERNAL-ACTIONS.md` 16 + `w0-public/candidate/PUBLISH-DECISIONS.md` 20; Q8 Verify |
| G-PUB-3 | 5-condition gate (e) not remotely executed | WRITTEN/REHEARSED only | Rollback written + locally rehearsed (SYNTHETIC DRYRUN_OK), but remote push intentionally SKIPPED/PROPOSED ONLY; does NOT unblock (a) | **Owner** + scoped Worker | `v4/release-gate/ROLLBACK.md`; `PARENT-PUB-REHEARSAL.md`; `research/Q8/REPORT.md` |
| G-Q6-INFO | Q6 `AUDIT.tsv` records PRE-FIX Q3 `exit 1` (X-001) | 1 finding | Resolved elsewhere: Q3 `## Verify` re-run TWICE by parent → exit 0; Q6 accepted bytes intentionally NOT rewritten (one-writer + minimal-change). Final synthesis states "Q3 failing at audit time, green now" | CLOSED (documented, not rewritten) | LEDGER 「Q6 post-fix audit status RESOLVED」; MASTER-INDEX X-001/G-Q3-1 RESOLVED |

## Closed in this run (not open)

C-001 (Q1 negation-regex), X-001 (Q3 `declared_rows==120`), G-Q3-1 (Q3 `trs 57/7` pins), Q2 non-delivery (landed 43m34s), Q6 post-fix status (parent decision recorded). All Q1–Q8 `answered` + `ACCEPTED`.

## Note

`STOP-EVIDENCE` means the *research loop* is bounded-complete, NOT that the *weapon library* is 295/295 REAL. The remaining 268 blockers are structural (Owner decisions + classifier口径 + scripts upper bound + unassigned claims), not missing effort. Writing `RELEASE_GATE=GREEN` here would be a FALSE PASS (Q8 negative control proves the checker rejects it).
