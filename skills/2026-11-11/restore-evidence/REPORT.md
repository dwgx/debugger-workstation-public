OWNER: RestoreWorkerB | F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111/restore-test/REPORT.md
# REPORT — WSA-RESTORE-B-20261111

- board: `WSA-RESTORE-B-20261111`
- scope written: `D:/Software/Tool/WorkStation/debugger/skills/debugger-workstation/SKILL.md`, `.../debugger-review/SKILL.md`, this directory
- station HEAD at work time: `2c25f26` (debugger repo)
- as_of: `2026-11-11T11:47:14Z`

## Answer

Both deleted station routers are restored **in place** and polished to the official Agent Skills frontmatter contract (Owner Q1=`B`). 2/2 files restored from HEAD blobs with every router semantic preserved, plus one hard-ban section, one honesty-gate section, and the dual-axis closeout line. Two new re-runnable tests cover **42 assertions** (22 + 20), both exit 0 with `VERDICT=PASS`, and **3/3 in-memory negative controls go RED** at the expected check. `git status --porcelain` moved from ` D` ×2 to ` M` ×2 on exactly these files (no third dirty line); `~/.omp/agent/skills/` is unchanged at **20** dirs.

Pre/post (bytes and sha256 measured, not estimated):

| file | pre bytes | pre sha256 | post bytes | post sha256 | delta |
|---|---|---|---|---|---|
| `debugger-workstation/SKILL.md` | 1125 | `7667301309272be2907d2dbfa730e9fe45ad9eb0409b1f31698ea89d420f09ee` | 2993 | `80de05c5da4f8f785799c35e57468101044a51a9c5e8a7e0597fa78f442a52d1` | +1868 |
| `debugger-review/SKILL.md` | 1353 | `2f85f4200a96a0b76327618c88565c82172aab7b4d3a4d9b50f5024c08d5addb` | 2934 | `1dbbd69bf7dcb0eb44fe794db92f68e3537a391fe40d06292b5518fa6210bb03` | +1581 |

The two pre sha256 values are the HEAD blobs and match the sha16 prefixes recorded in `PRE-CHANGE-SNAPSHOT.txt` (`7667301309272be2`, `2f85f4200a96a0b7`).

## Evidence

1. **Read-only export first.** Both HEAD blobs were exported with `git -C D:/Software/Tool/WorkStation/debugger show HEAD:skills/<n>/SKILL.md` into `before-debugger-workstation-SKILL.md` (1125 B) and `before-debugger-review-SKILL.md` (1353 B); sha256 recorded above. Re-export at `11:47:14Z` reproduced the same hashes (idempotent).
2. **Restore method.** Both files were written back with the file-write tool only. No `git checkout/reset/clean` on the product tree; no git write of any kind. Porcelain: before ` D` ×2, after ` M` ×2, both mine.
3. **Spec conformance (measured).** name == parent dir (`debugger-workstation` / `debugger-review`, 20/15 chars, lowercase-hyphen); description 869/842 chars (limit 1024) carrying what + when + `Keywords:`; `metadata` 4 keys, all quoted strings (`version: "1"`, `last-reviewed: "2026-11-11"`, `spec: "agentskills.io/specification"`, `owner: "<worker> | <path>"`); `license: MIT`; `compatibility` 316/293 chars (limit 500); body 23/27 lines (limit 500); no parent-relative refs.
4. **Router content preserved — diff summary** (`git diff --stat`: 2 files, 34 insertions(+), 8 deletions(-); review 14/4, workstation 20/4):
   - `debugger-workstation`: all 7 original router bullets kept verbatim — root contract `AGENTS.md`, init handshake (`README.md`/`AGENTS.md`/`OWNER.md`/`manifests/*.json`/`docs/I18N.md`), `.agent/RECOVERY-STATION.md`, high-risk consequences + rollback with never-silent-install drivers, `debugger-router` only / never a user-global `mcp-all`, `scripts/bootstrap.ps1` dry-run → `-Apply` + `download-tools.ps1 -Apply`, English commits via `docs/MAINTAIN.md`. Added: dual-axis closeout bullet, `## Hard bans` (vrc family banned 2026-09-19, no silent driver/Npcap/kernel install, no untrusted sample on host, no MCP widening), `## Honesty gate` (RED reported RED, never edit a check; `[UNVERIFIED]`).
   - `debugger-review`: all 9 authoritative pointers kept (`success-when`, `atomic-artifacts`, `probe-coverage`, `exit-conventions`, `clone-freshness`, `tools-manifest`, `tool-blinds`, `docs/AGENT_EVOLUTION.md`, `HANDOFF.md`) and all 5 numbered checklist items kept verbatim (the 4-item checklist: claim→artifact, reproducible manifest+version+hash, high-risk rollback+consequence note, exit/handoff true state; plus the conclusion-first report item); `Never modify the artifact under review during the review pass` kept. Added: `## Gates that must not be softened` (RED gate stays RED; the 2026-09-19 vrc ban is never accepted as restored work; English commits).
   - Frontmatter-only rewrites: description (trigger surface widened, semantics unchanged), `version: 1` → `"1"`, `last-reviewed` 2026-10-28 → 2026-11-11, added `spec` + `owner`, added `license` + `compatibility`.
5. **Public hygiene.** 5 credential patterns (`ghp_`, `sk-`, `AKIA`, `-----BEGIN … PRIVATE KEY-----`, email) → 0 hits in both files; 3 corpus patterns (`.jsonl`, `ChatGPT-*.json`, `THINK/mandate`) → 0 hits; no absolute private-tree path beyond the station repo path already public in the frontmatter `owner` field.
6. **Isolation.** `ls -1 ~/.omp/agent/skills/ | wc -l` = **20** (baseline unchanged); nothing was written outside the 3 owned paths.

Attribution note: the official spec requires `SKILL.md` to start with the YAML frontmatter, so the mandated `OWNER:` line cannot be line 1 of a SKILL.md without breaking the loader. Worker attribution is therefore carried inside the frontmatter as `metadata.owner: "RestoreWorkerB | <path>"`; the literal `OWNER:` first line is on this REPORT, on `RECEIPT.md`, and as `# OWNER:` line 1 of both `verify-*.py`.

## Confidence

High on everything printed above: each number is a command in `RECEIPT.md` and can be re-derived by re-running the two Verifies. Medium on the following, stated as such: `[INFERENCE]` the specialist router (`AgentRule/specialist/README.md:26`) will rediscover these skills — the files are back at the exact paths and frontmatter names it points at, but the actual dispatch/load smoke test lives in the parent-owned `dispatch-test/` slice and was not run here. `[INFERENCE]` git will normalize LF→CRLF on the next touch of these files (two warnings in `git diff --stat`); content is unchanged and the committed blob may differ in byte count from the working-tree bytes reported here.

## Falsifiers

- Re-run either Verifies: any `[FAIL]` line, any `NEGATIVE-CONTROL … GREEN`, or `VERDICT=FAIL`.
- `git -C D:/Software/Tool/WorkStation/debugger status --porcelain` showing any line other than the two ` M` lines for these files.
- `ls -1 ~/.omp/agent/skills/ | wc -l` ≠ 20.
- A grep hit for any of the 5 credential patterns or 3 corpus patterns inside either SKILL.md.
- Editing `vrc-dcc` back to a supported/restored state, or deleting the RED-honesty line: both are proven to flip the corresponding check to RED in memory (`NEGATIVE-CONTROL` lines).

## Open gaps

- Dispatch/load smoke test of the two routers is **not** run here (`dispatch-test/` is parent-owned) → `[UNVERIFIED]` for actual runtime discovery.
- `scripts/bootstrap.ps1` dry-run was not executed: no tool bootstrap was needed for this slice, and it is a station action outside this scope.
- Commit/push is a separate gated step (parent side); this slice leaves the working tree modified and uncommitted by design.
- Body growth (+1868 / +1581 bytes) is purely additive; no original bullet, pointer, or checklist item was dropped (see diff summary above).

## Verify

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111" && python -X utf8 -B restore-test/verify-workstation.py && python -X utf8 -B restore-test/verify-review.py
```

Real stdout, `2026-11-11T11:47:14Z`, both exit 0:

```
as_of: last-reviewed=2026-11-11 checked_utc=2026-11-11T11:47:14Z files=1 bytes=2993 lines=34 body_lines=23 description_chars=869 compatibility_chars=316 metadata_keys=4
skill: D:\Software\Tool\WorkStation\debugger\skills\debugger-workstation\SKILL.md
checks: 22/22 PASS (denominator=22)
[PASS] frontmatter_parses :: yaml-lite block at line 1
[PASS] name_matches_dir :: name='debugger-workstation' dir='debugger-workstation'
[PASS] name_charset_len :: len=20 rule=1-64 lowercase/digit/hyphen
[PASS] description_length :: chars=869 limit=1024
[PASS] description_what_when_keywords :: trigger_keywords=8/8 has_what_when=True
[PASS] license_present :: license='MIT'
[PASS] compatibility_length :: chars=316 limit=500
[PASS] metadata_all_strings :: keys=4 non_string=0
[PASS] metadata_keys :: present=['last-reviewed', 'spec', 'version'] missing=[]
[PASS] body_under_500_lines :: body_lines=23 limit=500
[PASS] router_recovery_pointer :: `.agent/RECOVERY-STATION.md`
[PASS] router_bootstrap_dryrun_apply :: scripts/bootstrap.ps1 dry-run -> -Apply
[PASS] router_mcp_default_only :: debugger-router only / no user-global mcp-all
[PASS] router_high_risk_consequence_rollback :: consequence+rollback + never silent-install
[PASS] router_contract_and_docs :: AGENTS.md + docs/MAINTAIN.md
[PASS] router_dual_axis_review :: artifact+evidence axis -> skills/debugger-review
[PASS] hard_ban_vrc_family :: vrc-dcc family banned 2026-09-19, never restore
[PASS] red_gate_honesty :: RED reported RED + never edit a check
[PASS] commit_language_english :: commits stay English
[PASS] zero_credential_shapes :: patterns=5 hits=0
[PASS] zero_corpus_jsonl_think :: patterns=3 hits=0
[PASS] refs_one_level :: no parent-relative reference
NEGATIVE-CONTROL ban-restored: RED at hard_ban_vrc_family (expected RED) failed=['hard_ban_vrc_family']
NEGATIVE-CONTROL red-honesty-deleted: RED at red_gate_honesty (expected RED) failed=['red_gate_honesty']
NEGATIVE-CONTROL metadata-unquoted: RED at metadata_all_strings (expected RED) failed=['metadata_all_strings']
VERDICT=PASS
as_of: last-reviewed=2026-11-11 checked_utc=2026-11-11T11:47:14Z files=1 bytes=2934 lines=38 body_lines=27 description_chars=842 compatibility_chars=293 metadata_keys=4
skill: D:\Software\Tool\WorkStation\debugger\skills\debugger-review\SKILL.md
checks: 20/20 PASS (denominator=20)
[PASS] frontmatter_parses :: yaml-lite block at line 1
[PASS] name_matches_dir :: name='debugger-review' dir='debugger-review'
[PASS] name_charset_len :: len=15 rule=1-64 lowercase/digit/hyphen
[PASS] description_length :: chars=842 limit=1024
[PASS] description_what_when_keywords :: trigger_keywords=8/8 has_what_when=True
[PASS] license_present :: license='MIT'
[PASS] compatibility_length :: chars=293 limit=500
[PASS] metadata_all_strings :: keys=4 non_string=0
[PASS] metadata_keys :: present=['last-reviewed', 'spec', 'version'] missing=[]
[PASS] body_under_500_lines :: body_lines=27 limit=500
[PASS] review_pointers :: pointers=9 missing=0
[PASS] review_checklist_4_items :: items=4/4 numbered_1_to_5=True missing=0
[PASS] review_read_only_rule :: never modify the artifact under review
[PASS] review_evolution_and_handoff :: AGENT_EVOLUTION + HANDOFF
[PASS] hard_ban_vrc_family :: vrc-dcc family banned 2026-09-19, review never accepts them
[PASS] red_gate_honesty :: RED gate stays RED + never edit a check
[PASS] commit_language_english :: commits stay English
[PASS] zero_credential_shapes :: patterns=5 hits=0
[PASS] zero_corpus_jsonl_think :: patterns=3 hits=0
[PASS] refs_one_level :: no parent-relative reference
NEGATIVE-CONTROL ban-restored: RED at hard_ban_vrc_family (expected RED) failed=['hard_ban_vrc_family']
NEGATIVE-CONTROL red-honesty-deleted: RED at red_gate_honesty (expected RED) failed=['red_gate_honesty']
NEGATIVE-CONTROL metadata-unquoted: RED at metadata_all_strings (expected RED) failed=['metadata_all_strings']
VERDICT=PASS
```
