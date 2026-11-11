OWNER: parent (took over stalled PackageDesign slice) | package/SELF-DEPLOY.md
# [NOT EXECUTED] remote deploy — SELF-DEPLOY entry

> **READ THIS FIRST when handed the repo.** Enabling Pages / pushing / changing
> settings / committing is `[NOT EXECUTED]` in this skill package. It produces a
> REVIEWABLE LOCAL PACKAGE + A PLAN ONLY (S10 prior wave). A remote action needs
> one explicit Owner sentence + a scoped Worker.

## ONE env self-check command (READ-ONLY)
```sh
python -X utf8 -c "import sys,subprocess as s; print('python='+sys.version.split()[0]); print('git='+s.check_output(['git','--version'],text=True).strip())" && C:/Program Files/Git/usr/bin/timeout.exe 60 git -C F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110/_v4_public_probe rev-parse HEAD
```
Expected: `python=3.10+`, a `git version` line, HEAD `875cd108a7c9015b4c7501d9f9698183916042e7`.

## ONE copy-pasteable clone + verify command
```sh
git clone --depth 1 https://github.com/dwgx/debugger-workstation-public.git _handoff_clone && git -C _handoff_clone rev-parse HEAD && python -X utf8 "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110/setukou-20261111/v5/publish/verify_publish.py"
```
Expected stdout tokens: `PUSHED_SHA=875cd108a7c9015b4c7501d9f9698183916042e7` / `VERDICT=PUBLISHED` (plus `MANIFEST_MATCH=YES`, `NO_FORBIDDEN_CONTENT=YES`, `PRIVATE_TREES_UNCHANGED=YES`, `ROLLBACK_WRITTEN=YES`).

## Add the skill to your own harness
Copy this `package/` dir into the harness skills dir (e.g. `~/.omp/agent/skills/debuggerstation-selfdeploy/`). `SKILL.md` `name` must match the package manifest name exactly (SmartCLI S18, 2026-11-11). Read `AGENTS.md` pointer. **No user-global `mcp-all`** (S1).

## Run the tests
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111/package" && python -X utf8 tests/verify.py
```
Exit 0 + `VERDICT=PASS` required; a negative control (empty `verify_command` FIX-KB row) must go RED.

## What an AI MAY / MAY NOT do
MAY: read repo + intros + `SATURATION.tsv` + `RELEASE-GATE-STATUS.md` + FIX-KB; re-run read-only verifiers; draft local reviewable files; cite dated sources.
MAY NOT: print/copy credential values (path only); change PRIVATE visibility; force push / history rewrite / `gh` write; restore `vrc-dcc` family; run untrusted binaries; touch raw corpora / `.jsonl` / THINK / Hackerone KB text; online exploitation / bounty targets / third-party penetration; write product trees without a named scoped Worker.

## Rollback pointer
`releases/2026-11-11-full-library/ROLLBACK.md` (append-only `git revert`, written + rehearsed, **NOT executed**). Any remote rollback needs a fresh Owner decision.

## Honest caveat
`RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE` / 295 claims, 27 REAL, 268 blockers. Strict in-package receipts = 0/27 (prior verifier D3). This repo ships evidence + claims, NOT "all capabilities work".
