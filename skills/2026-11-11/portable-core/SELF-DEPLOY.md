OWNER: parent (took over stalled PackageDesign slice) | package/SELF-DEPLOY.md
# [NOT EXECUTED] remote deploy — SELF-DEPLOY entry

> **READ THIS FIRST when handed the repo.** Enabling Pages / pushing / changing
> settings / committing is `[NOT EXECUTED]` in this skill package. It produces a
> REVIEWABLE LOCAL PACKAGE + A PLAN ONLY (S10 prior wave). A remote action needs
> one explicit Owner sentence + a scoped Worker.

## ONE env self-check command (READ-ONLY)
```sh
python -X utf8 -c "import sys,subprocess as s; print('python='+sys.version.split()[0]); print('git='+s.check_output(['git','--version'],text=True).strip())" && git -C . rev-parse HEAD
```
Expected: `python=3.10+`, a `git version` line, and the HEAD of the clone you are
standing in. The SHA is printed, never pinned: a pinned SHA goes stale on the next
commit and turns a green check into a lie.

## ONE copy-pasteable clone + verify command
```sh
git clone --depth 1 https://github.com/dwgx/debugger-workstation-public.git _handoff_clone && git -C _handoff_clone rev-parse HEAD && python -X utf8 _handoff_clone/skills/2026-11-11/portable-core/verify.py
```
Expected stdout tokens: `VERDICT=PASS` with `checks_run=9 checks_failed=0`, plus the
printed clone HEAD. Nothing here needs a research-archive path or a publish SHA:
every path resolves from the clone you just made.

## Add the skill to your own harness
Copy this dir into the harness skills dir as `portable-core`
(e.g. `~/.omp/agent/skills/portable-core/`). The dir name MUST equal the frontmatter
`name` (SmartCLI S18, 2026-11-11); `references/INSTALL.md` has the full rule. Read the
`AGENTS.md` pointer. **No user-global `mcp-all`** (S1). Writing into a live harness
config is the reader's decision — this package never does it for them.

## Run the tests
From the clone root (`repo_root` = the dir holding `skills/`):
```sh
python -X utf8 skills/2026-11-11/portable-core/tests/verify.py
python -X utf8 skills/2026-11-11/portable-core/tests/entry_checks.py
```
Exit 0 + `VERDICT=PASS` required from both. A negative control (empty `verify_command`
FIX-KB row) must go RED, and a temp copy with `references/INSTALL.md` deleted must FAIL.

## What an AI MAY / MAY NOT do
MAY: read repo + intros + `SATURATION.tsv` + `RELEASE-GATE-STATUS.md` + FIX-KB; re-run read-only verifiers; draft local reviewable files; cite dated sources.
MAY NOT: print/copy credential values (path only); change PRIVATE visibility; force push / history rewrite / `gh` write; restore `vrc-dcc` family; run untrusted binaries; touch raw corpora / `.jsonl` / THINK / Hackerone KB text; online exploitation / bounty targets / third-party penetration; write product trees without a named scoped Worker.

## Rollback pointer
`releases/2026-11-11-full-library/ROLLBACK.md` (append-only `git revert`, written + rehearsed, **NOT executed**). Any remote rollback needs a fresh Owner decision.

## Honest caveat
`RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE` / 295 claims, 27 REAL, 268 blockers. Strict in-package receipts = 0/27 (prior verifier D3). This repo ships evidence + claims, NOT "all capabilities work".
