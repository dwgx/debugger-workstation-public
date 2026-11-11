OWNER: parent (took over stalled PackageDesign slice) | package/AGENTS.md
# AGENTS — harness pointer for debuggerstation-selfdeploy

When an AI is handed a debugger-station repo, or when a debugger skill / tool / env
fails, read `SKILL.md` first, then `SELF-DEPLOY.md` (one-shot deploy) or
`SELF-REPAIR.md` + `FIX-KB/*.tsv` (self-diagnosis). Run `tests/verify.py` before
claiming anything works.

Boundaries (inherit machine hard floor): product trees READ-ONLY unless a scoped
Worker is named; 4 PRIVATE repos never change visibility; no credential values /
raw corpora / `.jsonl` / THINK; `vrc-dcc` family retired (never restore);
`RELEASE_GATE=RED` / 268 blockers / strict `0/27` in-package receipts — never
claim all capabilities work. Remote writes are `[NOT EXECUTED]`.

zh-CN 版指针见 `README.zh-CN.md`；English intro `README.md`.
