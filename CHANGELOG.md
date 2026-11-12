# Changelog

Only falsifiable events are recorded here: date, commit, file count, what changed.
Nothing becomes "done" because it was written down.

## 2026-11-11 — frontage bridge (this commit)

- Current state: [`docs/STATUS.md`](docs/STATUS.md) (as_of 2026-11-12).
- Added the front door: `README.md` / `README.zh-CN.md` "Start here / 从这里开始"
  bridge, `docs/AI_ENTRY.md` + `docs/AI_ENTRY.zh-CN.md`, root `CHANGELOG.md` +
  `RELEASE.md`, `docs/INDEX.md`, `docs/site/index.html` + `docs/site/.nojekyll`
  (**Pages content source only**), and a read-only
  `frontage-verify.py`.
- Marked `skills/debugger-workstation/SKILL.md` and `skills/debugger-review/SKILL.md`
  `SUPERSEDED` by `skills/2026-11-11/station-routers/*`. Files kept; nothing deleted.
- Fixed C20 in `skills/2026-11-11/portable-core/SKILL.md`: frontmatter `name` now
  matches the parent directory, and the internal owner line moved into
  `metadata.owner`. `skills/2026-11-11/portable-core/verify.py` was also corrected
  from a stale `package/` path to the in-tree `tests/verify.py` (baseline exit 2;
  now exit 0) — a path fix, not a relaxed check.
- Files in this commit: 14 (8 added, 6 modified). Pushed SHA: see
  `FRONTAGE-RECEIPT.md` (`PUSHED_SHA`).
- Gate unchanged: `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers.

## 2026-11-11 — `cc66638` (20 files)

- Second remote write: published the 2026-11-11 evidence/claims library under
  `releases/2026-11-11-full-library/` (295 claims, 8 research questions, 8 work
  slices), the `skills/2026-11-11/` package, and the release-gate status file.
- Gate unchanged: `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers.

## 2026-11-11 — `875cd10` (176 files)

- First remote write: published the public skeleton (docs, manifests, MCP router,
  labs, evidence) to `dwgx/debugger-workstation-public`.
