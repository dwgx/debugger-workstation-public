# Historical Pages claims — 2026-11-11

Captured 2026-11-12 from commit `cead32200a692d454b354a84562f619db0de1ef0` (2026-11-11).
These are the superseded current-state claims, kept verbatim. The single current state source is
[`../STATUS.md`](../STATUS.md). Nothing in this file is a current claim.

## README.md:15 — claimed "enabled 2026-11-11"

> 6. **GitHub Pages (enabled 2026-11-11):** the site root is the repository root `index.html` — a static, self-contained EN+中文 front page linking the release report, skills and AI entry. Source path `/` on `main`. Rendering is a GitHub-side build; this file is the source, not a claim that every link resolves inside the Pages sandbox.

## index.html:148-151 — claimed "not enabled"

> **GitHub Pages is not enabled in this repository.**
> This file is the prepared content source (`docs/site/index.html` plus `.nojekyll`);
> nothing is served at any site URL. Enabling Pages, setting a homepage and changing the licence are
> owner-gated remote settings and were not touched.

## index.html:183 — claimed "not enabled" (zh)

> **本仓库未启用 GitHub Pages。**此文件只是备好的内容源（`docs/site/index.html` 与 `.nojekyll`），没有任何站点 URL 在对外服务。启用 Pages、设置 homepage、更改许可证都属于需 Owner 决定的远端设置，本次未触碰。

## index.html:194 — footer

> debugger-workstation · public skeleton · as_of 2026-11-11 · content source only, Pages not enabled.

## RELEASE.md:24-26 — claimed "not enabled"

> The website content source for GitHub Pages lives in
> `docs/site/index.html`. **GitHub Pages is not enabled** in
> this repository; the source is prepared, nothing is served.

## CHANGELOG.md:8-12 — claimed "not enabled"

> - Added the front door: `README.md` / `README.zh-CN.md` "Start here / 从这里开始"
>   bridge, `docs/AI_ENTRY.md` + `docs/AI_ENTRY.zh-CN.md`, root `CHANGELOG.md` +
>   `RELEASE.md`, `docs/INDEX.md`, `docs/site/index.html` + `docs/site/.nojekyll`
>   (**Pages content source only — GitHub Pages is not enabled**), and a read-only
>   `frontage-verify.py`.

## APPEND 2026-11-12 — README.md line 15 at final60 adoption (superseded by this wave)

> 6. **Static front page:** the repository-root `index.html` is the current EN+中文 source. The older `docs/site/index.html` is a frozen 2026-11-11 frontage snapshot. Deployment status and the served URL require a separate check.

## APPEND 2026-11-12 — README.md tracked-file sentence at final60 adoption (superseded by this wave)

> Everything below was measured on 2026-10-03 against a pristine `git archive HEAD` export (383 tracked
> files) — not against this workstation, which has been built for a month.
