# STATUS — single current-state source

**as_of:** 2026-11-12 (UTC) · **HEAD at capture:** `cead32200a692d454b354a84562f619db0de1ef0` (branch `main`, 0 ahead of `origin/main`)
**Repository:** `dwgx/debugger-workstation-public` (public)
**Rule:** this is the only current-state source. `README.md`, `index.html`, `RELEASE.md` and `CHANGELOG.md` point here; they do not restate current state.

## CI

| Run | Commit | Conclusion | Note |
|---|---|---|---|
| `43021491720` (CI) | `cead322` | **failure** | job `Check relative doc links` failed: `notes/re-methods-20261015.md -> methods/re-method-upgrades-2026-10-15.md`; the other 4 jobs succeeded |
| `43021491143` (pages build and deployment) | `cead322` | success | deployment success is not proof of a served root; see URL codes |

## Pages

- Config: `status=built`, `build_type=legacy`, `source={"branch":"main","path":"/"}`.
- Canonical lowercase source: root [`index.html`](../index.html), built from `main:/`. `docs/site/index.html` is retained as the 2026-11-11 legacy content source (not a build input, not deleted).
- Latest Pages build record: `commit=1710e390dc091352884d48fa3a23499d021ec7dd` — bookkeeping mismatch; latest deployment `sha=cead32200a692d454b354a84562f619db0de1ef0` = success.

### URL codes (4 project URLs, measured 2026-11-12)

| URL | HTTP |
|---|---|
| `https://dwgx.github.io/debugger-workstation-public/` | **404** |
| `https://dwgx.github.io/debugger-workstation-public/index.html` | **404** |
| `https://dwgx.github.io/debugger-workstation-public/INDEX.html` | **200** |
| `https://dwgx.github.io/debugger-workstation-public/site/index.html` | **200** |

Control: `https://dwgx.github.io/` = **200**.

## Releases / tags

- Public `dwgx/debugger-workstation-public`: releases **0** / tags **0**.
- Private `dwgx/debugger-workstation`: releases **1** / tags **1** (`v1.0.0`, 2026-10-16).

## Acceptance (4 booleans)

| Boolean | Value | Basis |
|---|---|---|
| `CI_ALL_JOBS_GREEN` | **false** | run `43021491720` = failure |
| `PAGES_ROOT_200` | **false** | `/` = 404 |
| `PAGES_LOWERCASE_INDEX_200` | **false** | `/index.html` = 404 |
| `RELEASE_PUBLISHED` | **false** | public releases/tags = 0 / 0; `ACCEPTANCE_SUMMARY.json`: `release_candidate_pass=false`, `publication_performed=false` |

## Historical gate (unchanged, not upgraded)

`RELEASE_GATE=RED` · `COMPLETENESS_VERDICT=NOT_COMPLETE` · **295 claims** (27 REAL / 102 DECLARED / 151 OWNER_GATED / 15 MISSING) · **268 structural blockers** · external actions **0 / 36**. Verbatim: [`../RELEASE.md`](../RELEASE.md) and [`../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md). Publishing does not change these facts.

## History appendix

- Superseded Pages claims (verbatim, 2026-11-11): [`history/2026-11-11-pages-claim.md`](history/2026-11-11-pages-claim.md).
- README tracked-file count: the 2026-10-03 statement below is historical and was **not** regenerated; current `git ls-files` at `cead322` = **723** (measured 2026-11-12).
  > Everything below was measured on 2026-10-03 against a pristine `git archive HEAD` export (383 tracked
  > files) — not against this workstation, which has been built for a month.
