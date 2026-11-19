OWNER: SpecOptimizer | package/references/INSTALL.md
# INSTALL — add this skill to a harness and validate it

## Dir name rule
The official spec requires the skill directory name to equal frontmatter `name`
(1-64 chars, lowercase letters/digits/hyphens, no `--`). This package already
satisfies it: the directory is `portable-core/` and frontmatter `name` is
`portable-core`. Install it as:

```
<skills-dir>/portable-core/
```

A different install dir name breaks routing. If you must rename the directory,
rename the frontmatter `name` in the same edit — never one without the other.
`debuggerstation-selfdeploy` is the 2026-11-11 research-run alias: archived only,
never an install target.

## Copy
1. Copy this whole dir to `<skills-dir>/portable-core/` (frontmatter, `references/`, `scripts/`, `FIX-KB/`, `tests/`, `LICENSE`).
2. Register the same name in the harness manifest (SmartCLI S18) — a manifest name that differs from frontmatter `name` breaks routing.
3. Read `AGENTS.md` (harness pointer), then `SKILL.md` (entry).

## Validate (official CLI, if available)
```sh
skills-ref validate ./portable-core
```

## Validate without the CLI (always available, stdlib only)
From the clone root (`repo_root` = the dir holding `skills/`):
```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
python -X utf8 skills/2026-11-11/portable-core/tests/entry_checks.py
```
Exit 0 + `VERDICT=PASS` from both is the package contract. Both call the single
validator `tests/package_contract.py`. `verify.py` checks the honesty invariants and
the 19-file required closure (including `LICENSE`); `tests/entry_checks.py` runs 9
install cases on temp copies (missing `references/INSTALL.md`, missing `LICENSE`,
install dir ≠ frontmatter `name`, live absolute research path, stale publish SHA, a
legal 14th FIX-KB row, an LF checkout, the legacy INSTALL fix, a clean package).
A missing required file reports `MISSING_REQUIRED=<path>` and exits 1 — never a
traceback. Neither gate claims that every station capability works.

## Boundaries
Product trees stay READ-ONLY unless a scoped Worker is named. No remote write
(push / Pages / settings / visibility) happens from this skill: those are
`[NOT EXECUTED]` and need a separate Owner sentence.
