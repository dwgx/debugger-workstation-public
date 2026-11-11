OWNER: SpecOptimizer | package/references/INSTALL.md
# INSTALL — add this skill to a harness and validate it

## Dir name rule
The official spec requires the skill directory name to equal frontmatter `name`
(1-64 chars, lowercase letters/digits/hyphens, no `--`). Here `name` is
`debuggerstation-selfdeploy`, so install it as:

```
<skills-dir>/debuggerstation-selfdeploy/
```

This archive keeps the payload in `package/` only because it is a research-run
artifact with a root-relative verifier. That is the ONE place where the directory
name differs from `name`; after copying, the rule is satisfied. Never rename the
payload itself.

## Copy
1. Copy the whole `package/` payload to `<skills-dir>/debuggerstation-selfdeploy/` (frontmatter, `references/`, `scripts/`, `FIX-KB/`, `tests/`, `LICENSE`).
2. Register the same name in the harness manifest (SmartCLI S18) — a manifest name that differs from frontmatter `name` breaks routing.
3. Read `AGENTS.md` (harness pointer), then `SKILL.md` (entry).

## Validate (official CLI, if available)
```sh
skills-ref validate ./debuggerstation-selfdeploy
```

## Validate without the CLI (always available, stdlib only)
```sh
python -X utf8 package/verify.py
```
Exit 0 + `VERDICT=PASS` is the package contract; it checks the honesty invariants,
not that every station capability works.

## Boundaries
Product trees stay READ-ONLY unless a scoped Worker is named. No remote write
(push / Pages / settings / visibility) happens from this skill: those are
`[NOT EXECUTED]` and need a separate Owner sentence.
