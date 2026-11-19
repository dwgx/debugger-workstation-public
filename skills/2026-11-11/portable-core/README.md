OWNER: repository maintainers | portable-core/README.md
# portable-core — portable skill package

[English](README.md) · [简体中文](README.zh-CN.md)

A repository-delivered package for AI or human handoff: reuse a clone or archive,
install the skill in a project harness, verify its closure and diagnose tool or
environment failures. Installation and publication status require their own
receipts; this introduction does not assert either.

## Start

1. Read `SKILL.md`. Choose the existing-clone, archive or new-clone route in
   `SELF-DEPLOY.md`; do not clone again just to satisfy an old checklist.
2. Run the package and entry checks. From this package directory:

```sh
python -X utf8 -B verify.py
python -X utf8 -B tests/entry_checks.py
```

3. Follow `references/INSTALL.md` to install the whole `portable-core` directory.
   Verify actual harness source path, scope and SHA-256 against reviewed bytes.
   For a failure, use `SELF-REPAIR.md` and an applicable dated `FIX-KB/` entry.

Package PASS means the package contract passed, not that all station tools work.
`SKILL.md` retains the dated 2026-11-11 release caveat and the retired VRC family
boundary; `references/VERIFY.md` explains evidence scopes and historical output.
Current Owner scope applies without inheriting old named-worker restrictions or
another maintainer's personal authorization. Approval and technical gates remain.

The supported install name is **`portable-core`**. The historical alias
`debuggerstation-selfdeploy` is not an install target. Keep credentials, private
corpora and private-tree content out of public artifacts. `LICENSE` supplies the
package MIT text; repository documentation terms are in the root `LICENSE-docs`.
