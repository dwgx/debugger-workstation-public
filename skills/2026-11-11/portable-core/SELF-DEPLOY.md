OWNER: repository maintainers | portable-core/SELF-DEPLOY.md
# SELF-DEPLOY — start from the repository you have

Use the current clone Owner's scope and root `AGENTS.md`. Reuse already granted
authorization; an old named-worker or read-only assignment does not add a new
permission gate. Technical approvals, nonce/ledger and evidence gates still apply.

## 1. Check the local runtime

```sh
python -X utf8 -c "import sys; print('python='+sys.version.split()[0]); assert sys.version_info >= (3,10)"
```

Choose one source route:

- **Existing clone:** use it without cloning again. At its root, record
  `git rev-parse HEAD` and `git status --short`; preserve existing dirty work.
- **Extracted archive:** use the directory containing `AGENTS.md` and `skills/`.
  No `.git` is expected. Record the supplied archive/source hash when available;
  do not invent a commit or run a mandatory Git-HEAD probe.
- **No local copy:** the following is for a shell supporting `&&` (Git Bash,
  POSIX shell or PowerShell 7). The destination must not already exist:

```sh
git clone --depth 1 https://github.com/dwgx/debugger-workstation-public.git _handoff_clone && git -C _handoff_clone rev-parse HEAD && python -X utf8 -B _handoff_clone/skills/2026-11-11/portable-core/verify.py
```

Stop if cloning or verification fails. This command selects the remote revision
available when it runs; record that revision instead of inheriting an older receipt.

## 2. Verify the clone or archive

From its root (for the new clone above, first `cd _handoff_clone`):
```sh
python -X utf8 -B skills/2026-11-11/portable-core/verify.py
python -X utf8 -B skills/2026-11-11/portable-core/tests/entry_checks.py
```
Require exit 0 and `VERDICT=PASS` from both, using the denominators they print.
Entry checks use disposable copies and include negative controls. A failed check
must remain visible; package PASS does not prove every station capability works.

## 3. Install and prove discovery

Follow `references/INSTALL.md` for a project-scoped whole-package copy, checks run
from the installed location, and actual OMP catalog/read commands. Verify the
resolved source path and SHA-256 against this reviewed package. Copying a directory,
passing the package validator and loading the skill are separate results.

For an already installed package, run `verify.py` and `tests/entry_checks.py` from
that package directory; do not prepend the repository's `skills/2026-11-11/` path.

## Repair, rollback and closeout

Use `SELF-REPAIR.md` and a relevant dated FIX-KB row. Keep the preimage of the file
you change, verify the result and roll back your own failed change without
discarding unrelated work. Repository history/publication changes require the
applicable Owner authorization; do not infer them from a historical quote.

Keep credentials, raw corpora and private content out of public artifacts; do not
change private visibility, install drivers silently, run untrusted samples on the
host or widen user-global MCP. The dated release caveat and retired VRC family
boundary are recorded in `SKILL.md`. Report package checks, harness loading,
station runtime tests and remote publication separately, marking unrun steps.
