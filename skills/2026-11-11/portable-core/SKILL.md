---
name: portable-core
description: Set up or repair a debugger-station repository, install its portable skill into a project harness, and verify package closure plus actual loader source identity. Use for repository handoff, skill discovery failures, or shell and environment faults.
license: MIT
compatibility: "Python 3.10+ and stdlib for package checks; Git only for cloning or Git provenance. OMP is needed only for its loader checks. Use the documented shell for each command; package checks run on Windows and POSIX without network access."
metadata:
  version: "1"
  last-reviewed: "2026-11-19"
  spec: "agentskills.io/specification"
  owner: "repository maintainers | portable-core/SKILL.md"
---
# portable-core — package setup, installation and repair

This package travels with a clone, archive or harness installation. Station
routers (`debugger-workstation`, `debugger-review`) operate against a configured
station repository; installing this package does not install their tools.

## Choose the entry

- **Clone or archive:** `SELF-DEPLOY.md`. Reuse an existing checkout; Git metadata
  is optional for an archive and is not required by the package verifier.
- **Harness install/discovery:** `references/INSTALL.md`. Install the whole package
  as `portable-core`; verify loader source path, scope and SHA-256. A matching name
  alone does not identify the loaded bytes. Keep one active canonical project copy.
- **Tool/environment repair:** `SELF-REPAIR.md`, then `references/FIX-KB.md`.
  Check a row's date and applicability, inspect its proposed change, verify and
  retain a rollback. An undated or untested fix remains `[UNVERIFIED]`.

## Scope and evidence

Follow the current clone Owner's authorized scope and root contract; historical
worker restrictions and personal authorizations do not override that scope.
Preserve tool approvals, nonce/ledger and technical evidence gates. Keep private
repositories private, credentials and raw corpora out of public outputs, and
user-global MCP unchanged. Explain consequences and rollback for high-risk work;
never silently install drivers/Npcap or run untrusted samples on the host.

**Dated compatibility evidence (2026-11-11):** `RELEASE_GATE=RED`,
`COMPLETENESS_VERDICT=NOT_COMPLETE`, 268 blockers and strict `0/27` in-package
receipts belong to that historical inventory; they are not today's capability
count. **HARD BAN:** `vrc-dcc` / `vrc-review` / `vrc-world` and their overlays remain
retired (2026-09-19). Package acceptance does not change that dated release verdict.

## Verify

From this package directory, including an installed copy:
```sh
python -X utf8 -B verify.py
python -X utf8 -B tests/entry_checks.py
```
Require exit 0 and `VERDICT=PASS` from both; record each command's actual
denominator. `tests/package_contract.py` is the shared production validator.
Never weaken a valid check to obtain PASS. A suspected checker defect needs a
reproducible counterexample and independent review before changing it.

`references/VERIFY.md` explains results and dated samples; `AGENTS.md` is the
harness pointer. `README.md` / `README.zh-CN.md` are the introductions,
`references/PRIOR-WAVE.md` records earlier provenance, and `LICENSE` is included.
