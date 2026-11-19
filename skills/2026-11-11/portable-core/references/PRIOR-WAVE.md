OWNER: SpecOptimizer | package/references/PRIOR-WAVE.md
# PRIOR WAVE — earlier artifacts, by pointer only

Nothing from the earlier wave is copied into this package. These are pointers, so
the entry file stays one level deep and no stale duplicate can drift.

| artifact | path (relative to the research-runs root) | use |
|---|---|---|
| agent entry | `public-repo-best-handoff-20261111/deploy/AGENT-ENTRY.md` | how an AI is handed the repo |
| topology | `public-repo-best-handoff-20261111/assets/repo-topology.svg` | repo layout diagram |
| AI entry flow | `public-repo-best-handoff-20261111/assets/ai-entry.mmd` | mermaid entry flow |

Research-runs root: `F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/` — dated provenance, NOT a live command; none of the paths above ship with this clone.

Status of every path above: present on disk (checked 2026-11-11). None of them is
a capability claim; they are navigation aids. `RELEASE_GATE=RED` and the 268
blockers apply to them exactly as they do to this package.

## Frozen in-package snapshot (2026-11-12)

| artifact | path (in this package) | sha256 | use |
|---|---|---|---|
| 2026-11-11 verifier | `references/frozen/legacy-verify-2026-11-11.py.txt` | `7f7cf083a8fa88ceb01e70fa8f727c3833df53dd390edb57d9c6e40663d8b6bb` | dated proof that the old verifier missed `references/INSTALL.md` |

The frozen bytes are executed only on temp copies by `tests/entry_checks.py`; they
are not a live entry and are never a success token. The live gate is
`tests/package_contract.py`.
