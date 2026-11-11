# Repository index — classification, not deletion

`as_of 2026-11-11`. What lives where, and which files look like duplicates but are
not. **Nothing was deleted to build this index**; overlapping files are kept because
they answer different questions at different resolutions.

## `.agent/` — 11 files, operating memory of this station

| File | Class | What it answers |
| --- | --- | --- |
| `HANDOFF.md` | operating entry | The one rule everything follows from, the four-command workflow, capability table, traps in this repo's own tooling, what is deliberately not claimed. |
| `RECOVERY-STATION.md` | measured detail | The measurements behind `HANDOFF.md`; what to rebuild after a lost machine. |
| `atomic-artifacts.md` | rule | Atomic-artifact integrity survey — how a truncated artifact is detected. |
| `clone-freshness.md` | measured gap | What a fresh clone is missing (R3 / R5 / R6). |
| `detail-2026-10-02-deep-review.md` | review detail | Deep review and expansion, 2026-10-02. |
| `exit-conventions.md` | convention | Exit-code conventions for probes and scripts. |
| `mission-untested-mechanisms.md` | coverage gap | `mission.ps1` mechanisms with no ablate anchor and no selftest control. |
| `probe-coverage.md` | coverage audit | Probe coverage — the STRING-ONLY gap, measured. |
| `success-when.md` | convention | `success_when` evaluation in `scripts/mission.ps1`. |
| `tool-blinds.md` | trap list | Tool invocation blind spots ("root variable + bare name"). |
| `tools-manifest.md` | drift audit | `tools.json` vs. what the station actually launches. |

Subdirectories: `audit/` (`a1`, `a2`, `w2` audit reports), `reports/` (observed
verify + docs numbers), `verify/` (capability verification notes).

## `evidence/` — 2 files, the full measured logs

| File | Class | What it answers |
| --- | --- | --- |
| `atomic-artifacts.md` | evidence log | What tells a FINISHED artifact from a TRUNCATED one — full survey (21,995 B). |
| `probe-coverage.md` | evidence log | What each capability's recorded probe actually asserts (12,595 B). |

Subdirectory `probes/` holds the raw `.probe.log` / `.control.log` transcripts.

## `docs/` — 12 topic docs (+ this index, the AI entry pair, and subdirectories)

| File | Class | What it answers |
| --- | --- | --- |
| `AGENT_EVOLUTION.md` | after-action loop | How an agent scores a slice and writes lessons back. |
| `AI_USAGE_GUIDE.md` | AI reading order | What the AI may decide alone and what needs confirmation. |
| `BOOTSTRAP.md` | install | Install-root copy layout + project MCP. |
| `CACHE.md` | optional | Private binary zip cache; not required for a public clone. |
| `DISTRIBUTION_NOTES.md` | distribution | `D:\Tool\debugger` distribution notes (zh). |
| `EVAL.md` | contract eval | Static contract eval rubric (`scripts/eval-agent-contract.py`). |
| `EXPERT_PLAYBOOK.md` | playbook | Reverse / malware / security-analysis field manual (zh). |
| `I18N.md` | locale | Locale resolution and localized entry files. |
| `MAINTAIN.md` | maintenance | Maintaining this clone without breaking the contract. |
| `SMARTCLI.md` | conventions | SmartCLI conventions for this station. |
| `TOOLS_INDEX.md` | tools | Tool index after bootstrap. |
| `WORKSTATION_RULES.md` | rules | Operating rules for the installed root (zh). |

Subdirectories: `docs/extensions/INDEX.md` (curated MCP / skill extensions),
`docs/i18n/{zh-CN,ja,ko}/` (localized copies), `docs/research/` (research notes,
`workers/` reports), `docs/site/` (Pages content source).

## Overlaps that are deliberate (C9)

These pairs share a filename and a topic, and **differ in bytes and in purpose**.
Keep both:

| Pair | Bytes | Different purpose |
| --- | --- | --- |
| `.agent/atomic-artifacts.md` vs `evidence/atomic-artifacts.md` | 6,676 vs 21,995 | `.agent/` = the rule an agent applies; `evidence/` = the full survey that justifies it. |
| `.agent/probe-coverage.md` vs `evidence/probe-coverage.md` | 6,336 vs 12,595 | `.agent/` = the gap summary; `evidence/` = per-capability assertion detail. |

## Superseded, kept on purpose

| Legacy file | Superseded by |
| --- | --- |
| `skills/debugger-workstation/SKILL.md` | `skills/2026-11-11/station-routers/debugger-workstation/SKILL.md` |
| `skills/debugger-review/SKILL.md` | `skills/2026-11-11/station-routers/debugger-review/SKILL.md` |

Both legacy files carry a `SUPERSEDED` line in their header. They are kept so old
links and old clones do not break; the authoritative versions are in the 2026-11-11
package.

## Counts used above

- `.agent/` = 11 `.md` files (denominator: top-level `*.md`, subdirectories excluded).
- `evidence/` = 2 `.md` files (plus `probes/` logs).
- `docs/` = 12 topic `.md` files (denominator: top-level `*.md` before this index and
  the `AI_ENTRY` pair were added).
