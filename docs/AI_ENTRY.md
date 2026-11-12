# AI entry point — read this first

`as_of 2026-11-12`. One page that tells an AI agent (and its human) where the
authoritative instructions live, what to run, and what must never be claimed.
This page adds no rules of its own: it routes to the files that own them.

## 1. Authoritative contract — read before acting

| File | Role |
| --- | --- |
| [`AGENTS.md`](../AGENTS.md) | **Authoritative** agent contract: ask-then-act initialization handshake, clone-owner overlay, MCP strategy, stop lines. Localized: [`AGENTS.zh-CN.md`](../AGENTS.zh-CN.md) / [`AGENTS.ja.md`](../AGENTS.ja.md) / [`AGENTS.ko.md`](../AGENTS.ko.md). |
| [`docs/AI_USAGE_GUIDE.md`](AI_USAGE_GUIDE.md) | Reading order, what the AI may do on its own, what needs confirmation. |
| [`CLAUDE.md`](../CLAUDE.md) | Claude entry file — points to `AGENTS.md`. |
| [`GEMINI.md`](../GEMINI.md) | Gemini entry file — points to `AGENTS.md`. |
| [`.github/copilot-instructions.md`](../.github/copilot-instructions.md) | Copilot entry file — points to `AGENTS.md`. |
| [`.cursor/rules/`](../.cursor/rules/) | Cursor rules — point to `AGENTS.md`. |
| [`templates/INIT_QUESTIONNAIRE.md`](../templates/INIT_QUESTIONNAIRE.md) | The clarifying questions that drive initialization. |

Every per-client file is a pointer, not a second contract. When they disagree,
`AGENTS.md` wins.

## 2. The 2026-11-11 package

| Path | What it is |
| --- | --- |
| [`skills/2026-11-11/portable-core/SKILL.md`](../skills/2026-11-11/portable-core/SKILL.md) | Portable core skill: deploy / add-to-harness / test / self-repair / diagnose. |
| [`skills/2026-11-11/station-routers/`](../skills/2026-11-11/station-routers/) | Station routers (`debugger-workstation`, `debugger-review`). They supersede the legacy [`skills/debugger-workstation/SKILL.md`](../skills/debugger-workstation/SKILL.md) and [`skills/debugger-review/SKILL.md`](../skills/debugger-review/SKILL.md), which stay in-tree marked `SUPERSEDED`. |
| [`releases/2026-11-11-full-library/README.md`](../releases/2026-11-11-full-library/README.md) | The evidence/claims library that was published. |
| [`releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md) | The historical release verdict; preserve and cite it with its date and denominator. |

## 3. Verification scopes

| Scope | What can be concluded | Entry |
| --- | --- | --- |
| Portable package | Required package files and install contract are coherent. | `portable-core/verify.py` and `tests/entry_checks.py` below. |
| Selected candidate CLI | One pinned offline PCAP execution satisfies its frozen semantic oracle and cleanup contract. | [`CURRENT-CLI-PROFILE.md`](CURRENT-CLI-PROFILE.md). |
| Runtime MCP configuration | Router + 20 configured backends; installed readiness and real provider operations require separate evidence. | [`BOOTSTRAP.md`](BOOTSTRAP.md). |
| Historical library release | The 2026-11-11 verdict and its 295-row inventory classification remain as recorded. | [`RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md). |

The 295 inventory rows include scripts, skills, notes and metadata; they are not
295 runnable tools. A passing bounded profile does not replace the historical
release verdict or establish whole-product completion. Candidate code is local
until its adoption and publication are separately recorded.

### Package commands

```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
```

Exit 0 + `VERDICT=PASS` is the package check. Anything else is a finding, not a
local detail to be patched away.

**Taking over from the current clone — shortest path.** `repo_root` = the directory
holding `skills/` in the clone you just made; nothing below resolves against a research
archive, a private wiki, or a pinned publish SHA.

1. Read [`skills/2026-11-11/portable-core/SKILL.md`](../skills/2026-11-11/portable-core/SKILL.md)
   — deploy / add-to-harness / test / self-repair / diagnose.
2. Run the package check above, plus the install contract:
   `python -X utf8 skills/2026-11-11/portable-core/tests/entry_checks.py`.
   Both call one validator — `skills/2026-11-11/portable-core/tests/package_contract.py`.
   A missing required file reports `MISSING_REQUIRED=<path>` and exits 1 (never a
   traceback), and the required closure includes `LICENSE` and the reference files.
3. Read [`releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)
   and quote it verbatim. A green verifier does not change `RELEASE_GATE=RED`.

**Canonical skill name.** The install dir must equal the frontmatter `name`:
`portable-core`. `debuggerstation-selfdeploy` is the 2026-11-11 research-run alias —
archived only, never an install target, never a live command argument.

**Selected real CLI acceptance.** For the candidate runner that binds a pre-run plan, actual process execution, retained artifacts and a semantic oracle, follow [`CURRENT-CLI-PROFILE.md`](CURRENT-CLI-PROFILE.md). Its bounded result is separate from the package check and historical release gate.

## 4. Standing rules an agent must not learn the hard way

- **Ask before acting.** Explore read-only, ask the clarifying questions, present a
  plan; only then run `scripts/bootstrap.ps1`.
- **This repository ships no third-party tool binaries.** Tools are fetched from
  their official sources via `manifests/` + `scripts/bootstrap.ps1` /
  `scripts/download-tools.ps1`.
- **Never silent-install.** Drivers, services, Npcap, Defender / registry / startup
  changes, untrusted samples: state consequence + rollback first, then act on
  confirmation.
- **RED is reported as RED; scope and date are explicit.** The 2026-11-11 release records
  `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, **268** structural
  blockers (295 inventory claims: 27 REAL / 102 DECLARED / 151 OWNER_GATED /
  15 MISSING). Keep that historical classification intact; report new acceptance
  separately. An unverified claim is never quoted as a capability.
- **HARD BAN — vrc family.** `vrc-dcc` / `vrc-review` / `vrc-world` /
  `overlays/vrc-dcc` are retired (2026-09-19). Never restore them; never write a
  VRC overlay.
- **No credential values, no raw corpora.** Not in reports, commits, or notes.
- Git commits stay English; the contract changes in git, not in chat.

## 5. Where the rest is

- [`docs/INDEX.md`](INDEX.md) — classification index for `.agent/`, `evidence/`, `docs/`.
- [`docs/MAINTAIN.md`](MAINTAIN.md) — maintaining this clone.
- [`docs/BOOTSTRAP.md`](BOOTSTRAP.md) — install-root copy + project MCP layout.
- [`docs/TOOLS_INDEX.md`](TOOLS_INDEX.md) — tools after bootstrap.
