# debugger-workstation

<!-- I18N:START -->
**English** · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md)
<!-- I18N:END -->

## Start here

1. **Clone**, then read [`AGENTS.md`](AGENTS.md) — the authoritative AI contract (ask-then-act, stop lines).
2. **Dry run only:** `pwsh scripts/bootstrap.ps1 -InstallRoot "D:\Tool\debugger"` — prints the plan, writes and downloads nothing.
3. **What actually shipped:** [`releases/2026-11-11-full-library/README.md`](releases/2026-11-11-full-library/README.md) and its [`RELEASE-GATE-STATUS.md`](releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md) — `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, **268 blockers**; publishing does not change either fact.
4. **Skills:** [`skills/2026-11-11/`](skills/2026-11-11/) — portable core + station routers; check with `python -X utf8 skills/2026-11-11/portable-core/verify.py`.
5. **AI entry point:** [`docs/AI_ENTRY.md`](docs/AI_ENTRY.md) · what changed: [`CHANGELOG.md`](CHANGELOG.md) · releases: [`RELEASE.md`](RELEASE.md).

A **skeleton repository** for a portable reverse-engineering / security-analysis / debugging / unpacking / mobile-analysis / network-capture / system-inspection / MCP-automation workstation.

Any agent (Claude / Codex / Gemini / Cursor / Copilot) or human can clone this repo and reconstruct, on their own machine, a tooling station that is **optimized for AI to drive** — following the docs and manifests here. This tree is a **reference skeleton**: the clone owner keeps their own tools and prompts (`OWNER.example.md` → gitignored `OWNER.md`). Agents may **self-maintain this clone** when the owner asks; stop lines cannot be waived in chat ([docs/MAINTAIN.md](docs/MAINTAIN.md)).

After a job, agents score the slice (`skills/debugger-review`) and write `notes/` so the next session does not rediscover the same failure (Windows in-place `mcp`/`MCP`, Defender PUA, lazy MCP). See [docs/AGENT_EVOLUTION.md](docs/AGENT_EVOLUTION.md).

> 📍 **Operating this station: start at [`.agent/HANDOFF.md`](.agent/HANDOFF.md).** It carries the
> one rule everything else follows from, the four-command workflow, the capability table,
> the traps in this repo's own tooling, and what is deliberately *not* claimed.
> `.agent/RECOVERY-STATION.md` holds the measured detail behind it. Both are tracked on
> purpose — they are the only artifacts that survive a lost machine.

> ⚠️ **This repository ships no third-party tool binaries.** Tools are fetched from each official source via `manifests/` + `scripts/bootstrap.ps1`. See [DISCLAIMER.md](DISCLAIMER.md).

---

## What's in this repo

| Path | Contents |
| --- | --- |
| `AGENTS.md` | **Authoritative entry** for all AI agents — initialization handshake (ask-then-act), clone-owner overlay, MCP strategy, stop lines. Localized: `AGENTS.zh-CN.md` / `AGENTS.ja.md` / `AGENTS.ko.md`. See [docs/I18N.md](docs/I18N.md) and [docs/MAINTAIN.md](docs/MAINTAIN.md). |
| `OWNER.example.md` | Template for gitignored `OWNER.md` — this clone's prompt pack. |
| `docs/EVAL.md` | Static contract eval rubric (`scripts/eval-agent-contract.py`) |
| `docs/BOOTSTRAP.md` | InstallRoot copy + project MCP (router-only vs inventory) |
| `CLAUDE.md` / `GEMINI.md` / `.github/copilot-instructions.md` / `.cursor/rules/` | Per-client entry files, all pointing to `AGENTS.md`. |
| `templates/INIT_QUESTIONNAIRE.md` | The clarifying-questions checklist that drives dynamic initialization. |
| `docs/` | Human- and AI-facing docs. After-action: `docs/AGENT_EVOLUTION.md`. |
| `skills/debugger-review/` | Dual-axis review + learning loop for agents. |
| `notes/` | Short durable facts (no samples, no secrets). |
| `docs/extensions/INDEX.md` | Curated index of MCP servers / AI skills you can add. |
| `manifests/tools.json` | Tool manifest: name, version, official download source, install path. |
| `manifests/mcp-backends.json` | Third-party MCP backend upstreams + the self-developed core. |
| `mcp/debugger-router/server.py` | **Self-developed** lightweight MCP router (starts backends on demand; the only MCP enabled by default). |
| `mcp/bin/*.cmd` | **Self-developed** backend MCP wrapper scripts (relative paths, portable). |
| `mcp/.mcp.json.template` | MCP config template; bootstrap substitutes `{{DEBUGGER_ROOT}}`. |
| `scripts/bootstrap.ps1` | Reconstructs the workstation from the manifests (dry-run by default). |
| `scripts/download-tools.ps1` | Optional official GitHub/direct downloads (`-Apply`). Npcap installer is fetched, not installed. |
| `scripts/restore-from-cache.ps1` | Unpack an optional **private** zip cache you maintain yourself ([docs/CACHE.md](docs/CACHE.md)). Not required for a public clone. |

**Not included** (hard-excluded by `.gitignore`): tool binaries, `.env`/credentials, `.venv`/`node_modules`/runtimes, samples/pcap/dumps, scratch workspaces, local git history.

## Quick start

```powershell
# 1. dry-run: show the plan only, no writes, no downloads
pwsh scripts\bootstrap.ps1 -InstallRoot "D:\Tool\debugger"

# 2. once the plan looks right: deploy the self-developed MCP, generate local config, clone third-party MCPs
pwsh scripts\bootstrap.ps1 -Apply -CloneMcp -InstallRoot "D:\Tool\debugger"

# 3. download tool binaries (uses gh when available)
powershell -File scripts\download-tools.ps1 -Apply

# 4. rebuild each third-party MCP's .venv / dotnet / node dependencies, then smoke-test
```

> Windows PowerShell 5.1 also works (the script is UTF-8 BOM). Prefer PowerShell 7 (`pwsh`).

## What a fresh clone does not have

Everything below was measured on 2026-10-03 against a pristine `git archive HEAD` export (383 tracked
files) — not against this workstation, which has been built for a month.

**A clone ships 383 files and zero build products.** `.gitignore` excludes every `out/` directory, so
`crackme-corpus/out/`, `managed-lab/out/` and `headless-lab/out/` are empty directories that do not
even exist. That exclusion is deliberate and permanent: `crackme-corpus/README.md` states `out/` holds
compiled binaries plus ~1500 machine-generated decompiled C files and "exporting decompiled C into git
is forbidden by the station charter. The sources are the product."

**`scripts/bootstrap.ps1` does not build any of it.** Read what it actually does: it copies
`manifests/ skills/ docs/ scripts/ templates/` plus a fixed list of root files, generates `.mcp.json`,
clones third-party MCP upstreams, and creates **exactly one** virtualenv — `mcp/debugger-router/.venv`,
the only MCP enabled by default. It prints the official download URL for each third-party tool and
downloads none of them. No lab output directory is produced by any script in `scripts/`.

### Step 1 — build the corpus, from inside `crackme-corpus/`

This is the one build step nothing else does for you, and **11 of the 21 executable proofs in
`manifests/capabilities.json` read a binary out of it.**

```powershell
cd crackme-corpus
python tools\loop.py
```

Run it from **inside** `crackme-corpus/`, not from the repo root. `loop.py` passes `-OutDir "out"` as a
relative path and `build-c.ps1` resolves it against the current directory. Measured: from the repo root
the binaries land in `<repo>\out\` while the solvers look in `crackme-corpus\out\`, so the run reports
`PASS build c01` followed by `FAIL solve c01` against a file that was never built.
`scripts/crackme-corpus.ps1` dispatches the same runner and does not change the working directory, so
the same rule applies.

It needs four things, **none of which is in this repository**:

| Needs | Where the code demands it | What a fresh clone says |
|---|---|---|
| MSVC 2022 (`vcvars64.bat`) | `crackme-corpus/tools/build-c.ps1` probes five fixed `VC\Auxiliary\Build\vcvars64.bat` paths; there is no gcc on this design | not installed by any script here |
| Ghidra headless | `scripts/ghidra-headless.ps1` hardcodes `Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat` | `missing <that path>` |
| radare2 + rabin2 | `crackme-corpus/tools/labkit.py` pins `Static-Reversing\radare2\radare2-6.2.2-w64\bin\` | `radare2 not found at <that path>` |
| .NET SDK + ilspycmd | `loop.py` shells out to `dotnet build` for the c04 challenge, then probes `Static-Reversing\ilspycmd\ilspycmd.exe` | not installed by any script here |

`scripts/download-tools.ps1 -Apply` fetches radare2, Ghidra and ilspycmd from their official releases. It
does **not** install MSVC or the .NET SDK, and it has no job for Detect It Easy at all.

Cost, measured: `python tools\loop.py --no-ghidra` on the pristine export takes **8 s** of wall clock and
reports `PASS build` five times. The full run on this machine is recorded in the tracked evidence log
`evidence/probes/re.corpus.solve.probe.log`: **exit 0 in 132.29 s**. Without Ghidra the four native
challenges cannot close — they fail with `no ghidra export at ...-ghidra\decompiled`, which is a missing
prerequisite, not a corpus defect.

### Step 2 — install the third-party tools the other proofs call

Same table, one row further down: `rabin2`, `capa`, `diec` and Ghidra headless are named by absolute
path inside `native-lab/tools/`, `headless-lab/tools/` and `scripts/`. A fresh clone answers
`capa not found at <path>`, `diec.exe not found at <path>`, `ghidra headless not found at <path>`.
`manifests/tools.json` lists every one with its official source and version; `download-tools.ps1` covers
all of them except DiE.

### What is still BLOCKED after all of that

State this plainly so a half-green sweep is not read as a broken registry:

* **6 of the 27 capabilities are skipped by design** — `assert-probes.py` never runs them and prints
  why: the two `native.ida.*` entries are driven through the `idalib-mcp` MCP device rather than a CLI
  command, `dynamic.device.frida` needs an attached device, `native.il2cpp.symbols` needs an extracted
  metadata dump, `native.crosscompare.ghidra` is `planned` with no runnable command, and
  `native.ghidra.emulate` is `blocked` on a runtime the registry does not have. That leaves **21 checked**.
* **11 of those 21 read a `crackme-corpus/out/` binary** — 10 name the path directly in `probe.command`
  or `probe.prepare`; `native.ghidra.decompile` reaches it through `scripts/ghidra-failopen-regress.ps1`,
  whose first line used to pin an **absolute** `$repo = '<repo>'` instead of a path derived
  from the script — on a clone stored anywhere else that probe read a different machine's tree.
* **Measured on the pristine export, a sweep of exactly those 11 entries exits 1 with 14 DRIFT, 4 PREREQ
  and 7 TOOL-FAULT** — over half the checked surface, every failure naming a missing file. After building
  the corpus in that export, 3 of 7 re-run entries went `OK` and 4 stayed DRIFT on `rabin2` / `capa` /
  `diec` / Ghidra headless.

### The failure that invites the wrong repair

All of those failures say the same thing in a different dialect: `no such file:
crackme-corpus\out\c01-stringobf.exe`, `Cannot open file`, `Cannot find path ... because it does not
exist`, `capa not found at <path>`. `assert-probes.py` reads that as a PREREQ or a TOOL-FAULT, and both
are correct. **A missing prerequisite is not a registry defect.**

The wrong repair is to edit the recorded `probe.expect` string until the sweep goes quiet. That has
happened here: an audit found `net.pcap.selfparse`'s `negative_control.expect_output_note` asserting
`0x4d5a is 'MZ'` about a file that begins `23 20` (`"# "`, a markdown header), and the recorded
expectation was edited rather than the original mistake left visible — `.agent/audit/a1/REPORT.md`
finding A1-F3, corrected in commit `77f1151`. An expectation that was true stays true; a build step that
was skipped is a build step. Run `python tools\loop.py` first, re-run the sweep, and only then read a
verdict as a finding.

## For AI agents: read this first

After cloning, resolve the UI locale ([docs/I18N.md](docs/I18N.md)) and **read the matching [AGENTS.md](AGENTS.md)** (`AGENTS.zh-CN.md` / `AGENTS.ja.md` / `AGENTS.ko.md`). Chat in that language. Git commits stay English.

The key idea: when asked to set up the workstation, the AI **does not act immediately**. It explores (read-only), asks clarifying questions (install root, scope, which MCPs, whether to download binaries, AI client, system-level components), presents a plan, and only then — after your confirmation — runs `bootstrap.ps1`.

Further reading:
1. [AGENTS.md](AGENTS.md) — **authoritative entry**: handshake, MCP strategy, boundaries.
2. [templates/INIT_QUESTIONNAIRE.md](templates/INIT_QUESTIONNAIRE.md) — the clarifying-questions checklist.
3. [docs/AI_USAGE_GUIDE.md](docs/AI_USAGE_GUIDE.md) — reading order, what the AI may do on its own.
4. [docs/WORKSTATION_RULES.md](docs/WORKSTATION_RULES.md) — full workstation rules, update/cleanup flow.
5. [manifests/](manifests/) — tool & MCP manifests.
6. [docs/extensions/INDEX.md](docs/extensions/INDEX.md) — extensions you can add.

## MCP strategy

Only `debugger-router` — one lightweight MCP — is enabled by default. It spins up whichever of the 20 backends is needed, on demand, and keeps that backend process warm between calls (one process per `session_id`) until it idles out or is closed. Do not load all backends at once by default. For direct connections, use a profile (`mcp-mobile` / `mcp-re` / `mcp-net` / `mcp-ce` / `mcp-intel` / `mcp-all`).

## Security posture

The toolset includes debuggers, injectors, hooks, Frida, packet capture, and memory-analysis tools that may trigger AV/EDR. For high-risk operations (installing drivers/services/Npcap, modifying registry/Defender/startup, running untrusted samples on the host), the AI will brief you on consequences and rollback before proceeding — it won't silently act or refuse. Intended for security testing, CTFs, reverse engineering, research, and education.

> `bootstrap.ps1 -CloneMcp` clones and builds third-party MCP backends from their upstream repos (a few have no declared license). This is opt-in — review the code you clone before running it.

## License

Two licenses, split by what the file is:

- **Code, configuration, and the agent contract — MIT** ([LICENSE](LICENSE)). Covers `mcp/debugger-router`, `mcp/bin`, `scripts`, `manifests`, `skills`, `templates`, `.github`, `AGENTS*.md` / `CLAUDE.md` / `GEMINI.md`, and every non-Markdown file. Fork it and close your fork — nothing here forces you to publish changes.
- **Documentation prose — CC BY-SA 4.0** ([LICENSE-docs](LICENSE-docs)). Covers `docs/` (including `docs/i18n/`), `README*.md`, `DISCLAIMER*.md`, `notes/`, and the other prose Markdown. Reuse it with attribution; derivative docs stay under the same license.
- Third-party tools and third-party MCPs remain under the copyright and license of their respective upstreams; this repo redistributes none of their code or binaries. See [DISCLAIMER.md](DISCLAIMER.md).

## Contributing & security

- Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
- To report a security issue, see [SECURITY.md](SECURITY.md).
- Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
