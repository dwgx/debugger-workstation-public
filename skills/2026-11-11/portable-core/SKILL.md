---
name: portable-core
description: Deploy a debugger-station / WorkStation repo from a single entry, add this skill to your own harness, run the verification tests, self-repair tool and environment failures, and self-diagnose from official+community fix knowledge. Use when an AI is handed the repo, when SKILL.md/AGENTS.md is missing or deleted, when shell/encoding/glob/exit-code probes fail, or when a fix must be looked up before applying. NOT for vrc-dcc/VRC overlays, NOT for live hosts or bounty targets, NOT a claim that all capabilities work.
license: MIT
compatibility: "Python 3.10+ with stdlib only for the verify scripts (pathlib/re/subprocess/sys); git required for repo and HEAD probes; optional gh CLI used READ-ONLY (search/view) and never to write a remote; Windows + Git-Bash paths assumed at the station, POSIX fine for verify.py; no network needed to run the tests."
metadata:
  version: "1"
  last-reviewed: "2026-11-11"
  spec: "agentskills.io/specification"
  owner: "parent (took over stalled PackageDesign slice) | package/SKILL.md"
---
# portable-core — portable CORE (router stays at the station)

This skill is the **portable CORE**, not the station router. The 2 machine skills
(`debugger-workstation`, `debugger-review`) are station-bound: their authoritative
files live under the station's `debugger/` dir (`.agent/*`, `manifests/*.json`,
`scripts/bootstrap.ps1`, MCP `debugger-router`). Revive those at the station via a
scoped Worker; ship THIS package to any AI harness.

**Canonical install name: `portable-core`.** Frontmatter `name` must equal the install
dir name. `debuggerstation-selfdeploy` is the 2026-11-11 research-run alias — archived
only; never an install target, never a live command argument.

## Trigger branches (one per branch, front-loaded, per writing-for-agents S7)
- **Deploy** — AI is handed the repo → read `SELF-DEPLOY.md`, run ONE env self-check, ONE clone+verify.
- **Add to harness** — copy this dir as a skill dir named exactly `portable-core` (if you rename the dir, rename the frontmatter `name` with it); `name` must match the install dir (SmartCLI S18); steps in `references/INSTALL.md`; then read `AGENTS.md`.
- **Test** — run `scripts/verify.py` (same check as the `## Verify` command below); exit 0 + measured numbers required.
- **Self-repair** — tool/env failure → official fixes first, then community fixes (`references/FIX-KB.md`), dry-run first, re-run tests, rollback point in `SELF-REPAIR.md`.
- **Diagnose** — a fix has no verify command or no date → `[UNVERIFIED]`, never auto-apply.

## Non-negotiable invariants
- `RELEASE_GATE=RED`, `COMPLETENESS_VERDICT=NOT_COMPLETE`, 295 claims = 27 REAL / 102 DECLARED / 151 OWNER_GATED / 15 MISSING, 268 blockers (S8/S14, 2026-11-11). **Unverified ≠ usable.** Strict in-package receipt resolvability = **0/27** (prior verifier D3, S9); 6/27 is only a weak filename inference, never quote it as the public number.
- **HARD BAN**: `vrc-dcc` / `vrc-review` / `vrc-world` / `overlays/vrc-dcc` are retired (S4/S5, 2026-09-19). Never restore, never write a VRC overlay.
- 4 PRIVATE repos (`debugger-workstation`, `debugger-workstation-cache`, `workstation`, `hackerone`) NEVER change visibility. No credential values, no raw corpora `ChatGPT-*.json`, no Hackerone KB source text, no `.jsonl`, no `THINK/mandate.md`.
- High-risk drivers / Npcap / Defender / samples: consequence + rollback written first, **never silent-install** (S1/S2, 2026-10-28).
- Remote actions (push / Pages / settings / visibility) are `[NOT EXECUTED]` here; they need a separate Owner sentence + scoped Worker.

## Spec conformance (agentskills.io/specification, read 2026-11-11)
- Frontmatter: `name` (1-64 lowercase/digits/hyphens, no `--`, equal to the install dir name), `description` (1-1024: what + when + NOT-for), `license: MIT`, `compatibility` (≤500 chars), `metadata` as a **string→string** map — `metadata.version` and `metadata.last-reviewed` are strings by spec, never an int or a bare date.
- Progressive disclosure: frontmatter ~100 tokens → this body <5000 tokens / <500 lines → `references/` + `scripts/` loaded on demand; every reference from THIS file is one level deep.
- Validate after install: `skills-ref validate ./portable-core` (see `references/INSTALL.md`).

## Context pointers (all one level from this skill root)
- `AGENTS.md` — harness pointer.
- `SELF-DEPLOY.md` — one-shot deploy entry.
- `SELF-REPAIR.md` — symptom → fix → verify → rollback loop.
- `references/FIX-KB.md` — how to read the official + community fix tables (rows stay in their own tables, never copied here).
- `references/VERIFY.md` — what the ONE `## Verify` runs, what it prints, how to read RED.
- `references/INSTALL.md` — install dir naming + `skills-ref validate`.
- `references/PRIOR-WAVE.md` — earlier-wave artifacts, by pointer only.
- `scripts/verify.py` — re-runnable verifier entry for harnesses that only load `scripts/`.
- `tests/entry_checks.py` — install contract: the four fake-green counterexamples (missing `references/INSTALL.md`, dir name ≠ `name`, live absolute research path, stale publish SHA) on temp copies.
- `README.md` / `README.zh-CN.md` — zh/en reciprocal intro.
- `LICENSE` — MIT.

## Verify
From the clone root (`repo_root` = the dir holding `skills/`):
```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
```
Exit 0 + `VERDICT=PASS` is the package contract. The install contract is separate:
`tests/entry_checks.py` runs the four fake-green counterexamples (missing
`references/INSTALL.md`, dir name ≠ frontmatter `name`, live absolute research path,
stale publish SHA) on temp copies. See `references/VERIFY.md`.
