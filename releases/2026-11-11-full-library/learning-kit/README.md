OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/README.md

# Hash-locked file set — sanitised public learning kit

SYNTHETIC, self-contained, adoptable in a fresh clone. Everything here is
fabricated for teaching; there are no credentials, no real private paths, no
account names, no tokens, no whole conversation text, and no copy of any real
product source. Paths that look like hosts use the reserved `example.invalid`
domain.

## Placement (this is a NEW subdirectory, NOT a root overwrite)

The existing public repo is populated (518 files, dual licence already present,
4-language root docs, 8 lab dirs). This kit is proposed to land as ONE new
subdirectory `learning-kit/` on `main`. It MUST NOT overwrite `LICENSE` or
`LICENSE-docs`, MUST NOT replace or reorder the 4-language README/AGENTS, and
MUST NOT resurrect any historical `_scratch_*` audit fixtures. Adding this one
directory is the ONLY intended change of the release commit.

## What you get

- `SKILL.md` — teaches ONE verifiable capability (one command, one denominator,
  one falsifier).
- `check.py` — the runnable gate; `python check.py` from this directory.
- `examples/` — two SYNTHETIC fixtures with `.sha256` sidecars.
- `tools.json` — the MCP tool surface this capability exposes.
- `RECEIPT-SCHEMA.md` — the shape of a run receipt.
- `QA-GATES.md` — the four minimum-gate groups + method constraints, teaching
  version of the repo-QA model (26 gates, NOT-EXECUTED never passed).
- `KB-TO-BEHAVIOUR.md` — the knowledge-to-behaviour model (discovery → tutorial
  → implementation → machine test → receipt → gate → report).
- `PUBLIC-FACTS.md` — the read-only staging facts the package is allowed to cite.
- `LICENSE-NOTE.md` — dual licence: MIT (code), CC BY-SA 4.0 (docs).
- `CHANGELOG.md` — the continuous-update ledger.
- `BRIDGE.md` — the bridge test → optimise → iterate loop.
- `INCLUDE-MANIFEST.tsv` / `EXCLUDE-LOG.tsv` — what is in/out and why.

## Quickstart

Copy this directory into a fresh clone. From inside it run the single command
documented in `SKILL.md`. It recomputes each fixture hash from bytes and compares
to the sidecar; a one-byte in-memory tamper is rejected. Nothing is written and
nothing touches the network.

## No-noise contract

A claim counts only if a command prints it. The manifest has exactly one row per
file (no duplicate same-path rows). The test is not a tautology: it recomputes
from bytes and must go red on a crafted bad sample. A green that cannot go red
is rejected.

## Scope

This is a Worker-scope release PROPOSAL. Publication (copy + one commit + push)
is carried out by the parent ONLY after the 5-condition gate is GREEN. This kit
itself performs NO push, NO `gh` write, NO repo action.
