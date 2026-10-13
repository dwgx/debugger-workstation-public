---
name: debugger-review
description: >-
  逆向工程作业的双轴评审与事后学习。完成 unpack/RE/引导/工具下载类活后自动应用；
  用户说 debugger review / 评分 / 进化 / 收尾 时应用。写 Reports/ 与 notes/。
---

# debugger-review

Read `AGENTS.md` then `docs/AGENT_EVOLUTION.md`. This skill is **review + memory**, not a second constitution.

## Axes (always both)

**Standard:** correctness, security, style, no drive-by. Security defaults to guilty until a negative check exists (did not run the sample on the host, did not merge 19 MCP backends into user-global config, did not commit `.env` / dumps).

**Spec:** the clone owner's asked slice is present; extra scope is a finding. Tests/smoke that were named were actually run.

## Loop

1. Restate the mission in one sentence (install / unpack / triage / MCP / docs).
2. List evidence with path + command + exit. Do not upgrade to `verified` without current reconciliation — and note that a self-check is reconciliation of what you wrote, not verification of what you missed (see *Self-check is not verification* below).
3. Score 0–10 on each axis. Overall = min(standard, spec) if either has a **critical**; else weighted mean (spec 0.55, standard 0.45).
4. Findings first, ranked. Critical blocks "done".
5. **Evolve:** if the next agent would repeat a mistake, append `notes/YYYY-MM-DD-slug.md` and link `notes/INDEX.md`. If it is a standing rule, patch `docs/EXPERT_PLAYBOOK.md` or this skill — not chat.
6. Refresh `docs/TOOLS_INDEX.md` or `Reports/` when tools/MCP changed (`WORKSTATION_RULES.md` update flow).

### Stop-Search — how much evidence is enough (2026-10-12, from the prompt-research round)

Step 2 above can run forever. Bounded rule:

- **Enough** when: you can name the exact files/commands that decide each axis, AND the top
  signals converge on one verdict (~70% agreement). Then stop collecting and write the review.
- **Budget**: exploration (searches, re-reads, re-runs) ≤ 12 tool calls for a normal slice.
  Declared batches (per-axis evidence sweeps) may exceed it; hard ceiling 40.
- **Escape hatch**: if the budget ends without convergence, score with the evidence you have
  and say so in the review ("verdict at budget, could not settle X") — do not silently drop it.
  *Source: OpenAI GPT-5 cookbook `context_gathering`; the same round measured that unbounded
  "explore thoroughly" instructions produce over-run, and bounded ones produce over-shallow.*

### Self-check is not verification — who checks the checker (2026-10-13, from the dxgkrnl root-cause round)

A re-check script that asserts what you already wrote is a **regression net**, not a review.
It answers "did what I fixed stay fixed", never "what did I not think of".

Measured case, same day, same material: a 23-assertion re-check passed, the note was marked
`status: verified`, and an adversarial pass then found **4 wrong supporting claims** — including
two the author had no reason to doubt (a field's type, and a branch target misread as a return).

- **Outbound material** (issue / PR / mail / report): before it leaves the machine, run one
  `verifier` whose task text says **falsify**, not confirm. A confirm-shaped brief gets a nod.
- **The self-check stays** — but label the artifact by what it survived:
  self-checked only → `observed`; adversarial-checked → `verified`.
- **Ask the verifier for a counter-finding list**, not a score. "No findings" is only meaningful
  when the brief named the falsification angles (alternative call sites, omitted writers,
  misread branch targets).

*Rule of thumb: the check that can prove you right and the check that can find what you missed are
different checks. Running only the first raises error rates, because it buys false certainty.*

### Contradiction scan — one mechanical step before scoring

Rules and docs accumulate contradictions. **GPT-5 official measurement: conflicting
instructions burn reasoning tokens reconciling them, and get *worse* on stronger models.**
Before scoring a doc-writing slice:

1. `grep` the key verdict words the slice touches (e.g. `不许`, `必须`, `可以`, `禁止`) across
   the edited files and their cross-references — two hits with opposite verdicts = a finding.
2. A contradiction found in the docs being reviewed is a **Standard-axis finding**, not a note.

*Live example from this round: `翻车.md` said "重活父代自己算" while `派发.md` said the
opposite — fixed 2026-10-12.*

### Preamble discipline — what the review itself must contain

*Source: OpenAI `tool_preambles` (measured: the longer the rollout, the bigger the effect).*

- **Open with**: one-sentence mission restatement + the 3–5 step plan (this IS step 1 above).
- **Close with**: completed-vs-plan written **separately** — which items matched the plan,
  which deviated and why. A mixed summary hides the deviation from the reader who wrote the plan.
- Every claim in the review cites path + command; every score cites what moved it.

## MCP

Policy lives in `skill://debugger-workstation` §7 — one place to change it. Headline: debugger-router only, never `mcp-all` in user config, no second IDA server.

## Outputs

- `Reports/<date>-review.md` — scores, findings, leftover risk (local; not for git).
- `notes/` — durable facts (Defender PUA, missing binary, pin drift).
- Chat — resolved locale to the clone owner; one paragraph of scores then findings.
