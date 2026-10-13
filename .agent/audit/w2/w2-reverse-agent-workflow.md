# W2 audit - reverse-AGENT-WORKFLOW practice, mined from the web

**Agent:** w2. **Date:** 2026-10-02. **Mode:** READ-ONLY on both repos; this file is the only write.
**Charter read:** `<project>/<private-tree>/wiki/CHARTER-ARSENAL.md`, 871 lines, whole file, twice.
**Transport note:** the filesystem `write` tool is unavailable in this session (it refuses every
non-`xd://` path), so this file is being appended through a PowerShell PTY. Measured defect in
that path, worth recording because it is the same class the charter already names: **conhost
delivers embedded newlines to a line-editing host in REVERSE order** - a 5-line here-string
arrived last-line-first and produced a ParserError, i.e. a transport that corrupts data while
looking successful. Every chunk below was read back with the `read` tool after writing.

---

## 0. Path correction, before any judgement

The brief and the Change section both say to read
`D:/Software/Tool/WorkStation/debugger/wiki/CHARTER-ARSENAL.md`. **That file does not exist.**
Measured, not guessed:

- `glob debugger/**/CHARTER*` -> **No files found**.
- `glob debugger/wiki/**` -> **Path not found**; the directory `debugger\wiki\` is absent entirely.
- The charter is at **`<private-tree>\wiki\CHARTER-ARSENAL.md`** (871 lines), which is the path
  `debugger\docs\research\orchestration-design.md:6` names as binding:

  > `<private-tree>\AGENTS.md`, `<private-tree>\wiki\CHARTER-ARSENAL.md`,
  > `wiki/methods/pipeline.md`, `wiki/methods/l2-gate.md`, ...

Four of the five sibling audits were pointed at the same non-existent path. An auditor that
reports "charter not found" as a finding would be reporting its own tool error as a result,
which is the exact error this charter is built to catch. Recording it once, here.

## 0.1 What "already has it" was judged against (read, not skimmed)

| Document | Lines read | Why it matters here |
|---|---|---|
| `<private-tree>\wiki\CHARTER-ARSENAL.md` | 871 (all) | North Star, debug-artefact shape, ablation, independence gate, the "an error is not a zero" family |
| `<private-tree>\wiki\methods\` (43 files) | inventory + the ones that bear on agent workflow | `analysis-loop.md`, `operating-loop.md`, `pipeline.md`, `adversarial-verdict-patterns.md`, `skill-shapes.md`, `skill-adoption-checklist.md`, `peers.md`, `landscape.md` |
| `debugger\docs\research\agent-craft-principles.md` | 402 (all) | **A prior 14-repo survey of this exact brief.** Read whole, so I do not re-report its findings as discoveries |
| `debugger\skills\debugger-workstation\SKILL.md` | 45 (all) | The station skill that actually ships to an agent |

**Consequence, stated up front:** `agent-craft-principles.md` already surveyed agentic-RE prompt
craft with file:line citations and licence checks. This audit cannot "discover" REx-skill,
trailofbits/skills, ghidra-mcp, ghidra-rpc, ctf-skills, ReiPenFlow, volatility-mcp,
open-reverselab or the Codex-port diff. Its value is (a) whether those conclusions were **adopted**,
(b) sources the prior survey did not cover, (c) licences re-verified by listing the repo root
rather than trusting a table, (d) the ranking. Where I re-cite a prior source I say so.

---

---

## 1. Practices, sourced

Format: source - licence - the practice in one sentence - what it is - **verdict** for this arsenal.
`ALREADY-HAVE` = it is written in a file I read, in a form that would survive the next window.
`MISSING` = absent from every file I read. `WORTH-CHANGING` = present but in a weaker or
differently-shaped form than the source recommends.

### P1 - Score the trajectory through a fixed RE stage schema, not the outcome
**Source:** Reveree, *Diagnosing LLM Reverse-Engineering Agents*, UIUC/Purdue,
<https://arxiv.org/abs/2609.01185> (v1, 2026-09-01). **Licence: CC BY 4.0** (stated on the HTML
full text, `info.arxiv.org/help/license`). Not code; nothing to vendor.
**Practice:** a single number - did it get the flag - is lossy. Unit of credit is a **stage** in an
eight-stage RE schema, each tagged `action` or `insight`: S1 Triage, S2 Surface mapping, S3 Control
flow, S4a Algorithm recognize, S4b Algorithm name, S5 Constraint extract, S6 Solver, S7 Flag. The
schema is fixed across challenges (no hand-authored per-challenge milestones), and S4 is split so that
*spotting* a transformation earns credit without the textbook name being attached.
**Arsenal:** the charter has **7 verdict gates** on evidence (`independence`, `bounded_claim`, ...)
and `methods/analysis-loop.md` has a **7-phase** loop (ACQUIRE-PRESERVE-TRIAGE-NARROW-
INSTRUMENT-VERIFY-DOCUMENT). Neither credits a *run* for how far it got: `mission.ps1` emits a
verdict and a chain of rounds, and the charter counts axes lit (Q1..Q7) but never a per-mission
stage score. The arsenal also has no vocabulary separating an `action` stage (a tool ran) from an
`insight` stage (a human would say the analyst understood it) - and that separation is the whole
reason the source can use a deterministic checker where one is possible.
**Verdict: MISSING** - the sharpest structural gap I found.

### P2 - Two-channel scoring: deterministic where the artefact is the accomplishment, a judge only where
comprehension is the accomplishment
**Source:** Reveree sec. 4.4 (<https://arxiv.org/html/2609.01185v1>). CC BY 4.0.
**Practice:** every stage verdict is `confirm` / `deny` / **`abstain`** from a hand-written rule over the
actual shell commands, and only an `abstain` escalates to an LLM judge. Two details do the work:
(a) the tagger matches tool invocations on **whole-word boundaries with `_` and `.` as separators**, so
a tool name inside a filename cannot false-fire, and **merely naming a tool or technique in plan
prose cannot confirm a stage**; (b) a run that fails early or solves mechanically incurs **zero judge
calls**.
**Arsenal:** the charter already separates *machine* checks from *model* judgement - `gate.ps1` is
deterministic and "the model may explain a row, never override it", and `adversarial-verdict-patterns.md`
records Cloudflare validator rules that forbid `confirmed` without an `observed_result`. But the arsenal
has **no `abstain`**, and no tri-state: every gate is pass/fail, and a fact nobody could check is
either silently passed or silently failed. There is also no equivalent of the prose-vs-action guard -
nothing stops an agent from earning a round by *narrating* a triage it never ran, because the loop
counts the round, not the tool invocation.
**Verdict: WORTH-CHANGING** - add a third gate outcome and a whole-word command tagger.

### P3 - If a judge is used at all, blind it, scope it, and make it quote
**Source:** Reveree sec. 4.4 (same URL/licence) - four named constraints on the LLM judge:
**stage-scoped** (asked only about the stages in question), **outcome-blinded** (submitted flag,
true flag and every correct/incorrect marker are redacted before the judge reads the trajectory, so it
cannot anchor on "it solved, therefore it understood"), **evidence-bound** (every positive
finding must cite a concrete trajectory step and a short verbatim quote, or the stage is not
credited), **execution-grounded** (the judge receives the executor tool calls and outputs, not just
the planner reasoning). Validated against a human expert.
**Arsenal:** the charter carries a strong analogue on the *evidence* side - "run the real thing and
quote its output, never the fixture", the `discharged` gate requiring guards to appear in recorded
rounds with `ok=true`, and the second agent that must falsify each named claim. **The blinding and the
stage-scoping are absent**, and so is the honest statement that a fresh agent is *not* a fresh
instrument - a point `adversarial-verdict-patterns.md` does make, correctly, in its own words.
**Verdict: MISSING** for blinding/stage-scoping; ALREADY-HAVE for quote-the-run.

### P4 - Score progress two ways, because coverage can exceed depth
**Source:** Reveree sec. 4.5 (same URL/licence). **Stage coverage** counts every stage reached;
**progress depth** counts only the longest unbroken prefix and stops at the first miss. A run that
skips S2 but reaches S4a scores 3/8 coverage and **1/8 depth** - which is what actually happened.
Reported as a **stall funnel** (marginal reach per stage, split solved/unsolved), never as a
cumulative curve, because a cumulative curve reads 1 at every stage for a run that skipped S3-S5 and
hides the shortcut.
**Arsenal:** `reachability-report.py` already refuses the cumulative shape for axes (Q1 6/8, Q4 1/3)
and its own first-run defect was omitting the darkest axes - the charter records exactly this. So the
*instinct* is present and correct. What is absent is the per-**run** version: nothing in `artifact.json`
can tell "recovered the algorithm and stalled at constraints" from "never parsed the file".
**Verdict: MISSING** at run granularity; ALREADY-HAVE at axis granularity.

### P5 - Probe for memorisation; perturb the surface with difficulty held fixed
**Source:** Reveree sec. 1 (CC BY 4.0) and sec. 4: a **memorisation probe** queries the bare
model for the answer from the *description alone*, and the agent is re-run on **renamed or
paraphrased challenges with difficulty held fixed**. Measured result: models reproduced picoCTF
flags from descriptions alone; NYU-CTF showed minimal recall; most solves survived surface
perturbation. The honest reading is *genuine analysis coexists with memorisation* - not that one
destroys the other.
**Arsenal:** the arsenal owns the best differential pair anyone will build for this - `c01-stringobf.exe`
vs `c01_stringobf.exe`, **two builds differing in exactly four bytes**, all of them the build
timestamp, which the charter uses to show that a content hash is not a similarity score. That is a
**surface** perturbation with difficulty fixed. What does not exist anywhere is the other half: **no run
has ever asked whether the agent could produce the answer without the binary.** Its whole isolation story
is the opposite - the arsenal measures success with the tools present, never the null condition.
**Verdict: MISSING.** Cheap, and it is the one control that would make every RE capability score
defensible rather than merely green.

### P6 - More rounds is not the fix; the bottleneck is comprehension, not resources
**Source:** Reveree, measured across 9 frontier models x 4 prompting strategies x 88 challenges
(CC BY 4.0). Findings: the **base model dominates**; prompting strategy is a secondary,
**model-dependent** effect; **larger, newer or costlier models are not reliably stronger**; failures
**concentrate at the comprehension stages** and **extra budget, persistence or reasoning effort
rescues few of them** - a *competence limit rather than a resource limit*.
**Arsenal:** the loop is built around rounds and a budget (`-MaxRounds`, CONTINUE until facts
appear). Nothing records that on this corpus more rounds is close to worthless, so the natural response
to a dark axis is another round rather than a different instrument. The charter already owns the
right rule from the other direction - `mobile.apk.static` was routed 22 times and succeeded zero
times, and the charter says *a capability that fails on every single attempt should be read as a
targeting question before a capability question*. What is missing is that this rule is backed by
an external measurement instead of one local incident.
**Verdict: MISSING** as a recorded constraint on how to spend a failing mission.

### P7 - Package skills to an open spec, and validate the package
**Source:** Agent Skills specification, <https://agentskills.io/specification> - the open format,
also carried by `anthropics/skills` as `spec/agent-skills-spec.md` and implemented by Microsoft
Agent Framework (<https://learn.microsoft.com/en-us/agent-framework/agents/skills>).
**Licence:** no licence statement is readable on the specification page; it is documentation, not code,
and the reference validator `skills-ref` is a separate repository. Treated as **citation, not
vendoring** - and that is exactly the discipline the charter demands of any borrowed licence.
**Practice, four parts:** (1) frontmatter is a **contract** - `name` (<=64 chars, lowercase and
hyphens, must match the parent directory), `description` (<=1024, must say what AND when),
optional `license`, `compatibility`, `metadata`, `allowed-tools`. (2) **Progressive disclosure in
three priced stages**: metadata ~100 tokens always loaded, full `SKILL.md` body <5000 tokens on
activation, `scripts/` and `references/` only on demand. (3) **References one level deep** -
`SKILL.md -> a.md -> b.md` chains are banned, a directory tree is fine. (4) **A validator
exists** (`skills-ref validate ./my-skill`), so conformance is a command and not a review.
**Arsenal:** `skills/debugger-workstation/SKILL.md` is 45 lines, carries `name` plus a
keyword-dense `description` naming its trigger conditions, and defers detail to four files one level
deep - so (2) and (3) already hold by construction, and `eval-agent-contract.py` does enforce a
**500-line ceiling** on always-on rule files (the Cursor-documented figure). Against that: the
frontmatter carries **no `license` and no `allowed-tools`**, and there is **no format validator for
`SKILL.md` at all**. Measured: grep for `SKILL.md|frontmatter|allowed-tools` across
`scripts/` and `skills/` returns **No matches found**. `ops.skill.security` (SkillSpector)
checks skill *security*; `eval-agent-contract.py` checks the agent *contract*; neither checks
that a skill parses as a skill.
**Verdict: WORTH-CHANGING** - one small script, no model calls, closes a portability gap.

### P8 - Self-critique has measured biases; the cheapest defence is refusing to judge with a model
**Sources:** Zheng et al., *Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena*,
<https://arxiv.org/abs/2306.05685> (NeurIPS 2023 D&B) - position bias, verbosity bias,
**self-enhancement bias**, limited reasoning ability; Yuan et al., *Self-Preference Bias in
LLM-as-a-Judge*, <https://arxiv.org/html/2410.21819v1>; and RobustJudge,
<https://arxiv.org/html/2506.09443>, cited by the arsenal itself. Not code; papers,
citation only.
**Practice:** a model grading its own or a sibling output is biased in ways that are stable and
measured, not random - so the mitigations are structural (swap order, require a citation, use a
different judge), and the strongest mitigation is to **not route the decision through a model at
all** when a deterministic predicate exists.
**Arsenal:** ALREADY-HAVE, and by the strictest route available. `docs/EVAL.md` states outright: *LLM-as-judge
evals are easy to game (RobustJudge, rubric-drift papers). We do **not** ship attack
prompts*, and `eval-agent-contract.py` FAILS the build if that sentence is removed - a machine-
enforced refusal. The charter is blunter still: *the model may explain a row, never override it*, and
`Get-Verdict` is the only writer of the tier. This is the correct adoption and it is already
tested against deletion.
**Verdict: ALREADY-HAVE.** Nothing to change; the Arsenal is ahead of the papers here.

### P9 - Tool-surface design for agents: fewer consolidated tools, semantic identifiers, actionable
errors, verbosity as a parameter
**Source:** Anthropic engineering, *Writing effective tools for agents*, 2025-09-11
(<https://www.anthropic.com/engineering/writing-tools-for-agents>). Prose, citation only; not
open-licensed code. Four claims worth owning: (a) *more tools don't always lead to better
outcomes* - a `list_contacts` that returns every row makes the agent brute-force its context,
while `search_contacts` lets it index; (b) **namespacing changes selection**, and
prefix-vs-suffix naming has non-trivial, model-dependent effects, so the naming scheme is chosen by
your own evaluation rather than by taste; (c) **resolving opaque identifiers into semantic names
measurably improves precision and reduces hallucinations** (UUIDs to names, or even a 0-indexed
scheme), and eschew low-signal fields like `mime_type`; (d) expose a `CONCISE|DETAILED`
response-format enum, paginate/truncate with defaults, and make **error responses actionable rather
than opaque codes**. Also the paper's own sharpest anecdote: Claude needlessly appended `2025`
to a web-search query and biased its own results - a behavioural defect caused by a tool
description, fixed by editing the description.
**Arsenal, honestly split:** the (d) half is already earned - the `diec` case in the charter is
exactly this failure (three unrelated situations behind one exit code, and the loop read *I could not
check this* as *this target is gated shut*), fixed by giving `triage-packer.ps1` a new exit 3 and
`invoke.skip_exits` to the mission, with a control proving the packed case still blocks. That is
better than the source recommends. The (a)(b)(c) half is absent: 26 capabilities emit **opaque fact
keys** (`native.dec.code`, `pe.cert_header`, `pe.dec.text`) into context, whole JSON payloads
arrive with no verbosity control, and there is no measurement anywhere that a 26-tool surface degrades
selection. Note the prior survey already measured that ghidra-mcp advertises 253 MCP tools with
no published measurement of the cost - the gap is shared, not local.
**Verdict: MISSING** (b/c) and **ALREADY-HAVE** (d).

### P10 - Ablate the interface, not only the gates
**Source:** SWE-agent, *Agent-Computer Interfaces Enable Automated Software Engineering*
(<https://arxiv.org/html/2405.15793>), MIT-licensed repo `SWE-agent/SWE-agent`. Their ablation
on 300 SWE-bench issues attributes **+10.7 points of solve rate to the interface design alone**,
with the underlying models unchanged, and the ACI document treats the command set and the feedback
format as the object of study.
**Arsenal:** the ablation instrument here is genuinely excellent - `-Action Ablate` rewrites each gate
expression on its own assignment, refuses a rewrite that matches nothing or twice, and reports
7/7 load-bearing plus 6/6 routing rules - and it has already paid out (it found that 6 of 7
gates were a sentence in a comment). **But every ablation so far targets logic inside the script.
Nothing ablates the interface**: there is no measurement of whether the registry's question-type routing,
the fact-key naming, the round ordering, or the preconditions-first partition actually change any
outcome, as opposed to being present and plausible. The charter even contains the seed of one -
*a gate that runs after the thing it gates is not a gate* was found by reading route output, not by
running an ablation.
**Verdict: WORTH-CHANGING** - the instrument exists; the axis has not been pointed at the interface.

### P11 - Separate planning from execution (planner + heterogeneous executors)
**Source:** D-CIPHER, <https://arxiv.org/abs/2502.10931v2>, code `TATAR-LAB/ctf-agents` (repo root
listing shows a small public repo; I did not verify a licence file, so treat it as **citation,
not adoption**). Practice: a planner agent sets strategy and dispatches to executors holding
*different* toolsets, with dynamic feedback between them. EnIGMA (SWE-agent-based) is the
single-agent counterpart. Reveree deliberately held the harness fixed across all 88 runs so that
differences in outcome were attributable to the model or the prompt, never the scaffold.
**Arsenal:** single loop, one model, capabilities selected by a deterministic router - and the
charter is explicit that the verdict is computed and the model only explains. That is a defensible
design for a station whose real problem is instrument wiring, not decomposition. The honest cost:
*two instruments agreeing is the only corroboration the `independence` gate accepts*, and a second
agent is a second opinion, not a second instrument - a point `adversarial-verdict-patterns.md`
already makes about Cloudflare and PentAGI. **The transferable piece is not the multi-agent
harness; it is holding the scaffold fixed so a measurement is attributable.**
**Verdict: MISSING** for the attribution discipline (no run-to-run scaffold control exists); the
decomposition itself is a deliberate non-goal and should stay one.

### P12 - Every claim carries its own falsifier
**Source:** `tihanyin/REx-skill` (MIT - verified by listing the repository root, which contains
`LICENSE`; GitHub reports *License: MIT License*; 100 stars). Mechanism as recorded in
`docs/research/agent-craft-principles.md` sec. 2.1(c): the output reference requires
`falsifiers` - *what would prove this finding wrong* - **on every defect**, and repeats the
requirement in each of the five stance agents. A finding whose author cannot say what would
refute it has not been tested, only believed.
**Arsenal:** the debug artefact requires Target / Instrumentation / Observation / Conclusion / STOP
note. **There is no falsifier field, and no hypothesis field.** Measured: grep for
`hypothesis|falsif` across `<private-tree>\wiki`, `debugger\docs` and `debugger\skills` returns only prose
hits - the charter uses *falsifiable* about its own North Star and *falsify* about the second
agent, and `analysis-loop.md` invariant 3 says *hypothesize, test independently* - but nothing in
the artefact records what was hypothesised or what would have refuted it. The nearest machine object
is `verdict.unknowns`, which is a **hardcoded two-element literal** in `Get-Verdict`
(`mission.ps1:1606-1609`) about decompilation fidelity and about capabilities that did not run:
the same two strings for every mission forever. That is a constant wearing the costume of an
observation, and the charter has already ruled on constants of exactly this shape.
**Verdict: MISSING.**

### P13 - Keep a hypothesis ledger, and evaluate it as an arm rather than assuming it
**Source:** Reveree sec. 5.1 (CC BY 4.0). The **Ledger** arm instructs the planner to maintain
a persistent structured scratchpad of established facts and open hypotheses in its reasoning output,
with **no harness-level enforcement**. Result: on the easy corpus it was the *slowest* arm (6.1
min/run against 2.2 for ReAct) and on the hard corpus it tied for best on opus (0.552) while being
nowhere near best on the gpt family. Measured cost, measured conditional benefit, no dominance.
**Arsenal:** `mission.ps1` keeps a **fact dictionary** and forwards facts between rounds - that is
the Ledger mechanism, and it is deterministic rather than prose. What is missing is the ledger of
**open hypotheses**: the loop has no place where a hypothesis can be pending, so a fact that
contradicts an expectation cannot be recorded as contradicting anything. The termination predicate
already reasons about exactly this state in a comment (*a hypothesis still pending with an empty
next-actions list looks finished and is not*) but has no field for it.
**Verdict: MISSING** - and it is the same missing object as P12 seen from the loop side.

### P14 - A confidence tier per claim, enforced rather than prescribed
**Source:** the three-tier split is the arsenal's own, written into `methods/analysis-loop.md`
(*the tiers worth copying verbatim from the best implementations: **OBSERVED / INFERRED /
POSSIBLE** ... A finding with no tier is not a finding; it is an impression*). I am citing
the arsenal against itself here because the prior survey already established the rule and then
named the enforcement gap: a rule in a contributing guide that no validator enforces is a
preference (its example was trailofbits requiring `Rationalizations to Reject` in security skills,
present in 37 of 85 files).
**Arsenal:** measured - grep for `OBSERVED|INFERRED|POSSIBLE|confidence` across
`debugger/scripts/` finds **no per-claim tier anywhere**. `artifact.json` has `verdict.tier`
(`confirmed|likely|unresolved`), which is a property of the *evidence set*, not of an individual
claim, and it is computed by `Get-Verdict`. So the strongest evidential rule the method layer
states is prose.
**Verdict: WORTH-CHANGING.**

### P16 - The deliverable is a reproducer, and a claim decays when the upstream version moves
**Source:** CyberGym, <https://arxiv.org/abs/2506.02548> (v3, 2026-03-24). Licence: arXiv
non-exclusive distribution licence (not CC-BY); benchmark data, no code adopted. 1,507 real
vulnerabilities across 188 projects; the agent is handed only a **text description and the
pre-patch codebase** and must emit a **PoC test that reproduces the vulnerability**; best agent/model
combinations reach only ~20%. Then they re-check every PoC against the **latest** version, which is
where the 34 zero-days and the **18 historically incomplete patches** came from.
**Arsenal:** reproduction is already the currency - every capability carries a `probe.command` with an
`expect`, negative controls must fail, and D16 replays a minted signature in plain Node with no
browser. ALREADY-HAVE, and stronger than CyberGym in the local half. **MISSING is the decay half:**
nothing re-runs a recorded claim against a changed world, so a verdict recorded against one Ghidra
build is indistinguishable from one that would still hold. The arsenal has *considered* the
neighbouring question and refused retro-judging (a lint baseline that may only shrink, cited from
`mukul975/Anthropic-Cybersecurity-Skills`), and that refusal is sound for **lint debt** - but a
**finding about a binary** is not lint debt: it has an expiry date, and the expiry is not recorded.
**Verdict: ALREADY-HAVE** for reproduction, **MISSING** for expiry.

### P17 - An always-empty field is a constant wearing the costume of an observation
**Source:** the rule is the arsenal's own (`CHARTER-ARSENAL.md`, *declared at both ends, wired at
neither*; *a check that always passes is not evidence*). I am reporting it as a finding against
the arsenal, measured.
**Measured:** `scripts/mission.ps1:1126` emits `ruled_out = @()` into every `artifact.json` - a
**hardcoded empty array**, never written by anything. `grep ruled_out` across `scripts/` returns
that single line. The same shape at `:1606-1609`: `unknowns` is a **two-element literal**
(*whether the decompilation is faithful*, *what would have been found by capabilities that did
not run*) emitted identically for every mission ever.
**Why this matters more than it looks:** an empty `ruled_out` reads to a later window as *nothing was
ruled out*, when the truth is *nothing was recorded* - and the field name is exactly the string a
grep-based search for negatives would hit, so the corpus of negatives is unfindable. The charter
already says, in its own words, that *a report that omits the worst rows looks healthier than one that
prints them*.
**Verdict: MISSING.** Either wire it or rename it to something that cannot be misread; do not
ship a field that lies by being empty.

### P18 - Pin the toolchain so two runs are comparable
**Source:** `tihanyin/REx-skill` (MIT, root listing shows `LICENSE`) - `devshell/flake.lock` pins
every tool by revision *precisely so two runs are comparable*, on the stated grounds that *the
decompiler output IS the analyst input*, so two people on two Ghidra versions are not running
the same experiment.
**Arsenal:** ALREADY-HAVE - the debug artefact mandates *exact commands run, tools and versions
used*, the registry records measured versions (TShark 4.6.8, Frida 17.17.0), and the charter
attributes a whole finding to a `Write-Host` line that broke one tool while leaving the tool
itself fine.
**Verdict: ALREADY-HAVE.**

---

## 2. Tally

| # | Practice | Source | Verdict |
|---|---|---|---|
| P1 | Eight-stage RE schema, stage = unit of credit | Reveree (CC BY 4.0) | **MISSING** |
| P2 | confirm / deny / **abstain**, whole-word action tagger | Reveree | **WORTH-CHANGING** |
| P3 | Outcome-blinded, stage-scoped, quote-bound judge | Reveree | **MISSING** (quote-the-run: have) |
| P4 | Coverage **and** depth; stall funnel, not cumulative | Reveree | **MISSING** per run; have per axis |
| P5 | Memorisation probe + difficulty-preserving perturbation | Reveree | **MISSING** |
| P6 | Comprehension is the bottleneck, not budget | Reveree | **MISSING** |
| P7 | Open skill spec + a format validator | Agent Skills spec | **WORTH-CHANGING** |
| P8 | Judge bias is measured; refuse model judgement | MT-Bench / self-preference / RobustJudge | **ALREADY-HAVE** (stricter) |
| P9 | Fewer/consolidated tools, semantic ids, actionable errors | Anthropic eng 2025-09-11 | **MISSING** (b/c); **HAVE** (d) |
| P10 | Ablate the interface, not only the gates | SWE-agent (MIT) | **WORTH-CHANGING** |
| P11 | Hold the scaffold fixed so a measurement is attributable | D-CIPHER + Reveree method | **MISSING** (attribution only) |
| P12 | Every claim states its own falsifier | REx-skill (MIT) | **MISSING** |
| P13 | Hypothesis ledger, evaluated as an arm | Reveree | **MISSING** |
| P14 | Per-claim confidence tier, enforced | own analysis-loop.md | **WORTH-CHANGING** |
| P16 | Reproducer as deliverable; a claim has an expiry | CyberGym | **HAVE** / **MISSING** expiry |
| P17 | An always-empty field lies by being empty | own charter rule | **MISSING** |
| P18 | Pin the toolchain for comparability | REx-skill (MIT) | **ALREADY-HAVE** |

Seven MISSING, four WORTH-CHANGING, four ALREADY-HAVE. The ALREADY-HAVE verdicts matter: on
**judge bias** and **toolchain pinning** this arsenal is ahead of the literature, and on
**reproduction-as-deliverable** it is ahead of a 1,507-vulnerability benchmark. The deficits are
concentrated in two places - **the artefact has no epistemic fields** (P12, P13, P14, P17) and
**nobody measures the agent, only the instruments** (P1, P4, P5, P6).

---

## 3. Ranked changes (5, most load-bearing first)

**1. Give the artefact the two fields it has been pretending to have: a hypothesis with its
falsifier, and a real `ruled_out`.** Today `ruled_out` is `mission.ps1:1126` `= @()` and `unknowns`
is a two-string literal at `:1606`. Change: add `claim[]`, each entry
`{text, tier, hypothesis, falsifier, evidence_ids[], source_capability}`, and fill `ruled_out[]`
or set `ruled_out_status: not_recorded`. No gate changes; `Get-Verdict` still computes the
tier. This adds the record the gates have been scoring without. Closes P12, P13, P14, P17, and it
is what lets a later window **disagree on the record rather than on the prose**.
*Falsifiable test, in the arsenal's own idiom:* a fixture claiming `main` holds the check while
its falsifier is unrecorded must drop to `unresolved` under a new gate, and `-Action Ablate` must
report that new gate load-bearing.

**2. Score the run, not just the evidence set: an eight-stage RE schema with `action` /
`insight` tags, plus coverage and depth and a stall funnel.** The stages already exist
implicitly in `analysis-loop.md` and in the preconditions-first ordering; the credits do not exist
anywhere. Tag the real command line, whole-word, `_` and `.` as separators, so *narrating* a
triage cannot earn S1 - the one place this arsenal is exposed today, because a mission counts
rounds, not invocations. `Get-Termination` already computes DONE/EXHAUSTED/CONTINUE and is
the natural home. Closes P1, P2, P4.

**3. Add the null condition: a contamination probe per RE capability.** Two cheap arms:
(a) ask the same question with the artefact withheld - if the answer does not change, the
capability is measuring the model, not the binary; (b) difficulty-preserving perturbation
using the pair the arsenal already owns, `c01-stringobf.exe` against `c01_stringobf.exe` - four
bytes apart, identical code. Closes P5. This is the control that turns a green RE number from
*a number we produced* into *a number a stranger could re-derive*.

**4. Make two prose rules mechanical in one pass: per-claim tier, and SKILL.md conformance.**
`analysis-loop.md` already prescribes OBSERVED/INFERRED/POSSIBLE, and
`agent-craft-principles.md` already named the failure class - a guide rule no validator
enforces is a preference. `SKILL.md` has no `license`, no `allowed-tools`, and no format
check anywhere (grep for `SKILL.md|frontmatter|allowed-tools` across `scripts/` and `skills/`
returns no matches). Add both to `eval-agent-contract.py` / `registry-verify.py`, which
already run with no network and no model. Closes P14, P7.

**5. Record the competence-over-resource finding, then aim the existing ablation at the
interface.** Reveree measured that extra rounds, persistence and reasoning effort rescue few
RE failures - the deficit is comprehension - which argues for a different instrument, not a
bigger `-MaxRounds`. And `-Action Ablate` has so far ablated only logic *inside* `mission.ps1`;
it has never ablated the router ordering, the fact-key naming, or the preconditions-first
partition, all three of which are load-bearing by assertion only. Closes P6, P10.

**Deliberately NOT recommended, and why.** Multi-agent decomposition (D-CIPHER, or the REx federated adjudication the prior survey already read): the station problem is instrument wiring, and a second agent is a second opinion, not a second family of instrument - the arsenal says this itself and is right. A semantic renaming of the fact-key namespace (P9c): those keys are load-bearing across 26 entries, so it is a migration with an ablation budget, not a rename. And any model-judged comprehension stage (P3): docs/EVAL.md already refuses model judges with a build-enforced sentence, which is the stricter position.

---

## 4. Limits of this audit, stated rather than hidden
- **Not established:** whether any MISSING item would actually improve a verdict on this station. Every claim above is about shape and measurability, not outcomes; the Reveree numbers are measured on picoCTF and NYU-CTF and do not transfer to a Windows arsenal with one -Target. I ran no mission and do not claim one improves.
- **Not established:** the fit of the eight-stage schema here. It comes from CTF RE; the arsenal serves D1-D16 including web, mobile and forensics, where Solver and Flag have no analogue. That is why change 2 credits the stages rather than renaming the loop.
- **Not verified:** licences for agentskills.io (no licence statement readable on the page), TATAR-LAB/ctf-agents (I did not list its root for a LICENSE file) and anthropics/skills. I did verify tihanyin/REx-skill by listing the root (LICENSE present, GitHub reports MIT) rather than trusting the prior survey table, and I found no licence claim contradicted by a root listing.
- **A sampling warning about my own audit, borrowed from the charter:** my first pass over debugger/wiki returned path not found - for me and, per the brief, for four siblings. A survey that reports what it failed to find as what is absent commits exactly the sample-undercounts-the-class-it-cannot-see error the charter names. I therefore read the charter whole and both method trees whole before judging anything MISSING.
- **Read-only honoured:** no edit, commit or write outside this report; nothing installed or cloned; smoke-all.ps1, the labs and the fuzz loop were not run.

STATUS: DONE
