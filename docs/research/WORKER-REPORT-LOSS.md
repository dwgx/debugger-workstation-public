# WORKER-REPORT-LOSS — what the 2026-10-02 ecosystem survey is standing on

**Read this before quoting any figure from `docs/research/ecosystem-2026-10-02.md`.**

Measured 2026-10-04 by `scripts/arsenal-doctrine-check.py`, which exists because of this.

---

## What happened

That dossier is the most-cited document in the estate. Its header says:

> **Sources, read in full:** `w1-mcprev.md` (229 lines, MCP servers + security posture),
> `w1-retoolchain.md` (232 lines, 40 tools cost-ranked), `w1-revskills.md` (336 lines, 33
> repos), `w1-debugpairing.md` (1237 lines, 23 pairings…). **Every figure carries its
> `w1-*.md:line` or the command that produced it.**

**Eight worker reports are cited 230 times. One was never written to disk at all. The other
seven survive only as the subagent's final-answer summary, not the report the dossier cites —
and 159 of the citations point past the end of what survives.**

```
$ python scripts/arsenal-doctrine-check.py
worker citations: 230  missing-file: 12 (1 files)  past-the-end: 159 (7 files)
```

## The loss, named

| worker report | lines the dossier claims | lines that survive | citations | of which past the end |
|---|---|---|---|---|
| `w1-debugpairing.md` | **1237** | **1** | 45 | **45** |
| `w1-toolperf.md` | — | 190 | 35 | **35** |
| `w1-gateredteam.md` | — | 143 | 30 | **30** |
| `w1-composition.md` | — | 62 | 29 | **29** |
| `w1-retoolchain.md` | **232** | **77** | 15 | **11** |
| `w1-revskills.md` | **336** | **114** | 12 | **6** |
| `w1-agentworkflow.md` | — | 126 | 3 | **3** |
| `w1-mcprev.md` | **229** | **0 — no copy anywhere** | 12 | n/a |

`w1-mcprev.md` is the one that names **the yardstick every other row in the dossier is judged
against** (`w1-mcprev.md:9-16`). It does not exist in this tree, the wiki tree, or anywhere
under `~/.dwgx`.

## The recovery attempt, and its result: definitively unrecoverable

The remnants under `workers/` came from the harness's own persistence of each subagent's
**final answer**. The obvious next move was to dig the full bodies out of the session
transcripts. **That was tried, and it fails for a specific and final reason.**

`DebugPairing.jsonl` is **1,744,737 bytes across 597 lines** — the raw conversation is intact.
But parsing every text block out of it shows what it actually contains:

```
$ largest text blocks in the whole session directory
   51,403 bytes   A1Registry.jsonl      <- a tool RESULT (a file read of capabilities.json)
   51,368 bytes   ChainDesign.jsonl
   51,359 bytes   T2Controls.jsonl
   51,110 bytes   REToolchain.jsonl     <- a URL FETCH result (650 table cells of HTML)
   27,162 bytes   RevSkills.jsonl       <- a tool result: source lines from a cloned repo
```

Every large block is a **tool result** — a file read, a URL fetch, a search of a cloned repo.
The report prose was composed by the model and delivered as the final message, and **that is
the one thing the transcript does not store**: the transcript stores what the agent *read*, and
the harness separately persisted the *final answer* as the 718-byte `DebugPairing.md` whose
content is one line. `DebugPairing.md` at **718 bytes against a claimed 1237-line report** is
the whole story in one ratio.

⇒ **The full reports are gone.** Not mislaid, not mis-filed — the only artefacts that ever
existed were the agents' reads and a one-line summary. Re-running the survey is the only way
to get the evidence back; searching harder will not.

## How the gate was closed, and why this way

**212 dead line numbers were struck in place across 5 dossiers** (`~~w1-debugpairing.md:1211~~`),
not deleted. This reuses the convention `doc-facts.py` already writes into — struck text is
retired history that must not read as a live claim — so:

- the **conclusions survive** as history with their dead pointers visibly dead,
- the gate can **actually go green**, which is what a permanently red gate would have prevented,
- and the loss is **permanent and counted** rather than quietly hidden behind a green line.

`arsenal-doctrine-check.py` refuses any **new** unstruck dead citation, and its own success
message says plainly what its greenness means: *"0 live worker-report citations unresolved.
This means NO UNSTRUCK dead citation remains — not that the evidence exists."*

Two design decisions in that gate were forced by measurement, and both are worth keeping:

1. **It gates on line-numbered citations, not bare filename mentions.** `w1-mcprev.md` in
   prose says "a report by that name existed"; `w1-mcprev.md:9-16` says "these nine lines are
   my evidence". Only the second is checkable. The 232 bare mentions are counted and printed
   so the number stays visible without being gated.
2. **The struck count needed its own pattern** (`w1-foo.md~~:1211~~` does not match the live
   citation regex, because the `~~` sits between `.md` and `:`). "Citations before minus
   citations after" on the live pattern reports 0 and 0 — the instrument cannot see what it
   is supposed to be counting. That is the §R7 failure wearing a correct-looking number.

## Where the remnants came from

`%USERPROFILE%/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/`.
The harness persists each subagent's **final answer** as `<AgentName>.md` beside its
transcript. Those are the copies now under `docs/research/workers/`.

That is the whole recovery, and its limit is the finding: **the harness persisted the summary,
not the report.** `DebugPairing.md` is 1 line against a claimed 1237. The full bodies were
never written anywhere that survived — which is rule **R9** in
`wiki/methods/arsenal-workflow-rules.md` ("finish on disk before reporting status") failing at
the scale of an entire survey round.

## What this means for the figures

**The conclusions may well be correct. They are not checkable, and this project's own North
Star says a capability without a run is a claim, not a capability.** Concretely:

- The dossier's own **two disclosures stand** — no MCP server was installed or started, and no
  package was installed. Those were honest when written and remain honest.
- Every `w1-*.md:line` citation is **un-runnable**. Where a figure also carries a command, the
  command is the evidence and the citation is decoration.
- The **cost figures in §2 were verified independently** via `gh api repos/<r>/releases` asset
  `size` and HTTP `HEAD Content-Length` (`w1-retoolchain.md:30-33`) — but that verification was
  itself performed by the report that is now a 77-line remnant. Treat §2 as **unverified**.

## The rule this produced

`arsenal-doctrine-check.py` checks two things, and the second is the one that matters:

1. a cited worker report **exists**, and
2. **the cited line exists in the copy a reader would open.**

Without (2), recovering a 77-line remnant would have turned 159 dead citations green and made
the gate *reassuring* instead of honest. The control that proves it —
`w1-short.md:900` against a three-line file — is in `--selftest`.

## What would actually close it

Either the reports are found somewhere this estate has not been searched, or the citations are
struck and the figures they carry are marked `[UNVERIFIED]`. **Re-running the survey would also
close it**, and at four worker reports a day the cost is known. What does not close it is
leaving a green-looking dossier over dead citations, which is what two days of this looked like.