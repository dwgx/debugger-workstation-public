# Research dossier 2026-09-30

Five evidence-dense reports produced by agents that deep-read the public
reverse-engineering agent ecosystem, then corrected the record by running what
they found. Read with `wiki/methods/arsenal-upgrade-plan.md` in the sibling
`<private-tree>` repo, which is the decision layer over these findings.

| File | What it establishes |
|---|---|
| `orchestration-design.md` | The mission loop, the capability registry schema, and the gate as a program. Ships with four negative controls, N4 being the station's own known failure mode aimed at the new code. |
| `binary-mcp-map.md` | Capability delta against the public binary-analysis MCP set. Its headline is that our own recorded blocker was false. |
| `mobile-js-skill-map.md` | Mobile and JS skill comparison. Verdict: their tooling is worse than ours, their shape is better — ours are tools, theirs are decision procedures. |
| `knowledge-corpus.md` | 38 distilled notes from 14 sources. Each carries preconditions, a pass signal, and a negative control. |
| `curriculum.md` | 13-stage training path with exercises, pass conditions, and honest `[AUTHOR]` fixture gaps. |

Two premises in this dossier were wrong when written and are corrected in place
rather than quietly dropped: IDA Pro *is* installed and licensed, and Ghidra
*does* support the headless cross-program open our notes called impossible.

Everything here is evidence for a decision. Nothing here is a capability until it
has a runnable command on record.
