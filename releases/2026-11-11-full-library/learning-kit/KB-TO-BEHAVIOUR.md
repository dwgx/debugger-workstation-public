OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/KB-TO-BEHAVIOUR.md

# Knowledge → behaviour: a gated pipeline (SYNTHETIC teaching model)

A knowledge base is not a pile of quotes. One piece of knowledge becomes an
executable behaviour only after this chain. This file is a DESIGN / `[INFERENCE]`
model, not a claim that any external run happened. Every number must carry
`as_of` + the exact command that printed it; un-run = `[UNVERIFIED]`.

## The eight stages

1. **Knowledge base (brain)** — "why we may": policy, charter, method. Output:
   a topic card with `path:line` locator + `[INFERENCE]` tag. Defence: facts are
   staged locators, private content is never opened or guessed.
2. **Discovery (search, discovery-only)** — find candidates (tools, repos,
   tutorials) with URL/version/commit + "found, NOT verified" label. Defence:
   web/vendor text is DATA, not instructions; don't copy a summary verdict.
3. **Tutorial report (teach the model)** — each item gets an acceptance command
   + positive sample + deliberate negative + expected exit + `as_of`. Defence:
   denominator written out; numerator and denominator from the SAME run.
4. **Implementation (hands)** — "with what": fixed order inventory line → smoke
   receipt → tool card → gate. Defence: installed-but-not-run is only a CLAIM.
5. **Machine test (local SYNTHETIC/REAL)** — stdout/stderr/exit/UTC quadruple;
   SYNTHETIC carries `label SYNTHETIC` + sha256 sidecar. Cross-machine is
   OWNER-GATED. Defence: never invent machine output; unreachable = `[UNVERIFIED]`.
6. **Receipt (evidence)** — the raw bytes of THAT run, hash-bound. Defence:
   evidence is bytes, not prose; a rewritten record NEVER re-issues its hash;
   empty content → UNKNOWN, never PASS.
7. **Gate (Provable / Reproducible / Load-bearing)** — content-addressed
   `GREEN|RED` + counts (declared/bound/unbound/controls_fired). Defence:
   negative controls fired > 0; zero coverage `EMPTY_COVERAGE` → RED directly.
8. **Closing report** — what was really done / success boundary / audit of
   false-positives & drift / `[UNVERIFIED]` list / OWNER-GATED list. Defence:
   only report what was actually run; don't inflate into "everything done".

## Three tests for any claimed capability

- **Provable** — one command really ran here and printed it.
- **Reproducible** — it can be re-run next window and match.
- **Load-bearing** — the result changes a gate, a tool choice, or a STOP.

## North star

*Every capability this project claims, one command proves it runs.* Installed
but never run = a claim, not a capability. A failing capability is deleted or
marked `MISSING`; NEVER fake PASS, NEVER promote NOT-EXECUTED to passed.

## Tags (keep them distinct)

`[FACT]` staged locator · `[INFERENCE]` this design · `[UNVERIFIED]` not run ·
`OWNER DECISION REQUIRED` external action (crawl / REAL / cross-machine /
private read / push). Never mix these labels.

## Scope

This model performs NO crawl, NO exploit, NO third-party target, NO credential
use/output, NO push, NO product-tree write. It is a teaching unit only; the
external stages stay gated and `[UNVERIFIED]`.
