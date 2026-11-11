OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/QA-GATES.md

# QA-GATES: turning a QA process into OUR executable behaviour

Teaching version (SYNTHETIC). A rule counts only if ONE command can judge it
true or false — not a pretty sentence you can only quote. This is the public,
sanitized distillation of a 26-gate model organized into FOUR minimum-gate groups.

## The four minimum-gate groups (each with a falsifier)

1. **Version & contract** — a real call on a fixed input (not just a
   `initialize`/`tools-list` handshake); assert the content AND error fields;
   keep valid historical gates, regress only affected paths. Falsifier: a
   handshake reported as "passed".
2. **Persistent session & UI** — open target A → query → a SECOND independent
   call still targets A; opening B must not cross targets; reconnect must say
   restore/rebuild/invalid; cancel/exit must not leave a false "passed"; UI shows
   the same evidence, not a second conflicting fact base. Falsifier: a second
   call silently falls to a default target.
3. **Restore & diff** — the correct version must not over-error; a deliberate
   negative must not pass just because a screenshot looks similar; with no test
   the state is NOT EXECUTED, never `passed`; keep input↔output hash links.
   Falsifier: `not_run` promoted to `passed`.
4. **TTD & crash evidence** — repeated reads at one trace point agree; cursor
   independent of global object scope; dump/replay addresses & registers checked;
   API version, symbol availability, parse limits written into the result.
   Falsifier: addresses never compared yet reported as pass.

## Method constraints (don't confuse method with conclusion)

- Same-model subagents improve coverage + cross-checking; they are NOT an
  independent experiment.
- A discovery-only search layer finds candidates; never copy its verdict,
  version, language, maturity, or licence conclusion as fact.
- Save query logs + per-candidate evidence items.
- JSON shape passing ≠ factually correct. A valid-looking envelope can be false.
- `not_run / unsupported / passed / failed / error` are DISTINCT states; a
  boolean `true` is never a pass.
- Correct sample: PASS. Deliberate negative: NONZERO. Both must be really
  reproducible — never by screenshot, marketing copy, or a summary verdict.

## Evidence envelope (minimum fields)

`subject` + `subject_hash` (sha256), `operation`, `tool_version`, `confidence`,
`coverage`, `limitations`, `artifact_ref`, `verify_hash`, `status` (a discrete
enum, not a boolean). Verifier recomputes sha256(subject) and verify_hash from
bytes; any mismatch is non-zero. A status of `not_run` stays `not_run`.

## One-command / one-denominator / one-falsifier (how a card is written)

1. ONE `check_command` runnable from the repo root, no "as appropriate".
2. ONE denominator per number, with `as_of` + exact command; counts computed from
   files, never hardcoded.
3. ONE falsifier per rule (`fail_looks_like` + a SYNTHETIC negative that really
   returns non-zero exit).
4. No prose-only claim; a pass_condition is an assertable fact, not an adjective.
5. Card is readable by both a human and a model: fixed columns, fixed status
   enum, evidence fields separate "tool output / computed fact / model inference".

## Red lines (this kit runs NONE of these)

no network, no third-party install / untrusted binary, no real RE binary /
driver / cross-machine, no product-tree write, no push / PR / merge / release,
no token. Whatever needs a real external target stays `OWNER DECISION REQUIRED`,
SYNTHETIC locally staged. `completed != accepted`: the parent re-runs `## Verify`
from W and compares; only then is it accepted.
