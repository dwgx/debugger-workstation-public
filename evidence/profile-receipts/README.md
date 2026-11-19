# profile-receipts (DEMO fixtures)

**These are demonstration fixtures. They are NOT product acceptance receipts and NOT
evidence that any tool, backend, probe or profile actually ran.** No product entrypoint,
PowerShell runner, MCP backend or commercial engine was executed to produce them.

They exist to exercise `scripts/verify-profile.py` against the frozen contract in
`schemas/run-receipt.v1.json` (derived from `05-EVIDENCE-CONTRACT.md` §3–§6) and to prove
three behaviours the advisor's review demanded:

| fixture | what it shows | verifier verdict |
|---|---|---|
| `good-pass.json` | integrity + execution + semantic + negative all green; `expected_exit=1` honoured (nonzero is not coerced to 0) | `PROFILE_PASS` |
| `touch-only-stale.json` | the advisor's false-fresh counterexample: legacy bytes untouched, mtime refreshed, `attempt_id` reused, backend never executed. The receipt **self-declares** `result.verdict=pass`; the verifier rejects it. Integrity stays green, execution fails, freshness is `stale_not_fresh`. | `PROFILE_FAIL` |
| `retry-preserves-failure.json` | retry as a new `attempt_id` (`attempt-002`) with `parent_attempt_id=attempt-001`; the parent's failure log bytes are preserved unchanged and are re-hashed by the verifier | `PROFILE_PASS` |

`oracle-public-core-demo.json` is the frozen expected set used by all three: required
check ids, prior-attempt artifact hashes, and the semantic/negative assertion values.
It is a demo oracle, not an independent measurement of a real tool.

## Run

```
python -X utf8 -B scripts/verify-profile.py \
  --schema  schemas/run-receipt.v1.json \
  --receipt evidence/profile-receipts/good-pass.json \
  --oracle  evidence/profile-receipts/oracle-public-core-demo.json
```

Exit codes: `0` PROFILE_PASS, `1` PROFILE_FAIL, `2` PROFILE_BLOCKED, `3` PROFILE_NOT_RUN,
`4` unreadable input.

## What these fixtures do NOT cover (honest limits)

- No real PowerShell/probe runner was observed; `execution.observed_via=runner` is a
  declared value, not a live observation (`not_run`).
- The semantic layer compares declared `observed.facts` against the oracle; deriving those
  facts from artifact bytes is not implemented here (`not_run`).
- Concurrent attempt isolation (two runners sharing temp paths) is a contract rule in
  `05` §5.1 but not exercised by a static fixture (`blocked`).
