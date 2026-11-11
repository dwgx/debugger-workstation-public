OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/CHANGELOG.md

# CHANGELOG (持续更新 / continuous update)

Append-only. Each entry carries `as_of` (UTC), a `sha256_snapshot` of the file
set from bytes, and the printed denominator. A new entry is added only by a run
that prints real numbers; prose-only edits do not earn an entry.

## [1.0.0] - 2026-11-11

- Initial SANITIZED public learning kit: ONE capability (hash-lock), ONE command
  (`python check.py`), ONE denominator (`checked=N`), ONE falsifier (in-memory
  byte flip must go red). Proposed as NEW subdirectory `learning-kit/` on the
  EXISTING public repo `main`; no root-file overwrite.
- as_of: 2026-11-11T00:00:00Z
- fixture_set_sha256_snapshot: 53169d461cf10fc3af636062de5465d62df093cf4cb4c08a8af1388f407b44d5
- denominator: checked=2 (examples/*.txt), matched=2, negative_control=tamper_caught=1
- exact_command: `python check.py` (from candidate/); result VERDICT=GREEN exit 0.
- licence: MIT(code) / CC BY-SA 4.0(docs); NOT a grant executed by this worker.

## Update rule (no drift)

1. Edit any file → recompute its sha256 from bytes.
2. Update `INCLUDE-MANIFEST.tsv` (one row per file, no duplicate same-path rows).
3. Re-run the `## Verify`; capture new `as_of` + `sha256_snapshot`.
4. Append a receipt per `RECEIPT-SCHEMA.md`. Never rewrite an old row.
5. Any private/credential-shaped file appearing → add an `EXCLUDE` row, do not
   silently include it. External publish stays OWNER DECISION REQUIRED.
