OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/RECEIPT-SCHEMA.md

# Receipt schema (SYNTHETIC)

A receipt is the only evidence a run happened. Prose is not a receipt. Each
receipt is one JSON object; the adopting repo appends receipts to a ledger and
never edits old rows.

## Fields (all required)

| field | type | meaning |
| --- | --- | --- |
| `as_of` | string (UTC ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`) | when the command ran |
| `command` | string | the exact ONE command executed, W-relative or repo-relative |
| `exit` | integer | process exit code; GREEN requires 0 |
| `checked` | integer | denominator = fixture/file count actually seen |
| `matched` | integer | how many hashes matched their sidecar/manifest |
| `sha256_snapshot` | string (64 hex) | sha256 of the sorted `<path>\t<sha256>` lines of the file set |
| `verdict` | string | `GREEN` \| `RED` \| `UNKNOWN` |
| `negative_control` | string | `tamper_caught=1` or `UNKNOWN` |

## Invariants (no-noise)

- `checked == 0` forces `verdict=UNKNOWN`; an empty set never passes.
- `verdict=GREEN` requires `exit=0 AND checked==matched AND negative_control=tamper_caught=1`.
- One receipt per run, no duplicate same-path rows, no tautology (a check that
  cannot go red is `RED` regardless of `matched`).
- `sha256_snapshot` is computed from bytes, never copied from prose.
- NOT-EXECUTED / not_run / unsupported NEVER become `passed`.

## Example receipt (illustrative, SYNTHETIC values)

```json
{"as_of": "2026-11-11T00:00:00Z", "command": "python check.py", "exit": 0,
 "checked": 2, "matched": 2, "sha256_snapshot": "<64 hex>", "verdict": "GREEN",
 "negative_control": "tamper_caught=1"}
```
