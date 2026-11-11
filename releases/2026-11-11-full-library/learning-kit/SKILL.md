OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/SKILL.md

# Skill: hash-lock a small SYNTHETIC file set

Teaches ONE capability: prove a directory of fixtures is byte-identical to what
its `.sha256` sidecars recorded, and prove the check can go RED on tampering.

## One command

Run from inside this directory (a fresh clone is enough):

```sh
python check.py
```

That is the entire command surface. No network, no credentials, no writes, no
dependency on any parent workspace. measured at `as_of 2026-11-11`:
`checked=2 matched=2 hash_lock_ok=1 tamper_caught=1` then `VERDICT=GREEN`, exit 0.

## One denominator

`checked = N`, where N is the count of `examples/*.txt` fixtures present on disk
(here N=2). `matched` counts how many recomputed sha256 equal their sidecar.
Green requires `checked == matched == N` and `checked > 0`. The number is
printed, not asserted in prose.

## One falsifier

`check.py` flips a single byte of the first fixture IN MEMORY (never on disk),
re-runs the SAME hash-lock, and requires `tamper_caught=1`. If a one-byte change
still verifies, the gate is decoration, not a gate. `VERDICT=GREEN` only when
`hash_lock_ok=1 AND tamper_caught=1`.

## Failure table

| printed symptom | meaning |
| --- | --- |
| `checked=0` | no fixtures; verdict is UNKNOWN, never PASS |
| `matched < checked` | a fixture drifted from its sidecar |
| `tamper_caught=0` | gate is a tautology; reject the package |
| `VERDICT=RED` | do not adopt; re-derive hashes from bytes |

## What this does NOT claim

It does not prove any third-party repo, live MCP session, real binary, HMC/Linux
cross-machine run, or online target works. It is a SYNTHETIC, repo-agnostic
teaching unit. Adopting repos wire their real surface behind `tools.json`, but
the hash-lock capability itself stands alone.
