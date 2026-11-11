OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/BRIDGE.md

# BRIDGE: test → optimise → iterate (gated)

"Bridge" = the loop that connects this SYNTHETIC teaching unit to a real
capability in an adopting repo. It is deliberately gated so a green on fake
fixtures is never mistaken for a green on production.

## The three phases

1. **Test (local, always allowed).** Run the ONE command `python check.py`.
   Record a receipt per `RECEIPT-SCHEMA.md`. The negative control (in-memory
   byte flip) MUST go red. Synthetic only.
2. **Optimise (local, gated).** Propose improvements (more fixtures, a tighter
   denominator, a sharper falsifier). EACH change must keep `sha256_match` green
   and add a fresh receipt with a new `as_of`. A prose-only claim that prints no
   new number is rejected.
3. **Iterate (external, OWNER DECISION REQUIRED).** Wiring a real MCP server,
   real binaries, cross-machine (Linux/HMC) runs, network research, or publishing
   is an external action. It stays OWNER DECISION REQUIRED and is NEVER executed
   by this kit. No-decision = keep local staged.

## Gate between phases

Advance from Test to Optimise only when the receipt shows `verdict=GREEN` AND
`negative_control=tamper_caught=1`. Advance from Optimise to Iterate only with
an explicit Owner decision. A missing receipt, a duplicate same-path row, or a
tautology test (one that cannot go red) blocks the gate and forces `UNKNOWN`.

## Continuous update without drift

- Every run stamps `as_of` + `sha256_snapshot`; the denominator is printed.
- `INCLUDE-MANIFEST.tsv` binds each candidate file to its sha256; recomputing
  from bytes catches drift.
- Old ledger rows are never rewritten; append-only. An `EXCLUDE` row is added
  the moment a private/credential-shaped file appears.

## What this kit does NOT do

It does not run any third-party target, install unknown code, open real MCP
sessions, push, or touch a product tree. The bridge is a documented, gated path
— not an executed one.
