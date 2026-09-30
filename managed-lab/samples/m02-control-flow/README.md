# m02 — control-flow flattening with opaque predicates

**Technique.** The straight-line computation is rewritten as a state machine.
Every basic block became a `case`, one variable carries every control transfer,
the entry state is `Boot[1]` (not `Boot[0]`), and five of the cases are guarded by
predicates that can never be true. A decoy block `case 0x2B` is reachable-looking
and reachable from nothing.

**The traps.**

1. **Dead guards.** `Opaque1(id, bias) = (id*id + bias) % 3 == 0` and
   `Opaque2(id) = (id & 0x20) == 0x20 && id % 2 == 0` are always false at the ids
   they are called with. A parser that harvests every `state = ...` in a case body
   follows the dead edge. `solve-m02.mjs --ignore-opaque` is that parser, and it
   cannot even finish the walk.
2. **The decoy.** Recovering the order by walking backwards from the exit, or by
   assuming blocks appear in execution order, both land on `0x2B`.
3. **The entry.** `Boot[1]`, resolved from the array initialiser.

**Known answer.**

```
order  0x1C -> 0x07 -> 0x4A -> 0x35 -> 0x11 -> 0x2E -> 0x59 -> 0x41
acc    0xDBB9C662          ( (acc * 31 + k) mod 4294967295, acc starts at 1 )
```

**Solve.**

```powershell
node managed-lab\tools\solve-m02.mjs --asm managed-lab\out\m02\m02_flatten.dll --expect dbb9c662
node managed-lab\tools\solve-m02.mjs --asm ... --ignore-opaque --expect dbb9c662   # exits 1
node managed-lab\tools\solve-m02.mjs --asm ... --entry 43        --expect dbb9c662   # exits 4
```

The second control is the stronger one: `--entry 43` produces a **complete,
confident, wrong** answer (`0x000020cb`) — the failure mode the loop's invariant 3
exists to catch.

**Loop placement.** NARROW (the dispatcher is the only control flow) → VERIFY
(recovered order and accumulator compared against the sample's own `--trace`
output) → DOCUMENT (the two unreachable cases are part of the finding).

**Skill.** Dataflow, not reading. The solver evaluates each `OpaqueN` at the
argument it is actually called with, drops the dead edge, and reports a case whose
successors are ambiguous without an evaluated guard as `valid: false` — the solver
refuses to hand back a guess dressed as a result.
