# Mission output success contracts

`scripts/mission.ps1` evaluates declared output semantics with the explicit machine
contracts in `manifests/success-contracts.json`. The evaluator is the pure PowerShell
module `scripts/mission-success-contract.ps1`. It does not interpret English prose
as a programming language and does not invoke a tool itself.

This closes the live loop's former two-regex shortcut: an exit-zero JSON response
could satisfy `ok` while violating another part of `success_when`, and declarations
without the recognized phrases were effectively unchecked. The old experimental
prose parser remains in `mission.ps1` as dated source; neither the live loop nor the
new verdict gate calls it.

## What the coverage numbers mean

The current capability registry contains **29 declarations**: **25 invoke** and
**4 envelope** declarations on 26 of the registry's 28 capabilities. These are distinct denominators:

| Scope | Count | Meaning |
| --- | ---: | --- |
| Explicit catalog | 29 / 29 | Every current declaration has a sidecar entry, including explicit unsupported entries. |
| Predicate implementation | 27 / 29 | A supplied subject can be evaluated. This includes two IDA transport objects supplied by synthetic tests. |
| Current live subject adapters | 25 / 29 | The mission can obtain these subjects from its stdout or its own Ghidra scratch directory. |

An available adapter or a passing synthetic predicate test does **not** establish
that its external tool ran successfully. Full provider receipts remain separate.
These counts also do not declare the public product, every capability, or a release
complete.

The four declarations that cannot currently receive a verified live result are:

| Declaration | Live outcome and reason |
| --- | --- |
| `native.ida.decompile/envelope` | `unsupported`: today's wrapper returns flattened stdout, without the original transport body required by the envelope. |
| `native.ida.list_functions/envelope` | `unsupported`: original query/result batch arrays are unavailable from the live adapter. |
| `native.yara.triage/invoke` | `unsupported`: the prose asks whether matches answer the question. No objective machine predicate for that question has been defined. |
| `native.ghidra.emulate/envelope` | `unsupported`: this entry has no invocable runner and no bound live research artifact adapter. |

The IDA operation itself may still execute. Its stdout predicates can pass, but its
whole round is incomplete without the envelope subject. That round is recorded as
`ok: false`, cannot forward facts, and cannot count as verified success evidence.
The fixtures that explicitly supply IDA transport objects exist only in the test
helper; the live runner never fabricates those objects.

## Contract binding and strict types

Each sidecar row names a capability and its `invoke` or `envelope` section, hashes
the exact `success_when` string, and pins the runner, stdout mode and ordered argv.
Changing an argument or declaration requires reviewing and updating the explicit
sidecar entry. Moving the prose to a different wording is therefore a visible
contract change even if a human considers the new wording equivalent.

Coverage is checked in both directions. Every current declaration needs a matching
entry, and every sidecar section for that capability must still exist in the
registry. Deleting `envelope`, deleting its `success_when`, or deleting an invoke
declaration cannot remove an obligation and turn the round green. Unknown entries,
unknown predicate operations, unknown schema fields and malformed bindings fail
closed. No generic rule accepts a new capability identifier.

Schema version 1 is a JSON number with an integer value; the string `"1"` is not
accepted. Boolean predicates require JSON booleans. A string such as `"true"` or a
number such as `1` cannot satisfy `ok == true`. Numeric predicates reject strings,
booleans, null and non-finite values. Integer predicates reject fractions. Member
names and string enum values are case-sensitive. `present` requires a member and
a non-null value; `absent` requires that the member not exist, including when its
value would otherwise have been null.

The process result is part of the input. Its original value must be a finite JSON
number with an integer value in the signed 32-bit range. Only numeric zero passes.
The evaluator validates this before any PowerShell cast or parameter binding could
turn `null`, `false`, `"0"` or `0.49` into zero. Rechecking a stored result repeats
the same validation.

The implemented predicates are deliberately finite: presence/absence, strict
booleans and strings, nonempty strings, arrays and objects, integer/numeric bounds,
array correspondence and the specific declared fuzz accounting relation. A
predicate checks only what it names. For example, a measured `aslr: false`, zero
matched capa rules, an unsigned image, or nullable managed mitigation data may be
legitimate observations; the contract does not turn every negative measurement
into a tool failure.

## Success, fact forwarding and the eighth verdict gate

A live round succeeds only when its process result is zero, every expected section
has a supported subject, and every predicate passes. The evidence trace stores the
structured result as `success_contract`, together with its actual inputs, their
canonical hash, the sidecar hash, the evaluator hash and per-predicate results.

Facts are added to the downstream input dictionary only when that round succeeds.
Failed output may remain visible in the trace for diagnosis; those observations
are not forwarded as successful facts. Existing precondition semantics are kept:
a failed applicable precondition stops downstream rounds, while an explicitly
declared `skip_exits` result remains an inapplicable precondition and permits
independent downstream work.

The original seven verdict gates retain their implementations. An eighth gate,
`success_contract`, checks each round offered as **successful evidence**. It
requires a complete current contract and re-evaluates the stored inputs. A
caller-written `ok: true`/`complete: true` marker is insufficient. Unrelated failed
or skipped attempts do not by themselves invalidate other sufficient successful
evidence. The other seven gates continue to decide process, reachability,
observation, independence, bounded claim, uncertainty and discharged guards.

Old evidence without this result is explicitly `legacy_evidence_without_contract`.
The implementation does not rewrite old receipts or retrospectively label their
providers verified. The input hash detects inconsistent data and binds a result to
its inputs; it is not a signature proving that a provider really produced them.
The live mission supplies its own runner outputs. This feature does not introduce
an externally authenticated receipt ingestion protocol.

## Ghidra artifact and stdout identity

For `native.ghidra.decompile`, the mission resolves `{scratch:ghidra-out}` to a new
GUID-named directory inside the case on each execution. Repeating a case does not
reuse the previous summary directory. The runner context records that the mission
created this directory and that `summary.json` was absent before dispatch.

The evaluator reads exactly that directory's `summary.json`. It requires an
ordinary file, an ordinary directory and ordinary ancestors up to the volume
root. A symlink or Windows junction at any checked level is refused, even if its
leaf child appears ordinary. This conservative rule means a case directory below
a junction must be moved to an ordinary physical path to use this contract.

The file must parse to an object whose canonical JSON value equals the stdout
object, and its `ok` must be true. The file's SHA-256 is recorded. Missing files,
malformed JSON, stale/reused context, a substituted file path, or a different
stdout object fail. A stdout-provided `outdir` is not trusted to choose the file.
Rechecking a Ghidra record reads the assigned artifact again.

These checks establish consistency for the runner-owned summary. They are not an
OS sandbox, an atomic file-handle protocol, protection against every filesystem
race, or a binding of each decompiled `.c` file to a hash. A tool running with the
same OS permissions is still outside those stronger guarantees.

## Whole-object fact mapping

`$` is a reserved **source key in `invoke.fact_map`** that selects the whole parsed
JSON object. It is not a general JSONPath language and does not change ordinary
field lookup:

```json
{
  "fact_map": {
    "$": "native.ghidra.summary",
    "outdir": "native.ghidra.outdir"
  }
}
```

This maps the actual Ghidra report without requiring the emitter to wrap itself in
a duplicate `summary` field. Null or unparseable stdout creates no whole-object
fact. The successful-round gate still controls whether any mapped fact can be
forwarded.

## Installed dependencies and verification

The installation closure explicitly includes `scripts/mission.ps1`, the module,
the sidecar, and the narrow `tests/mission_contract` fixture/probe files. The runtime
refuses a missing module or invalid sidecar before any runner is launched.

**A bare `-SkipTools` installation can run the pure contract probe.** It needs
Windows PowerShell 5.1 or PowerShell 7, those installed first-party files, and a new
writable output directory on an ordinary local filesystem that supports Windows junctions. Its Ghidra files and junction
control are owned test fixtures. It does not need a corpus binary, DIE, Python,
Git, an MCP backend or a running provider:

```powershell
# From the installation root; choose a new directory for every run.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/mission_contract/contract_probe.ps1 -OutDir C:/owned-test-output/contract-001
```

**The full historical `Selftest` and `Ablate` have additional prerequisites.** Run
them from a prepared workstation/source tree with a usable Git repository/index
and `git` on PATH. Their existing real-registry control reads the compiled,
author-owned `crackme-corpus/out/c01-stringobf.exe` using the complete runnable DIE
portable installation at `Static-Reversing/die_win64_portable_3.21_x64/die/`,
including `diec.exe` and its runtime dependencies. They also invoke the Windows
`powershell` command internally, even when the outer invocation uses `pwsh`.
Those binary/tool/index prerequisites are not installed by this narrow closure
change and are not promised by `-SkipTools`. The closeout integration fixture
explicitly copied the corpus binary and DIE, and created its own Git index before
running these commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/mission.ps1 -Action Selftest
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File scripts/mission.ps1 -Action Selftest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/mission.ps1 -Action Ablate
```

The separate wiring probe needs Python, Git, Windows PowerShell 5.1 and PowerShell
7 available by their usual command names. It creates its own Git fixture trees
and runner scripts, and does not require c01, DIE or another third-party provider:

```powershell
python -B tests/mission_contract/mission_wiring_probe.py --out-dir C:/owned-test-output/wiring-001
```

`Selftest` retains the original seven-gate controls and adds controls that call the
full eight-gate implementation. Its historical synthetic evidence is supplied with
explicit raw fixtures passed through the real evaluator; no helper inserts a bare
pass marker or grants unknown identifiers success. `Ablate` makes each of the eight
gates permissive in turn and requires a meaningful control failure.

The standalone predicate probe includes legal negative measurements, one
independent negative per declared predicate, malformed types, unknown/drifted
contracts, unavailable transport, artifact disagreement and receipt rechecking.
The wiring probe runs the actual mission entry point against owned fixture
registries and runner processes, then inspects real artifacts and traces for
fact-forwarding, precondition behavior, Ghidra freshness and serialized-record
rechecking. It also accepts `--mission-source` to run the same inputs against a
frozen earlier mission implementation. Those runners are explicit fixtures; their
results do not stand in for live IDA, Ghidra or other provider execution.

Current execution receipts, source hashes and the independent old/new counterexample
results belong to the dated closeout evidence package. This document describes the
installed behavior and its limits; it does not alter any frozen historical receipt.
