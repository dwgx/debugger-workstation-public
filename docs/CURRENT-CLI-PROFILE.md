# Current bounded CLI profile

This handoff describes the candidate strict CLI runner added in the final PRO
review. A passing selected profile does not pass `public-core`, the complete
workstation, a real MCP provider, or a release gate. Historical release evidence
keeps its original status.

## Entry and execution

Start with `docs/AI_ENTRY.md` (or `docs/AI_ENTRY.zh-CN.md`) for workstation routing.
For a reproducible selected Python CLI execution, the coordinator prepares a
`debugger-run-plan.1` JSON document **outside the installed source tree** and pins
its SHA-256 before starting the runner. The plan binds the source manifest,
Python executable, tool, target bytes, oracle, fixed check IDs, denominator,
attempt ID, output contract, timeout, and optional failed parent attempt.

The installed package includes a caller-side generator for this exact limited
PCAP profile. It creates one authored DNS-query packet, a six-check oracle,
source manifest and plan in a **new external directory**. It does not run the
parser or claim that the profile passed. From any working directory, use:

```text
python -X utf8 -B <installed-root>/scripts/freeze-pcap-plan.py --source <installed-root> --out <new-external-run-directory> --source-commit <reviewed-40-hex-source-baseline>
```

Retain the printed `expected_plan_sha256` in the coordinator's record before
execution. The generated `caller-freeze.json` also contains `runner_argv` and
`verifier_argv` arrays with absolute paths and the actual Python executable.
Run those commands in that order. The source commit is supplied provenance for
this manifest installation, not an observation of a local Git repository. Add
`--source-repo <reviewed-source-identity>` when a repository label is known. If
omitted, the plan records the measured absolute source directory; it does not
assign a public-repository identity to a private installation.

The underlying commands are:

```text
python -X utf8 -B scripts/assert-probes.py --plan <absolute-plan.json> --expected-plan-sha256 sha256:<pinned-digest>
python -X utf8 -B scripts/verify-profile.py --product --plan <absolute-plan.json> --expected-plan-sha256 sha256:<pinned-digest> --runner-terminal <absolute-attempt-directory>/terminal.json
```

The coordinator supplies the expected digest; do not copy it from an untrusted
receipt. `scripts/runner_evidence.py` provides `python_identity()` and
`freeze_source_manifest()` as data helpers. Its plan validation is the versioned
contract. The generator above is available in the installed package; developer
tests are not required to construct or run this profile.

The selected real-tool integration used for review is
`net-reverse/tools/pcap_reader.py`: offline parsing of a controlled synthetic PCAP.
Its input origin remains explicit. It establishes no live capture, remote
target, decompiler, debugger, or other backend capability.

## Read the result correctly

`PROFILE_PASS` requires the frozen semantic assertions and negative assertion,
the complete check set, successful execution, verified retained artifacts, and
observed cleanup. Raw stdout and stderr are separate files. `intent.json`
precedes dispatch; `receipt.json` and `terminal.json` bind the retained results.
An existing attempt ID is never reused. For a retry, give the generator a fresh
external output directory and add `--parent-terminal <failed-terminal.json>`.
It generates a fresh attempt ID, pins the failed parent's terminal digest, and
preserves its terminal, receipt, intent and artifact bytes. It does not retain
the parent's external plan, oracle or source snapshot automatically; the caller
must archive those too if the parent must remain independently reproducible.

After dispatch, cancellation or timeout does not imply that the backend never
executed. A missing terminal, unknown cleanup, mismatched bytes, missing trusted
inputs, or unsupported schema cannot become a passing product result. Legacy
v1/v2 receipt fixtures remain available as **static diagnostics** without
`--product`; they do not demonstrate an actual new run.

## Scope and trust

This is local tamper detection under a trusted coordinator and runner, not a
signature or hardware attestation. A writer who can replace every trusted input
and observation is outside the claim. Manifest-based installations report
manifest provenance and do not claim to have observed a Git checkout. Python
executable and selected source bytes are bound; the full OS and standard library
are not attested. The shipped PCAP generator enumerates this parser's local
dependencies. A custom tool's dependency closure is not discovered automatically
and needs a separate reviewed manifest and admission test.

Windows runner cleanup covers its direct child. POSIX cleanup covers the owned
process group; a process that detaches into another session is outside that
scope. Arbitrary descendant cleanup remains unverified for this CLI profile.

The separate Router wire tests exercise a real MCP frontend and SDK with an
owned synthetic backend. They do not convert this CLI profile into MCP or
real-provider acceptance. Consult the final review execution pack for observed
test receipts, exact candidate hashes, remaining work orders, and the guarded
apply/rollback procedure before adopting or publishing the candidate.
