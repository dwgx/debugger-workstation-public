# Current maintenance — 2026-11-19

This page separates the current source layer, dated execution evidence and pending
acceptance. It is not a release receipt and does not replace historical verdicts
under `releases/` or `evidence/`.

## Reading order

1. [AI entry](AI_ENTRY.md): station contract and package/evidence boundaries.
2. [Current CLI profile](CURRENT-CLI-PROFILE.md): bounded offline PCAP path,
   immutable attempts and caller-pinned provenance.
3. [Router descriptors](ROUTER_DESCRIPTORS.md): command/argv/cwd/environment
   identity and legacy-template versus explicit-descriptor behavior.
4. [Mission success contracts](MISSION-SUCCESS-CONTRACTS.md): typed output
   predicates, successful-evidence gate and unsupported live subjects.
5. [Repository index](INDEX.md): current routes and retained historical material.

## Source and denominators

The closeout layer covers PCAP wire boundaries, forensics JSON output, mobile
argument forwarding, Router descriptors, selected exit branches, registry
producer/fact pairing, PowerShell script-entry checks, inline-comment path
scanning, exact Owner-message attestation binding, package closure and entry docs.
Receipts must identify the exact source bytes they exercised.

The public manifest has 28 capability entries. Mission declarations number 29,
of which 25 have live subject adapters; this does not prove 25 external tools ran.
Router configuration has 20 backend definitions plus the Router entry. The
24-component manifest and historical 295-row inventory count different objects.
Do not add or substitute these denominators.

## Dated evidence and current acceptance

| Evidence scope | Recorded result | Limit |
| --- | --- | --- |
| Historical worktree installers | `windows-install-final-001`: 755 files, 45/45; later `installation-closure-wave`: 788 files, 45/45, dated 2026-11-13 | The former belongs to the 2026-11-12 closeout batch; neither is this integration's clean archive. |
| Historical installed missions | `installed-mission-final-001`: 10/10 with 136 synthetic predicates per shell; `mission-final-gates-002`: 86 controls per shell | 2026-11-12 closeout batch, reread 2026-11-19; receipts do not specify execution times. Bounded fixtures, not all external subjects. |
| Historical Owner gate selftest | 9/9 in the 2026-11-12 closeout batch | Text provenance and gate behavior for the tested version; batch date is not an asserted execution timestamp. |
| 2026-11-19 MCP SDK comparison | Wire 6/6 and descriptors 33/33 in each of the two tested SDK environments, including 1.30 | Protocol/descriptor coverage; not all backend tools. |
| 2026-11-19 original 7-Zip wrapper | Real positive and negative cases completed | Only the exercised wrapper/tool path. |
| 2026-11-19 E02_01 | 17/17 on frozen skill inputs | Does not cover subsequent Skill edits or changed hashes. |
| 2026-11-19 clean archive at `9b69579` | 785 files; **45/45 PASS**, no FAIL/BLOCKED | Actual PowerShell 5.1 and 7. Layout/script closure with tools and Router venv skipped; this is not full runtime acceptance. |
| Current edited skills in OMP 19 | Source/installed package checks, 22 copied payloads and three actual canonical reads passed on 2026-11-19 | Mechanical loader acceptance only; no new model call. Both unrelated global-alias warnings were retained. |

The new archive SHA-256 is
`c9ae0e6442e014f4320c6f739e72b35527c96b65f1c1eed30830047059ea1424`;
its 45-case report SHA-256 is
`8de4373fd5769d0732b40c9f765ff5d6210140f2ef66fd772aa69cb8e288c64f`.
The first archive's 41/45 receipt remains retained. Seven hash-bound fixture
paths now preserve their original bytes through Git checkout and archive;
receipt digests and validators were unchanged.
[CI run 44538403203](https://github.com/dwgx/debugger-workstation-public/actions/runs/44538403203)
also passed all five jobs at that commit, including archive installation, cache
regressions on both shells, and the 11-case mocked cleanup suite. CI retains
bounded raw evidence artifacts for 14 days. Later documentation-only commits
do not change which archive the above local receipt exercised.

The [Wireshark error-status patch](../patches/mcp-wireshark-0.5.0-errors/README.md)
also passed 19 selected unit cases and verification through the original live
wrapper. Its scope is decode errors and shared outer routing errors, not all tools.

These execution records belong to their dated audit evidence sets; this summary
does not make private receipt paths public prerequisites. Record the source hash,
command, environment and result with each final acceptance receipt.

## Resource cleanup correction

The CDP node collector now completes its owned browser/Chrome cleanup before
emitting a process-terminating result. Frida runtime facts now covers partial
staging/spawn/attach acquisition with the same cleanup guard. Eleven bounded
mock lifecycle cases passed; the unchanged original wrappers failed seven of
those cases. These are controlled resource-ownership tests, not live Chrome,
Frida, arbitrary process attachment or sample-execution acceptance.

## Remaining boundaries

- Full-product, public-core, release-candidate and publication acceptance remain
  separate from bounded tests; this page does not set them to true.
- IDA envelope transport, question-specific YARA semantics and the non-invocable
  Ghidra emulation entry remain unsupported live contracts.
- The forensics lab uses an authored synthetic directory, not a real memory image.
- Router child-tree cleanup and CLI runner cleanup are distinct. Windows
  direct-child runner evidence does not inherit Router Job Object claims.
- Bounded real wrapper receipts do not validate every tool or backend definition.
- Owner attestation checks an exact attributed message body. It is a text-provenance
  check, not a semantic consent classifier or tamper-proof authority.
- The Pages URL returned 404 on 2026-11-12 and 200 in the later 2026-11-13 check.
  Neither observation establishes availability of this integration's final
  published revision. A local page or successful build is not a live URL receipt.

## Re-entry after an interrupted closeout

Read exact source hashes, Git state and the pending process/result ledger before
repeating commands. Inspect an owned result path after a remote timeout; timeout
does not prove non-execution. Use a fresh external evidence directory, match
preimages before an explicit overlay, and preserve existing dirty work and prior
attempts. Do not rewrite old logs or infer deletion from a selected snapshot.

The 2026-11-12 execution package supplied apply/rollback tools and a Windows plan;
that package itself made no product commit, push or Pages change. Current actions
follow the clone owner's current authorization and existing approval mechanisms.
Report implementation, execution, independent acceptance and publication separately.
