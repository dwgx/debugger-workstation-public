---
tags: [debugger]
status: verified
source: agent-notes 2026-10-12
---

# rea-and-ida-session-lessons

REA (morluto/rea, rea-agents 6.4.0) + IDA/Ghidra lessons, measured 2026-10-12 (lanes L119/L126/L140, Romantic project).

WIRING IS THREE USER ENV VARS, NOT A CONFIG FILE.
  GHIDRA_INSTALL_DIR  = <repo>\Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC
  REA_IDA_MCP_CONFIG  = <repo>\MCP\rea-ida-registration.json
  JAVA_HOME           = D:\Software\Developer\jdk\21
With those, "rea doctor --provider ghidra" is fully green and
"rea decompile <target> --procedure get_sizes --provider ghidra" exits 0 with byte-identical
output across two runs. setx persists for NEW processes only; the current shell still needs an
explicit export. Evidence: <project>\Romantic\research\REA-DECOMPILE-WIRING.md section 1.1.

REA-IDA FAILURE IS CONFIG DEFAULT + PARAMETER CONTRACT, NOT A PROTOCOL BUG.
Two independent causes, both measured:
 (1) rea-ida-registration.json has no "mode" field, so REA defaults to the attached (legacy 1.4)
     profile while this host's idalib-mcp only exposes the modern tool surface. The handshake
     fails in under a second. Adding "mode":"headless" makes it connect and disassemble.
 (2) REA 6.4.0's IDA adapter sends {addr, offset, max_lines} to decompile, but the local idalib
     decompile accepts only {addr, database, include_addresses}; the call fails with
     "Invalid params: unexpected parameters: ['max_lines','offset']".
Going straight to the idalib supervisor (no REA) works and agrees with Ghidra value-for-value
(32/64/32). So the honest statement is "this combination is unusable on this host", not
"REA does not support IDA". Evidence: same file, sections 0 and 3.

IDA'S isError:false TRAP, REPRODUCED LIVE.
A failed decompile comes back with the ENVELOPE isError = false while the payload carries
error plus code: null. A wrapper that only tests isError treats a failed decompile as an empty
result and keeps going. Check the payload error field and a null code, never the envelope flag.
This is the trap already written in the station SKILL.md 2.2; this session reproduced it verbatim.
Evidence: same file, section 3.4 (a).

idb_open WRITES THE IDA DATABASE NEXT TO THE TARGET.
idb_open creates .i64/.id0/.id1/.id2/.nam/.til in the target's own directory. An earlier run
dropped them into the live Steam install tree
(D:\Steam\steamapps\common\VRChat\VRChat_Data\Plugins\x86_64\vrc_fast_crypto.dll.i64 ...).
Rule: copy the target into work/ first and open the copy. Re-checked after the run: the live
install directory holds only the original DLL. Evidence: same file, section 3.4 (b).

## 追加（2026-10-16，windsurf-re 波 2 实测）

DEFAULT ANALYSIS TIMEOUT IS TOO SHORT FOR MEDIUM RUST PEs. `rea decompile` on a 7.8 MB
PE32+ (Rust) exits 1 with `provider_timeout` under the dist default
`DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS=330_000`; the provider needs ~660-710 s per full fresh
Ghidra analysis. Fix = the official knob, exported in-session:
`REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000` (30 min). Then `rea search --kind procedures` =
13,834 procedures and `rea decompile <t> --procedure FUN_1403cd050 --provider ghidra`
x2 -> exit 0 (708 s / 672 s), stdout sha256 identical (`6c4ae778…`), cmp = 0 bytes.
Attribution: config default, not a contract/environment defect; tool unmodified.
Also: on this host bare `bash script.sh` resolves to WSL (exit 127) — invoke via `sh`
or the Git bash absolute path. Evidence: `Reports/private/windsurf-re-20261015/derived/rea-sample/`
+ `dispatches-20261015/REA-SAMPLE.report.md`.
