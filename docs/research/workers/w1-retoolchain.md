> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/REToolchain.md (76 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "status": "STATUS: DONE",
  "report": "%TEMP%/w1-retoolchain.md",
  "report_bytes": 29964,
  "rows_written": 40,
  "acceptance": [
    "table>20 tools with name/what-it-adds/licence/Windows-native/install-command/disk/proving-command/verdict: DONE (~40 unique tools across 7 themed tables)",
    ">8 rows with a command verified on the tool's own site or repo: DONE (20 entries in the provenance section)",
    "top-8 ranked by capability-per-gigabyte: DONE",
    "no repo writes, no installs: DONE (only pip --dry-run --no-cache-dir resolution; scratch scripts deleted)"
  ],
  "key_machine_facts_verified": [
    "no clang/clang-cl/llvm anywhere; VS 'LLVM tools' component contains only clang-format.exe and clang-tidy.exe",
    "MSVC cl.exe 14.44.35207 present; cmake 4.4.3, git 2.55, cargo 1.98, go 1.26.7, .NET SDK 10.0.400, Python 3.14.7 + uv",
    "E: free = 30,080,245,760 B (28.01 GiB)",
    "installed pip RE packages: only capstone 5.0.9 and pefile 2024.8.26"
  ],
  "instrument_bugs_found": [
    "pip install speakeasy installs an unrelated metrics-aggregation server; the emulator is speakeasy-emulator, which pins unicorn==1.0.2 and will fight angr/Qiling",
    "pip install snowman is a xueqiu portfolio tool, not a decompiler; the real Snowman upstream is dead since 2017-09-29",
    "triton 3.8.0 has zero Windows wheels (12 manylinux-only wheels); pip dry-run returns rc=1 'No matching distribution found'",
    "Intel Pin 4.4 dropped the MSVC kit entirely - Windows builds need clang-cl, which this box lacks",
    "nccgroup/Nemesis, ezyang/muesli and VirusTotal/ligma are all HTTP 404; sslab-gatech/qsym is archived since 2022",
    "firmware-tools has no PyPI package - the name in the brief is unverified"
  ],
  "top8_capability_per_gb": [
    "1. libfuzzer-dotnet + SharpFuzz - 1.5 MB - coverage-guided .NET fuzzing, SDK already installed",
    "2. LIEF 1.0.0 - 4.1 MB - PE/DLL static rewriting, IAT and section surgery",
    "3. Speakeasy - 19.4 MB - unattended Windows unpacking/shellcode triage with JSON reports",
    "4. Unicorn + Keystone - 17.3 MB - CPU emulation + assembly substrate for decryptors",
    "5. angr 10.0.1 - 69.9 MB - CFGFast on stripped PEs, decompiler, symbolic execution",
    "6. WinAFL + DynamoRIO - 466.2 MB - black-box coverage-guided fuzzing of closed-source Windows binaries",
    "7. LLVM + clang-cl - 374.3 MB - multiplier that unblocks libFuzzer, Intel PIN, AFL++-on-Windows and atheris",
    "8. retdec v5.0 - 165.6 MB - independent headless decompiler as a disagreement check"
  ],
  "adopt_set_cost": {
    "verified_download_bytes": "1.12 GB",
    "pct_of_free_E": "4%",
    "installed_estimate": "~5 GB [INFERENCE], >22 GiB still free"
  },
  "rejected": [
    "Triton (no Windows wheels)",
    "Snowman (dead upstream, PyPI name collision)",
    "Hopper (macOS-native)",
    "rev.ng (Linux/macOS only)",
    "goblin (duplicates pefile+LIEF)",
    "KLEE, SymCC, QSYM, muesli (Linux/clang-only, archived or 404)",
    "AFL++ (no Windows build), honggfuzz (no Windows target), atheris (manylinux-only wheels)",
    "Fuzzilli, AFLNet, syzkaller, panda (no reachable Windows domain)",
    "qiling, unblob, binwalk, hashdeep, yara-python, vivisect, Miasm (DEFER)",
    "Ligma/Nemesis/yara-gen (404 or unproven)"
  ],
  "unverifiable": [
    "installed (uncompressed) sizes - all disk figures are verified download bytes",
    "LLVM-23.1.2-win64.exe size (21.1.0 measured at 374.3 MB)",
    "whether frida/objection/capa/floss/yara-x are actually runnable - not on PATH in my shell",
    "Qiling rootfs download size",
    "Miasm on Windows (pip resolves but no Windows-supported command found on project docs)",
    "Binary Ninja installer size",
    "yara-x CLI binary name (docs index 404'd; rule language verified from repo README)"
  ],
  "coverage_of_fuzz_lab_gap": "WinAFL adds feedback fuzz-lab cannot have: edge coverage from a closed-source PE, corpus minimisation (winafl-cmin.py), crash dedup, persistent-mode restart, and a network test-case DLL path - so it supersedes rather than complements fuzz-lab.",
  "next_action_for_main": [
    "decision_needed: LLVM on/off - it is the gate for 4 rows",
    "ask_DebugPairing whether an LLVM install exists outside my search paths, since that flips PIN/atheris/AFL++ to ADOPT",
    "flag_GateRedTeam that DynamoRIO and WinAFL -A attach mode cross the debugging-lane attach boundary",
    "Speakeasy must land in its own venv to avoid downgrading unicorn to 1.0.2"
  ],
  "red_lines_respected": [
    "no repo writes",
    "no installs (pip --dry-run --no-cache-dir only)",
    "no certutil/store changes",
    "no proxy changes",
    "no sample or exploit material",
    "scratch scripts deleted; only the report file remains"
  ]
}