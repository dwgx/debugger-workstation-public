> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/ToolPerf.md (189 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "status": "DONE",
  "report_path": "%USERPROFILE%/AppData/Local/Temp/w1-toolperf.md",
  "rows_measured": 15,
  "runs": 38,
  "instrument_bugs_found_and_fixed": 3,
  "instrument_note": "CIM/WMI returns nothing on this box (empty Win32_LogicalDisk too), so RSS is sampled via psutil. My first contention runner timed children from communicate() rather than launch and reported 0.00 s for an already-exited probe; v2 built results before joining watchers and did it again for 2 of 3 probes. Only v3 (per-child thread owns the lifecycle) is in the report. Two earlier samplers also died on psutil.NoSuchProcess under Ghidra load and degraded to 0 MB, making the most expensive probes look free.",
  "cost_matrix": [
    {
      "probe": "net-reverse/trustcheck.mjs",
      "wall_med_s": 0.22,
      "spread_s": 0.01,
      "tree_MB": 65.6,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "native-lab/tools/loop.mjs",
      "wall_med_s": 2.13,
      "spread_s": 2.01,
      "tree_MB": 247.9,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "scripts/smoke-tools.ps1",
      "wall_med_s": 2.84,
      "spread_s": 0.06,
      "tree_MB": 169.5,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "web-reverse/tools/loop.mjs",
      "wall_med_s": 3.92,
      "spread_s": 0.1,
      "tree_MB": 689.3,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "crypto-lab/tools/loop.mjs",
      "wall_med_s": 4.27,
      "spread_s": 1.2,
      "tree_MB": 129.4,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "mobile-lab/tools/loop.mjs",
      "wall_med_s": 5.33,
      "spread_s": 0.69,
      "tree_MB": 388.6,
      "disk_delta": "±4 B",
      "rss_samples": 3
    },
    {
      "probe": "forensics-lab/tools/loop.mjs",
      "wall_med_s": 6.95,
      "spread_s": 15.79,
      "tree_MB": 144.3,
      "disk_delta": "0 B",
      "note": "22.30 s first run was cold cache, re-measured 5.99/6.14/6.40 warm",
      "rss_samples": 3
    },
    {
      "probe": "web-reverse/tools/loop2.mjs",
      "wall_med_s": 7.03,
      "spread_s": 10.77,
      "tree_MB": 751.3,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "net-reverse/tools/loop.mjs",
      "wall_med_s": 8.28,
      "spread_s": 2.44,
      "tree_MB": 595.5,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "scripts/il2cpp-probe.ps1",
      "wall_med_s": 12.34,
      "spread_s": 0.14,
      "tree_MB": 162.4,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "managed-lab/tools/loop.mjs",
      "wall_med_s": 13.46,
      "spread_s": 1.69,
      "tree_MB": 188.9,
      "disk_delta": "0 B",
      "rss_samples": 3
    },
    {
      "probe": "scripts/emulation-probe.ps1",
      "wall_med_s": 17.68,
      "spread_s": 5.16,
      "tree_MB": 1321.5,
      "disk_delta": "0 B",
      "note": "verdict is 'blocked'; exits 0 while printing fail:1",
      "rss_samples": 6
    },
    {
      "probe": "scripts/ghidra-failopen-regress.ps1",
      "wall_med_s": 24.77,
      "spread_s": 1.87,
      "tree_MB": 1447.8,
      "disk_delta": "0 B",
      "note": "heaviest RAM item measured",
      "rss_samples": 2
    },
    {
      "probe": "crackme-corpus/tools/loop.py",
      "wall_med_s": 119.48,
      "spread_s": 26.47,
      "tree_MB": 1410.6,
      "disk_delta": "+2 B",
      "rss_samples": 3
    },
    {
      "probe": "fuzz-lab/tools/loop.mjs --budget 40",
      "wall_med_s": 704.7,
      "spread_s": 1038.27,
      "tree_MB": 542.5,
      "disk_delta": "+2.2…+4.7 KB",
      "note": "4 runs: 1071.37s exit0, 33.10s exit9, 704.70s exit0, 982.05s exit0",
      "rss_samples": 4
    }
  ],
  "contention_claim_verdict": "NOT REPRODUCED",
  "contention_evidence": [
    "All three Ghidra-consuming probes launched simultaneously (contend.py v3): batchWall 103.47 s vs sum-of-solo-medians 161.93 s, batchPeak 3405.5 MB / 61 procs, allPassed true. Concurrency SAVED ~59 s; nothing was killed by timeout.",
    "Per-probe: ghidra-failopen +3.4%, emulation-probe +1.5%, crackme-corpus -13.4% (faster). The dominant effect is host load from the parent's parallel work, not probe-vs-probe contention (box was at 81.9-88.7% RAM).",
    "Cheap tier of 5 labs, two independent trials: batch 21.65 s / 8.40 s against sums of 36.44 s / 25.10 s. Both allPassed true.",
    "REAL hazard is fixed loopback ports and it is a hard fail, not a timeout: 2x crypto-lab (both bind 8791) -> one exits 1 with uncaught EADDRINUSE; 2x native-lab (both bind 8745) -> loser exits 1 via its portFree() guard reporting {total:2,pass:1,fail:1}."
  ],
  "startup_vs_steady_state": {
    "baselines": "node -e 0.035 s @ ~49 MB; python -c 0.033 s; powershell -NoProfile -Command 0.18 s @ ~60 MB; java -version 0.04 s @ ~27 MB; one full Ghidra headless run on the 140.5 KB crackme = 20.43/20.7/21.1/21.9 s @ 0.98-1.2 GB, 520 files, 671,991 bytes",
    "classification": "All 9 Node/Python labs are compute-bound: interpreter boot is 0.3-1.6% of wall. All 3 Ghidra-backed probes are startup-bound: emulation-probe's 17.68 s is LESS than one Ghidra launch and delivers zero capability (recorded blocked); ghidra-failopen 84.8% startup; crackme-corpus is 4 Ghidra launches = 74% of wall (loop.py has build=='c' on 4 of 5 challenges).",
    "process_churn": "net-reverse spawns 60 distinct children (13 concurrent), web-reverse 51 (13 concurrent) - their cost is process churn, which is what bites under parallel load."
  },
  "disk": {
    "E_growth": "ZERO. E: read 28686.8 MiB free at session start and 28686.8 MiB after ~25 probe executions including 5 crackme runs and a 3-way concurrent Ghidra trial. Ghidra projects land on C: %TEMP%, not E:.",
    "accumulation": "Per-run deltas are flat (crackme +2 B, fuzz-lab/out +2.2-4.7 KB, everything else 0 B) - every lab rewrites in place. Only fuzz-lab/crashes trends up (97 to 101 files across my runs) and it is gitignored.",
    "total_after_session": "out/ 0.58 MiB; crackme-corpus/out 12.57 MiB; fuzz-lab/crashes 4.99 MiB; mobile-lab/out 4.33 MiB; managed-lab/out 1.33 MiB; headless-lab/out 0.21 MiB"
  },
  "routing_table": {
    "TierA_every_mission": "net-reverse/trustcheck.mjs (0.22 s, 65.6 MB), native-lab/tools/loop.mjs (2.13 s, 247.9 MB - cheap but port-bound on 8745, never concurrent), scripts/smoke-tools.ps1 (2.84 s, 169.5 MB)",
    "TierB_on_demand": "crypto-lab, web-reverse, mobile-lab, forensics-lab, web-reverse/loop2, net-reverse, il2cpp-probe, managed-lab - ~57 s serial, or 8.40 s as one concurrent batch",
    "TierC_never_on_a_mission": "crackme-corpus (113-140 s, 1411 MB - proves the tooling not the target), fuzz-lab (705-1071 s, 542 MB - nightly), emulation-probe (17.68 s, 1322 MB - blocked capability on a deprecated API), ghidra-failopen-regress (24.77 s, 1448 MB - harness regression, belongs on harness-change CI)",
    "rule": "RAM is the scarce resource, not time. Serialise anything that starts a Ghidra JVM (~1.2-1.3 GB each; three at once measured 3405 MB / 61 procs on a box with 3.5 GiB free, which is exactly where WinError 1455 paging-file-too-small appeared). Parallelise everything else."
  },
  "doc_contradictions_found": [
    "HANDOFF.md:233 and :257 - contention claim not reproducible (§3).",
    "HANDOFF.md:254 - '18.1 MB of stale %TEMP%\\ghidra-proj-* on E:' not reproducible: E: has ZERO such dirs; C: has one holding 586 bytes, not 5 dirs / 18.1 MB. Two further headless runs left count and bytes unchanged. That open cleanup item can likely be closed - but deleting is Owner's call and I deleted nothing.",
    "fuzz-lab --budget 40 is NOT reliably green: 1 of 4 runs exited 9 with 'web-triage: the flawed twin SURVIVED'. The documented MIN_BUDGET floor of 40 is not a reliable floor. Recorded, not patched - outside my slice.",
    "crypto-lab has no portFree() guard and dies on uncaught EADDRINUSE (crypto-lab/lab/server.mjs:318 binds 8791); native-lab has the guard (native-lab/tools/loop.mjs:105) and reports cleanly.",
    "emulation-probe exits 0 while printing fail:1 - correct by design but 'exit 0' there does not mean the capability works."
  ],
  "unverifiable": [
    "Python peak-RSS baseline: python -c print(1) returns in 0.033 s, faster than the 20-50 ms sampler interval, so psutil recorded 0.0 MB. The 0.033 s TIME is real; the RSS is not measured. Needs a <=5 ms sampler or Get-Process immediately after start. Only this baseline is affected - every probe RSS in the matrix measured fine.",
    "Aggregate smoke-all.ps1 total: forbidden by brief. Per-probe medians sum to ~1050 s with fuzz-lab / ~360 s without, against the recorded ~270 s aggregate - but the aggregate ran a DIFFERENT probe set, so the two are not comparable and I did not reconcile them.",
    "Idle-box wall times: host was at 81.9-88.7% RAM with the parent's work throughout; spreads are wide (crackme 26.5 s, fuzz 1038 s).",
    "fuzz-lab at budget 90: 12-18 min per run; parent ground truth already records 740 s.",
    "The 20+ PowerShell lab wrappers (native-lab.ps1, crypto-lab.ps1, etc.) add a layer I did not time individually - I measured the underlying tools/loop.mjs entry points named in the brief."
  ],
  "dependencies_for_siblings": [
    "smoke-all.ps1 ALREADY emits per-probe seconds (scripts/smoke-all.ps1:141, printed at :149) - whoever runs the aggregate gets the timing table free, no new instrumentation.",
    "A portFree() guard for crypto-lab, for parity with native-lab, belongs in crypto-lab/lab/server.mjs:318 / tools/loop.mjs.",
    "manifests/capabilities.json has no cost fields; adding measured wall_s / peak_rss_mb would let gate.ps1 refuse an over-budget mission."
  ],
  "constraints_honoured": [
    "scripts/smoke-all.ps1 NOT run",
    "No repo file edited (git status shows only siblings' gate.ps1 / mission.ps1 / wiki changes, which are not mine)",
    "No out/ directory deleted",
    "Measured and reported only; nothing 'fixed'"
  ],
  "side_effect_disclosed": "psutil 7.2.2 pip-installed into D:\\Software\\Developer\\Python314 as the measurement instrument. Outside both repos. Harness and logs live in %USERPROFILE%\\AppData\\Local\\Temp\\w1perf\\.",
  "evidence_paths": [
    "%USERPROFILE%/AppData/Local/Temp/w1-toolperf.md",
    "%USERPROFILE%/AppData/Local/Temp/w1perf/measure2.py",
    "%USERPROFILE%/AppData/Local/Temp/w1perf/contend.py",
    "%USERPROFILE%/AppData/Local/Temp/w1perf/leaktest.ps1",
    "%USERPROFILE%/AppData/Local/Temp/w1perf/logs/ (25 raw files)"
  ]
}