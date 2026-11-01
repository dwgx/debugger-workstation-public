> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/AgentWorkflow.md (125 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "status": "DONE",
  "report_path": "%TEMP%/w1-agentworkflow.md",
  "report_bytes": "53505",
  "report_lines": "954",
  "patterns_delivered": "22",
  "primary_source_urls": "18",
  "repo_writes": "none — all experiments ran on copies in %TEMP%\\ablate and %TEMP%\\rv-base",
  "baseline_docs_read": {
    "item": [
      "<repo>/docs/research/agent-craft-principles.md",
      "<repo>/docs/research/orchestration-design.md"
    ]
  },
  "measured_findings": {
    "item": [
      {
        "id": "P1",
        "claim": "6 of 7 verdict gates in mission.ps1 are removable with the entire 15-control selftest still green; only bounded_claim is load-bearing",
        "method": "copied mission.ps1 + gate.ps1 + capabilities.json to %TEMP%\\ablate, confirmed 15/15 green on the unmodified copy, then rewrote each `G '<gate>' <expr>` to `$true` in a fresh copy and re-ran -Action Selftest",
        "output": "BASELINE exit=0 failing_controls=0; process/reachability/observation/independence/uncertainty/discharged all exit=0; bounded_claim exit=2 with 1 red control",
        "source": "https://raw.githubusercontent.com/anthropics/skills/main/skills/claude-api/shared/evals/eval-audit.md (the mechanism is wired: disable it and confirm the score drops) + https://www.anthropic.com/engineering/harness-design-long-running-apps"
      },
      {
        "id": "P1b",
        "claim": "10 of 11 registry-verify.py rules are load-bearing; r_shape is not tested",
        "method": "inserted `return []` as the first statement of each rule function in a fresh copy, ran --selftest",
        "output": "all 11 ablations; 10 exit=2 with named red cases, r_shape exit=0",
        "source": "same eval-audit.md §5"
      },
      {
        "id": "P10",
        "claim": "the fuzz negative control passes for the wrong reason",
        "method": "ran both invocation forms",
        "output": "`fuzz-lab.ps1 --budget 12` -> exit 2, {\"error\":\"unknown action --budget\"}; `fuzz-lab.ps1 loop --budget 12` -> exit 1, \"--budget 12 is below the floor of 40.\" orchestration-design.md:274 records exit 2 as the floor refusal",
        "source": "eval-audit.md §2 errors.jsonl sidecar / 'score plumbing as a model failure'"
      },
      {
        "id": "P6",
        "claim": "recorded figures contradict each other under identical date stamps",
        "output": "D: recorded 288 GB at mobile-js-skill-map.md:14 and :612, and 172.12 GiB free of 640.12 at mobile-js-skill-map.md:779, binary-mcp-map.md:375, orchestration-design.md:469 — all dated 2026-10-02. Measured now: 168.42 free of 640.12. E: 28.01 of 33.67 still matches, so the drift is selective",
        "source": "prompt-audit.md Group 2 Volatile specifics"
      },
      {
        "id": "P7",
        "claim": "state:observed is not bound to a run",
        "output": "native.ida.decompile.probe = {command, expect:\"LOOP CLOSED\", exit:0, last_run:\"2026-09-30\", last_summary:<hand-transcribed>} — no sha256, no run-log reference, no verified_at",
        "source": "agent-design.md staleness-checks criterion + https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents"
      },
      {
        "id": "P17",
        "claim": "negative result: both-direction coverage is already present, contradicting the brief's framing",
        "output": "gate.ps1 10 controls = 3 grants / 7 refusals; mission.ps1 15 controls = 10 refusals / 5 positives",
        "source": "demystifying-evals §3 / eval-audit §1 both-directions coverage"
      }
    ]
  },
  "top_5_ranked": {
    "item": [
      {
        "rank": "1",
        "pattern": "P1",
        "action": "mission.ps1 -Action Ablate plus per-gate controls",
        "reason": "the only measured defect in our own harness; ~25 lines; the arsenal's central claim (the model never writes the verdict) is currently enforced by 1 of 7 gates"
      },
      {
        "rank": "2",
        "pattern": "P10",
        "action": "add negative_control.expect_stderr, required and non-empty, enforced by R5",
        "reason": "measured; a control that passes while testing the wrong invariant; generalises to all 15 negative controls; ~10 lines"
      },
      {
        "rank": "3",
        "pattern": "P6",
        "action": "static fact-linter over recorded figures in docs/**/*.md",
        "reason": "direct fix for the estate's named chronic failure; evidence on disk with identical date stamps; ~40 lines read-only; folds into smoke-all's existing pass/fail line"
      },
      {
        "rank": "4",
        "pattern": "P7",
        "action": "state_evidence {run_log, probe_stdout_sha256, registry_sha256} + new rule R11",
        "reason": "state is the field the whole registry is built on and is a hand-written date string; Anthropic measured the model flipping exactly this kind of status without running the test"
      },
      {
        "rank": "5",
        "pattern": "P18",
        "action": "the missing oracle: one end-to-end mission control asserting tier=confirmed, >=3 capabilities, >=1 satisfied consumes link",
        "reason": "largest untested surface — both halves of Invoke-Mission are tested, the seam never has been; ranked fifth only because it needs a real target and ~10 min per run"
      }
    ]
  },
  "empty_results": {
    "item": [
      "gh search repos \"agent skills claude\" — top hit 6332 stars (internet-court/internet-court-skill), then a design-token extractor; no validator, no negative control, no measurement",
      "gh search repos \"subagent orchestration\" — 1033 stars a monitoring dashboard, 749 stars a prompt collection",
      "gh search repos \"context engineering agent\" — 314 stars a handbook index; no pattern source",
      "self-verification literature (Chain-of-Verification, self-consistency, MARCH) deliberately not adopted: the mechanism in all of them is the same model checking itself, which trailofbits says degrades output and Anthropic measures as the weak option",
      "agents.md reported as 179285 stars and claude-code as 148826 by the GitHub API on 2026-10-02; reported as returned, no conclusion drawn because the numbers are almost certainly wrong"
    ]
  },
  "unverified": {
    "item": [
      "the AgentProp-Bench '24 percentage points' figure is garbled in the served arXiv text; marked [UNVERIFIED] and not relied on",
      "no model was run; P3/P14/P16 discuss model behaviour by citation only",
      "P18's oracle control is specified, not executed",
      "P7/P10/P20 patches are sketches, none executed",
      "smoke-all.ps1 not run (~270s); parent's pass=19 fail=0 used as inherited",
      "gate.ps1 -Action Selftest not executed directly; its 3/7 direction census is from reading gate.ps1:340-386 (it was exercised indirectly through the mission selftest)"
    ]
  },
  "dependencies_for_siblings": {
    "item": [
      "RevSkills owns the skills slice; P21 and P19 touch skill/sizing conventions and should land there rather than here",
      "the P1 ablation patch edits scripts/mission.ps1 — if a sibling is already editing that file, merge there"
    ]
  },
  "acceptance_check": {
    "at_least_15_patterns": "22",
    "each_with_primary_source_url": "true",
    "each_mapped_or_explicit_no_equivalent": "true",
    "ranked_top_5_with_reasons": "true",
    "distinguishes_primary_from_commentary": "true",
    "reports_empty_searches": "true",
    "no_padding": "true"
  }
}