> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/RevSkills.md (113 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "status": "STATUS: DONE",
  "report_path": "%TEMP%\\w1-revskills.md",
  "report_size": "37592 bytes / 336 lines",
  "acceptance": {
    "item": [
      {
        "criterion": ">=25 repo rows with stars/licence/date/tool/headless/risk",
        "actual": "33 rows, all columns populated",
        "verdict": "PASS"
      },
      {
        "criterion": ">=5 ADOPT with concrete install-and-prove command",
        "actual": "5 ADOPT sections, each with a runnable PowerShell block including negative controls",
        "verdict": "PASS"
      },
      {
        "criterion": "BORROW list specific enough to implement",
        "actual": "12 techniques, each with source file:line and an explicit 'Implement as:' action",
        "verdict": "PASS"
      },
      {
        "criterion": "every row cites the gh command",
        "actual": "all via gh api search/repositories + per-repo gh api repos/OWNER/REPO",
        "verdict": "PASS"
      },
      {
        "criterion": "failed searches reported as data",
        "actual": "'binja agent mcp' = 0 results (retried after rate limit, still 0); 12 rate-limited queries retried successfully",
        "verdict": "PASS"
      },
      {
        "criterion": "no repo modified",
        "actual": "git status --porcelain = 0 dirty entries in BOTH <private-tree> and debugger",
        "verdict": "PASS"
      },
      {
        "criterion": "scratch dir only, nothing installed",
        "actual": "%LOCALAPPDATA%\\Temp\\re-research\\ used for all clones/fetches; no installs performed",
        "verdict": "PASS"
      }
    ]
  },
  "scale": {
    "queries_run": "30",
    "rows_collected": "739",
    "distinct_repos": "492",
    "not_in_existing_corpus": "471",
    "deep_dived": "26",
    "source_files_fetched_and_grepped": "~440"
  },
  "critical_findings": {
    "item": [
      {
        "title": "The rubric my brief told me to use DOES NOT EXIST",
        "detail": "docs/research/skill-adoption-checklist.md is absent; glob **/*adoption* finds no such file. I did not invent 10 blocks and pass them off as ours — I derived each from a real cited line in the repo (agent-craft-principles.md:32,218-223; ida-mcp-source-study.md:442-446). Recommended action #1 is to actually write that file."
      },
      {
        "title": "4 'top candidates' are ALREADY vendored in our own mcp/ tree",
        "detail": "radareorg/radare2-mcp, zinja-coder/apktool-mcp-server, dnakov/frida-mcp, mrexodia/ida-pro-mcp confirmed via git remote origin.url. Recommending them as new adoptions would have been a duplicate-adoption failure. radare2-mcp upstream is 1.8.8 with .sha256 sidecars -> upgrade, not install."
      },
      {
        "title": "disrobe is not open source and blocks our exact mission",
        "detail": "LicenseRef-Disrobe-Source-Available-1.1: LICENSE-SUMMARY.md:7 requires a signed licence for bug-bounty work on in-scope targets; :19-20 no public forks; :21 a 24-month post-use non-compete; :22 no ML training. Hard reject despite 141 stars."
      },
      {
        "title": "ghidra-cli's only egress is a path we can simply not take",
        "detail": "reqwest is used solely in 'ghidra setup', which downloads+unzips Ghidra from api.github.com (ghidra_setup.rs:45,59,199). It honours GHIDRA_INSTALL_DIR (SKILL.md:506), so pointing it at our existing Ghidra 12.1.3 keeps every byte on-host."
      },
      {
        "title": "reverify ships a default list of third-party URLs to probe",
        "detail": "reverify_boundary_auditor.py:404-411 includes https://api.openai.com/v1 and 169.254.169.254. Running it as-shipped would send this box requests to external infrastructure. Adopting only the offline core; the auditor's URL list must be emptied and supplied per-case."
      },
      {
        "title": "incogbyte's Android skill harvests Firebase/Google API keys and fires live requests",
        "detail": "SKILL.md:495-533 — crosses the no-scanning-third-party-services red line. Rejected."
      }
    ]
  },
  "instrument_defects_found": {
    "item": [
      "gh search repos returns exit 0 with an EMPTY body for multi-word queries while the same query via gh api returns total_count=94. Silent-empty-with-success; reported to xd://report_issue. All queries were rerouted to gh api.",
      "gh search code IGNORES OR — 'reqwest OR ureq OR telemetry' returned total_count=0 on repos that provably contain those strings. That 0 is a FALSE NEGATIVE. Discarded; I fetched real files through the core bucket and grepped locally instead.",
      "GitHub secondary rate limit failed 12 of 30 queries; retried with backoff, all recovered. An ERROR is not a zero.",
      "curl.exe gets HTTP 403 from crates.io on this box for every crate, so 'not published on crates.io' is UNPROVABLE here. Not claimed either way.",
      "My own two bugs: a merge step overwrote raw.tsv (376 rows lost, regenerated) and a dedupe script cast before filtering. Both caught and fixed.",
      "Get-Command reported radare2/capa/floss/7z/frida/yara all MISSING, contradicting ground truth. They exist inside our own repo tree but are not on PATH — this reshaped which candidates are provable this week."
    ]
  },
  "self_corrections_made": {
    "item": [
      "disrobe: my table said 'No network.' WRONG — Cargo.toml:267 declares reqwest 0.12.28. 0 hits across 21 .rs files so no egress observed, but the capability is declared and one code path from live. Row corrected; verdict unchanged (licence still decisive).",
      "knife: my ADOPT-2 draft put --json AFTER the subcommand. src/main.rs:30 declares it #[arg(long, global = true)] — clap would have rejected it. Corrected and verified Info/Sections/Imports/Diff/Iocs all exist.",
      "My per-repo fetch capped at 40 files in tree order and that cap BIT: it hid knife's entire CLI definition in main.rs. I only caught it because I tried to verify a subcommand I had guessed. Now documented as a bound on every 'no egress found' verdict."
    ]
  },
  "borrow_highlights": {
    "item": [
      "reverify's claim ledger — separates durable state from chatter so compaction cannot eat it; the best idea in the survey for our own .agent/HANDOFF.md",
      "re-mcp's attribute-denylist sandbox, incl. the CPython fromlist escape it guards (re_mcp_sandbox.py:352-392, :449) — a hole we do not currently guard",
      "ghidra-cli's count-first / server-side-filter discipline (SKILL.md:414-433)",
      "knife's offline SHA-256 loldrivers snapshot + IOC defanging (185.220.101.47 -> 185.220.101[.]47)",
      "morluto/rea's per-backend conformance tests (tests/conformance/ghidra/)"
    ]
  },
  "unverified": {
    "item": [
      "No ADOPT command was run end-to-end — installing was out of scope. Preconditions were verified; binaries were not executed.",
      "morluto/rea's 'skills list'/'analyze' subcommand names unconfirmed (past the 40-file fetch cap); its bin entry rea -> scripts/rea.mjs IS verified from package.json.",
      "crates.io publication status for reknife/ghidra-cli unprovable (curl.exe 403). Both have GitHub release prebuilts, which I did verify.",
      "disrobe (10007 files) and zhaoxuya520/reverse-skill (599) sampled at ~0.4% and ~7% — their REJECT verdicts rest on licence/red-line grounds, which are file-independent, but their egress status is not established."
    ]
  }
}