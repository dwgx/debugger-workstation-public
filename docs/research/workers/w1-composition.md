> RECOVERED 2026-10-04  from ~/.omp/agent/sessions/--D--Project-<private-tree>--/2026-10-01T15-49-39-407Z_01a0f828/Composition.md (61 lines).
> This is the agent final-answer REMNANT, not the report the dossier cites. Read
> docs/research/WORKER-REPORT-LOSS.md before treating any line here as evidence.

{
  "status": "DONE",
  "report": "%USERPROFILE%/AppData/Local/Temp/w1-composition.md",
  "verdict": "Diagnosis CONFIRMED and worse than stated",
  "findings": [
    {
      "claim": "Registry declares exactly ONE from-edge in 1493 lines, and it is misaligned with the edge that runs",
      "evidence": "Programmatic tree walk of the whole JSON found 1 `from` block: capabilities.json:43-46. It declares native.func.addr (:212, type address); mission.ps1:302 binds invoke.consumes_fact = native.func.named (:137, :220, type string). Ran the comparison: 'ALIGNMENT: MISALIGNED -- declared field is native.func.addr but the loop binds native.func.named'."
    },
    {
      "claim": "Graph is a 2-node path with 13 isolated vertices",
      "evidence": "Chainable-as-declared pairs = 1; triples = 0. 14 of 15 capabilities are roots and 14 are leaves."
    },
    {
      "claim": "mission.ps1 does NOT consult the registry for capability selection -- that is the core finding",
      "evidence": "Selection is the hardcoded hashtable at mission.ps1:85-93 read at :220 ($wanted = $QUESTION_TYPES[$qt].needs). grep 'question_types' over scripts/ returns only :185,:193 which are the local $question_type variable; ZERO code reads the registry field. grep '\\$c\\.consumes' over mission.ps1 returns nothing, so the file's own header claim at :9 ('it picks capabilities whose consumes are satisfied') is false."
    },
    {
      "claim": "Q3, Q4, Q6 are dead questions; Q6 exits 0 having run nothing",
      "evidence": "Ran -Action Plan -QuestionType Q6.crypto: 'plan 0 step(s), 0 written before any tool ran', EXIT=0. Also, Q5 and Q7 route capabilities the registry does not list for them: mission.ps1:90 sends Q5 to list_functions+decompile while the registry declares only fuzz.differential.parse (:980-983); mission.ps1:92 sends Q7 to list_functions whose question_types are Q1,Q2 only (:188-191)."
    },
    {
      "claim": "The Ghidra arm is blocked by one unsubstituted placeholder, and all 3 declared artifacts are unbound",
      "evidence": "capabilities.json:1194 declares '-OutDir {outdir}'; mission.ps1:294 substitutes {target} and :295 matches only {input.x}. Ran the exact substitution loop over the real argv: '{outdir} SURVIVES into the command line verbatim'. Separately, all three produces.artifacts (native.dec.saved :74, fuzz.repro.bytes :1011, native.ghidra.c :1118) are bound by NO fact_map."
    },
    {
      "claim": "registry-verify.py is structurally blind to composition",
      "evidence": "Mutated the registry in memory and ran the real validator 13 ways. Blind (0 problems): from.capability pointing at a nonexistent id; silently dropping a from-edge; retyping an input that has no from-edge; inventing question_type Q99.made-up; removing question_types from every capability; and DELETING any island capability. Only R4/R10 fire, and R4 (:130-155) only checks inputs that HAVE a from -- 1 of 42 consumed inputs. Registry currently reports REGISTRY CLEAN, exit=0."
    },
    {
      "claim": "Declared-vs-ideal diff = 6 missing edges, 1 declared-but-misaligned",
      "evidence": "Enumerated 31 type-compatible producer/consumer pairs, filtered to 7 semantically real chains; 1 is already declared. Each maps to a ranked patch: P1 align the existing edge, P2 drop {outdir}, P3 declare crosscompare's own stated precondition (:1280 'needs both programs imported into ONE project first'), P4 declare list_functions -> ghidra.emulate (native.ghidra.emulate:1402 has function:address required:true with no producer), P5 un-narrow fuzz.differential.parse's opaque string target (:991 already names all four labs), P6 publish the pinning fact mobile.apk.static measures and discards (analyze.mjs:687-690), P7 add invoke blocks to 12 probe-only capabilities, P8 bind the 3 orphan artifacts."
    }
  ],
  "question_coverage": [
    "Q1.identify: 7 declared, 1 routed",
    "Q2.locate: 5 declared, 2 routed",
    "Q3.behaviour: 7 declared, 0 routed (dead)",
    "Q4.data: 6 declared, 0 routed (dead)",
    "Q5.vuln-shape: 1 declared, 0 correctly routed",
    "Q6.crypto: 1 declared, 0 routed (dead, exits 0)",
    "Q7.origin: 6 declared, 0 correctly routed"
  ],
  "chain_conclusion": "The strongest chain executable today is 2 hops (list_functions -> decompile), and even it lies about which fact crosses the arrow. Everything past hop 2 is blocked by declaration gaps, not missing tools: Ghidra, the wrapper, the scripts and the project machinery are all present.",
  "acceptance": {
    "capability_table": "a -- §1.1, 15 rows with consumes/produces/question_types/invoke/lane plus per-capability line anchors",
    "declared_vs_ideal_diff": "b -- §1.2 (1 declared, misaligned), §1.3 (1 pair / 0 triples), §1.4 (7-edge ideal table, 6 missing)",
    "question_coverage": "c -- §2 enum table + real-analyst-question table (1 of 6 partially answerable)",
    "patches": "d -- §5 P1..P8, 8 patches with exact JSON fragments, ranked by composition per line"
  },
  "blockers_not_registry": [
    "mission.ps1 :85-93 / :220 hardcoded selection + no topological sort -- until changed, P3/P4/P5/P7/P8 are declarations no code executes. P1/P2/P6 are still worth landing (P1/P2 remove active falsehoods).",
    "{case_dir} does not exist as a placeholder (mission.ps1:294-295) -- P2's alternate form needs it added first.",
    "registry-verify.py needs 3 new rules: from.capability must resolve; consumes_fact must equal the from.field it serves; question_types must be a closed enum."
  ],
  "unverified": [
    "No analysis was run; every hop determined by reading declarations, invoke.argv and tool source.",
    "Whether native.ghidra.emulate would succeed if reached (state=blocked, :1400).",
    "P7's proposed argv shapes read off each tool's CLI parser but not executed."
  ],
  "constraints_respected": "Read-only. git status --porcelain on D:\\Software\\Tool\\WorkStation\\debugger returned empty. Wrote only to the Temp report path. No registry or script was edited."
}