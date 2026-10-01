# Research dossier

Two rounds. **2026-09-30**: five evidence-dense reports from agents that deep-read the
public reverse-engineering agent ecosystem, then corrected the record by running what they
found. **2026-10-02**: five more, from eight agents that attacked the arsenal's own
instruments rather than the ecosystem's tools, plus one adoption survey.

Read with `wiki/methods/arsenal-upgrade-plan.md` in the sibling `<private-tree>` repo, which is
the decision layer over these findings.

## 2026-09-30

| File | What it establishes |
|---|---|
| `orchestration-design.md` | The mission loop, the capability registry schema, and the gate as a program. Ships with four negative controls, N4 being the station's own known failure mode aimed at the new code. |
| `binary-mcp-map.md` | Capability delta against the public binary-analysis MCP set. Its headline is that our own recorded blocker was false. |
| `mobile-js-skill-map.md` | Mobile and JS skill comparison. Verdict: their tooling is worse than ours, their shape is better — ours are tools, theirs are decision procedures. |
| `knowledge-corpus.md` | 38 distilled notes from 14 sources. Each carries preconditions, a pass signal, and a negative control. |
| `curriculum.md` | 13-stage training path with exercises, pass conditions, and honest `[AUTHOR]` fixture gaps. |
| `agent-craft-principles.md` | What makes an agent good at RE, read line by line from 14 cloned repos rather than from READMEs. Sets the bar the rest of this dossier answers to: a rule no code path checks carries no signal, and a confidently wrong registry entry is worse than an absent one. |
| `ghidra-capability-spec.md` | The Ghidra 12.1.3 column of the capability registry, every number re-runnable from §6. Its own rule is the one this dossier inherited: unverifiable is registered `absent` or `degraded`, never as a confident entry. |
| `ida-mcp-source-study.md` | A read of the *installed* `ida-pro-mcp` v2.0.0, not its README, plus a live probe. Supplies the yardstick the 2026-10-02 MCP survey uses: one unauthenticated `POST /config` reversed `--unsafe` and persisted the policy into the sample's `.i64`. |

## 2026-10-02

| File | What it establishes |
|---|---|
| `review-2026-10-02.md` | The integrity review, led by the **ablation** discipline that found all of it: six of seven verdict gates could be deleted with all 15 controls green, `gate.ps1` had 8 of 11 authority attacks exploited, and `registry-verify.py`'s R8 could not fire for any of its five effects (`implied` was built from `reach`, so `missing` was empty by construction). Carries **both** halves for every figure — the before-measurement and the re-measurement. **Re-measured 2026-10-02**: 24 gate controls, **51** mission controls, 46 validator cases over **19** rule functions, ablation at 7 verdict gates + 6 routing rules, all load-bearing. C1 refused in five gates at once; forged identity → exit 5; **a one-byte registry edit invalidates every outstanding grant**. Records **§9** — registry-driven routing replacing the hardcoded table (`Q5`/`Q6` refuse with exit 2) — and **§5.5**, `dynamic.win.frida` registered and measured *without* claiming interception, then closed by the sibling `dynamic.win.frida.intercept`. Names the **three** open items — most negative controls still prose, the LYING-CLEAN fixture not re-run, the gate attacks not re-run — rather than dropping them. |
| `cost-matrix.md` | 15 probes measured with wall time, peak tree RSS and disk delta per row, and the three-tier routing rule they imply. **Refutes** the handoff's contention claim as an arithmetic identity (103.47 s concurrent against a 161.93 s serial sum, all passing) and substitutes the real hazards: peak RSS at 3.4 GB / 61 procs, and fixed ports 8791/8745 where a second concurrent lab **exits 1 on `EADDRINUSE` rather than running slowly**. Flags `fuzz-lab --budget 40`'s 33.10 s–1071.37 s spread and its one exit-9 run as an unexplained failure mode. |
| `composition-plan.md` | The arsenal's stated core gap — *the gap is not coverage, it is composition* — as its own document. As measured on 2026-10-02 morning: 15 capabilities, **1 declared edge, 0 triples, 14 roots and 14 leaves**, and that one edge is the one the loop does not bind; `Q3`/`Q4`/`Q6` route nothing and **`Q6` exits 0 having run nothing**. Eight ranked registry patches, marked by whether they are worth landing before `mission.ps1` changes. **§4a and §4a.1 now record the per-edge disposition**: the plan asked for 7 edges, 4 were declared and **3 refused** (module imports return untyped values — an untyped handoff declared as a typed edge is worse than a missing one); since grown to **6 declared, 2 refused**.
| `ecosystem-2026-10-02.md` | 25 MCP servers against one yardstick — *does the gate survive someone who is not us rewriting it* — of which **only two pass**; 3 repos with **no licence at all**, the highest-starred at 2,039. 40 tools cost-ranked behind the single fact that **there is no LLVM on this machine and one 374 MB install gates four rows**. 33 skill repos, including the **four already vendored in our own `mcp/` tree**. |
| `dynamic-pairings.md` | 23 pairings, each with the typed fact that links step N to N+1: 3 expressible today, 11 need only a fact key, 9 need a capability. Leads with the finding that **the Android Frida entry is correctly absent but a Windows-local Frida capability is real**, which turned four static→dynamic pairings from documents into three lines of glue. **Both halves of that are now on the record** (§1.3a, §1.3b): `dynamic.win.frida` shipped **without** claiming interception — the `frida -f` CLI resumes the main thread before the script loads, so no `onEnter` fired — and the gap was then closed by a **sibling** capability, `dynamic.win.frida.intercept`, which publishes `instrument.ordering` and `runtime.hook.hit` as measured facts. Carries `DebugSymbol.fromName('main') → 0` as the reason RVA-plus-module-base transfer is mandatory, not stylistic, the four different runtime module bases one binary produced in one session, and that `frida-ps -ai` **hangs 300 s** rather than refusing — so it is neither a probe nor a control. |

---

## Two premises in this dossier were wrong when written and are corrected in place

rather than quietly dropped: IDA Pro *is* installed and licensed, and Ghidra
*does* support the headless cross-program open our notes called impossible.

## How to read a number here

Every figure in the 2026-10-02 round carries the command that produced it and the date it
was measured, because a recorded number decays — and three capacity figures have already
gone stale in this project. Where a source report is `[UNVERIFIED]` or self-contradicting,
that qualifier is carried through rather than smoothed over.

**Reconciled 2026-10-02 at `HEAD` = `e246427`.** Every figure in the table above was
re-measured from the repo root by running the command, and where a fix has since superseded
a finding the document says so **in place** rather than deleting the original. Five suites,
all run for this reconciliation:

```
python scripts/registry-verify.py                     -> capabilities: 16   REGISTRY CLEAN
python scripts/registry-verify.py --selftest          -> SELFTEST OK: 46 cases
powershell -File scripts/gate.ps1   -Action Selftest  -> 24 refusals and grants
powershell -File scripts/mission.ps1 -Action Selftest  -> 51 controls
powershell -File scripts/mission.ps1 -Action Ablate    -> 7 + 6 load-bearing, 0 unproved
```

**⚠ The capability count moved twice while this pass was being written**, which is the
clearest possible demonstration of why every figure here is commit-stamped: **16 at
`e246427`, 18 at `96e718c`** (`python scripts/registry-verify.py`), and typed edges **5 → 6**
(`grep -c '"from"' manifests/capabilities.json`). The two added capabilities are
`ops.skill.security` and **`dynamic.win.frida.intercept`** — the latter closing the
interception gap that `dynamic.win.frida` honestly declined to claim. The other four
figures above were re-run after both commits and are unchanged.

**The number that moved furthest inside a single day:** `mission.ps1`'s selftest was
recorded as 15 controls, then as 34, and is **51** — because the registry-driven routing
rewrite added ten routing controls to the same suite. A recorded count decays; only a
command is evidence.

Everything here is evidence for a decision. Nothing here is a capability until it
has a runnable command on record.
