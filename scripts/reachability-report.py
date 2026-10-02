#!/usr/bin/env python
"""What can this arsenal actually DO, as distinct from what it declares?

WHY THIS EXISTS. "12 of 24 capabilities are callable" is a static fact about the registry: an
`invoke` block exists. It is the wrong number, and it was wrong by a lot. BASELINE, measured
2026-10-02 by scanning all 32 mission artifacts under E:/missions -- this is a dated reading,
kept as the record of what the scan said BEFORE the population split below; it is NOT what the
command prints now, and the command is the only current claim:

    capabilities declaring an invoke   12
    never ran inside any mission        1   crypto.jose.parse
    ran but never SUCCEEDED              3   net.pcap.analyse, forensics.memory.artefact, mobile.apk.static

So **four of twelve "callable" capabilities had never once produced a fact in a mission.**
Nothing static could have said so, because being callable is a property of the registry while
having worked is a property of history. `forensics.memory.artefact` is the instructive one: it
is routable, it runs, and it exits non-zero with a Node stack trace -- a capability that looks
perfectly armed in the registry and cannot succeed for any caller on this station.

This script exists so that figure is a command rather than a thing somebody remembered to
recompute, and so the per-axis number that matters is reported next to the one that does not.

    python scripts/reachability-report.py
    python scripts/reachability-report.py --missions-root E:\\missions
    python scripts/reachability-report.py --selftest

An error is not a zero here either: a mission artifact that cannot be parsed is COUNTED as
unreadable and reported, never quietly skipped, because a scan that silently drops the files it
cannot read will report a rosier arsenal than the one that exists.

THE THREE POPULATIONS, AND WHY ONE NUMBER OVER THEM IS WORTHLESS. Until 2026-10-03 this scan
counted every mission as if it had run to its own end. `scripts/mission.ps1` now writes
`termination_reason` for exactly this reason: a mission whose step cap cut the route short and a
mission that ran every planned step leave the SAME artifact shape, and a "has this capability
ever worked" ratio computed over the two together answers a question nobody asked. Consider a
capability that appears only in a mission that stopped at 2 of 11 planned steps: it was never
ROUTE-selected for a complete question, it was merely the first thing the cap got to. Calling
that evidence that the capability works is a category error, and calling its absence evidence
that it does not is the same error pointed the other way.

So every artifact is placed in exactly one population before anything is counted:

    complete   the mission ran every planned step it was given
    truncated  the step cap ended it with planned work still to run
    other      ended some other way -- a recorded halt reason (grant_halt, registry_changed,
               precondition_failed, unrecognised_halt), or an artifact that predates the
               `termination_reason` field and ended early for a reason it does not record

`other` is deliberately NOT folded into `complete`. A mission whose ending nobody recorded has
not been shown to have finished; counting it as finished is the same defect this file exists to
refuse, one level up. Aggregates are therefore reported per population and the pooled figure is
printed only with an explicit statement that it is not actionable.

WHERE THE CLASSIFICATION COMES FROM, in precedence order, and never from a single silent default:

  1. RECORDED. `termination_reason` (top level), else `termination.reason` / `termination.halt`,
     with `termination.truncated_by_budget` as the tie-break. This is what `mission.ps1` writes;
     when it is present it is authoritative and nothing is inferred over it.
  2. DERIVED, for artifacts written before that field existed. Measured across all 50 artifacts on
     E:/missions (2026-10-03): every one lacks `termination_reason`, and 5 of them are derivable
     as budget-truncated because `plan.json` records the cap (`budget.max_rounds`) and the full
     planned route, while `artifact.json` records the steps executed. Truncated requires ALL of:
     steps_executed >= cap, planned > steps_executed, and chain length == steps_executed.
  3. UNKNOWN. No recorded reason and not derivable. Reported, counted, never guessed at.

Deriving truncation is refused when the artifact disagrees with itself -- measured on
`mobilelab-20261002-031710`, which records 6 steps executed but a 7-entry chain. That case is
NOT counted as truncated: a substrate that contradicts itself has not been shown to be truncated,
it has been shown to be untrustworthy, and those are different claims.

MEASURED POPULATION COUNTS on all 50 real artifacts, 2026-10-03, before `termination_reason`
existed on any of them: 6 complete, 5 budget-truncated, 39 other. The 39 is the load-bearing
number and it is not an error class -- it is the population that had been silently counted as
"finished" before this change. A sixth case (`mobilelab-20261002-031710`) met every numeric
test for truncation and is still not counted as truncated, because its chain length contradicts
its own step count.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import tempfile
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(REPO, "manifests", "capabilities.json")

# A recorded reason that means "the mission ran its route to the end" and nothing else.
COMPLETE_REASONS = {"steps_completed"}
# A recorded reason that means the cap cut work off. `mission.ps1` only emits this one when the
# cap actually DROPPED a step, so trusting it here cannot manufacture a truncation that did not
# happen.
TRUNCATED_REASONS = {"budget_exhausted"}


# ---------------------------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------------------------

def _as_dict(v) -> dict:
    """`termination` has been written as a dict and, in one shape only in old artifacts, absent.
    `chain` has been observed as a list, a dict and a bare string. A report that dies on the odd
    shape suppresses every real row, so every read goes through here."""
    return v if isinstance(v, dict) else {}


def _as_list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, (dict, str)) and v:
        return [v]
    return []


def termination_of(a: dict, plan: dict | None) -> dict:
    """Place one artifact in exactly one population. Returns the record the report prints."""
    term = _as_dict(a.get("termination"))
    reason = a.get("termination_reason") or term.get("reason") or None
    halt = term.get("halt") or None
    steps = a.get("steps_executed")
    if steps is None:
        steps = a.get("rounds")
    try:
        steps = int(steps)
    except (TypeError, ValueError):
        steps = None
    chain_len = len(_as_list(a.get("chain")))

    rec = {
        "reason": reason, "halt": halt, "steps": steps, "chain_len": chain_len,
        "cap": None, "planned": None, "dropped": None, "source": "recorded", "population": None,
        "note": "",
    }

    # 1. RECORDED -- authoritative, nothing inferred over it.
    if reason:
        if reason in TRUNCATED_REASONS or term.get("truncated_by_budget") is True:
            rec["population"] = "truncated"
        elif reason in COMPLETE_REASONS:
            rec["population"] = "complete"
        else:
            rec["population"] = "other"
            rec["note"] = ("a halt this report does not name; recorded verbatim, counted as "
                           "neither complete nor budget-truncated")
        dropped = _as_list(a.get("steps_dropped_by_budget")) or _as_list(
            term.get("steps_dropped_by_budget"))
        rec["dropped"] = len(dropped) or None
        cap = term.get("max_steps", a.get("max_steps"))
        if isinstance(cap, int):
            rec["cap"] = cap
        return rec

    # No recorded reason. Everything below is DERIVED, and says so.
    rec["source"] = "derived" if plan is not None else "unknown"
    if plan is None:
        rec["population"] = "other"
        rec["note"] = "no plan.json beside the artifact, so nothing can be derived or checked"
        return rec

    budget = _as_dict(plan.get("budget"))
    cap = budget.get("max_steps", budget.get("max_rounds"))
    planned = len(_as_list(plan.get("capabilities")))
    rec["cap"] = cap if isinstance(cap, int) else None
    rec["planned"] = planned or None

    # The artifact contradicting itself is not evidence of truncation. Measured:
    # mobilelab-20261002-031710 records 6 steps executed and a 7-entry chain.
    if steps is not None and chain_len != steps:
        rec["population"] = "other"
        rec["note"] = (f"artifact disagrees with itself: {steps} step(s) executed but a "
                       f"{chain_len}-entry chain; refused to classify")
        return rec

    # `rec["cap"]` is tested FIRST. `steps >= rec["cap"] and rec["cap"]` raised TypeError on a
    # plan with no numeric cap, because `int >= None` is evaluated before the truthiness guard.
    # Measured, then fixed: a plan.json without a `budget` block crashed the whole report.
    if planned and steps is not None and rec["cap"] and steps >= rec["cap"] and planned > steps:
        rec["population"] = "truncated"
        rec["reason"] = "budget_exhausted"
        rec["dropped"] = planned - steps
        rec["note"] = "derived: the cap was reached with planned steps unrun"
        return rec

    if planned and steps is not None and planned == steps:
        rec["population"] = "complete"
        rec["reason"] = "steps_completed"
        rec["note"] = "derived: every planned step ran and the cap was not what ended it"
        return rec

    rec["population"] = "other"
    # Short here on purpose: this same sentence appears on dozens of rows. The full claim is
    # stated once, under the table, rather than forty times.
    rec["note"] = "ended before its cap, planned steps unrun, no recorded reason"
    return rec


# ---------------------------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------------------------

def scan(root: str):
    """Return (files, routed, ok, unreadable, missions). `routed`/`ok` are keyed by population
    first: a counter keyed by capability alone cannot express 'only ever routed inside a mission
    that the cap cut short', which is the number this report exists to publish."""
    routed: dict[str, Counter] = {p: Counter() for p in ("complete", "truncated", "other")}
    ok: dict[str, Counter] = {p: Counter() for p in ("complete", "truncated", "other")}
    unreadable: list[tuple[str, str]] = []
    missions: list[dict] = []

    files = sorted(glob.glob(os.path.join(root, "*", "artifact.json")))
    for f in files:
        case = os.path.basename(os.path.dirname(f))
        try:
            a = json.load(open(f, encoding="utf-8-sig"))
        except Exception as e:  # noqa: BLE001
            unreadable.append((f, str(e)))
            continue
        if not isinstance(a, dict):
            unreadable.append((f, f"top level is {type(a).__name__}, not an object"))
            continue

        pf = os.path.join(os.path.dirname(f), "plan.json")
        plan = None
        if os.path.exists(pf):
            try:
                p = json.load(open(pf, encoding="utf-8-sig"))
                plan = p if isinstance(p, dict) else None
            except Exception:  # noqa: BLE001 -- an unreadable plan means undecidable, not zero
                plan = None

        t = termination_of(a, plan)
        t["case"] = case
        t["path"] = f
        pop = t["population"] or "other"
        missions.append(t)

        for r in _as_list(a.get("chain")):
            rr = _as_dict(r)
            cid = rr.get("capability")
            if not cid:
                continue
            routed[pop][cid] += 1
            # ok AND produced at least one fact. Reading `ok` alone was WRONG and an audit
            # proved it: a synthetic artifact with ok:true and facts:[] reported as
            # "worked (2x)" while the docstring claims the report is about capabilities
            # that "have never once produced a FACT". Every reachability number this project
            # quoted before this fix was an UPPER BOUND, because `ok` means "the round did
            # not error", not "the round learned anything". A round that succeeds and emits
            # nothing is the always-green shape this project exists to refuse.
            # TRUTHINESS, NOT A TYPE CHECK. The first attempt at this fix used
            # isinstance(facts, (list, dict)) and that was wrong in the flattering-to-the-old-
            # error direction again: artifacts store the produced-fact marker in THREE shapes --
            # a list ['mobile.manifest.summary', ...], a dict, and a bare STRING naming one fact
            # ('net.flow.summary', 'pcap.dns_direction'). Excluding the string form silently
            # reported two capabilities that demonstrably produced facts as never having run.
            # Measured across all 45 artifacts: list 84, dict 45, str 6, None 5 -- and among the
            # dicts an empty {} means NOTHING was produced, which is exactly the case this rule
            # exists to catch. Plain truthiness gets all six shapes right.
            if rr.get("ok") and rr.get("facts"):
                ok[pop][cid] += 1
    return files, routed, ok, unreadable, missions


def pop_counts(missions) -> Counter:
    return Counter(m["population"] or "other" for m in missions)


# ---------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------

def report(root: str) -> int:
    caps = json.load(open(REG, encoding="utf-8"))["capabilities"]
    inv = {c["id"]: c for c in caps if c.get("invoke")}
    files, routed, ok, unreadable, missions = scan(root)
    pops = pop_counts(missions)
    n_complete, n_trunc, n_other = pops["complete"], pops["truncated"], pops["other"]
    recorded = sum(1 for m in missions if m["source"] == "recorded")

    print(f"mission artifacts read : {len(files)}"
          + (f"   UNREADABLE: {len(unreadable)}" if unreadable else ""))
    for f, e in unreadable:
        print(f"   !! could not parse {f}: {e}")

    print(f"capabilities declaring an invoke : {len(inv)}")
    print("'worked' means: ran ok AND emitted at least one fact. An ok round with no facts")
    print("does NOT count -- see the comment in scan().")
    print()

    # --- per-mission termination, first, because every aggregate below depends on it ----------
    print("per mission: how the mission ENDED. Every aggregate in this report is counted over")
    print("one of these populations, and they are never pooled into a single ratio.")
    print(f"  {'case':<36}{'pop':<11}{'reason':<20}{'src':<9}{'steps':>5}{'cap':>4}{'plan':>5}{'drop':>5}  note")
    for m in missions:
        print(f"  {m['case']:<36}{m['population']:<11}{str(m['reason'] or '-'):<20}"
              f"{m['source']:<9}{_num(m['steps']):>5}{_num(m['cap']):>4}{_num(m['planned']):>5}"
              f"{_num(m['dropped']):>5}  {m['note']}")
    print(f"  populations: {n_complete} complete, {n_trunc} budget-truncated, {n_other} other")
    print(f"  termination reason recorded by mission.ps1: {recorded}/{len(missions)}"
          f"   derived from plan.json: {len(missions) - recorded}/{len(missions)}")
    if recorded == 0:
        print("  NOTE: no artifact on this disk records its ending, so every classification above is")
        print("  DERIVED from plan.json. The 'other' row is NOT a small remainder: an artifact that")
        print("  stopped before its cap without recording why has not been shown to have finished,")
        print("  so it is counted as neither complete nor truncated. Reading it as 'finished' is")
        print("  the defect this table exists to expose.")
    else:
        print("  Rows marked src=derived are artifacts written before mission.ps1 recorded an ending;")
        print("  rows marked src=recorded are taken from the artifact and never inferred over.")
    print()

    # --- capability table, split by population ------------------------------------------------
    print(f"{'capability':<30}{'complete':>13}{'truncated':>13}{'other':>13}  verdict")
    print(f"{'':<30}{'ok/missions':>13}{'ok/missions':>13}{'ok/missions':>13}")
    # The verdict names WHICH population the evidence came from, because "worked" alone is the
    # ambiguity this report exists to remove. A capability that produced facts inside missions
    # which never finished did work; it did not work in a mission that answered its question.
    # `only_trunc` therefore means "no fact from a COMPLETE mission", not "no fact at all".
    never_ran, only_trunc, never_ok = [], [], []
    for cid in sorted(inv):
        c_ok, t_ok, o_ok = ok["complete"][cid], ok["truncated"][cid], ok["other"][cid]
        c_run, t_run, o_run = (routed["complete"][cid], routed["truncated"][cid],
                               routed["other"][cid])
        if c_ok:
            verdict = f"worked ({c_ok}x in COMPLETE missions)"
        elif c_run == 0 and (t_run + o_run) == 0:
            verdict = "NEVER ROUTED INTO ANY MISSION"
            never_ran.append(cid)
        elif c_run == 0:
            where = [f"{t_ok} fact(s) in budget-truncated" if t_ok else "",
                     f"{o_ok} fact(s) in missions that did not complete" if o_ok else ""]
            verdict = ("no fact from a COMPLETE mission; "
                       + ", ".join(w for w in where if w))
            if not any(where):
                verdict += f"routed {t_run + o_run}x into missions that did not complete, 0 facts"
            only_trunc.append(cid)
        elif c_ok == 0:
            verdict = f"routed in {c_run} COMPLETE mission(s), produced no fact in any of them"
            never_ok.append(cid)
        else:  # pragma: no cover -- unreachable while the ladder above is total
            verdict = "unclassified"
        print(f"{cid:<30}{_frac(c_ok, c_run):>13}{_frac(t_ok, t_run):>13}{_frac(o_ok, o_run):>13}"
              f"  {verdict}")

    # EVERY declared axis, counted over ALL capabilities, including the ones with no callable
    # entry at all. The first version iterated only over axes that had an invoke, which silently
    # hid precisely the darkest ones: Q5.vuln-shape never appeared in the output, and its absence
    # read as "not applicable" rather than "nothing has ever worked here". That is the same
    # failure as an unreadable artifact being skipped, in a different costume -- a report that
    # omits the worst rows looks healthier than one that prints them.
    per_axis: dict[str, dict] = {}
    for c in caps:
        for q in (c.get("question_types") or []):
            d = per_axis.setdefault(q, {"declared": 0, "worked_c": 0, "worked_t": 0, "worked_o": 0})
            if c.get("invoke"):
                d["declared"] += 1
                if ok["complete"].get(c["id"]):
                    d["worked_c"] += 1
                if ok["truncated"].get(c["id"]):
                    d["worked_t"] += 1
                if ok["other"].get(c["id"]):
                    d["worked_o"] += 1

    print()
    print("per axis, DECLARED callable vs has produced a fact -- COMPLETE missions only, then")
    print("the truncated population beside it. A ratio over both together is not a number anyone")
    print("can act on: a fact produced by a mission that never finished is evidence about the")
    print("capability, but it is not evidence that the question was answerable end to end.")
    dark, dark_but_trunc = [], []
    for q in sorted(per_axis):
        d = per_axis[q]
        if d["worked_c"] == 0 and (d["worked_t"] or d["worked_o"]):
            why = (f"{d['declared']} declared callable; none produced a fact in a COMPLETE "
                   f"mission, {d['worked_t']} did inside budget-truncated missions and "
                   f"{d['worked_o']} inside missions that did not complete")
            dark_but_trunc.append(q)
            print(f"  {q:<16} {d['worked_c']}/{d['declared']} complete   "
                  f"{d['worked_t']} truncated   {d['worked_o']} other   <-- DARK: {why}")
        elif d["worked_c"] == 0:
            why = ("no callable capability declares it" if d["declared"] == 0
                   else f"{d['declared']} declared callable, none has ever worked")
            dark.append(q)
            print(f"  {q:<16} {d['worked_c']}/{d['declared']} complete   {d['worked_t']} truncated"
                  f"   <-- DARK: {why}")
        else:
            print(f"  {q:<16} {d['worked_c']}/{d['declared']} complete   {d['worked_t']} truncated")

    # --- the numbers, and the ones that are not numbers --------------------------------------
    total_invocable = len(inv)
    no_complete_evidence = len(never_ran) + len(never_ok) + len(only_trunc)
    pooled_ok = sum(ok[p][cid] for p in ok for cid in inv)
    print()
    print("THE QUOTABLE FIGURES")
    print(f"  capabilities that have NEVER produced a fact in a mission that ran to its end :")
    print(f"      {no_complete_evidence} of {total_invocable}")
    for cid in sorted(never_ran):
        print(f"        never routed into any mission at all: {cid}")
    for cid in sorted(never_ok):
        print(f"        routed in COMPLETE missions but produced no fact in any of them: {cid}")
    if only_trunc:
        print(f"  capabilities whose ONLY positive evidence is from missions that did not complete :")
        print(f"      {len(only_trunc)} of {total_invocable}  (per-capability breakdown above)")
    print(f"  axes with no fact from a complete mission : "
          f"{len(dark) + len(dark_but_trunc)} of {len(per_axis)}"
          + (f" ({', '.join(sorted(dark + dark_but_trunc))})" if dark or dark_but_trunc else ""))
    print()
    print(f"  POOLED, and NOT actionable: {pooled_ok} facts over {len(missions)} missions, of which")
    print(f"  {n_trunc} were cut short by the step cap and {n_other} ended for a reason they do not")
    print("  record. A reachability ratio over that mixture answers no question a reader can act")
    print("  on, so it is printed last, labelled, and must not be quoted alone.")
    if never_ran or never_ok or only_trunc:
        print()
        print("  'Callable' is a property of the registry; 'worked' is a property of history; and")
        print("  'worked in a mission that ran to its end' is a third, narrower property than both.")
        print("  Only the first table above separates them.")
    return 0


def _num(v) -> str:
    return "-" if v is None else str(v)


def _frac(a: int, b: int) -> str:
    return f"{a}/{b}" if b else "-"


# ---------------------------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------------------------

_CASES = [
    # Real cases on E:/ (2026-10-03): the first derives budget-truncated, the second completes
    # its route. These are COPIED, never moved and never written to.
    ("c01-stringobf-20261002-080031", "truncated"),
    ("accept-c01", "complete"),
]


def _clone_as(src_root: str, dst_root: str, src_case: str, dst_case: str) -> str:
    """Copy a real case dir under a new name. The originals are only ever READ."""
    dst = os.path.join(dst_root, dst_case)
    os.makedirs(dst, exist_ok=True)
    for name in ("artifact.json", "plan.json"):
        s = os.path.join(src_root, src_case, name)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(dst, name))
    return dst


def _copy_case(src_root: str, dst_root: str, case: str) -> str:
    return _clone_as(src_root, dst_root, case, case)


def _rewrite(path: str, mutate) -> None:
    a = json.load(open(path, encoding="utf-8-sig"))
    mutate(a)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(a, fh, indent=1)


def selftest() -> int:
    real = r"E:\missions"
    if not os.path.isdir(real):
        print("REACHABILITY SELFTEST BLOCKED: E:\\missions is not present; these controls run "
              "against real artifacts and refuse to substitute invented ones.")
        return 2

    tmp = tempfile.mkdtemp(prefix="reach-selftest-")
    behaved = failed = 0
    try:
        # C1 -- the two real populations land in two different buckets.
        for case, expected in _CASES:
            _copy_case(real, tmp, case)
        got = {m["case"]: m["population"] for m in scan(tmp)[4]}
        line = " ".join(f"{c}={got.get(c)}" for c, _ in _CASES)
        assert got.get("c01-stringobf-20261002-080031") == "truncated", line
        assert got.get("accept-c01") == "complete", line
        behaved += 1

        # C2 -- a recorded budget_exhausted OVERRIDES a derivation that says complete. The copy
        # below derives 'complete' (2 planned, 2 executed, cap 6); the stamp says the cap ended
        # it with two steps still to run. If the recorded field were ignored, C2 is
        # indistinguishable from C1 -- that is the mutation C2 exists to catch.
        d = _clone_as(real, tmp, "accept-c01", "recorded-trunc")
        _rewrite(os.path.join(d, "artifact.json"),
                 lambda a: a.update({"termination_reason": "budget_exhausted",
                                     "steps_executed": a.get("rounds"),
                                     "termination": {"state": "DONE",
                                                     "reason": "budget_exhausted",
                                                     "halt": "budget_cap",
                                                     "truncated_by_budget": True,
                                                     "steps_dropped_by_budget": ["x", "y"]}}))
        m = {x["case"]: x for x in scan(tmp)[4]}["recorded-trunc"]
        assert m["population"] == "truncated", m
        assert m["source"] == "recorded" and m["dropped"] == 2, m
        behaved += 1

        # C3 -- the field mission.ps1 writes is what this report reads; without it the same
        # artifact derives 'complete'. Ignoring the recorded field is the mutation C3 catches.
        d2 = _clone_as(real, tmp, "accept-c01", "recorded-complete")
        _rewrite(os.path.join(d2, "artifact.json"),
                 lambda a: a.update({"termination_reason": "steps_completed",
                                     "steps_executed": a.get("rounds")}))
        m2 = {x["case"]: x for x in scan(tmp)[4]}["recorded-complete"]
        assert m2["population"] == "complete" and m2["source"] == "recorded", m2
        behaved += 1

        # C4 -- an ending this file does not name is reported, never folded into 'complete'.
        d3 = _clone_as(real, tmp, "accept-c01", "recorded-halt")
        _rewrite(os.path.join(d3, "artifact.json"),
                 lambda a: a.update({"termination_reason": "grant_halt",
                                     "steps_executed": a.get("rounds")}))
        m3 = {x["case"]: x for x in scan(tmp)[4]}["recorded-halt"]
        assert m3["population"] == "other", m3
        behaved += 1

        # C5 -- an artifact that disagrees with itself is refused, not called truncated. The real
        # measured shape is mobilelab-20261002-031710: 6 steps executed, a 7-entry chain.
        d4 = _clone_as(real, tmp, "accept-c01", "self-inconsistent")
        m4 = {x["case"]: x for x in scan(tmp)[4]}["self-inconsistent"]
        assert m4["steps"] == 2 and m4["chain_len"] == 2 and m4["population"] == "complete", m4
        a5 = json.load(open(os.path.join(d4, "artifact.json"), encoding="utf-8-sig"))
        a5["chain"].append({"capability": "net.pcap.selfparse", "ok": True, "facts": ["x"]})
        with open(os.path.join(d4, "artifact.json"), "w", encoding="utf-8") as fh:
            json.dump(a5, fh)
        m5 = {x["case"]: x for x in scan(tmp)[4]}["self-inconsistent"]
        assert m5["population"] == "other" and "disagrees" in m5["note"], m5
        behaved += 1

        # C6 -- `steps_executed` beats the legacy `rounds` spelling. `rounds` is set to a value
        # that would classify the artifact as self-inconsistent, so a reader that takes `rounds`
        # first lands in 'other' instead of 'complete'.
        d6 = _clone_as(real, tmp, "accept-c01", "steps-spelling")
        _rewrite(os.path.join(d6, "artifact.json"),
                 lambda a: (a.update({"steps_executed": a.pop("rounds")}), a.update({"rounds": 99})))
        m6 = {x["case"]: x for x in scan(tmp)[4]}["steps-spelling"]
        assert m6["steps"] == 2 and m6["population"] == "complete", m6
        behaved += 1

        # C7 -- the AGGREGATE separates the populations: a capability that only ever ran inside a
        # truncated mission is not credited to the complete population.
        assert len(_CASES) == 2
        _, routed, ok, _, _ = scan(tmp)
        assert ok["truncated"]["native.pe.packer"] > 0, \
            "fixture no longer exercises a truncated-only capability"
        assert ok["complete"]["native.pe.packer"] == 0 and \
            routed["complete"]["native.pe.packer"] == 0, \
            "complete population must not inherit a truncated mission's capability"
        behaved += 1

        # C8 -- the report PRINTS the separation, not merely computes it.
        buf = _capture(report, tmp)
        for needle in ("per mission: how the mission ENDED",
                       "budget-truncated",
                       "POOLED, and NOT actionable",
                       "never finished"):
            assert needle in buf, f"report does not print {needle!r}"
        assert "native.pe.packer" in buf
        behaved += 1

        # C9 -- an unreadable artifact is counted and named, never a quiet zero.
        os.makedirs(os.path.join(tmp, "broken"), exist_ok=True)
        with open(os.path.join(tmp, "broken", "artifact.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        f2, _, _, unread2, _ = scan(tmp)
        assert len(f2) == 8 and len(unread2) == 1 and "broken" in unread2[0][0], unread2
        behaved += 1

        # C10 -- no artifact is silently dropped from the per-mission table.
        pops = pop_counts(scan(tmp)[4])
        assert sum(pops.values()) == 7, pops
        assert pops["truncated"] == 2 and pops["complete"] == 3 and pops["other"] == 2, pops
        behaved += 1

        # C11 -- a plan with NO numeric cap is undecidable, not a crash. Reproduced as a real
        # TypeError before this control existed: `int >= None` was evaluated ahead of the
        # truthiness guard, so one plan.json without a `budget` block killed the entire report.
        d7 = _clone_as(real, tmp, "c01-stringobf-20261002-080031", "no-cap")
        p7 = json.load(open(os.path.join(d7, "plan.json"), encoding="utf-8-sig"))
        p7.pop("budget", None)
        with open(os.path.join(d7, "plan.json"), "w", encoding="utf-8") as fh:
            json.dump(p7, fh)
        m7 = {x["case"]: x for x in scan(tmp)[4]}["no-cap"]
        assert m7["population"] == "other" and m7["cap"] is None, m7
        assert len(scan(tmp)[4]) == 8, "the no-cap case vanished from the table"
        behaved += 1

        # C12 -- the odd chain shapes the substrate has actually produced (an empty object, a
        # dict, a bare string) are survived and kept in the table, not raised on. An audit found
        # all three; an AttributeError there suppresses every real row in the report.
        # Each shape is a SEPARATE clone and all three persist, so the expected table size grows
        # by one per iteration: 8 after C11, then 9, 10, 11.
        for idx, (shape, nm) in enumerate((({}, "empty-obj"),
                                           ({"capability": "net.pcap.selfparse"}, "dict-chain"),
                                           ("net.pcap.selfparse", "str-chain"))):

            dd = _clone_as(real, tmp, "accept-c01", nm)
            _rewrite(os.path.join(dd, "artifact.json"), lambda a, s=shape: a.update({"chain": s}))
            got = scan(tmp)
            # C9 planted one deliberately broken artifact, so 'no new unreadable' is the
            # assertion, not 'no unreadable at all'.
            assert [u[0] for u in got[3]] == [os.path.join(tmp, "broken", "artifact.json")], \
                f"{nm} raised or was counted unreadable: {got[3]}"
            assert len(got[4]) == 9 + idx, f"{nm}: expected {9 + idx} rows, got {len(got[4])}"
            assert any(m["case"] == nm for m in got[4]), f"{nm} dropped from the table"
        behaved += 1

        # C13 -- the per-mission TABLE and the AGGREGATE cannot disagree. `scan()` used to read
        # the population from the classifier for the table and from a separate expression for
        # the counters; a mutation of one left the report printing "truncated" on a row whose
        # facts were being counted as complete. The population is now read once, and this control
        # pins the consequence: every chain entry must be counted under the population its own
        # row claims.
        for label, root_dir in (("temp tree", tmp), ("real E:\\missions", real)):
            _, r2, _, _, ms = scan(root_dir)
            expect = Counter()
            for m in ms:
                case = m["case"]
                art = os.path.join(root_dir, case, "artifact.json")
                try:
                    a = json.load(open(art, encoding="utf-8-sig"))
                except Exception:  # noqa: BLE001 -- C9's planted break is not a mission
                    continue
                n = sum(1 for x in _as_list(a.get("chain"))
                        if _as_dict(x).get("capability"))
                expect[m["population"] or "other"] += n
            got_totals = {p: sum(r2[p].values()) for p in r2}
            assert got_totals == dict(expect), \
                f"{label}: table says {dict(expect)}, counters say {got_totals}"
        behaved += 1
    except AssertionError as e:
        failed += 1
        print(f"    REFUSED: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"REACHABILITY SELFTEST {'OK' if not failed else 'RED'}: "
          f"{behaved + failed} controls, {behaved} behaved, {failed} did not.")
    return 0 if not failed else 1


def _capture(fn, *a) -> str:
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*a)
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--missions-root", default=r"E:\missions")
    ap.add_argument("--selftest", action="store_true",
                    help="run the population controls against COPIES of real artifacts")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(args.missions_root)


if __name__ == "__main__":
    raise SystemExit(main())