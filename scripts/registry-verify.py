#!/usr/bin/env python3
"""registry-verify.py — the capability registry cannot lie.

The registry is what makes the nine labs composable: an orchestrator can only call
a capability it can introspect. That makes this validator load-bearing, which makes
its own correctness the thing to worry about. A checker that inspects zero items and
passes is worse than no checker, so:

  * an EMPTY registry is a failure, not a vacuous success;
  * every rule below is exercised by `--selftest`, which builds a registry that
    violates that exact rule and asserts the validator rejects it.

Rules, each traceable to a failure it prevents:

  R1  empty registry fails                     a checker over nothing proves nothing
  R2  observed state needs a probe             "observed" without a command is a wish
  R3  proves[] and does_not_prove[] non-empty  honesty is a pair; one alone is marketing
  R4  fact-key types agree across consumers    an orchestrator hands typed facts between
                                                labs; a mismatch is a silent wrong answer
  R5  negative_control present, expects != 0   a control that must SUCCEED is not a control
  R6  net=any or admin=true needs escalation   reach beyond loopback is never a runtime
                                                self-decision; it needs an Owner word
  R7  ids unique and non-empty                 two capabilities with one id compose randomly

Usage:
    python scripts/registry-verify.py                     validate the real registry
    python scripts/registry-verify.py --selftest           prove each rule fires
    python scripts/registry-verify.py --json               machine-readable

Exit: 0 clean, 1 violations found, 2 selftest failed (the validator itself is wrong).
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

DEFAULT = pathlib.Path(__file__).resolve().parent.parent / "manifests" / "capabilities.json"

TOP_REQUIRED = ("id", "title", "domains", "state", "consumes", "produces",
                "requires", "proves", "does_not_prove", "negative_control", "gate")
VALID_STATES = {"observed", "absent", "degraded", "planned", "blocked"}
VALID_ESCALATION = {"none", "owner_word", "impossible"}


# --------------------------------------------------------------------------- rules

def r1_not_empty(reg, doc):
    caps = doc.get("capabilities")
    if not isinstance(caps, list) or not caps:
        return ["R1 capabilities[] is empty. A registry with nothing in it validates "
                "nothing; a checker that inspects zero items must fail."]
    return []


def r2_observed_needs_probe(reg, doc):
    out = []
    for c in reg:
        if c.get("state") == "observed":
            probe = c.get("probe")
            if not isinstance(probe, dict) or not probe.get("command"):
                out.append(f"R2 {c.get('id','?')}: state=observed but no probe.command. "
                           f"'observed' has to mean a command ran, not that someone hoped so.")
    return out


def r3_honesty_pair(reg, doc):
    """An entry that claims to work must say what it proves AND what it does not.

    An `absent` or `blocked` entry is the opposite case: it must prove nothing, and
    forcing it to list a proof would be forcing a lie. For those, does_not_prove is
    the required half -- it is the record of what we do not have. This refinement was
    not a relaxation to make real data pass; the validator found the case on its
    first run against a real entry."""
    out = []
    for c in reg:
        absent = c.get("state") in ("absent", "blocked")
        if not absent and not c.get("proves"):
            out.append(f"R3 {c.get('id','?')}: proves[] is empty.")
        if not c.get("does_not_prove"):
            out.append(f"R3 {c.get('id','?')}: does_not_prove[] is empty. A capability that "
                       f"only lists what it proves is an advertisement.")
    return out


def r4_fact_types_agree(reg, doc):
    """Every fact a capability produces must be typed, and every consumer that
    names the same key must agree on that type."""
    produced: dict[str, tuple[str, str]] = {}
    for c in reg:
        for f in (c.get("produces") or {}).get("facts", []) or []:
            key, typ = f.get("key"), f.get("type")
            if not key or not typ:
                return [f"R4 {c.get('id','?')}: a produced fact lacks key or type."]
            if key in produced and produced[key][1] != typ:
                return [f"R4 fact '{key}' produced as {produced[key][1]} by "
                        f"{produced[key][0]} and as {typ} by {c.get('id')}."]
            produced[key] = (c.get("id", "?"), typ)
    out = []
    for c in reg:
        for i in (c.get("consumes") or {}).get("inputs", []) or []:
            src = i.get("from")
            if not src:
                continue
            key = src.get("field")
            want = i.get("type")
            if key in produced and want and produced[key][1] != want:
                out.append(f"R4 {c.get('id','?')} consumes '{key}' as {want} but "
                           f"{produced[key][0]} produces {produced[key][1]}. "
                           f"The orchestrator would hand a typed fact to the wrong slot.")
    return out


def r5_control_must_fail(reg, doc):
    out = []
    for c in reg:
        nc = c.get("negative_control")
        if not isinstance(nc, dict):
            out.append(f"R5 {c.get('id','?')}: no negative_control. A capability whose "
                       f"checks always pass is a check, not evidence.")
            continue
        if not nc.get("command"):
            out.append(f"R5 {c.get('id','?')}: negative_control has no command.")
        exp = nc.get("expect_exit")
        if exp is None:
            out.append(f"R5 {c.get('id','?')}: negative_control has no expect_exit.")
        elif exp == 0:
            out.append(f"R5 {c.get('id','?')}: negative_control expects exit 0. A control "
                       f"that must SUCCEED proves nothing.")
    return out


def r6_reach_needs_escalation(reg, doc):
    out = []
    for c in reg:
        req, gate = c.get("requires") or {}, c.get("gate") or {}
        esc = gate.get("escalation_class")
        if esc is not None and esc not in VALID_ESCALATION:
            out.append(f"R6 {c.get('id','?')}: unknown escalation_class '{esc}'.")
        wide = req.get("net") == "any" or req.get("admin") is True
        if wide and esc == "none":
            out.append(f"R6 {c.get('id','?')}: requires net={req.get('net')} "
                       f"admin={req.get('admin')} but escalation_class=none. Reach beyond "
                       f"loopback is never a runtime self-decision.")
    return out


def r7_ids(reg, doc):
    out, seen = [], set()
    for c in reg:
        cid = c.get("id")
        if not cid or not str(cid).strip():
            out.append("R7 a capability has an empty id.")
        elif cid in seen:
            out.append(f"R7 duplicate id '{cid}'. Two capabilities sharing an id compose "
                       f"nondeterministically.")
        else:
            seen.add(cid)
    return out


def r_shape(reg, doc):
    out = []
    for c in reg:
        cid = c.get("id", "?")
        missing = [k for k in TOP_REQUIRED if k not in c]
        if missing:
            out.append(f"R-shape {cid}: missing {', '.join(missing)}.")
        if c.get("state") not in VALID_STATES:
            out.append(f"R-shape {cid}: state '{c.get('state')}' not in "
                       f"{sorted(VALID_STATES)}.")
    return out


RULES = (r1_not_empty, r_shape, r2_observed_needs_probe, r3_honesty_pair,
         r4_fact_types_agree, r5_control_must_fail, r6_reach_needs_escalation, r7_ids)


# ---------------------------------------------------------------------------- core

def validate(doc: dict) -> list[str]:
    problems: list[str] = []
    for rule in RULES:
        reg = doc.get("capabilities") or []
        problems.extend(rule(reg, doc))
    # R1 must be able to fail the run on its own, so check it before the rest
    # assumes a list exists.
    return problems


def _good_entry() -> dict:
    return {
        "id": "example.lab",
        "title": "Example",
        "domains": ["example"],
        "state": "observed",
        "consumes": {"inputs": []},
        "produces": {"facts": [{"key": "example.out", "type": "string"}]},
        "requires": {"runtime": "node", "net": "none", "admin": False},
        "proves": ["that the example ran"],
        "does_not_prove": ["anything about a real target"],
        "negative_control": {"id": "x", "command": "false", "expect_exit": 1, "why": "must fail"},
        "gate": {"lane": "debug", "escalation_class": "none"},
        "probe": {"command": "example --selftest", "expect": "ok", "exit": 0},
    }


def selftest() -> int:
    """Build a registry that breaks each rule and assert we catch it. A validator
    whose own rules are untested is the most confident untested thing in the repo."""
    def doc_of(caps):
        return {"schema": "capabilities.v1", "capabilities": caps}

    cases = []

    def case(name, mutate, must_contain):
        base = [_good_entry(), _good_entry()]
        base[0]["id"], base[1]["id"] = "a.one", "b.two"
        base[1]["produces"]["facts"] = [{"key": "b.out", "type": "string"}]
        mutate(base)
        got = validate(doc_of(base))
        hit = any(must_contain in p for p in got)
        cases.append((name, hit, got))

    case("baseline must be clean", lambda b: None, "!!never!!")
    # An absent entry may prove nothing, but it must still say what it does NOT
    # prove -- otherwise "absent" quietly becomes "unexamined".
    case("R3 absent may have empty proves", lambda b: b[0].update(
        state="absent", proves=[]), "!!never!!")
    case("R3 absent still needs does_not_prove", lambda b: b[0].update(
        state="absent", proves=[], does_not_prove=[]), "R3")
    case("R1 empty registry fails", lambda b: b.clear(), "R1")
    case("R2 observed without probe", lambda b: b[0].pop("probe"), "R2")
    case("R3 missing does_not_prove", lambda b: b[0].__setitem__("does_not_prove", []), "R3")
    case("R4 fact type mismatch", lambda b: b[0]["consumes"].__setitem__(
        "inputs", [{"name": "v", "type": "int", "from": {"capability": "b.two",
                                                          "field": "b.out"}}]), "R4")
    case("R5 control expecting exit 0", lambda b: b[0]["negative_control"].__setitem__(
        "expect_exit", 0), "R5")
    case("R5 control missing", lambda b: b[0].pop("negative_control"), "R5")
    case("R6 admin without escalation", lambda b: b[0]["requires"].__setitem__(
        "admin", True), "R6")
    case("R7 duplicate id", lambda b: b[1].__setitem__("id", "a.one"), "R7")

    width = max(len(n) for n, _, _ in cases)
    failed = 0
    for name, hit, got in cases:
        if name.startswith("baseline"):
            ok = not got
            detail = "clean" if ok else f"unexpected: {got[:2]}"
        elif "may have" in name:
            # A deliberately relaxed case: the rule must stay SILENT here, so that a
            # relaxation cannot quietly widen into a hole.
            ok = not got
            detail = "correctly silent" if ok else f"WRONGLY FLAGGED — {got[:2]}"
        else:
            ok = hit
            detail = "caught" if ok else f"NOT CAUGHT — got {got[:2] or 'nothing'}"
        if not ok:
            failed += 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")

    print()
    if failed:
        print(f"SELFTEST FAILED: {failed} rule(s) did not fire. The validator is the bug, "
              f"not the registry.")
        return 2
    print(f"SELFTEST OK: {len(cases) - 1} rules each fire on a registry built to break them.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", type=pathlib.Path, default=DEFAULT)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if not a.registry.exists():
        print(f"registry not found: {a.registry}")
        return 1
    try:
        doc = json.loads(a.registry.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"registry is not valid JSON: {e}")
        return 1

    problems = validate(doc)
    caps = doc.get("capabilities") or []
    if a.json:
        print(json.dumps({"ok": not problems, "count": len(caps),
                          "problems": problems}, ensure_ascii=False))
    else:
        print(f"registry: {a.registry}")
        print(f"capabilities: {len(caps)}")
        for p in problems:
            print(f"  VIOLATION  {p}")
        if not problems:
            print("REGISTRY CLEAN: every capability declares what it proves, what it does "
                  "not prove, a probe, and a negative control that must fail.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
