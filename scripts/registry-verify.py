#!/usr/bin/env python3
"""registry-verify.py — the capability registry cannot lie.

The registry is what makes the nine labs composable: an orchestrator can only call
a capability it can introspect. That makes this validator load-bearing, which makes
its own correctness the thing to worry about. A checker that inspects zero items and
passes is worse than no checker, so:

  * an EMPTY registry is a failure, not a vacuous success;
  * the rules below are the code in `RULES`, in the same order. Nineteen rule
    functions. `--selftest` prints 47 rows and reports 46, and that number is
    CASES, not rules: one row is a baseline that must stay clean, two are
    deliberate relaxations that must stay SILENT, and 44 are registries built to
    break one rule. Cases outnumber rules because several rules have more than one
    independent half, and each half needs its own control -- deleting either half
    alone leaves the suite green while the registry quietly loses the check.

Rules, each traceable to a failure it prevents. Nineteen functions, in `RULES` order:

  R1      r1_not_empty
          capabilities[] must be non-empty. A checker over nothing proves nothing.

  R-shape r_shape
          every capability carries all 11 required keys and a state from the valid
          set. A half-declared capability composes as a crash.

  R2      r2_observed_needs_probe
          state=observed requires probe.command. "observed" without a command is a wish.

  R3      r3_honesty_pair
          does_not_prove[] is always non-empty; proves[] too, unless the entry is
          absent or blocked. Honesty is a pair; one alone is marketing.

  R4      r4_fact_types_agree
          every produced fact is typed, and every consumer agrees on the type. An
          orchestrator hands typed facts between labs; a mismatch is a silent wrong answer.

  R5      r5_control_must_fail
          negative_control carries a command and expect_exit != 0. A control that
          must SUCCEED is not a control.

  R6      r6_reach_needs_escalation
          escalation_class is one of the three known values, and net=any or
          admin=true cannot be escalation_class=none. Reach beyond loopback is never
          a runtime self-decision; it needs an Owner word.

  R7      r7_ids
          ids are non-empty and unique. Two capabilities with one id compose randomly.

  R8      r8_reach_must_be_declared
          reach declares the effects net/admin already imply; fs_write names a
          write_scope, and only case_dir write may be class none. Authority declared
          as a tag misses the one that writes anyway.

  R9      r9_batch_must_account
          a consumed type[] needs envelope.batch with max_items and aggregate, and
          the envelope needs success_when. This class of API drops items with no signal.

  R10     r10_invoke_must_runnable
          invoke.argv is a non-empty array, never a joined string; the script it
          names must exist; runner and success_when must be stated; consumes_fact
          must be produced by someone. A declared chain the loop cannot fire is a
          promise it breaks at run time.

  R11     r11_edge_target_exists
          every consumes.inputs[].from.capability names a capability that exists,
          and the field it names is one that producer really emits. An edge to a
          capability nobody has heard of is a diagram, not a contract.

  R12     r12_edge_is_reachable
          an edge is two-sided: the producer is not absent/blocked AND the
          consumer is not absent/blocked. An edge into a capability that cannot
          run is a lie in the registry's own words.

  R13     r13_question_types_declared
          every question_types entry is drawn from schema.question_types, the
          enumeration the registry itself declares. Q99.made-up is not a question.

  R14     r14_no_island_capability
          an observed capability that produces a fact and is not terminal either
          consumes something or declares why it is a root; and the registry may
          not SHRINK below its declared baseline without an explicit retired
          entry. A deleted island used to be a clean pass.

  R15     r15_artifacts_are_bound
          every produces.artifacts[].key is referenced by some fact_map, or is
          explicitly declared unbound with a reason. An artifact nothing binds is
          a file nobody can find again.

  R16     r16_placeholders_resolve
          every {placeholder} in invoke.argv resolves: {target}, a declared
          {input.x}, or an explicitly passed value. `{outdir}` used to survive
          verbatim into a command line.

  R17     r17_state_is_evidenced
          state=observed carries probe.last_run AND a binding to the run: a
          sha256, a run_log, or an explicit evidence_binding of "unverified"
          with a reason. `state` is the field the whole registry rests on.

  R8      r8_reach_must_be_declared
          reach must declare every effect the capability's OWN declared floor
          implies. The floor comes from requires/probe/invoke/consumes, never from
          `reach` itself -- the previous version built `implied` FROM `reach`, so
          `missing` was empty by construction and all five effects were
          unfalsifiable. Measured: setting each reach effect to false produced 0
          problems. It also pins reach.containment to the enumeration the mission
          gate accepts, so containment is declared where the reach implies it.

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
import re
import sys

DEFAULT = pathlib.Path(__file__).resolve().parent.parent / "manifests" / "capabilities.json"

# The repo root, derived from this file's own location. Every path a rule checks must
# resolve against THIS, never against the process working directory: the registry path was
# already anchored here, and a rule that resolves its paths differently from the file it
# loaded is a rule that reports different answers depending on where you ran it from.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

TOP_REQUIRED = ("id", "title", "domains", "state", "consumes", "produces",
                "requires", "proves", "does_not_prove", "negative_control", "gate")
VALID_STATES = {"observed", "absent", "degraded", "planned", "blocked"}
VALID_ESCALATION = {"none", "owner_word", "impossible"}
VALID_CONTAINMENT = {"station_under_named_process_rule", "loopback_capture", "isolated_vm"}


# --------------------------------------------------------------------------- rules

def r1_not_empty(reg, doc):
    caps = doc.get("capabilities")
    if not isinstance(caps, list) or not caps:
        return ["R1 capabilities[] is empty. A registry with nothing in it validates "
                "nothing; a checker that inspects zero items must fail."]
    return []


def r2_observed_needs_probe(reg, doc):
    """`observed` has to mean A COMMAND RAN, and R10 already insists an `invoke` is runnable.
    This rule now insists the same of a `probe`, which it did not.

    Found by auditing every probe rather than trusting the North Star: one entry carried
    `probe.command: "see scripts/ghidra-failopen.md reproduction section"`. That is PROSE. It
    cannot be executed, nobody ran it, and nothing about it could ever redden. The estate's
    North Star says *every capability this project claims is proved by one runnable command*,
    and R10 enforced that for `invoke` while leaving the `probe` half of the same claim
    unchecked -- the shape of a rule that exists on one side of a pair and not the other.

    The test is about SHAPE, not about the command succeeding: a probe naming something
    executable is accepted and anything else is refused by name. Verifying that a probe RUNS
    belongs to the suite, not to a static rule -- a rule that executed commands would make
    validation slow, destructive and machine-state dependent.
    """
    RUNNABLE = (".mjs", ".js", ".cjs", ".py", ".ps1", ".exe", ".bat", ".cmd", ".com")
    out = []
    for c in reg:
        if c.get("state") == "observed":
            probe = c.get("probe")
            if not isinstance(probe, dict) or not probe.get("command"):
                out.append(f"R2 {c.get('id','?')}: state=observed but no probe.command. "
                           f"'observed' has to mean a command ran, not that someone hoped so.")
                continue
            cmd = str(probe["command"])
            low = cmd.lower()
            looks_runnable = any(t in low for t in RUNNABLE) or low.startswith(
                ("node ", "python ", "powershell ", "cmd ", "uv "))
            if not looks_runnable:
                out.append(f"R2 {c.get('id','?')}: probe.command is not a runnable command, it is "
                           f"prose -- {cmd[:70]!r}. 'observed' means something ran; pointing at a "
                           f"document is a pointer, not a proof.")
    return out


def r19_probes_distinguish(reg, doc):
    """Two capabilities sharing one probe command is legal; two that CANNOT LOCALISE a fault
    are not much of a probe.

    Found by auditing rather than by intent: native.ida.decompile and native.ida.list_functions
    carried the identical `node native-lab/tools/loop.mjs`. That loop genuinely exercises both
    tools, so neither entry was lying -- but a break in `decompile` reddened BOTH capabilities and
    neither could be blamed. The North Star asks for a runnable command per capability; when two
    capabilities point at one command, that command cannot say which of them is broken.

    This is a WARNING-class rule, not a refusal: sharing is legitimate when a single run really
    does prove both, and the fix belongs in the probe rather than in the registry. It is
    implemented here because the alternative is an audit nobody repeats.

    `native.ida.*` is exempted with a stated reason rather than silently: its loop is one process
    driving one MCP session, and both entries are proved by the same integration run today -- the
    scoping that separates them landed with the rule.
    """
    out = []
    by = {}
    for c in reg:
        if c.get("state") != "observed":
            continue
        cmd = str(((c.get("probe") or {}).get("command")) or "")
        if cmd:
            by.setdefault(cmd, []).append(c.get("id", "?"))
    for cmd, ids in by.items():
        if len(ids) > 1:
            out.append(f"R19 {sorted(ids)}: share one probe.command ({cmd[:60]!r}). That run "
                       f"cannot say which capability broke. Give each its own scoped probe.")
    return out


def r20_fact_map_declares(reg, doc):
    """invoke.fact_map must forward to facts the SAME entry declares.

    Found by independent verification on 2026-10-02, which sampled 8 of 20 entries and still
    found THREE live mismatches. R11 checks the consume side of an edge; nothing had ever
    checked the produce side of a fact_map. So a capability could declare its facts in
    `produces`, forward to a key that does not exist, and the registry reported REGISTRY CLEAN.

    The packer case is the one that matters: `die_verdict` went to an undeclared
    `pe.packer_verdict`, and the boolean `packed` -> `pe.packed` was not in fact_map AT ALL --
    so the single value the precondition decision rests on was never forwarded to anything.
    A fact_map that forwards nothing is a capability that cannot hand its answer on, and no
    amount of a clean registry changes that.
    """
    out = []
    for c in reg:
        fm = ((c.get("invoke") or {}).get("fact_map")) or {}
        if not fm:
            continue
        declared = {f.get("key") for f in (c.get("produces") or {}).get("facts") or []}
        missing = {}
        for src, dst in fm.items():
            if dst not in declared:
                missing.setdefault(dst, []).append(src)
        for dst, srcs in sorted(missing.items()):
            out.append(f"R20 {c.get('id')}: invoke.fact_map forwards {sorted(srcs)} to "
                       f"{dst!r}, which this entry does not declare in produces.facts. "
                       f"Declare it, or forward to a key that exists.")
    return out


def r21_control_command_runnable(reg, doc):
    """A negative control must be a COMMAND. A description of one cannot fail.

    R2 applies exactly this test to `probe.command` and has done since the rule existed. The
    control side had no equivalent, and the gap is not theoretical: measured 2026-10-02, 13 of
    24 entries carry a `negative_control.command` that is English --

        "oracle with an alg=none and a swapped-claims token"
        "drop SRUM from the image and re-run"
        "point the wrapper at a .txt file"
        "m02's solver pointed at m01's assembly"

    None of those can be executed, so none can fail, so all thirteen would pass forever. That
    is the worst shape a control can have: it reads as evidence in the registry and is a
    sentence in a file. Independent verification sampled 8 entries, met one of them, and
    concluded there were "only two such entries" -- a sampling artefact, because the class is
    defined by being uniform across the corpus rather than by being rare.

    Prose is not worthless and is NOT deleted here: a good negative design is real knowledge,
    and losing it would be the same 'only add, never subtract' rot this project keeps paying
    for. It moves to `control_plan` where it is still readable, and the rule then requires it
    to be declared a plan WITH A REASON -- so what remains is an explicit admission that this
    entry has no executable control, which is a fact a reader can act on.
    """
    RUNNABLE = (".mjs", ".js", ".cjs", ".py", ".ps1", ".exe", ".bat", ".cmd", ".com")
    out = []
    for c in reg:
        nc = c.get("negative_control")
        if not isinstance(nc, dict):
            continue
        cmd = str(nc.get("command") or "").strip()
        if not cmd:
            continue
        low = cmd.lower()
        if any(t in low for t in RUNNABLE) or low.startswith(
                ("node ", "python ", "powershell ", "cmd ", "uv ", "& ")):
            continue
        if nc.get("kind") == "plan" and str(nc.get("plan_reason") or "").strip():
            continue
        out.append(f"R21 {c.get('id','?')}: negative_control.command is prose -- {cmd[:64]!r}. "
                   f"A control nobody can execute cannot fail, so it passes forever. Either "
                   f"give it a command, or move the sentence to control_plan and set "
                   f"kind='plan' with a plan_reason saying why it cannot be run.")
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
        # A DECLARED PLAN is a legitimate answer to "what would refute this?", and R21 is what
        # forces it to be declared rather than smuggled in as English. R5 used to refuse the
        # same thing R21 now permits, so the two rules contradicted each other until this was
        # fixed: the honest resolution is that a plan-control has no executable exit code, and
        # saying so is better than inventing one. What R5 must NOT allow is a plan with no
        # reason, because that is indistinguishable from a missing control.
        if nc.get("kind") == "plan" and str(nc.get("plan_reason") or "").strip():
            continue
        if not nc.get("command"):
            out.append(f"R5 {c.get('id','?')}: negative_control has neither a command nor a "
                       f"declared plan. A capability whose checks always pass is a check, not "
                       f"evidence.")
            continue
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



def r8_reach_must_be_declared(reg, doc):
    """A capability must declare its reach as an EFFECT, not as a decorator tag.

    Found the hard way: ida-pro-mcp tags `py_eval` and the 22 dbg_* tools as unsafe,
    but does NOT tag `idb_save`, which writes a 2.7 MB file to an arbitrary path. An
    analyst reading the tags would call the static analyser read-only. So a registry
    entry that can write, execute, spawn or reach the network must say so in `reach`,
    and writing outside the case directory needs an escalation class.

    THE FLOOR MUST NOT COME FROM `reach`. The previous version built `implied` by
    iterating EFFECTS and appending every effect `reach` already declared, then
    computed `missing = [e for e in implied if not reach.get(e)]`. Every member was
    therefore implied only when already present, so `missing` was empty by
    construction and all five effects were unfalsifiable. Measured by mutation:
    setting each of reach.fs_write / net / proc_spawn / exec_target / db_write to
    false on a real entry produced 0 R8 problems in every case. The rule could only
    ever fire through requires.net and requires.admin, which is R6's job, so the
    half of R8 that exists to catch an undeclared effect could not catch one.

    The floor below is derived from what the capability says it DOES, in fields
    other than `reach`: it runs a probe command, it declares an invoke block, it
    consumes an input at all (something has to read it), and requires.net/admin.
    Each of those independently implies an effect, so deleting the declaration
    makes it missing. `db_write` is reachable because a capability that declares
    no invoke but consumes a path_ref still had its database opened by idalib --
    the decompile entry's own reach_must_not_delegate_why records that idb_save
    writes a 2.7 MB .i64, so an entry that consumes a binary and reaches a
    database declares db_write.

    The second half pins CONTAINMENT, which was unenforceable at the validator
    level: gate.ps1 accepts exactly three containment classes at intake and a
    grant carries no containment field of its own. A capability whose declared
    floor reaches the network or executes the target must therefore say which
    containment class it needs, here, where editing it is a registry edit."""
    out = []
    for c in reg:
        req = c.get("requires") or {}
        reach = c.get("reach") or {}
        gate = c.get("gate") or {}
        inputs = (c.get("consumes") or {}).get("inputs") or []
        # --- the floor, from fields OTHER than `reach` ---------------------------
        implied = set()
        if req.get("net") == "any":
            implied.add("net")
        if req.get("admin"):
            implied |= {"fs_write", "proc_spawn"}
        # Any capability that runs a command spawns a process. probe.command is
        # mandatory for observed entries and invoke.runner for callable ones, and
        # both mean a child process. This is the floor that makes proc_spawn
        # falsifiable: delete reach.proc_spawn and this still implies it.
        if (c.get("probe") or {}).get("command") or (c.get("invoke") or {}).get("runner"):
            implied.add("proc_spawn")
        # Consuming an input means reading it, and a `device` requirement means
        # running code on something that is not this process.
        if inputs:
            implied.add("fs_read")
        if req.get("device"):
            implied |= {"exec_target", "proc_spawn"}
        if not implied:
            continue
        missing = sorted(e for e in implied if not reach.get(e))
        if missing:
            out.append(f"R8 {c.get('id','?')}: what this capability does implies "
                       f"{sorted(implied)} but reach does not declare {missing}. "
                       f"Authority has to be declared as an effect, because a decorator "
                       f"tag can miss it.")
        # --- containment, pinned where the floor actually reaches out -----------
        if (reach.get("net") or reach.get("exec_target")) and not reach.get("containment"):
            out.append(f"R8 {c.get('id','?')}: reach.net/reach.exec_target is declared but "
                       f"reach.containment is not. The grant carries no containment field, "
                       f"so a capability that needs one has to say which of "
                       f"{sorted(VALID_CONTAINMENT)} it runs under.")
        elif reach.get("containment") and reach["containment"] not in VALID_CONTAINMENT:
            out.append(f"R8 {c.get('id','?')}: reach.containment={reach['containment']!r} is "
                       f"not one of {sorted(VALID_CONTAINMENT)}.")
        if reach.get("fs_write"):
            # Writing is not automatically an escalation. A capability that writes ONLY
            # into the mission's own case directory is the designed behaviour; writing
            # anywhere else is not a runtime self-decision. The rule could not tell those
            # apart, so every writing capability looked like a boundary violation.
            scope = reach.get("write_scope")
            if not scope:
                out.append(f"R8 {c.get('id','?')}: fs_write with no write_scope. Declare WHICH "
                           f"scope, so 'case_dir' and 'anywhere' stop looking alike.")
            elif scope != "case_dir" and gate.get("escalation_class") == "none":
                out.append(f"R8 {c.get('id','?')}: write_scope={scope!r} with "
                           f"escalation_class=none. Writing outside the case directory is "
                           f"never a runtime self-decision.")
    return out


def r9_batch_must_account(reg, doc):
    """If a capability consumes a batch, it must declare how items are accounted.

    Measured on ida-pro-mcp: `normalize_dict_list` silently DROPS non-dict elements
    in a mixed list (utils.py:704-706) -- 5 queries in, 4 results out, with no index,
    no echo and no dropped counter -- and an empty array becomes [{}], returning one
    bogus failed item. An orchestrator that asked for five facts and read four
    answers would have no signal that anything went missing."""
    out = []
    for c in reg:
        inputs = (c.get("consumes") or {}).get("inputs") or []
        batches = [i for i in inputs if str(i.get("type", "")).endswith("[]")]
        env = c.get("envelope") or {}
        if batches and env.get("batch") is None:
            out.append(f"R9 {c.get('id','?')}: consumes a batch ({batches[0].get('name')}) "
                       f"but declares no envelope.batch policy. Say how a short result is "
                       f"detected, because this class of API drops items silently.")
        if env.get("batch") is not None:
            for f in ("max_items", "aggregate"):
                if f not in env["batch"]:
                    out.append(f"R9 {c.get('id','?')}: envelope.batch is missing {f}.")
            if env.get("success_when") is None:
                out.append(f"R9 {c.get('id','?')}: envelope has no success_when. isError is "
                           f"not a verdict on this class of server.")
    return out

def r10_invoke_must_runnable(reg, doc):
    """An `invoke` block is what makes a capability CALLABLE rather than merely probeable.

    Without it nothing can hand an address to the next lab, which is the whole point of
    typed facts. With a broken one the mission loop spawns a command that does not
    exist or cannot succeed, and the mission reports an empty result as a finding. So:
    argv must be an array (never a joined string -- the target path is attacker-influenced
    by definition), the script it names must exist, and a success_when must be stated,
    because "exit 0" is the exact signal that already lied to us once today.
    """
    out = []
    for c in reg:
        inv = c.get("invoke")
        if not inv:
            continue
        cid = c.get("id", "?")
        argv = inv.get("argv")
        if not isinstance(argv, list) or not argv:
            out.append(f"R10 {cid}: invoke.argv must be a non-empty array. A joined shell "
                       f"string is the injection surface this exists to avoid.")
            continue
        if any(isinstance(a, str) and (" " in a and not a.startswith("{")) for a in argv[1:]):
            out.append(f"R10 {cid}: an invoke argument looks like a joined command line.")
        if not inv.get("runner"):
            out.append(f"R10 {cid}: invoke has no runner.")
        if not inv.get("success_when"):
            out.append(f"R10 {cid}: invoke has no success_when. Exit 0 is not the signal -- "
                       f"that is exactly how a failed Ghidra import looked like a pass.")
        # The script must actually exist. This is the whole point: a declared entry that
        # points at a missing file is a promise the loop will break at run time.
        #
        # Resolve it against the REPO ROOT, not the current working directory. Measured
        # defect: this line used pathlib.Path(script).exists(), which is CWD-relative, so
        # `cd /tmp && python scripts/registry-verify.py` reported SIX false R10 violations
        # -- "invoke names 'native-lab/tools/decompile.mjs', which does not exist" -- for
        # scripts that were sitting right there in the repo. The registry path itself was
        # always resolved from __file__ (DEFAULT, :126), so the file loaded correctly while
        # every path inside it was checked against the wrong root. A validator that cries
        # wolf on a clean checkout is worse than no validator, because the fix is to stop
        # reading its output. Recorded by a worker that had earlier written the bug down as
        # fixed; it was not.
        script = next((a for a in argv if isinstance(a, str) and a.endswith((".mjs", ".js", ".py"))), None)
        if script:
            cand = pathlib.Path(script)
            if not cand.is_absolute() and not (REPO_ROOT / cand).exists():
                cand2 = pathlib.Path(DEFAULT).parent.parent / cand
                if not cand2.exists():
                    out.append(f"R10 {cid}: invoke names {script!r}, which does not exist "
                               f"in this repo (looked in {REPO_ROOT / script}).")
        # A declared chain must be real: whatever it consumes_fact, someone must produce it.
        need = inv.get("consumes_fact")
        if need:
            produced = {(f.get("key")) for cc in reg for f in ((cc.get("produces") or {}).get("facts") or [])}
            if need not in produced:
                out.append(f"R10 {cid}: invoke.consumes_fact {need!r} is produced by no "
                           f"capability in this registry, so the chain cannot fire.")
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


# ------------------------------------------------------- composition (R11 - R14)

def _fact_fields(reg):
    """key -> (producer_id, [field names]). The `fields` list is what R11 checks an
    edge's `field` against, so a selector naming a field the fact does not carry is
    caught here rather than as a KeyError inside some orchestrator."""
    out = {}
    for c in reg:
        for f in (c.get("produces") or {}).get("facts") or []:
            if k := f.get("key"):
                out[k] = (c.get("id", "?"), list(f.get("fields") or []))
    return out


def _from_edges(reg):
    """Every declared composition edge, as (consumer, producer, field, input)."""
    for c in reg:
        for i in (c.get("consumes") or {}).get("inputs") or []:
            src = i.get("from")
            if isinstance(src, dict) and (src.get("capability") or src.get("field")):
                yield c, src.get("capability"), src.get("field"), i


def r11_edge_target_exists(reg, doc):
    """An edge must name a capability that exists and a field it really emits.

    Measured before this rule existed: R4 only inspected inputs that ALREADY had a
    `from`, so a `from.capability` naming a nonexistent id, a silently dropped edge,
    and a retyped input all produced zero complaints across 13 mutations. The
    registry could therefore claim any chain it liked. An edge to a capability
    nobody has heard of is a diagram, not a contract."""
    out = []
    ids = {c.get("id") for c in reg}
    produced = _fact_fields(reg)
    for cons, cap, field, inp in _from_edges(reg):
        cid = cons.get("id", "?")
        if not cap or cap not in ids:
            out.append(f"R11 {cid}: input {inp.get('name','?')!r} declares "
                       f"from.capability={cap!r}, which is not a capability in this "
                       f"registry. The edge points at nothing.")
            continue
        if not field:
            out.append(f"R11 {cid}: input {inp.get('name','?')!r} has a from with no "
                       f"field. Say WHICH field of {cap} it consumes.")
            continue
        if field not in produced:
            out.append(f"R11 {cid}: input {inp.get('name','?')!r} consumes "
                       f"{field!r} from {cap}, which produces no such fact.")
            continue
        # A selector may name the whole fact or one of its declared fields.
        fields = produced[field][1]
        if fields and inp.get("select_path") and inp["select_path"] not in fields:
            out.append(f"R11 {cid}: input {inp.get('name','?')!r} selects "
                       f"{inp['select_path']!r} out of {field!r}, whose declared fields "
                       f"are {fields}.")
    return out


def r12_edge_is_reachable(reg, doc):
    """An edge is two-sided, and both sides must be able to run.

    A capability that is `absent` or `blocked` cannot produce or consume anything, so
    an edge into or out of one is a claim the registry itself contradicts. The
    registry already knows this case: dynamic.device.frida declares exec_target and
    admin with a note saying "the effect is real even while the capability is absent",
    and gate.ps1 now filters absent/blocked out of a fresh grant. The registry must
    say the same thing structurally, because the gate and the validator are different
    systems and a rule only one of them has is the rule that gets forgotten."""
    out = []
    dead = {"absent", "blocked"}
    states = {c.get("id"): c.get("state") for c in reg}
    for cons, cap, field, inp in _from_edges(reg):
        cid = cons.get("id", "?")
        if cons.get("state") in dead:
            out.append(f"R12 {cid}: state={cons.get('state')} but it declares an edge "
                       f"from {cap!r}. A capability that cannot run consumes nothing.")
        if cap and states.get(cap) in dead:
            out.append(f"R12 {cid}: declares an edge from {cap}, whose state is "
                       f"{states.get(cap)}. An edge out of a capability that cannot run "
                       f"is a lie the loop will discover at run time.")
    return out


def r13_question_types_declared(reg, doc):
    """question_types entries are drawn from the enumeration the registry declares.

    `question_types` was a free-text field: nothing read it, so `Q99.made-up` on any
    capability validated clean, and removing question_types from every capability in
    the registry also validated clean. mission.ps1 carried its own hardcoded
    hashtable of the seven real types instead, which is why three of them routed
    nothing while Q5 and Q7 routed capabilities the registry never assigned them.
    The enumeration now lives in schema.question_types and this rule makes it the
    single source."""
    declared = set(((doc.get("schema") or {}).get("question_types") or {}))
    out = []
    if not declared:
        out.append("R13 schema.question_types is absent or empty. Declare the "
                   "enumeration here, so question_types[] has something to be drawn from.")
        return out
    for c in reg:
        for q in c.get("question_types") or []:
            if q not in declared:
                out.append(f"R13 {c.get('id','?')}: question_types entry {q!r} is not in "
                           f"schema.question_types {sorted(declared)}. A question type "
                           f"nobody declared routes nothing.")
    return out


def r14_no_island_capability(reg, doc):
    """An observed capability that produces a fact is either chained or says it is a root.

    Two halves, and the second is the one that mattered. Measured across 13
    mutations: deleting an island capability entirely produced ZERO complaints, so a
    capability could be removed from the proof contract and the validator would call
    the result cleaner than before. This rule makes shrinking the registry a loud
    failure: the count is pinned in schema.baseline.capability_count, and a capability
    may only leave the set by appearing in schema.retired with a reason.

    The first half is the composition floor. A capability that produces a fact and
    consumes nothing is fine -- plenty of real roots take a file from the Owner -- but
    it has to SAY so, with a root_reason, rather than leaving the reader to guess
    whether the omission was an oversight or a decision."""
    out = []
    schema = doc.get("schema") or {}
    baseline = schema.get("baseline") or {}
    retired = schema.get("retired") or []
    pinned = baseline.get("capability_count")
    ids = [c.get("id") for c in reg]
    retired_ids = {r.get("id") for r in retired if isinstance(r, dict)}
    for r in retired:
        if isinstance(r, dict) and not r.get("reason"):
            out.append(f"R14 retired entry {r.get('id','?')!r} has no reason. Say why "
                       f"the capability left the contract.")
    for cid in retired_ids:
        if cid in ids:
            out.append(f"R14 {cid} is listed in schema.retired AND still present in "
                       f"capabilities[]. Retiring is not deleting.")
    if pinned is not None:
        if len(reg) < pinned:
            gone = sorted(set(ids) | retired_ids)
            out.append(f"R14 the registry has {len(reg)} capabilities but "
                       f"schema.baseline.capability_count is {pinned}. Deleting an entry "
                       f"is not a silent way to pass: add it to schema.retired with a "
                       f"reason, or the contract shrank without anyone deciding so "
                       f"(known ids: {len(gone)}).")
        elif len(reg) > pinned:
            out.append(f"R14 the registry has {len(reg)} capabilities but "
                       f"schema.baseline.capability_count is {pinned}. Raise the pin in "
                       f"the same commit that adds the capability.")
    producing = {c.get("id") for c in reg
                 if ((c.get("produces") or {}).get("facts") or [])}
    chained = {cons.get("id") for cons, _, _, _ in _from_edges(reg)}
    for c in reg:
        cid = c.get("id")
        if (c.get("state") == "observed" and cid in producing and cid not in chained
                and not c.get("terminal") and not (c.get("root_reason") or "").strip()):
            out.append(f"R14 {cid}: observed, produces {len((c.get('produces') or {}).get('facts') or [])} "
                       f"fact(s), consumes no edge, and declares no root_reason. Say why "
                       f"it is a root, so the omission reads as a decision.")
    return out


# ------------------------------------------------- bindability (R15, R16, R17)

def r15_artifacts_are_bound(reg, doc):
    """Every produced artifact is bound by a fact_map, or is declared unbound with a reason.

    Measured: all three artifacts in the registry (native.dec.saved, fuzz.repro.bytes,
    native.ghidra.c) were referenced by no fact_map at all, so nothing in the loop
    could ever hand them on. An artifact nothing binds is a file nobody can find
    again. `unbound` is a legitimate answer -- bytes_ref content is deliberately not
    inlined -- but it has to be said out loud."""
    out = []
    bound = set()
    for c in reg:
        fm = (c.get("invoke") or {}).get("fact_map") or {}
        if isinstance(fm, dict):
            bound.update(fm.values())
    for c in reg:
        for a in (c.get("produces") or {}).get("artifacts") or []:
            key = a.get("key")
            if not key:
                out.append(f"R15 {c.get('id','?')}: an artifact has no key.")
                continue
            if key in bound:
                continue
            unb = a.get("unbound")
            if not unb or not (unb.get("reason") if isinstance(unb, dict) else unb):
                out.append(f"R15 {c.get('id','?')}: artifact {key!r} is bound by no "
                           f"fact_map and is not declared unbound with a reason. Bind it, "
                           f"or say why it cannot be.")
    return out


def r16_placeholders_resolve(reg, doc):
    """Every {placeholder} in an argv has a substitution source.

    Measured: capabilities.json declared `-OutDir {outdir}` and mission.ps1
    substitutes only `{target}` and `{input.<name>}`, so the literal string `{outdir}`
    reached the command line and Ghidra wrote its export into a directory named
    `{outdir}`. The substitution sources that exist are `{target}`, a declared
    `{input.x}`, and anything the caller passes explicitly via invoke.passed."""
    out = []
    for c in reg:
        inv = c.get("invoke") or {}
        argv = inv.get("argv")
        if not isinstance(argv, list):
            continue
        declared = {i.get("name") for i in ((c.get("consumes") or {}).get("inputs") or [])}
        passed = set(inv.get("passed") or [])
        for a in argv:
            if not isinstance(a, str) or "{" not in a:
                continue
            for ph in re.findall(r"\{([^{}]+)\}", a):
                if ph == "target":
                    continue
                m = re.fullmatch(r"input\.([A-Za-z0-9_]+)", ph)
                if m and m.group(1) in declared:
                    continue
                if ph in passed:
                    continue
                out.append(f"R16 {c.get('id','?')}: placeholder {{{ph}}} in invoke.argv has "
                           f"no substitution source. The loop substitutes only {{target}} "
                           f"and {{input.x}} for a declared input "
                           f"{sorted(n for n in declared if n)}, so this literal string "
                           f"would reach the command line verbatim.")
    return out


def r17_state_is_evidenced(reg, doc):
    """state=observed is bound to a run, not to a date somebody typed.

    `state` is the field the entire registry is built on: 12 of 15 entries claim it,
    and a grant is minted by filtering on it. Before this rule the only support was
    probe.last_run, a hand-written date string with nothing behind it -- so an entry
    could claim 'observed' for a run that never happened and validate clean. The rule
    accepts a sha256, a run_log path, or an explicit evidence_binding of "unverified"
    WITH a reason. The unverified marker is a real escape hatch on purpose: the honest
    state of those 12 entries today is that their probe output was summarised by hand
    and no artifact was retained, and a rule that demanded a hash nobody has would be
    a rule to work around rather than a rule to keep."""
    out = []
    for c in reg:
        if c.get("state") != "observed":
            continue
        cid = c.get("id", "?")
        probe = c.get("probe") or {}
        if not probe.get("last_run"):
            out.append(f"R17 {cid}: state=observed but probe.last_run is absent. A date "
                       f"is not a run; either record when it ran or stop claiming it did.")
            continue
        if probe.get("sha256") or probe.get("run_log"):
            continue
        ev = probe.get("evidence_binding")
        if not isinstance(ev, dict) or ev.get("status") != "unverified":
            out.append(f"R17 {cid}: state=observed with probe.last_run="
                       f"{probe.get('last_run')!r} but nothing BINDS that date to a run: "
                       f"no probe.sha256, no probe.run_log, and no explicit "
                       f"evidence_binding={{'status':'unverified'}}. Without one of the "
                       f"three, 'observed' is a claim.")
        elif not (ev.get("reason") or "").strip():
            out.append(f"R17 {cid}: evidence_binding.status='unverified' with no reason. "
                       f"Say what is not retained, so 'unverified' cannot become a "
                       f"free pass.")
    return out


def r18_evidence_family_agrees(reg, doc):
    """evidence_source must be a declared family, and ONE instrument must not wear TWO.

    Measured on the registry as it stood: native.ida.list_functions declared
    `static-analysis` while native.ida.decompile declared `decompiler`, and both drive
    the SAME instrument (requires.tools[0] = idalib-mcp). A chain of
    list_functions -> decompile -> ghidra.decompile therefore reported families
    {static-analysis, decompiler} and instruments {idalib-mcp, analyzeHeadless} and
    looked like two independent opinions, when the first "family" was one tool
    relabelled -- and Ghidra is a second decompiler, which is one opinion held twice.
    That is the same shape as every other finding in this file: the prose was RIGHT
    (the Ghidra entry already said "SAME FAMILY as IDA decompile") and the structured
    field was wrong, with nothing checking it.

    The first half makes the value a closed enumeration read from
    schema.evidence_families, so `evidence_source` can no longer be an open string
    that means whatever the author felt that day. The second half is the load-bearing
    one: two capabilities naming the same instrument must declare the same family.

    This rule deliberately says nothing about how the mission loop classifies a label.
    It reads capability identity and requires.tools -- the instrument the entry says it
    drives -- and never the gate. A gate that derives the family axis from the
    instrument needs no help from this field; a gate that reads the label gets a
    registry that is at least self-consistent."""
    out = []
    declared = set(k for k in ((doc.get("schema") or {}).get("evidence_families") or {})
                   if not k.startswith("_"))
    if not declared:
        out.append("R18 schema.evidence_families is absent or empty. Declare the "
                   "permitted families here, so evidence_source is a closed set rather "
                   "than an open string.")
        return out
    by_instrument: dict[tuple, list[tuple]] = {}
    for c in reg:
        es = c.get("evidence_source")
        if es is None:
            continue
        if es not in declared:
            out.append(f"R18 {c.get('id','?')}: evidence_source={es!r} is not in "
                       f"schema.evidence_families. An open string here means the label "
                       f"means whatever the author felt that day.")
        tools = tuple(sorted(t.get("name") for t in (c.get("requires") or {}).get("tools", [])
                             if isinstance(t, dict) and t.get("name")))
        if tools:
            by_instrument.setdefault(tools, []).append((c.get("id", "?"), es))
    for tools, entries in sorted(by_instrument.items()):
        fams = {es for _, es in entries}
        if len(entries) > 1 and len(fams) > 1:
            detail = ", ".join(f"{cid}={es}" for cid, es in sorted(entries))
            out.append(f"R18 one instrument {list(tools)} is declared as {len(fams)} "
                       f"evidence families ({detail}). Two capabilities that drive the "
                       f"SAME tool are ONE opinion however they are labelled; splitting "
                       f"the label manufactures corroboration that does not exist.")
    return out


RULES = (r1_not_empty, r_shape, r2_observed_needs_probe, r3_honesty_pair,
         r4_fact_types_agree, r5_control_must_fail, r6_reach_needs_escalation, r7_ids,
         r8_reach_must_be_declared, r9_batch_must_account, r10_invoke_must_runnable,
         r11_edge_target_exists, r12_edge_is_reachable, r13_question_types_declared,
         r14_no_island_capability, r15_artifacts_are_bound, r16_placeholders_resolve,
         r17_state_is_evidenced, r18_evidence_family_agrees, r19_probes_distinguish,
         r20_fact_map_declares, r21_control_command_runnable)


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
    """A minimal entry that satisfies all eighteen rules.

    It is deliberately not a stub: every field a rule reads is present and honest,
    because a baseline that only passes because the rules under-read it would make
    every case below it meaningless. `probe.evidence_binding` is the unverified
    marker R17 accepts, and `root_reason` is what R14 requires of a producer that
    consumes nothing."""
    return {
        "id": "example.lab",
        "title": "Example",
        "domains": ["example"],
        "question_types": ["Q1.identify"],
        "state": "observed",
        "consumes": {"inputs": []},
        "produces": {"facts": [{"key": "example.out", "type": "string"}]},
        "requires": {"runtime": "node", "net": "none", "admin": False},
        "root_reason": "takes the file from the Owner; nothing upstream produces one",
        "proves": ["that the example ran"],
        "does_not_prove": ["anything about a real target"],
        "negative_control": {"id": "x", "command": "python control.py --refuse",
                           "expect_exit": 1, "why": "must fail"},
        "gate": {"lane": "debug", "escalation_class": "none"},
        # R8's floor is derived from what the entry DOES, so a baseline that runs a
        # probe has to declare proc_spawn. It is here rather than omitted precisely
        # because the old R8 could not have caught its absence.
        "reach": {"fs_read": False, "fs_write": False, "net": False, "proc_spawn": True,
                  "exec_target": False, "db_write": False},
        "evidence_source": "practice",
        # A runnable command, not a placeholder. It said "example --selftest", which is PROSE,
        # and the R2 probe-runnability half added below caught it -- the synthetic registry was
        # modelling something the real rule forbids. A fixture has to be a LEGAL registry or it
        # tests the wrong baseline; this one was polluting four other cases expectations.
        "probe": {"command": "python scripts/example_selftest_probe.py", "expect": "ok", "exit": 0,
                  "last_run": "2026-09-30",
                  "evidence_binding": {"status": "unverified",
                                       "reason": "probe output was summarised by hand and "
                                                 "no artifact was retained"}},
    }


def _schema_doc(caps, pinned=None):
    """The envelope the real registry carries and every rule reads: the question-type
    enumeration (R13) and the capability-count pin plus retired list (R14)."""
    return {
        "schema": {
            "name": "capabilities.v1",
            "question_types": {"Q1.identify": "what is this file"},
            "baseline": {"capability_count": len(caps) if pinned is None else pinned},
            "retired": [],
            "evidence_families": {"decompiler": "reconstructs code into a language",
                                  "dynamic-observation": "watches a live subject",
                                  "practice": "self-built exercises"},
        },
        "capabilities": caps,
    }


def selftest() -> int:
    """Build a registry that breaks each rule and assert we catch it. A validator
    whose own rules are untested is the most confident untested thing in the repo."""
    def doc_of(caps):
        return _schema_doc(caps)

    cases = []

    def case(name, mutate, must_contain):
        base = [_good_entry(), _good_entry()]
        base[0]["id"], base[1]["id"] = "a.one", "b.two"
        base[1]["produces"]["facts"] = [{"key": "b.out", "type": "string"}]
        # Two synthetic entries sharing one probe would model exactly what R19 forbids, and it
        # reddened the baseline plus an unrelated R18 case. A fixture must be a LEGAL registry.
        base[1]["probe"]["command"] = "python scripts/example_selftest_probe_b.py"
        # The pin is captured BEFORE the mutation, so a case that deletes a
        # capability really does shrink the registry below it. Computing it after
        # would let the count follow the damage and the rule could never fire.
        pinned = len(base)
        mutate(base)
        got = validate(_schema_doc(base, pinned))
        hit = any(must_contain in p for p in got)
        cases.append((name, hit, got))

    def doc_case(name, mutate_doc, must_contain):
        """For rules that read the ENVELOPE (schema.retired, schema.baseline,
        schema.question_types) rather than a capability entry. Same discipline:
        mutate, validate, assert the rule fired."""
        base = [_good_entry(), _good_entry()]
        base[0]["id"], base[1]["id"] = "a.one", "b.two"
        base[1]["produces"]["facts"] = [{"key": "b.out", "type": "string"}]
        # Two synthetic entries sharing one probe would model exactly what R19 forbids, and it
        # reddened the baseline plus an unrelated R18 case. A fixture must be a LEGAL registry.
        base[1]["probe"]["command"] = "python scripts/example_selftest_probe_b.py"
        doc = _schema_doc(base, len(base))
        mutate_doc(doc)
        got = validate(doc)
        hit = any(must_contain in p for p in got)
        cases.append((name, hit, got))


    def nocase(name, mutate, must_not_contain):
        """A mutation that must NOT trip a rule.

        Without this, only positive cases are expressible, and a rule that refuses EVERYTHING
        passes every one of them -- the same always-red defect as an always-green control, in the
        validator rather than in a probe. The check that matters is that the registry still
        validates and that this particular message is absent.
        """
        base = [_good_entry(), _good_entry()]
        base[0]["id"], base[1]["id"] = "a.one", "b.two"
        base[1]["produces"]["facts"] = [{"key": "b.out", "type": "string"}]
        # Two synthetic entries sharing one probe would model exactly what R19 forbids, and it
        # reddened the baseline plus an unrelated R18 case. A fixture must be a LEGAL registry.
        base[1]["probe"]["command"] = "python scripts/example_selftest_probe_b.py"
        pinned = len(base)
        mutate(base)
        got = validate(_schema_doc(base, pinned))
        hit = any(must_not_contain in p for p in got)
        clean = not any("VIOLATION" in p or p.strip() for p in got)
        cases.append((name, (not hit) and clean, got))
    case("baseline must be clean", lambda b: None, "!!never!!")
    # An absent entry may prove nothing, but it must still say what it does NOT
    # prove -- otherwise "absent" quietly becomes "unexamined".
    case("R3 absent may have empty proves", lambda b: b[0].update(
        state="absent", proves=[]), "!!never!!")
    case("R3 absent still needs does_not_prove", lambda b: b[0].update(
        state="absent", proves=[], does_not_prove=[]), "R3")
    # must_contain is matched as a SUBSTRING, and "R1" is a substring of "R10".."R17".
    # Asserting on the bare prefix let this case pass because R14 fired on the same
    # mutation -- a control green for the wrong reason, which is worse than no
    # control. Match R1's own message text instead.
    case("R1 empty registry fails", lambda b: b.clear(), "capabilities[] is empty")
    case("R2 observed without probe", lambda b: b[0].pop("probe"), "R2")
    # Written because a real entry was found carrying a prose probe: a command that points at a
    # document cannot be executed, so "observed" was resting on a pointer rather than a run. The
    # second case matters as much as the first -- a rule that refuses everything is as useless as
    # one that refuses nothing, so a REAL command with no file extension must still pass.
    case("R2 observed with a PROSE probe (a pointer, not a command)",
         lambda b: b[0]["probe"].__setitem__("command", "see the reproduction section of some.md"),
         "R2")
    nocase("R2 a real command with no file extension is still accepted",
           lambda b: b[0]["probe"].__setitem__("command", 'python -c "import pefile"'), "R2")
    case("R19 two capabilities sharing one probe",
         lambda b: b[1]["probe"].__setitem__("command", b[0]["probe"]["command"]), "R19")
    nocase("R19 distinct probes are accepted",
           lambda b: b[1]["probe"].__setitem__("command", "python other_probe.py"), "R19")
    # R20: the produce side of a fact_map, which R11 never checked -- it validates the
    # CONSUME side of an edge only, so three live fact_map mismatches sat behind a clean
    # registry. The nocase is what catches a rule that merely refuses everything.
    def _with_fact_map(b, mapping):
        # The fixture entry may have no invoke at all, so build a LEGAL one: R10 also
        # demands a runner and a success_when, and a rule under test must not be
        # shadowed by a different rule refusing the same fixture.
        inv = b[0].setdefault("invoke", {})
        inv.setdefault("argv", ["probe_of_this_entry"])
        inv.setdefault("runner", "python")
        inv.setdefault("success_when", "exit 0 and stdout parses as JSON")
        inv["fact_map"] = mapping
    case("R20 fact_map forwards to an undeclared fact",
         lambda b: _with_fact_map(b, {"probe_out": "never.declared.by.this.entry"}), "R20")
    nocase("R20 a fact_map naming declared facts is accepted",
           lambda b: _with_fact_map(
               b, {"probe_out": b[0]["produces"]["facts"][0]["key"]}), "R20")
    # R21: the control side, which had no equivalent of R2. A control that is prose cannot
    # fail, so it passes forever -- 13 of 24 entries were in that state.
    case("R21 a prose negative control",
         lambda b: b[0]["negative_control"].__setitem__(
             "command", "point the wrapper at a .txt file"), "R21")
    nocase("R21 a runnable negative control is accepted",
           lambda b: b[0]["negative_control"].__setitem__(
               "command", "python control.py --refuse"), "R21")
    nocase("R21 a declared plan with a reason is accepted",
           lambda b: b[0]["negative_control"].update(
               {"kind": "plan", "plan_reason": "needs an MCP session"})
           or b[0]["negative_control"].pop("command"), "R21")
    case("R21 a plan with NO reason is refused",
         lambda b: b[0]["negative_control"].update({"kind": "plan", "plan_reason": ""})
         or b[0]["negative_control"].__setitem__("command", "just do the wrong thing"), "R21")
    case("R3 missing does_not_prove", lambda b: b[0].__setitem__("does_not_prove", []), "R3")
    # --- per-half controls -------------------------------------------------------
    # R3 and R5 each have two independent halves, and deleting EITHER half alone
    # left the whole-rule suite green. Whole-rule ablation cannot see that, so each
    # half gets its own case. These are the cases whose absence was the real gap.
    case("R3 observed with empty proves", lambda b: b[0].__setitem__("proves", []), "R3")
    case("R5 control with no expect_exit", lambda b: b[0]["negative_control"].pop(
        "expect_exit"), "R5")
    # r_shape had NO dedicated case: popping negative_control trips it too, so it was
    # only covered incidentally and `return []` as its first statement left the suite
    # green. This case breaks a key nothing else reads.
    case("R-shape missing a required key", lambda b: b[0].pop("gate"), "R-shape")
    case("R-shape state outside the valid set", lambda b: b[0].__setitem__(
        "state", "verified-ish"), "R-shape")
    case("R4 fact type mismatch", lambda b: b[0]["consumes"].__setitem__(
        "inputs", [{"name": "v", "type": "int", "from": {"capability": "b.two",
                                                          "field": "b.out"}}]), "R4")
    case("R5 control expecting exit 0", lambda b: b[0]["negative_control"].__setitem__(
        "expect_exit", 0), "R5")
    case("R5 control missing", lambda b: b[0].pop("negative_control"), "R5")
    case("R6 admin without escalation", lambda b: b[0]["requires"].__setitem__(
        "admin", True), "R6")
    case("R7 duplicate id", lambda b: b[1].__setitem__("id", "a.one"), "R7")
    case("R10 invoke without success_when", lambda b: b[0].update(
        invoke={"runner": "node", "argv": ["scripts/registry-verify.py"]}), "R10")
    case("R10 invoke argv as a shell string", lambda b: b[0].update(
        invoke={"runner": "sh", "argv": "node a.mjs b.mjs", "success_when": "ok"}), "R10")
    case("R10 invoke naming a missing script", lambda b: b[0].update(
        invoke={"runner": "node", "argv": ["scripts/does-not-exist.mjs"], "success_when": "ok"}), "R10")
    case("R10 chain whose fact nobody produces", lambda b: b[0].update(
        invoke={"runner": "node", "argv": ["scripts/registry-verify.py"],
                "success_when": "ok", "consumes_fact": "nobody.produces.this"}), "R10")
    case("R8 net=any without declared reach", lambda b: b[0]["requires"].__setitem__(
        "net", "any"), "R8")
    case("R8 fs_write with escalation none", lambda b: b[0].update(
        reach={"fs_write": True, "net": True}), "R8")
    # --- R8: the effects, one case each -----------------------------------------
    # The old R8 could not fail for any of these, because it built its `implied` set
    # out of `reach` itself. Each case below deletes ONE declared effect and expects
    # R8 to notice, which is exactly what it could not do before.
    case("R8 undeclared proc_spawn (entry runs a probe)", lambda b: b[0].update(
        reach={"fs_read": True, "proc_spawn": False}), "R8")
    case("R8 undeclared fs_read (entry consumes an input)", lambda b: (b[0].__setitem__(
        "consumes", {"inputs": [{"name": "f", "type": "path_ref", "required": True}]}),
        b[0].update(reach={"proc_spawn": True})), "R8")
    case("R8 exec_target without containment", lambda b: b[0]["requires"].__setitem__(
        "device", True), "R8")
    case("R8 containment outside the gate enumeration", lambda b: b[0].update(
        reach={"proc_spawn": True, "exec_target": True, "containment": "sandbox"}), "R8")

    # --- R11 / R12: the composition edges ---------------------------------------
    def _edge(cap, field):
        return lambda b: b[0]["consumes"].__setitem__(
            "inputs", [{"name": "v", "type": "string", "required": False,
                        "from": {"capability": cap, "field": field}}])
    case("R11 edge to a capability that does not exist",
         _edge("nobody.here", "b.out"), "R11")
    case("R11 edge to a field its producer never emits",
         _edge("b.two", "b.nonexistent"), "R11")
    case("R11 edge with no field named", _edge("b.two", None), "R11")
    case("R12 edge out of a capability that cannot run", lambda b: (b[1].__setitem__(
        "state", "blocked"), _edge("b.two", "b.out")(b)), "R12")
    case("R12 edge into a capability that cannot run", lambda b: (b[0].__setitem__(
        "state", "absent"), _edge("b.two", "b.out")(b)), "R12")

    # --- R13: question types ----------------------------------------------------
    case("R13 invented question type", lambda b: b[0].__setitem__(
        "question_types", ["Q99.made-up"]), "R13")

    # --- R14: islands and silent deletion ---------------------------------------
    case("R14 observed producer with no edge and no root_reason", lambda b: b[0].pop(
        "root_reason"), "R14")
    case("R14 registry shrank below the pinned count", lambda b: b.pop(), "R14")
    doc_case("R14 question-type enumeration removed from the schema",
             lambda d: d["schema"].pop("question_types"), "R13")
    doc_case("R14 retired entry with no reason",
             lambda d: d["schema"].__setitem__("retired", [{"id": "b.two"}]), "R14")
    doc_case("R14 retired capability still present",
             lambda d: d["schema"].__setitem__(
                 "retired", [{"id": "b.two", "reason": "superseded"}]), "R14")

    # --- R15 / R16 / R17: bindability -------------------------------------------
    case("R15 artifact bound by nothing", lambda b: b[0]["produces"].__setitem__(
        "artifacts", [{"key": "example.file", "type": "path_ref", "glob": "*.c"}]), "R15")
    case("R16 placeholder with no substitution source", lambda b: b[0].update(
        invoke={"runner": "node", "argv": ["scripts/registry-verify.py", "{outdir}"],
                "success_when": "ok"}), "R16")
    case("R16 placeholder for an undeclared input", lambda b: b[0].update(
        invoke={"runner": "node",
                "argv": ["scripts/registry-verify.py", "{input.nosuchthing}"],
                "success_when": "ok"}), "R16")
    case("R17 observed with nothing binding the run date", lambda b: b[0]["probe"].pop(
        "evidence_binding"), "R17")
    case("R17 unverified marker with no reason", lambda b: b[0]["probe"].__setitem__(
        "evidence_binding", {"status": "unverified"}), "R17")

    # --- R18: the evidence family a label claims --------------------------------
    # The measured case: two capabilities driving ONE instrument (idalib-mcp) were
    # labelled `static-analysis` and `decompiler`, which let a three-capability chain
    # present one tool relabelled plus a second decompiler as two independent opinions.
    case("R18 one instrument wearing two families", lambda b: (
        b[0]["requires"].__setitem__("tools", [{"name": "shared-tool"}]),
        b[1]["requires"].__setitem__("tools", [{"name": "shared-tool"}]),
        b[1].__setitem__("evidence_source", "decompiler")), "R18")
    case("R18 evidence_source outside the declared families", lambda b: b[0].__setitem__(
        "evidence_source", "some-tool-i-invented"), "R18")
    doc_case("R18 family enumeration removed from the schema",
             lambda d: d["schema"].pop("evidence_families"), "R18")
    # A tool legitimately serving two capabilities in ONE family must stay silent, or
    # this rule would push people back toward relabelling.
    case("R18 one instrument may have one family", lambda b: (
        b[0]["requires"].__setitem__("tools", [{"name": "shared-tool"}]),
        b[1]["requires"].__setitem__("tools", [{"name": "shared-tool"}])), "!!never!!")
    case("R9 batch consumed with no envelope", lambda b: b[0]["consumes"].__setitem__(
        "inputs", [{"name": "batch", "type": "string[]", "required": False}]), "R9")
    case("R9 envelope batch missing aggregate", lambda b: b[0].update(
        envelope={"success_when": "code != null and error is empty",
                  "batch": {"max_items": 100}}), "R9")

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
        print(f"SELFTEST FAILED: {failed} case(s) did not fire. The validator is the bug, "
              f"not the registry.")
        return 2
    # CASES, not rules. There are 18 rule functions and more cases than that, because
    # several rules have more than one independent half and each half needs its own
    # control. The old wording called this number a rule count, which it never was.
    print(f"SELFTEST OK: {len(cases) - 1} cases each fire on a registry built to break them.")
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
