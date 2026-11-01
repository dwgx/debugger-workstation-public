#!/usr/bin/env python3
"""registry-verify.py — the capability registry cannot lie.

The registry is what makes the nine labs composable: an orchestrator can only call
a capability it can introspect. That makes this validator load-bearing, which makes
its own correctness the thing to worry about. A checker that inspects zero items and
passes is worse than no checker, so:

  * an EMPTY registry is a failure, not a vacuous success;
  * the rules below are the code in `RULES`, in the same order.

THREE COUNTS USED TO BE STATED HERE AND EVERY ONE WAS WRONG. This header claimed 25 rule
functions, `--selftest` printing 67 rows and reporting 66, and 63 registries built to
break one rule. Measured stale by a verifier at both ends of the day's work: 34 numbered
rules, 104 cases. `--count` exists precisely because this prose used to state the numbers
and a mutation sweep measured them stale -- the FLAG was added and the PROSE WAS NEVER
REMOVED, so the one place a reader looks first kept lying while the gate beside it was
right. `doc-facts.py` does not catch this, because it checks the wiki and never the
validator's own docstring.

So this header states NO counts. Run `--count` for the rule total and `--selftest` for the
case count. Both are measured by running the thing, which is the only version of this number
that has ever been worth reading.

What is worth saying here, because it is not a number that drifts: cases outnumber rules
because several rules have more than one independent half, and each half needs its own
control -- deleting either half alone leaves the suite green while the registry quietly
loses the check. One row is a baseline that must stay clean and two are deliberate
relaxations that must stay SILENT, so the case count is not the rule count plus one.
R9 onward are not repeated in this header; each is documented at its own definition,
which is where the measurement behind it lives.

Rules, each traceable to a failure it prevents. R1 to R8, in `RULES` order:

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
import hashlib
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


def r35_control_buckets_reconcile(reg, doc):
    """runnable and plan must not overlap, and a runnable control must not still call itself a plan.

    Measured 2026-10-05. Converting `fuzz.differential.parse` from a declared plan to an
    executable control removed its `plan_note` but left `kind: "plan"` behind. Two counters then
    counted it twice -- one reading `command`, the other reading `kind` -- and doc-facts.py
    reported **25 runnable controls + 3 declared plans for a registry of 27**. Nothing failed,
    because both numbers were individually correct and only their SUM was impossible, and no
    check anywhere compared them against the total.

    That is the "it cannot count" shape from this project's own recurring-false-green page, in a
    gate rather than in a tool: two right answers nobody added up. The same sweep found
    `managed.il.decompile` still carrying a 2026-10-02 note that said "declared a plan, not a
    control" while a working `command` sat beside it -- verified working before the note was
    removed, not assumed from the absence of the note.
    """
    caps = reg if isinstance(reg, list) else reg.get("capabilities", [])
    runnable = {c.get("id", "?") for c in caps
                if str(((c.get("negative_control") or {}).get("command")) or "").strip()}
    plans = {c.get("id", "?") for c in caps
             if (c.get("negative_control") or {}).get("kind") == "plan"}
    out = []
    both = sorted(runnable & plans)
    if both:
        out.append(
            f"R35 {len(both)} entrie(s) declare BOTH a negative_control.command and kind='plan', so "
            f"the runnable and plan buckets overlap and the counts cannot reconcile: {both}. A plan "
            f"that became executable must lose kind='plan' in the SAME edit that adds the command.")
    stale = sorted(
        c.get("id", "?") for c in caps
        if c.get("id", "?") in runnable
        and "DECLARED A PLAN" in str((c["negative_control"].get("plan_note") or "")).upper()
    )
    if stale:
        out.append(
            f"R35 {len(stale)} entrie(s) have a runnable negative_control.command but a plan_note "
            f"still saying DECLARED A PLAN: {stale}. The note outlived the plan, so the entry "
            f"describes itself as something it stopped being.")
    return out



_RUNNABLE_VERBS = frozenset({
    "node", "python", "python3", "py", "powershell", "pwsh", "cmd", "uv", "uvx", "bash", "sh",
    "dotnet", "java", "javac", "adb", "git", "docker", "pip", "npx", "cargo", "go", "make",
})


def r37_skip_dict_agrees_with_state(reg, doc):
    """Nothing may sit in assert-probes' SKIP dict while its registry state is `observed`.

    Measured 2026-10-05, and I committed the drift before I noticed it. Promoting
    `native.crosscompare.ghidra` from planned to observed left the id in assert-probes.py's
    hardcoded SKIP dict, so the harness kept skipping an entry the registry now calls observed --
    and the entry with the strongest control in the tree, which measures 399 decompiled bodies
    across two real Ghidra analyses, was the one being skipped.

    The cause is structural rather than careless: SKIP and `state` are TWO SOURCES for the same
    fact, and nothing compared them. The same shape bit me twice more today -- a `skip_note`
    written into capabilities.json while the same words went into the SKIP reason string, and a
    `kind: "plan"` left behind on an entry that had gained a command. Three instances of "the
    registry says X and some other file says not-X".

    The rule is the narrow one that would have caught all three. The SKIP dict is allowed to be
    more conservative than `state` (that is what a SKIP is), never less: an entry may be
    skipped while observed only if something says so, and the gate reads that something from the
    registry rather than trusting a hand-maintained list.
    """
    import importlib.util as _ilu
    here = pathlib.Path(__file__).resolve()
    harness = here.parent / "assert-probes.py"
    if not harness.exists():
        return []
    try:
        spec = _ilu.spec_from_file_location("_ap_probe", harness)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        skip = getattr(mod, "SKIP", {})
    except Exception as exc:                                    # noqa: BLE001
        return [f"R37 could not read assert-probes.SKIP to reconcile it with the registry "
                f"({exc}). Two sources for the same fact, and the check itself is not running."]
    out = []
    for c in reg if isinstance(reg, list) else reg.get("capabilities", []):
        cid = c.get("id", "?")
        if cid in skip and c.get("state") == "observed":
            out.append(
                f"R37 {cid}: state is `observed` but it is still in assert-probes.py's SKIP dict "
                f"({skip[cid][:60]!r}...), so the harness skips a capability the registry calls "
                f"observed. Remove it from SKIP, or set the state to whatever it really is. A "
                f"skip nobody reads is how a control stops being evidence.")
    return out


def r36_probe_command_is_runnable(reg, doc):
    """`probe.command` must be something a shell can run, not a sentence about where to look.

    R21 already refuses prose in `negative_control.command`. There was no equivalent for
    `probe.command`, and the asymmetry is what let this through:

        native.crosscompare.ghidra
          command : see scripts/ghidra-failopen.md reproduction section
          expect  : Auto Version Tracking Command completed successfully with no apply markup errors

    A pointer to documentation is not a command. The `expect` string is worse than useless
    there: it is a Ghidra auto-analysis message with no relationship to cross-comparing two
    decompilers, so the entry reads as a probe that would catch a divergence and cannot.

    Measured, and this is the part worth recording: `powershell -File <anything-not-.ps1>`
    prints "Processing -File ... failed because the file does not have a .ps1 extension"
    and **exits 0**. So the prose command does not merely look wrong -- running it produces an
    error message on stdout with a SUCCESS exit code. Anything keying on the exit code reads a
    failure as a pass. That is the same shape as a deferred probe (R--require-complete) and as
    the budget path before it: an instrument that cannot fail.

    The rule is about the COMMAND being runnable. The entry may still be planned, blocked or
    absent -- that is a separate, honest claim with its own evidence. What it may not do is
    present prose as the thing the harness executes.
    """
    out = []
    for c in reg if isinstance(reg, list) else reg.get("capabilities", []):
        cmd = str(((c.get("probe") or {}).get("command")) or "").strip()
        if not cmd:
            continue
        head = cmd.split()[0].lower() if cmd.split() else ""
        # RUNNABLE is a local inside r10_invoke_must_be_runnable, not a module global, so
        # naming it here raised NameError at call time. Reference my own tuple instead.
        # Membership, NOT startswith-with-a-trailing-space. `cmd.split()[0]` is "node", never
        # "node ", so the first version of this matched nothing and fired on all 27 entries --
        # including ten `node <path>.mjs` commands that are perfectly runnable. Same family as the
        # `new Set('--json')` bug this session: a plausible string test that is quietly always-false
        # in one direction or the other, and only a run against the real tree shows which.
        if head in _RUNNABLE_VERBS:
            continue
        out.append(
            f"R36 {c.get('id','?')}: probe.command is not a runnable command -- {cmd[:70]!r}. "
            f"The harness executes this string; prose is executed as a filename, and "
            f"`powershell -File <non-.ps1>` exits 0 after printing an error, so the entry reads as "
            f"a passing probe that measured nothing. Either give it a command that runs, or move "
            f"the prose to plan_reason and declare the entry planned -- which is a claim a reader "
            f"can check, whereas this is one they cannot.")
    return out

def r25_plan_needs_a_checkable_ref(reg, doc):
    """A declared plan must point at something a machine can check, or admit it cannot.

    This is the rule that the 2026-10-03 audit of the ten plan-only controls asked for, and
    the audit is the reason it exists: **six of those ten `plan_reason` strings were
    contradicted by the tree they sat in.** `mobile.apk.static` said "no second AXML decoder
    is installed" while Apktool 3.0.3 and JADX 1.5.6 were both on disk and both already being
    run by the lab; `native.il2cpp.symbols` said the blocker was a missing metadata dump when
    the real blocker is a .NET runtime and an authorisation decision; `native.ghidra.emulate`
    said the runtime was missing while Ghidra 12.1.3 is installed and already used by another
    entry. R21 and R5 accept `kind: plan` on the sole condition that `plan_reason` is a
    non-empty STRING, so a false blocker costs nothing to write and nothing to catch.

    Three reference forms, and the third is the honest one:

      file:<path>        the reason is "this artefact does not exist". It MUST exist -- a
                         `file:` ref that resolves is a plan whose reason is already false.
      missing:<glob>     the reason is "nothing matches this". The repo-relative glob MUST
                         match nothing.
      undecidable:<why>  the blocker is outside the repository (a tool on PATH, a device, a
                         runtime, an Owner decision). Allowed, but only with a sentence saying
                         why it cannot be checked here -- so "nobody checked" is visible as a
                         claim rather than hidden inside prose.

    What this rule does NOT do: decide whether a plan is justified. It only refuses a plan
    whose stated blocker was never pointed at, which is the part that was silently wrong.
    """
    out = []
    for c in reg:
        nc = c.get("negative_control") or {}
        if nc.get("kind") != "plan":
            continue
        cid = c.get("id", "?")
        ref = str(nc.get("plan_ref") or "").strip()
        if not ref:
            out.append(f"R25 {cid}: negative_control.kind='plan' with no plan_ref. A plan "
                       f"reason is a sentence, and a sentence cannot be checked: six of the "
                       f"ten plans in this registry were contradicted by the tree they sat "
                       f"in. Add plan_ref as file:<path> (and it must exist), "
                       f"missing:<glob> (and it must match nothing), or "
                       f"undecidable:<why> (and say why it cannot be checked here).")
            continue
        if ref.startswith("file:"):
            p = pathlib.Path(ref[5:].strip())
            if not p.is_absolute():
                p = REPO_ROOT / p
            if not p.exists():
                out.append(f"R25 {cid}: plan_ref file:{ref[5:].strip()} does not exist. The "
                           f"plan says something is missing and points at it; if the thing is "
                           f"missing, the path is a real blocker to record -- if it is NOT "
                           f"missing, the plan_reason is false and the control is writable now.")
        elif ref.startswith("missing:"):
            hits = list(REPO_ROOT.glob(ref[8:].strip()))
            if hits:
                out.append(f"R25 {cid}: plan_ref missing:{ref[8:].strip()} MATCHES "
                           f"{len(hits)} existing path(s), first {hits[0].name!r}. The plan "
                           f"says nothing is there and something is; the blocker is stale.")
        elif ref.startswith("undecidable:"):
            if len(ref[12:].strip()) < 12:
                out.append(f"R25 {cid}: plan_ref undecidable: with no reason. If the blocker "
                           f"cannot be checked from this repository -- a tool on PATH, a "
                           f"device, an Owner decision -- SAY WHICH, in a sentence. 'nobody "
                           f"checked' is a claim; it has to be visible as one.")
        else:
            out.append(f"R25 {cid}: plan_ref {ref[:40]!r} is not one of the three forms: "
                       f"file:<path>, missing:<glob>, undecidable:<why>.")
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
                # `{scratch:<name>}` is the third source, added 2026-10-03: the ORCHESTRATOR
                # provides it, as a directory it creates inside the mission's own case dir. It
                # exists because `native.ghidra.decompile` needed an output directory, declared one
                # as an input, and therefore bound a fact NOBODY produces -- so the round was
                # permanently `skipped_unmet_input` and the capability could never run. Both
                # alternative fixes are worse: dropping the placeholder makes the entry's
                # `write_scope: case_dir` a lie (the wrapper falls back to %TEMP%, measured), and
                # inventing a producer capability for a directory is new machinery.
                # A scratch dir is not evidence: nothing produces it, so it must never be typed
                # as a fact and must never appear in consumes_fact.
                if re.fullmatch(r"scratch:[A-Za-z0-9_-]+", ph):
                    continue
                if ph in passed:
                    continue
                out.append(f"R16 {c.get('id','?')}: placeholder {{{ph}}} in invoke.argv has "
                           f"no substitution source. The loop substitutes {{target}}, "
                           f"{{input.x}} for a declared input {sorted(n for n in declared if n)}, "
                           f"and {{scratch:name}} as a directory it creates in the case dir, so this "
                           f"literal string would reach the command line verbatim.")
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
            # HARDENED 2026-10-03, and this is the deepest instance of the disease this file
            # exists to catch. The branch used to `continue` on ANY non-empty string, and all
            # eleven `probe.run_log` values in this registry turned out to be PROSE -- "measured
            # 2026-10-02 in this session, ...", "identity control (same content, two filenames):
            # ok=true ...". `state: observed` is not a documentation field: gate.ps1's
            # Get-GrantableIds grants a capability only where `state == observed`, so a sentence
            # in a run_log was enough to make a capability RUNNABLE. A run_log is now a path to
            # a file that exists, and a sha256 must be that file's hash.
            #
            # What this does NOT claim: that the file was produced by the instrument. A stub
            # which prints the recorded strings can also write those strings to a file. That
            # limit is written down rather than papered over -- the same sentence appears in
            # assert-probes.py's OK verdict.
            rl = str(probe.get("run_log") or "").strip()
            want = str(probe.get("sha256") or "").strip().lower()
            if not rl:
                out.append(f"R17 {cid}: probe.sha256 is recorded but probe.run_log is not, so "
                           f"there is nothing to hash. A hash of nothing is a decoration.")
                continue
            p = pathlib.Path(rl)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if not p.is_file():
                out.append(f"R17 {cid}: probe.run_log {rl!r} is not a file that exists. A run_log "
                           f"is the retained OUTPUT of a run; a sentence describing one is not "
                           f"evidence, and state=observed is what decides what a grant may "
                           f"contain. Either point it at the file a real run wrote "
                           f"(`python scripts/assert-probes.py --save-evidence evidence/probes` "
                           f"writes one per capability), or record "
                           f"evidence_binding={{'status':'unverified','reason':...}} and say what "
                           f"is not retained.")
                continue
            if want and hashlib.sha256(p.read_bytes()).hexdigest() != want:
                out.append(f"R17 {cid}: probe.sha256 does not match {rl}. The retained run has "
                           f"changed under the registry, so the claim and the evidence have come "
                           f"apart. Re-run the probe and record the new hash, or say why the old "
                           f"run is still the one being claimed.")
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


def r22_ungrantable_needs_a_reason(reg, doc):
    """A capability that declares itself outside every grant must say why.

    `gate.Get-GrantableIds` grants a capability only where `requires_verdict` is true --
    its docstring reads "same lane, THE GRANT IS THE VERDICT, AND state observed". So
    `requires_verdict: false` does not mean "this one is safe"; it means **a grant does not
    authorise this at all**, and no mission can ever run it.

    Measured 2026-10-02: three capabilities carry that flag -- crypto.jose.parse,
    re.corpus.solve and fuzz.differential.parse -- and **none had a reason recorded**. One of
    them is the sole target-scoped candidate for Q5.vuln-shape, so an entire axis is dark
    because of three characters in a JSON field nobody wrote a sentence about.

    This rule deliberately does NOT ask whether the flag should be true. That is an Owner
    decision, and a validator that could flip a safety marker would be a validator that
    improves metrics by weakening gates. It asks only that the exclusion be deliberate --
    an exclusion with no stated reason reads as an oversight, and this registry has learned
    twice today that an unexamined field is a field that is wrong.
    """
    out = []
    for c in reg:
        g = c.get("gate") or {}
        if g.get("requires_verdict") is False:
            why = str(g.get("requires_verdict_reason") or "").strip()
            if not why:
                out.append(f"R22 {c.get('id','?')}: gate.requires_verdict is false, which keeps this "
                           f"capability outside EVERY grant -- no mission can run it -- and no "
                           f"requires_verdict_reason is recorded. State why. (Do NOT flip the flag "
                           f"to make a metric improve: that is an Owner decision, not a fix.)")
    return out


def r23_escalation_class_needs_a_reason(reg, doc):
    """A class above `none` is a claim about authority, so it must be justified -- once, under one key.

    Measured 2026-10-03. `gate.escalation_class` is checked against VALID_ESCALATION by R6,
    so the vocabulary was sound; the EXPLANATION was the soft field, and it was spelled two
    ways. `gate.escalation_why` appears on `dynamic.win.frida.intercept` and
    `native.function.match`; `gate.escalation_reason` appears on `native.signature.certverify`.
    Neither key is read by any rule in this file or any other script, so which spelling wins
    is decided by whoever typed last, and four of the seven non-`none` entries carry no
    explanation under any spelling at all.

    `owner_word` is not a formality: it is the only class that lets a mission widen its own
    invocable set with a fresh Owner sentence. An entry that declares it without saying what
    the extra authority buys is an entry nobody can review.

    What this rule does NOT do: decide whether a class is right. As in R22, that is an Owner
    decision and a validator that could flip it would improve metrics by weakening gates.
    """
    out = []
    for c in reg:
        g = c.get("gate") or {}
        cls = g.get("escalation_class")
        if cls in (None, "none"):
            continue
        if "escalation_why" in g:
            out.append(f"R23 {c.get('id','?')}: gate.escalation_class is '{cls}' and the "
                       f"reason is spelled `escalation_why`. The canonical key is "
                       f"`escalation_reason`; two spellings means whichever one a reader "
                       f"knows to look for is the one that is missing.")
            # One defect, one message. Without this `continue` the same entry ALSO drew "no
            # escalation_reason is recorded", which is true but reads as though the entry had
            # never had a reason -- two complaints where the fix is one rename. (Independent
            # verification, 2026-10-03, finding 6.)
            continue
        why = str(g.get("escalation_reason") or "").strip()
        if not why:
            out.append(f"R23 {c.get('id','?')}: gate.escalation_class is '{cls}', which is the "
                       f"only class that lets a mission widen its own invocable set with a fresh "
                       f"Owner sentence, and no escalation_reason is recorded. State what the "
                       f"extra authority buys. (Do NOT lower the class to make a metric improve: "
                       f"that is an Owner decision, not a fix.)")
    return out


def r24_input_types_are_declared(reg, doc):
    """Every input is typed from the input vocabulary, and a fact type is not an input type.

    Measured 2026-10-03, and this rule exists because of three wrong declarations rather than
    a theory. `net.pcap.analyse` and `net.pcap.selfparse` both declared `capture: pcap`, and
    `mobile.apk.static` declared `apk: apk`. Read against `fact_types`, whose own text is
    "a parsed packet-capture record set" and "a parsed Android package manifest or dex
    summary", those three inputs claimed to be ALREADY-PARSED CONTENT while all three are
    paths to files on disk. The board's next-action said to fix `net.pcap.selfparse`; the
    measurement said three entries and a missing vocabulary.

    Nothing caught it, and the reason is structural rather than accidental: R4 compares a
    consumer's declared input type against the producer's fact type ONLY when the input
    carries a `from` edge. 34 of the 41 inputs in this registry have no edge -- they are
    supplied from outside -- so their `type` was read by no rule at all. `schema.input_types`
    was added the same day so the field has a closed vocabulary to be wrong about.

    The second half is the one that generalises: `pcap`, `apk`, `verdict` and `bytes_ref` are
    fact types, and naming one as an input type asserts that the caller hands over parsed
    content. That is almost never true, and when it is, the input has a producer and a `from`.
    """
    declared = (doc.get("schema") or {}).get("input_types") or {}
    out = []
    parsed = {k for k, v in (doc.get("fact_types") or {}).items()
              if k not in ("string", "address", "structure", "token", "path_ref")}
    for c in reg:
        for i in (c.get("consumes") or {}).get("inputs") or []:
            t = i.get("type")
            if not t:
                out.append(f"R24 {c.get('id','?')}: input {i.get('name','?')!r} has no type.")
                continue
            if t not in declared:
                extra = ""
                if t in parsed:
                    extra = (f" It is a FACT type ({sorted(parsed)}), which asserts the caller "
                             f"hands over parsed content. A file on disk is a path_ref; what a "
                             f"reader makes of it is a fact.")
                out.append(f"R24 {c.get('id','?')}: input {i.get('name','?')!r} is typed "
                           f"{t!r}, which is not in schema.input_types "
                           f"({sorted(k for k in declared if not k.startswith('_'))}).{extra}")
    return out


def r26_bare_braces_survive_the_shell(reg, doc):
    """A command the runner executes VERBATIM may not contain an unquoted brace.

    This rule exists because of one measured failure, and the failure is nastier than a
    typo. `assert-probes.py` writes `probe.command` / `negative_control.command` byte-for-byte
    into a .ps1 and runs it with `powershell -File`. PowerShell does not treat `{` as an ordinary
    character in argument position: it starts a SCRIPT BLOCK. So

        --expect-flag FLAG{c01_string_table_xor}

    does not reach python as that string. PowerShell evaluates `FLAG{...}` as a command with a
    script block, re-enters itself, and the child process is finally handed

        -encodedCommand YwAwADEAXwBzAHQAcgBpAG4AZwBfAHQAYQBiAGwAZQBfAHgAbwByAA== -inputFormat xml ...

    which base64/UTF-16LE-decodes to `c01_string_uableble_hor` -- a mangled fragment of the flag.
    Measured: the control exits 2 (argparse "unrecognized arguments"), not the 1 it declares, and
    the recorded expect_output is absent. R21 accepted the command as runnable, because as a
    STRING it is perfectly runnable. Nothing was wrong with the text; everything was wrong with
    what the shell did to it.

    Quoted spans are exempt, and that exemption is what makes the rule usable: the frida
    commands carry a whole JavaScript payload inside PowerShell SINGLE quotes, full of braces,
    and they work. The scan therefore tracks both quote characters and skips their contents.

    What this does NOT do: parse PowerShell. A backtick-escaped quote and a here-string are
    handled, an unterminated quote is not diagnosed. It refuses the shape it has measured.
    """
    out = []
    for c in reg:
        for field, holder in (("probe", c.get("probe") or {}),
                              ("negative_control", c.get("negative_control") or {})):
            cmd = holder.get("command")
            if not isinstance(cmd, str) or "{" not in cmd:
                continue
            quote = None
            i = 0
            hits = []
            while i < len(cmd):
                ch = cmd[i]
                if ch == "`" and i + 1 < len(cmd):   # backtick escapes the next character
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = None
                    i += 1
                    continue
                if ch in "\"'":
                    quote = ch
                    i += 1
                    continue
                if ch == "{":
                    m = re.match(r"\{[A-Za-z0-9_.:]+\}", cmd[i:])
                    hits.append(m.group(0) if m else "{")
                    i += 1
                    continue
                i += 1
            if hits:
                out.append(f"R26 {c.get('id','?')}: {field}.command contains an UNQUOTED brace "
                           f"({hits[0]}). The runner writes this string verbatim into a .ps1 and "
                           f"runs it with `powershell -File`, where a bare '{{' in argument "
                           f"position starts a script block: PowerShell re-enters itself and the "
                           f"child gets `-encodedCommand <base64 of a mangled token>` instead. "
                           f"Measured on re.corpus.solve: the control exited 2 (argparse "
                           f"'unrecognized arguments') instead of the 1 it declares. Quote the "
                           f"value -- \"FLAG{{...}}\" -- or stop putting a brace in argument "
                           f"position. A brace inside quotes is fine, which is why the whole "
                           f"frida JavaScript payload does not trip this.")
    return out


def r27_probe_exit_has_one_spelling(reg, doc):
    """`probe.exit` is not read by anything. `probe.expect_exit` is. Only one may be written.

    Found 2026-10-03 by a mutation sweep of every registry field (a copy in %TEMP%, one field
    changed across all entries that carry it, the real validator run against the copy). Setting
    `probe.exit` to 999 on all sixteen entries that declare it left the validator at exit 0,
    REGISTRY CLEAN.

    The measurement underneath it is sharper than "unchecked". This registry spells the same
    contract two ways and the two spellings never meet: SIXTEEN entries declare `probe.exit` and
    ELEVEN declare `probe.expect_exit`, and NOT ONE declares both. `assert-probes.py` reads
    `expect_exit` and has never read `exit`. So `probe.exit` is not merely unchecked, it is the
    spelling that means `state: observed` while quietly never being compared -- and `state:
    observed` is the field gate.ps1 grants on.

    This is the same disease as `escalation_why` / `escalation_reason`, which produced R23 on
    2026-09-30: two spellings, a reader for one, silence for the other, and nothing to notice
    because each spelling is individually well-formed. The lesson generalises past the field:
    when two names exist for one contract, the check that closes the gap is to REFUSE the
    unreadable one, not to start reading it as well.
    """
    out = []
    for c in reg:
        probe = c.get("probe") or {}
        if "exit" not in probe:
            continue
        out.append(f"R27 {c.get('id','?')}: probe.exit is declared (={probe.get('exit')!r}) and "
                   f"NOTHING reads it -- assert-probes.py compares probe.expect_exit, and no rule "
                   f"in this file looks at probe.exit at all. Measured 2026-10-03: setting it to "
                   f"999 on every entry that declares it leaves this validator at exit 0. Rename "
                   f"it to probe.expect_exit, which is compared on every run. Two spellings of one "
                   f"contract, and only one of them is a check.")
    return out


def r28_evidence_is_tracked_not_merely_present(reg, doc):
    """A run_log that exists but is not in git is evidence the next window cannot check.

    R17 already refuses a `probe.run_log` that is not a file, and refuses a `sha256` that does not
    match it. Neither of those notices whether git CARRIES the file, and this registry learned the
    hard way why that is the wrong question to stop at.

    Measured 2026-10-03, in this order. `evidence/probes/*.log` matched `.gitignore`'s blanket
    `*.log`, so eleven `probe.run_log` paths pointed at files git refused to carry: present on this
    workstation, invisible to a clone, hash-checkable here and nowhere else. The fix was a
    deliberate `.gitignore` exception plus `.gitattributes` `-text`, and both were applied BY HAND,
    once, by a person who remembered. Nothing in the validator would have noticed the next person
    adding a twenty-second binding under a path nobody had excepted -- which is the same shape as
    every other finding in this file: a contract maintained by memory.

    So the exception is now checked rather than remembered. `git ls-files` is the only honest
    answer to "will the next window have this file", and it is what this rule asks.

    What this does NOT do: verify the file is unmodified, or that git's copy matches the working
    tree beyond what R17's hash already does. It asks one question -- is it committed.
    """
    import subprocess
    out = []
    tracked = None
    for c in reg:
        probe = c.get("probe") or {}
        rl = str(probe.get("run_log") or "").strip()
        if not rl:
            continue
        if tracked is None:
            try:
                r = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"],
                                   cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60)
                tracked = set(r.stdout.split("\n")) if r.returncode == 0 else set()
            except Exception:                                        # noqa: BLE001
                tracked = set()
            if not tracked:
                out.append("R28?: git ls-tree HEAD produced nothing, so nothing here can be "
                           "checked for tracking. Refusing to pass rather than pretending the "
                           "evidence is committed.")
                return out
        if rl.replace("\\", "/") not in tracked:
            out.append(f"R28 {c.get('id','?')}: probe.run_log {rl!r} exists and its sha256 matches, "
                       f"but HEAD does not carry it -- STAGED IS NOT COMMITTED. On this "
                       f"workstation that file is present and checkable; in a clone it does "
                       f"not exist, so the binding is a claim about one machine. Commit it (and "
                       f"check .gitignore -- a blanket `*.log` "
                       f"will swallow a .log silently) or drop the binding and say the evidence is "
                       f"not retained.")
    return out



def r29_fact_types_are_declared(reg, doc):
    """Every produced fact's type must be a MEMBER of the fact_types vocabulary.

    Found 2026-10-03 by a mutation sweep of every registry field: retyping all 51 facts to
    `banana` left the validator at exit 0, REGISTRY CLEAN. R4 checks that two producers of the same
    key AGREE and that a consumer matches its producer -- and it only does the second where a `from`
    edge exists, so 47 of 51 facts were compared against nothing at all. The vocabulary existed the
    whole time, ten members wide, and was read by exactly one rule -- R24, and only to work out
    which types are NOT input types.

    Landing this rule turned the registry red on 19 rows, which is the interesting part: it is not
    that the field was unchecked, it is that NINE facts were actively LYING about their shape.
    Measured against retained probe logs and the emitters themselves:

      pe.entry_rva            declared `address`, and its own note said "An RVA, not an address"
      behav.count             declared `verdict`, and its own note said "A COUNT IS NOT A FINDING"
      pe.packed / pe.signed   declared `verdict`; both emit a bare boolean
      pe.die_score            declared `structure`; emits 6.15091
      insn.stream             declared `bytes_ref`, defined as "the bytes are not inlined"; the
                              40 instructions are inlined in stdout and no file is written
      pe.section_extent, fn.pair, insn.rip_operand, behav.pattern
                              declared `structure`; all four are LISTS
      net.flow.summary        declared `structure` with fields src/dst; fact_map binds `detail`,
                              which is prose
      skill.findings          declared `path_ref`; skillspector writes JSON to stdout and creates
                              no file, so the path does not exist

    Two of those had the right prose and the wrong type in the same object, which is the strongest
    argument for the rule: a human reading the entry was told the truth, and a machine reading the
    field was told the opposite.

    Enforcing membership required GROWING the vocabulary first, because four of the measured shapes
    had no member to be typed as: `rva`, `boolean`, `number`, `structure[]`. Those four were added
    in the same commit, each with the measurement that demanded it in its definition. A closed list
    that cannot express what the instruments emit is a closed list people route around.
    """
    declared = set((doc.get("fact_types") or {}))
    out = []
    for c in reg:
        for f in (c.get("produces") or {}).get("facts") or []:
            t = f.get("type")
            if t not in declared:
                out.append(f"R29 {c.get('id','?')}: fact {f.get('key','?')!r} is typed {t!r}, "
                           f"which is not in fact_types ({sorted(declared)}). A fact typed as "
                           f"something it is not is worse than an untyped one, because every "
                           f"consumer of that type assumes a shape it will not find. If the "
                           f"instrument really emits something the vocabulary cannot name, ADD the "
                           f"member with the measurement that demands it -- do not retype the fact "
                           f"to something convenient.")
    return out



def r30_requires_and_lane_are_declared(reg, doc):
    """`requires.net` and `gate.lane` are read by a literal comparison and nothing else.

    Measured 2026-10-03 by mutation: setting `requires.net` to `the-internet` on all 27 entries
    leaves this validator at exit 0, REGISTRY CLEAN. The reason is not that the field is ignored --
    it IS read, twice, by the exact test `req.get("net") == "any"` (the R6 escalation floor and the
    R8 reach floor). Every other string is therefore INERT: `any` means escalate me, and every
    other value means the same thing, whatever it says. A field whose only live value is one
    string is a flag wearing a vocabulary clothes.

    `gate.lane` is worse in the way that matters for authority. gate.ps1 filters grants on
    `$_.gate.lane -eq $Lane` (Get-GrantableIds) and `-ne $Lane` (Check), both plain equality
    against a caller-supplied lane. There is no VALID_LANES anywhere, so `atlantis` validates here,
    is simply never equal to `debug` or `bounty`, and silently drops the capability out of every
    grant rather than being refused. A typo in a lane is not an error today; it is a capability
    that stops being grantable and nobody is told.

    Both are now closed against `schema.net_requirements` and `schema.lanes`, which is where every
    other enumeration in this document already lives -- R13 question types, R24 input types, R18
    evidence families. The values are not invented: `none` is what 27 of 27 entries declare, `any`
    is the only other literal the code reads, and the two lanes are the two in use and the two the
    MCP surface names in prose.

    What this does NOT do: it does not make `reach.net` and `requires.net` agree. They are
    different questions -- need the network, versus touch the network -- and `net.pcap.analyse` is
    the case that proves it: its probe needs no network, its lab negative control is a CA-trust
    check. A sweep flagged that pair as a contradiction and it is not one; `schema._two_net_fields`
    records the distinction so the next sweep does not re-raise it.
    """
    schema = doc.get("schema") or {}
    nets = set(schema.get("net_requirements") or {})
    lanes = set(schema.get("lanes") or {})
    out = []
    if not nets:
        out.append("R30?: schema.net_requirements is absent, so requires.net cannot be checked "
                   "against anything. Refusing to pass rather than skipping the check quietly.")
        return out
    if not lanes:
        out.append("R30?: schema.lanes is absent, so gate.lane cannot be checked against "
                   "anything. Refusing to pass rather than skipping the check quietly.")
        return out
    for c in reg:
        cid = c.get("id", "?")
        rn = (c.get("requires") or {}).get("net")
        if rn not in nets:
            out.append(f"R30 {cid}: requires.net is {rn!r}, which is not in schema."
                       f"net_requirements ({sorted(nets)}). The escalation and reach floors key "
                       f"on the literal 'any', so every other string -- including a typo -- means "
                       f"'no escalation needed' while reading like something else. If this "
                       f"capability genuinely needs the network, say 'any'.")
        ln = (c.get("gate") or {}).get("lane")
        if ln is not None and ln not in lanes:
            out.append(f"R30 {cid}: gate.lane is {ln!r}, which is not in schema.lanes "
                       f"({sorted(lanes)}). gate.ps1 filters grants by EQUALITY against a "
                       f"caller-supplied lane, so an unrecognised lane is not refused -- it "
                       f"silently matches nothing and drops this capability out of every grant. "
                       f"A typo in a lane should be an error, not a capability that quietly "
                       f"stops being grantable.")
    return out



def r31_callability_is_declared(reg, doc):
    """An entry must say whether it can be called, and `not_callable` must carry a reason.

    Measured 2026-10-03: `not_callable` appears ZERO times outside the manifest. Six entries
    declared it and nothing read it, so it was prose in a field shaped like a contract -- the same
    species as `gate_must_not_delegate` before today, and it survived a whole day of fixing that
    one. Meanwhile FIVE entries declared NEITHER `invoke` nor `not_callable`: three because they
    are absent or blocked, and two that are `state: observed`.

    The two observed ones are the finding. `ops.skill.security` is observed, has no invoke, has no
    not_callable, and its probe emits a box-drawn TEXT report with zero JSON bytes -- so there is
    no machine value for a caller to receive at all. A planner reading only the two callability
    keys could not tell it apart from a capability that is callable through a driver nobody wrote.
    `dynamic.win.frida` argues its own non-callability at length in a `composition_note` and then
    leaves the machine-readable marker absent, which is the whole disease in one entry.

    So: `state: observed` must declare EXACTLY ONE of the two. Zero means the registry is silent
    about whether a granted capability can be driven at all; both means it contradicts itself.
    Today's tree has zero entries declaring both, so forbidding it costs nothing. And
    `not_callable.reason` must be a non-empty string, because a presence-only check is satisfied
    by `{}` and this file exists because presence is not the question.

    Why `observed` and not every state: an absent capability has no entry point to declare, and
    forcing one would be forcing a sentence nobody can honestly write. All five now carry a
    `not_callable` anyway -- three of them because the reason was true and unwritten.
    """
    out = []
    for c in reg:
        if c.get("state") != "observed":
            continue
        cid = c.get("id", "?")
        inv = c.get("invoke")
        nc = c.get("not_callable")
        if inv is not None and nc is not None:
            out.append(f"R31 {cid}: declares BOTH an invoke and a not_callable. An invoke makes "
                       f"the capability callable and a not_callable says it is not; a reader "
                       f"cannot honour both. Zero entries do this today, so nothing depends on "
                       f"the combination being tolerated.")
        elif inv is None and nc is None:
            out.append(f"R31 {cid}: state=observed but declares NEITHER an invoke NOR a "
                       f"not_callable, so the registry does not say whether a capability the gate "
                       f"will happily grant can actually be driven. Declare one. If the answer is "
                       f"that it cannot, say why in not_callable.reason -- a planner cannot infer "
                       f"that from the absence of a field.")
        if nc is not None and not str(nc.get("reason") or "").strip():
            out.append(f"R31 {cid}: not_callable carries no reason. A presence-only check would be "
                       f"satisfied by {{}}, and this field exists because presence is not the "
                       f"question: WHY it cannot be called is the content.")
    return out



def r32_owner_decision_agrees_with_grantability(reg, doc):
    """`gate.owner_decision_required` and `gate.requires_verdict` must tell the same story.

    Measured 2026-10-03 by mutation: `gate.owner_decision_required` appears ZERO times outside the
    manifest. Three entries declare it true, and they are -- measured -- the ONLY three in the
    registry with `requires_verdict: false`:

        crypto.jose.parse / re.corpus.solve / fuzz.differential.parse

    So the restriction those three carry is enforced, but by a DIFFERENT mechanism than the one
    the manifest names. `requires_verdict: false` is what keeps them out of every grant
    (gate.ps1 Get-GrantableIds filters on it, and Check refuses a capability that is not on the
    list). `owner_decision_required: true` is the sentence that says WHY, and it is read by nothing
    at all. The registry's own schema note even records the intent -- "It is recorded as an OWNER
    DECISION on the three capabilities carrying it" -- in prose that no code consults.

    The dangerous state is the one this rule refuses: somebody edits `requires_verdict` to true on
    one of the three, because it looks like an ordinary flag flip. The capability becomes grantable
    to anything, and the field that records the Owner's decision is still `true` and still dead, so
    nothing in the tree objects. That is the shape of every finding in this file -- a restriction
    that lives in one field while another field silently governs it.

    Both directions are checked, because both are silent today:
      * owner_decision_required true with requires_verdict true  -> contradicts itself
      * requires_verdict false with no recorded reason            -> ungrantable for no stated cause

    `requires_verdict: false` is NOT treated as a defect here and never will be. It is a safety
    marker; this rule only insists that whatever removes a capability from every grant says out
    loud that it is doing so, and that the two fields which describe that state agree.
    """
    out = []
    for c in reg:
        g = c.get("gate") or {}
        if not isinstance(g, dict):
            continue
        cid = c.get("id", "?")
        odr = g.get("owner_decision_required")
        rv = g.get("requires_verdict")
        if odr is True and rv is not False:
            out.append(f"R32 {cid}: gate.owner_decision_required is true but "
                       f"gate.requires_verdict is {rv!r}. Those two fields are the same statement -- "
                       f"only the Owner may authorise this -- and they disagree. Today the "
                       f"restriction is enforced by requires_verdict alone, because "
                       f"owner_decision_required is read by nothing in this repository (measured: "
                       f"zero occurrences outside the manifest). Flip requires_verdict for an "
                       f"ordinary reason and this capability becomes grantable to anything while "
                       f"the field recording the Owner's decision still reads true.")
        if rv is False and not str(g.get("requires_verdict_reason") or "").strip():
            out.append(f"R32 {cid}: gate.requires_verdict is false with no reason. That flag is "
                       f"the only thing keeping this capability out of every grant, and a silent "
                       f"refusal cannot be reviewed, inherited or deliberately lifted by whoever "
                       f"inherits this registry. Record why.")
    return out



def r33_envelope_error_field_is_an_error(reg, doc):
    """`envelope.item_error_field` must name an error, not the success sentinel.

    Measured 2026-10-03: the field is read by nothing (a sweep set it to `-1` on every entry
    that has it and the validator stayed clean), and one entry had it wrong in a way that would
    invert a consumer. `native.ghidra.decompile` declared `item_error_field: "ok"` while its own
    `success_when` -- three lines above, in the same object -- reads "summary.json EXISTS and its
    `ok` is true -- NEVER the process exit code". So the entry named the field that means SUCCESS
    as the field that means ERROR, and a batch consumer keying on it would read a good result as a
    failed item. The other three entries name `error`.

    The closed part is small on purpose: a name, not a type. The anti-contradiction part is the
    load-bearing one and it is textual on purpose -- `ok`, `success`, `status: 0` and `exit_code`
    are the names a success sentinel actually takes, and this entry used one of them. A consumer
    asking "which field carries a per-item error" deserves an answer that cannot be the field the
    same object calls its success condition.

    What this does NOT do: validate that `error` exists in the output. That is a property of the
    TOOL, not of the manifest, and the honest place to check it is a probe -- which is what
    `probe.expect` is for.
    """
    SUCCESS_SENTINELS = ("ok", "success", "status", "exit", "exit_code", "exitcode", "result")
    out = []
    for c in reg:
        env = c.get("envelope") or c.get("invoke", {}).get("envelope") or {}
        if not isinstance(env, dict):
            continue
        fld = env.get("item_error_field")
        if fld is None:
            continue
        cid = c.get("id", "?")
        if str(fld).strip().lower() in SUCCESS_SENTINELS:
            sw = str(env.get("success_when") or "")
            out.append(f"R33 {cid}: envelope.item_error_field is {fld!r}, which is a SUCCESS "
                       f"sentinel name, not an error field"
                       + (f" -- and this entry's own success_when reads {sw[:70]!r}, so the same "
                          f"object names one field as both." if sw else ".")
                       + f" A consumer keying on this field would read a good item as a failed "
                         f"one. Name the field that actually carries the error (`error` on all "
                         f"three sibling entries) and record why here.")
    return out



def r34_no_absolute_paths_outside_the_repo(reg, doc):
    """A recorded command may not name an absolute path outside the repository it lives in.

    Measured 2026-10-03 by an independent audit of re-runnability, and the finding is worse than
    "a clone cannot run this". Two instruments hardcoded the ORIGINAL station's absolute tool
    path -- `native-lab/tools/capa_probe.py` and `native-lab/tools/hardening_probe.py` -- so a
    clone at any other path did not fail: it found the binary on the machine the path named and
    measured with it, reporting PASS. A passing number about a machine the reader is not on is
    the most expensive kind of wrong, because nothing anywhere looks wrong.

    Eleven registry commands had the same shape: eight `probe.prepare` fields that were the
    literal string `cd '<repo>'`, and three absolute paths inside
    frida probe commands. All are now relative to the script that runs them.

    What this refuses is the SHAPE, not the string: an absolute Windows path that does not begin
    with this repository's own root. That is deliberately narrow. `%TEMP%` and `%USERPROFILE%`
    are absolute and are CORRECT in several places -- a probe that stages a fixture outside the
    repo on purpose is doing the right thing, and a rule that refused those would be a rule that
    had to be argued with rather than obeyed. A path under the repo is equally fine and is what
    every portable form resolves to.

    Why the registry rather than the tools: a tool that hardcodes a path is invisible to a reader
    of the manifest, and the manifest is the document that claims what runs. The two probes that
    did it are fixed in their own files; this rule stops the next one from being written.
    """
    root = str(REPO_ROOT).replace("/", "\\").lower()
    out = []
    for c in reg:
        cid = c.get("id", "?")
        for field, holder in (("probe.command", (c.get("probe") or {})),
                              ("probe.prepare", (c.get("probe") or {})),
                              ("negative_control.command", (c.get("negative_control") or {}))):
            cmd = holder.get(field.split(".")[-1])
            if not isinstance(cmd, str):
                continue
            for m in re.finditer(r"[A-Za-z]:\\(?:[^\"'\s;|]+)", cmd):
                found = m.group(0)
                if not found.lower().startswith(root):
                    out.append(f"R34 {cid}: {field} names the absolute path {found!r}, which is "
                               f"not under this repository ({REPO_ROOT}). Measured 2026-10-03: two "
                               f"probes that did exactly this reported PASS from a clone while "
                               f"measuring the ORIGINAL machine's binaries -- a green verdict about "
                               f"a tool the reader is not running. Write it relative to the script "
                               f"that runs it (Join-Path (Split-Path -Parent $PSScriptRoot) ...), or "
                               f"as %TEMP% / %USERPROFILE% if the file genuinely lives outside the "
                               f"repository.")
    return out


RULES = (r1_not_empty, r_shape, r2_observed_needs_probe, r3_honesty_pair,
         r4_fact_types_agree, r5_control_must_fail, r6_reach_needs_escalation, r7_ids,
         r8_reach_must_be_declared, r9_batch_must_account, r10_invoke_must_runnable,
         r11_edge_target_exists, r12_edge_is_reachable, r13_question_types_declared,
         r14_no_island_capability, r15_artifacts_are_bound, r16_placeholders_resolve,
         r17_state_is_evidenced, r18_evidence_family_agrees, r19_probes_distinguish,
         r20_fact_map_declares, r21_control_command_runnable,
         r22_ungrantable_needs_a_reason, r23_escalation_class_needs_a_reason,
         r24_input_types_are_declared, r25_plan_needs_a_checkable_ref,
         r36_probe_command_is_runnable, r37_skip_dict_agrees_with_state,
         r35_control_buckets_reconcile,
         r26_bare_braces_survive_the_shell,
         r27_probe_exit_has_one_spelling,
         r28_evidence_is_tracked_not_merely_present,
         r29_fact_types_are_declared,
         r30_requires_and_lane_are_declared,
         r31_callability_is_declared,
         r32_owner_decision_agrees_with_grantability,
         r33_envelope_error_field_is_an_error,
         r34_no_absolute_paths_outside_the_repo)


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
        # FIXTURE, 2026-10-03: this said "exit". R27 refuses that spelling -- nothing in the
        # harness reads it -- so a baseline written with it is no longer a legal registry and
        # 17 cases failed for that reason alone. The right response to a new rule invalidating
        # the fixture is to fix the fixture, never to relax the rule: every one of those 17 was
        # reporting "your baseline is broken", not "your case is wrong".
        # FIXTURE, 2026-10-03: R31 (added today) requires a `state: observed` entry to declare
        # EXACTLY ONE of invoke / not_callable, and this baseline declared neither -- so 19 cases
        # failed at once, every one of them reporting "your fixture is not a legal registry". Same
        # response as when R27 invalidated the baseline: fix the fixture, never the rule.
        "not_callable": {"reason": "the fixture entry has no invoke on purpose: a baseline that "
                                   "carried one would be routed by R10 and R16 as well."},
        "probe": {"command": "python scripts/example_selftest_probe.py", "expect": "ok",
                  "expect_exit": 0,
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
            # R24 reads this vocabulary. Without it in the envelope every case below would
            # redden on R24 instead of on the rule it is testing -- the fixture must be a
            # legal registry, and a registry without the vocabulary R24 checks against is
            # not one.
            "input_types": {"path_ref": "a path to a file the caller supplies",
                            "string": "a text literal",
                            "structure": "a typed record the caller builds"},
            # R30 reads these two. Without them in the envelope every case below would either
            # redden on "schema.net_requirements is absent" instead of on the rule it is testing,
            # or -- worse -- pass vacuously, because a rule that finds no vocabulary and skips is
            # a rule that never runs.
            "net_requirements": {"none": "runs with no network access",
                                 "any": "cannot run without network access"},
            "lanes": {"debug": "locally authored target", "bounty": "in-scope third-party asset"},
        },
        "capabilities": caps,
        # R24 reads the FACT vocabulary at the document root, where the real registry keeps
        # it. Declared here so the "a fact type is not an input type" half has something to
        # compare against; without it that half is inert in every selftest case.
        # The four members R29's negative case needs, added 2026-10-03 for the same reason as the
        # real vocabulary grew them: a fixture whose vocabulary cannot express what the instruments
        # emit will redden on the fixture rather than on the rule under test.
        "fact_types": {"string": "a text literal recovered from the target",
                       "structure": "a typed record",
                       "structure[]": "an ordered list of records",
                       "path_ref": "a filesystem path to an artifact",
                       "boolean": "true or false",
                       "number": "a scalar measurement",
                       "rva": "an offset from the image base"},
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
        # Adding an invoke makes the entry CALLABLE, so a fixture carrying both would be refused
        # by R31 (added 2026-10-03) for a reason that has nothing to do with the rule under test.
        # Two rules colliding over one field is a real cost of adding a rule, and the fix is to
        # make the helper honest rather than to weaken R31.
        b[0].pop("not_callable", None)
        inv.setdefault("argv", ["probe_of_this_entry"])
        inv.setdefault("runner", "python")
        inv.setdefault("success_when", "exit 0 and stdout parses as JSON")
        inv["fact_map"] = mapping
    case("R20 fact_map forwards to an undeclared fact",
         lambda b: _with_fact_map(b, {"probe_out": "never.declared.by.this.entry"}), "R20")
    nocase("R20 a fact_map naming declared facts is accepted",
           lambda b: _with_fact_map(
               b, {"probe_out": b[0]["produces"]["facts"][0]["key"]}), "R20")
    # R31 cases. The positive that matters is BOTH-keys: a reader cannot honour "callable" and
    # "not callable" at once, and today nothing notices. The fixture had to give up its
    # not_callable for this one, which is the collision two rules can have over one field.
    # R32: two fields that are the same statement, one of which is enforced and one of which is
    # documentation. The dangerous mutation is flipping `requires_verdict` to true, which is what an
    # ordinary flag edit looks like; the second branch is the silent one.
    # R33: the anti-contradiction half, planted on an entry whose own success_when mentions `ok`.
    # R34: the shape that made two probes report PASS from a clone while measuring the ORIGINAL
    # machine's binaries. The negative case is the one that keeps the rule from being a nuisance:
    # %TEMP% and %USERPROFILE% are absolute too, and a probe that stages a fixture outside the
    # repository on purpose is doing the right thing.
    case("R34 a command naming another machine's absolute path",
         lambda b: b[0]["probe"].__setitem__(
             "command", "& 'D:\\Some\\Other\\Machine\\tool.exe' --version"), "R34")
    case("R34 a control naming another machine's absolute path",
         lambda b: b[0]["negative_control"].__setitem__(
             "command", "python D:\\elsewhere\\x.py"), "R34")
    nocase("R34 a command using %TEMP% is accepted",
           lambda b: b[0]["probe"].__setitem__(
               "command", "python scripts/x.py --out $env:TEMP\\out.json"), "R34")
    nocase("R34 a repo-relative command is accepted",
           lambda b: b[0]["probe"].__setitem__(
               "command", "python native-lab\\tools\\disasm.py x.exe"), "R34")
    case("R33 an envelope naming a success sentinel as its error field",
         lambda b: b[0].__setitem__(
             "envelope", {"success_when": "body.ok is true", "item_error_field": "ok"}), "R33")
    nocase("R33 an envelope naming a real error field is accepted",
           lambda b: b[0].__setitem__(
               "envelope", {"success_when": "body.ok is true", "item_error_field": "error"}),
           "R33")
    case("R32 an owner-decision entry that became grantable",
         lambda b: b[0]["gate"].update({"owner_decision_required": True,
                                         "requires_verdict": True}), "R32")
    case("R32 an ungrantable entry with no stated reason",
         lambda b: b[0]["gate"].update({"requires_verdict": False,
                                         "requires_verdict_reason": ""}), "R32")
    nocase("R32 an owner-decision entry that stays ungrantable is accepted",
           lambda b: b[0]["gate"].update({"owner_decision_required": True,
                                          "requires_verdict": False,
                                          "requires_verdict_reason": "only the Owner may authorise it"}),
           "R32")
    case("R31 an observed entry declaring neither",
         lambda b: b[0].pop("not_callable"), "R31")
    case("R31 an observed entry declaring both",
         lambda b: b[0].__setitem__("invoke", {"runner": "python", "argv": ["scripts/x.py"]}),
         "R31")
    case("R31 a not_callable with no reason",
         lambda b: b[0]["not_callable"].__setitem__("reason", ""), "R31")
    nocase("R31 an ABSENT entry needs neither",
           lambda b: b[0].update(state="absent", proves=[]) or b[0].pop("not_callable"), "R31")
    # R21: the control side, which had no equivalent of R2. A control that is prose cannot
    # fail, so it passes forever -- 13 of 24 entries were in that state.
    case("R21 a prose negative control",
         lambda b: b[0]["negative_control"].__setitem__(
             "command", "point the wrapper at a .txt file"), "R21")
    nocase("R21 a runnable negative control is accepted",
           lambda b: b[0]["negative_control"].__setitem__(
               "command", "python control.py --refuse"), "R21")
    # `plan_ref` rides along because R25 (2026-10-03) narrowed what "accepted" means for a plan:
    # a reason plus a checkable reference. Without it this case went red on R25 -- correctly,
    # since the mutation really does leave a plan nobody can check.
    nocase("R21 a declared plan with a reason and a checkable reference is accepted",
           lambda b: b[0]["negative_control"].update(
               {"kind": "plan", "plan_reason": "needs an MCP session",
                "plan_ref": "undecidable:the MCP device is not on this host's PATH"})
           or b[0]["negative_control"].pop("command"), "R21")
    case("R21 a plan with NO reason is refused",
         lambda b: b[0]["negative_control"].update({"kind": "plan", "plan_reason": ""})
         or b[0]["negative_control"].__setitem__("command", "just do the wrong thing"), "R21")
    # R22: an exclusion that is not explained reads as an oversight. It does NOT ask whether
    # the flag should be true -- that is an Owner decision -- only that the exclusion is deliberate.
    case("R22 ungrantable with no recorded reason",
         lambda b: b[0]["gate"].update({"requires_verdict": False}), "R22")
    nocase("R22 ungrantable WITH a reason is accepted",
           lambda b: b[0]["gate"].update({"requires_verdict": False,
                                             "requires_verdict_reason": "a grant does not authorise this"}), "R22")
    nocase("R22 a grantable capability needs no reason",
           lambda b: b[0]["gate"].update({"requires_verdict": True}), "R22")
    case("R23 an escalation class with no recorded reason",
         lambda b: b[0]["gate"].update({"escalation_class": "owner_word"}), "R23")
    case("R23 the reason under the WRONG key is still no reason",
         lambda b: b[0]["gate"].update({"escalation_class": "owner_word",
                                         "escalation_why": "needs a word"}), "R23")
    nocase("R23 an escalation class WITH a reason is accepted",
           lambda b: b[0]["gate"].update({"escalation_class": "owner_word",
                                           "escalation_reason": "needs a fresh Owner word"}), "R23")
    nocase("R23 a class of none needs no reason",
           lambda b: b[0]["gate"].update({"escalation_class": "none"}), "R23")
    # R24: the field had no vocabulary, so it had no wrong answer. Three real entries were
    # wrong and nothing said so.
    case("R24 an input typed with a FACT type",
         lambda b: b[0]["consumes"].update(
             {"inputs": [{"name": "capture", "type": "pcap", "required": True}]}), "R24")
    case("R24 an input with no type at all",
         lambda b: b[0]["consumes"].update(
             {"inputs": [{"name": "capture", "required": True}]}), "R24")
    # `reach.fs_read` comes along because R8's floor is "an input implies reading it", so a
    # legal fixture carrying an input must declare the read. The first attempt at this case
    # reddened on R8 instead of staying silent -- the fixture was illegal, not the rule wrong.
    nocase("R24 an input typed from the vocabulary is accepted",
           lambda b: b[0]["consumes"].update(
               {"inputs": [{"name": "capture", "type": "path_ref", "required": True}]})
           or b[0]["reach"].update({"fs_read": True}), "R24")

    # R25: a plan whose stated blocker was never pointed at. Written after an audit measured
    # that six of the ten real plan_reason strings are contradicted by the tree they sit in --
    # `mobile.apk.static` claiming no second AXML decoder while Apktool 3.0.3 sits on disk and
    # the lab already runs it. `missing:scripts/*.py` is the load-bearing case here: it is the
    # one that says "the thing your plan says is not there, IS there".
    def _plan(ref=None, reason="needs a thing that is not here"):
        def mutate(b):
            nc = b[0]["negative_control"]
            nc.update({"kind": "plan", "plan_reason": reason, "command": ""})
            nc.pop("plan_ref", None)
            if ref is not None:
                nc["plan_ref"] = ref
        return mutate
    case("R25 a plan with no machine-checkable reference", _plan(), "R25")
    case("R25 a file: reference that does not exist", _plan("scripts/no-such-file.ps1"), "R25")
    case("R25 a missing: reference that MATCHES something", _plan("missing:scripts/*.py"), "R25")
    case("R25 undecidable: with no reason", _plan("undecidable:"), "R25")
    case("R25 a reference in a form nobody defined", _plan("probably fine"), "R25")
    nocase("R25 a file: reference that resolves is accepted",
           _plan("file:scripts/registry-verify.py"), "R25")
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
    # R26: PowerShell reads a bare `{` in argument position as the start of a script block, so
    # the text can be perfectly runnable and still deliver something else to the child. The
    # negative case is the load-bearing half: the frida commands carry a whole JavaScript
    # payload full of braces inside single quotes and they work, so a rule that flagged quoted
    # spans would fire on working code and get switched off.
    case("R26 a bare brace in a control command",
         lambda b: b[0]["negative_control"].__setitem__(
             "command", "python solve.py --expect-flag FLAG{c01_string_table_xor}"), "R26")
    case("R26 a bare brace in a probe command",
         lambda b: b[0]["probe"].__setitem__(
             "command", "python probe.py --flag FLAG{abc}"), "R26")
    # R27: the mirror image of R23. Two spellings of one contract, a reader for one of them,
    # and sixteen entries using the unreadable one. The case has to fire on the FIELD, not on a
    # value, because every value in the registry is currently a correct 0 -- which is exactly why
    # nobody noticed.
    case("R27 the unreadable spelling probe.exit",
         lambda b: b[0]["probe"].__setitem__("exit", 0), "R27")
    case("R27 probe.exit with a deliberately wrong value",
         lambda b: b[0]["probe"].__setitem__("exit", 999), "R27")
    # R28: the file existing and hashing correctly is not the question -- git carrying it is.
    # The positive plants a REAL file with a REAL matching hash in %TEMP%, which is byte-for-byte
    # the state this registry was in on 2026-10-03 before the .gitignore exception existed.
    def _untracked_evidence(b):
        import tempfile, hashlib as _h
        d = pathlib.Path(tempfile.mkdtemp(prefix="r28-"))
        f = d / "fake.probe.log"
        f.write_text("# a real file nobody committed\n", encoding="utf-8")
        b[0]["probe"]["run_log"] = str(f)
        b[0]["probe"]["sha256"] = _h.sha256(f.read_bytes()).hexdigest()
    case("R28 a run_log git does not carry", _untracked_evidence, "R28")
    # The negative side must leave the registry CLEAN, not merely quiet about R28 -- so the hash
    # is READ from the file at selftest time rather than typed. Typing it would make this case
    # fail the moment the evidence is refreshed, and a case that rots teaches people to ignore it.
    def _tracked_evidence(b):
        import hashlib as _h
        rel = "evidence/probes/ops.skill.security.probe.log"
        b[0]["probe"]["run_log"] = rel
        b[0]["probe"]["sha256"] = _h.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()
    # R29: membership in the vocabulary. The negative case matters more than usual here, because
    # the vocabulary lives at the document ROOT (`fact_types`), not under `schema.*` -- so a rule
    # written to read `schema.fact_types` finds nothing and refuses every fact in the registry.
    # R30: two fields whose only live behaviour is a string comparison. `requires.net` is read by
    # `== "any"` and every other value is inert; `gate.lane` is read by equality in gate.ps1, so an
    # unrecognised lane silently removes a capability from every grant instead of being refused.
    case("R30 requires.net outside the vocabulary",
         lambda b: b[0]["requires"].__setitem__("net", "the-internet"), "R30")
    case("R30 gate.lane outside the vocabulary",
         lambda b: b[0]["gate"].__setitem__("lane", "atlantis"), "R30")
    # The obvious negative case -- "net: any" is legal" -- is NOT expressible, and that is a fact
    # worth keeping rather than working around: R6 requires an escalation class whenever net is
    # `any`, so `any` is legal only in company. What is worth pinning instead is the fail-closed
    # branch: a rule that cannot find its vocabulary must REFUSE, not skip, or it becomes a rule
    # that silently checks nothing on a registry that lost its schema.
    doc_case("R30 a registry with no net_requirements vocabulary is refused",
             lambda d: d["schema"].pop("net_requirements"), "R30")
    doc_case("R30 a registry with no lanes vocabulary is refused",
             lambda d: d["schema"].pop("lanes"), "R30")
    case("R29 a fact typed outside the vocabulary",
         lambda b: b[0]["produces"]["facts"][0].__setitem__("type", "banana"), "R29")
    nocase("R29 a fact typed from the vocabulary is accepted",
           lambda b: b[0]["produces"]["facts"][0].__setitem__("type", "structure[]"), "R29")
    nocase("R28 a tracked run_log is accepted", _tracked_evidence, "R28")
    nocase("R27 probe.expect_exit alone is accepted",
           lambda b: b[0]["probe"].__setitem__("expect_exit", 0), "R27")
    nocase("R26 braces inside a quoted span are accepted",
           lambda b: b[0]["negative_control"].__setitem__(
               "command", "frida.exe -e 'var m=Process.mainModule;console.log(`${m.base}`)'"),
           "R26")
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
    # R17, hardened 2026-10-03: the eleven real `run_log` values in this registry were all PROSE,
    # and a prose run_log was enough to make a capability grantable, because gate.ps1 filters on
    # `state == observed`. The file used below is this validator's own source, which exists by
    # construction -- so the "accepted" case cannot rot the way a fixture path would.
    case("R17 a run_log that is a sentence, not a file", lambda b: b[0]["probe"].update(
        {"run_log": "measured 2026-09-30 in that session, output pasted into the wiki"}), "R17")
    case("R17 a run_log naming a file that does not exist", lambda b: b[0]["probe"].update(
        {"run_log": "evidence/probes/nothing-was-ever-written-here.log"}), "R17")
    case("R17 a sha256 that does not match the file it names", lambda b: b[0]["probe"].update(
        {"run_log": "scripts/registry-verify.py", "sha256": "0" * 64}), "R17")
    case("R17 a sha256 with no run_log to hash", lambda b: b[0]["probe"].update(
        {"sha256": "a" * 64, "run_log": ""}), "R17")
    nocase("R17 a run_log naming a file that exists is accepted", lambda b: b[0]["probe"].update(
        {"run_log": "scripts/registry-verify.py"}), "R17")

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
    ap.add_argument("--count", action="store_true",
                    help="print the live rule total and nothing else. Exists because this file's "
                         "own header used to STATE its numbers in prose and a mutation sweep "
                         "measured them stale: an instrument describing itself is the one "
                         "description nothing checks.")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if a.count:
        numbered = sum(1 for r in RULES if r.__name__[1:2].isdigit())
        print(f"RULES {len(RULES)} entries, {numbered} numbered")
        return 0

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
            # This sentence was a FALSE CLAIM and an audit proved it: 14 of 26 entries had no
            # runnable negative_control.command at all -- they are kind:'plan' with a
            # control_plan, and two carry only an isolation_check whose own polarity field says
            # it is not a negative control. So "REGISTRY CLEAN" was asserting a control that
            # must fail for the majority of the registry. A summary line that overstates what
            # was checked is worse than no summary, because it is the one line everyone reads.
            # It now states the counts it actually verified, including the ones that are not
            # what they would ideally be.
            runnable = sum(1 for c in caps
                           if str(((c.get("negative_control") or {}).get("command")) or "").strip())
            planned = sum(1 for c in caps if (c.get("negative_control") or {}).get("kind") == "plan")
            print(f"REGISTRY CLEAN: no rule fired. Negative controls -- {runnable} runnable "
                  f"commands, {planned} declared PLANS (documented negative designs that cannot be "
                  f"executed). 'CLEAN' means no rule fired; it does NOT mean every capability has a "
                  f"working control.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
