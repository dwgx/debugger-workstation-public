#!/usr/bin/env python
"""Expose the arsenal's capabilities as MCP tools, so any MCP client can compose them.

WHY THIS EXISTS. The arsenal had 27 capabilities and no protocol surface. Everything an agent
needs to know in order to CALL one safely lived in a registry keyed by the arsenal's own vocabulary
-- `reach.fs_write`, `escalation_class`, `invoke.fact_map`, `gate.requires_verdict` -- which no
client outside this repository can read. So the arsenal was composable only by something that had
already learned its private dialect.

MCP is the protocol the ecosystem already speaks, and its `ToolAnnotations` shape maps onto fields
this registry has been tracking since before MCP existed:

    readOnlyHint     <- reach.fs_write == false and reach.db_write == false
    destructiveHint  <- gate.escalation_class != "none"
    idempotentHint   <- derived from reach: a read-only tool is safe to retry
    openWorldHint    <- reach.net == true

The MCP maintainers' own guidance (blog.modelcontextprotocol.io, 2026-03-16, "Tool Annotations as
Risk Vocabulary") is that annotations are HINTS, clients must treat them as untrusted, and: *"Hints
inform decisions; contracts enforce them. If a proposal's value depends on the annotation being
true, it's asking for a contract, and the right place for that is the authorization layer, the
transport, or the runtime rather than ToolAnnotations."*

**So this file emits hints and ENFORCES the gate.** As of 2026-10-03 every call carries a
`case_dir`, and `gate_check` runs `gate.ps1 -Action Check` on it before anything is executed:
no grant naming the capability, no call. That sentence used to read "Every call still goes
through the same gate invocation and the same refuse-on-wrong-subject logic as a mission" --
and grepping this file for `gate`, `grant` or `OwnerWord` found only that sentence and two like
it, because no such call existed. Sixteen invocable capabilities were reachable from any MCP
client, against any path on this machine, with no Owner word and no containment class, while
this header described the file as the surface that does not bypass the gate. That was a written
contract with no implementation behind it -- the same species as `requires.tools[].expect` and
`grant.escalation`, and the third time in this project. It is fixed by making the sentence true,
not by making the sentence better.

THE ACQUIRING CONTRACT, AND WHY `case_dir` ALONE WAS WRONG. The breaking change above fixed the
hole -- a call now carries a grant -- and in doing so made the surface unusable in practice. A
grant lives in a mission case directory under the missions root, and that root is a property of
the STATION, not of the client: it is `E:/missions` by default and `mission.ps1 -CaseRoot`
otherwise. So requiring every client to supply `case_dir` required every client to know
something the client cannot know, and a contract that cannot be satisfied by a correct client is
not a safety property, it is an outage. What a client can know is the MISSION's identifier.

So a tool takes `mission_id`, the server resolves it against the configured missions root
(`DEBUGGER_MISSIONS_ROOT`, default `E:/missions`), and the resolved directory is the
authorisation carrier. `case_dir` still works, and is validated by the same containment rules,
but the identifier is what a client should send.

Every step of that resolution REFUSES BY NAME. An identifier that is absolute, one that escapes
the root by traversal, one that does not exist, one that is not a directory, and one that is a
symlink or junction pointing out of the root are five different bugs in the client, and the
answer says which one it is and prints the absolute path the server was about to use. A single
"invalid case_dir" for all five teaches a caller nothing and is how a client ends up retrying a
path that was never going to work.

WHAT IT DELIBERATELY DOES NOT DO. It does not expose a capability whose `invoke` is absent, and
it does not accept a caller-supplied argv. Every tool takes exactly the capability's declared
inputs and runs the capability's own runner -- there is no path by which an MCP client can cause
an arbitrary command to run, which is the property that makes exposing read-oriented instruments
to a model safe at all. It also refuses a capability whose argv still carries a placeholder fed
by an upstream fact (`{input.function}`, `{input.outdir}`), because handing a subprocess a literal
`{...}` is not a call, it is a crash waiting for a client to trigger.

THE ACQUISITION CONTRACT, AND ITS HISTORY. `case_dir` became a REQUIRED parameter on all sixteen
tools on 2026-10-03. Any existing client stopped working until it passed one, which was the
correct direction -- the previous signature let a model run the arsenal with no authorisation at
all. It was also, measured the same day, unusable in practice, because the path it demands is
station state a client cannot be expected to hold. The parameter is now OPTIONAL and there are
two accepted forms, in this order of preference:

    mission_id   the mission's identifier. The server resolves it against the missions root and
                 derives case_dir. This is the form a client should use.
    case_dir     an explicit absolute path. Kept for back-compat, validated by the identical
                 containment rules, and refused -- by name -- when it leaves the root.

Supplying both is itself a refusal rather than a silent preference for one, because the
authorisation carrier is not a value to guess at: a caller that names two different missions has
a bug, and picking one for it would pick the wrong one half the time.

NEITHER FORM RELAXES THE TWO CONTROLS INSTALLED ON 2026-10-03. Resolution happens BEFORE the
gate, and the gate still runs before anything is executed; a capability that binds an unbound
`{input.*}` placeholder is still refused by name rather than handed to a subprocess as a literal.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# WHERE MISSION CASES LIVE. Station configuration, so it is read from the environment with a
# default rather than being a parameter: a caller-supplied missions root would let a client point
# the resolution at a directory it controls, which is the same hole as a caller-supplied
# registry, and gate.ps1 already refuses that shape on purpose (its G10 control).
MISSIONS_ROOT_ENV = "DEBUGGER_MISSIONS_ROOT"
DEFAULT_MISSIONS_ROOT = Path(r"E:\missions")     # mission.ps1 -CaseRoot default

# fact_types are a closed vocabulary in the registry; map each onto a JSON Schema type so the
# tool's outputSchema is real rather than decorative. An unrecognised type becomes a permissive
# object rather than being dropped, because a schema that silently omits a field teaches a client
# that the field does not exist.
TYPE_MAP = {
    "verdict": "string", "string": "string", "path_ref": "string",
    "structure": "object", "count": "integer", "binary": "string",
}
JSON_TYPES = {"string", "integer", "number", "boolean", "object", "array"}


def load() -> dict:
    return json.load(open(REG, encoding="utf-8"))


def annotations_for(c: dict) -> ToolAnnotations:
    """Derive the four hints from fields this registry already maintains."""
    reach = c.get("reach") or {}
    writes = bool(reach.get("fs_write")) or bool(reach.get("db_write"))
    network = bool(reach.get("net"))
    # destructiveHint is NOT escalation_class. The first version mapped
    # `escalation_class != "none"` to destructive, which made net.pcap.analyse report
    # destructive:true -- it spawns tshark and needs an owner word, but it destroys nothing.
    # MCP's hint means "if this modifies things, is the change destructive"; the arsenal's
    # escalation_class means "running this needs authorisation". Those are different questions,
    # and conflating them would tell a client to prompt for a routine read.
    #
    # Measured: of 16 invocable capabilities exactly TWO write at all --
    # native.ghidra.decompile (write_scope case_dir) and native.signature.certverify (temp_dir).
    # Only the latter writes outside the mission's own case directory, and that is what
    # destructiveHint is given here.
    destructive = str(reach.get("write_scope") or "") not in ("", "case_dir", "none")

    return ToolAnnotations(
        title=c.get("title") or c["id"],
        readOnlyHint=not writes,
        destructiveHint=destructive,
        # Idempotency is derived, not asserted. A tool that writes nothing and reaches nothing
        # outside the machine is safe to retry; anything that writes or escapes is not, and saying
        # otherwise would be exactly the kind of optimistic hint the maintainers warn about.
        idempotentHint=(not writes and not network),
        openWorldHint=network,
    )


def placeholders(c: dict) -> list[str]:
    """The parameter names an invoke can ACTUALLY bind, read out of its own argv.

    The first version built the tool signature from `consumes.inputs`. That was wrong and the
    MCP audit caught it by calling a tool: native.pe.hardening declares an input named `binary`,
    while its invoke binds `{target}`, so every call was refused with "does not take an input named
    binary". The registry's input vocabulary and the orchestrator's placeholder vocabulary are not
    the same thing, and only one of them is what the runner can substitute.

    So the signature is derived from the argv itself. That makes it impossible for a client to be
    offered a parameter the invoke cannot fill -- the shape and the capability cannot drift apart,
    because the shape IS the capability's own argv.
    """
    inv = c.get("invoke") or {}
    found: list[str] = []
    for tok in re.findall(r"\{([a-z_][a-z0-9_]*)\}", " ".join(map(str, inv.get("argv") or []))):
        if tok not in found:
            found.append(tok)
    return found


def input_schema_for(c: dict) -> dict:
    names = placeholders(c)
    declared = {i["name"]: i for i in ((c.get("consumes") or {}).get("inputs") or [])}
    props: dict = {}
    required: list[str] = []
    for n in names:
        d = declared.get(n) or declared.get("target") or {}
        props[n] = {"type": "string", "description": (d.get("note") or n)[:300]}
        required.append(n)          # every placeholder the invoke binds must be supplied
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": False}


def output_schema_for(c: dict) -> dict:
    props: dict = {}
    for f in (c.get("produces") or {}).get("facts") or []:
        t = f.get("type")
        props[f["key"]] = {"type": TYPE_MAP.get(t, "object"),
                           "description": (f.get("note") or "")[:300]}
    return {"type": "object", "properties": props, "additionalProperties": True}


def missions_root() -> Path:
    """The one directory every mission case lives under. Not a parameter -- see the note on
    MISSIONS_ROOT_ENV for why a caller may not name it."""
    raw = os.environ.get(MISSIONS_ROOT_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_MISSIONS_ROOT


def _contained(child: Path, parent: Path) -> bool:
    """True when `child` is `parent` or lives under it, compared case-insensitively because the
    station is NTFS and `E:\\missions` and `e:\\missions` are the same directory to Windows but
    not to Path.relative_to's string comparison."""
    try:
        Path(os.path.normcase(str(child))).relative_to(Path(os.path.normcase(str(parent))))
        return True
    except ValueError:
        return False


def _refuse(check: str, error: str, root: Path, resolved: Path, **extra: Any) -> dict[str, Any]:
    """Every rejection from this file has this shape: the NAME of the check that failed, the
    absolute path the server was about to use, and the root it was measured against. A refusal
    that omits the resolved path leaves a caller guessing which of six inputs was wrong."""
    out = {"ok": False, "check_failed": check, "error": error,
           "resolved_case_dir": str(resolved), "missions_root": str(root)}
    out.update(extra)
    return out


def resolve_case(mission_id: str = "", case_dir: str = "") -> tuple[str, dict[str, Any] | None]:
    """Turn what the client sent into the case directory a grant can live in.

    Returns `(case_dir, None)` on success or `("", refusal)` on any of nine named refusals. The
    two forms are NOT merged before the checks: which form was used decides what the checks
    mean, so `E:\\missions\\c01` is a legal `mission_id` and an illegal `case_dir`-shaped one is
    a different caller's bug with a different fix.

    WHY THE ORDER IS WHAT IT IS. Lexical containment comes before existence, because the
    question "does this exist" has a different answer for `E:\\missions\\c01` than for
    `..\\..\\Windows` and reporting the wrong one sends a caller looking in the wrong place.
    Symlink resolution comes LAST and on its own check, because it is the only one that can
    disagree with the lexical answer: a directory that is textually inside the root and
    physically outside it is exactly the case a purely lexical check waves through.
    """
    root = missions_root()
    root_abs = Path(os.path.abspath(str(root)))
    mid = str(mission_id or "").strip()
    cdir = str(case_dir or "").strip()

    if mid and cdir:
        return "", _refuse(
            "both_acquisition_forms_given",
            f"both mission_id={mid!r} and case_dir={cdir!r} were given. The authorisation "
            f"carrier is not a value to guess at: send the mission identifier alone.",
            root, root_abs / mid, given={"mission_id": mid, "case_dir": cdir})
    if not mid and not cdir:
        return "", _refuse(
            "neither_acquisition_form_given",
            "no mission_id and no case_dir. A call carries authority through a mission case "
            f"directory under {root_abs}; pass mission_id=<the mission's identifier> "
            "(preferred) or case_dir=<an absolute path inside it>.",
            root, root_abs)

    if mid:
        raw, label = mid, "mission_id"
    else:
        raw, label = cdir, "case_dir"

    cand = Path(raw)
    is_abs = cand.is_absolute() or bool(cand.drive) or bool(cand.root)
    resolved = Path(os.path.abspath(str(cand if is_abs else root_abs / cand)))
    escapes = not _contained(resolved, root_abs)

    # ---- 1. shape: is this even the right KIND of string for its parameter?
    if label == "case_dir" and not is_abs:
        return "", _refuse(
            "case_dir_is_relative",
            f"case_dir={raw!r} is relative, so it would resolve against this process's working "
            f"directory ({os.getcwd()}) rather than the missions root. case_dir is for absolute "
            f"paths; if you meant a mission identifier, pass it as mission_id and it will be "
            f"resolved under {root_abs}.",
            root, resolved)
    if escapes and is_abs:
        return "", _refuse(
            "identifier_is_absolute" if label == "mission_id" else "case_dir_outside_root",
            f"{label}={raw!r} is an absolute path that leaves the missions root. "
            + (f"A mission identifier is a NAME inside {root_abs}, not a path -- if you mean "
               f"this case, send its identifier alone."
               if label == "mission_id" else
               f"A case_dir is only accepted when it names a directory inside {root_abs}."),
            root, resolved)
    if escapes and ".." in cand.parts:
        return "", _refuse(
            "identifier_traversal" if label == "mission_id" else "case_dir_traversal",
            f"{label}={raw!r} walks out of the missions root with '..'. It resolves to "
            f"{resolved}, which is not under {root_abs}.",
            root, resolved)
    if escapes:
        return "", _refuse(
            "identifier_escapes_root" if label == "mission_id" else "case_dir_escapes_root",
            f"{label}={raw!r} resolves to {resolved}, which is not under the missions root "
            f"{root_abs}.",
            root, resolved)

    # ---- 2. existence. Resolved and absolute now, so the message can name the real path.
    if not resolved.exists():
        return "", _refuse(
            "case_does_not_exist" if label == "mission_id" else "case_dir_does_not_exist",
            f"{label}={raw!r} resolves to {resolved}, which does not exist. Nothing at that "
            f"path is a mission case, so there is no grant to check.",
            root, resolved)
    if not resolved.is_dir():
        return "", _refuse(
            "case_is_not_a_directory" if label == "mission_id" else "case_dir_is_not_a_directory",
            f"{label}={raw!r} resolves to {resolved}, which is a file, not a case directory. "
            f"A grant lives in a directory.",
            root, resolved)

    # ---- 3. the physical check. Lexical containment above cannot see a junction.
    real_root = Path(os.path.abspath(str(Path(os.path.normcase(str(root_abs))).resolve())))
    real_case = Path(os.path.abspath(str(resolved.resolve())))
    if not _contained(real_case, real_root):
        return "", _refuse(
            "case_symlink_escapes_root" if label == "mission_id" else "case_dir_symlink_escapes_root",
            f"{label}={raw!r} is textually inside the missions root ({resolved}) but resolves "
            f"to {real_case}, which is outside {real_root}. That is a symlink or a directory "
            f"junction pointing out of the root, and it is refused even though the path passed "
            f"every textual check.",
            root, resolved, physical_case_dir=str(real_case),
            physical_missions_root=str(real_root))
    return str(resolved), None


def gate_check(case_dir: str, cid: str) -> tuple[bool, str]:
    """Ask the ONE component on this station that may say yes to authority.

    Measured 2026-10-03, and this function exists because a sentence in this file's own header
    was false. The header said "Every call still goes through the same gate invocation"; grepping
    the file for `gate`, `grant` or `OwnerWord` found only that sentence and two others like it.
    `run_capability` resolved the capability, substituted placeholders and called subprocess.run.
    So all 16 invocable capabilities were reachable from any MCP client, against any path on this
    machine, with no Owner word, no containment class and no grant -- while the file described
    itself as the surface that does not bypass the gate.

    The property the header claimed was right; the code was not. This is the third instance in
    this project of one species -- a written contract with no implementation behind it -- after
    `requires.tools[].expect` and `grant.escalation`. The fix is not a better sentence: it is a
    call to the authority, whose answer is an exit code.

    Deliberately a subprocess, not a re-implementation: this file must not grow its own idea of
    what a grant means. mission.ps1 already does exactly this (its Invoke-Gate), so the MCP
    surface and the mission loop now ask the same question of the same program.
    """
    if not case_dir or not str(case_dir).strip():
        # Defence in depth, and no longer reachable from the tool path: `run_capability` refuses
        # an absent acquisition form in `resolve_case` before this is called. It stays because
        # `gate_check` is the function whose entire job is to fail closed, and a fail-closed
        # branch that can be deleted is one that eventually is.
        return False, ("no case directory was resolved, so there is no grant to check. Every "
                       "call to this surface is authorised by a grant, and a grant lives in a "
                       "mission case directory. Pass mission_id=<the mission's identifier>.")
    gate = Path(__file__).resolve().parent / "gate.ps1"
    if not gate.exists():
        return False, f"gate.ps1 is missing at {gate}; refusing rather than running unauthorised"
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(gate),
           "-Action", "Check", "-CaseDir", str(case_dir), "-Capability", cid]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           stdin=subprocess.DEVNULL)
    except Exception as exc:                                    # noqa: BLE001
        return False, f"the gate could not be run ({exc}); refusing rather than assuming yes"
    if p.returncode == 0:
        return True, "gate.ps1 exit 0"
    detail = (p.stdout or "").strip()[:400]
    return False, (f"gate.ps1 refused this capability (exit {p.returncode}). "
                   f"A debugging-lane ALLOW is not a bounty-lane ALLOW and neither is a "
                   f"model's request. {detail}")


def run_capability(cid: str, mission_id: str = "", case_dir: str = "", **kwargs) -> dict[str, Any]:
    """The single execution path. No caller-supplied argv, by construction -- and no call
    without a grant that names the capability, by construction too.

    FOUR STAGES, AND THE ORDER IS THE SAFETY PROPERTY, NOT A STYLE CHOICE:
      1. structural  -- does the capability exist, and does it have an invoke block at all
      2. acquisition -- resolve mission_id / case_dir to a case directory inside the missions
                        root, or refuse by the name of the check that failed
      3. authority   -- gate.ps1 -Action Check against that directory
      4. binding     -- substitute placeholders, refuse any `{input.*}` this surface cannot fill
    Only then is a subprocess spawned. A refusal at any stage returns before stage 4 completes,
    which is what makes "no capability executes without a grant" a property of the code rather
    than an observation about today's clients."""
    reg = load()
    cap = next((x for x in reg["capabilities"] if x["id"] == cid), None)
    if cap is None:
        return {"ok": False, "error": f"no such capability: {cid}"}
    inv = cap.get("invoke")
    if not inv:
        return {"ok": False, "error": f"{cid} has no invoke block, so it cannot be called",
                "state": cap.get("state"),
                "note": "a capability with only a probe is not something an agent can invoke"}

    # Acquisition comes BEFORE the authority question, for the same reason the structural
    # refusals come first: a path that escapes the missions root cannot carry a grant, so
    # spending a gate invocation on it is a subprocess spawned to learn something the answer is
    # already known. And the refusal it returns is more specific than the gate's, because the
    # gate would answer "no grant.json in the case directory" about a directory that was never
    # going to have one -- the caller sent the wrong KIND of thing, and that is worth saying.
    resolved_case, refusal = resolve_case(mission_id, case_dir)
    if refusal is not None:
        return {**refusal, "capability": cid,
                "note": "nothing was executed and the gate was not consulted: a case directory "
                        "inside the missions root could not be resolved from what you sent."}

    # The authorisation check comes AFTER the cheap structural refusals and BEFORE anything is
    # executed. A capability nobody may run should not be able to spend a gate invocation, and a
    # capability that does not exist should not produce an authorisation question at all.
    ok, why = gate_check(resolved_case, cid)
    if not ok:
        return {"ok": False, "capability": cid, "error": f"{cid} refused by the gate: {why}",
                "gate": "scripts/gate.ps1 -Action Check",
                "resolved_case_dir": resolved_case, "missions_root": str(missions_root()),
                "check_failed": "gate_denied_capability",
                "note": "mint a grant first: gate.ps1 -Action New -Target <object> -OwnerWord "
                        "'<the Owner's sentence>' -Containment station_under_named_process_rule"}

    argv = list(inv["argv"])
    for k, v in kwargs.items():
        token = "{" + k + "}"
        if token not in argv:
            return {"ok": False,
                    "error": f"{cid} does not bind an input named {k}",
                    "binds": placeholders(cap)}
        argv = [str(v) if a == token else a for a in argv]

    # Fail closed on an UNBOUND placeholder. `placeholders()` matches `\{[a-z_][a-z0-9_]*\}`, so a
    # token like `{input.function}` does not match -- the dot is not in the class -- and it was
    # therefore invisible to the generated signature. The consequence, measured 2026-10-03:
    # calling native.disasm.capstone through this surface ran
    # `disasm.py <target> --hex {input.function} --count 48`, argparse rejected it, and the client
    # got a Python traceback. Four of the sixteen invocable capabilities bind such a token
    # (native.ida.decompile, native.disasm.capstone, native.ghidra.decompile, crypto.jose.parse).
    #
    # Handing a subprocess a literal `{...}` is never right, and a tool that looks callable and
    # is not is the exact failure this project keeps finding. So an unbound placeholder is a
    # refusal that names the missing binding, not a process that guesses.
    leftover = sorted({t for a in argv for t in re.findall(r"\{[^}]+\}", str(a))})
    if leftover:
        return {"ok": False,
                "error": f"{cid} binds {leftover} from a fact this surface cannot supply",
                "consumes_fact": inv.get("consumes_fact"),
                "binds": placeholders(cap),
                "note": "a placeholder fed by an upstream fact belongs to a mission, not to a "
                        "model. Either run it as a mission round, or expose the value the runner "
                        "needs as an argument this tool does not currently take."}

    runner = inv.get("runner", "python")
    exe = {"python": sys.executable, "powershell": "powershell",
           "node": "node"}.get(runner, runner)
    cmd = [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"] if runner == "powershell" \
        else [exe]
    cmd += argv
    # stdin=DEVNULL IS LOAD-BEARING, and the reason is a hang this project has already paid for
    # once with a different tool. The server process owns the JSON-RPC pipe on its stdin. A child
    # spawned with capture_output still INHERITS stdin, so anything the child reads -- or any tool
    # that decides to prompt -- blocks forever waiting on a pipe it must never touch. Measured:
    # with stdin inherited, a real tools/call hung past 600 s and the audit died on a timeout
    # rather than on a result. The child gets its own null stdin and can never see the protocol.
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=900,
                       stdin=subprocess.DEVNULL)
    out = (p.stdout or "") + (p.stderr or "")
    try:
        return json.loads(p.stdout)
    except Exception:
        return {"ok": False, "exit": p.returncode, "raw": out[:2000],
                "note": "the runner did not produce pure JSON on stdout, so its result is returned "
                        "verbatim rather than paraphrased into a shape it did not claim"}


def build() -> FastMCP:
    reg = load()
    srv = FastMCP("arsenal")

    def register(c: dict):
        cid = c["id"]
        meta = [cap for cap in reg["capabilities"] if cap["id"] == cid][0]

        # A REAL SIGNATURE, GENERATED, NOT **kwargs. FastMCP builds a pydantic arguments model
        # from the function signature, and `**kwargs` becomes a field literally named `kwargs` --
        # measured: a real call failed with "1 validation error ... kwargs Field required". The
        # parameter list is therefore generated from the invoke's own placeholders, so the model
        # the client sees IS the set of things the runner can substitute.
        params = placeholders(c)
        # Neither acquisition parameter is one of the registry's placeholders: they carry
        # AUTHORITY, not data, and they are generated here rather than declared by the registry
        # because no capability knows anything about where this station keeps its cases.
        #
        # BOTH ARE OPTIONAL in the signature, and that is not a weakening. The pair is what is
        # required: `resolve_case` refuses a call carrying neither, and refuses one carrying
        # both, so exactly one authorisation carrier must reach it. Making them optional is what
        # lets a client that knows only a mission identifier use this surface at all -- which is
        # the point of the change. FastMCP turns a default of `''` into an optional field with a
        # default, so a client that omits both sends none and is refused by name.
        #
        # ORDER MATTERS FOR PYTHON, not for JSON: a non-default parameter cannot follow a
        # defaulted one, so the capability's own placeholders lead and the two defaulted
        # acquisition parameters trail. JSON object members are unordered, so the client is
        # unaffected by the sequence.
        # The `if lead else ""` is load-bearing, not tidiness. `", ".join([])` is the empty
        # string, so a capability whose argv binds NOTHING at all produced
        # `def handler(, mission_id: str = '', ...)` and `build()` raised SyntaxError at import
        # time -- the whole surface, every tool, dead, over one capability's empty parameter
        # list. Joining into a local and concatenating THAT leaves no phantom parameter behind,
        # which matters twice over: FastMCP rejects any parameter whose name starts with '_'
        # (InvalidSignature), and a sentinel argument would be a parameter a caller can fill.
        lead = ", ".join(f"{n}: str" for n in params)
        sig = (lead + ", " if lead else "") + "mission_id: str = '', case_dir: str = ''"
        # keyword arguments, not dict entries: run_capability(cid, target=target) --
        # "target": target inside a call is a SyntaxError, found by running it.
        kwarg = ", ".join(f"{n}={n}" for n in params)
        ns: dict[str, Any] = {"run_capability": run_capability, "cid": cid, "Any": Any}
        exec(f"def handler({sig}) -> dict[str, Any]:\n"
             f"    return run_capability(cid, mission_id=mission_id, case_dir=case_dir, {kwarg})\n",
             ns)   # noqa: S102
        handler = ns["handler"]

        handler.__doc__ = (f"{c.get('title','')}\n\n{c.get('composition_note','')[:1200]}\n\n"
                           f"AUTHORITY. PREFERRED FORM: pass `mission_id` -- the mission's "
                           f"identifier. This server resolves it under the missions root "
                           f"({MISSIONS_ROOT_ENV}, default {DEFAULT_MISSIONS_ROOT}) and derives the "
                           f"case directory itself, so a client needs no knowledge of this "
                           f"station's layout. `case_dir` is also accepted, for back-compat, and "
                           f"is validated by the identical containment rules; send exactly one of "
                           f"the two. Every refusal names the check that failed and prints the "
                           f"absolute path the server was about to use. The gate is consulted "
                           f"before anything executes, and nothing runs without a grant naming "
                           f"this capability.\n\n"
                           f"DOES NOT PROVE: " + " | ".join(
                               d[:220] for d in (meta.get("does_not_prove") or [])[:4]))
        srv.add_tool(handler, name=cid, title=c.get("title"),
                     description=handler.__doc__,
                     annotations=annotations_for(c),
                     structured_output=bool((c.get("produces") or {}).get("facts")))

    for c in reg["capabilities"]:
        if c.get("invoke") and c["state"] == "observed":
            register(c)
    return srv


if __name__ == "__main__":
    build().run(transport="stdio")