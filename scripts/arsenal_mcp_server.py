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

WHAT IT DELIBERATELY DOES NOT DO. It does not expose a capability whose `invoke` is absent, and
it does not accept a caller-supplied argv. Every tool takes exactly the capability's declared
inputs and runs the capability's own runner -- there is no path by which an MCP client can cause
an arbitrary command to run, which is the property that makes exposing read-oriented instruments
to a model safe at all. It also refuses a capability whose argv still carries a placeholder fed
by an upstream fact (`{input.function}`, `{input.outdir}`), because handing a subprocess a literal
`{...}` is not a call, it is a crash waiting for a client to trigger.

THE BREAKING CHANGE. `case_dir` is now a REQUIRED parameter on all sixteen tools. Any existing
client stops working until it passes one, which is the correct direction: the previous signature
let a model run the arsenal with no authorisation at all.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

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
        return False, ("no case_dir was given, so there is no grant to check. Every call to this "
                       "surface is authorised by a grant, and a grant lives in a mission case "
                       "directory. Pass case_dir=<the mission's case dir>.")
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


def run_capability(cid: str, case_dir: str = "", **kwargs) -> dict[str, Any]:
    """The single execution path. No caller-supplied argv, by construction -- and no call
    without a grant that names the capability, by construction too."""
    reg = load()
    cap = next((x for x in reg["capabilities"] if x["id"] == cid), None)
    if cap is None:
        return {"ok": False, "error": f"no such capability: {cid}"}
    inv = cap.get("invoke")
    if not inv:
        return {"ok": False, "error": f"{cid} has no invoke block, so it cannot be called",
                "state": cap.get("state"),
                "note": "a capability with only a probe is not something an agent can invoke"}

    # The authorisation check comes AFTER the cheap structural refusals and BEFORE anything is
    # executed. A capability nobody may run should not be able to spend a gate invocation, and a
    # capability that does not exist should not produce an authorisation question at all.
    ok, why = gate_check(case_dir, cid)
    if not ok:
        return {"ok": False, "error": f"{cid} refused by the gate: {why}",
                "gate": "scripts/gate.ps1 -Action Check",
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
        # `case_dir` is NOT one of the registry's placeholders: it is the authorisation carrier,
        # and it is required on every tool because a capability that cannot be authorised must
        # not be callable. It is a breaking change for any existing client, which is the point --
        # the previous signature let a model run 16 capabilities with no Owner word at all.
        sig = "case_dir: str, " + ", ".join(f"{n}: str" for n in params)
        # keyword arguments, not dict entries: run_capability(cid, target=target) --
        # "target": target inside a call is a SyntaxError, found by running it.
        kwarg = ", ".join(f"{n}={n}" for n in params)
        ns: dict[str, Any] = {"run_capability": run_capability, "cid": cid, "Any": Any}
        exec(f"def handler({sig}) -> dict[str, Any]:\n"
             f"    return run_capability(cid, case_dir=case_dir, {kwarg})\n", ns)   # noqa: S102
        handler = ns["handler"]

        handler.__doc__ = (f"{c.get('title','')}\n\n{c.get('composition_note','')[:1200]}\n\n"
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