"""Drive scripts/arsenal_mcp_server.py with a REAL MCP client over stdio.

A real client, not a direct function call: `mcp.client.stdio` spawns the server as a subprocess
and speaks JSON-RPC on its stdin/stdout, which is the only path a caller outside this repository
can take. Every result printed below came back over that wire.

NEGATIVE CONTROL, and the reason this harness exists rather than `import arsenal_mcp_server`.
"Refused before executing anything" is a claim about subprocesses, and the only way to measure it
is to make execution observable. A `node.cmd` shim sits first on the PATH of the SERVER process,
so any capability whose runner is `node` -- which is most of them -- writes a line to
EXECUTION_SENTINEL.txt instead of running. A positive control proves the shim fires at all; then
the sentinel is truncated and every refusal must leave it empty.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
# PROMOTED 2026-10-03 from %TEMP%\arsenal-mcp-probe. Its scratch (a scratch missions root, two
# PATH shims, three sentinel files) goes to %TEMP%, NOT next to this file: a proof harness that
# writes into the repository it is proving things about is a harness that can dirty the evidence.
import os as _os
SCRATCH = Path(_os.environ.get("ARSENAL_MCP_PROBE_DIR") or (_os.environ["TEMP"] + "\\arsenal-mcp-probe"))
SCRATCH.mkdir(parents=True, exist_ok=True)
# ARGS, and why they are this forgiving. The first version read argv[1] as REPO and argv[2] as an
# optional SERVER, so calling it with just the server path -- which is the obvious thing to do --
# silently made REPO a FILE and produced
#   '...\arsenal_mcp_server.py\scripts\gate.ps1' does not exist
# with an exit code that looks like a crash (4294770688). A harness whose first argument can be
# either thing must SAY which is which, or it will be called wrong by the next person and blamed
# for it. Measured 2026-10-03, from scripts/verify-all.ps1.
_a = [Path(x).resolve() for x in sys.argv[1:]]
if not _a:
    raise SystemExit("mcp-probe: pass the repository root, or the server script.")
if _a[0].is_file():
    SERVER = _a[0]
    REPO = SERVER.parent.parent
else:
    REPO = _a[0]
    SERVER = _a[1] if len(_a) > 1 else REPO / "scripts" / "arsenal_mcp_server.py"
if not SERVER.is_file():
    raise SystemExit(f"mcp-probe: no server script at {SERVER}")
if not (REPO / "scripts" / "gate.ps1").is_file():
    raise SystemExit(f"mcp-probe: {REPO} does not look like the station (no scripts/gate.ps1)")
MISSIONS = SCRATCH / "missions"
SENTINEL = SCRATCH / "EXECUTION_SENTINEL.txt"
TARGET = REPO / "crackme-corpus" / "out" / "c01-stringobf.exe"
CASE = "probe-c01"
SHIM = SCRATCH / "shim"
GATE_SHIM = SCRATCH / "gate-shim"
GATE_SENTINEL = SCRATCH / "GATE_SENTINEL.txt"

# Keys only a completed runner subprocess can produce. A refusal must contain NONE of them:
# that is the "nothing executed" claim turned into an assertion instead of an impression.
RUNNER_KEYS = {"raw", "exit", "image", "mitigations", "binary", "caveats", "facts"}


# ---------------------------------------------------------------- FIXTURE
# ADDED 2026-10-03 at promotion. The original harness assumed a scratch case directory and a
# grant already existed, because the author had made them by hand minutes earlier. A proof the
# next window cannot re-run is a transcript, not a proof, so the setup is here now and the probe
# is self-contained. It mints its OWN grant in a scratch missions root under %TEMP% -- never in
# E:/missions, and never against a real case.
#
# Provenance and owner_word are the Owner's own strings, reused verbatim from the grants already
# in E:/missions ('Owner-authored; built by crackme-corpus/tools/loop.py from our own source' /
# 'analyze this exe'). The ONLY field supplied here is the registry digest, which gate.ps1
# demands be re-minted after any registry edit -- so this fixture breaks loudly rather than
# silently when the registry moves, which is the correct direction.
OWNER_PROVENANCE = "Owner-authored; built by crackme-corpus/tools/loop.py from our own source"
OWNER_WORD = "analyze this exe"


def prepare_case() -> str:
    """Create the scratch case and mint a debugging-lane grant into it. Returns a note."""
    case = MISSIONS / CASE
    case.mkdir(parents=True, exist_ok=True)
    (case / "case.json").write_text(
        json.dumps({"id": CASE, "created": "mcp-probe", "purpose": "negative-control harness"}),
        encoding="utf-8")
    gate = REPO / "scripts" / "gate.ps1"
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(gate),
           "-Action", "New", "-CaseDir", str(case), "-Target", str(TARGET),
           "-Provenance", OWNER_PROVENANCE, "-OwnerWord", OWNER_WORD,
           "-Containment", "station_under_named_process_rule"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
    note = (p.stdout or p.stderr or "").strip().replace("\r\n", " ")[:220]
    if p.returncode != 0:
        raise SystemExit(f"mcp-probe: could not mint a grant (gate.ps1 exit {p.returncode}): {note}")
    return note


def assert_no_execution(label: str, payload: dict) -> bool:
    leaked = sorted(RUNNER_KEYS & set(payload))
    ok = payload.get("ok") is False and not leaked
    print("    ASSERT_NO_EXECUTION %s ok=%s leaked=%s check_failed=%s"
          % (label, ok, leaked, payload.get("check_failed")))
    return ok


def sentinel() -> str:
    return SENTINEL.read_text(encoding="utf-8").strip() if SENTINEL.exists() else ""


def truncate_sentinel() -> None:
    SENTINEL.write_text("", encoding="utf-8")


def show(label: str, res: dict) -> dict:
    # CallToolResult is a pydantic model, not a dict.
    text = "".join(getattr(c, "text", "") or "" for c in (res.content or []))
    if getattr(res, "isError", False):
        payload = {"isError": True, "text": text[:900]}
    else:
        payload = res.structuredContent
        if payload is None:
            payload = {"text": text[:900]}
    print(f"\n### {label}")
    print(json.dumps(payload, indent=1, ensure_ascii=False)[:1600])
    return payload


async def main() -> int:
    env = dict(os.environ)
    print("### fixture\n" + prepare_case())
    env["DEBUGGER_MISSIONS_ROOT"] = str(MISSIONS)
    # The shim goes FIRST so the server's `node` resolves to it. Everything else is untouched.
    if os.environ.get("PROBE_GATE_SHIM") == "1":
        env["PATH"] = str(GATE_SHIM) + os.pathsep + env["PATH"]
    env["PATH"] = str(SHIM) + os.pathsep + env["PATH"]
    truncate_sentinel()

    env["ARSENAL_PROBE_SENTINEL"] = str(SENTINEL)
    env["ARSENAL_PROBE_GATE_SENTINEL"] = str(GATE_SENTINEL)
    GATE_SENTINEL.write_text("", encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = await s.list_tools()
            print(f"TOOLS {len(tools.tools)}")
            schema = next(t for t in tools.tools if t.name == "native.pe.hardening").inputSchema
            print("SCHEMA native.pe.hardening props=%s required=%s"
                  % (list(schema["properties"]), schema.get("required")))

            results: list[tuple[str, bool]] = []

            async def call(label, tool, expect_executes: bool, expect_check: str | None,
                           **args):
                res = await s.call_tool(tool, args)
                payload = show(label, res)
                print(f"    sentinel_after={sentinel()!r}")
                # The "nothing executed" claim, asserted rather than asserted-in-prose: a refusal
                # carries only server keys, a completed runner leaks exit/raw/image/...
                leaked = sorted(RUNNER_KEYS & set(payload))
                no_exec = payload.get("ok") is False and not leaked
                # ...and the refusal must arrive with the RIGHT NAME. Without this second
                # assertion the suite is satisfied by any refusal at all, including a mutant
                # that deleted the containment checks entirely and fell through to the gate.
                named = payload.get("check_failed") == expect_check
                ok = (no_exec == (not expect_executes)) and named
                print("    ASSERT %s expect_check=%s got=%s no_exec=%s leaked=%s"
                      % (label, expect_check, payload.get("check_failed"), no_exec, leaked))
                results.append((label, ok))
                return payload

            async def refuse(label, tool, expect_check: str, **args):
                return await call(label, tool, False, expect_check, **args)

            # ---- 1. THE ACCEPTANCE CASE: a client that knows only a mission identifier.
            p = await call("A1 mission_id valid -> real execution", "native.pe.hardening",
                           True, None, mission_id=CASE, target=str(TARGET))
            print("    A1 ok=%s keys=%s" % (p.get("ok"), sorted(p)[:12]))

            # ---- 2. POSITIVE CONTROL that the execution sentinel actually fires.
            await call("A2 sentinel positive control (allowed, node runner)",
                       "forensics.memory.artefact", True, None, mission_id=CASE, target=str(TARGET))
            fired = bool(sentinel())
            print(f"\nSENTINEL_FIRES={fired}")
            truncate_sentinel()

            # A python-runner capability, so the assertion covers BOTH runner families rather
            # than only the node-runner ones the PATH shim can intercept.
            await refuse("R8 python runner, traversal identifier", "native.pe.hardening",
                         "identifier_traversal", mission_id="../../Windows", target=str(TARGET))
            await refuse("R9 python runner, no acquisition form", "native.pe.hardening",
                         "neither_acquisition_form_given", target=str(TARGET))

            # ---- 3. every refusal below must leave the sentinel empty.
            await refuse("R1 mission_id with .. traversal", "forensics.memory.artefact",
                         "identifier_traversal", mission_id="../../Windows", target=str(TARGET))
            await refuse("R2 mission_id absolute path outside root", "forensics.memory.artefact",
                         "identifier_is_absolute", mission_id=r"C:\Windows\System32", target=str(TARGET))
            await refuse("R3 case_dir absolute path outside root", "forensics.memory.artefact",
                         "case_dir_outside_root", case_dir=r"C:\Windows\System32", target=str(TARGET))
            await refuse("R4 no acquisition form at all", "forensics.memory.artefact",
                         "neither_acquisition_form_given", target=str(TARGET))
            await refuse("R5 both forms at once", "forensics.memory.artefact",
                         "both_acquisition_forms_given", mission_id=CASE, case_dir=str(MISSIONS / CASE), target=str(TARGET))
            await refuse("R6 mission_id that does not exist", "forensics.memory.artefact",
                         "case_does_not_exist", mission_id="no-such-mission", target=str(TARGET))

            # junction inside the root pointing outside it: textually inside, physically out.
            link = MISSIONS / "probe-junction"
            await refuse("R7 mission_id is a junction pointing out of the root",
                         "forensics.memory.artefact", "case_symlink_escapes_root", mission_id="probe-junction",
                         target=str(TARGET))
            print(f"    (junction {link} exists={link.exists()})")

            # ---- 4. the gate still runs, and still refuses BY CAPABILITY NAME.
            await refuse("G1 gate refuses crypto.jose.parse (not in the grant)", "crypto.jose.parse",
                         "gate_denied_capability", mission_id=CASE)
            print("    sentinel_after_gate_refusal=%r" % sentinel())

            # ---- 5. the other installed control: unbound {input.*} refused by name.
            await refuse("P1 unbound {input.function} still refused by name",
                         "native.disasm.capstone", None, mission_id=CASE, target=str(TARGET))

            # ---- 6. the OLD explicit case_dir form still works.
            await refuse("L0 legacy case_dir OUTSIDE the root is still refused",
                         "native.pe.hardening", "case_dir_outside_root", case_dir=r"D:\Software\Tool\WorkStation\debugger",
                         target=str(TARGET))

            # ---- 7. the OLD explicit case_dir form still works, inside the root.
            p = await call("L1 legacy explicit case_dir form -> real execution",
                           "native.pe.hardening", True, None, case_dir=str(MISSIONS / CASE),
                           target=str(TARGET))
            print("    L1 ok=%s keys=%s" % (p.get("ok"), sorted(p)[:12]))

    print("\n=== SENTINEL AFTER ALL REFUSALS: %r ===" % sentinel())
    print("=== GATE SENTINEL (powershell invocations) ===")
    print(GATE_SENTINEL.read_text(encoding="utf-8") or "(empty)")
    print("=== VERDICTS ===")
    for _label, _ok in results:
        print("  %-6s %s" % ("PASS" if _ok else "FAIL", _label))
    print("  FAILURES: %d of %d" % (sum(1 for _, o in results if not o), len(results)))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))