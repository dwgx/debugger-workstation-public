#!/usr/bin/env python
"""Re-run each capability's recorded probe and control, and check the recorded strings.

WHY THIS EXISTS. The registry's honesty was, until now, checked by whoever remembered to
check it. A recorded `probe.expect` is a CLAIM about what a tool prints, and nothing static
can test it -- R2 can tell a command is runnable and can never tell that its output still
matches the string beside it. Independent verification on 2026-10-02 found exactly this:

  native.pe.packer    probe.expect read '"packed": false' with a space. The tool emits
                      PowerShell's compact ConvertTo-Json, '"packed":false'. A literal
                      substring check FAILS on a perfectly healthy probe.
  native.function.match  expect read '"match_rate": 37.6'; the tool emits '"match_rate":37.6'.
                      The SAME defect, in a second entry, which is what makes it a class.
  native.pe.authenticode  its control was three statements joined by ';'. That separates
                      commands in PowerShell and is an ARGUMENT DELIMITER in cmd.exe, so run
                      verbatim under cmd it reached authenticode.py as one invocation and died
                      with "unrecognized arguments: python -c import sys;d=open(...)". Under
                      PowerShell it produces exactly what was always claimed -- so the string
                      was never false, it was simply in a shell that could not run it.
  native.pe.container  control.measured said "the wrapper prints REFUSED and exits 2" while
                      quoting the BARE pefile command, which exits 1 and prints a traceback.
                      grep -c REFUSED native-lab/tools/pe_probe.py returns 0.

None of those is visible to a static rule, and all four survived a registry that reported
REGISTRY CLEAN. They were found only because somebody ran the strings.

    python scripts/assert-probes.py                 # every capability whose probe is safe here
    python scripts/assert-probes.py native.pe.packer native.pe.container
    python scripts/assert-probes.py --list          # ids only, run nothing

WHAT IT DELIBERATELY DOES NOT DO. It does not fix anything, and it does not rewrite a string
that no longer matches: a probe whose output legitimately changed has two possible causes --
the instrument regressed, or the claim was never true -- and those have OPPOSITE fixes, so the
tool reports and leaves it to a human. It does not run smoke-all.ps1, any lab loop, or any
fuzz run; those are parent-owned.

THE VERDICT THAT MATTERS MOST: TOOL-FAULT. This script's own first run reported 21 DRIFT out
of 24, and nearly all were its own fault -- the registry's commands are PowerShell and were
being handed to cmd.exe, which dies in 0.0 s with exit 255. A shell failure is not evidence
about the registry, so a command that dies fast with no output is named as THIS SCRIPT's
fault and never counted as DRIFT. A broken harness is not a finding, the same way an error is
not a zero.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# Never run here: long, parent-owned, or prose only an MCP session can execute. Always shown.
SKIP = {
    "native.ida.decompile": "driven through the idalib-mcp MCP device, not a CLI command",
    "native.ida.list_functions": "driven through the idalib-mcp MCP device, not a CLI command",
    "native.crosscompare.ghidra": "state=planned; no runnable command exists to check",
    "native.ghidra.emulate": "state=blocked; needs a runtime the registry does not have",
    "dynamic.device.frida": "state=absent; needs an attached device",
    "native.il2cpp.symbols": "state=absent; needs an extracted IL2CPP metadata dump",
}

FAULT_MARKERS = ("is not recognized", "not recognized as an", "the term",
                 "commandnotfound", "is not installed", "no such file", "parsererror",
                 "stringnotexpanded", "was unexpected at this time", "syntaxerror")

TOOL_FAULT_SECS = 0.5


def load() -> list[dict]:
    return json.load(open(REG, encoding="utf-8"))["capabilities"]


def run(cmd: str, timeout: int) -> tuple[int, str, float]:
    """Execute `cmd` byte-for-byte, with no re-quoting of any kind.

    The command goes into a .ps1 file which PowerShell runs with -File. Two earlier designs
    were wrong: sniffing for PowerShell markers and wrapping in `powershell -Command "..."`
    missed 8 commands AND destroyed every command containing a double quote. Re-quoting a
    command you did not write is how a harness quietly breaks a probe and then reports the
    breakage as the registry's. The only arrangement in which 'verbatim' is true is no
    transformation at all.

    stderr is merged into stdout on purpose: a tool may decorate stderr and write its contract
    on stdout, and the recorded expect strings were written against combined output. This is
    the OPPOSITE of mission.ps1, which separates the two because a capability under a mission
    must not corrupt its JSON. Two contracts, two behaviours.
    """
    script = REPO / "_assert_probe_cmd.ps1"
    t0 = time.time()
    try:
        # The wrapper MUST propagate the exit code. `powershell -File` returns 0 unless the
        # script says `exit`, so without this line assert-probes reports EVERY control as
        # exiting 0 and every refusal looks like a pass. That is not hypothetical: it is what
        # this script did on its previous run, and it is the same defect it was written to
        # find. The failure mode of a checking tool is to check nothing and look green.
        script.write_text(cmd + "\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
        p = subprocess.run(
            f'powershell -NoProfile -ExecutionPolicy Bypass -File "{script}"',
            shell=True, cwd=REPO, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return -1, f"<timeout after {timeout}s>", time.time() - t0
    except Exception as e:  # noqa: BLE001 - a broken shell is a finding, not a crash
        return -2, f"<could not run: {e}>", time.time() - t0
    finally:
        try:
            script.unlink()
        except OSError:
            pass


def tool_fault(rc: int, blob: str, secs: float) -> str | None:
    """Did this command fail to RUN, rather than run and fail? Never report that as DRIFT."""
    if rc == 0 or secs >= TOOL_FAULT_SECS:
        return None
    low = blob.lower()
    hit = next((m for m in FAULT_MARKERS if m in low), None)
    if hit:
        return (f"never ran: the shell rejected it ({hit!r}) after {secs:.2f}s, exit {rc}. "
                f"THIS TOOL'S FAULT -- the registry is not implicated.")
    if not blob.strip():
        return (f"never ran: no output at all after {secs:.2f}s, exit {rc}. THIS TOOL'S "
                f"FAULT, most likely the shell -- the registry is not implicated.")
    return None


def prose(cmd: str) -> bool:
    head = cmd.strip().split()[0] if cmd.strip() else ""
    return head in {"see", "list_funcs", "run", "use", "the"} or not cmd.strip()


def check(cap: dict, timeout: int) -> list[tuple[str, str]]:
    cid = cap["id"]
    if cid in SKIP:
        return [("SKIP", f"{cid}: {SKIP[cid]}")]

    out: list[tuple[str, str]] = []
    probe = cap.get("probe") or {}
    cmd = (probe.get("command") or "").strip()
    if not cmd or prose(cmd):
        return [("SKIP", f"{cid}: probe.command is not executable ({cmd[:50]!r})")]

    rc, blob, secs = run(cmd, timeout)
    fault = tool_fault(rc, blob, secs)
    if fault:
        out.append(("TOOL-FAULT", f"{cid} PROBE {fault} :: {cmd[:60]}"))
    else:
        want_exit = probe.get("expect_exit")
        if want_exit is not None and rc != want_exit:
            out.append(("DRIFT", f"{cid} PROBE exit: recorded expect_exit={want_exit}, real={rc} "
                                  f"after {secs:.1f}s :: {cmd[:60]}"))
        want = probe.get("expect")
        if want and want not in blob:
            near = ""
            for pat in (r'"packed"\s*:\s*\S+', r'"match_rate"\s*:\s*\S+', r'verdict=\S+',
                        r'width=\S+'):
                m = re.search(pat, blob)
                if m:
                    near = f" (output has {m.group(0)!r})"
                    break
            out.append(("DRIFT", f"{cid} PROBE expect: {want!r} is not a substring of the real "
                                  f"output{near}. Either the instrument regressed or the string "
                                  f"was never true; those have opposite fixes, so read it."))

    nc = cap.get("negative_control") or {}
    ccmd = (nc.get("command") or "").strip()
    if not ccmd or prose(ccmd):
        out.append(("SKIP", f"{cid} CONTROL: not executable ({ccmd[:50]!r})"))
        return out

    crc, cblob, csecs = run(ccmd, timeout)
    cfault = tool_fault(crc, cblob, csecs)
    if cfault:
        out.append(("TOOL-FAULT", f"{cid} CONTROL {cfault} :: {ccmd[:60]}"))
        return out

    want_ce = nc.get("expect_exit")
    if want_ce is None:
        out.append(("DRIFT", f"{cid} CONTROL: declares no expect_exit, so nothing states what "
                              f"the refusal looks like."))
    elif crc != want_ce:
        out.append(("DRIFT", f"{cid} CONTROL exit: recorded expect_exit={want_ce}, real={crc} "
                              f"after {csecs:.1f}s :: {ccmd[:60]}"))
    want_co = nc.get("expect_output")
    if want_co and want_co not in cblob:
        out.append(("DRIFT", f"{cid} CONTROL expect_output: {want_co!r} absent from real output"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="capability ids; default = every safe one")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--list", action="store_true", help="show what would run, run nothing")
    args = ap.parse_args()

    caps = load()
    known = {c["id"] for c in caps}
    if args.ids:
        missing = set(args.ids) - known
        if missing:
            print(f"assert-probes: unknown id(s): {sorted(missing)}", file=sys.stderr)
            return 2

    if args.list:
        for c in caps:
            print(f"  {'SKIP ' if c['id'] in SKIP else 'run  '} {c['id']:<30} "
                  f"{(c.get('probe') or {}).get('command', '')[:58]}")
        return 0

    todo = [c for c in caps if not args.ids or c["id"] in args.ids]
    results: list[tuple[str, str]] = []
    for c in todo:
        results.extend(check(c, args.timeout))

    counts: dict[str, int] = {}
    for s, _ in results:
        counts[s] = counts.get(s, 0) + 1
    for s, m in results:
        print(f"  {s:<11} {m}")

    print(f"\nassert-probes: {len(todo)} checked, "
          + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + ".")
    if counts.get("TOOL-FAULT"):
        print("\nTOOL-FAULT is this script's problem, not the registry's: those commands never\n"
              "ran. Fix this script before reading anything else in this output.")
    if counts.get("DRIFT"):
        print("\nA DRIFT is a finding, not an auto-fix: the instrument may have regressed, or the\n"
              "recorded string may never have been true. Those have opposite fixes, so read it.")
    return 1 if counts.get("DRIFT") else 0


if __name__ == "__main__":
    sys.exit(main())