#!/usr/bin/env python
"""Execute every `requires.tools[].probe` and check it against its declared `expect`.

WHY THIS EXISTS. Nothing in this project ever executed `requires.tools[].expect`. An audit
proved it by grep: the field appears only in R18, which reads `.name` for instrument identity and
never touches `expect`. So the field was decoration that read like a contract.

And it was not decoration about nothing. One entry declared

    { "name": "tshark", "probe": "tshark --version", "expect": "TShark" }

which FAILS on this station -- `where tshark` finds nothing, because the station ships a PORTABLE
Wireshark at Network-HTTP/Wireshark/portable/App/Wireshark/tshark.exe (measured TShark 4.6.8).
Another declared `corpus.json written to %TEMP%\\net-reverse-lab\\pcaps`, which can never match:
%TEMP% is a CMD token the program does not expand, and it prints `label -> <path>\\corpus.json`.

Both sat there with the registry reporting CLEAN, and neither would ever have been noticed.

WHAT IT IS NOT. This is NOT `assert-probes.py`. That tool checks a capability's PROBE -- the run
that produces its evidence. This checks the PRECONDITION that says the tool is even present.
They fail in opposite directions and confusing them would be its own bug: a capability whose probe
cannot reproduce is a defect; a capability whose required tool is missing is an environment fact,
and the right answer is to say so rather than to fail the registry.

    python scripts/check-requires-tools.py            # all entries
    python scripts/check-requires-tools.py --verbose  # show each probe's real output
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# A probe that must never run here. Every one is a state=absent or state=blocked entry, so the
# tool does not exist by definition -- running the probe would be trying to verify something the
# registry already says is not present.
NEVER_RUN_IF_STATE = {"absent", "blocked"}


def as_powershell(cmd: str) -> tuple[str, str]:
    """Return (shell, line). Written to a .ps1 and run with -File, never re-quoted inline.

    `powershell -Command "<cmd>"` destroys any command containing a double quote, and a
    PowerShell marker sniff misses the rest. That mis-dispatch produced 21 false DRIFTs in
    assert-probes.py's first run. The text reaching the interpreter has to be byte-for-byte the
    text in the registry, so the file is the only arrangement in which 'verbatim' is true.
    """
    script = Path(tempfile.gettempdir()) / "_check_requires_tools_cmd.ps1"
    script.write_text(cmd + "\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
    return f'powershell -NoProfile -ExecutionPolicy Bypass -File "{script}"', str(script)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    caps = json.load(open(REG, encoding="utf-8"))["capabilities"]
    rows: list[tuple[str, str, str, str]] = []   # (id, tool, verdict, detail)

    for c in caps:
        req = c.get("requires") or {}
        for t in req.get("tools") or []:
            name = t.get("name", "?")
            probe = (t.get("probe") or "").strip()
            expect = t.get("expect")
            # An entry may DECLARE itself unverifiable, which is honest and is not the same as
            # declaring a probe that cannot fail. MCP devices and browser surfaces have no CLI
            # invocation; giving them one would manufacture a check that passes without testing.
            if t.get("verify") is False:
                rows.append((c["id"], name, "UNDECLARED-UNVERIFIABLE",
                             str(t.get("verify_note") or "declared verify:false -- no CLI invocation can prove it")))
                continue
            if not probe:
                rows.append((c["id"], name, "NO-PROBE",
                             "declares a tool with no probe, so its presence is asserted and never checked"))
                continue
            if c["state"] in NEVER_RUN_IF_STATE:
                rows.append((c["id"], name, "SKIP",
                             f"state={c['state']}: the registry already says this is not present, "
                             f"so running its probe would be checking a contradiction"))
                continue
            shell, script = as_powershell(probe)
            try:
                p = subprocess.run(shell, shell=True, cwd=REPO, capture_output=True, text=True,
                                   timeout=args.timeout, encoding="utf-8", errors="replace")
                rc, blob = p.returncode, (p.stdout or "") + (p.stderr or "")
            except subprocess.TimeoutExpired:
                rc, blob = -1, f"<timeout after {args.timeout}s>"
            except Exception as e:  # noqa: BLE001
                rc, blob = -2, f"<could not run: {e}>"
            finally:
                try:
                    os.unlink(script)
                except OSError:
                    pass

            if rc == -1:
                rows.append((c["id"], name, "TOOL-FAULT",
                             f"probe timed out after {args.timeout}s -- this script's limit, "
                             f"not the registry's. A truncated run is not evidence."))
                continue
            if rc == -2:
                rows.append((c["id"], name, "TOOL-FAULT", blob.strip()[:120]))
                continue
            # The probe must SUCCEED. A non-zero exit with a matching string would let a broken
            # tool satisfy its own precondition, which is the shape this whole script exists to
            # refuse -- the same shape as assert-probes.py's stub finding.
            # A tool whose PRESENCE SIGNAL is a usage banner exits non-zero for having no
            # arguments. Ghidra's analyzeHeadless.bat prints its usage and exits -1 when invoked
            # bare, which is exactly what proves the batch file exists and responds. Calling that
            # BROKEN would make the gate unable to describe that case honestly, so a tool may
            # declare expect_exit and say which non-zero code is the one it means.
            want_rc = t.get("expect_exit", 0)
            if rc != want_rc:
                rows.append((c["id"], name, "BROKEN",
                             f"probe exited {rc} (declared expect_exit {want_rc}): {blob.strip()[:100]}"))
                continue
            if expect is None:
                rows.append((c["id"], name, "NO-EXPECT",
                             "probe succeeded but declares no expect, so success and failure look identical"))
                continue
            # `expect` is used in BOTH senses across this registry and both are legitimate:
            #   "exit 0"            a description of the expected EXIT CODE, and
            #   "TShark"            a literal substring the OUTPUT must contain.
            # Treating both as substrings made the first kind permanently unmeetable -- the
            # output of `python -c "import pefile"` is empty, so the substring "exit 0" can
            # never appear. Recognising the exit-code form is the honest resolution rather than
            # rewriting a dozen entries to match a convention half of them never used.
            m = re.fullmatch(r"exit\s+(\d+)", str(expect).strip(), re.IGNORECASE)
            if m:
                want_rc = int(m.group(1))
                if rc != want_rc:
                    rows.append((c["id"], name, "UNMATCHED",
                                 f"declared expect exit {want_rc}, real exit was {rc}"))
                else:
                    rows.append((c["id"], name, "OK", ""))
                continue
            if str(expect) not in blob:
                near = blob.strip().replace("\n", " ")[:150]
                rows.append((c["id"], name, "UNMATCHED",
                             f"declared expect {str(expect)!r} does not occur in the real output: {near!r}"))
            else:
                rows.append((c["id"], name, "OK", ""))

    widths = (max(len(r[1]) for r in rows) if rows else 8,
              max(len(r[2]) for r in rows) if rows else 8)
    for cid, name, verdict, detail in rows:
        print(f"  {verdict:<{widths[1]}}  {name:<{widths[0]}}  {cid}")
        if detail and (args.verbose or verdict in ("BROKEN", "UNMATCHED", "NO-PROBE", "NO-EXPECT")):
            print(f"      {detail}")

    bad = [r for r in rows if r[2] in ("BROKEN", "UNMATCHED", "NO-PROBE", "NO-EXPECT")]
    fault = [r for r in rows if r[2] == "TOOL-FAULT"]
    ok = [r for r in rows if r[2] == "OK"]
    skipped = [r for r in rows if r[2] == "SKIP"]
    print(f"\nrequires-tools: {len(rows)} declared tool probes across {len(caps)} capabilities "
          f"-- {len(ok)} ok, {len(bad)} wrong, {len(fault)} tool-fault, {len(skipped)} skipped.")
    if bad:
        print("\nA WRONG entry is a declaration nothing was checking. Nothing else in this project\n"
              "executes requires.tools[].expect, so these would otherwise have stayed invisible\n"
              "indefinitely -- and one of them already was: `tshark --version` cannot pass on this\n"
              "station, which ships a PORTABLE Wireshark that is not on PATH.")
        return 1
    if fault:
        print("\nTOOL-FAULT is this script's problem, not the registry's. Fix the shell or raise\n"
              "--timeout before reading anything else in this output.")
    return 0


if __name__ == "__main__":
    sys.exit(main())