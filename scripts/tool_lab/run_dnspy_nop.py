#!/usr/bin/env python3
"""Check a stack-balanced NOP edit on an authored DLL without executing it."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from lab_session import LabSession


def instructions(text):
    return [(m.group(1), m.group(2)) for m in re.finditer(r"^IL_([0-9A-Fa-f]+): (.+)$", text, re.MULTILINE)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--csc", type=Path)
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    (out / "temp").mkdir()
    source = out / "NopFixture.cs"
    source.write_text('using System; public static class NopFixture { public static void Marker() { Console.WriteLine("TOOLLAB_NOP_MARKER"); } }\n', encoding="utf-8")
    dll = out / "NopFixture.dll"
    patched = out / "NopFixture.patched.dll"
    csc = (args.csc or Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe").resolve()
    compile_argv = [str(csc), "/nologo", "/target:library", "/optimize-", "/debug+", "/out:" + str(dll), str(source)]
    result = subprocess.run(compile_argv, capture_output=True, timeout=30)
    (out / "compiler.stdout.txt").write_bytes(result.stdout)
    (out / "compiler.stderr.txt").write_bytes(result.stderr)
    if result.returncode != 0 or not dll.is_file():
        raise RuntimeError("fixture compile failed")
    wrapper = station / "MCP/bin/dnspy-mcp.cmd"
    argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
    env = no_mcp_env()
    env.update({"TEMP": str(out / "temp"), "TMP": str(out / "temp")})
    plan = {"schema": "tool-lab-dnspy-nop/1", "wrapper": str(wrapper), "wrapper_sha256": digest(wrapper),
            "compiler": {"argv": compile_argv, "sha256": digest(csc)}, "source_sha256": digest(source),
            "input_sha256": digest(dll), "runner_sha256": digest(Path(__file__)),
            "scope": "Own compiled DLL; no assembly execution. Remove one ldstr and its immediately following void WriteLine(string) call, preserving stack balance. No writer option changes."}
    write_json(out / "PLAN.json", plan)
    query = {"assemblyPath": str(dll), "typeFullName": "NopFixture", "methodName": "Marker", "parameterTypeNames": []}
    with LabSession("dnspy", argv, out, env, out / "session", "original wrapper", timeout=30) as lab:
        c = lab.call("get_method_il", query, "before-balanced-pair")
        il = instructions(c["payload"])
        pairs = [i for i, (_, op) in enumerate(il[:-1]) if op.strip() == "ldstr TOOLLAB_NOP_MARKER" and "call System.Void System.Console::WriteLine(System.String)" == il[i + 1][1].strip()]
        lab.check(c, "one_balanced_push_voidcall_pair", len(pairs), 1)
        lab.check(c, "known_method_token", "MethodDef 0x06000001" in c["payload"], True)
        if len(pairs) != 1:
            raise RuntimeError("fixture IL does not match the safe balanced pair; patch refused")
        offset = "IL_" + il[pairs[0]][0]
        c = lab.call("patch_nop_instructions", {"assemblyPath": str(dll), "methodDefToken": "0x06000001", "ilOffset": offset, "count": 2, "inPlace": False, "outputPath": str(patched)}, "nop-balanced-pair")
        lab.check(c, "receipt", "Patch applied: NOP instructions" in str(c["payload"]), True)
        lab.check(c, "fresh_output_exists", patched.is_file(), True)
        lab.check(c, "input_unchanged", digest(dll), plan["input_sha256"])
        backups = list(out.glob("NopFixture.dll.*.bak"))
        if not backups:
            backups = [p for p in out.iterdir() if p.is_file() and p not in (dll, patched) and "backup" in p.name.lower()]
        c["observed_backup_files"] = [{"path": str(p), "sha256": digest(p)} for p in backups]
        lab.check(c, "matching_backup_exists", any(digest(p) == plan["input_sha256"] for p in backups), True)
        if patched.is_file():
            c = lab.call("get_method_il", {**query, "assemblyPath": str(patched)}, "after-no-call")
            after = instructions(c["payload"])
            lab.check(c, "only_nop_and_ret", bool(after) and all(op.strip() in ("nop", "ret") for _, op in after), True)
            lab.check(c, "one_return", sum(op.strip() == "ret" for _, op in after), 1)
            lab.check(c, "nop_count_increased_by_two", sum(op.strip() == "nop" for _, op in after), sum(op.strip() == "nop" for _, op in il) + 2)
    unchanged = digest(dll) == plan["input_sha256"] and digest(wrapper) == plan["wrapper_sha256"]
    final = {"all_checks_pass": lab.record["all_checks_pass"] and unchanged, "input_and_wrapper_unchanged": unchanged,
             "session_results_sha256": digest(out / "session/RESULTS.json"), "limitation": "Straight-line stack-balanced edit only; no branch-target or exception-handler edit validated."}
    write_json(out / "FINAL.json", final)
    print(json.dumps(final))
    return 0 if final["all_checks_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
