#!/usr/bin/env python3
"""Portable 11-case resource-lifecycle regression; all browser/Frida APIs mocked."""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WRAPPERS = {"cdp": "web-reverse/tools/cdp-nodes.mjs",
            "frida": "native-lab/tools/frida_runtime_facts.py"}
CASES = {
    "cdp": [("success", 0), ("evaluate-fail", 2), ("connect-fail", 2),
            ("non-loopback", 1), ("foreign-pid", 2)],
    "frida": [("success", 0), ("attach-fail", 1), ("spawn-fail", 1),
              ("copy-fail", 1), ("caller-stage-fail", 1), ("foreign-pid", 2)],
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def executable(value):
    path = Path(shutil.which(value) or value).resolve()
    if not path.is_file():
        raise ValueError("installed executable not found: " + value)
    return path

def run_case(kind, mode, expected_exit, subject, output, node, python):
    case = output / "runs" / kind / mode
    case.mkdir(parents=True, exist_ok=False)
    (case / "foreign-owned-marker").write_text("never delete", encoding="utf-8")
    env = os.environ.copy()
    for key in ("NODE_OPTIONS", "NODE_PATH", "NODE_COMPILE_CACHE", "PYTHONPATH", "PYTHONSTARTUP"):
        env.pop(key, None)
    env.update(CLEANUP_CASE_ROOT=str(case), CLEANUP_MODE=mode, PYTHONDONTWRITEBYTECODE="1")
    fixture_digest = None
    script = subject / WRAPPERS[kind]
    if kind == "cdp":
        url = "https://example.invalid/forbidden" if mode == "non-loopback" else "http://127.0.0.1:9/fixture"
        argv = [str(node), str(script), "--url", url]
        if mode == "foreign-pid":
            argv += ["--attach-pid", "900001"]
    else:
        temporary = case / "tmp"
        temporary.mkdir()
        env.update(TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary))
        fixture = temporary / "fixture.exe"
        # Parser-only bytes authored by this test; the mock never executes them.
        blob = bytearray(512)
        blob[:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3c, 0x80)
        blob[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", blob, 0x98, 0x10b)
        struct.pack_into("<I", blob, 0x98 + 16, 0x10)
        struct.pack_into("<I", blob, 0x98 + 28, 0x400000)
        fixture.write_bytes(blob)
        fixture_digest = hashlib.sha256(blob).hexdigest()
        argv = [str(python), "-X", "utf8", "-B", str(script), "--target", str(fixture), "--timeout", "0.05"]
        if mode == "caller-stage-fail":
            caller = case / "caller-stage"
            caller.mkdir()
            (caller / "caller-marker").write_text("caller owns this", encoding="utf-8")
            argv += ["--stage-dir", str(caller)]
        elif mode == "foreign-pid":
            argv += ["--pid", "900001"]
    record = {"kind": kind, "mode": mode, "argv": argv, "cwd": str(case),
              "timeout_seconds": 10, "expected_exit": expected_exit, "timed_out": False}
    with (case / "stdout.txt").open("xb") as so, (case / "stderr.txt").open("xb") as se:
        try:
            proc = subprocess.run(argv, cwd=case, env=env, stdout=so, stderr=se, timeout=10)
            record["exit_code"] = proc.returncode
        except subprocess.TimeoutExpired:
            record.update(exit_code=None, timed_out=True)
    stdout = (case / "stdout.txt").read_text(encoding="utf-8", errors="replace")
    stderr = (case / "stderr.txt").read_text(encoding="utf-8", errors="replace")
    checks = {"exit_code_preserved": record["exit_code"] == expected_exit and not record["timed_out"]}
    events_file = case / "events.jsonl"
    parsed, events = None, []
    try:
        events = [json.loads(x) for x in events_file.read_text(encoding="utf-8").splitlines()] if events_file.exists() else []
        names = [x["event"] for x in events]
        checks["foreign_resource_preserved"] = (case / "foreign-owned-marker").read_text(encoding="utf-8") == "never delete"
        if kind == "cdp":
            parsed = json.loads(stdout)
            checks["single_json_verdict"] = len(stdout.splitlines()) == 1 and parsed["exit"] == expected_exit
            checks["no_owned_profile_leak"] = not (case / "mock-owned-profile").exists()
            checks["no_owned_connection_leak"] = not (case / "mock-owned-socket").exists()
            if mode in ("success", "evaluate-fail"):
                checks["awaited_both_owned_closures"] = names[-4:] == ["cdp.close.begin", "cdp.close.end", "chrome.close.begin", "chrome.close.end"]
            elif mode == "connect-fail":
                checks["partial_acquisition_cleanup"] = names[-2:] == ["chrome.close.begin", "chrome.close.end"] and "cdp.close.begin" not in names
            else:
                checks["refused_before_launch"] = events == []
            if mode == "success":
                checks["success_payload"] = parsed["ok"] is True and parsed["nodes"] == [{"selector": "p#owned", "text": "owned fixture"}]
        else:
            owned_calls = [x for x in events if x["event"] in ("device.attach", "device.kill", "device.resume")]
            checks["only_owned_pid_used"] = all(x["pid"] == 730001 for x in owned_calls)
            checks["no_owned_pid_leak"] = not (case / "mock-owned-pid").exists()
            checks["owned_stage_removed"] = list(temporary.glob("fridafacts-*")) == []
            checks["fixture_not_modified"] = sha(fixture) == fixture_digest
            if mode in ("success", "attach-fail", "caller-stage-fail"):
                checks["owned_spawn_killed_once"] = [x["pid"] for x in events if x["event"] == "device.kill"] == [730001]
            else:
                checks["unacquired_pid_not_killed"] = "device.kill" not in names
            if mode == "success":
                parsed = json.loads(stdout)
                checks["success_payload"] = parsed["ok"] is True and parsed["module_base"] == "0x1000" and parsed["export_addr"] == "0x2000" and parsed["hook_addr"] == "0x1010"
                checks["ordered_lifecycle"] = names[-5:] == ["script.create", "script.load", "device.resume", "session.detach", "device.kill"]
            elif mode == "foreign-pid":
                checks["foreign_pid_argument_refused"] = names == ["frida.mock.import"] and "unrecognized arguments" in stderr
            else:
                token = "MOCK_ATTACH_FAILURE" if mode in ("attach-fail", "caller-stage-fail") else "MOCK_" + mode.split("-")[0].upper() + "_FAILURE"
                checks["original_failure_preserved"] = token in stderr and "AttributeError" not in stderr
                checks["unacquired_session_not_detached"] = "session.detach" not in names
            if mode == "caller-stage-fail":
                checks["caller_stage_preserved"] = (caller / "caller-marker").read_text(encoding="utf-8") == "caller owns this" and (caller / "fixture.exe").is_file()
    except Exception as exc:
        checks["oracle_evaluation_completed"] = False
        record["oracle_error"] = repr(exc)
    record.update(checks=checks, all_pass=all(checks.values()), parsed=parsed,
                  event_names=[x.get("event") for x in events], case_root=str(case))
    record["raw_sha256"] = {p.name: sha(p) for p in (case / "stdout.txt", case / "stderr.txt")}
    if events_file.exists():
        record["raw_sha256"]["events.jsonl"] = sha(events_file)
    save(case / "result.json", record)
    return record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="repository root containing the two wrappers")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory; must not exist")
    parser.add_argument("--node", required=True, help="installed Node executable path or command")
    parser.add_argument("--python", default=sys.executable, help="Python executable; default is this interpreter")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    node, python = executable(args.node), executable(args.python)
    package = Path(__file__).resolve().parent
    for rel in WRAPPERS.values():
        p = (source / rel).resolve()
        if not p.is_file() or not p.is_relative_to(source):
            raise ValueError("wrapper missing or outside source root: " + rel)
    if output.is_relative_to(source):
        raise ValueError("output must be outside the read-only source root")
    output.mkdir(parents=True, exist_ok=False)
    subject = output / "subject"
    bound = [Path(__file__).resolve(), node, python]
    for rel in WRAPPERS.values():
        src, dst = source / rel, subject / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        assert sha(src) == sha(dst)
        bound.extend([src, dst])
    for name, rel in (("cdp.mjs", "web-reverse/tools/cdp.mjs"),
                      ("chrome.mjs", "web-reverse/tools/chrome.mjs"),
                      ("frida.py", "native-lab/tools/frida.py")):
        src, dst = package / "mocks" / name, subject / rel
        shutil.copyfile(src, dst)
        bound.extend([src, dst])
    inputs = {str(p): {"sha256": sha(p), "bytes": p.stat().st_size} for p in bound}
    def unchanged():
        return {p: Path(p).is_file() and sha(Path(p)) == value["sha256"] for p, value in inputs.items()}
    save(output / "INPUTS.json", {"files": inputs})
    result = {"schema": "resource-cleanup-mock/1", "started_utc": datetime.now(timezone.utc).isoformat(),
              "source": str(source), "output": str(output), "node": str(node), "python": str(python),
              "inputs_sha256": sha(output / "INPUTS.json"), "cases": [],
              "boundary": "Two copied wrappers, explicit mocked sibling modules, no real browser/Frida/network/target execution."}
    for kind, cases in CASES.items():
        for mode, expected in cases:
            record = run_case(kind, mode, expected, subject, output, node, python)
            result["cases"].append(record)
            save(output / "RESULTS.json", result)
            print(json.dumps({"kind": kind, "mode": mode, "pass": record["all_pass"],
                              "failed": [k for k, v in record["checks"].items() if not v]}), flush=True)
    result["inputs_unchanged"] = unchanged()
    result["case_count"] = len(result["cases"])
    result["all_pass"] = result["case_count"] == 11 and all(c["all_pass"] for c in result["cases"]) and all(result["inputs_unchanged"].values())
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    save(output / "RESULTS.json", result)
    return 0 if result["all_pass"] else 2

if __name__ == "__main__":
    raise SystemExit(main())
