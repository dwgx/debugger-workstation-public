#!/usr/bin/env python3
"""Exercise local Frida only against a freshly compiled, authored sleeper."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from fixtures import build_all
from lab_session import LabSession
from raw_mcp import job_observation, snap_all


def owned_handle(pid, expected_image):
    import win32api
    import win32process
    handle = win32api.OpenProcess(0x00100000 | 0x1000 | 0x0001, False, pid)
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        query = kernel.QueryFullProcessImageNameW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if not query(int(handle), 0, buf, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(buf.value).resolve() != expected_image.resolve():
            raise RuntimeError("returned PID is not this run's unique authored executable")
        times = {k: str(v) for k, v in win32process.GetProcessTimes(handle).items()}
        return handle, {"pid": pid, "image": buf.value, "process_times": times}
    except BaseException:
        win32api.CloseHandle(handle)
        raise


def main():
    import win32api
    import win32event
    import win32process
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--csc", type=Path)
    ap.add_argument("--candidate-cli", type=Path, help="Explicit isolated candidate source; otherwise use original wrapper")
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    fixtures = build_all(out / "fixtures")
    (out / "temp").mkdir()
    csc = (args.csc or Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe").resolve()
    unique = hashlib.sha256(str(out).encode()).hexdigest()[:12]
    image = out / "fixtures" / ("OwnedSleeper_" + unique + ".exe")
    compile_argv = [str(csc), "/nologo", "/target:exe", "/platform:x64", "/out:" + str(image), str(out / "fixtures/OwnedSleeper.cs")]
    compile_result = subprocess.run(compile_argv, capture_output=True, timeout=30)
    (out / "compiler.stdout.txt").write_bytes(compile_result.stdout)
    (out / "compiler.stderr.txt").write_bytes(compile_result.stderr)
    if compile_result.returncode != 0 or not image.is_file():
        raise RuntimeError("authored sleeper compilation failed; no target launched")
    wrapper = station / "MCP/bin/frida-mcp.cmd"
    env = no_mcp_env()
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(out / "temp"), "TMP": str(out / "temp")})
    if args.candidate_cli:
        argv = [str(station / "MCP/frida-mcp/.venv/Scripts/python.exe"), "-X", "utf8", "-B", str(args.candidate_cli.resolve())]
        provider = args.candidate_cli.resolve()
        route = "isolated source candidate"
    else:
        argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
        provider = station / "MCP/frida-mcp/.venv/Lib/site-packages/frida_mcp/cli.py"
        route = "original wrapper"
    marker = "TOOLLAB_ARG_" + unique
    plan = {"schema": "tool-lab-authored-frida/1", "fixtures": fixtures, "wrapper": str(wrapper), "wrapper_sha256": digest(wrapper),
            "provider": str(provider), "provider_sha256": digest(provider), "runner_sha256": digest(Path(__file__)),
            "compiler": {"argv": compile_argv, "sha256": digest(csc), "exit_code": compile_result.returncode},
            "owned_image": {"path": str(image), "sha256": digest(image)}, "argument_marker": marker,
            "scope": "Execute only authored sleeper; explicit local device; attach/kill only returned PID whose retained handle resolves to this unique executable. No enumeration output or USB access."}
    write_json(out / "PLAN.json", plan)
    print(json.dumps({"plan_sha256": digest(out / "PLAN.json"), "output": str(out)}), flush=True)
    handle = None
    pid = None
    target_cleanup = {"observed_terminated": False, "fallback_used": False}
    with LabSession("frida", argv, out, env, out / "session", route, timeout=30) as lab:
        try:
            for method in ("get_local_device", "get_device"):
                c = lab.call(method, {} if method == "get_local_device" else {"device_id": "local"}, method)
                lab.check(c, "local_device_id", c["payload"].get("id"), "local")
                lab.check(c, "local_device_type", c["payload"].get("type"), "local")
            c = lab.call("spawn_process", {"program": str(image), "args": [marker], "device_id": "local"}, "spawn-authored")
            pid = c["payload"].get("pid") if isinstance(c["payload"], dict) else None
            lab.check(c, "returned_pid", isinstance(pid, int) and pid > 0, True)
            if not isinstance(pid, int) or pid <= 0:
                raise RuntimeError("spawn did not return an owned PID; dependent calls refused")
            handle, identity = owned_handle(pid, image)
            members = job_observation(lab.client._job)
            observations = [p for p in snap_all() if int(p["ProcessId"]) == pid]
            c["owned_identity"] = identity
            c["job_membership"] = members
            c["owned_process_observation"] = observations
            lab.check(c, "exact_image_identity", str(Path(identity["image"]).resolve()), str(image.resolve()))
            lab.check(c, "one_current_owned_process", len(observations), 1)
            lab.check(c, "argument_forwarded", len(observations) == 1 and marker in (observations[0].get("CommandLine") or ""), True)
            c = lab.call("resume_process", {"pid": pid, "device_id": "local"}, "resume-owned")
            lab.check(c, "resumed", c["payload"].get("success"), True)
            time.sleep(0.25)
            c = lab.call("get_process_by_name", {"name": image.stem, "device_id": "local"}, "find-only-owned-name")
            lab.check(c, "exact_owned_pid", c["payload"].get("pid"), pid)
            c = lab.call("attach_to_process", {"pid": pid, "device_id": "local"}, "attach-owned")
            lab.check(c, "attached", c["payload"].get("success"), True)
            lab.check(c, "pid", c["payload"].get("pid"), pid)
            c = lab.call("create_interactive_session", {"process_id": pid, "device_id": "local"}, "session-owned")
            lab.check(c, "created", c["payload"].get("status"), "success")
            lab.check(c, "pid", c["payload"].get("process_id"), pid)
            session_id = c["payload"].get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise RuntimeError("no owned Frida session; dependent scripts refused")
            c = lab.call("execute_in_session", {"session_id": session_id, "javascript_code": 'JSON.stringify({pid:Process.id,marker:"TOOLLAB_FRIDA_MARKER",answer:6*7})', "keep_alive": False}, "read-authored-process-facts")
            lab.check(c, "status", c["payload"].get("status"), "success")
            lab.check(c, "script_unloaded", c["payload"].get("script_unloaded"), True)
            lab.check(c, "facts", json.loads(c["payload"].get("result", "null")), {"pid": pid, "marker": "TOOLLAB_FRIDA_MARKER", "answer": 42})
            c = lab.call("execute_in_session", {"session_id": session_id, "javascript_code": 'send({marker:"TOOLLAB_FRIDA_QUEUE",answer:42})', "keep_alive": True}, "owned-persistent-message")
            lab.check(c, "status", c["payload"].get("status"), "success")
            lab.check(c, "script_persistent", c["payload"].get("script_unloaded"), False)
            c = lab.call("get_session_messages", {"session_id": session_id}, "read-owned-message-queue")
            messages = c["payload"].get("messages", [])
            lab.check(c, "queue_marker", any(m.get("payload") == {"marker": "TOOLLAB_FRIDA_QUEUE", "answer": 42} for m in messages), True)
            lab.check(c, "execution_receipt", any(isinstance(m.get("payload"), dict) and m["payload"].get("type") == "execution_receipt" for m in messages), True)
            c = lab.call("get_session_messages", {"session_id": session_id}, "queue-cleared")
            lab.check(c, "empty_after_read", c["payload"].get("messages"), [])
        finally:
            if handle is not None:
                try:
                    if win32event.WaitForSingleObject(handle, 0) == 258:
                        c = lab.call("kill_process", {"pid": pid, "device_id": "local"}, "kill-owned")
                        lab.check(c, "kill_acknowledged", c["payload"].get("success") if isinstance(c["payload"], dict) else None, True)
                        gone = win32event.WaitForSingleObject(handle, 3000) == 0
                        lab.check(c, "retained_owned_handle_terminated", gone, True)
                    target_cleanup["observed_terminated"] = win32event.WaitForSingleObject(handle, 0) == 0
                finally:
                    if win32event.WaitForSingleObject(handle, 0) == 258:
                        win32process.TerminateProcess(handle, 1)
                        target_cleanup["fallback_used"] = True
                        target_cleanup["observed_terminated"] = win32event.WaitForSingleObject(handle, 3000) == 0
                    win32api.CloseHandle(handle)
                    write_json(out / "TARGET-CLEANUP.json", target_cleanup)
    unchanged = digest(image) == plan["owned_image"]["sha256"] and digest(provider) == plan["provider_sha256"] and digest(wrapper) == plan["wrapper_sha256"]
    final = {"all_checks_pass": lab.record["all_checks_pass"] and unchanged and target_cleanup["observed_terminated"] and not target_cleanup["fallback_used"],
             "source_and_fixture_unchanged": unchanged, "target_cleanup": target_cleanup,
             "session_results_sha256": digest(out / "session/RESULTS.json"), "methods_called": lab.record["unique_methods_called"], "positive_methods": lab.record["unique_positive_methods"]}
    write_json(out / "FINAL.json", final)
    print(json.dumps(final))
    return 0 if final["all_checks_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
