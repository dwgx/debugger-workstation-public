#!/usr/bin/env python3
"""Read authored PE bytes through the actual IDA wrapper in force_headless mode."""
import argparse
import json
import os
from pathlib import Path
import sys

from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from fixtures import build_all
from lab_session import LabSession
from raw_mcp import job_observation, snap_all


def as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("result"), list):
        return value["result"]
    raise ValueError("expected an actual result array")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    fixture = build_all(out / "fixtures")
    binary = out / "fixtures/owned-static.exe"
    wrapper = station / "MCP/bin/ida-pro-mcp.cmd"
    argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
    env = no_mcp_env()
    (out / "temp").mkdir()
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(out / "temp"), "TMP": str(out / "temp"),
                "IDA_MCP_OPEN_TIMEOUT": "45", "IDA_MCP_MAX_WORKERS": "1"})
    plan = {"schema": "tool-lab-authored-ida/1", "fixture": fixture, "wrapper": str(wrapper), "wrapper_sha256": digest(wrapper),
            "runner_sha256": digest(Path(__file__)), "client_sha256": digest(Path(__file__).with_name("raw_mcp.py")),
            "methods": ["idb_open", "get_bytes", "get_int", "get_string", "int_convert", "imports", "idb_close"],
            "scope": "Static reads only; force_headless; no GUI adoption; only this fresh authored file; no execution of the PE."}
    write_json(out / "PLAN.json", plan)
    print(json.dumps({"plan_sha256": digest(out / "PLAN.json"), "output": str(out)}), flush=True)
    session_id = None
    with LabSession("ida", argv, out, env, out / "session", "original wrapper", timeout=60) as lab:
        try:
            before_members = set(job_observation(lab.client._job)["pids"])
            opened = lab.call("idb_open", {"input_path": str(binary), "mode": "force_headless", "run_auto_analysis": True,
                             "build_caches": False, "init_hexrays": False, "idle_ttl_sec": 60}, "open-owned", timeout=60)
            data = opened["payload"]
            lab.check(opened, "success", data.get("success") if isinstance(data, dict) else None, True)
            session = data.get("session", {}) if isinstance(data, dict) else {}
            membership = job_observation(lab.client._job)
            # tools/list may create the schema worker before idb_open reuses it.
            # Ownership comes from the suspended launch's non-breakaway Job,
            # not from a newly appearing PID or a provider's own claim.
            processes = [p for p in snap_all() if int(p["ProcessId"]) in set(membership["pids"])]
            owned_workers = [p for p in processes if "-m ida_pro_mcp.idalib_server" in (p.get("CommandLine") or "")
                             and "--host 127.0.0.1" in (p.get("CommandLine") or "")]
            opened["owned_headless_observation"] = {"before_open_pids": sorted(before_members), "after_job": membership,
                                                    "owned_processes": processes, "launch": lab.client.start_observation}
            lab.check(opened, "one_owned_headless_worker", len(owned_workers), 1)
            lab.check(opened, "input_path", str(Path(session.get("input_path", "")).resolve()), str(binary.resolve()))
            session_id = session.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise RuntimeError("no owned headless session; preserve result and stop dependent calls")
            c = lab.call("get_bytes", {"database": session_id, "regions": {"addr": "0x401000", "size": 6}}, "exact-code-bytes")
            row = as_list(c["payload"])[0]
            got = bytes(int(token, 16) for token in (row.get("data") or "").split()).hex()
            lab.check(c, "authored_code", got, "b82a000000c3")
            c = lab.call("get_int", {"database": session_id, "queries": {"addr": "0x401001", "ty": "u32le"}}, "integer-42")
            lab.check(c, "immediate_value", as_list(c["payload"])[0].get("value"), 42)
            c = lab.call("get_string", {"database": session_id, "addrs": "0x402000"}, "authored-marker")
            lab.check(c, "marker_value", as_list(c["payload"])[0].get("value"), fixture["pe"]["marker"])
            c = lab.call("int_convert", {"database": session_id, "inputs": {"text": "0x2a", "size": 4}}, "conversion")
            row = as_list(c["payload"])[0].get("result", {})
            lab.check(c, "decimal", row.get("decimal"), "42")
            lab.check(c, "hexadecimal", row.get("hexadecimal"), "0x2a")
            lab.check(c, "bytes", row.get("bytes"), "2a 00 00 00")
            c = lab.call("imports", {"database": session_id, "offset": 0, "count": 10}, "authored-no-imports")
            data = c["payload"]
            lab.check(c, "no_imports", data.get("data") if isinstance(data, dict) else None, [])
        finally:
            if session_id:
                c = lab.call("idb_close", {"database": session_id, "save": False}, "close-owned")
                data = c["payload"]
                lab.check(c, "close_success", data.get("success") if isinstance(data, dict) else None, True)
    original_ok = digest(binary) == fixture["files"]["owned-static.exe"]["sha256"] and digest(wrapper) == plan["wrapper_sha256"]
    write_json(out / "FINAL.json", {"fixture_and_wrapper_unchanged": original_ok, "session_results_sha256": digest(out / "session/RESULTS.json"), "all_checks_pass": lab.record["all_checks_pass"] and original_ok})
    print(json.dumps({"methods_called": lab.record["unique_methods_called"], "positive_methods": lab.record["unique_positive_methods"], "all_checks_pass": lab.record["all_checks_pass"] and original_ok}))
    return 0 if lab.record["all_checks_pass"] and original_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
