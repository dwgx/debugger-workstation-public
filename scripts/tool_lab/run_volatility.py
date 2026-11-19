#!/usr/bin/env python3
"""Check Volatility's original wrapper metadata; no genuine RAM-image claim."""
import argparse
import json
import os
from pathlib import Path

from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from lab_session import LabSession


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--candidate-root", type=Path, help="Explicit isolated source directory")
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    (out / "temp").mkdir()
    fixture = out / "owned-metadata-placeholder.bin"
    fixture.write_bytes(b"TOOLLAB_METADATA_ONLY_NOT_A_RAM_IMAGE\n")
    wrapper = station / "MCP/bin/volatility3-mcp.cmd"
    source_root = station / "MCP/volatility3-mcp"
    route = "original wrapper"
    if args.candidate_root:
        source_root = args.candidate_root.resolve()
        route = "isolated source candidate"
    sources = {str(p): digest(p) for p in (source_root / "bridge_mcp_volatility.py", source_root / "vol_wrapper.py")}
    argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
    if args.candidate_root:
        argv = [str(station / "MCP/volatility3-mcp/.venv/Scripts/python.exe"), "-X", "utf8", "-B", str(source_root / "bridge_mcp_volatility.py")]
    env = no_mcp_env()
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(out / "temp"), "TMP": str(out / "temp")})
    plan = {"schema": "tool-lab-volatility-metadata/1", "wrapper": str(wrapper), "wrapper_sha256": digest(wrapper), "provider_sources": sources,
            "fixture_sha256": digest(fixture), "runner_sha256": digest(Path(__file__)),
            "scope": "Authored placeholder establishes file-existence precondition only. Plugin list/docs are metadata; no OS detection, plugin analysis, symbol download, host memory, or private image access."}
    write_json(out / "PLAN.json", plan)
    with LabSession("volatility3", argv, out, env, out / "session", route, timeout=35) as lab:
        c = lab.call("initialize_memory_file", {"file_path": str(out / "missing-owned.bin")}, "missing-image", kind="negative")
        lab.check(c, "missing_image_rejected", "Memory file not found:" in str(c["payload"]), True)
        c = lab.call("initialize_memory_file", {"file_path": str(fixture)}, "metadata-context-only")
        lab.check(c, "file_precondition_acknowledged", c["payload"], "Successfully initialized Volatility3 with memory file: " + str(fixture))
        c = lab.call("list_plugins", {}, "available-plugin-metadata")
        values = c["payload"]
        # FastMCP serializes the list as one content item per string.
        if isinstance(values, str):
            values = [x.get("text") for x in c["response"].get("result", {}).get("content", []) if x.get("type") == "text"]
        lab.check(c, "windows_pslist_present", isinstance(values, list) and "windows.pslist.PsList" in values, True)
        lab.check(c, "linux_pslist_present", isinstance(values, list) and "linux.pslist.PsList" in values, True)
        c = lab.call("get_plugin_info", {"plugin_name": "windows.pslist.PsList"}, "known-plugin-description")
        lab.check(c, "known_upstream_description", c["payload"], "Lists the processes present in a particular windows memory image.")
    unchanged = digest(fixture) == plan["fixture_sha256"] and digest(wrapper) == plan["wrapper_sha256"] and all(digest(Path(p)) == sha for p, sha in sources.items())
    final = {"all_checks_pass": lab.record["all_checks_pass"] and unchanged, "source_and_fixture_unchanged": unchanged,
             "memory_forensics_validated": False, "limitation": "No valid public or Owner-authorized RAM image used; metadata only.",
             "session_results_sha256": digest(out / "session/RESULTS.json"), "methods_called": lab.record["unique_methods_called"], "positive_methods": lab.record["unique_positive_methods"]}
    write_json(out / "FINAL.json", final)
    print(json.dumps(final))
    return 0 if final["all_checks_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
