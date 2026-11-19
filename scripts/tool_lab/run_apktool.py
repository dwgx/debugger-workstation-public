#!/usr/bin/env python3
"""Check the original APKTool wrapper with owned inert project metadata.

Run on Windows with the tool-lab client's existing pywin32 environment:
  python scripts/tool_lab/run_apktool.py --station STATION --output NEW_DIRECTORY

Five positive calls inspect authored text and the installed CLI version. Seven
negative calls must reject missing owned inputs before decoding, building,
writing, or cleaning anything. No APK is executed; no shared workspace is used.
The existing LabSession preserves raw RPCs, checks MCP isError semantics, and
observes stdout and owned Job cleanup. An existing output directory is refused.
"""
import argparse
import json
import os
from pathlib import Path
import re

import catalog
import common
import lab_session
import raw_mcp
from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from lab_session import LabSession


def build_project(workspace):
    """Create only inert text; no downloaded APK, runtime or executable fixture."""
    project = workspace / "LabApkProject"
    (project / "smali/lab/demo").mkdir(parents=True)
    (project / "res/values").mkdir(parents=True)
    manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="lab.demo"><application android:label="Owned lab"><activity android:name=".MainActivity" /></application></manifest>\n'
    smali = '.class public Llab/demo/MainActivity;\n.super Ljava/lang/Object;\n.method public static labValue()Ljava/lang/String;\n    .registers 1\n    const-string v0, "APK_ORACLE_2b9c"\n    return-object v0\n.end method\n'
    (project / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    (project / "apktool.yml").write_text("version: 2.12.0\napkFileName: LabFixture.apk\nsdkInfo:\n  minSdkVersion: '21'\n", encoding="utf-8")
    (project / "smali/lab/demo/MainActivity.smali").write_text(smali, encoding="utf-8")
    return project, manifest, smali


def snapshot_tree(root):
    """Include names as well as bytes, so a refused mutation cannot add files."""
    return {p.relative_to(root).as_posix(): digest(p) if p.is_file() else "directory"
            for p in sorted(root.rglob("*"))}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    workspace = out / "workspace"
    project, manifest, smali = build_project(workspace)
    wrapper = station / "MCP/bin/apktool-mcp.cmd"
    text = wrapper.read_text(encoding="utf-8-sig")
    if 'if not defined APKTOOL_WORKSPACE set "APKTOOL_WORKSPACE=' not in text or '--workspace "%APKTOOL_WORKSPACE%"' not in text:
        raise RuntimeError("original wrapper cannot preserve this owned workspace")
    source = station / "MCP/apktool-mcp-server/apktool_mcp_server.py"
    jar = station / "Mobile-Android/Apktool/apktool.jar"
    venv = source.parent / ".venv"
    identity_paths = [wrapper, source, jar, venv / "Scripts/python.exe"]
    versions = {}
    for name in ("mcp", "fastmcp", "pydantic"):
        matches = list((venv / "Lib/site-packages").glob(name + "-*.dist-info/METADATA"))
        if len(matches) != 1:
            raise RuntimeError("provider metadata is absent or ambiguous: " + name)
        identity_paths.append(matches[0])
        versions[name] = next(line.partition(": ")[2] for line in matches[0].read_text(encoding="utf-8").splitlines() if line.startswith("Version: "))
    before = snapshot_tree(workspace)
    plan = {"schema": "tool-lab-authored-apktool/1", "wrapper": str(wrapper),
            "provider_inputs": {str(p): digest(p) for p in identity_paths},
            "installed_distribution_versions": versions, "fixture_tree": before,
            "harness_inputs": {str(Path(m.__file__).resolve()): digest(Path(m.__file__))
                               for m in (catalog, common, lab_session, raw_mcp)},
            "runner_sha256": digest(Path(__file__)),
            "scope": "Five positive metadata/version calls and seven missing-input refusals. No APK execution, successful decode/build, GUI, network or shared workspace."}
    write_json(out / "PLAN.json", plan)
    (out / "temp").mkdir()
    env = no_mcp_env()
    env.update({"APKTOOL_WORKSPACE": str(workspace), "PYTHONDONTWRITEBYTECODE": "1",
                "TEMP": str(out / "temp"), "TMP": str(out / "temp")})
    argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
    print(json.dumps({"output": str(out), "plan_sha256": digest(out / "PLAN.json")}), flush=True)
    with LabSession("apktool", argv, out, env, out / "session", "original wrapper", timeout=30) as lab:
        c = lab.call("health_check", {}, "owned-apktool-health")
        lab.check(c, "server_running", c["payload"].get("server_status"), "running")
        lab.check(c, "owned_workspace", c["payload"].get("workspace_dir"), str(workspace))
        lab.check(c, "installed_cli_invoked", c["payload"].get("apktool_available"), True)
        lab.check(c, "version_syntax", bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-\w.]*)?", c["payload"].get("apktool_version", ""))), True)
        c = lab.call("get_workspace_info", {}, "only-owned-project")
        data = c["payload"].get("workspace_info", {})
        lab.check(c, "exact_workspace", data.get("workspace_path"), str(workspace))
        lab.check(c, "exact_project_names", [p["name"] for p in data.get("projects", [])], ["LabApkProject"])
        c = lab.call("get_manifest", {"project_dir": str(project)}, "exact-authored-manifest")
        lab.check(c, "manifest", c["payload"].get("manifest"), manifest)
        c = lab.call("get_smali_file", {"project_dir": str(project), "class_name": "lab.demo.MainActivity"}, "exact-authored-smali")
        lab.check(c, "smali", c["payload"].get("content"), smali)
        c = lab.call("search_in_files", {"project_dir": str(project), "search_pattern": "APK_ORACLE_2b9c"}, "known-literal-search")
        lab.check(c, "one_matching_file", c["payload"].get("search_stats", {}).get("files_matched"), 1)
        lab.check(c, "owned_class_hit", any("MainActivity.smali" in x.get("file", "") for x in c["payload"].get("results", [])), True)

        missing = str(workspace / "MissingProject")
        missing_apk = str(workspace / "Missing.apk")
        missing_resource = str(project / "res/values/missing.xml")
        negative = [
            ("get_manifest", {"project_dir": missing}, "missing-owned-project", "Path does not exist: " + missing),
            ("get_resource_file", {"project_dir": str(project), "resource_type": "values", "resource_name": "missing.xml"}, "missing-owned-resource", "Resource file not found: " + missing_resource),
            ("decode_apk", {"apk_path": missing_apk}, "missing-owned-apk", "Path does not exist: " + missing_apk),
            ("build_apk", {"project_dir": missing}, "missing-project-build", "Path does not exist: " + missing),
            ("clean_project", {"project_dir": missing, "backup": True}, "missing-project-clean", "Path does not exist: " + missing),
            ("modify_smali_file", {"project_dir": missing, "class_name": "lab.demo.MainActivity", "new_content": "// inert and never written", "create_backup": True}, "missing-project-smali-write", "Path does not exist: " + missing),
            ("modify_resource_file", {"project_dir": missing, "resource_type": "values", "resource_name": "missing.xml", "new_content": "inert and never written", "create_backup": True}, "missing-project-resource-write", "Path does not exist: " + missing),
        ]
        for method, arguments, case_id, expected_error in negative:
            c = lab.call(method, arguments, case_id, kind="negative")
            data = c["payload"] if isinstance(c["payload"], dict) else {}
            lab.check(c, "explicit_non_success", data.get("success"), False)
            lab.check(c, "exact_owned_path_rejection", data.get("error"), expected_error)
            lab.check(c, "workspace_names_and_bytes_unchanged", snapshot_tree(workspace), before)
    provider_unchanged = all(p.is_file() and digest(p) == plan["provider_inputs"][str(p)] for p in identity_paths)
    fixture_unchanged = snapshot_tree(workspace) == before
    harness_unchanged = all(digest(Path(p)) == value for p, value in plan["harness_inputs"].items()) and digest(Path(__file__)) == plan["runner_sha256"]
    final = {"all_checks_pass": lab.record["all_checks_pass"] and provider_unchanged and fixture_unchanged and harness_unchanged,
             "provider_inputs_unchanged": provider_unchanged, "fixture_names_and_bytes_unchanged": fixture_unchanged,
             "harness_inputs_unchanged": harness_unchanged,
             "calls": len(lab.record["cases"]), "positive_calls": sum(c["kind"] == "positive" for c in lab.record["cases"]),
             "negative_calls": sum(c["kind"] == "negative" for c in lab.record["cases"]),
             "methods_called": lab.record["unique_methods_called"], "positive_methods": lab.record["unique_positive_methods"],
             "runtime_catalog_methods": len(lab.record["tools"]), "stdout_audit": lab.record["stdout_audit"],
             "failed_cases": [{"case_id": c["case_id"], "status": c["status"], "isError": c["mcp_error_flag"]}
                              for c in lab.record["cases"] if c["status"] not in ("positive_pass", "expected_rejection")],
             "session_results_sha256": digest(out / "session/RESULTS.json")}
    write_json(out / "FINAL.json", final)
    print(json.dumps(final))
    return 0 if final["all_checks_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
