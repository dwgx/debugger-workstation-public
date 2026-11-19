#!/usr/bin/env python3
"""Acceptance run for the original installed APKTool MCP wrapper.

The fixture is authored text only. The wrapper builds it with the installed
Apktool, decodes the resulting APK, and the runner compares exact decoded
smali/manifest/resource facts against the authored fixture. Raw JSON-RPC,
MCP error flags, Job-Object child cleanup, provider identities, and fixture
hashes are preserved. No APK is executed, installed, signed, or attached to
a device; no network or shared workspace is used.

Usage (client Python with pywin32):
  python run_apk_roundtrip.py \
    --station <owned-station-root> \
    --runs-root <external-evidence-parent> \
    --apktool-version <observed-installed-version>
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import apk_oracles as oracles  # noqa: E402


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def read_text(path: Path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        return None


def safe(fn, *args):
    try:
        return fn(*args)
    except Exception as error:
        return {"error": f"{type(error).__name__}: {error}"}


def posix(value) -> str:
    return (value or "").replace("\\", "/")


class CheckBook:
    def __init__(self):
        self.checks: dict[str, dict] = {}

    def check(self, name: str, actual, expected) -> bool:
        passed = actual == expected
        self.checks[name] = {"pass": passed, "actual": actual, "expected": expected}
        return passed

    def true(self, name: str, value, detail=None) -> bool:
        passed = bool(value)
        entry = {"pass": passed, "actual": bool(value)}
        if detail is not None:
            entry["detail"] = detail
        self.checks[name] = entry
        return passed

    def fail(self, name: str, detail) -> None:
        self.checks[name] = {"pass": False, "detail": detail}

    def failed(self) -> list[str]:
        return [name for name, entry in self.checks.items() if not entry["pass"]]

    @property
    def all_pass(self) -> bool:
        return bool(self.checks) and not self.failed()


def load_harness(public_source: Path):
    sys.path.insert(0, str(public_source))
    import catalog  # noqa: F401
    import common  # noqa: F401
    import lab_session  # noqa: F401
    return catalog, common, lab_session


def git_head(path: Path):
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.strip() or None
    except Exception:
        return None


def reserve_run(runs_root: Path) -> Path:
    runs_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = runs_root / f"{stamp}-{os.getpid()}"
    candidate = base
    suffix = 1
    while True:
        try:
            candidate.mkdir(exist_ok=False)
            return candidate
        except FileExistsError:
            suffix += 1
            candidate = runs_root / f"{base.name}-{suffix}"


def provider_identities(station: Path, apktool_version: str):
    wrapper = station / "MCP/bin/apktool-mcp.cmd"
    source = station / "MCP/apktool-mcp-server/apktool_mcp_server.py"
    jar = station / "Mobile-Android/Apktool/apktool.jar"
    venv = source.parent / ".venv"
    venv_python = venv / "Scripts/python.exe"
    framework = Path(os.environ.get("LOCALAPPDATA", "")) / "apktool/framework/1.apk"
    java = Path(shutil.which("java")) if shutil.which("java") else None

    versions = {}
    metadata = []
    for name in ("mcp", "fastmcp", "pydantic"):
        matches = list((venv / "Lib/site-packages").glob(name + "-*.dist-info/METADATA"))
        if len(matches) != 1:
            raise RuntimeError(f"provider metadata is absent or ambiguous: {name}")
        metadata.append(matches[0])
        version_line = next(
            (
                line.partition(": ")[2]
                for line in matches[0].read_text(encoding="utf-8").splitlines()
                if line.startswith("Version: ")
            ),
            None,
        )
        versions[name] = version_line

    paths = [wrapper, source, jar, venv_python, framework, *metadata]
    if java is not None:
        paths.append(java)
    identity = {
        str(path): oracles.digest_file(path)
        for path in paths
        if path is not None and path.is_file()
    }
    return {
        "wrapper": wrapper,
        "source": source,
        "jar": jar,
        "venv_python": venv_python,
        "framework": framework,
        "java": java,
        "metadata": metadata,
        "paths": [path for path in paths if path is not None],
        "identity": identity,
        "versions": versions,
    }


def authored_hashes(project: Path, files: dict[str, str]) -> dict[str, str]:
    return {
        relative: oracles.digest_file(project / relative)
        for relative in files
        if (project / relative).is_file()
    }


def write_fixture(workspace: Path, apktool_version: str) -> dict[str, str]:
    project = workspace / "LabApkProject"
    authored = oracles.write_authored_project(project, apktool_version)

    default_project = workspace / "DefaultFlagProject"
    for relative, text in authored.items():
        path = default_project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    not_a_project = workspace / "NotAProject"
    not_a_project.mkdir()
    (not_a_project / "AndroidManifest.xml").write_bytes(
        authored["AndroidManifest.xml"].encode("utf-8")
    )
    (workspace / "NotAnApk.apk").write_bytes(b"inert text, not a zip\n")
    (workspace / "Plain.txt").write_bytes(b"inert text\n")
    return authored


def payload(case) -> dict:
    value = case.get("payload")
    return value if isinstance(value, dict) else {}


def is_error(case):
    result = case.get("response", {}).get("result")
    return result.get("isError") if isinstance(result, dict) else None


def run_positive(lab, ctx: dict) -> None:
    workspace = ctx["workspace"]
    project = ctx["project"]
    built = ctx["built"]
    decoded = ctx["decoded"]
    authored = ctx["authored"]
    cases = ctx["cases"]
    timeout = ctx["timeout"]
    expected_version = ctx["apktool_version"]

    def call(method, arguments, case_id, call_timeout=None):
        case = lab.call(method, arguments, case_id, timeout=call_timeout)
        cases[case_id] = case
        return case

    c = call("health_check", {}, "health")
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "server_running", p.get("server_status"), "running")
    lab.check(c, "owned_workspace", p.get("workspace_dir"), str(workspace))
    lab.check(c, "workspace_exists", p.get("workspace_exists"), True)
    lab.check(c, "installed_cli_invoked", p.get("apktool_available"), True)
    lab.check(c, "installed_version", p.get("apktool_version"), expected_version)

    c = call("get_workspace_info", {}, "workspace-info")
    p = payload(c)
    info = p.get("workspace_info") or {}
    projects = {item.get("name"): item for item in info.get("projects", [])}
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "exact_workspace", info.get("workspace_path"), str(workspace))
    lab.check(
        c,
        "exact_project_names",
        sorted(projects),
        sorted(["LabApkProject", "DefaultFlagProject", "NotAProject"]),
    )
    lab.check(c, "lab_project_valid", projects.get("LabApkProject", {}).get("is_apktool_project"), True)
    lab.check(
        c,
        "default_flag_project_valid",
        projects.get("DefaultFlagProject", {}).get("is_apktool_project"),
        True,
    )
    lab.check(c, "not_a_project_invalid", projects.get("NotAProject", {}).get("is_apktool_project"), False)
    lab.check(c, "not_a_project_missing_yml", projects.get("NotAProject", {}).get("has_apktool_yml"), False)

    c = call("get_manifest", {"project_dir": str(project)}, "authored-manifest")
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "exact_authored_manifest", payload(c).get("manifest"), authored["AndroidManifest.xml"])

    c = call(
        "get_smali_file",
        {"project_dir": str(project), "class_name": oracles.CLASS_NAME},
        "authored-smali",
    )
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(
        c,
        "exact_authored_smali",
        payload(c).get("content"),
        authored["smali/lab/demo/MainActivity.smali"],
    )

    c = call(
        "get_resource_file",
        {"project_dir": str(project), "resource_type": "values", "resource_name": "strings.xml"},
        "authored-strings",
    )
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "exact_authored_strings", payload(c).get("content"), authored["res/values/strings.xml"])

    c = call(
        "get_resource_file",
        {"project_dir": str(project), "resource_type": "values", "resource_name": "colors.xml"},
        "authored-colors",
    )
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "exact_authored_colors", payload(c).get("content"), authored["res/values/colors.xml"])

    c = call(
        "search_in_files",
        {"project_dir": str(project), "search_pattern": oracles.ORACLE_LITERAL},
        "authored-search",
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "one_matching_file", (p.get("search_stats") or {}).get("files_matched"), 1)
    lab.check(
        c,
        "owned_class_hit",
        any(
            posix(item.get("file", "")).endswith("smali/lab/demo/MainActivity.smali")
            for item in p.get("results", [])
        ),
        True,
    )

    c = call(
        "build_apk",
        {
            "project_dir": str(project),
            "output_apk": str(built),
            "debug": False,
            "force_all": True,
            "timeout": timeout,
        },
        "build",
        timeout + 30,
    )
    p = payload(c)
    built_size = built.stat().st_size if built.is_file() else None
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "success", p.get("success"), True)
    lab.check(c, "returncode", p.get("returncode"), 0)
    lab.check(c, "apk_path", p.get("apk_path"), str(built))
    lab.check(c, "apk_size", p.get("apk_size"), built_size)
    lab.check(c, "artifact_exists", built.is_file(), True)
    lab.check(c, "cli_built_marker", "Built apk into" in (p.get("stdout") or ""), True)
    lab.check(c, "no_unrecognized_option", "Unrecognized option" in (p.get("stdout") or ""), False)

    c = call(
        "decode_apk",
        {
            "apk_path": str(built),
            "output_dir": str(decoded),
            "force": True,
            "timeout": timeout,
        },
        "decode",
        timeout + 30,
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "success", p.get("success"), True)
    lab.check(c, "returncode", p.get("returncode"), 0)
    lab.check(c, "output_dir", p.get("output_dir"), str(decoded))
    lab.check(c, "has_manifest", p.get("has_manifest"), True)
    lab.check(c, "has_apktool_yml", p.get("has_apktool_yml"), True)
    lab.check(c, "decoded_tree_exists", decoded.is_dir(), True)

    decoded_manifest = read_text(decoded / "AndroidManifest.xml")
    decoded_smali = read_text(decoded / "smali/lab/demo/MainActivity.smali")
    decoded_strings = read_text(decoded / "res/values/strings.xml")
    decoded_colors = read_text(decoded / "res/values/colors.xml")
    decoded_public = read_text(decoded / "res/values/public.xml")
    decoded_yml = read_text(decoded / "apktool.yml")

    c = call("get_manifest", {"project_dir": str(decoded)}, "decoded-manifest")
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "manifest_matches_file", p.get("manifest"), decoded_manifest)
    lab.check(
        c,
        "manifest_tree_exact",
        safe(oracles.manifest_tree, p.get("manifest") or ""),
        safe(oracles.manifest_tree, authored["AndroidManifest.xml"]),
    )
    lab.check(
        c,
        "manifest_facts_exact",
        safe(oracles.manifest_facts, p.get("manifest") or ""),
        {
            "package": oracles.PACKAGE_NAME,
            "application_label": "@string/lab_label",
            "activities": [".MainActivity"],
        },
    )

    c = call(
        "get_smali_file",
        {"project_dir": str(decoded), "class_name": oracles.CLASS_NAME},
        "decoded-smali",
    )
    p = payload(c)
    content = p.get("content") or ""
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "smali_matches_file", p.get("content"), decoded_smali)
    lab.check(
        c,
        "canonical_smali_exact",
        safe(oracles.canonical_smali, content),
        safe(oracles.canonical_smali, authored["smali/lab/demo/MainActivity.smali"]),
    )
    lab.check(c, "class_descriptor", oracles.CLASS_DESCRIPTOR in content, True)
    lab.check(c, "method_signature", oracles.METHOD_SIGNATURE in content, True)
    lab.check(
        c,
        "oracle_literal",
        f'const-string v0, "{oracles.ORACLE_LITERAL}"' in content,
        True,
    )

    c = call(
        "get_resource_file",
        {"project_dir": str(decoded), "resource_type": "values", "resource_name": "strings.xml"},
        "decoded-strings",
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "strings_match_file", p.get("content"), decoded_strings)
    lab.check(
        c,
        "strings_exact",
        safe(oracles.resource_values, p.get("content") or "", "string"),
        {"lab_label": "Owned lab", "lab_greeting": oracles.RESOURCE_LITERAL},
    )

    c = call(
        "get_resource_file",
        {"project_dir": str(decoded), "resource_type": "values", "resource_name": "colors.xml"},
        "decoded-colors",
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "colors_match_file", p.get("content"), decoded_colors)
    lab.check(
        c,
        "colors_exact",
        safe(oracles.resource_values, p.get("content") or "", "color"),
        {"lab_accent": "#112233"},
    )

    c = call(
        "get_resource_file",
        {"project_dir": str(decoded), "resource_type": "values", "resource_name": "public.xml"},
        "decoded-public",
    )
    p = payload(c)
    public = safe(oracles.public_resources, p.get("content") or "")
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "public_matches_file", p.get("content"), decoded_public)
    lab.check(
        c,
        "public_entries_exact",
        sorted((entry["type"], entry["name"]) for entry in public)
        if isinstance(public, list)
        else public,
        [("color", "lab_accent"), ("string", "lab_greeting"), ("string", "lab_label")],
    )
    ids = [entry["id"] for entry in public] if isinstance(public, list) else []
    lab.check(c, "public_ids_unique", len(set(ids)), 3)
    lab.check(
        c,
        "public_ids_package_7f",
        all(re.fullmatch(r"0x7f[0-9a-f]{6}", value or "") for value in ids),
        True,
    )

    c = call(
        "search_in_files",
        {"project_dir": str(decoded), "search_pattern": oracles.ORACLE_LITERAL},
        "decoded-search-code",
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "one_code_file", (p.get("search_stats") or {}).get("files_matched"), 1)
    lab.check(
        c,
        "code_literal_hit",
        any(
            posix(item.get("file", "")).endswith("smali/lab/demo/MainActivity.smali")
            for item in p.get("results", [])
        ),
        True,
    )

    c = call(
        "search_in_files",
        {"project_dir": str(decoded), "search_pattern": oracles.RESOURCE_LITERAL},
        "decoded-search-resource",
    )
    p = payload(c)
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "one_resource_file", (p.get("search_stats") or {}).get("files_matched"), 1)
    lab.check(
        c,
        "resource_literal_hit",
        any(
            posix(item.get("file", "")).endswith("res/values/strings.xml")
            for item in p.get("results", [])
        ),
        True,
    )

    c = call("get_apktool_yml", {"project_dir": str(decoded)}, "decoded-yml")
    p = payload(c)
    yml_facts = safe(oracles.apktool_yml_facts, p.get("content") or "")
    lab.check(c, "mcp_isError", is_error(c), False)
    lab.check(c, "yml_matches_file", p.get("content"), decoded_yml)
    lab.check(
        c,
        "yml_facts_exact",
        yml_facts,
        {
            "version": expected_version,
            "apk_file_name": "Built.apk",
            "min_sdk": "21",
            "target_sdk": "21",
            "framework_ids": ["1"],
        },
    )


def run_negative(lab, ctx: dict) -> None:
    workspace = ctx["workspace"]
    project = ctx["project"]
    outside = ctx["outside"]
    cases = ctx["cases"]
    timeout = ctx["timeout"]

    def call(method, arguments, case_id, call_timeout=None):
        case = lab.call(method, arguments, case_id, kind="negative", timeout=call_timeout)
        cases[case_id] = case
        return case

    def common(case):
        lab.check(case, "mcp_isError", is_error(case), True)
        lab.check(case, "success", payload(case).get("success"), False)

    missing_project = workspace / "MissingProject"
    c = call("build_apk", {"project_dir": str(missing_project)}, "negative-build-missing")
    common(c)
    lab.check(c, "exact_error", payload(c).get("error"), f"Path does not exist: {missing_project}")

    c = call(
        "build_apk",
        {"project_dir": str(workspace / "NotAProject")},
        "negative-build-no-yml",
    )
    common(c)
    lab.check(
        c,
        "exact_error",
        payload(c).get("error"),
        "apktool.yml not found. Is this a valid APKTool project?",
    )

    outside_apk = outside / "Out.apk"
    c = call(
        "build_apk",
        {"project_dir": str(project), "output_apk": str(outside_apk), "debug": False},
        "negative-build-outside-workspace",
    )
    common(c)
    lab.check(
        c,
        "exact_error",
        payload(c).get("error"),
        "Path must be within the workspace directory "
        f"({os.path.realpath(workspace)}). Resolved path: {os.path.realpath(outside_apk)}",
    )
    lab.check(c, "no_outside_artifact", outside_apk.exists(), False)

    default_apk = workspace / "DefaultFlag.apk"
    c = call(
        "build_apk",
        {
            "project_dir": str(workspace / "DefaultFlagProject"),
            "output_apk": str(default_apk),
            "timeout": timeout,
        },
        "negative-build-default-debug",
        timeout + 30,
    )
    common(c)
    p = payload(c)
    lab.check(c, "returncode", p.get("returncode"), 1)
    lab.check(
        c,
        "unrecognized_d",
        "Unrecognized option: -d" in ((p.get("stdout") or "") + (p.get("stderr") or "")),
        True,
    )
    lab.check(c, "exact_error", p.get("error"), "Command failed with return code 1")
    lab.check(c, "no_default_flag_artifact", default_apk.exists(), False)

    missing_apk = workspace / "Missing.apk"
    c = call("decode_apk", {"apk_path": str(missing_apk)}, "negative-decode-missing")
    common(c)
    lab.check(c, "exact_error", payload(c).get("error"), f"Path does not exist: {missing_apk}")

    c = call(
        "decode_apk",
        {"apk_path": str(workspace / "Plain.txt")},
        "negative-decode-wrong-extension",
    )
    common(c)
    lab.check(c, "exact_error", payload(c).get("error"), "File must have .apk or .xapk extension")

    invalid_out = workspace / "NotDecodedInvalid"
    c = call(
        "decode_apk",
        {
            "apk_path": str(workspace / "NotAnApk.apk"),
            "output_dir": str(invalid_out),
            "force": True,
            "timeout": timeout,
        },
        "negative-decode-invalid-content",
        timeout + 30,
    )
    common(c)
    p = payload(c)
    lab.check(c, "returncode", p.get("returncode"), 1)
    lab.check(c, "not_a_zip", "NotAZipFileException" in (p.get("stderr") or ""), True)
    lab.check(c, "exact_error", p.get("error"), "Command failed with return code 1")
    lab.check(c, "no_output_dir", invalid_out.exists(), False)

    outside_decoded = outside / "DecodedOutside"
    c = call(
        "decode_apk",
        {"apk_path": str(workspace / "NotAnApk.apk"), "output_dir": str(outside_decoded)},
        "negative-decode-outside-workspace",
    )
    common(c)
    lab.check(
        c,
        "exact_error",
        payload(c).get("error"),
        "Path must be within the workspace directory "
        f"({os.path.realpath(workspace)}). Resolved path: {os.path.realpath(outside_decoded)}",
    )
    lab.check(c, "no_outside_decoded", outside_decoded.exists(), False)

    c = call(
        "get_smali_file",
        {"project_dir": str(project), "class_name": "lab.demo.Missing"},
        "negative-smali-missing",
    )
    common(c)
    lab.check(c, "exact_error", payload(c).get("error"), "Smali file not found for class: lab.demo.Missing")
    lab.check(c, "searched_dirs", payload(c).get("searched_dirs"), ["smali"])

    missing_resource = project / "res/values/missing.xml"
    c = call(
        "get_resource_file",
        {
            "project_dir": str(project),
            "resource_type": "values",
            "resource_name": "missing.xml",
        },
        "negative-resource-missing",
    )
    common(c)
    lab.check(
        c,
        "exact_error",
        payload(c).get("error"),
        f"Resource file not found: {missing_resource}",
    )
    lab.check(c, "expected_path", payload(c).get("expected_path"), str(missing_resource))


def execute(args, run: Path, result: dict, book: CheckBook, log_lines: list[str]) -> None:
    def log(message: str) -> None:
        line = f"[{utc()}] {message}"
        log_lines.append(line)
        print(line, flush=True)

    station = args.station.resolve()
    public_source = args.public_source.resolve()
    if not station.is_dir():
        raise RuntimeError(f"station is not a directory: {station}")
    if not public_source.is_dir():
        raise RuntimeError(f"public source is not a directory: {public_source}")

    catalog, common, lab_session = load_harness(public_source)

    workspace = run / "workspace"
    temp = run / "temp"
    outside = run / "outside"
    workspace.mkdir()
    temp.mkdir()
    outside.mkdir()

    project = workspace / "LabApkProject"
    built = workspace / "Built.apk"
    decoded = workspace / "DecodedBuilt"
    authored = write_fixture(workspace, args.apktool_version)
    authored_before = authored_hashes(project, authored)
    default_before = authored_hashes(workspace / "DefaultFlagProject", authored)
    workspace_before = oracles.snapshot_tree(workspace)

    wrapper = station / "MCP/bin/apktool-mcp.cmd"
    wrapper_text = wrapper.read_text(encoding="utf-8-sig")
    book.check(
        "wrapper_preserves_owned_workspace",
        'if not defined APKTOOL_WORKSPACE set "APKTOOL_WORKSPACE=' in wrapper_text
        and '--workspace "%APKTOOL_WORKSPACE%"' in wrapper_text,
        True,
    )

    provider = provider_identities(station, args.apktool_version)
    provider_identity = provider["identity"]
    book.check("java_available", provider["java"] is not None and provider["java"].is_file(), True)
    book.check("framework_available", provider["framework"].is_file(), True)
    book.check("apktool_jar_available", provider["jar"].is_file(), True)
    book.check("wrapper_available", wrapper.is_file(), True)
    book.check("provider_source_available", provider["source"].is_file(), True)
    book.check("provider_venv_available", provider["venv_python"].is_file(), True)

    harness_paths = [
        public_source / "catalog.py",
        public_source / "common.py",
        public_source / "lab_session.py",
        public_source / "raw_mcp.py",
        HERE / "apk_oracles.py",
        Path(__file__).resolve(),
    ]
    harness_identity = {
        str(path): oracles.digest_file(path) for path in harness_paths if path.is_file()
    }
    book.check("harness_modules_available", len(harness_identity), len(harness_paths))

    result["source_identities"] = {
        "station": str(station),
        "station_git_head": git_head(station),
        "public_source": str(public_source),
        "public_git_head": git_head(public_source.parent.parent),
        "wrapper": str(wrapper),
        "wrapper_sha256": oracles.digest_file(wrapper) if wrapper.is_file() else None,
        "server_source": str(provider["source"]),
        "server_source_sha256": oracles.digest_file(provider["source"])
        if provider["source"].is_file()
        else None,
        "apktool_jar": str(provider["jar"]),
        "apktool_jar_sha256": oracles.digest_file(provider["jar"])
        if provider["jar"].is_file()
        else None,
        "java": str(provider["java"]) if provider["java"] else None,
        "java_sha256": oracles.digest_file(provider["java"])
        if provider["java"] is not None and provider["java"].is_file()
        else None,
        "venv_python": str(provider["venv_python"]),
        "venv_python_sha256": oracles.digest_file(provider["venv_python"])
        if provider["venv_python"].is_file()
        else None,
        "framework": str(provider["framework"]),
        "framework_sha256": oracles.digest_file(provider["framework"])
        if provider["framework"].is_file()
        else None,
        "installed_distribution_versions": provider["versions"],
        "provider_metadata": {
            str(path): oracles.digest_file(path) for path in provider["metadata"] if path.is_file()
        },
        "harness_modules": harness_identity,
        "runner_sha256": oracles.digest_file(Path(__file__).resolve()),
        "oracle_module_sha256": oracles.digest_file(HERE / "apk_oracles.py"),
        "client_python": sys.executable,
        "client_python_version": sys.version,
        "platform": platform.platform(),
        "pywin32_available": True,
    }

    plan = {
        "schema": "tool-lab-apk-roundtrip-plan/1",
        "task": result["task"],
        "created_utc": utc(),
        "station": str(station),
        "public_source": str(public_source),
        "wrapper": str(wrapper),
        "provider_inputs": provider_identity,
        "installed_distribution_versions": provider["versions"],
        "authored_fixture_sha256": authored_before,
        "workspace_before": workspace_before,
        "expected": {
            "apktool_version": args.apktool_version,
            "package": oracles.PACKAGE_NAME,
            "class": oracles.CLASS_NAME,
            "oracle_literal": oracles.ORACLE_LITERAL,
            "resource_literal": oracles.RESOURCE_LITERAL,
            "apk_entries": list(oracles.REQUIRED_APK_ENTRIES),
            "manifest_magic": oracles.AXML_MAGIC,
            "dex_magic": oracles.DEX_MAGIC,
            "arsc_magic": oracles.ARSC_MAGIC,
        },
        "scope": (
            "One successful build_apk (debug=false) and one successful decode_apk through "
            "the original installed wrapper; exact decoded smali/manifest/resource facts; "
            "ten pre-CLI or CLI-failure negatives; raw JSON-RPC; Job cleanup; no APK "
            "execution, device, network, user target, or shared workspace."
        ),
    }
    write_json(run / "PLAN.json", plan)
    result["plan_sha256"] = oracles.digest_file(run / "PLAN.json")

    env = common.no_mcp_env()
    env.update(
        {
            "APKTOOL_WORKSPACE": str(workspace),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "TEMP": str(temp),
            "TMP": str(temp),
            "TMPDIR": str(temp),
        }
    )
    argv = [
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
        "/d",
        "/v:off",
        "/c",
        "call",
        str(wrapper),
    ]

    session_dir = run / "session"
    cases: dict[str, dict] = {}
    ctx = {
        "workspace": workspace,
        "project": project,
        "built": built,
        "decoded": decoded,
        "outside": outside,
        "authored": authored,
        "cases": cases,
        "timeout": args.timeout,
        "apktool_version": args.apktool_version,
    }

    log(f"run={run}")
    log(f"station={station}")
    log(f"public_source={public_source}")
    log(f"workspace={workspace}")
    try:
        with lab_session.LabSession(
            "apktool",
            argv,
            str(run),
            env,
            session_dir,
            "original installed station wrapper",
            timeout=30,
        ) as lab:
            log(f"catalog_tools={len(lab.record['tools'])}")
            try:
                run_positive(lab, ctx)
            except BaseException as error:
                result["positive_phase_error"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                }
                log(f"positive_phase_error={type(error).__name__}: {error}")
            after_positives = oracles.snapshot_tree(workspace)
            try:
                run_negative(lab, ctx)
            except BaseException as error:
                result["negative_phase_error"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                }
                log(f"negative_phase_error={type(error).__name__}: {error}")
            after_negatives = oracles.snapshot_tree(workspace)
    except BaseException as error:
        result["session_start_error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "traceback": traceback.format_exc(),
        }
        log(f"session_start_error={type(error).__name__}: {error}")
        after_positives = oracles.snapshot_tree(workspace)
        after_negatives = after_positives

    result["fixture"] = {
        "authored_sha256": authored_before,
        "default_flag_project_sha256": default_before,
        "workspace_before": workspace_before,
        "workspace_after_positives": after_positives,
        "workspace_after_negatives": after_negatives,
        "built_apk_sha256": oracles.digest_file(built) if built.is_file() else None,
        "decoded_tree_sha256": {
            name: value
            for name, value in after_negatives.items()
            if name.startswith("DecodedBuilt/") and value != "directory"
        },
    }

    session_results = None
    session_results_path = session_dir / "RESULTS.json"
    if session_results_path.is_file():
        try:
            session_results = json.loads(session_results_path.read_text(encoding="utf-8"))
        except Exception as error:
            book.fail("session_results_readable", f"{type(error).__name__}: {error}")
    else:
        book.fail("session_results_present", str(session_results_path))

    if session_results is not None:
        book.check("session_all_checks_pass", session_results.get("all_checks_pass"), True)
        book.check("session_wire_protocol_clean", session_results.get("wire_protocol_clean"), True)
        cleanup = session_results.get("cleanup") or {}
        book.check("cleanup_observed_ok", cleanup.get("observed_cleanup_ok"), True)
        book.check("cleanup_tree_empty", cleanup.get("tree_empty_after_close"), True)
        book.check(
            "cleanup_job_active_zero",
            (cleanup.get("job_after_terminate") or {}).get("accounting", {}).get("ActiveProcesses"),
            0,
        )
        book.check("cleanup_no_survivors", cleanup.get("survivor_pids"), [])
        book.check("cleanup_no_known_survivors", cleanup.get("known_snapshot_survivors"), [])
        book.check("cleanup_no_observation_errors", cleanup.get("observation_errors"), [])
        result["session"] = {
            "results_path": str(session_results_path),
            "results_sha256": oracles.digest_file(session_results_path),
            "raw_sha256": session_results.get("raw_sha256"),
            "all_checks_pass": session_results.get("all_checks_pass"),
            "wire_protocol_clean": session_results.get("wire_protocol_clean"),
            "stdout_noise": session_results.get("stdout_noise"),
            "unique_methods_called": session_results.get("unique_methods_called"),
            "unique_positive_methods": session_results.get("unique_positive_methods"),
            "catalog_methods": [tool.get("name") for tool in session_results.get("tools", [])],
            "calls": [
                {
                    "case_id": case.get("case_id"),
                    "method": case.get("method"),
                    "kind": case.get("kind"),
                    "status": case.get("status"),
                    "isError": case.get("mcp_error_flag"),
                    "protocol_flag_consistent": case.get("protocol_flag_consistent"),
                    "elapsed_seconds": case.get("elapsed_seconds"),
                    "arguments": case.get("arguments"),
                    "failed_checks": {
                        name: entry
                        for name, entry in case.get("checks", {}).items()
                        if not entry.get("pass")
                    },
                    "error": case.get("error"),
                }
                for case in session_results.get("cases", [])
            ],
            "cleanup": {
                "observed_cleanup_ok": cleanup.get("observed_cleanup_ok"),
                "tree_empty_after_close": cleanup.get("tree_empty_after_close"),
                "job_after_terminate": cleanup.get("job_after_terminate"),
                "survivor_pids": cleanup.get("survivor_pids"),
                "known_snapshot_survivors": cleanup.get("known_snapshot_survivors"),
                "observation_errors": cleanup.get("observation_errors"),
                "returncode": cleanup.get("returncode"),
            },
        }
        result["methods_called"] = sorted(
            {case.get("method") for case in session_results.get("cases", []) if case.get("method")}
        )
        called = set(result["methods_called"])
        result["methods_not_called"] = sorted(
            {
                tool.get("name")
                for tool in session_results.get("tools", [])
                if tool.get("name") and tool.get("name") not in called
            }
        )
    else:
        result["methods_called"] = []
        result["methods_not_called"] = []

    authored_after = authored_hashes(project, authored)
    default_after = authored_hashes(workspace / "DefaultFlagProject", authored)
    book.check("authored_project_unchanged", authored_after, authored_before)
    book.check("default_flag_project_unchanged", default_after, default_before)
    book.check("negative_calls_leave_workspace_unchanged", after_negatives, after_positives)

    provider_after = {
        str(path): oracles.digest_file(path)
        for path in provider["paths"]
        if path is not None and path.is_file()
    }
    book.check("provider_inputs_unchanged", provider_after, provider_identity)

    harness_after = {
        str(path): oracles.digest_file(path) for path in harness_paths if path.is_file()
    }
    book.check("harness_inputs_unchanged", harness_after, harness_identity)

    book.check("built_apk_exists", built.is_file(), True)
    apk = {"error": "built APK missing"}
    if built.is_file():
        try:
            apk = oracles.apk_facts(built)
        except Exception as error:
            apk = {"error": f"{type(error).__name__}: {error}"}
            book.fail("apk_readable", apk["error"])
        else:
            book.check("apk_zip_test", apk["zip_test"], None)
            book.check(
                "apk_entry_names",
                sorted(apk["names"]),
                sorted(oracles.REQUIRED_APK_ENTRIES),
            )
            book.check("apk_manifest_magic", apk["manifest_magic"], oracles.AXML_MAGIC)
            book.check("apk_dex_magic", apk["dex_magic"], oracles.DEX_MAGIC)
            book.check("apk_arsc_magic", apk["arsc_magic"], oracles.ARSC_MAGIC)
            book.check("apk_dex_oracle_literal", apk["dex_has_oracle_literal"], True)
            book.check("apk_arsc_resource_literal", apk["arsc_has_resource_literal"], True)
            build_payload = payload(cases.get("build", {}))
            book.check("apk_size_matches_provider", apk["size"], build_payload.get("apk_size"))
            book.check("apk_path_matches_provider", apk["path"], build_payload.get("apk_path"))

    decoded_facts = {"error": "decoded tree missing"}
    if decoded.is_dir():
        try:
            decoded_facts = oracles.decoded_facts(decoded, apk)
        except Exception as error:
            decoded_facts = {"error": f"{type(error).__name__}: {error}"}
            book.fail("decoded_tree_readable", decoded_facts["error"])
        else:
            expected_files = [
                "AndroidManifest.xml",
                "apktool.yml",
                "original/AndroidManifest.xml",
                "res/values/colors.xml",
                "res/values/public.xml",
                "res/values/strings.xml",
                "smali/lab/demo/MainActivity.smali",
            ]
            book.check(
                "decoded_file_set",
                sorted(decoded_facts["file_sha256"]),
                sorted(expected_files),
            )
            book.check(
                "decoded_smali_file_set",
                decoded_facts["smali_files"],
                ["smali/lab/demo/MainActivity.smali"],
            )
            book.check(
                "decoded_canonical_smali",
                decoded_facts["canonical_smali"],
                oracles.canonical_smali(authored["smali/lab/demo/MainActivity.smali"]),
            )
            book.check(
                "decoded_manifest_tree",
                decoded_facts["manifest_tree"],
                oracles.manifest_tree(authored["AndroidManifest.xml"]),
            )
            book.check(
                "decoded_manifest_facts",
                decoded_facts["manifest_facts"],
                {
                    "package": oracles.PACKAGE_NAME,
                    "application_label": "@string/lab_label",
                    "activities": [".MainActivity"],
                },
            )
            book.check(
                "decoded_strings",
                decoded_facts["strings"],
                {"lab_label": "Owned lab", "lab_greeting": oracles.RESOURCE_LITERAL},
            )
            book.check("decoded_colors", decoded_facts["colors"], {"lab_accent": "#112233"})
            book.check(
                "decoded_public_entries",
                sorted((entry["type"], entry["name"]) for entry in decoded_facts["public"]),
                [("color", "lab_accent"), ("string", "lab_greeting"), ("string", "lab_label")],
            )
            book.check("decoded_public_ids_unique", decoded_facts["public_ids_unique"], True)
            book.check(
                "decoded_public_ids_package_7f",
                decoded_facts["public_ids_package_7f"],
                True,
            )
            book.check(
                "decoded_yml",
                decoded_facts["apktool_yml"],
                {
                    "version": args.apktool_version,
                    "apk_file_name": "Built.apk",
                    "min_sdk": "21",
                    "target_sdk": "21",
                    "framework_ids": ["1"],
                },
            )
            book.check(
                "decoded_original_manifest_matches_apk",
                decoded_facts["original_manifest_matches_apk"],
                True,
            )

            book.check(
                "mcp_manifest_matches_file",
                payload(cases.get("decoded-manifest", {})).get("manifest"),
                read_text(decoded / "AndroidManifest.xml"),
            )
            book.check(
                "mcp_smali_matches_file",
                payload(cases.get("decoded-smali", {})).get("content"),
                read_text(decoded / "smali/lab/demo/MainActivity.smali"),
            )
            book.check(
                "mcp_strings_matches_file",
                payload(cases.get("decoded-strings", {})).get("content"),
                read_text(decoded / "res/values/strings.xml"),
            )
            book.check(
                "mcp_colors_matches_file",
                payload(cases.get("decoded-colors", {})).get("content"),
                read_text(decoded / "res/values/colors.xml"),
            )
            book.check(
                "mcp_public_matches_file",
                payload(cases.get("decoded-public", {})).get("content"),
                read_text(decoded / "res/values/public.xml"),
            )
            book.check(
                "mcp_yml_matches_file",
                payload(cases.get("decoded-yml", {})).get("content"),
                read_text(decoded / "apktool.yml"),
            )

    result["independent_oracles"] = {"apk": apk, "decoded": decoded_facts}
    result["acceptance"] = {
        "all_checks_pass": book.all_pass
        and session_results is not None
        and bool(session_results.get("all_checks_pass")),
        "independent_checks_pass": book.all_pass,
        "session_checks_pass": bool(session_results and session_results.get("all_checks_pass")),
        "checks": book.checks,
        "failed": book.failed(),
    }

    blockers = [
        {"scope": "independent", "check": name, **book.checks[name]} for name in book.failed()
    ]
    if session_results is not None:
        for case in session_results.get("cases", []):
            if case.get("status") not in ("positive_pass", "expected_rejection"):
                blockers.append(
                    {
                        "scope": "session",
                        "case_id": case.get("case_id"),
                        "method": case.get("method"),
                        "status": case.get("status"),
                        "isError": case.get("mcp_error_flag"),
                        "failed_checks": {
                            name: entry
                            for name, entry in case.get("checks", {}).items()
                            if not entry.get("pass")
                        },
                        "error": case.get("error"),
                    }
                )
    result["blockers"] = blockers
    result["corrections"] = [
        {
            "id": "framework-binding",
            "observed_failure": (
                "aapt2 link reported 'attribute android:label not found' because the authored "
                "apktool.yml had no usesFramework.ids, so apktool passed no -I framework file"
            ),
            "minimal_correction": "authored apktool.yml now declares usesFramework.ids: [1]",
            "evidence": "exploration/first-fail-build-no-usesframework.log",
        },
        {
            "id": "debug-flag",
            "observed_failure": "apktool 3.0.3 rejects build_apk's default debug=True because it appends -d",
            "minimal_correction": "successful build_apk call passes debug=false",
            "evidence": "negative-build-default-debug in session/RESULTS.json",
        },
    ]
    result["finished_utc"] = utc()
    result["all_checks_pass"] = result["acceptance"]["all_checks_pass"]

    log(f"session_all_checks_pass={result['acceptance']['session_checks_pass']}")
    log(f"independent_checks_pass={result['acceptance']['independent_checks_pass']}")
    log(f"all_checks_pass={result['all_checks_pass']}")
    for blocker in blockers:
        log(f"blocker={json.dumps(blocker, ensure_ascii=False)}")

    write_json(run / "RESULT.json", result)
    (run / "run.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--station", type=Path, required=True)
    parser.add_argument("--public-source", type=Path, default=HERE)
    parser.add_argument("--runs-root", type=Path, required=True, help="external directory; each run is unique")
    parser.add_argument("--apktool-version", required=True, help="observed version, e.g. 3.0.3")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    run_parent = args.runs_root.resolve()
    station_root, source_root = args.station.resolve(), args.public_source.resolve()
    if run_parent == station_root or station_root in run_parent.parents:
        parser.error("--runs-root may not be inside the station")
    if run_parent == source_root or source_root in run_parent.parents:
        parser.error("--runs-root may not be inside the source")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-\w.]*)?", args.apktool_version):
        parser.error("--apktool-version must be an observed semantic version")
    run = reserve_run(run_parent)
    result = {
        "schema": "tool-lab-apk-roundtrip/1",
        "task": "WS-APK-POSITIVE-20261120-01",
        "started_utc": utc(),
        "run_dir": str(run),
        "all_checks_pass": False,
    }
    book = CheckBook()
    log_lines: list[str] = []
    try:
        execute(args, run, result, book, log_lines)
    except BaseException as error:
        result["runner_error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "traceback": traceback.format_exc(),
        }
        result["acceptance"] = {
            "all_checks_pass": False,
            "independent_checks_pass": book.all_pass,
            "session_checks_pass": False,
            "checks": book.checks,
            "failed": book.failed(),
        }
        result["blockers"] = [
            {"scope": "independent", "check": name, **book.checks[name]} for name in book.failed()
        ]
        result["finished_utc"] = utc()
        result["all_checks_pass"] = False
        write_json(run / "RESULT.json", result)
        print(json.dumps({"run_dir": str(run), "error": result["runner_error"]}, indent=2))
        return 2

    print(
        json.dumps(
            {
                "run_dir": str(run),
                "all_checks_pass": result.get("all_checks_pass"),
                "acceptance": {
                    "independent_checks_pass": result["acceptance"]["independent_checks_pass"],
                    "session_checks_pass": result["acceptance"]["session_checks_pass"],
                },
                "blockers": result.get("blockers", []),
                "result_json": str(run / "RESULT.json"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.get("all_checks_pass") else 2


if __name__ == "__main__":
    raise SystemExit(main())
