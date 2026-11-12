#!/usr/bin/env python3
"""Exercise bootstrap from a real ZIP in PS 5.1/7; never mutate --source.

This is a bounded installation contract, not workstation/capability acceptance.
No CloneMcp, pip, binary download, global config, or existing install is used.
Each invocation requires a fresh output root and retains every case and raw log.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

sys.dont_write_bytecode = True
FIXTURE = "evidence/profile-receipts/retry-preserves-failure/artifacts/attempt-1-failure.log"
V2_FIXTURE = "evidence/profile-receipts/attempts/attempt-20261112-101/failure.log"
MANIFEST = "manifests/installation-closure.v1.json"
HELPER = "scripts/installation-closure.ps1"
RELEASE = "releases/2026-11-11-full-library"
# Independent, user-visible contract. This is deliberately NOT read from the
# production manifest: removing a requirement there cannot shrink these checks.
READBACK = (
    "LICENSE", "LICENSE-docs", "AGENTS.md", "README.md", "locales.json",
    "docs/AI_ENTRY.md", "docs/AI_ENTRY.zh-CN.md", "docs/BOOTSTRAP.md",
    "schemas/run-receipt.v1.json", "schemas/run-receipt.v2.json",
    "schemas/run-receipt.v3.json", FIXTURE,
    "evidence/profile-receipts/retry-preserves-failure.json",
    "evidence/profile-receipts/oracle-public-core-demo.json",
    ".agent/HANDOFF.md", ".agent/RECOVERY-STATION.md", ".agent/success-when.md",
    f"{RELEASE}/README.md", f"{RELEASE}/RELEASE-GATE-STATUS.md",
    f"{RELEASE}/PACKAGE-MANIFEST.tsv", f"{RELEASE}/SATURATION.tsv",
    f"{RELEASE}/learning-kit/LICENSE-NOTE.md",
    "skills/2026-11-11/portable-core/LICENSE",
    "skills/2026-11-11/portable-core/references/INSTALL.md",
    "scripts/assert-probes.py", "scripts/verify-profile.py",
    "scripts/runner_evidence.py", "scripts/probe_artifact.py",
    "net-reverse/tools/pcap_reader.py", MANIFEST, HELPER,
    "scripts/freeze-pcap-plan.py", "docs/CURRENT-CLI-PROFILE.md",
)
BASE_NEGATIVE_CASES = (
    ("missing_license", "LICENSE", "MISSING_REQUIRED"),
    ("missing_schemas", "schemas", "MISSING_REQUIRED"),
    ("missing_retry_log", FIXTURE, "MISSING_REQUIRED"),
    ("missing_handoff", ".agent/HANDOFF.md", "MISSING_REQUIRED"),
    ("missing_release_gate", f"{RELEASE}/RELEASE-GATE-STATUS.md", "MISSING_REQUIRED"),
    ("missing_mcp_template", "mcp/.mcp.json.template", "MISSING_REQUIRED"),
    ("missing_manifest", MANIFEST, "MISSING_REQUIRED"),
    ("empty_schema", "schemas/run-receipt.v2.json", "EMPTY_REQUIRED"),
)
BASE_PER_SHELL_CASES = (
    "shell_version", "dry_run_readonly", "apply_exit", "required_bytes",
    "project_config", "installed_entry_gate", "installed_package_gate",
    "installed_retry_diagnostic", "installed_source_independent",
    "recursive_cache_exclusion",
) + tuple(row[0] for row in BASE_NEGATIVE_CASES)
NEGATIVE_CASES = BASE_NEGATIVE_CASES + (
    ("missing_v2_retry_log", V2_FIXTURE, "MISSING_REQUIRED"),
    ("missing_plan_freezer", "scripts/freeze-pcap-plan.py", "MISSING_REQUIRED"),
)
PER_SHELL_CASES = BASE_PER_SHELL_CASES + (
    "installed_v2_retry_diagnostic", "missing_v2_retry_log", "missing_plan_freezer")
BASE_REQUIRED_CASES = ["package/retry_log_preserved", "package/unrelated_log_ignored"] + [
    sid + "/" + case for sid in ("ps51", "ps7") for case in BASE_PER_SHELL_CASES]
V2_APPENDED_REQUIRED_CASES = ["package/v2_retry_log_preserved"] + [
    sid + "/" + case for sid in ("ps51", "ps7")
    for case in ("installed_v2_retry_diagnostic", "missing_v2_retry_log")]
INHERITED_REQUIRED_CASES = BASE_REQUIRED_CASES + V2_APPENDED_REQUIRED_CASES
APPENDED_REQUIRED_CASES = [sid + "/missing_plan_freezer" for sid in ("ps51", "ps7")]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*"))
            if p.is_file() and ".git" not in p.relative_to(root).parts}


def command(argv: list[str], cwd: Path, logs: Path, label: str, timeout: int = 90) -> dict:
    started = time.monotonic()
    env = os.environ.copy()
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
        error = None
    except subprocess.TimeoutExpired as exc:
        code, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
        error = "COMMAND_TIMEOUT"
    except OSError as exc:
        code, stdout, stderr, error = None, b"", str(exc).encode("utf-8"), "COMMAND_UNAVAILABLE"
    logs.mkdir(parents=True, exist_ok=True)
    out, err = logs / (label + ".stdout.bin"), logs / (label + ".stderr.bin")
    out.write_bytes(stdout)
    err.write_bytes(stderr)
    return {"argv": argv, "cwd": str(cwd), "exit": code, "error": error,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout_path": str(out), "stdout_sha256": sha(out),
            "stderr_path": str(err), "stderr_sha256": sha(err),
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace")}


def bootstrap(shell: str, release: Path, install: Path, cwd: Path,
              logs: Path, label: str, apply: bool) -> dict:
    argv = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(release / "scripts/bootstrap.ps1"),
            "-InstallRoot", str(install), "-SkipTools", "-SkipRouterVenv",
            "-UiLanguage", "zh-CN"]
    if apply:
        argv.append("-Apply")
    return command(argv, cwd, logs, label)


def parse_preflight(result: dict) -> list[dict]:
    records = []
    for line in (result["stdout"] + "\n" + result["stderr"]).splitlines():
        if line.startswith("INSTALL_CLOSURE="):
            try:
                records.append(json.loads(line.partition("=")[2]))
            except ValueError:
                pass
    return records


def bytes_check(source: Path, installed: Path) -> list[dict]:
    failures = []
    for rel in READBACK:
        a, b = source / rel, installed / rel
        if not a.is_file():
            failures.append({"path": rel, "reason": "absent_from_source"})
        elif not b.is_file():
            failures.append({"path": rel, "reason": "absent_from_install"})
        elif a.read_bytes() != b.read_bytes():
            failures.append({"path": rel, "reason": "bytes_differ",
                             "source_sha256": sha(a), "install_sha256": sha(b)})
    return failures


def build_zip(source: Path, out: Path, logs: Path) -> tuple[Path, dict]:
    # Existing repository inventory preserves tracked author files, including
    # previously tracked ignored paths. For a byte snapshot use an external empty
    # git-dir, so .gitignore is still applied without writing into --source.
    if (source / ".git").exists():
        prefix = ["git", "-C", str(source)]
        kind = "repository_tracked_and_untracked_authored_files"
    else:
        git_dir = out / "inventory.git"
        init = command(["git", "init", "--bare", str(git_dir)], out, logs, "git-init")
        if init["exit"] != 0:
            raise RuntimeError("Cannot create external git inventory; see git-init logs")
        prefix = ["git", "--git-dir", str(git_dir), "--work-tree", str(source)]
        kind = "snapshot_unignored_files_external_git_dir"
    p = subprocess.run(prefix + ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                       cwd=out, capture_output=True, check=True)
    names = sorted(set(n.decode("utf-8") for n in p.stdout.split(b"\0") if n))
    archive = out / "release.zip"
    records = []
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in names:
            path = source / rel
            if not path.is_file() or path.is_symlink():
                continue
            z.write(path, rel)
            records.append({"path": rel, "sha256": sha(path), "bytes": path.stat().st_size})
    return archive, {"kind": kind, "file_count": len(records), "files": records,
                     "sha256": sha(archive)}


def extract(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            p = Path(name)
            if p.is_absolute() or ".." in p.parts or ":" in name:
                raise ValueError("Unsafe ZIP member: " + name)
        z.extractall(destination)


def run_shell(shell_id: str, shell: str, archive: Path, source: Path, out: Path,
              add) -> None:
    area = out / shell_id
    area.mkdir()
    cwd = area / "foreign cwd"
    cwd.mkdir()
    release = area / "发行包 中文 空格"
    extract(archive, release)
    install = area / "安装 中文 空格"
    logs = area / "logs"
    version = command([shell, "-NoProfile", "-NonInteractive", "-Command",
                       "$PSVersionTable.PSVersion.ToString()"], cwd, logs, "version")
    expected = "5.1." if shell_id == "ps51" else "7."
    add(shell_id, "shell_version", version["exit"] == 0 and version["stdout"].strip().startswith(expected), version)
    before = inventory(release)
    dry = bootstrap(shell, release, install, cwd, logs, "dry", False)
    add(shell_id, "dry_run_readonly", dry["exit"] == 0 and not install.exists()
        and inventory(release) == before, {"command": dry, "install_exists": install.exists()})
    apply = bootstrap(shell, release, install, cwd, logs, "apply", True)
    add(shell_id, "apply_exit", apply["exit"] == 0, apply)
    failures = bytes_check(source, install)
    add(shell_id, "required_bytes", not failures, {"files_checked": len(READBACK), "failures": failures})
    config_errors = []
    for rel in ("MCP/.mcp.json", ".mcp.json", ".cursor/mcp.json", "local.json"):
        try:
            obj = json.loads((install / rel).read_text(encoding="utf-8"))
            if rel == "local.json" and Path(obj["install_root"]).resolve() != install.resolve():
                config_errors.append({"path": rel, "reason": "wrong_install_root"})
            if "{{DEBUGGER_ROOT}}" in json.dumps(obj):
                config_errors.append({"path": rel, "reason": "unrendered_template"})
        except (OSError, ValueError, KeyError) as exc:
            config_errors.append({"path": rel, "reason": str(exc)})
    add(shell_id, "project_config", not config_errors, {"failures": config_errors})
    # Hide the only extracted source used by bootstrap. All commands below name
    # installed files and run from a foreign cwd. They cannot resolve into release.
    hidden = area / "retained source unavailable"
    release.rename(hidden)
    for case, script in (
        ("installed_entry_gate", "skills/2026-11-11/portable-core/tests/entry_checks.py"),
        ("installed_package_gate", "skills/2026-11-11/portable-core/verify.py"),
    ):
        result = command([sys.executable, "-X", "utf8", "-B", str(install / script)], cwd, logs, case)
        add(shell_id, case, result["exit"] == 0 and "VERDICT=PASS" in result["stdout"], result)
    diagnostic = command([
        sys.executable, "-X", "utf8", "-B", str(install / "scripts/verify-profile.py"),
        "--schema", str(install / "schemas/run-receipt.v1.json"),
        "--receipt", str(install / "evidence/profile-receipts/retry-preserves-failure.json"),
        "--oracle", str(install / "evidence/profile-receipts/oracle-public-core-demo.json"),
        "--artifact-root", str(install / "evidence/profile-receipts"),
    ], cwd, logs, "installed-retry-diagnostic")
    add(shell_id, "installed_retry_diagnostic", diagnostic["exit"] == 0
        and "VERDICT=PROFILE_PASS" in diagnostic["stdout"], diagnostic)
    v2_diagnostic = command([
        sys.executable, "-X", "utf8", "-B", str(install / "scripts/verify-profile.py"),
        "--schema", str(install / "schemas/run-receipt.v2.json"),
        "--receipt", str(install / "evidence/profile-receipts/v2-retry-preserves-failure.json"),
        "--oracle", str(install / "evidence/profile-receipts/oracle/public-core-demo-retry.anchor.json"),
        "--artifact-root", str(install / "evidence/profile-receipts"),
    ], cwd, logs, "installed-v2-retry-diagnostic")
    add(shell_id, "installed_v2_retry_diagnostic", v2_diagnostic["exit"] == 0
        and "VERDICT=PROFILE_PASS" in v2_diagnostic["stdout"], v2_diagnostic)
    second = area / "再次安装 中文 空格"
    standalone = bootstrap(shell, install, second, cwd, logs, "standalone", True)
    standalone_failures = bytes_check(source, second)
    add(shell_id, "installed_source_independent", standalone["exit"] == 0 and not standalone_failures,
        {"command": standalone, "failures": standalone_failures})
    hidden.rename(release)
    # Real, nested contamination in a separate copy catches top-level-only
    # exclusion. The final ZIP itself remains byte-for-byte unchanged.
    polluted = area / "cache-control-source"
    extract(archive, polluted)
    pollution = (
        "scripts/closure-control/deep/__pycache__/probe.pyc",
        "scripts/closure-control/deep/orphan.pyc",
        "scripts/closure-control/deep/orphan.pyo",
        "skills/closure-control/deep/.venv/marker.txt",
        "docs/closure-control/deep/.git/marker.txt",
        "templates/closure-control/deep/node_modules/marker.txt",
        "manifests/closure-control/deep/.pytest_cache/marker.txt",
    )
    for rel in pollution:
        p = polluted / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"synthetic installer cache control\n")
    clean = area / "cache-control-install"
    result = bootstrap(shell, polluted, clean, cwd, logs, "cache-control", True)
    leaked = [rel for rel in pollution if (clean / rel).exists()]
    add(shell_id, "recursive_cache_exclusion", result["exit"] == 0 and not leaked,
        {"command": result, "leaked": leaked})
    for case, rel, code in NEGATIVE_CASES:
        broken = area / (case + "-source")
        extract(archive, broken)
        target = broken / rel
        if case.startswith("empty_"):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"")
        elif target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        rejected = area / (case + "-install")
        result = bootstrap(shell, broken, rejected, cwd, logs, case, True)
        records = parse_preflight(result)
        errors = [e for record in records for e in record.get("errors", [])]
        reported = any(e.get("code") == code and
                       (e.get("path") == rel or e.get("path", "").startswith(rel + "/"))
                       for e in errors)
        add(shell_id, case, result["exit"] not in (None, 0) and not rejected.exists() and reported,
            {"command": result, "install_exists": rejected.exists(), "preflight": records,
             "expected_code": code, "expected_path": rel})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--release-zip", type=Path,
                        help="Use the caller's actual packaged copy, with --source as byte oracle")
    parser.add_argument("--shell", action="append", default=[], metavar="ID=PATH",
                        help="Explicit ps51=... or ps7=...; defaults to installed commands")
    parser.add_argument("--package-only", action="store_true",
                        help="Package controls only; never reports the Windows contract as PASS")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output_root.resolve()
    if out.exists():
        parser.error("--output-root already exists; retain it and choose a fresh attempt")
    if source == out or source in out.parents:
        parser.error("--output-root must be outside --source")
    if not (source / "scripts/bootstrap.ps1").is_file():
        parser.error("--source is not a bootstrap source tree")
    out.mkdir(parents=True)
    results = []
    report = {"contract": "installation-closure.3", "platform": sys.platform,
              "source": str(source), "source_bootstrap_sha256": sha(source / "scripts/bootstrap.ps1"),
              "test_driver_sha256": sha(Path(__file__)), "cases": results,
              "limits": ["Layout and script closure only; no third-party binaries or router venv installed",
                         "Legacy receipt check is diagnostic, never product acceptance",
                         "No source repository, global agent config, or existing install is modified"]}

    def add(shell_id, case, ok, details):
        item = {"id": shell_id + "/" + case, "status": "PASS" if ok else "FAIL", "details": details}
        results.append(item)
        print(item["id"] + "=" + item["status"], flush=True)
        (out / "report.partial.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.release_zip:
        archive = out / "release.zip"
        shutil.copyfile(args.release_zip, archive)
        packaged = {"kind": "caller_provided_zip", "sha256": sha(archive)}
    else:
        archive, packaged = build_zip(source, out, out / "package-logs")
    report["package"] = packaged
    with zipfile.ZipFile(archive) as z:
        names = set(z.namelist())
        fixture_in_zip = FIXTURE in names and (source / FIXTURE).is_file()
        fixture_matches = fixture_in_zip and z.read(FIXTURE) == (source / FIXTURE).read_bytes()
    add("package", "retry_log_preserved", fixture_matches, {"path": FIXTURE, "present": fixture_in_zip})
    with zipfile.ZipFile(archive) as z:
        v2_in_zip = V2_FIXTURE in set(z.namelist()) and (source / V2_FIXTURE).is_file()
        v2_matches = v2_in_zip and z.read(V2_FIXTURE) == (source / V2_FIXTURE).read_bytes()
    add("package", "v2_retry_log_preserved", v2_matches, {"path": V2_FIXTURE, "present": v2_in_zip})
    # Check an unrelated log in an isolated throwaway repository, not in source.
    ignore_root = out / "ignore-control"
    ignore_root.mkdir()
    shutil.copyfile(source / ".gitignore", ignore_root / ".gitignore")
    command(["git", "init", "--quiet"], ignore_root, out / "package-logs", "ignore-init")
    unrelated_logs = ("unrelated.log",
                      "evidence/profile-receipts/retry-preserves-failure/artifacts/unrelated.log",
                      "evidence/profile-receipts/attempts/attempt-20261112-101/unrelated.log")
    ignore = command(["git", "check-ignore", "--no-index", *unrelated_logs], ignore_root,
                     out / "package-logs", "unrelated-log")
    add("package", "unrelated_log_ignored", ignore["exit"] == 0
        and set(ignore["stdout"].splitlines()) == set(unrelated_logs), ignore)
    if args.package_only:
        report["required_case_ids"] = ["package/retry_log_preserved", "package/unrelated_log_ignored", "package/v2_retry_log_preserved"]
        report["contract"] = "installation-package-control.2"
        report["windows_contract"] = "NOT_RUN"
    else:
        report["inherited_contract"] = "installation-closure.2"
        report["inherited_checks_total"] = len(INHERITED_REQUIRED_CASES)
        report["inherited_required_case_ids"] = INHERITED_REQUIRED_CASES
        report["historical_contracts"] = [
            {"contract": "installation-closure.1", "checks_total": len(BASE_REQUIRED_CASES),
             "required_case_ids": BASE_REQUIRED_CASES},
            {"contract": "installation-closure.2", "checks_total": len(INHERITED_REQUIRED_CASES),
             "required_case_ids": INHERITED_REQUIRED_CASES,
             "frozen_driver_sha256": "cc4b8544a5b3dd6de44e116dc2fc9e9fa77ab142d5509742045d5cd3e380d6a2"},
        ]
        report["appended_required_case_ids"] = APPENDED_REQUIRED_CASES
        report["required_case_ids"] = INHERITED_REQUIRED_CASES + APPENDED_REQUIRED_CASES
        report["readback_additions"] = ["scripts/freeze-pcap-plan.py", "docs/CURRENT-CLI-PROFILE.md"]
        report["test_correction"] = {
            "case_ids": ["ps51/installed_retry_diagnostic", "ps7/installed_retry_diagnostic"],
            "reason": "Fixture paths are relative to receipt.dirname, not install root; use installed evidence/profile-receipts as artifact-root",
            "frozen_v1_driver_sha256": "e8d714e50fef524fd0c5bd1cf799217af1b96da634942fe3403d751efaaef3f9",
            "expected_verdict_unchanged": "PROFILE_PASS",
        }
        shells = {"ps51": shutil.which("powershell.exe"), "ps7": shutil.which("pwsh.exe") or shutil.which("pwsh")}
        for item in args.shell:
            sid, sep, value = item.partition("=")
            if not sep or sid not in shells:
                parser.error("--shell must be ps51=PATH or ps7=PATH")
            shells[sid] = value
        for sid in ("ps51", "ps7"):
            if shells[sid] is None or os.name != "nt":
                for case in PER_SHELL_CASES:
                    results.append({"id": sid + "/" + case, "status": "BLOCKED",
                                    "details": {"reason": "Required Windows PowerShell runtime unavailable"}})
                continue
            try:
                run_shell(sid, shells[sid], archive, source, out, add)
            except Exception as exc:
                seen = {r["id"] for r in results}
                for case in PER_SHELL_CASES:
                    if sid + "/" + case not in seen:
                        results.append({"id": sid + "/" + case, "status": "BLOCKED",
                                        "details": {"reason": "Test driver error", "error": repr(exc)}})
    required = set(report["required_case_ids"])
    actual = {r["id"] for r in results}
    report["checks_total"] = len(required)
    report["checks_observed"] = len(results)
    report["denominator_complete"] = actual == required and len(actual) == len(results)
    report["counts"] = {s: sum(r["status"] == s for r in results) for s in ("PASS", "FAIL", "BLOCKED")}
    report["verdict"] = "PASS" if report["denominator_complete"] and all(r["status"] == "PASS" for r in results) else "FAIL"
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("REPORT=" + str(out / "report.json"))
    print("VERDICT=" + report["verdict"])
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
