#!/usr/bin/env python3
"""One-command, provider-free PCAP product demo with frozen-plan verification.

Requires Python >= 3.12; makes a new owned directory outside the source tree.
No network traffic, driver, GUI, external MCP service or real packet capture.
Each subprocess is invoked by an exact argv, never a shell command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

SOURCE_FILE = Path(__file__).resolve()
EXPECTED_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
FILES = (
    "scripts/freeze-pcap-plan.py",
    "scripts/assert-probes.py",
    "scripts/verify-profile.py",
    "scripts/runner_evidence.py",
    "scripts/probe_artifact.py",
    "schemas/run-receipt.v3.json",
    "net-reverse/tools/pcap_reader.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_json_exclusive(path: Path, obj: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def observed_git_revision(source: Path) -> str | None:
    try:
        a = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        b = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    try:
        top = Path(a.stdout.strip()).resolve()
    except (OSError, ValueError):
        return None
    commit = b.stdout.strip()
    return commit if top == source and COMMIT_RE.fullmatch(commit) else None


def validated_commands(source: Path, out: Path, data: dict) -> tuple[list[str], list[str], str]:
    """Fail closed if the generated dispatcher arguments are not the reviewed shape."""
    digest = data.get("expected_plan_sha256")
    if not isinstance(digest, str) or not EXPECTED_RE.fullmatch(digest):
        raise ValueError("invalid frozen plan digest")
    plan = out / "run-plan.json"
    if "sha256:" + sha256(plan.read_bytes()) != digest:
        raise ValueError("plan digest does not match caller freeze")
    expected_runner = [
        sys.executable, "-X", "utf8", "-B",
        str(source / "scripts/assert-probes.py"),
        "--plan", str(plan), "--expected-plan-sha256", digest,
    ]
    attempt = json.loads(plan.read_text(encoding="utf-8")).get("attempt_id")
    if not isinstance(attempt, str) or not re.fullmatch(r"attempt-[0-9a-f]{32}", attempt):
        raise ValueError("invalid generated attempt ID")
    terminal = out / "runs" / "attempts" / attempt / "terminal.json"
    expected_verifier = [
        sys.executable, "-X", "utf8", "-B",
        str(source / "scripts/verify-profile.py"), "--product",
        "--plan", str(plan), "--expected-plan-sha256", digest,
        "--runner-terminal", str(terminal),
    ]
    if data.get("runner_argv") != expected_runner:
        raise ValueError("runner argv differs from reviewed frozen contract")
    if data.get("verifier_argv") != expected_verifier:
        raise ValueError("verifier argv differs from reviewed frozen contract")
    return expected_runner, expected_verifier, digest


def run_owned(label: str, argv: list[str], out: Path, timeout: int) -> dict:
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, shell=False)
        code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as error:
        code = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        timed_out = True
    for channel, blob in (("stdout", stdout), ("stderr", stderr)):
        with (out / f"{label}.{channel}.bin").open("xb") as stream:
            stream.write(blob)
    return {
        "label": label,
        "argv": argv,
        "exit_code": code,
        "timed_out": timed_out,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256(stdout),
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256(stderr),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_FILE.parent.parent)
    parser.add_argument("--output", type=Path, required=True, help="NEW folder outside source")
    parser.add_argument("--source-commit", help="40-hex provenance for a ZIP without Git")
    parser.add_argument("--source-repo", help="caller-reviewed optional repository identity")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    if source == out or source in out.parents:
        parser.error("--output must be outside the source tree")
    if out.exists():
        parser.error("--output already exists; never overwrite a previous run")
    if any(not (source / name).is_file() for name in FILES):
        parser.error("missing required runner/fixture source files")
    observed_commit = observed_git_revision(source)
    commit = args.source_commit or observed_commit
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        parser.error("provide --source-commit on a non-Git source release")
    if args.source_commit and observed_commit and args.source_commit != observed_commit:
        parser.error("provided commit conflicts with the observed checkout HEAD")
    before = {name: sha256((source / name).read_bytes()) for name in FILES}
    freeze_argv = [
        sys.executable, "-X", "utf8", "-B",
        str(source / "scripts/freeze-pcap-plan.py"),
        "--source", str(source), "--out", str(out),
        "--source-commit", commit,
    ]
    if args.source_repo:
        freeze_argv.extend(["--source-repo", args.source_repo])
    # The freeze script owns creating this directory exclusively.
    freeze = subprocess.run(freeze_argv, capture_output=True, timeout=40, shell=False)
    if freeze.returncode:
        # It may fail before creating the folder; retain diagnostics when it exists.
        if out.is_dir():
            (out / "freeze.stdout.bin").write_bytes(freeze.stdout)
            (out / "freeze.stderr.bin").write_bytes(freeze.stderr)
        print("FREEZE_FAIL", freeze.returncode, freeze.stderr.decode("utf-8", "replace")[-600:])
        return 1
    (out / "freeze.stdout.bin").write_bytes(freeze.stdout)
    (out / "freeze.stderr.bin").write_bytes(freeze.stderr)
    summary = {
        "schema": "workstation-first-success/1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(source),
        "source_revision": commit,
        "git_revision_observed": observed_commit == commit,
        "source_repo_supplied": args.source_repo,
        "python": sys.executable,
        "source_sha256_before": before,
        "stages": [],
        "verdict": "FAIL",
    }
    try:
        frozen = json.loads((out / "caller-freeze.json").read_text(encoding="utf-8"))
        runner, verifier, digest = validated_commands(source, out, frozen)
        summary["frozen_plan_sha256"] = digest
        save_json_exclusive(out / "CONTROLLER-INTENT.json", {
            "schema": "workstation-first-success-intent/1",
            "plan_sha256": digest,
            "source_revision": commit,
            "runner_argv": runner,
            "verifier_argv": verifier,
            "source_sha256_before": before,
        })
        first = run_owned("runner", runner, out, 90)
        summary["stages"].append(first)
        second = run_owned("verifier", verifier, out, 45)
        summary["stages"].append(second)
        after = {name: sha256((source / name).read_bytes()) for name in FILES}
        summary["source_unchanged"] = after == before
        summary["terminal_present"] = Path(verifier[-1]).is_file()
        summary["verdict"] = "PROFILE_PASS" if (
            first["exit_code"] == 0 and second["exit_code"] == 0
            and not first["timed_out"] and not second["timed_out"]
            and summary["source_unchanged"] and summary["terminal_present"]
        ) else "FAIL"
    except (ValueError, OSError, json.JSONDecodeError) as error:
        summary["error_type"] = type(error).__name__
        summary["error"] = str(error)
    finally:
        save_json_exclusive(out / "FIRST-SUCCESS.json", summary)
    print(json.dumps({
        "verdict": summary["verdict"],
        "plan_sha256": summary.get("frozen_plan_sha256"),
        "summary": str(out / "FIRST-SUCCESS.json"),
        "stage_exit_codes": [s["exit_code"] for s in summary["stages"]],
    }, ensure_ascii=False))
    return 0 if summary["verdict"] == "PROFILE_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
