#!/usr/bin/env python3
"""Caller-side example: freeze the selected pcap CLI plan, without running it.

Save the printed expected_plan_sha256 in the caller's audit record BEFORE the
runner starts. Do not read the expected value back from a receipt or terminal.
This script creates a benign synthetic PCAP and uses no network or dependencies.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import uuid

sys.dont_write_bytecode = True
FILES = ["scripts/assert-probes.py", "scripts/verify-profile.py", "scripts/runner_evidence.py",
         "scripts/probe_artifact.py", "schemas/run-receipt.v3.json", "net-reverse/tools/pcap_reader.py"]


def packet():
    dns = struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x01a\x07example\x00\x00\x01\x00\x01"
    udp = struct.pack("!4H", 12000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 53]))
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", (~checksum) & 65535) + ip[12:]
    frame = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + udp
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new caller-owned external directory")
    parser.add_argument("--source-commit", required=True, help="pinned provenance, NOT a claim that this install contains .git")
    parser.add_argument("--source-repo", help="caller-reviewed source identity; defaults to the measured absolute source directory")
    parser.add_argument("--attempt-id", default="attempt-" + uuid.uuid4().hex)
    parser.add_argument("--parent-terminal", type=Path)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    if args.source_repo is not None and not args.source_repo.strip():
        parser.error("--source-repo must not be empty")
    if out.is_relative_to(source):
        parser.error("--out must be external to the source tree")
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("runner_evidence_freeze", source / "scripts/runner_evidence.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    target = out / "one-dns-query.pcap"
    target.write_bytes(packet())
    source_manifest = out / "source-manifest.json"
    write(source_manifest, helper.freeze_source_manifest(source, FILES, args.source_commit, True))
    checks = [
        {"id": "I-OUTPUT", "kind": "integrity"},
        {"id": "E-EXIT", "kind": "execution", "expected_exit": 0},
        {"id": "S-OK", "kind": "semantic", "pointer": "/ok", "expected": True},
        {"id": "S-PACKETS", "kind": "semantic", "pointer": "/packets", "expected": 1},
        {"id": "S-DNS", "kind": "semantic", "pointer": "/dns_queries", "expected": 1},
        {"id": "N-WRONG", "kind": "negative", "pointer": "/packets", "expected": 2},
    ]
    oracle = out / "pcap-oracle.json"
    write(oracle, {"oracle_version": "bounded-cli-oracle.1", "parser": "json-object@1", "checks": checks})
    parent = None
    if args.parent_terminal:
        terminal = args.parent_terminal.resolve()
        doc = helper.load_json(terminal)
        parent = {"attempt_id": doc["attempt_id"], "terminal_path": str(terminal), "terminal_sha256": helper.sha256_file(terminal)}
    plan = {
        "plan_version": "debugger-run-plan.1", "run_id": "run-pcap-" + uuid.uuid4().hex,
        "attempt_id": args.attempt_id, "parent_attempt": parent,
        "source": {"kind": "manifest-snapshot", "root": str(source), "repo": args.source_repo or str(source),
                   "commit": args.source_commit, "dirty": True, "manifest_path": str(source_manifest),
                   "manifest_sha256": helper.sha256_file(source_manifest)},
        "runtime": helper.python_identity(),
        "tool": {"path": "net-reverse/tools/pcap_reader.py", **helper.identity(source / "net-reverse/tools/pcap_reader.py")},
        "target": {"path": str(target), **helper.identity(target), "kind": "synthetic-pcap", "fixture_id": "one-dns-query-pcap@1"},
        "profile": {"id": "bounded-cli-pcap-structure", "version": "1", "capability_id": "net.pcap.selfparse",
                    "limitations": ["One explicitly authored PCAP, parser-only. No capture, reassembly, TLS, real network or provider validation."]},
        "oracle": {"path": str(oracle), "sha256": helper.sha256_file(oracle)},
        "required_case_ids": [check["id"] for check in checks], "checks_total": len(checks), "required_steps": helper.STEPS,
        "run_root": str(out / "runs"),
        "execution": {"argv": ["{python}", "-I", "-B", "{tool}", "{target}"], "timeout_s": 15, "cancel_file": None},
        "outputs": ["artifacts/net-reverse/out/last-run-pcap_reader.json"],
    }
    plan_path = out / "run-plan.json"
    write(plan_path, plan)
    expected = helper.sha256_file(plan_path)
    helper.plan_and_oracle(plan_path, expected)
    terminal = out / "runs" / "attempts" / args.attempt_id / "terminal.json"
    commands = {
        "plan": str(plan_path), "expected_plan_sha256": expected, "checks_total": len(checks),
        "runner_argv": [sys.executable, "-X", "utf8", "-B", str(source / "scripts/assert-probes.py"), "--plan", str(plan_path), "--expected-plan-sha256", expected],
        "verifier_argv": [sys.executable, "-X", "utf8", "-B", str(source / "scripts/verify-profile.py"), "--product", "--plan", str(plan_path), "--expected-plan-sha256", expected, "--runner-terminal", str(terminal)],
    }
    write(out / "caller-freeze.json", commands)
    print(json.dumps(commands, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
