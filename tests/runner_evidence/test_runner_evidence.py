#!/usr/bin/env python3
"""Bounded runner behavior and adversarial tests, using real child processes.

The pcap tests invoke the existing product parser on explicitly authored packet
bytes. Remaining subprocess tests use fixture_cli.py and make no provider claim.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2]
EVIDENCE = None
CORE = ["scripts/assert-probes.py", "scripts/verify-profile.py", "scripts/runner_evidence.py",
        "scripts/probe_artifact.py", "schemas/run-receipt.v3.json", "net-reverse/tools/pcap_reader.py",
        "tests/runner_evidence/fixture_cli.py"]
HEAD = "cead32200a692d454b354a84562f619db0de1ef0"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def put(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def one_packet_pcap():
    dns = struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x01a\x07example\x00\x00\x01\x00\x01"
    udp = struct.pack("!4H", 12000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 53]))
    total = sum(struct.unpack("!10H", ip))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    ip = ip[:10] + struct.pack("!H", (~total) & 65535) + ip[12:]
    frame = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + udp
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame


class Harness:
    def __init__(self, root, source=SOURCE, copy_source=True):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.source = self.root / "source" if copy_source else Path(source).resolve()
        if copy_source:
            for name in CORE:
                dest = self.source / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(source) / name, dest)
        self.helper = module(self.source / "scripts/runner_evidence.py", "runner_helper_" + self.root.name.replace("-", "_"))
        self.manifest = self.root / "source-manifest.json"
        put(self.manifest, self.helper.freeze_source_manifest(self.source, CORE, HEAD, True))
        self.runs = self.root / "runs"

    def freeze(self, attempt="attempt-one", mode="good", tool="fixture", parent=None, timeout=3, cancel=None,
               expected=7, target_bytes=None):
        oracle_path = self.root / (attempt + "-oracle.json")
        target = self.root / (attempt + "-target.bin")
        if tool == "pcap":
            target.write_bytes(one_packet_pcap() if target_bytes is None else target_bytes)
            relative = "net-reverse/tools/pcap_reader.py"
            checks = [{"id": "I-OUTPUT", "kind": "integrity"}, {"id": "E-EXIT", "kind": "execution", "expected_exit": 0},
                      {"id": "S-OK", "kind": "semantic", "pointer": "/ok", "expected": True},
                      {"id": "S-PACKETS", "kind": "semantic", "pointer": "/packets", "expected": 1},
                      {"id": "S-DNS", "kind": "semantic", "pointer": "/dns_queries", "expected": 1},
                      {"id": "N-WRONG", "kind": "negative", "pointer": "/packets", "expected": 2}]
            outputs = ["artifacts/net-reverse/out/last-run-pcap_reader.json"]
            extra = []
            profile_id, capability, kind = "bounded-cli-pcap-structure", "net.pcap.selfparse", "synthetic-pcap"
        else:
            if target_bytes is None:
                put(target, {"value": 7})
            else:
                target.write_bytes(target_bytes)
            relative = "tests/runner_evidence/fixture_cli.py"
            checks = [{"id": "I-OUTPUT", "kind": "integrity"}, {"id": "E-EXIT", "kind": "execution", "expected_exit": 0},
                      {"id": "S-VALUE", "kind": "semantic", "pointer": "/value", "expected": expected},
                      {"id": "N-WRONG", "kind": "negative", "pointer": "/value", "expected": 999}]
            outputs = ["artifacts/result.json"]
            extra = [mode]
            profile_id, capability, kind = "bounded-cli-runner-test", "runner.fixture", "test-json"
        put(oracle_path, {"oracle_version": "bounded-cli-oracle.1", "parser": "json-object@1", "checks": checks})
        plan = {"plan_version": self.helper.PLAN_VERSION, "run_id": "run-tests", "attempt_id": attempt,
                "parent_attempt": parent,
                "source": {"kind": "manifest-snapshot", "root": str(self.source), "repo": "debugger-workstation snapshot",
                           "commit": HEAD, "dirty": True, "manifest_path": str(self.manifest),
                           "manifest_sha256": self.helper.sha256_file(self.manifest)},
                "runtime": self.helper.python_identity(), "tool": {"path": relative, **self.helper.identity(self.source / relative)},
                "target": {"path": str(target), **self.helper.identity(target), "kind": kind, "fixture_id": "runner-explicit-fixture-v1"},
                "profile": {"id": profile_id, "version": "1", "capability_id": capability,
                            "limitations": ["Parser/runner fixture only; no network traffic, provider or full product claim."]},
                "oracle": {"path": str(oracle_path), "sha256": self.helper.sha256_file(oracle_path)},
                "required_case_ids": [check["id"] for check in checks], "checks_total": len(checks), "required_steps": self.helper.STEPS,
                "run_root": str(self.runs), "execution": {"argv": ["{python}", "-I", "-B", "{tool}", "{target}", *extra],
                                                          "timeout_s": timeout, "cancel_file": str(cancel) if cancel else None},
                "outputs": outputs}
        path = self.root / (attempt + "-plan.json")
        put(path, plan)
        return path, self.helper.sha256_file(path)

    def run_command(self, pair):
        return [sys.executable, "-X", "utf8", "-B", str(self.source / "scripts/assert-probes.py"),
                "--plan", str(pair[0]), "--expected-plan-sha256", pair[1]]

    def execute(self, pair):
        result = subprocess.run(self.run_command(pair), capture_output=True, text=True, timeout=25)
        plan = json.loads(pair[0].read_text())
        transcript = self.root / (plan["attempt_id"] + "-runner.txt")
        transcript.write_text(result.stdout + result.stderr)
        return result

    def attempt(self, pair):
        return self.runs / "attempts" / json.loads(pair[0].read_text())["attempt_id"]

    def verify(self, pair, terminal=None, receipt=None):
        args = [sys.executable, "-X", "utf8", "-B", str(self.source / "scripts/verify-profile.py"), "--product", "--json",
                "--plan", str(pair[0]), "--expected-plan-sha256", pair[1],
                "--runner-terminal", str(terminal or self.attempt(pair) / "terminal.json")]
        if receipt:
            args += ["--receipt", str(receipt)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        report = json.loads(result.stdout)
        return result.returncode, report

    def mutate_receipt(self, pair, mutate):
        attempt = self.attempt(pair)
        receipt = json.loads((attempt / "receipt.json").read_text())
        mutate(receipt)
        put(attempt / "receipt.json", receipt)
        terminal = json.loads((attempt / "terminal.json").read_text())
        # Explicitly rebind the receipt digest to test the semantic/provenance
        # guard itself, not merely the outer content hash.
        terminal["receipt_sha256"] = self.helper.sha256_file(attempt / "receipt.json")
        put(attempt / "terminal.json", terminal)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = None
        if EVIDENCE:
            root = Path(EVIDENCE) / self._testMethodName
        else:
            self.temp = tempfile.TemporaryDirectory(prefix="runner-evidence-test-")
            root = Path(self.temp.name)
        self.h = Harness(root, SOURCE)

    def tearDown(self):
        if self.temp:
            self.temp.cleanup()

    def positive(self, **kwargs):
        pair = self.h.freeze(**kwargs)
        run = self.h.execute(pair)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        code, report = self.h.verify(pair)
        self.assertEqual(code, 0, report)
        return pair

    def rejected(self, pair, needle=None):
        code, report = self.h.verify(pair)
        self.assertNotEqual(code, 0, report)
        if needle:
            self.assertIn(needle, json.dumps(report))
        return report

    def test_real_pcap_positive_and_owned_output(self):
        pair = self.positive(tool="pcap")
        self.assertFalse((self.h.source / "net-reverse/out").exists())
        artifact = self.h.attempt(pair) / "artifacts/net-reverse/out/last-run-pcap_reader.json"
        self.assertEqual(json.loads(artifact.read_text())["dns_queries"], 1)

    def test_real_pcap_valid_json_wrong_semantics(self):
        pair = self.h.freeze(tool="pcap", target_bytes=one_packet_pcap()[:24])
        result = self.h.execute(pair)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.rejected(pair, "S-PACKETS")
        self.assertEqual(report["verdict"], "PROFILE_FAIL")

    def test_forged_commit_with_rebound_terminal(self):
        pair = self.positive()
        self.h.mutate_receipt(pair, lambda receipt: receipt["source"].update(commit="0" * 40))
        self.rejected(pair, "source provenance")

    def test_forged_target_with_rebound_terminal(self):
        pair = self.positive()
        self.h.mutate_receipt(pair, lambda receipt: receipt["target"].update(sha256="sha256:" + "0" * 64))
        self.rejected(pair, "target identity")

    def test_changed_source_bytes(self):
        pair = self.positive()
        with (self.h.source / "tests/runner_evidence/fixture_cli.py").open("a") as fh:
            fh.write("\n# drift\n")
        self.rejected(pair, "source tests/runner_evidence/fixture_cli.py byte identity mismatch")

    def test_changed_target_bytes(self):
        pair = self.positive()
        plan = json.loads(pair[0].read_text())
        Path(plan["target"]["path"]).write_text('{"value":8}')
        self.rejected(pair, "target byte identity mismatch")

    def test_missing_terminal_blocks_complete_receipt(self):
        pair = self.positive()
        (self.h.attempt(pair) / "terminal.json").unlink()
        report = self.rejected(pair, "runner terminal missing")
        self.assertEqual(report["verdict"], "PROFILE_BLOCKED")

    def test_receipt_shrunken_denominator(self):
        pair = self.positive()
        def mutate(receipt):
            receipt["result"]["required_case_ids"].pop()
            receipt["result"]["checks_total"] -= 1
            receipt["checks"].pop()
        self.h.mutate_receipt(pair, mutate)
        self.rejected(pair, "required checks")

    def test_resealed_plan_cannot_replace_caller_expected_digest(self):
        pair = self.positive()
        plan = json.loads(pair[0].read_text())
        plan["required_case_ids"].pop()
        plan["checks_total"] -= 1
        put(pair[0], plan)
        self.rejected(pair, "caller-pinned plan digest mismatch")

    def test_cross_attempt_terminal(self):
        first = self.positive(attempt="attempt-one")
        second = self.positive(attempt="attempt-two")
        code, report = self.h.verify(second, terminal=self.h.attempt(first) / "terminal.json")
        self.assertNotEqual(code, 0)
        self.assertIn("different attempt", str(report))

    def test_timeout_after_complete_json_preserves_execution(self):
        pair = self.h.freeze(mode="wait", timeout=0.3)
        result = self.h.execute(pair)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        receipt = json.loads((self.h.attempt(pair) / "receipt.json").read_text())
        self.assertTrue(receipt["execution"]["backend_executed"])
        self.assertEqual(receipt["execution"]["terminal_state"], "timeout")
        self.assertTrue(receipt["execution"]["cleanup"]["child_reaped"])
        self.assertEqual(self.rejected(pair)["verdict"], "PROFILE_BLOCKED")

    def test_cancel_after_complete_json_preserves_execution(self):
        cancel = self.h.root / "cancel.flag"
        pair = self.h.freeze(mode="wait", timeout=5, cancel=cancel)
        proc = subprocess.Popen(self.h.run_command(pair), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = self.h.attempt(pair) / "stdout.bin"
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and (not output.exists() or not output.stat().st_size):
            time.sleep(0.01)
        self.assertTrue(output.exists() and output.stat().st_size)
        cancel.write_text("cancel")
        stdout, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2, stdout + stderr)
        receipt = json.loads((self.h.attempt(pair) / "receipt.json").read_text())
        self.assertTrue(receipt["execution"]["backend_executed"])
        self.assertTrue(receipt["execution"]["cancelled"])
        self.assertEqual(receipt["execution"]["terminal_state"], "cancelled")
        self.assertEqual(self.rejected(pair)["verdict"], "PROFILE_BLOCKED")

    def test_hard_interruption_has_no_published_terminal(self):
        pair = self.h.freeze(mode="pid-wait", timeout=10)
        proc = subprocess.Popen(self.h.run_command(pair), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = self.h.attempt(pair) / "stdout.bin"
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and (not output.exists() or not output.stat().st_size):
            time.sleep(0.01)
        child_pid = json.loads(output.read_text())["pid"]
        proc.kill()
        proc.communicate(timeout=5)
        try:
            if os.name == "nt":
                os.kill(child_pid, signal.SIGTERM)
            else:
                os.killpg(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.assertTrue((self.h.attempt(pair) / "intent.json").is_file())
        self.assertFalse((self.h.attempt(pair) / "terminal.json").exists())
        self.assertEqual(self.rejected(pair)["verdict"], "PROFILE_BLOCKED")

    def test_failed_retry_preserves_parent_bytes(self):
        first = self.h.freeze(attempt="attempt-failed", mode="bad")
        self.assertEqual(self.h.execute(first).returncode, 1)
        terminal = self.h.attempt(first) / "terminal.json"
        frozen = self.h.helper.sha256_file(terminal)
        parent = {"attempt_id": "attempt-failed", "terminal_path": str(terminal), "terminal_sha256": frozen}
        second = self.positive(attempt="attempt-retry", parent=parent)
        self.assertEqual(self.h.helper.sha256_file(terminal), frozen)
        (self.h.attempt(first) / "stdout.bin").write_text('{"value":7}')
        self.rejected(second, "artifact stdout.bin byte identity mismatch")

    def test_concurrent_attempts_and_identical_bytes_are_independent(self):
        pairs = [self.h.freeze(attempt="attempt-concurrent-a"), self.h.freeze(attempt="attempt-concurrent-b")]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.h.execute, pairs))
        self.assertEqual([result.returncode for result in results], [0, 0], [result.stdout for result in results])
        for pair in pairs:
            self.assertEqual(self.h.verify(pair)[0], 0)
        first, second = [self.h.attempt(pair) for pair in pairs]
        self.assertNotEqual(first, second)
        self.assertEqual((first / "stdout.bin").read_bytes(), (second / "stdout.bin").read_bytes())
        self.assertEqual((first / "artifacts/result.json").read_bytes(), (second / "artifacts/result.json").read_bytes())

    def test_attempt_id_cannot_be_reused(self):
        pair = self.positive()
        terminal = self.h.attempt(pair) / "terminal.json"
        before = self.h.helper.sha256_file(terminal)
        self.assertNotEqual(self.h.execute(pair).returncode, 0)
        self.assertEqual(self.h.helper.sha256_file(terminal), before)

    def test_nested_reserved_filename_is_bound_as_artifact(self):
        pair = self.h.freeze(mode="reserved-name")
        plan = json.loads(pair[0].read_text())
        plan["outputs"] = ["artifacts/terminal.json"]
        put(pair[0], plan)
        pair = (pair[0], self.h.helper.sha256_file(pair[0]))
        self.assertEqual(self.h.execute(pair).returncode, 0)
        self.assertEqual(self.h.verify(pair)[0], 0)
        (self.h.attempt(pair) / "artifacts/terminal.json").write_text('{"tampered":true}')
        self.rejected(pair, "artifact artifacts/terminal.json byte identity mismatch")

    def test_preexisting_cancel_prevents_dispatch_and_marker(self):
        # Positive control proves this exact child writes a real side-effect marker.
        control = self.positive(attempt="attempt-control", mode="marker")
        self.assertTrue((self.h.attempt(control) / "artifacts/dispatched.marker").is_file())
        cancel = self.h.root / "cancel.flag"
        cancel.write_text("already cancelled before invocation")
        pair = self.h.freeze(attempt="attempt-cancelled", mode="marker", cancel=cancel)
        result = self.h.execute(pair)
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads((self.h.attempt(pair) / "receipt.json").read_text())
        self.assertFalse(receipt["execution"]["backend_executed"], receipt["execution"])
        self.assertIsNone(receipt["execution"]["pid"])
        self.assertFalse((self.h.attempt(pair) / "artifacts/dispatched.marker").exists())
        self.assertEqual(self.rejected(pair)["verdict"], "PROFILE_NOT_RUN")

    def test_touching_old_artifact_does_not_produce_owned_output(self):
        old = self.h.root / "old.json"
        old.write_text('{"value":7}')
        pair = self.h.freeze(mode="touch-only", target_bytes=json.dumps({"value": 7, "old_artifact": str(old)}).encode())
        self.assertEqual(self.h.execute(pair).returncode, 1)
        self.rejected(pair, "required tool artifacts missing")

    def test_legacy_mtime_only_is_stale_and_retries_keep_logs(self):
        legacy = module(self.h.source / "scripts/assert-probes.py", "legacy_runner")
        artifact = self.h.root / "legacy.bin"
        artifact.write_bytes(b"stable")
        before = legacy.snapshot_produces([str(artifact)])
        stat = artifact.stat()
        os.utime(artifact, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1000000000))
        state, rows, _ = legacy.check_produces("test.touch", [str(artifact)], "touch", before)
        self.assertEqual(state, "stale")
        self.assertTrue(rows)
        legacy.EVIDENCE_DIR = self.h.root / "legacy-evidence"
        legacy.save_evidence("same.id", "probe", "first", 1, 0.1, "failed-first")
        legacy.save_evidence("same.id", "probe", "retry", 0, 0.1, "passed-second")
        logs = list(legacy.EVIDENCE_DIR.rglob("*.log"))
        self.assertEqual(len(logs), 2)
        self.assertTrue(any("failed-first" in p.read_text() for p in logs))
        self.assertNotIn('script = REPO / "_assert_probe_cmd.ps1"', (self.h.source / "scripts/assert-probes.py").read_text())

    def test_original_v2_controls_and_adversarial_diagnostics(self):
        evidence = SOURCE / "evidence/profile-receipts"
        fixtures = sorted(evidence.glob("v2-*.json"))
        self.assertGreaterEqual(len(fixtures), 10)
        for receipt_path in fixtures:
            receipt = json.loads(receipt_path.read_text())
            args = [sys.executable, "-B", str(SOURCE / "scripts/verify-profile.py"), "--schema", str(SOURCE / "schemas/run-receipt.v2.json"),
                    "--receipt", str(receipt_path), "--oracle", str(evidence / receipt["oracle"]["anchor_path"])]
            run = subprocess.run(args, capture_output=True, text=True, timeout=10)
            with self.subTest(receipt=receipt_path.name):
                if receipt_path.name in ("v2-good-pass.json", "v2-retry-preserves-failure.json"):
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    product = subprocess.run(args + ["--product"], capture_output=True, text=True, timeout=10)
                    self.assertEqual(product.returncode, 2, product.stdout + product.stderr)
                else:
                    self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def startTest(self, test):
        self.started = time.monotonic()
        super().startTest(test)

    def addSuccess(self, test):
        self.records.append({"test": test.id(), "status": "passed", "seconds": round(time.monotonic() - self.started, 4)})
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.records.append({"test": test.id(), "status": "failed", "detail": self._exc_info_to_string(err, test)})
        super().addFailure(test, err)

    def addError(self, test, err):
        self.records.append({"test": test.id(), "status": "error", "detail": self._exc_info_to_string(err, test)})
        super().addError(test, err)


def main():
    global SOURCE, EVIDENCE
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    SOURCE = args.source.resolve()
    EVIDENCE = args.evidence_dir.resolve() if args.evidence_dir else None
    if EVIDENCE:
        EVIDENCE.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
    runner = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult)
    result = runner.run(suite)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        put(args.report, {"contract": "bounded-runner-tests", "platform": sys.platform, "python": sys.version,
                          "source": str(SOURCE), "tests_run": result.testsRun, "successful": result.wasSuccessful(),
                          "results": result.records, "subtest_failures": [str(test) for test, _ in result.failures]})
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
