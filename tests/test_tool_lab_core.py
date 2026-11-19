"""Counterexamples for evidence accounting; these are not provider acceptance."""
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import queue
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "scripts/tool_lab"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("tool_lab_coverage", TOOLS / "coverage.py")
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)
import catalog
import fixtures
from lab_session import LabSession


def case(kind="positive", flag=False, actual=42, expected=42):
    return {"case_id": "one", "method": "read", "arguments": {"path": "owned.bin"}, "kind": kind,
            "checks": {"answer": {"pass": True, "actual": actual, "expected": expected}},
            "response_id": 3, "response": {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "42"}], "isError": flag}}}


def session(cases):
    return {"backend": "demo", "route": "original wrapper", "tools": [{"name": "read", "inputSchema": {"type": "object"}}],
            "cleanup": {"observed_cleanup_ok": True}, "cases": cases}


class CoverageCounterexamples(unittest.TestCase):
    def test_catalog_is_not_execution(self):
        result = coverage.merge_sessions([], [("catalog", {"backends": [{"backend": "demo", "catalog_status": "observed", "tools": session([])["tools"]}]})])
        self.assertEqual(result["summary"]["actual_recorded_calls"], 0)
        self.assertEqual(result["summary"]["original_wrapper_positive_unique_methods"], 0)
        self.assertEqual(next(iter(result["methods"].values()))["status"], "unexecuted")

    def test_source_only_denominator_is_unknown_at_runtime(self):
        result = coverage.merge_sessions([], declarations=[("source", {"backends": [{"backend": "demo", "tools": [{"name": "read"}], "reason": "plugin unavailable"}]})])
        self.assertIsNone(result["backends"]["demo"]["runtime_method_count"])
        self.assertFalse(result["summary"]["runtime_denominator_complete"])

    def test_reported_pass_cannot_override_wrong_answer(self):
        self.assertEqual(coverage.case_status(case(actual=7), True), "failed")

    def test_negative_requires_mcp_error_flag(self):
        self.assertEqual(coverage.case_status(case(kind="negative"), True), "failed")
        self.assertEqual(coverage.case_status(case(kind="negative", flag=True), True), "expected_rejection")

    def test_positive_error_result_cannot_pass(self):
        self.assertEqual(coverage.case_status(case(flag=True), True), "failed")

    def test_missing_result_cannot_pass(self):
        malformed = case()
        malformed["response"] = {"jsonrpc": "2.0", "id": 3}
        self.assertEqual(coverage.case_status(malformed, True), "failed")

    def test_later_success_does_not_erase_failure(self):
        failed, good = case(actual=0), case()
        good["case_id"] = "two"
        result = coverage.merge_sessions([("session", session([failed, good]))])
        self.assertEqual(next(iter(result["methods"].values()))["status"], "failed")
        self.assertEqual(result["summary"]["original_wrapper_positive_unique_methods"], 0)

    def test_unknown_cleanup_cannot_pass(self):
        self.assertEqual(coverage.case_status(case(), False), "failed")

    def test_recorded_live_reader_cannot_regain_green(self):
        data = session([case()])
        data["wire_protocol_clean"] = True
        data["stdout_audit"] = {"reader_stopped": False, "post_close_lines": 0}
        result = coverage.merge_sessions([("session", data)])
        self.assertEqual(next(iter(result["methods"].values()))["status"], "failed")
        self.assertEqual(result["summary"]["original_wrapper_positive_unique_methods"], 0)

    def assert_zero_call_failure(self, changes, reason, noise=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = session([])
            record.update(all_checks_pass=False, stdout_audit={"reader_stopped": True})
            record.update(changes)
            record["catalog_response"] = {"jsonrpc": "2.0", "id": 2,
                                          "result": {"tools": record["tools"]}}
            request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            (root / "requests.jsonl").write_text(json.dumps(request) + "\n")
            (root / "responses.jsonl").write_text(
                json.dumps(record["catalog_response"]) + "\n" + ("SHUTDOWN_NOISE\n" if noise else ""))
            (root / "stderr.txt").write_bytes(b"")
            record["raw_sha256"] = {n: coverage.sha(root / n)
                                    for n in ("requests.jsonl", "responses.jsonl", "stderr.txt")}
            (root / "RESULTS.json").write_text(json.dumps(record))
            argv = ["coverage.py", "--session", str(root / "RESULTS.json"),
                    "--output", str(root / "out")]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                status = coverage.main()
            self.assertEqual(status, 2)
            result = json.loads((root / "out/COVERAGE.json").read_text())
            self.assertEqual(result["summary"]["session_count"], 1)
            self.assertEqual(result["summary"]["failed_sessions"], 1)
            self.assertEqual(result["summary"]["actual_recorded_calls"], 0)
            self.assertEqual(result["summary"]["failed_cases"], 0)
            self.assertIn(reason, result["session_failures"][0]["reasons"])
            self.assertEqual(result["session_failures"][0]["runner_error"], record.get("runner_error"))

    def test_zero_call_runner_error_fails_cli(self):
        self.assert_zero_call_failure(
            {"runner_error": {"type": "RuntimeError", "message": "oracle setup failed"}},
            "runner_error")

    def test_zero_call_unknown_cleanup_fails_cli(self):
        self.assert_zero_call_failure(
            {"cleanup": {"observed_cleanup_ok": False}}, "cleanup_not_observed")

    def test_zero_call_live_reader_fails_cli(self):
        self.assert_zero_call_failure(
            {"stdout_audit": {"reader_stopped": False}}, "stdout_not_clean_or_complete")

    def test_zero_call_stdout_noise_fails_cli(self):
        self.assert_zero_call_failure({}, "stdout_not_clean_or_complete", noise=True)

    def test_catalog_only_cli_remains_unexecuted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = {"backends": [{"backend": "demo", "catalog_status": "observed",
                                  "tools": session([])["tools"]}]}
            (root / "CATALOG.json").write_text(json.dumps(data))
            argv = ["coverage.py", "--catalog", str(root / "CATALOG.json"),
                    "--output", str(root / "out")]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                status = coverage.main()
            self.assertEqual(status, 0)
            result = json.loads((root / "out/COVERAGE.json").read_text())
            self.assertEqual(result["summary"]["actual_recorded_calls"], 0)
            self.assertEqual(result["summary"]["original_wrapper_positive_unique_methods"], 0)
            self.assertEqual(next(iter(result["methods"].values()))["status"], "unexecuted")

    def test_raw_response_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = session([case()])
            record["catalog_response"] = {"jsonrpc": "2.0", "id": 2, "result": {"tools": record["tools"]}}
            requests = [{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read", "arguments": {"path": "owned.bin"}}}]
            responses = [record["catalog_response"], record["cases"][0]["response"]]
            for name, values in (("requests.jsonl", requests), ("responses.jsonl", responses)):
                (root / name).write_text("\n".join(json.dumps(v) for v in values) + "\n")
            (root / "stderr.txt").write_bytes(b"")
            record["raw_sha256"] = {n: coverage.sha(root / n) for n in ("requests.jsonl", "responses.jsonl", "stderr.txt")}
            path = root / "RESULTS.json"
            path.write_text(json.dumps(record))
            coverage.verify_session(path)
            record["cases"][0]["response"]["result"]["content"][0]["text"] = "forged"
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "differs from raw"):
                coverage.verify_session(path)


class FixtureAndLifecycleChecks(unittest.TestCase):
    def assert_partial_catalog_start_closed(self, cleanup_raises):
        instances = []

        class PartialStart:
            def __init__(self, *args, **kwargs):
                self.req, self.res, self.stderr_chunks = [], [], []
                self.close_calls = 0
                self.resource_live = False
                instances.append(self)

            def start(self):
                self.resource_live = True
                raise RuntimeError("reader startup failed after process creation")

            def close(self):
                self.close_calls += 1
                if cleanup_raises:
                    raise RuntimeError("cleanup observation failed")
                self.resource_live = False
                return {"observed_cleanup_ok": True}

        with tempfile.TemporaryDirectory() as tmp, patch.object(catalog, "RawMcp", PartialStart):
            root = Path(tmp)
            record = catalog.probe_backend("demo", {"command": "python"},
                                           root / "station", root / "result", 1)
            self.assertEqual(instances[0].close_calls, 1)
            self.assertEqual(record["catalog_status"], "unavailable")
            self.assertEqual(record["error"]["message"], "reader startup failed after process creation")
            self.assertEqual(record["cleanup"]["observed_cleanup_ok"], not cleanup_raises)
            saved = json.loads((root / "result/catalog.json").read_text())
            self.assertEqual(saved["error"], record["error"])
            self.assertEqual(saved["cleanup"], record["cleanup"])
            if cleanup_raises:
                self.assertIn("cleanup observation failed", record["cleanup"]["error"])
            else:
                self.assertFalse(instances[0].resource_live)

    def test_catalog_partial_start_is_closed(self):
        self.assert_partial_catalog_start_closed(False)

    def test_catalog_start_and_cleanup_errors_are_both_retained(self):
        self.assert_partial_catalog_start_closed(True)

    def test_authored_pe_offsets_are_consistent(self):
        image = fixtures.build_pe()
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        self.assertEqual(image[pe:pe + 4], b"PE\0\0")
        self.assertEqual(struct.unpack_from("<I", image, pe + 24 + 16)[0], 0x1000)
        self.assertEqual(image[512:518], b"\xb8\x2a\0\0\0\xc3")
        self.assertEqual(image[1024:1045], b"TOOLLAB_OWNED_MARKER\0")

    def test_authored_har_has_known_http_and_closed_ws(self):
        http, websocket = fixtures.build_har()["log"]["entries"]
        self.assertEqual(json.loads(http["response"]["content"]["text"])["answer"], 42)
        self.assertEqual(http["request"]["url"], "https://fixture.test/api/items/7")
        self.assertEqual([m["opcode"] for m in websocket["_webSocketMessages"]], [1, 1, 8])

    def test_new_output_refuses_stale_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = catalog.reserve_output(root / "out", root / "station")
            (output / "old.txt").write_text("old")
            with self.assertRaises(FileExistsError):
                catalog.reserve_output(output, root / "station")
            self.assertEqual((output / "old.txt").read_text(), "old")

    def test_cleanup_exception_preserves_raw_and_fails(self):
        class BrokenCleanup:
            req = [{"raw": '{"jsonrpc":"2.0","id":1,"method":"ping"}'}]
            res = []
            stderr_chunks = [b"diagnostic"]
            def close(self):
                raise RuntimeError("process observation failed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lab = LabSession("demo", [], root, {}, root / "session", "test")
            lab.client = BrokenCleanup()
            lab.record["cases"] = [case()]
            lab.__exit__(None, None, None)
            result = json.loads((root / "session/RESULTS.json").read_text())
            self.assertFalse(result["all_checks_pass"])
            self.assertFalse(result["cleanup"]["observed_cleanup_ok"])
            self.assertIn("ping", (root / "session/requests.jsonl").read_text())

    def test_launch_failure_retains_failed_receipt(self):
        class RefusedLaunch:
            req, res, stderr_chunks = [], [], []
            def start(self):
                raise RuntimeError("Job assignment refused")
            def close(self):
                return {"observed_cleanup_ok": False}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lab = LabSession("demo", [], root, {}, root / "session", "test")
            lab.client = RefusedLaunch()
            with self.assertRaisesRegex(RuntimeError, "assignment refused"):
                lab.__enter__()
            result = json.loads((root / "session/RESULTS.json").read_text())
            self.assertFalse(result["all_checks_pass"])
            self.assertEqual(result["runner_error"]["message"], "Job assignment refused")

    def test_session_rejects_malformed_success_envelope(self):
        class CleanClose:
            req, res, stderr_chunks = [], [], []
            def close(self):
                return {"observed_cleanup_ok": True}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lab = LabSession("demo", [], root, {}, root / "session", "test")
            lab.client = CleanClose()
            malformed = case()
            malformed["response"] = {"jsonrpc": "2.0", "id": 3}
            lab.record["cases"] = [malformed]
            lab.__exit__(None, None, None)
            self.assertFalse(lab.record["all_checks_pass"])
            self.assertFalse(lab.record["cases"][0]["protocol_flag_consistent"])

    def test_shutdown_noise_is_retained_and_fails(self):
        class StoppedReader:
            def is_alive(self):
                return False
        class TrailingNoise:
            def __init__(self):
                self.req, self.res, self.stderr_chunks = [], [], []
                self._q = queue.Queue()
                self._q.put({"t": "fixed", "raw": "TARGET_SHUTDOWN_OUTPUT"})
                self._q.put(None)
                self._reader = StoppedReader()
            def close(self):
                return {"observed_cleanup_ok": True}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lab = LabSession("demo", [], root, {}, root / "session", "test")
            lab.client = TrailingNoise()
            lab.record["cases"] = [case()]
            lab.__exit__(None, None, None)
            self.assertFalse(lab.record["all_checks_pass"])
            self.assertFalse(lab.record["wire_protocol_clean"])
            self.assertEqual(lab.record["stdout_audit"]["post_close_lines"], 1)
            self.assertIn("TARGET_SHUTDOWN_OUTPUT", (root / "session/responses.jsonl").read_text())

    def test_repeated_catalog_cursor_fails_closed(self):
        class RepeatedCursor:
            def __init__(self, *a, **kw):
                self.req, self.res, self.stderr_chunks = [], [], []
            def start(self):
                pass
            def initialize(self, **kw):
                return {"result": {}}
            def send(self, *a, **kw):
                return {"result": {"tools": [], "nextCursor": "same"}}
            def close(self):
                return {"observed_cleanup_ok": True}
        with tempfile.TemporaryDirectory() as tmp, patch.object(catalog, "RawMcp", RepeatedCursor):
            root = Path(tmp)
            record = catalog.probe_backend("demo", {"command": "python"}, root / "station", root / "result", 1)
            self.assertEqual(record["catalog_status"], "unavailable")
            self.assertIn("repeated", record["error"]["message"])
            self.assertIsNone(record["tool_count"])


if __name__ == "__main__":
    unittest.main()
