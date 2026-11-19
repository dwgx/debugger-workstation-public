"""Regression controls for false-green coverage and provider cleanup."""
import importlib.util
import json
from pathlib import Path
import queue
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

MODULE = Path(__file__).resolve().parents[1] / "scripts/tool_lab/offline_acceptance.py"
spec = importlib.util.spec_from_file_location("offline_acceptance_under_test", MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def fake_run(cases):
    run = lab.ProviderRun("test", Path("wrapper.cmd"), Path("out"), {})
    run.cases = cases
    run.cleanup = {"observed_cleanup_ok": True}
    run.session["stdout_audit"] = {"wire_protocol_clean": True}
    return run


def case(name, kind="positive", passed=True):
    return {"case_id": name + "-case", "tool": name,
            "classification": kind, "all_pass": passed}


def coverage(provider, names, cases):
    catalog = {"providers": {provider: {"tools": [{"name": n} for n in names]}}}
    return lab.build_coverage(catalog, {provider: fake_run(cases)})


class OfflineOracleTests(unittest.TestCase):
    def test_shutdown_noise_is_retained_and_fails_acceptance(self):
        queued = queue.Queue()
        queued.put({"t": "after-response", "raw": "owned child output"})
        queued.put(None)
        client = SimpleNamespace(_q=queued, _reader=Mock(is_alive=Mock(return_value=False)), res=[])
        audit = lab.audit_stdout(client)
        self.assertEqual(client.res[0]["raw"], "owned child output")
        self.assertEqual(audit["post_close_lines"], 1)
        self.assertFalse(audit["wire_protocol_clean"])
        run = fake_run([case("open_binary")])
        run.session["stdout_audit"] = audit
        report = coverage("rea", ["open_binary"], run.cases)
        self.assertIn("rea: clean stdout through reader shutdown not observed", lab.collect_failures(report, {"rea": run}))

    def test_json_without_rpc_envelope_is_noise(self):
        for raw in ('{"message":"log"}', 'null', '[]'):
            with self.subTest(raw=raw):
                client = SimpleNamespace(_q=queue.Queue(), _reader=Mock(is_alive=Mock(return_value=False)), res=[{"t":"now", "raw":raw}])
                self.assertFalse(lab.audit_stdout(client)["wire_protocol_clean"])

    def test_stopped_reader_required_even_with_valid_rpc(self):
        raw = json.dumps({"jsonrpc":"2.0", "id":1, "result":{}})
        for alive in (False, True):
            client = SimpleNamespace(_q=queue.Queue(), _reader=Mock(is_alive=Mock(return_value=alive)), res=[{"t":"now", "raw":raw}])
            self.assertEqual(lab.audit_stdout(client)["wire_protocol_clean"], not alive)

    def test_wireshark_failures_require_error_flag(self):
        root = Path("fixtures")
        checks = lab.ws_checks(root / "valid.pcap", root / "corrupt.pcap", root / "exports")
        messages = {
            "ws-read-pcap-corrupt": "Error reading pcap file: tshark failed: isn't a capture file in a format TShark understands",
            "ws-display-filter-invalid": "Error applying display filter: Unexpected end of filter expression",
            "ws-export-json-missing": f"Error: File not found: {root / 'missing.pcap'}",
        }
        for name, message in messages.items():
            for flag in (None, False, True):
                with self.subTest(name=name, flag=flag):
                    result = {} if flag is None else {"isError": flag}
                    c = lab.Checks()
                    checks[name]({"text": message, "result": result}, c)
                    self.assertEqual(c.ok, flag is True)

    def test_failed_case_downgrades_tested_and_prior_methods(self):
        for provider, name in (("wireshark", "read_pcap"),
                               ("rea", "binary_session"),
                               ("sevenzip", "mcp7zop_get_archive_item_list")):
            with self.subTest(provider=provider):
                report = coverage(provider, [name], [case(name), case(name, "negative", False)])
                self.assertEqual(report["providers"][provider]["methods"][name]["status"], "FAILED")
                self.assertEqual(report["totals"]["failed"], 1)
                self.assertEqual(report["totals"]["pass"], 0)

    def test_uncalled_known_name_cannot_pass(self):
        report = coverage("rea", ["binary_session", "open_binary", "capture_browser_scenario"], [])
        self.assertEqual(report["totals"]["untested"], 3)
        self.assertEqual(report["totals"]["pass"], 0)
        self.assertEqual(report["totals"]["blocked"], 0)

    def test_only_actual_capability_refusal_is_blocked(self):
        name = "inspect_binary_layout"
        report = coverage("rea", [name], [case(name, "blocked")])
        self.assertEqual(report["totals"]["blocked"], 1)
        self.assertEqual(report["totals"]["pass"], 0)

    def test_negative_only_and_partial_are_not_positive_passes(self):
        for kind, status in (("negative", "negative_only"), ("partial", "partial")):
            with self.subTest(kind=kind):
                report = coverage("rea", ["open_binary"], [case("open_binary", kind)])
                self.assertEqual(report["totals"][status], 1)
                self.assertEqual(report["totals"]["pass"], 0)

    def test_positive_and_valid_rejection_share_one_method(self):
        report = coverage("wireshark", ["read_pcap"],
                          [case("read_pcap"), case("read_pcap", "negative")])
        self.assertEqual(report["totals"]["methods_called"], 1)
        self.assertEqual(report["totals"]["calls"], 2)
        self.assertEqual(report["totals"]["pass"], 1)

    def test_uncataloged_call_is_explicit(self):
        report = coverage("rea", [], [case("new_method")])
        self.assertEqual(report["providers"]["rea"]["called_but_not_cataloged"], ["new_method"])

    def test_start_failure_always_finishes(self):
        run = fake_run([])
        run.start = Mock(side_effect=RuntimeError("start failed"))
        run.finish = Mock()
        exercise = Mock()
        run.execute(exercise)
        exercise.assert_not_called()
        run.finish.assert_called_once_with()
        self.assertIn("start failed", run.error)

    def test_setup_failure_after_start_always_finishes(self):
        run = fake_run([])
        run.start = Mock()
        run.finish = Mock()
        run.execute(Mock(side_effect=RuntimeError("oracle setup failed")))
        run.finish.assert_called_once_with()
        self.assertIn("oracle setup failed", run.error)

    def test_empty_oracle_is_not_pass(self):
        self.assertFalse(lab.Checks().ok)

    def test_close_requires_explicit_valid_result(self):
        checks, _ = lab.rea_checks(Path("fixtures"), {"files": {}}, Path("bundle.json"))
        for body in (None, {}, {"error": {"code": "failure"}}, {"result": None}):
            with self.subTest(body=body):
                c = lab.Checks()
                checks["rea-close-archive"]({"parsed": body, "result": {"isError": False}}, c)
                self.assertEqual(c.ok, body == {"result": None})

    def test_closed_session_with_error_flag_fails(self):
        checks, _ = lab.rea_checks(Path("fixtures"), {"files": {}}, Path("bundle.json"))
        c = lab.Checks()
        checks["rea-session-after-close"]({"parsed": {"result": {"open": False}},
                                           "result": {"isError": True}}, c)
        self.assertFalse(c.ok)

    def test_existing_output_is_not_overwritten_on_start_failure(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            target = output / "cases.json"
            target.write_text("preserve me")
            run = lab.ProviderRun("rea", Path("unused.cmd"), output, {})
            exercise = Mock()
            run.execute(exercise)
            exercise.assert_not_called()
            self.assertEqual(target.read_text(), "preserve me")
            self.assertFalse((output / "session.json").exists())
            self.assertIsNotNone(run.error)

    def test_missing_cases_and_unknown_method_share_failure_collector(self):
        run = fake_run([])
        catalog = {"providers": {"rea": {"tools": [{"name": "open_binary"}]}}}
        report = lab.build_coverage(catalog, {"rea": run})
        self.assertIn("rea: no cases executed", lab.collect_failures(report, {"rea": run}))
        run.cases = [case("not_cataloged")]
        report = lab.build_coverage(catalog, {"rea": run})
        self.assertIn("rea: called method absent from catalog", lab.collect_failures(report, {"rea": run}))

    def test_output_inside_station_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as root:
            station = Path(root)
            target = station / "new-output"
            with self.assertRaisesRegex(SystemExit, "outside the station"):
                lab.main(["--station", str(station), "--output", str(target)])
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
