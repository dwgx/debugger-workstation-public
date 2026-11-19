"""Semantic regressions for the public tool inventory/version entry point.

Runs real small owned Python subprocesses; no station binaries or credentials.
The heartbeat checks observe descendant side effects independently of the runner.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/smoke-tools.py"
spec = importlib.util.spec_from_file_location("smoke_tools", SOURCE)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
PATTERN = r"example\s+(\d+\.\d+\.\d+)"


class SmokeToolsTests(unittest.TestCase):
    def test_version_zero_exit(self):
        result = smoke.run_probe([sys.executable, "-c", "print('example 1.2.3')"], 4)
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "VERSION_VERIFIED")
        self.assertEqual(result["exit_code"], 0)

    def test_matching_banner_nonzero_is_failure(self):
        result = smoke.run_probe([sys.executable, "-c", "print('example 1.2.3'); raise SystemExit(7)"], 4)
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "PROBE_FAILED")

    def test_zero_exit_without_version_is_failure(self):
        result = smoke.run_probe([sys.executable, "-c", "print('not an observed version')"], 4)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "PROBE_FAILED")

    def test_stderr_version_is_captured(self):
        result = smoke.run_probe([sys.executable, "-c", "import sys; print('example 1.2.3',file=sys.stderr)"], 4)
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "VERSION_VERIFIED")
        self.assertGreater(result["stderr_bytes"], 0)

    def test_unicode_and_space_arguments(self):
        with tempfile.TemporaryDirectory(prefix="smoke space-") as temp:
            script = Path(temp) / "中文 version.py"
            script.write_text("import sys\nassert sys.argv[1] == '参数 with space'\nprint('example 1.2.3')\n", encoding="utf-8")
            result = smoke.run_probe([sys.executable, str(script), "参数 with space"], 4)
            self.assertEqual(smoke.judge(result, PATTERN)["status"], "VERSION_VERIFIED", result)

    def test_real_timeout_is_bounded(self):
        result = smoke.run_probe([sys.executable, "-c", "import time; time.sleep(60)"], .3)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["seconds"], 5)
        self.assertNotIn("cleanup_error", result)

    def descendant_case(self, wait_parent):
        with tempfile.TemporaryDirectory(prefix="smoke-child-") as temp:
            directory = Path(temp); beat = directory / "heartbeat.txt"
            child = directory / "child.py"
            child.write_text("import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nwhile True:\n p.write_text(str(time.monotonic()))\n time.sleep(.02)\n")
            parent = directory / "parent.py"
            parent.write_text("import pathlib,subprocess,sys,time\nsubprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])\np=pathlib.Path(sys.argv[2])\nend=time.monotonic()+3\nwhile not p.exists() and time.monotonic()<end: time.sleep(.01)\nprint('example 1.2.3',flush=True)\n" + ("time.sleep(60)\n" if wait_parent else ""))
            result = smoke.run_probe([sys.executable, str(parent), str(child), str(beat)], 1.5 if wait_parent else 5)
            self.assertTrue(beat.exists(), result)
            before = beat.read_bytes(); time.sleep(.2)
            self.assertEqual(before, beat.read_bytes(), "owned descendant continued writing after cleanup")
            self.assertNotIn("cleanup_error", result)
            if wait_parent:
                self.assertTrue(result["timed_out"])
            else:
                self.assertEqual(smoke.judge(result, PATTERN)["status"], "VERSION_VERIFIED", result)

    def test_timeout_reclaims_descendant(self):
        self.descendant_case(True)

    def test_normal_exit_reclaims_descendant(self):
        self.descendant_case(False)

    def test_output_limit(self):
        result = smoke.run_probe([sys.executable, "-c", "import sys,time; sys.stdout.write('x'*2097152);sys.stdout.flush();time.sleep(60)"], 4)
        self.assertTrue(result["output_limit_exceeded"])
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), 65536)
        self.assertLess(result["seconds"], 5)
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "PROBE_FAILED")

    def test_spawn_error_is_not_a_pass(self):
        result = smoke.run_probe(["station-deliberately-missing-executable"], 1)
        self.assertIsNotNone(result["error"])
        self.assertEqual(smoke.judge(result, PATTERN)["status"], "PROBE_FAILED")

    def test_inventory_is_not_runtime_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "GUI.exe").write_text("inert fixture")
            manifest = root / "tools.json"
            manifest.write_text(json.dumps({"tools": {"test": [{"name": "GUI", "dir": ".", "entry": "GUI.exe"}]}}))
            result = smoke.inspect(root, manifest, [], False, 1)
            self.assertEqual(result["tools"][0]["status"], "FILE_PRESENT")
            self.assertEqual(result["summary"]["runtime_calls"], 0)
            self.assertFalse(result["summary"]["full_tool_acceptance"])

    def test_missing_known_probe_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest = root / "tools.json"
            manifest.write_text(json.dumps({"tools": {"test": [{"name": "capa", "dir": ".", "entry": "missing.exe"}]}}))
            result = smoke.inspect(root, manifest, [], True, 1)
            self.assertEqual(result["exit_code"], 2)
            self.assertEqual(result["tools"][0]["status"], "BLOCKED")
            self.assertEqual(result["summary"]["runtime_calls"], 0)

    def test_bad_selection_cannot_be_an_empty_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest = root / "tools.json"
            manifest.write_text('{"tools": {"test": []}}')
            with self.assertRaisesRegex(ValueError, "unknown tool"):
                smoke.inspect(root, manifest, ["typo"], True, 1)

    def test_environment_expansion_and_unresolved(self):
        key = "STATION_SMOKE_TEST_ROOT_20261119"
        old = os.environ.get(key)
        try:
            os.environ[key] = str(Path(tempfile.gettempdir()).resolve())
            path, error = smoke.resolve_entry(Path.cwd(), {"dir": "%" + key + "%", "entry": "x.exe"})
            self.assertIsNone(error); self.assertEqual(path.name, "x.exe")
            del os.environ[key]
            path, error = smoke.resolve_entry(Path.cwd(), {"dir": "%" + key + "%"})
            self.assertIsNone(path); self.assertIn("unresolved", error)
        finally:
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old

    def test_existing_report_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "existing.json"; report.write_text("sentinel")
            with contextlib.redirect_stderr(io.StringIO()):
                code = smoke.main(["--report", str(report), "--probe"])
            self.assertEqual(code, 2); self.assertEqual(report.read_text(), "sentinel")


if __name__ == "__main__":
    unittest.main(verbosity=2)
