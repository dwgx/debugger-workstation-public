"""Regression tests for the standalone, provider-free first-success entry."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/first-success.py"
spec = importlib.util.spec_from_file_location("first_success_module", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FirstSuccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ws-first-success-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def invoke(self, *parts):
        return subprocess.run(
            [sys.executable, "-X", "utf8", "-B", str(SCRIPT), "--source",
             str(ROOT), *[str(x) for x in parts]],
            capture_output=True, text=True, timeout=120,
        )

    def test_live_product_profile_pass_on_owned_pcap(self):
        out = self.path / "accepted-run"
        result = self.invoke("--output", out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        info = json.loads((out / "FIRST-SUCCESS.json").read_text(encoding="utf-8"))
        self.assertEqual(info["verdict"], "PROFILE_PASS")
        self.assertTrue(info["terminal_present"])
        self.assertTrue(info["source_unchanged"])
        self.assertEqual([s["exit_code"] for s in info["stages"]], [0, 0])
        self.assertEqual(info["stages"][0]["timed_out"], False)
        expected = json.loads((out / "caller-freeze.json").read_text(encoding="utf-8"))
        self.assertEqual("sha256:" + hashlib.sha256((out / "run-plan.json").read_bytes()).hexdigest(),
                         expected["expected_plan_sha256"])
        self.assertEqual(info["frozen_plan_sha256"], expected["expected_plan_sha256"])

    def test_existing_run_cannot_be_overwritten(self):
        out = self.path / "occupied"
        out.mkdir()
        marker = out / "sentinel"
        marker.write_bytes(b"unchanged")
        result = self.invoke("--output", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_bytes(), b"unchanged")
        self.assertFalse((out / "FIRST-SUCCESS.json").exists())

    def test_output_inside_source_is_refused(self):
        out = ROOT / "bad-inside-repo-output-NOT-CREATED"
        self.assertFalse(out.exists())
        result = self.invoke("--output", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out.exists())

    def test_missing_source_commit_on_non_git_copy_is_refused(self):
        source = self.path / "extracted-no-git"
        for rel in runner.FILES:
            target = source / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
        out = self.path / "non-git-output"
        result = subprocess.run(
            [sys.executable, "-X", "utf8", "-B", str(SCRIPT),
             "--source", str(source), "--output", str(out)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out.exists())
        self.assertIn("source-commit", result.stderr)

    def test_non_git_copy_with_explicit_provenance_runs(self):
        source = self.path / "no-git-source"
        for rel in runner.FILES:
            target = source / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
        out = self.path / "non-git-run"
        result = subprocess.run(
            [sys.executable, "-X", "utf8", "-B", str(SCRIPT), "--source",
             str(source), "--output", str(out), "--source-commit", "a" * 40],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        info = json.loads((out / "FIRST-SUCCESS.json").read_text(encoding="utf-8"))
        self.assertEqual(info["verdict"], "PROFILE_PASS")
        self.assertFalse(info["git_revision_observed"])
        self.assertEqual(info["source_revision"], "a" * 40)

    def test_tampered_plan_rejected_before_runner(self):
        out = self.path / "tamper"
        out.mkdir()
        plan = out / "run-plan.json"
        plan.write_text('{"attempt_id":"attempt-' + ("0" * 32) + '"}', encoding="utf-8")
        freeze = {"expected_plan_sha256": "sha256:" + ("0" * 64)}
        with self.assertRaisesRegex(ValueError, "plan digest"):
            runner.validated_commands(ROOT, out, freeze)

    def test_injected_command_argv_rejected(self):
        out = self.path / "injection"
        out.mkdir()
        plan = out / "run-plan.json"
        plan.write_text('{"attempt_id":"attempt-' + ("0" * 32) + '"}', encoding="utf-8")
        digest = "sha256:" + hashlib.sha256(plan.read_bytes()).hexdigest()
        frozen = {"expected_plan_sha256": digest, "runner_argv": ["cmd", "/c", "echo injected"]}
        with self.assertRaisesRegex(ValueError, "runner argv"):
            runner.validated_commands(ROOT, out, frozen)

    def test_rejected_nonhex_digest(self):
        out = self.path / "invalid"
        out.mkdir()
        with self.assertRaisesRegex(ValueError, "invalid frozen plan digest"):
            runner.validated_commands(ROOT, out, {"expected_plan_sha256": "sha256:" + ("x" * 64)})


if __name__ == "__main__":
    unittest.main()
