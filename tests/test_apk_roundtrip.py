"""Portable, no-provider guard and authored APK oracle tests.

The complete original-wrapper build/decode acceptance runs separately on
Windows with installed Java, framework and Apktool. CI does not claim it.
"""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ORACLES = ROOT / "scripts/tool_lab/apk_oracles.py"
RUNNER = ROOT / "scripts/tool_lab/run_apk_roundtrip.py"
spec = importlib.util.spec_from_file_location("apk_oracles_for_test", ORACLES)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


class ApkAuthoredOracleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="apk-oracle-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_authored_fixture_contains_known_semantics(self):
        files = o.write_authored_project(self.dir / "project", "3.0.3")
        self.assertEqual(len(files), 5)
        self.assertEqual(o.manifest_facts(files["AndroidManifest.xml"])["package"], "lab.demo")
        self.assertEqual(o.resource_values(files["res/values/strings.xml"], "string")["lab_greeting"], o.RESOURCE_LITERAL)
        self.assertIn(o.ORACLE_LITERAL, files["smali/lab/demo/MainActivity.smali"])
        self.assertEqual(o.apktool_yml_facts(files["apktool.yml"])["framework_ids"], ["1"])
        for relative, authored in files.items():
            self.assertEqual((self.dir / "project" / relative).read_bytes(), authored.encode("utf-8"))

    def test_canonical_smali_normalizes_only_allowed_difference(self):
        expected = o.SMALI_TEXT
        observed = expected.replace(".registers 1", ".locals 1")
        self.assertEqual(o.canonical_smali(expected), o.canonical_smali(observed))
        altered = observed.replace(o.ORACLE_LITERAL, "IMPOSTER_LITERAL")
        self.assertNotEqual(o.canonical_smali(expected), o.canonical_smali(altered))

    def test_manifest_tree_rejects_changed_activity(self):
        other = o.MANIFEST_TEXT.replace(".MainActivity", ".MaliciousActivity")
        self.assertNotEqual(o.manifest_tree(o.MANIFEST_TEXT), o.manifest_tree(other))
        self.assertEqual(o.manifest_facts(o.MANIFEST_TEXT)["activities"], [".MainActivity"])

    def test_snapshot_detects_new_file_and_modified_bytes(self):
        path = self.dir / "fixture"
        o.write_authored_project(path)
        first = o.snapshot_tree(path)
        (path / "res/values/strings.xml").write_text("CHANGED", encoding="utf-8")
        self.assertNotEqual(o.snapshot_tree(path), first)
        (path / "new-file").write_bytes(b"injected")
        self.assertIn("new-file", o.snapshot_tree(path))

    def test_apk_container_checks_known_magic_and_literal(self):
        path = self.dir / "authored.apk"
        entries = {
            "AndroidManifest.xml": bytes.fromhex(o.AXML_MAGIC) + b"manifest",
            "classes.dex": bytes.fromhex(o.DEX_MAGIC) + o.ORACLE_LITERAL.encode(),
            "resources.arsc": bytes.fromhex(o.ARSC_MAGIC) + o.RESOURCE_LITERAL.encode(),
        }
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        facts = o.apk_facts(path)
        self.assertIsNone(facts["zip_test"])
        self.assertEqual(facts["manifest_magic"], o.AXML_MAGIC)
        self.assertEqual(facts["dex_magic"], o.DEX_MAGIC)
        self.assertEqual(facts["arsc_magic"], o.ARSC_MAGIC)
        self.assertTrue(facts["dex_has_oracle_literal"])
        self.assertTrue(facts["arsc_has_resource_literal"])
        self.assertEqual(set(facts["names"]), set(entries))

    def test_bad_zip_is_not_a_success(self):
        path = self.dir / "not-an-apk.apk"
        path.write_bytes(b"random bytes")
        with self.assertRaises(zipfile.BadZipFile):
            o.apk_facts(path)

    def test_run_folder_may_not_be_source_or_station(self):
        proc = subprocess.run([sys.executable, "-X", "utf8", "-B", str(RUNNER),
                               "--station", str(ROOT), "--runs-root", str(ROOT / "forbidden"),
                               "--apktool-version", "3.0.3"],
                              capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--runs-root may not be inside the station", proc.stderr)
        self.assertFalse((ROOT / "forbidden").exists())

    def test_version_required_without_mutating_output(self):
        out = self.dir / "not-created"
        proc = subprocess.run([sys.executable, "-X", "utf8", "-B", str(RUNNER),
                               "--station", str(ROOT), "--runs-root", str(out)],
                              capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--apktool-version", proc.stderr)
        self.assertFalse(out.exists())

    def test_global_result_json_is_not_a_runner_cli_option(self):
        proc = subprocess.run([sys.executable, "-X", "utf8", "-B", str(RUNNER),
                               "--station", str(ROOT), "--runs-root", str(self.dir / "runs"),
                               "--apktool-version", "3.0.3",
                               "--result-json", str(self.dir / "overwrite.json")],
                              capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unrecognized arguments", proc.stderr)
        self.assertFalse((self.dir / "overwrite.json").exists())


if __name__ == "__main__":
    unittest.main()
