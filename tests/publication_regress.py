#!/usr/bin/env python3
"""Bounded source-publication regression. No tool binaries or network are used.

Run against a committed candidate containing its reviewed allowlist. --output
must be a NEW directory; all generated archives stay there for inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    script = args.repo / "scripts/publication.py"
    rows = []

    def run(name, *arguments, expected=0):
        result = subprocess.run([sys.executable, "-B", str(script), *map(str, arguments)], capture_output=True, text=True, encoding="utf-8")
        (args.output / (name + ".stdout.txt")).write_text(result.stdout, encoding="utf-8")
        (args.output / (name + ".stderr.txt")).write_text(result.stderr, encoding="utf-8")
        ok = result.returncode == 0 if expected == 0 else result.returncode != 0
        rows.append({"case": name, "ok": ok, "exit": result.returncode, "expected": expected})
        return result

    first = args.output / "source-a.zip"
    second = args.output / "source-b.zip"
    run("catalog_and_allowlist", "check", "--repo", args.repo)
    run("build_git_blobs", "build", "--repo", args.repo, "--revision", "HEAD", "--output", first)
    run("bind_to_repository", "verify", "--bundle", first, "--repo", args.repo, "--revision", "HEAD")
    run("second_build", "build", "--repo", args.repo, "--revision", "HEAD", "--output", second)
    rows.append({"case": "deterministic_bytes", "ok": first.read_bytes() == second.read_bytes()})
    before = sha(first.read_bytes())
    run("refuse_existing_output", "build", "--repo", args.repo, "--revision", "HEAD", "--output", first, expected=1)
    rows.append({"case": "existing_output_unchanged", "ok": sha(first.read_bytes()) == before})
    with zipfile.ZipFile(first) as archive:
        original = {name: archive.read(name) for name in archive.namelist()}

    def mutant(name, mutate, resign=False):
        content = dict(original)
        mutate(content)
        if resign:
            receipt = json.loads(content["SOURCE-BUNDLE.json"])
            for row in receipt["files"]:
                if row["path"] in content:
                    data = content[row["path"]]
                    row.update(sha256=sha(data), bytes=len(data))
            content["SOURCE-BUNDLE.json"] = json.dumps(receipt).encode()
        path = args.output / (name + ".zip")
        with zipfile.ZipFile(path, "x") as archive:
            for key, data in content.items():
                archive.writestr(key, data)
        run(name, "verify", "--bundle", path, expected=1)

    mutant("changed_payload", lambda data: data.update({"README.md": data["README.md"] + b"\ntampered\n"}))
    mutant("missing_payload", lambda data: data.pop("README.md"))
    mutant("unexpected_private_path", lambda data: data.update({".env": b"SYNTHETIC=fixture\n"}))
    mutant("path_traversal", lambda data: data.update({"../outside.txt": b"synthetic\n"}))
    synthetic_token = ("gh" + "p_" + "x" * 40).encode()
    mutant("credential_shape_with_updated_receipt", lambda data: data.update({"README.md": synthetic_token}), resign=True)

    def remove_backend(data):
        policy = json.loads(data["manifests/publication.json"])
        policy["backends"].pop()
        data["manifests/publication.json"] = json.dumps(policy).encode()
    mutant("coverage_gap_with_updated_receipt", remove_backend, resign=True)
    report = {"schema": "workstation-publication-regress/v1", "total": len(rows), "passed": sum(row["ok"] for row in rows), "cases": rows,
              "scope": "Source packaging, catalog consistency, overwrite guard and negative controls; no installed-tool/backend acceptance."}
    (args.output / "RESULTS.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if all(row["ok"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
