#!/usr/bin/env python3
"""Validate publication coverage and build/verify an explicit Git-blob source bundle.

No downloads, installs, environment changes, or executable payloads. Python 3.10+.
The allowlist is reviewed data; this tool never discovers files to add to it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zipfile

CATALOG = "manifests/publication.json"
ALLOWLIST = "manifests/publication-files.json"
RECEIPT = "SOURCE-BUNDLE.json"
FORBIDDEN_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".omp", "vendor", "_download-stage"}
FORBIDDEN_NAMES = {"owner.md", "local.json", ".mcp.json", "auth.json", "credentials.json", "idapro.hexlic"}
FORBIDDEN_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".zip", ".7z", ".rar", ".jar", ".apk", ".pcap", ".pcapng", ".dmp", ".pem", ".pfx", ".key", ".jsonl"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
)
MAX_FILE = 20 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes):
    return json.loads(data.decode("utf-8-sig"))


def safe_path(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        fail(f"unsafe path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(p in (".", "..") for p in path.parts):
        fail(f"unsafe path: {name!r}")
    lower = [p.lower() for p in path.parts]
    if any(p in FORBIDDEN_PARTS for p in lower) or path.name.lower() in FORBIDDEN_NAMES:
        fail(f"private/runtime path is not distributable: {name}")
    if path.name.lower() == ".env" or path.name.lower().startswith(".env."):
        if not path.name.lower().endswith(".example"):
            fail(f"environment values are not distributable: {name}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        fail(f"binary/capture/credential/transcript payload is not distributable: {name}")
    return name


def inspect_bytes(name: str, data: bytes) -> None:
    safe_path(name)
    if len(data) > MAX_FILE:
        fail(f"oversize source file: {name}")
    data.decode("utf-8-sig")  # Source release is text-only; binary fixtures are regenerated.
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        fail(f"credential-shaped content in {name}; review/redact the source, never bypass the check")


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "--no-optional-locks", "-C", str(repo), *args], capture_output=True, check=False)
    if result.returncode:
        fail(result.stderr.decode("utf-8", "replace").strip() or f"git failed: {args[0]}")
    return result.stdout


def revision_tree(repo: Path, revision: str):
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    entries = {}
    for item in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if not item:
            continue
        head, raw_name = item.split(b"\t", 1)
        mode, kind, object_id = head.decode().split()
        name = raw_name.decode("utf-8")
        if kind != "blob" or mode not in ("100644", "100755"):
            fail(f"symlinks and submodules are not source payloads: {name}")
        entries[name] = (mode, object_id)
    return commit, entries


def validate(data: dict[str, bytes], *, all_paths: set[str] | None = None) -> dict:
    policy = parse_json(data[CATALOG])
    listing = parse_json(data[ALLOWLIST])
    if policy.get("schema") != "workstation-publication/v1" or listing.get("schema") != "workstation-publication-files/v1":
        fail("unsupported publication schema")
    approved = listing["files"]
    paths = [row["path"] for row in approved]
    if paths != sorted(set(paths)):
        fail("publication file paths must be sorted and unique")
    if len({path.casefold() for path in paths}) != len(paths):
        fail("publication paths collide on a case-insensitive filesystem")
    if all_paths is not None and set(paths) != all_paths:
        fail(f"allowlist/tree mismatch: missing={sorted(set(paths)-all_paths)}, unreviewed={sorted(all_paths-set(paths))}")
    if set(data) != set(paths):
        fail("source payload does not exactly match the reviewed allowlist")
    if sum(map(len, data.values())) > MAX_TOTAL:
        fail("source bundle exceeds the documented size ceiling")
    for row in approved:
        if not row.get("license") or not row.get("provenance"):
            fail(f"missing license/provenance: {row.get('path')}")
        inspect_bytes(row["path"], data[row["path"]])
    tools = parse_json(data["manifests/tools.json"])["tools"]
    expected_tools = {(category, tool["name"]) for category, group in tools.items() for tool in group}
    recorded_tools = [(tool["category"], tool["name"]) for tool in policy["tools"]]
    if len(recorded_tools) != len(set(recorded_tools)) or set(recorded_tools) != expected_tools:
        fail("tool publication coverage differs from tools.json")
    expected_backends = set(parse_json(data["mcp/.mcp.json.template"])["mcpServers"]) - {"debugger-router"}
    recorded_backends = [backend["id"] for backend in policy["backends"]]
    if len(recorded_backends) != len(set(recorded_backends)) or set(recorded_backends) != expected_backends:
        fail("backend publication coverage differs from the wired template")
    sources = {source["id"] for source in policy["sources"]}
    for record in policy["tools"] + policy["backends"]:
        if not record.get("source_ids") or not set(record["source_ids"]) <= sources:
            fail(f"unknown source reference: {record.get('id', record.get('name'))}")
        if not record.get("distribution") or not record.get("install"):
            fail("each tool/backend needs an explicit distribution decision and installation method")
    for source in policy["sources"]:
        if not source.get("url") or not source.get("license", {}).get("status"):
            fail(f"source lacks URL/license decision: {source.get('id')}")
    counts = {"tools": len(expected_tools), "backends": len(expected_backends)}
    if counts != policy["expected_counts"]:
        fail("publication count contract differs from the declared manifests")
    return {"schema": "workstation-publication-check/v1", "ok": True, "files": len(paths), **counts}


def read_worktree(repo: Path) -> dict[str, bytes]:
    listing = parse_json((repo / ALLOWLIST).read_bytes())
    data = {}
    root = repo.resolve()
    for row in listing["files"]:
        name = safe_path(row["path"])
        path = repo / name
        if any(part.is_symlink() for part in (path, *path.parents)) or not path.resolve().is_relative_to(root):
            fail(f"symlink/reparse source path: {name}")
        data[name] = path.read_bytes()
    return data


def load_revision(repo: Path, revision: str):
    commit, tree = revision_tree(repo, revision)
    if ALLOWLIST not in tree:
        fail("selected revision has no reviewed publication allowlist")
    approved = parse_json(git(repo, "cat-file", "blob", tree[ALLOWLIST][1]))["files"]
    names = [row["path"] for row in approved]
    if set(names) != set(tree):
        fail(f"allowlist/tree mismatch: missing={sorted(set(names)-set(tree))}, unreviewed={sorted(set(tree)-set(names))}")
    data = {name: git(repo, "cat-file", "blob", tree[name][1]) for name in names}
    summary = validate(data, all_paths=set(tree))
    return commit, tree, data, summary


def build(repo: Path, revision: str, output: Path) -> dict:
    commit, tree, data, summary = load_revision(repo, revision)
    receipt = {
        "schema": "workstation-source-bundle/v1", "revision": commit,
        "byte_source": "git-blob", "checks": summary,
        "files": [{"path": name, "sha256": digest(content), "bytes": len(content),
                   "mode": tree[name][0], "git_object": tree[name][1]}
                  for name, content in sorted(data.items())],
        "scope": "The receipt describes source payload files, excluding this receipt itself. It is not a signature or runtime acceptance.",
    }
    # 'x' refuses an existing output, including an existing symlink. No extracted files.
    with output.open("xb") as target:
        import os
        created_identity = os.fstat(target.fileno())
        try:
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, content in sorted({**data, RECEIPT: (json.dumps(receipt, ensure_ascii=False, indent=2)+"\n").encode()}.items()):
                    item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | (0o755 if tree.get(name, ("100644",))[0] == "100755" else 0o644)) << 16
                    archive.writestr(item, content)
        except BaseException:
            # Only remove the file this call created; never an existing input/output.
            target.close()
            current = output.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created_identity.st_dev, created_identity.st_ino):
                output.unlink()
            raise
    return {**summary, "revision": commit, "bundle_sha256": digest(output.read_bytes()), "output": str(output)}


def verify(bundle: Path, repo: Path | None, revision: str | None) -> dict:
    with zipfile.ZipFile(bundle) as archive:
        infos = archive.infolist()
        if len(infos) != len({i.filename for i in infos}):
            fail("duplicate archive member")
        if sum(i.file_size for i in infos) > MAX_TOTAL + MAX_FILE:
            fail("oversize archive payload")
        for item in infos:
            safe_path(item.filename)
            if item.is_dir() or stat.S_ISLNK(item.external_attr >> 16) or item.file_size > MAX_FILE:
                fail(f"unsupported archive member: {item.filename}")
        receipt = parse_json(archive.read(RECEIPT))
        if receipt.get("schema") != "workstation-source-bundle/v1" or receipt.get("byte_source") != "git-blob":
            fail("unsupported bundle receipt")
        rows = receipt["files"]
        names = [row["path"] for row in rows]
        if names != sorted(set(names)) or set(names) | {RECEIPT} != {i.filename for i in infos}:
            fail("archive members do not match receipt")
        data = {}
        for row in rows:
            content = archive.read(row["path"])
            if len(content) != row["bytes"] or digest(content) != row["sha256"]:
                fail(f"payload checksum mismatch: {row['path']}")
            data[row["path"]] = content
    summary = validate(data)
    if repo is not None:
        commit, _, expected, _ = load_revision(repo, revision or receipt["revision"])
        if commit != receipt["revision"] or expected != data:
            fail("bundle differs from the selected repository revision")
        summary["repository_match"] = True
    else:
        summary["repository_match"] = None
    return {**summary, "revision": receipt["revision"], "bundle_sha256": digest(bundle.read_bytes())}


def verify_preserved(bundle: Path, manifest_path: Path) -> dict:
    expected_bytes = manifest_path.read_bytes()
    manifest = parse_json(expected_bytes)
    if manifest.get("schema") != "workstation-preserved-source/v1":
        fail("unsupported preserved source schema")
    rows = manifest["source_files"]
    names = [row["path"] for row in rows]
    if names != sorted(set(names)) or len({p.casefold() for p in names}) != len(names):
        fail("preserved source paths are duplicated or unsorted")
    with zipfile.ZipFile(bundle) as archive:
        members = archive.infolist()
        expected_names = set(names) | {"SOURCE-MANIFEST.json", "PRESERVATION-NOTICE.txt"}
        if len(members) != len(expected_names) or {i.filename for i in members} != expected_names:
            fail("preserved archive does not match its exact source allowlist")
        if sum(i.file_size for i in members) > MAX_TOTAL:
            fail("oversize preserved archive")
        for item in members:
            safe_path(item.filename)
            if item.is_dir() or stat.S_ISLNK(item.external_attr >> 16) or item.file_size > MAX_FILE:
                fail("unsupported preserved archive member")
        if archive.read("SOURCE-MANIFEST.json") != expected_bytes:
            fail("preserved archive manifest differs from the reviewed repository copy")
        for row in rows:
            content = archive.read(row["path"])
            inspect_bytes(row["path"], content)
            if len(content) != row["bytes"] or digest(content) != row["sha256"]:
                fail(f"preserved source checksum mismatch: {row['path']}")
        if digest(archive.read("LICENSE")) != manifest["license_sha256"]:
            fail("preserved license differs")
    return {"ok": True, "source_files": len(rows), "revision": manifest["revision"],
            "bundle_sha256": digest(bundle.read_bytes()), "scope": "source bytes and license; no service/runtime acceptance"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    check = sub.add_parser("check", help="validate an explicit working-tree allowlist and catalog")
    check.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    make = sub.add_parser("build", help="build exact Git blobs at a committed revision")
    make.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    make.add_argument("--revision", required=True)
    make.add_argument("--output", type=Path, required=True)
    verify_parser = sub.add_parser("verify", help="check bundle consistency; optionally bind it to a repository revision")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser.add_argument("--repo", type=Path)
    verify_parser.add_argument("--revision")
    preserved = sub.add_parser("verify-preserved", help="verify a separately licensed preserved source release")
    preserved.add_argument("--bundle", type=Path, required=True)
    preserved.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "check":
            result = validate(read_worktree(args.repo))
        elif args.action == "build":
            result = build(args.repo, args.revision, args.output)
        elif args.action == "verify-preserved":
            result = verify_preserved(args.bundle, args.manifest)
        else:
            if args.revision and not args.repo:
                fail("--revision requires --repo")
            result = verify(args.bundle, args.repo, args.revision)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, zipfile.BadZipFile) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
