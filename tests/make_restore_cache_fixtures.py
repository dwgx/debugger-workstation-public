#!/usr/bin/env python3
"""Build inert 7z inputs for restore-from-cache.regress.ps1.

Requires an explicitly selected 7z executable and a new output directory.
The .exe/.zip members are synthetic text sentinels, never executed. Member
bytes reproduce the 2026-11-19 regression captures; timestamps are fixed.
Archive hashes can differ between 7z versions and historical captures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

MEMBERS = {
    "A/_download-stage/sentinelA-tool.zip": ("stage zip A", "3f8e1e69e6c6d06ef6bfd5b4860c2a78a7e6631992110376926b480b8c4b68f5"),
    "A/_download-stage/subdir/sentinelA-sub.zip": ("stage zip A subdir", "50aeeaaf3c2ed42643b6ed539f848ad255e37bcd993dbec7d6b1971fb9573e70"),
    "A/Cheat Engine/cheatengine-sentinelA.txt": ("cheat engine tree file A", "f8df1f3ae077ad45de942558cbc69268e94169919ad07d8638d8eafe1a0a9de8"),
    "A/npcap-1.90-sentinelA.exe": ("NPCAP-SENTINEL-A dummy payload, never executed", "7a5f6156e5fda8392eb96316c830ed1be45dc1964cf8b14982a0a652dc65c7bd"),
    "A/WiresharkPortable64_4.2.0-sentinelA.paf.exe": ("WIRESHARK-PAF-SENTINEL-A dummy payload, never executed", "54a01b75e4dd967dba313968eab3009cc0511e5ada1af0a9c6a613382ef3ba92"),
    "B/_download-stage/sentinelB-tool.zip": ("stage zip B", "10b4d28366c3954ecd56f115c32996e6fa7647787579a92ccf96d4ec760eeac8"),
    "B/Cheat Engine/cheatengine-sentinelB.txt": ("cheat engine tree file B", "23592507d0199a4f553bc528edf1166ba77e863c65a9163702f6f842ff20ebd2"),
    "C/_download-stage/sentinelC-tool.zip": ("stage zip C", "6a159b05ec491b6a3dfcd2e83c6fdb377c6fe833f78b22eff8cbc8f453a4430e"),
    "C/Cheat Engine/cheatengine-sentinelC.txt": ("cheat engine tree file C", "e1744b4ff7cba2a682c5374665a6391cce78259cfe41e1e6159f58f782fb9580"),
    "C/npcap-1.91-sentinelC.exe": ("NPCAP-SENTINEL-C dummy payload, never executed", "83d4fed063d8932c9e0cd606aa6cf2916c53072370f5b732962e59cea08d1833"),
}
FIXED_TIME_NS = 1577836800 * 1_000_000_000  # 2020-01-01 00:00:00 UTC


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sevenzip", required=True, type=Path, help="Existing 7z executable")
    parser.add_argument("--output", required=True, type=Path, help="New output directory")
    args = parser.parse_args()
    sevenzip = args.sevenzip.expanduser().resolve()
    if not sevenzip.is_file():
        parser.error("--sevenzip must identify an existing executable file")
    output = Path(os.path.abspath(os.path.expanduser(str(args.output))))
    if output.exists() or output.is_symlink():
        parser.error("--output must not already exist")
    output.mkdir(parents=True, exist_ok=False)
    payload = output / "payload"
    archives = output / "archives"
    logs = output / "logs"
    for folder in (payload, archives, logs):
        folder.mkdir()
    for name, (content, expected_sha256) in MEMBERS.items():
        path = payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("ascii"))
        if sha256(path) != expected_sha256:
            raise RuntimeError(f"Synthetic member hash mismatch: {name}")
    for path in sorted(payload.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        os.utime(path, ns=(FIXED_TIME_NS, FIXED_TIME_NS))
    os.utime(payload, ns=(FIXED_TIME_NS, FIXED_TIME_NS))

    commands = []
    for name, archive_name, options in (
        ("A", "A.7z", ["-mx=5"]),
        ("B", "B.7z", ["-mx=5"]),
        ("C", "corruptC.7z", ["-mx=0", "-ms=off"]),
    ):
        argv = [str(sevenzip), "a", "-t7z", "-y", *options, str(archives / archive_name), "*"]
        log = logs / f"{name}-build.log"
        with log.open("wb") as stream:
            result = subprocess.run(argv, cwd=payload / name, stdout=stream, stderr=subprocess.STDOUT)
        commands.append({"argv": argv, "exit": result.returncode, "log": str(log)})
        if result.returncode:
            raise RuntimeError(f"7z fixture creation failed for {name}; see {log}")

    # Match the original corrupt capture: damage npcap data bytes 16..19 while
    # leaving the stored member CRC and archive header intact.
    corrupt_path = archives / "corruptC.7z"
    data = bytearray(corrupt_path.read_bytes())
    marker = b"NPCAP-SENTINEL-C"
    if data.count(marker) != 1:
        raise RuntimeError("Expected exactly one stored synthetic npcap marker")
    offset = data.find(marker)
    data[offset + 16:offset + 20] = bytes((0, 255, 0, 255))
    corrupt_path.write_bytes(data)

    unicode_dir = archives / "\u7a7a\u683c \u76ee\u5f55"
    unicode_dir.mkdir()
    shutil.copyfile(archives / "A.7z", unicode_dir / "\u6863\u6848 A.7z")
    archive_a = (archives / "A.7z").read_bytes()
    (archives / "partial-A.7z").write_bytes(archive_a[:int(len(archive_a) * 0.55)])
    manifest = {
        "schema": "cache-restore-synthetic-fixtures.1",
        "sevenzip": str(sevenzip),
        "sevenzip_sha256": sha256(sevenzip),
        "output": str(output),
        "archives": str(archives),
        "fixed_member_timestamp_utc": "2020-01-01T00:00:00Z",
        "members": [
            {"path": name, "sha256": digest, "bytes": len(content.encode("ascii"))}
            for name, (content, digest) in MEMBERS.items()
        ],
        "archive_files": [
            {"path": path.relative_to(archives).as_posix(), "bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in sorted(archives.rglob("*")) if path.is_file()
        ],
        "commands": commands,
        "corruption": "C npcap bytes 16..19 replaced with 00 FF 00 FF; original stored CRC retained",
        "fixture_executables_run": False,
    }
    manifest_path = output / "fixture-manifest.json"
    manifest_path.write_bytes((json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(f"ARCHIVES={archives}")
    print(f"MANIFEST={manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
