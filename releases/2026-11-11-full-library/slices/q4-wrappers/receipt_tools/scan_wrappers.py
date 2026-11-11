# OWNER: researcher-q4 | setukou-20261111/v5/slices/q4-wrappers/receipt_tools/scan_wrappers.py
"""Q4 LOCAL-CHECK-2: bounded, READ-ONLY presence + sha256 scan of mcp/bin/*.cmd.

Runs under `timeout.exe 30`. Reads product-tree files only; never executes a
wrapper, never starts a backend, never writes outside stdout. A hash proves the
wrapper TEXT is stable/readable — NOT that its backend is installed or connectable.
"""
from __future__ import annotations
import hashlib
import pathlib
import sys

BIN = pathlib.Path("D:/Software/Tool/WorkStation/debugger/mcp/bin")
files = sorted((p for p in BIN.glob("*") if p.is_file()), key=lambda p: p.name)
print(f"bin_dir={BIN}")
print(f"wrappers_scanned={len(files)}")
by_ext: dict[str, int] = {}
for p in files:
    by_ext[p.suffix.lower()] = by_ext.get(p.suffix.lower(), 0) + 1
    data = p.read_bytes()
    print(f"wrapper|{p.name}|bytes={len(data)}|sha256={hashlib.sha256(data).hexdigest()}")
print("by_ext=" + ",".join(f"{k}:{v}" for k, v in sorted(by_ext.items())))
print("NOTE: file presence + sha256 = static evidence only; backend_usable UNVERIFIED")
sys.exit(0)
