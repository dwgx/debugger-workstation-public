# OWNER: researcher-q4 | setukou-20261111/v5/slices/q4-wrappers/receipt_tools/dump_wrappers.py
"""Q4 LOCAL-CHECK-0: bounded, READ-ONLY text dump of all 23 mcp/bin/*.cmd wrappers.

Runs under `timeout.exe 30`. This is the evidence behind CLASSIFY.tsv: the
`kind` / `launches_what` columns are derived from THIS literal wrapper text,
not from memory. No wrapper is executed; only its bytes are read and printed.
"""
from __future__ import annotations
import pathlib
import sys

BIN = pathlib.Path("D:/Software/Tool/WorkStation/debugger/mcp/bin")
wrappers = sorted((p for p in BIN.glob("*.cmd") if p.is_file()), key=lambda p: p.name)
print(f"wrappers_dumped={len(wrappers)}")
for p in wrappers:
    text = p.read_text(encoding="utf-8", errors="replace")
    print(f"=== BEGIN {p.name} ===")
    for i, line in enumerate(text.splitlines(), 1):
        print(f"{i:>3}|{line}")
    print(f"=== END {p.name} ===")
print("NOTE: text dump = static evidence only; backend_usable UNVERIFIED")
sys.exit(0)
