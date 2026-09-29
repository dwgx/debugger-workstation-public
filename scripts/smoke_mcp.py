"""Smoke debugger-router list_backends plus backends that do not need a GUI session."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("DEBUGGER_ROOT", Path(__file__).resolve().parents[1]))
os.environ["DEBUGGER_ROOT"] = str(ROOT)
sys.path.insert(0, str(ROOT / "mcp" / "debugger-router"))

import server  # noqa: E402


def main() -> int:
    data = server.list_backends()
    names = sorted(b["name"] for b in data["backends"])
    print("BACKENDS", data.get("count"), ",".join(names))
    required = ("sevenzip", "apktool", "jadx", "wireshark")
    optional = ("ghidra", "ida", "ilspy", "imhex", "radare2", "frida", "volatility3", "reqable", "x64dbg")
    fail = 0
    for name in required:
        try:
            result = asyncio.run(server.smoke_backend(name, timeout_seconds=35.0))
            print("SMOKE", name, result.get("status"), "tools", result.get("tool_count"), "s", result.get("elapsed_seconds"))
            if result.get("status") != "PASS":
                fail += 1
        except Exception as exc:
            print("SMOKE", name, "FAIL", type(exc).__name__, str(exc)[:240])
            fail += 1
    for name in optional:
        try:
            result = asyncio.run(server.smoke_backend(name, timeout_seconds=20.0))
            print("OPT", name, result.get("status"), "tools", result.get("tool_count"), "s", result.get("elapsed_seconds"))
        except Exception as exc:
            print("OPT", name, "FAIL", type(exc).__name__, str(exc)[:180])
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
