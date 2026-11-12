#!/usr/bin/env python3
"""Harmless subprocess fixture. It is not a product capability or provider."""
import json
import os
from pathlib import Path
import sys
import time

target = json.loads(Path(sys.argv[1]).read_text())
mode = sys.argv[2] if len(sys.argv) > 2 else "good"
value = target["value"] if mode != "bad" else target["value"] + 1
output = {"value": value}
if mode in ("wait", "pid-wait"):
    output["pid"] = os.getpid()
print(json.dumps(output), flush=True)
root = Path(os.environ["DEBUGGER_PROBE_ARTIFACT_ROOT"])
root.mkdir(parents=True, exist_ok=True)
if mode != "touch-only":
    (root / ("terminal.json" if mode == "reserved-name" else "result.json")).write_text(json.dumps(output))
else:
    # Only touches an external old file: no owned output is produced.
    os.utime(target["old_artifact"], None)
if mode == "marker":
    (root / "dispatched.marker").write_text("a real child executed this write")
if mode in ("wait", "pid-wait"):
    time.sleep(15)
if mode == "fail-exit":
    raise SystemExit(7)
