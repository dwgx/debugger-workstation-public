#!/usr/bin/env python3
"""Shared helpers: executable oracle checks and nonzero CLI exit enforcement."""
import json
import sys
from pathlib import Path


def fresh_run_dir(parent, name):
    """Reserve an unused owned directory before any provider is launched."""
    if Path(name).name != name or name in ("", ".", ".."):
        raise ValueError("run name must be one directory component")
    parent = Path(parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / name
    target.mkdir(exist_ok=False)
    return target


class Oracle:
    """Accumulates named boolean checks; fail()/finish() drive CLI exit."""

    def __init__(self):
        self.checks = {}

    def check(self, name, value, detail=None):
        v = bool(value)
        self.checks[name] = {"pass": v, "detail": detail}
        return v

    @property
    def ok(self):
        return all(c["pass"] for c in self.checks.values()) and bool(self.checks)

    @property
    def failed(self):
        return [k for k, c in self.checks.items() if not c["pass"]]

    def finish(self, result, out_path=None, extra=None):
        """Write result with oracle block, print summary, exit nonzero on any fail."""
        result["oracle"] = {
            "checks": self.checks,
            "all_pass": self.ok,
            "failed": self.failed,
        }
        if extra:
            result.update(extra)
        if out_path is not None:
            out_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        summary = {
            "all_pass": self.ok,
            "failed": self.failed,
            "checks": {k: c["pass"] for k, c in self.checks.items()},
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        sys.exit(0 if self.ok else 2)


def no_mcp_env(base=None):
    """Neutralize inherited MCP client plumbing without printing any value."""
    env = dict(base if base is not None else __import__("os").environ)
    for k in list(env):
        ku = k.upper()
        if ku.startswith("MCP") or ku.startswith("CLAUDE") or ku.startswith("CODEX"):
            env.pop(k, None)
    env.update({"PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"})
    return env

