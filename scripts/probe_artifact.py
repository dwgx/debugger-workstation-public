"""Shared artifact writer for probe scripts.

WHY THIS EXISTS. `assert-probes.py` decides a capability is real by matching STRINGS against
captured stdout, and it says so in its own OK verdict: "NOT a claim that the instrument ran: a
stub which prints them satisfies it." Measured 2026-10-04: 22 of 27 capabilities declared no
artifact, so 22 verdicts rested on that string match alone.

A probe that writes its result to disk closes that gap in the only way a stub cannot fake
without also writing a file. The shape is deliberately boring:

    from probe_artifact import write_artifact
    write_artifact("hardening_probe", result)          # -> native-lab/out/last-run-hardening_probe.json

and the registry entry gains `"produces": "native-lab/out/last-run-hardening_probe.json"`.

TWO RULES, both learned the hard way:

1. **One artifact per tool name.** Several capabilities run the SAME script with different
   flags. A single fixed path would let one tool's run satisfy another entry's declaration --
   which is the "a probe that cannot localise a fault is not much of a probe" failure.

2. **Never delete the old artifact on failure.** A failed run writes `ok: false` and its own
   error. "The artifact says this failed" is a fact a reader needs; the ABSENCE of a file is
   ambiguous between "never ran", "crashed before writing" and "wrote somewhere else".

Not imported by the lab loops themselves: those are Node, and `native-lab/tools/loop.mjs`
already carries its own equivalent writer. Two implementations of one boring idea is better
than one implementation with a language boundary nobody wants to cross.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

# scripts/probe_artifact.py -> station root
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def artifact_path(tool: str, out_dir: str = "native-lab/out") -> str:
    """-> repo-relative path for this tool's artifact.

    The tool name is slugified rather than trusted: it reaches here from a command line, and a
    name containing a path separator would otherwise write outside the output directory. That
    is a directory-traversal guard, not tidiness.

    `out_dir` is a PARAMETER. It used to be baked into the return value as "native-lab/out",
    which is the defect that put net-reverse's reader evidence inside another lab -- measured
    2026-10-04, and fixed at the call site there, but the default that caused it was still here.
    A default nobody can see is a default nobody overrides.
    """
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in tool).strip("._")
    if not safe:
        raise ValueError(f"probe_artifact: unusable tool name {tool!r}")
    return f"{out_dir}/last-run-{safe}.json"


def write_artifact(tool: str, payload: dict, out_dir: str = "native-lab/out") -> str:
    """Write `payload` to this tool's artifact. Never raises -- a probe must not fail because its
    bookkeeping failed, so a write error is printed and the probe still returns its verdict.

    Returns the repo-relative path, or "" if the write failed.
    """
    rel = artifact_path(tool, out_dir)
    try:
        # The strict bounded runner owns this absolute per-attempt root. Legacy
        # callers keep their established paths when no override is present.
        override = os.environ.get("DEBUGGER_PROBE_ARTIFACT_ROOT")
        if override:
            base = pathlib.Path(override)
            subdir = pathlib.Path(out_dir)
            if not base.is_absolute() or subdir.is_absolute() or ".." in subdir.parts:
                raise ValueError("invalid per-attempt artifact root or output directory")
            full = base / subdir / pathlib.Path(rel).name
            if not full.resolve().is_relative_to(base.resolve()):
                raise ValueError("artifact escaped its per-attempt root")
        else:
            full = REPO_ROOT / out_dir / pathlib.Path(rel).name
        full.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "schema": "probe-artifact@1",
            "artifact_version": 1,
            "tool": tool,
            **payload,
        }
        # COUNTS ARE DERIVED, not left to the caller. The .mjs member has always done this; this
        # one did not, so a caller that passed `checks` got an artifact with counts: null while
        # the sibling language produced real ones -- and a reader comparing the two would have to
        # know that the difference was an accident of implementation rather than a difference in
        # what was measured. Measured 2026-10-05 on crackme-corpus, which passed checks and got
        # null.
        checks = payload.get("checks")
        if isinstance(checks, list) and all(isinstance(c, dict) for c in checks):
            doc["counts"] = {
                "total": len(checks),
                "pass": sum(1 for c in checks if c.get("ok") or c.get("pass")),
                "fail": sum(1 for c in checks if not (c.get("ok") or c.get("pass"))),
            }
        out = full.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"ARTIFACT {str(full) if override else rel}", file=sys.stderr)
        return str(full) if override else rel
    except Exception as exc:  # noqa: BLE001
        print(f"ARTIFACT WRITE FAILED: {exc} -- the probe ran but left nothing checkable",
              file=sys.stderr)
        return ""
