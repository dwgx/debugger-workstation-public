#!/usr/bin/env python
"""Run capa over a PE and emit its behavioural findings as JSON.

WHY THIS EXISTS. capa 8.x is installed, works headlessly, and had NO capability entry at all --
an audit for it found the string only inside the word "capabilit*y*". It is target-scoped, which
is the property this registry has been missing: it takes a path, so a mission can actually route
it, unlike the five capabilities whose subject is a token, a pcap, an APK or a lab artefact.

STDOUT MUST BE PURE JSON and stderr must stay silent. mission.ps1 runs a capability as
`& $runner @argList 2>&1 | Out-String` and MERGES the two streams, so a tool that decorates
stderr corrupts the JSON it declared -- measured twice on other tools, each time costing a whole
mission round that reported ok:false while the same command worked by hand.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

# Added 2026-10-04 so this probe stops being a string match. `assert-probes.py` matches
# substrings in stdout and prints its own weakness on every OK: "NOT a claim that the
# instrument ran: a stub which prints them satisfies it." 22 of 27 capabilities were in
# exactly that position. Writing the result to disk moves the verdict onto the filesystem.
# See scripts/probe_artifact.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from probe_artifact import write_artifact  # noqa: E402

# RESOLVED RELATIVE TO THIS FILE, and that is a fix rather than a style choice.
# Measured 2026-10-03 by an independent audit: this used to hardcode the ORIGINAL station's
# absolute path. Run from a clone at any other path it did not refuse -- it found capa.exe on the
# machine it was written on and measured with it, reporting PASS about a tool the reader is not
# using. A silent wrong-machine measurement is strictly worse than a clean failure: the number
# looks right and is not. The three sibling tools that resolve from $PSScriptRoot already fail
# cleanly in a clone, which is the correct behaviour; this joins them.
#
# CAPA_ENV overrides the location for a caller who keeps the tools elsewhere.
_HERE = pathlib.Path(__file__).resolve().parent
CAPA = os.environ.get("CAPA_EXE") or str(
    _HERE.parents[1] / "Static-Reversing" / "capa" / "capa.exe")


def refuse(code: int, msg: str, **extra):
    out = {"ok": False, "exit": code, "error": msg}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--capa", default=CAPA)
    args = ap.parse_args()

    # Checked before invoking: capa exits non-zero on a non-PE but only after ~3 s of engine
    # start, and its refusal arrives as a formatted banner rather than anything parseable. A
    # refusal should cost nothing and read as a refusal.
    try:
        with open(args.binary, "rb") as fh:
            head = fh.read(2)
    except OSError as e:
        refuse(1, f"cannot read {args.binary}: {e}")
    if head != b"MZ":
        refuse(2, f"not a PE: first two bytes are {head.hex()}, expected 4d5a ('MZ')",
               first_bytes=head.hex())

    if not os.path.isfile(args.capa):
        refuse(2, f"capa not found at {args.capa}")

    p = subprocess.run([args.capa, "-j", args.binary], capture_output=True, text=True,
                       timeout=900)
    # stderr is deliberately NOT merged: capa is chatty on stderr and stdout is the contract.
    try:
        doc = json.loads(p.stdout)
    except Exception as e:
        refuse(2, f"capa did not produce parseable JSON on stdout: {e}",
               returncode=p.returncode, stdout_head=p.stdout[:200])

    rules = doc.get("rules") or {}
    by_ns: dict[str, int] = {}
    matched = []
    for name, r in rules.items():
        meta = (r or {}).get("meta") or {}
        ns = meta.get("namespace") or "(none)"
        by_ns[ns] = by_ns.get(ns, 0) + 1
        matched.append({
            "rule": name,
            "namespace": ns,
            "lib": meta.get("lib"),
        })

    result = {
        "ok": True,
        "exit": 0,
        "binary": args.binary,
        "capa_version": ((doc.get("meta") or {}).get("analysis") or {})
                         .get("capa", {}).get("version") or "(not reported in -j output)",
        "rules_matched": len(matched),
        "namespaces": by_ns,
        "matches": matched,
        "caveat": ("capa MATCHES A RULE, IT DOES NOT PROVE BEHAVIOUR. A rule hit means the "
                   "instructions for a known pattern are present -- 'change memory protection' "
                   "says the capability exists, not that it was used, and not that it was "
                   "malicious. It is also NOT a trust-boundary analysis: nothing here answers "
                   "'where does this trust something it should not'. Read a hit as 'look here', "
                   "which is also what the rule library's own docstrings mean."),
    }
    print(json.dumps(result))
    write_artifact("capa_probe", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())