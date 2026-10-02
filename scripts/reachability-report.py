#!/usr/bin/env python
"""What can this arsenal actually DO, as distinct from what it declares?

WHY THIS EXISTS. "12 of 24 capabilities are callable" is a static fact about the registry: an
`invoke` block exists. It is the wrong number, and it was wrong by a lot. Measured 2026-10-02 by
scanning all 32 mission artifacts under E:/missions:

    capabilities declaring an invoke   12
    never ran inside any mission        1   crypto.jose.parse
    ran but never SUCCEEDED              3   net.pcap.analyse, forensics.memory.artefact, mobile.apk.static

So **four of twelve "callable" capabilities have never once produced a fact in a mission.**
Nothing static could have said so, because being callable is a property of the registry while
having worked is a property of history. `forensics.memory.artefact` is the instructive one: it
is routable, it runs, and it exits non-zero with a Node stack trace -- a capability that looks
perfectly armed in the registry and cannot succeed for any caller on this station.

This script exists so that figure is a command rather than a thing somebody remembered to
recompute, and so the per-axis number that matters is reported next to the one that does not.

    python scripts/reachability-report.py
    python scripts/reachability-report.py --missions-root E:\\missions

An error is not a zero here either: a mission artifact that cannot be parsed is COUNTED as
unreadable and reported, never quietly skipped, because a scan that silently drops the files it
cannot read will report a rosier arsenal than the one that exists.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(REPO, "manifests", "capabilities.json")


def scan(root: str):
    routed, ok, unreadable = Counter(), Counter(), []
    files = sorted(glob.glob(os.path.join(root, "*", "artifact.json")))
    for f in files:
        try:
            a = json.load(open(f, encoding="utf-8-sig"))
        except Exception as e:  # noqa: BLE001
            unreadable.append((f, str(e)))
            continue
        for r in (a.get("chain") or []):
            cid = r.get("capability")
            if not cid:
                continue
            routed[cid] += 1
            if r.get("ok"):
                ok[cid] += 1
    return files, routed, ok, unreadable


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--missions-root", default=r"E:\missions")
    args = ap.parse_args()

    caps = json.load(open(REG, encoding="utf-8"))["capabilities"]
    inv = {c["id"]: c for c in caps if c.get("invoke")}
    files, routed, ok, unreadable = scan(args.missions_root)

    print(f"mission artifacts read : {len(files)}"
          + (f"   UNREADABLE: {len(unreadable)}" if unreadable else ""))
    for f, e in unreadable:
        print(f"   !! could not parse {f}: {e}")
    print(f"capabilities declaring an invoke : {len(inv)}")
    print()
    print(f"{'capability':<30}{'routed':>7}{'ok':>5}  status")
    never_ran, never_ok = [], []
    for cid in sorted(inv):
        if routed[cid] == 0:
            status = "NEVER RAN IN A MISSION"
            never_ran.append(cid)
        elif ok[cid] == 0:
            status = "ran, never succeeded"
            never_ok.append(cid)
        else:
            status = f"worked ({ok[cid]}x)"
        print(f"{cid:<30}{routed[cid]:>7}{ok[cid]:>5}  {status}")

    # EVERY declared axis, counted over ALL capabilities, including the ones with no callable
    # entry at all. The first version iterated only over axes that had an invoke, which silently
    # hid precisely the darkest ones: Q5.vuln-shape never appeared in the output, and its absence
    # read as "not applicable" rather than "nothing has ever worked here". That is the same
    # failure as an unreadable artifact being skipped, in a different costume -- a report that
    # omits the worst rows looks healthier than one that prints them.
    per_axis: dict[str, dict] = {}
    for c in caps:
        for q in (c.get("question_types") or []):
            d = per_axis.setdefault(q, {"declared": 0, "worked": 0})
            if c.get("invoke"):
                d["declared"] += 1
                if ok.get(c["id"]):
                    d["worked"] += 1

    print()
    print("per axis, DECLARED callable vs has actually produced a fact in a mission:")
    dark = []
    for q in sorted(per_axis):
        d = per_axis[q]
        if d["worked"] == 0:
            why = ("no callable capability declares it" if d["declared"] == 0
                   else f"{d['declared']} declared callable, none has ever worked")
            dark.append(q)
            print(f"  {q:<16} {d['worked']}/{d['declared']}   <-- DARK: {why}")
        else:
            print(f"  {q:<16} {d['worked']}/{d['declared']}")
    if dark:
        print(f"\n{len(dark)} of {len(per_axis)} axes have never produced a single fact in a mission: "
              + ", ".join(dark))

    if never_ran or never_ok:
        print(f"\n{len(never_ran) + len(never_ok)} of {len(inv)} 'callable' capabilities have never"
              f" produced a fact in a mission.")
        print("That is the number to quote. 'Callable' is a property of the registry; 'worked' is a")
        print("property of history, and only history can tell you which one you have.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())