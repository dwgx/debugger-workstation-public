"""Rewrite the wiki's registry figures from the LIVE registry, using the checker's own patterns.

WHY THIS SHAPE, and it is not the shape I wrote first.

The first version of this script carried its own nine regexes for the wiki's sentences. A sibling
measured what that actually covers: **2 of `doc-facts.py`'s 12 claim labels**, because its nine
entries were nine SENTENCE SHAPES all carrying the same two quantities -- the validator's rule and
case counts. Twenty-two live claims across four files (capability count, observed count, typed
edges, declared plans, runnable controls) were still maintained by hand, and one of the nine
shapes was DEAD: zero live matches, so drift could return through it with no writer and this script
saying nothing.

A second defect in the same shape: the script maintained "RULES holds 35 entries, 34 of them
numbered", which matches NO doc-facts claim at all -- a one-way ratchet with nothing behind it.

So this version imports `doc-facts.py` and uses ITS patterns. The checker decides what a claim
looks like; the writer cannot drift from it, because a shape the checker stops recognising is a
shape this script has never heard of.

  python scripts/sync-wiki-figures.py            # rewrite, print every change
  python scripts/sync-wiki-figures.py --check    # exit 1 if anything WOULD change

It writes only the numeric claims in the wiki, and it never deletes a superseded value: the wiki's
convention is to strike them, and `doc-facts.py` is built to ignore struck lines.

ONE PROSE SEGMENT NO GATE CHECKS, kept and labelled: "RULES holds N entries, M of them numbered
R1..RM". It is not one of doc-facts' claims, so nothing would notice it rotting. It is rewritten
here and named here so that the reader knows which number in the wiki has no referee.

Writes nothing outside `<project>/<private-tree>/wiki`. Reads the station registry read-only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WIKI = Path(r"<private-tree>\wiki")
# The four files that carry live registry figures. Named here rather than walked, because a figure in
# a file nobody listed is a figure nobody keeps correct -- and the harness asserts the list is the
# same one doc-fats scans.
FILES = (WIKI / "INDEX.md", WIKI / "CHARTER-ARSENAL.md", WIKI / "methods" / "arsenal-inventory.md",
         WIKI / "methods" / "arsenal-upgrade-plan.md")


def load_doc_facts():
    """doc-facts.py by path, so this script does not depend on the caller's sys.path."""
    spec = importlib.util.spec_from_file_location("doc_facts", REPO / "scripts" / "doc-facts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # MEASURED BUG, found by a sibling's harness on a planted wiki: two of doc-facts' claims --
    # the validator's rule count and its selftest case count -- derive through `_validator_number()`,
    # which returns None unless this module global is set. It is set in doc-facts' own main(), which
    # exec_module does not run. My writer then hit `if expected is None: continue` and SKIPPED BOTH,
    # silently: a wiki carrying "41 numbered rules" was reported "already current" by the writer while
    # doc-fats on the same wiki exited 1. A FALSE GREEN, on the very sentence that drifted four times
    # today. One line to fix; the reason it survived is below.
    mod._REPO = REPO
    return mod


def rules_total() -> int:
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "registry-verify.py"), "--count"],
                         capture_output=True, text=True, cwd=REPO)
    m = re.search(r"(\d+) entries", out.stdout)
    return int(m.group(1)) if m else 0


def rewrite(text: str, pattern: re.Pattern, expected: int, multiline: bool) -> tuple[str, int]:
    """Replace the NUMBER inside each match, choosing the group that actually holds it.

    Not `pattern.sub(str(expected))`: several of these patterns capture more than one number, and
    only one of them is the quantity being claimed. The group is found by asking which captured
    text is entirely digits, which is the only honest way to tell without re-deriving each claim's
    grammar by hand -- and re-deriving it by hand is the mistake this version exists to undo.
    """
    out, changed, pos = [], 0, 0
    for m in pattern.finditer(text):
        gi = None
        for i in range(1, (pattern.groups or 0) + 1):
            g = m.group(i)
            if g is not None and g.isdigit():
                gi = i
                break
        if gi is None or m.group(gi) == str(expected):
            continue
        out.append(text[pos:m.start(gi)])
        out.append(str(expected))
        pos = m.end(gi)
        changed += 1
    out.append(text[pos:])
    return "".join(out), changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if any figure is stale, changing nothing.")
    # --repo and --wiki, mirroring doc-facts.py's own pair. MEASURED REASON: this writer derives REPO
    # from __file__, so a copy of it inside a %TEMP% skeleton reads a registry that is not there,
    # `_validator_number` returns None for both validator claims, and the run exits 1 saying "could
    # not derive" -- indistinguishable, from the exit code, from "found stale figures". A writer that
    # can only ever touch one real wiki cannot be tested at all; these two flags are what make the
    # sibling's harness possible, and they are also just correct.
    ap.add_argument("--repo", default=None,
                    help="station repo root; defaults to this script's parent")
    ap.add_argument("--wiki", default=None,
                    help="wiki root; defaults to the sibling <project>/<private-tree>")
    args = ap.parse_args()

    global REPO, WIKI, FILES
    if args.repo:
        REPO = Path(args.repo).resolve()
    if args.wiki:
        WIKI = Path(args.wiki).resolve()
    FILES = (WIKI / "INDEX.md", WIKI / "CHARTER-ARSENAL.md", WIKI / "methods" / "arsenal-inventory.md",
             WIKI / "methods" / "arsenal-upgrade-plan.md")

    df = load_doc_facts()
    reg = json.loads((REPO / "manifests" / "capabilities.json").read_text(encoding="utf-8"))

    total_rules = rules_total()
    stale_files = 0
    underived: list[str] = []
    for path in FILES:
        if not path.exists():
            print(f"  !! missing: {path}")
            stale_files += 1
            continue
        original = text = path.read_text(encoding="utf-8")
        for label, pattern, fn, multiline in df.CLAIMS:
            try:
                expected = fn(reg)
            except Exception as exc:                   # noqa: BLE001 - a claim we cannot derive
                print(f"  !! {path.name}: cannot derive {label!r} ({exc})")
                underived.append(label)
                continue
            if expected is None:
                # NOT A SILENT SKIP. doc-facts refuses to print OK when a claim goes unchecked, and
                # says so in its own docstring: "a gate that quietly stops checking is the
                # always-green failure wearing a new hat". A writer that skips quietly is the same
                # failure wearing a writer's costume. Record it, finish, and exit non-zero.
                print(f"  !! {path.name}: cannot derive {label!r} -- LEFT ALONE")
                underived.append(label)
                continue
            hay = text if multiline else None
            if multiline:
                text, n = rewrite(text, pattern, int(expected), True)
            else:
                # per-line, because that is how the checker reads it
                lines = text.split("\n")
                total = 0
                for i, line in enumerate(lines):
                    new, k = rewrite(line, pattern, int(expected), False)
                    lines[i] = new
                    total += k
                text = "\n".join(lines)
                n = total
            if n:
                print(f"  {path.name:<26} {label:<34} {n} figure(s) -> {expected}")
        # the one segment with no referee, rewritten and labelled as such
        seg = re.compile(r"holds \*\*\d+ entries, \d+ of them numbered R1\.\.R\d+\*\*")
        text, n_seg = seg.subn(f"holds **{total_rules} entries, "
                              f"{total_rules - 1} of them numbered R1..R{total_rules - 1}**", text)
        if n_seg:
            print(f"  {path.name:<26} {'(unchecked) RULES holds N entries':<34} -> {total_rules}")
        if text != original:
            stale_files += 1
            if not args.check:
                path.write_text(text, encoding="utf-8")
                print(f"  -> rewrote {path}")
        else:
            print(f"  {path.name:<26} already current")

    if underived:
        print(f"\nREFUSING TO PASS: {len(set(underived))} claim label(s) had no derivable expected "
              f"value, so those figures were NOT checked or rewritten:\n  "
              f"{sorted(set(underived))}")
    if underived and not args.check:
        return 1
    if args.check and stale_files:
        print(f"\n{stale_files} file(s) carry a stale figure. Run without --check to rewrite.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
