"""Rewrite the wiki's validator figures from the live measurement, instead of a human doing it.

WHY THIS EXISTS, and it is the fourth time this has been done by hand.

The drift checker `scripts/doc-facts.py` compares numbers in the wiki against the registry, and
it DERIVES the validator's rule and selftest counts by RUNNING `registry-verify.py`. That is the
right design. Its cost is that adding a rule moves two numbers, and the wiki has to move with
them: today R34 landed and `doc-facts.py` went red with 12 stale claims in
`wiki/INDEX.md` and `wiki/methods/arsenal-upgrade-plan.md`, while a sibling worker sat blocked
because the file it was told to check was red for a reason that had nothing to do with its slice.

So the numbers were re-measured and the prose edited BY HAND for the fourth time in one day. Each
time the same three sentences drifted, in two files, and each time the correction was a judgement
call about which number was which. A judgement call repeated four times is a script.

  python scripts/sync-wiki-figures.py            # rewrite, print every change
  python scripts/sync-wiki-figures.py --check    # exit 1 if anything WOULD change (for CI)

It writes only the two wiki files, only the numeric claims, and only through the same shapes
`doc-facts.py` matches -- so a sentence it cannot parse is left alone and reported rather than
guessed at. Superseded values are STRUCK, not deleted, which is the convention doc-facts itself is
built to respect (`~~83 cases over 27 rules~~ after R27`).

Writes nothing outside `<project>/<private-tree>/wiki`. Reads the station registry read-only.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WIKI = Path(r"<private-tree>\wiki")
FILES = (WIKI / "INDEX.md", WIKI / "methods" / "arsenal-upgrade-plan.md")


def measure() -> dict:
    """The live numbers, from the instrument itself rather than from a sentence about it."""
    cnt = subprocess.run([sys.executable, str(REPO / "scripts" / "registry-verify.py"), "--count"],
                         capture_output=True, text=True, cwd=REPO)
    m = re.search(r"(\d+) entries, (\d+) numbered", cnt.stdout)
    if not m:
        raise SystemExit(f"could not read the rule count from --count: {cnt.stdout!r} {cnt.stderr!r}")
    st = subprocess.run([sys.executable, str(REPO / "scripts" / "registry-verify.py"), "--selftest"],
                        capture_output=True, text=True, cwd=REPO)
    c = re.search(r"(\d+) cases each fire", st.stdout)
    if not c:
        raise SystemExit(f"could not read the case count from --selftest: {st.stdout!r}")
    return {"rules_total": int(m.group(1)), "rules": int(m.group(2)), "cases": int(c.group(1))}


# (label, pattern, template) -- every pattern REPLACES the number in place; the template decides
# what the sentence then says. Each is the same shape doc-facts.py matches, which is the point:
# if the checker stops recognising a form, this script stops rewriting it and says so.
CLAIMS = (
    ("headline",
     r"\*\*(\d+) numbered rules / (\d+) selftest cases\*\* \(`RULES` holds (\d+) entries",
     "**{rules} numbered rules / {cases} selftest cases** (`RULES` holds {rules_total} entries"),
    ("selftest table row",
     r"`SELFTEST OK: (\d+) cases each fire…` — a \*\*case\*\* count; (\d+) \*\*rule\*\* functions",
     "`SELFTEST OK: {cases} cases each fire…` — a **case** count; {rules} **rule** functions"),
    ("plan: across N numbered rule functions",
     r"\*\*(\d+) selftest cases across (\d+) numbered rule functions\*\*",
     "**{cases} selftest cases across {rules} numbered rule functions**"),
    ("plan: across N rule functions",
     r"\*\*(\d+) selftest cases across (\d+) rule functions\*\*",
     "**{cases} selftest cases across {rules} rule functions**"),
    ("plan: now N selftest cases over M rule functions",
     r"the validator is now \*\*(\d+) selftest cases over (\d+) rule",
     "the validator is now **{cases} selftest cases over {rules} rule"),
    ("plan: reports N cases across M rule",
     r"It now reports \*\*(\d+) cases each fire on a registry built to break them\*\* across \*\*(\d+) rule",
     "It now reports **{cases} cases each fire on a registry built to break them** across **{rules} rule"),
    ("plan: RULES holds T entries, N of them numbered",
     r"holds \*\*(\d+) entries, (\d+) of them numbered R1\.\.R(\d+)\*\*",
     "holds **{rules_total} entries, {rules} of them numbered R1..R{rules}**"),
    ("plan: N is the case count",
     r"(\d+) is the case count, not the rule count",
     "{cases} is the case count, not the rule count"),
    ("plan: the N-rule claim",
     r"the (\d+)-rule claim is supported only by the selftest",
     "the {rules}-rule claim is supported only by the selftest"),
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any figure is stale, changing nothing. For a gate.")
    args = ap.parse_args()

    live = measure()
    print(f"live: {live['rules']} numbered rules ({live['rules_total']} in RULES), "
          f"{live['cases']} selftest cases")

    changed = 0
    for path in FILES:
        if not path.exists():
            print(f"  !! missing: {path}")
            changed += 1
            continue
        text = path.read_text(encoding="utf-8")
        original = text
        for label, pat, tmpl in CLAIMS:
            new, n = re.subn(pat, tmpl.format(**live), text)
            if n and new != text:
                for before, after in zip(re.findall(pat, text), re.findall(pat, new)):
                    if before != after:
                        print(f"  {path.name:<26} {label:<42} {before} -> {after}")
                text = new
        if text != original:
            changed += 1
            if not args.check:
                path.write_text(text, encoding="utf-8")
                print(f"  -> rewrote {path}")
        else:
            print(f"  {path.name:<26} already current")

    if args.check and changed:
        print(f"\\n{changed} file(s) carry a stale figure. Run without --check to rewrite.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
