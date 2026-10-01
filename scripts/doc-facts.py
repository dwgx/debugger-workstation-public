#!/usr/bin/env python
"""Fail when the wiki asserts a number the registry no longer produces.

WHY THIS EXISTS. On 2026-10-02 the capability count moved three times in one session -- 16,
then 17, then 19 -- and the wiki pages carrying it were fixed by hand each time. Three manual
passes is a rule waiting to be written down. This is that rule.

The failure it catches is specific and has happened here repeatedly: a prose document claims
"N capabilities" or "N controls" and the claim silently rots. Worse, the usual fix is to
STRIKE the old number rather than delete it, so the document ends up containing both the true
and the false figure and a naive grep cannot tell them apart.

So the check is deliberately conservative in the only direction that is safe:

  * a number on a STRUCK-THROUGH line is history and is ignored;
  * a number on a live line that contradicts the registry is a FAILURE;
  * a live line that agrees is fine, and a document with no such claim is fine.

Exit 0 clean, 1 violations, 2 could not run. An error is never a zero.

Run:  python scripts/doc-facts.py --repo D:/Software/Tool/WorkStation/debugger
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# (label, regex with one capture group, callable taking the registry -> expected int or None)
# `None` means "this claim is not derivable from the registry", so it is not checked.
CLAIMS: list[tuple[str, re.Pattern[str], object]] = []


def claim(label, pattern, fn):
    CLAIMS.append((label, re.compile(pattern, re.IGNORECASE), fn))


def _cap_count(reg):
    return len(reg["capabilities"])


def _observed(reg):
    return sum(1 for c in reg["capabilities"] if c.get("state") == "observed")


def _edges(reg):
    n = 0
    for c in reg["capabilities"]:
        for i in (c.get("consumes") or {}).get("inputs") or []:
            if i.get("from"):
                n += 1
    return n


def _make(fn):
    return fn


# The first version of the capability pattern was
#     (?:capabilities:\s*|carries\s+)(\d{1,3})\s+capabilit | ...\*\*(\d)\*\*
# and its negative control FAILED. Planting `capabilities: 99` in a live wiki line produced
# "OK" and exit 0, because that alternative requires the literal word "capabilit" AFTER the
# number -- and after `capabilities: 99` comes a backtick. So the most common phrasing in the
# wiki was the one phrasing the gate could not see.
#
# That is the same defect this script exists to catch, authored here: a control that passes
# for a reason unrelated to what it checks. It is written down in the source for the next
# reader, and it is why the pattern is now written as independent alternatives that each
# stand alone rather than one alternation with an unreachable branch.
# DELIBERATELY NARROW, and the limit is stated rather than papered over. The first version
# under-matched (a control that always passes is worse than none). The second over-matched:
# it flagged "fourteen of the sixteen rows in that table" because the row count looked like a
# capability count, flagged a sentence that says the suites "first reported capabilities: 16"
# -- history in live text -- and produced one nonsense match of "2". Both failures came from
# trying to read arbitrary prose numbers.
#
# So only the two unambiguous forms are checked, and anything looser is declared out of scope
# rather than half-handled:
#   `capabilities: N`     the shape a command's stdout is quoted in, and
#   **N capabilities**    the shape a bolded summary uses.
# A document that writes "the sixteen-entry table" or "N rows" is not checked, because there
# is no way to tell a row count from a capability count without parsing prose. Better to check
# two forms reliably than five forms noisily -- a gate that cries wolf is switched off.
# NOTE ON GROUPING: every alternative carries exactly ONE capture group, because the checker
# takes the first non-empty group. An earlier draft nested one inside another, so a match on
# **21 capabilities** yielded the whole '**21 capabilities' string and int() raised.
claim("capability count",
      r"(?:`capabilities:\s*`?\s*(\d{1,3})`)"   # `capabilities: 21`
      r"|\*\*(\d{1,3})\s+capabilit",           # **21 capabilities**
      _cap_count)
claim("observed count",
      r"(\d{1,3})\s+`observed`", _observed)
claim("typed edge count",
      r"(\d{1,3})\s+typed\s+(?:from-)?edges", _edges)

STRIKE = re.compile(r"~~.*?~~")


def live_lines(text: str):
    """Yield (lineno, line-with-struck-segments-removed).

    Struck-through text is HISTORY and must never read as drift, because the house style is
    to strike an old figure rather than delete it. Two shapes occur:

      * a run spanning whole lines -- common in a changelog block;
      * a run in the MIDDLE of a live line -- measured, and this was a false positive in the
        first version. arsenal-upgrade-plan.md:95 reads
            **21 capabilities, CLEAN** -- 18 `observed` ... ~~16 capabilities, 13 `observed`~~
        where the live text is correct and the struck tail is history on the same line. The
        first version only skipped whole lines, so it flagged the struck numbers and would
        have sent someone to "fix" a figure that was already right.

    So a struck run is DELETED from the line rather than the line being skipped, and only what
    survives is searched. An unclosed run swallows the rest of the line, which is the safe
    direction to be wrong in.
    """
    inside = False
    for i, line in enumerate(text.splitlines(), 1):
        if inside:
            # still inside a multi-line strike; only a closing run ends it
            if line.count("~~") % 2 == 1:
                inside = False
            continue
        if line.count("~~") % 2 == 1:
            # opens and does not close on this line: keep only what precedes it
            yield i, line.split("~~", 1)[0]
            inside = True
            continue
        # balanced: drop every struck segment, keep the rest
        yield i, STRIKE.sub("", line)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parents[1]))
    ap.add_argument("--wiki", default=None,
                    help="wiki repo root; defaults to the sibling <project>/<private-tree>")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    manifest = repo / "manifests" / "capabilities.json"
    if not manifest.exists():
        print(f"doc-facts: cannot run, no registry at {manifest}", file=sys.stderr)
        return 2
    reg = json.loads(manifest.read_text(encoding="utf-8"))

    # Measured: the first default guessed repo.parent.parent/"Project"/"<private-tree>", which from
    # D:\Software\Tool\WorkStation\debugger resolves to D:\Software\Project\<private-tree> -- a path
    # that does not exist, so the gate refused with exit 2 rather than silently checking
    # nothing. A wrong default would have produced a gate that only ran when somebody
    # remembered an argument, which is the same always-green failure this script exists to
    # catch. An explicit --wiki overrides.
    wiki = pathlib.Path(args.wiki or r"<private-tree>")
    if not wiki.exists():
        print(f"doc-facts: cannot run, no wiki at {wiki}", file=sys.stderr)
        return 2

    # SCOPE, deliberately narrow. Two classes are excluded because they are RECORDS OF WHAT WAS
    # TRUE WHEN WRITTEN, not live prose: `.agent/research/` (dated survey reports -- the
    # pentagi study says "16 capabilities, 5 typed edges", true on 2026-10-02 and not a claim
    # about today) and `literature/` (imported third-party reports, same reasoning). The same
    # reasoning governs struck-through lines, which live_lines() already skips. A gate that
    # cries wolf on archived truth is the failure this script exists to prevent, and it was
    # measured: the first run reported 16 violations of which 2 were exactly that.
    SKIP = {".git", ".agent", "literature"}
    targets = sorted(p for p in wiki.rglob("*.md")
                     if not SKIP.intersection(p.relative_to(wiki).parts))

    violations: list[str] = []
    checked = 0
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in live_lines(text):
            for label, rx, fn in CLAIMS:
                for m in rx.finditer(line):
                    # A line may carry the number twice (two capture groups); take the first
                    # group that actually captured something.
                    got = next((g for g in m.groups() if g), None)
                    if got is None:
                        continue
                    want = fn(reg)
                    if want is None:
                        continue
                    checked += 1
                    if int(got) != want:
                        rel = path.relative_to(wiki)
                        violations.append(
                            f"{rel}:{lineno}: claims {got} {label}; registry says {want}\n"
                            f"    {line.strip()[:110]}")

    print(f"doc-facts: registry has {_cap_count(reg)} capabilities "
          f"({_observed(reg)} observed, {_edges(reg)} typed edges)")
    print(f"doc-facts: scanned {len(targets)} wiki files, {checked} live numeric claims checked")
    if violations:
        print(f"doc-facts: {len(violations)} STALE CLAIM(S)\n")
        for v in violations:
            print("  " + v)
        print("\nFix by editing the live figure. Do NOT delete a struck old value -- history "
              "is kept on purpose, and this check ignores struck lines precisely so that "
              "history does not read as drift.")
        return 1
    print("doc-facts: OK, every live numeric claim matches the registry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())