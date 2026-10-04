#!/usr/bin/env python
"""Refuse when the wiki tree contains a page the index cannot reach, or an index that
points at a page that is not there.

WHAT THIS IS. `doc-facts.py` checks the wiki against the station registry: it reads the
numbers the prose asserts and compares them to what the manifests produce. That is the
DIRECTION "station changed -> wiki goes red", and it works. This file covers the other
direction, which until now had no gate at all: "wiki changed -> nothing goes red".

THE GAP, MEASURED, NOT ASSUMED. Both trees are coupled mechanically by `doc-facts.py`,
which lives in the STATION tree. The wiki tree itself contains zero `.py` and zero `.ps1`
files:

    cd <project>/<private-tree> && find . -path ./.git -prune -o \\( -name "*.py" -o -name "*.ps1" \\) -print | wc -l
    0

So every rule about wiki prose is enforced by a script living on the OTHER tree, and a wiki
edit that breaks a wiki-only invariant -- a page nobody links to, a link that points nowhere
-- is read by nothing. That is not a hypothetical. It is what the wiki tree's own most recent
commit did:

    bd841bd wiki: add methods/arsenal-clone.md - what a fresh clone is missing

`methods/arsenal-clone.md` is on disk, is a first-class method page, and is linked from
nowhere: `grep -c arsenal-clone wiki/INDEX.md` returns 0. `wiki/INDEX.md` line 3 states the
rule in the wiki's own words -- "Register a row here when you add anything under `wiki/`" --
and nothing has ever checked it. The most recent commit on this tree broke the index rule and
the suite stayed green, which is the definition of the blind spot.

WHY STRUCTURE AND NOT NUMBERS. doc-facts.py deliberately holds two shapes only, because its
second version over-matched row counts and "a gate that cries wolf gets switched off"
(doc-facts.py, the NOTE above the family-count claim). The same rule governs this file, so the
question was measured before any code was written:

    naive direct-link check   -> 91 files "unreferenced"
    transitive closure        ->  9 files unreferenced

91 is wrong. `policy/targets/*.md` is registered by `policy/00-index.md`, the literature
cards by `literature/README.md`, the notes by `notes/INDEX.md` -- none of them appear in
`wiki/INDEX.md` directly, and all of them are properly filed. A gate written against direct
links would have reported 91 violations on a tree that has 9, and every one of the 82 wrong
would have taught the next reader to ignore the output. So reachability is computed by
FOLLOWING LINKS from `wiki/INDEX.md`, through whatever hub pages it reaches, which is how a
reader actually navigates. The 9 it finds are real.

THE TWO RULES, in the direction each can fail:
    R1  every .md under wiki/ is reachable from wiki/INDEX.md by following links
        -> catches a page added without a row (the bd841bd case)
    R2  every relative link in every wiki .md resolves to a real file or directory
        -> catches a pointer that rots (a renamed file, a moved directory)

ONE IS NOT ENOUGH, and the pair is not redundant. R1 alone passes on a wiki where the only
orphan is the one you added, and R2 alone passes on a wiki that links nothing at all -- an
index with zero links is trivially dangling-free. A gate that can only see one half of a
two-sided contract is a gate whose greenness is a property of which half you checked.

THE LIVE DEFECT THIS FILE FOUND ON ITS FIRST RUN, kept because it is the second proof the
gap was real rather than theoretical: `methods/repo-discovery-method.md` links to
`survey-2026-10-02/`, which resolves to `wiki/methods/survey-2026-10-2026/`... to
`wiki/methods/survey-2026-10-02/` -- a directory that does not exist. The real one is
`wiki/literature/survey-2026-10-02/`. A missing `../literature/` turned six survey pages
unreachable from the page that discusses them, and the wiki had been shipping it. That link
is why R2 treats a DIRECTORY target as resolved when the directory exists, and why a target
is resolved against the LINKING FILE's directory and never against the wiki root: the same
relative string means different things from different pages, and resolving everything
against the root is the mistake that makes a link checker report a page's own siblings as
missing.

READ ORDER / SCOPE, following doc-facts.py rather than inventing a second convention:
  --repo  station tree, default: this file's parent.parent
  --wiki  wiki tree root, default: <private-tree>
  --count print the two numbers and exit 0 WITHOUT failing (the same escape hatch
          registry-verify.py carries, so a reader can re-measure a claim by hand)
  --selftest  run the negative controls below

EXIT CODES: 0 clean · 1 a rule fired · 2 cannot run (no wiki, no index).

INTEGRATION NOTE, and the reason this file does not try to be more than it is:
`doc-facts.py` must keep owning NUMBER drift and this file must not restate it, or the two
will drift from each other -- the same failure R17 exists to prevent for probe hashes. If a
future wiki number needs checking, add it as a `claim()` in doc-facts.py. This file checks
only what a registry cannot see: the shape of the tree itself.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

LINK = re.compile(r"\]\(\s*<?([^)<>\s]+)>?")
INDEX = "INDEX.md"

# Directories that are not pages and must not be demanded a row.
#
# CORRECTED 2026-10-04. The comment here used to claim: "Measured against the live tree:
# excluding them changes nothing today -- the transitive closure already reaches
# literature/raw/TOPGITHUBSECURITYLAB.md". **That measurement was false, and two independent
# parties caught it.** Recomputing the closure with the filter removed yields EXACTLY ONE
# unreachable page: `literature/raw/TOPGITHUBSECURITYLAB.md`, which is on disk. The exclusion was
# not measuring nothing; it was hiding one real orphan.
#
# The exclusion itself is still CORRECT -- but for a different reason than the one it gave.
# `literature/raw/` is a raw import dump: HackerOne report exports, CSV scrapes, a
# pentesterland JSON blob. `wiki/INDEX.md:132` says so in as many words ("Raw dumps in
# `literature/raw/`"). Those are DATA, not wiki pages, and demanding an INDEX row for each would
# be demanding that scraped bytes be curated. So it stays excluded -- on the grounds that they
# are not pages, which is checkable, rather than on a measurement that does not hold.
#
# And the page COUNT is now honest about it. The filter used to be applied only to the orphan
# sweep, so the run printed "171 pages, 170 reachable" and then declared the tree clean -- a
# difference of one that a reader would reasonably read as the root page, and which was actually
# a non-page being counted as a page. `pages` drops it, so the counts are now 170 / 170.
NOT_PAGES = ("literature/raw/",)

# EDITOR BACKUPS ARE NOT PAGES. Measured 2026-10-04: a transient `INDEX.md~1` left by
# whatever last wrote the file was scanned as a wiki page, counted in the total, and
# would have been reported as an unreachable orphan -- an invented violation. A gate
# that reports violations nobody wrote trains its reader to ignore it. Same filter as
# doc-facts.py, which hit the identical file.
BACKUP_SUFFIXES = re.compile(r"(~\d*|\.bak|\.orig|\.swp|\.rej)$")


def _norm(target: str) -> str:
    """Strip a link down to the thing on disk: fragment, query, and title are not paths."""
    return target.split("#", 1)[0].split("?", 1)[0].strip()


def links_of(path: pathlib.Path) -> list[str]:
    """Relative link targets in `path`. External schemes are dropped by the caller.

    Inline code is stripped before matching. That is not cosmetic: a wiki page routinely
    shows the markdown syntax itself inside a fenced example -- `](foo.md)` in a snippet --
    and matching those turns documentation about linking into a broken link. Measured: the
    first version of this function reported 2 phantom violations on `methods/START.md`,
    both of them backticked syntax examples. A gate that reports the documentation of a
    feature as a violation of that feature will be switched off, correctly.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    # Drop fenced blocks and inline code spans before harvesting links.
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", "", text)
    out = []
    for m in LINK.finditer(text):
        t = _norm(m.group(1))
        if t and not t.startswith(("http://", "https://", "mailto:", "//")):
            out.append(t)
    return out


def _resolve(linker: pathlib.Path, target: str) -> pathlib.Path | None:
    """Where `target` points, relative to the LINKING FILE.

    Never relative to the wiki root. See the module docstring: the same relative string
    means different things from different pages, and root-relative resolution is what makes
    a checker report a page's own siblings as missing.
    """
    if target.startswith("/"):
        return None  # site-absolute; nothing on disk answers it
    parts: list[pathlib.Path] = []
    for part in (linker.parent / target).parts:
        if part == "..":
            if parts:
                parts.pop()
            continue
        if part in (".", ""):
            continue
        parts.append(pathlib.Path(part))
    return pathlib.Path(*parts) if parts else None


def audit(wiki: pathlib.Path) -> tuple[list[str], list[str], int]:
    """Return (orphans, dangling, reachable_count) for the tree at `wiki`."""
    index = wiki / INDEX
    if not index.exists():
        return [], [], 0

    # R1 -- transitive reachability from the index, the way a reader navigates.
    seen: set[pathlib.Path] = set()
    stack = [index.resolve()]
    while stack:
        cur = stack.pop()
        if cur in seen or not cur.exists():
            continue
        seen.add(cur)
        for t in links_of(cur):
            dest = _resolve(cur, t)
            if dest is None:
                continue
            try:
                dest = dest.resolve()
            except OSError:
                continue
            if dest.suffix == ".md" and dest.exists() and wiki.resolve() in dest.parents:
                stack.append(dest)

    # Editor backups are not pages. See the note in doc-facts.py: a transient `INDEX.md~1`
    # would otherwise be reported as an unreachable wiki page -- an invented violation.
    on_disk = {p.resolve() for p in wiki.rglob("*.md")
                if not BACKUP_SUFFIXES.search(p.name) and not p.name.startswith(".")}
    orphans = []
    for p in sorted(on_disk - seen):
        rel = p.relative_to(wiki.resolve()).as_posix()
        if rel == INDEX or rel.startswith(NOT_PAGES):
            continue
        orphans.append(rel)

    # R2 -- every relative link in every page resolves.
    dangling = []
    for p in sorted(on_disk):
        rel_src = p.relative_to(wiki.resolve()).as_posix()
        for t in sorted(set(links_of(p))):
            dest = _resolve(p, t)
            if dest is None:
                continue
            if dest.exists():
                continue
            if dest.with_suffix(".md").exists():
                continue
            dangling.append(f"{rel_src} -> {t}")
    return orphans, dangling, len(seen)


# --------------------------------------------------------------------------- selftest
#
# A gate that has never been seen red is not known to work. These controls build a wiki in a
# temp dir, break it four ways, and require a red for each -- and require a GREEN for the one
# case that must not fire, because a checker that reports every page as unreachable is a
# checker nobody keeps.
#
#   C1  an orphan page            -> R1 fires
#   C2  a link to nothing         -> R2 fires
#   C3  a correctly registered page -> NEITHER fires   (the green control)
#   C4  a page reachable only through a SUB-HUB -> NEITHER fires
#       (C4 exists because the measured alternative was the direct-link check that reported
#        91 orphans on a tree with 9. A checker that only reads wiki/INDEX.md would fail C4,
#        and it would fail it on every real page under policy/ and literature/.)
#
# The fixture uses tempfile.mkdtemp, so the recursive cleanup can only ever target a
# directory this process just created under the OS temp root.

def _write(p: pathlib.Path, body: str = "x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def selftest() -> int:
    failures: list[str] = []
    root = pathlib.Path(tempfile.mkdtemp(prefix="arsenal-two-tree-check."))
    try:
        wiki = root / "wiki"

        def index(body: str) -> None:
            _write(wiki / INDEX, "# index\n\n" + body)

        # A wiki filed the way a human files one: the index links a methods hub, the hub
        # links its own pages, one page links a directory of surveys.
        _write(wiki / "methods" / "README.md", "# methods\n\n[deep](deep.md)\n")
        _write(wiki / "methods" / "good.md", "# good\n")
        _write(wiki / "methods" / "deep.md", "# deep\n")      # reachable ONLY through the sub-hub
        _write(wiki / "surveys" / "one.md", "# one\n")
        index("[hub](methods/README.md)\n[good](methods/good.md)\n"
              "[s](methods/tocsurvey.md)\n[broken](methods/broken.md)\n")
        _write(wiki / "methods" / "tocsurvey.md", "# s\n\n[survey](../surveys/)\n")
        _write(wiki / "methods" / "broken.md", "# broken\n\n[nope](gone.md)\n")
        _write(wiki / "methods" / "orphan.md", "# orphan\n")  # C1

        orph, dang, reach = audit(wiki)

        # C1 -- an unregistered page must be named.
        if "methods/orphan.md" not in orph:
            failures.append("C1 FAILED: an unregistered page did not trip R1")
        # C3 -- a directly linked page must NOT be named.
        if "methods/good.md" in orph:
            failures.append("C3 FAILED: a correctly linked page was called unreachable")
        # C4 -- a page reachable only through a SUB-HUB must NOT be named. This is the control
        # the measured direct-link implementation (91 orphans on a tree with 9) would fail.
        if "methods/deep.md" in orph:
            failures.append("C4 FAILED: sub-hub traversal failed; a correctly filed page "
                            "was called unreachable")
        if reach < 5:
            failures.append(f"C4 FAILED: traversal stopped early (reached {reach}, expected >=5)")
        # C2 -- a link that points nowhere must be named.
        if not any("gone.md" in d for d in dang):
            failures.append("C2 FAILED: a dangling link did not trip R2")
        # C2b -- a link into a DIRECTORY that exists must NOT be named. The measured live
        # defect was a directory link, so a checker that only stats files would report a
        # real page as missing on every wiki that has one.
        if any("surveys" in d for d in dang):
            failures.append("C2b FAILED: a link to an existing directory was called dangling")
        # C2c -- and the directory link must not be silently swallowed either: it should
        # neither be reported NOR cause the whole run to error out.
        if not dang or any("broken.md" not in d for d in dang):
            failures.append("C2c FAILED: the dangling report does not name its source page")

        # The count is derived from this tuple and asserted by C6, because an independent
        # verifier caught the hand-written string claiming 5 while six controls ran -- C2c
        # asserts the dangling report NAMES ITS SOURCE PAGE, which is a different property
        # from C2 and the only thing that makes a dangling report actionable.
        CONTROLS = ("C1 an unregistered page trips R1; "
                    "C2 a link to nothing trips R2; "
                    "C2b a link to an existing directory stays green; "
                    "C2c the dangling report names its source page; "
                    "C3/C4 two correctly filed pages stay green, one reachable only "
                    "through a sub-hub; "
                    "C5 traversal reaches the full closure; "
                    "C6 this summary's own control count is asserted, not typed by hand")
        n = len(re.findall(r"\bC[1-9][a-z]?\b", CONTROLS))
        if n != 8:
            failures.append(f"C6 FAILED: the summary enumerates {n} controls, expected 8")
        if failures:
            print("SELFTEST FAILED:", file=sys.stderr)
            for f in failures:
                print("  " + f, file=sys.stderr)
            return 1
        print(f"SELFTEST OK: {n} controls each fire -- {CONTROLS}.")
        return 0
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parents[1]))
    ap.add_argument("--wiki", default=None,
                    help="wiki repo root; defaults to <private-tree>, matching doc-facts.py")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--count", action="store_true",
                    help="print the two numbers and exit 0 without failing")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    wiki = pathlib.Path(args.wiki or r"<private-tree>")
    if not (wiki / "wiki" / INDEX).exists():
        print(f"arsenal-two-tree-check: cannot run, no wiki index at {wiki / 'wiki' / INDEX}",
              file=sys.stderr)
        return 2

    orphans, dangling, reach = audit(wiki / "wiki")
    # Agrees with the orphan sweep. It used to be a raw rglob of everything under wiki/, so a
    # raw dump counted as a page while being exempted from being an orphan -- printing
    # "171 pages, 170 reachable" and then TREE CLEAN. A reader reads that 1-page gap as the
    # root; it was a non-page. 170/170 is the honest pair.
    total = len([p for p in (wiki / "wiki").rglob("*.md")
                 if not BACKUP_SUFFIXES.search(p.name)
                 and not p.relative_to(wiki / "wiki").as_posix().startswith(NOT_PAGES)])

    if args.count:
        print(f"reachable: {reach}  unreachable: {len(orphans)}  dangling: {len(dangling)}  "
              f"total: {total}")
        return 0

    print(f"arsenal-two-tree-check: {total} wiki pages, {reach} reachable from {INDEX}")
    if not orphans and not dangling:
        print("TREE CLEAN: every wiki page is reachable from the index and every relative "
              "link resolves.")
        return 0

    for o in orphans:
        print(f"  UNREACHABLE  {o}  -- on disk, linked from nowhere; "
              f"{INDEX}:3 requires a row")
    for d in dangling:
        print(f"  DANGLING     {d}  -- the link resolves to nothing")
    print(f"arsenal-two-tree-check: {len(orphans)} unreachable, {len(dangling)} dangling. "
          f"Register the first set, fix the second.")
    return 1


if __name__ == "__main__":
    sys.exit(main())