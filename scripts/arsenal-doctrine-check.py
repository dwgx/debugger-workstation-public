#!/usr/bin/env python
"""Refuse when this project's own dossiers cite a worker report that is not on disk.

WHAT THIS IS. `arsenal-workflow-rules.md` rule **R4** says *provenance must be a path a reader
can open*. This file is the gate that rule was missing. It exists because of one measured
failure and nothing else.

THE FAILURE. `docs/research/ecosystem-2026-10-02.md` is the most-cited dossier in the estate.
It cites eight worker reports -- `w1-mcprev.md`, `w1-retoolchain.md`, `w1-revskills.md`,
`w1-debugpairing.md`, `w1-toolperf.md`, `w1-gateredteam.md`, `w1-composition.md`,
`w1-agentworkflow.md` -- **222 times in total, with `file:line` references, and not one of the
eight files exists**, in this tree, in the wiki tree, or anywhere under `~/.dwgx`. Verified:

    for f in w1-mcprev.md w1-debugpairing.md; do
      find <project> D:/Software/Tool/WorkStation/debugger %USERPROFILE%/.dwgx -name "$f"
    done      -> MISSING for all eight

=> Every one of those 222 evidence citations is **un-re-runnable**. The conclusions may be
correct; by this project's own North Star they are not yet facts. This is R4's whole content:
a citation is not provenance until somebody can open it.

WHY ONLY THIS ONE CLASS, and why that is the honest scope rather than a convenient one.
The dossiers also cite **124 distinct filenames that are not in this estate** -- `SKILL.md`
(54), `README.md` (35), `mcp.py`, `rpc.py`, `idalib_server.py`, `formats/luac.md`. Those are
citations into **external repositories cloned to %TEMP% for the survey**, and %TEMP% is deleted.
A gate that flagged those would report 124 permanent reds for files that were *never supposed to
survive*, and it would be switched off within a day. That is the exact failure
`doc-facts.py` records about its own second version and `arsenal-two-tree-check.py` records
about its first: **measure before shipping the gate**. So R4a checks the one class where the
file is supposed to be ours, and R4b COUNTS the other class so the number stays visible instead
of being quietly dropped.

The distinguishing property is not the filename. It is ownership: `w<N>-<slug>.md` is this
project's own worker-report convention (`w12-*.md` exists, at
`<project>/<private-tree>/.agent/research/`), so a citation to one is a promise that the file is
here. A citation to `SKILL.md` is a promise about somebody else's repository.

WHAT IS A REPORT, NOT A GATE, AND WHY
    R4b  external-citation count          -- unfixable by design; %TEMP% is deleted
    R10  forbidden paths that are tracked -- `wiki/AGENTS.md` lists `.agent/` as
        forbidden-to-commit and `.agent/HANDOFF.md` IS tracked. That is a live violation of a
        red line and it is the Owner's call to resolve, not a gate's. A permanently red gate is
        a gate people learn to ignore, so it is reported and exits 0.

EXIT CODES: 0 clean (reports may still print) | 1 a rule fired | 2 cannot run.
"""
from __future__ import annotations

import argparse
import collections
import os
import pathlib
import re
import sys

# This project's worker-report naming convention: w1-..., w12-..., w18-...
WORKER_CITATION = re.compile(r"\bw(\d+)-([a-z0-9][a-z0-9_-]*)\.md\b", re.IGNORECASE)
ANY_FILENAME = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:md|py|ps1|json|mjs|c|cpp|js))\b")

DEFAULT_ESTATE = (
    pathlib.Path(r"D:\Software\Tool\WorkStation\debugger"),
    pathlib.Path(r"<private-tree>"),
    pathlib.Path.home() / ".dwgx",
)

# This project's worker-report naming convention: w1-..., w12-..., w18-...
WORKER_CITATION = re.compile(r"\bw(\d+)-([a-z0-9][a-z0-9_-]*)\.md\b", re.IGNORECASE)
# A citation WITH a line number: `w1-foo.md:12` or `w1-foo.md:12-48`. Group 3 is the high line
# of a range and may be None for a single-line citation -- hence `or m.group(2)` at the use
# site. Checking that the FILE exists is not enough: a citation into a 4-line remnant of a
# 1237-line report resolves fine and means nothing.
CITE_LINE = re.compile(r"\b(w\d+-[a-z0-9][a-z0-9_-]*\.md):(\d+)(?:-(\d+))?", re.IGNORECASE)
# The STRUCK form is `w1-foo.md~~:1211~~`. It deliberately does NOT match CITE_LINE -- the
# `~~` sits between `.md` and `:` -- which is why struck text is invisible to the live check
# and why the struck count needs its own pattern. Counting "citations before minus after" on
# CITE_LINE reports 0 and 0, because neither side of that subtraction can see a struck one.
CITE_STRUCK = re.compile(r"\b(w\d+-[a-z0-9][a-z0-9_-]*\.md)~~:\d+(?:-\d+)?~~", re.IGNORECASE)
ANY_FILENAME = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:md|py|ps1|json|mjs|c|cpp|js))\b")
# Retired figures are struck, exactly as `doc-facts.py` writes them, and struck text is
# history that must not read as a live claim.
#
# FIXED 2026-10-04, and the bug was found by an independent verifier trying to break this
# gate, not by reading it. This used to be `re.compile(r"~~.+?~~", re.S)` applied blindly with
# `.sub("", text)`. An ODD number of `~~` markers therefore paired the first marker with
# some later one and deleted everything between -- including LIVE, unstruck, dead citations --
# after which the gate reported `PROVENANCE CLEAN`. Measured: one stray tilde plus a real
# citation to a nonexistent report turned a red run green. The comment above this used to
# claim the opposite ("Unbalanced ~~ is left alone"), and that claim was false.
#
# The fix is deliberately the conservative one: a document with an odd marker count is NOT
# stripped at all. It is harvested raw and it is REPORTED, because an unterminated strike is
# a formatting bug in a document whose citations we cannot classify -- and silently guessing
# which side of the tilde is live is how a red becomes a green in the first place.
STRIKE = re.compile(r"~~.+?~~", re.S)
# Code fences are removed BEFORE anything else, and this is not cosmetic. Measured 2026-10-04:
# a dossier quoting a real PowerShell ParserError contains a `~~~~~~~~~~~~~~` underline inside
# a fenced block, which the odd-marker rule then reported as an unterminated strike and turned
# a green run red. A syntax example is not a citation and not a strike. The same class of bug
# was independently reported against the two-tree gate, where an unbalanced fence made the
# link-harvesting regex match nothing and every example link inside it became a phantom
# DANGLING. Strip fences first, then judge what is left.
FENCE = re.compile(r"^```.*?^```", re.S | re.M)


def strip_strikes(text: str) -> tuple[str, bool]:
    """-> (text without struck spans, unbalanced?). Never hides a citation on a guess."""
    # Fences first: a syntax example inside ``` is not prose. The ParserError underline
    # `~~~~~~~~~~~~~~` in docs/research/2026-10-04-two-tree-and-dead-code.md is real, and it
    # made this gate red before fences were removed here.
    body = FENCE.sub("", text)
    if body.count("~~") % 2 == 1:
        return body, True       # odd markers: not stripped, caller harvests raw + reports
    return STRIKE.sub("", body), False
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".ruff_cache", "evidence", "out"}
# Files that are DATA or DISCLOSURE, not dossiers relying on their citations.
#   knowledge-corpus.md cites %TEMP% clone paths by design.
#   WORKER-REPORT-LOSS.md is the document that NAMES the dead reports. Counting its mentions
#     would make the gate report the disclosure of a loss as further instances of the loss --
#     the observer inflating the measurement. Measured 2026-10-04: adding that one disclosure
#     moved w1-mcprev.md from 12 citations to 19 with nothing new having happened.
SKIP_DOSSIER = {"knowledge-corpus.md", "WORKER-REPORT-LOSS.md"}


def _index(roots) -> set[str]:
    """Every filename anywhere in the estate, lowercased."""
    names: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in filenames:
                names.add(f.lower())
    return names


def _line_counts(roots) -> dict[str, int]:
    """Line count per filename, keeping the LARGEST copy.

    Several of these filenames exist in more than one place -- the recovered remnant under
    `docs/research/workers/` and, for the ones that were never lost, an original elsewhere.
    Keeping the largest is the only defensible choice: if a citation points past the end of
    the copy a reader would actually open, saying the citation is fine because a *bigger*
    copy exists somewhere is the exact "an instrument narrower than its subject" failure this
    project keeps recording. The smallest copy is the one a reader finds by name.
    """
    best: dict[str, int] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in filenames:
                if not f.lower().endswith(".md"):
                    continue
                try:
                    n = sum(1 for _ in open(os.path.join(dirpath, f), encoding="utf-8",
                                             errors="ignore"))
                except OSError:
                    continue
                k = f.lower()
                if n > best.get(k, -1):
                    best[k] = n
    return best

def audit(repo: pathlib.Path, estate) -> tuple[dict, int, int, dict]:
    """Return (missing worker files -> cites, live line citations, external cites, past-the-end).

    Two decisions here are load-bearing, and both were made by measurement rather than taste.

    1. It gates on LINE-NUMBERED citations, not bare filename mentions. `w1-mcprev.md` written
       in prose says "a report by that name existed"; `w1-mcprev.md:9-16` says "these nine lines
       are my evidence". Only the second is a checkable claim, and only the second is gated.
       A bare mention is counted and printed so the number stays visible.

    2. It ignores STRUCK citations. That is the convention `doc-facts.py` already uses for
       retired figures, and it is how the 2026-10-04 repair closed this gate: 168 dead line
       numbers across five dossiers were struck in place rather than deleted, so the knowledge
       they supported survives as history and the gate can actually go green. A gate that
       re-reddens struck history is a gate nobody can ever close.
    """
    have = _index(estate)
    lines = _line_counts(estate)
    missing: collections.Counter = collections.Counter()
    past_end: collections.Counter = collections.Counter()
    worker_total = 0
    bare_mentions = 0
    struck: list = []
    unbalanced_docs: list[str] = []
    external = 0
    docs = sorted((repo / "docs" / "research").rglob("*.md"))
    for d in docs:
        if d.name in SKIP_DOSSIER:
            continue
        text = d.read_text(encoding="utf-8", errors="ignore")
        live, unbalanced = strip_strikes(text)
        if unbalanced:
            # Counted and NAMED, never silently tolerated. Before this, the surplus marker
            # paired across the document and deleted live citations, after which the gate
            # reported PROVENANCE CLEAN. `live` is the RAW text in this case, so the citations
            # are still counted -- we just cannot claim which of them are struck.
            unbalanced_docs.append(d.name)
        worker_total += len(CITE_LINE.findall(live))
        bare_mentions += len(WORKER_CITATION.findall(live)) - len(CITE_LINE.findall(live))
        struck.append((d.name, len(CITE_STRUCK.findall(text))))
        for m in CITE_LINE.finditer(live):
            name = m.group(1)
            hi = int(m.group(3) or m.group(2))
            n = lines.get(name.lower())
            if n is None:
                missing[name] += 1
            elif hi > n:
                past_end[name] += 1
        for m in ANY_FILENAME.finditer(live):
            if m.group(1).lower() not in have and not WORKER_CITATION.fullmatch(m.group(1)):
                external += 1
    return (dict(missing), worker_total, external, dict(past_end), bare_mentions,
            sum(n for _, n in struck), len([1 for _, n in struck if n]), unbalanced_docs)

def _r10_report(repo: pathlib.Path) -> list[str]:
    """Tracked files the tree's own contract forbids. A report, not a gate."""
    import subprocess
    out = []
    try:
        r = subprocess.run(["git", "-C", str(repo), "ls-files", ".agent"],
                           capture_output=True, text=True, timeout=30)
        tracked = [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return out
    if tracked:
        out.append(f"R10  wiki tree tracks {len(tracked)} file(s) under .agent/ , which its own "
                   f"AGENTS.md lists as forbidden-to-commit: {', '.join(tracked[:4])}"
                   f"{' ...' if len(tracked) > 4 else ''}")
    return out

def _r11_report(repo: pathlib.Path, wiki: pathlib.Path) -> list[str]:
    """R11 -- every wired MCP backend needs a recorded reason for existing.

    Measured 2026-10-04: 9 of 21 backends had manifest-only provenance, and one wired backend
    (`mcp-virustotal`) sends IOCs to a public API while this project's own doctrine names
    untrusted-content + private-data + egress as the lethal trifecta. Both are now recorded in
    `wiki/methods/arsenal-backend-provenance.md`.

    A report, not a gate, for the same reason as R10: six backends still have no recorded
    evaluation, and a permanently red gate is a gate people learn to ignore. What this makes
    checkable is that the RECORD exists and stays current -- not that the verdict is clean.
    """
    import json
    out = []
    mcp = repo / "manifests" / "mcp-backends.json"
    rec = wiki / "wiki" / "methods" / "arsenal-backend-provenance.md"
    if not mcp.exists():
        return out
    try:
        m = json.loads(mcp.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"R11  cannot parse {mcp}: {exc}"]
    entries = m.get("third_party", []) + m.get("resolved_upstream", {}).get("entries", [])
    text = rec.read_text(encoding="utf-8", errors="ignore") if rec.exists() else ""
    undocumented = [e.get("name", "?") for e in entries if e.get("name", "?") not in text]
    if not rec.exists():
        out.append("R11  NO provenance record at wiki/methods/arsenal-backend-provenance.md")
    else:
        out.append(f"R11  {len(entries)} wired backends, {len(entries) - len(undocumented)} "
                   f"named in the provenance record, {len(undocumented)} missing: "
                   f"{', '.join(undocumented) if undocumented else 'none'}")
    noteless = [e.get("name", "?") for e in entries if not e.get("note")]
    out.append(f"R11  {len(noteless)} of {len(entries)} carry no manifest `note` either -- "
               f"their only provenance is a `git` URL")
    egress = sorted({e.get("name") for e in entries
                     if any(k in json.dumps(e, ensure_ascii=False).lower()
                            for k in ("api_key", "virustotal", "public api", "公网 api"))})
    if egress:
        out.append(f"R11  EGRESS: {', '.join(egress)} reach the public internet. An RE agent "
                   f"holds untrusted content and private data at once -- see RECOVERY.md "
                   f"section 8 on the lethal trifecta. Confirm the call site is opt-in.")
    return out


def selftest() -> int:
    """Four controls: a missing report fires, a present one does not, an external citation is
    never gated, and a citation past the end of the file it names DOES fire."""
    import tempfile
    failures = []
    root = pathlib.Path(tempfile.mkdtemp(prefix="arsenal-doctrine-check."))
    try:
        repo = root / "station"
        (repo / "docs" / "research").mkdir(parents=True)
        (repo / "docs" / "research" / "d.md").write_text(
            "see w1-present.md:1 and w1-short.md:900 and w1-ghost.md:213-215 and SKILL.md:7\n",
            encoding="utf-8")
        (repo / "w1-present.md").write_text("one\n", encoding="utf-8")
        (repo / "w1-short.md").write_text("only\nthree\nlines\n", encoding="utf-8")
        missing, total, _, past, _bare, _s, _sf, _ub = audit(repo, [repo])
        if total != 3:
            failures.append(f"C1 setup: expected 3 worker citations, saw {total}")
        if "w1-ghost.md" not in missing:
            failures.append("C1 FAILED: a cited-but-absent worker report did not fire")
        if missing.get("w1-ghost.md") != 1:
            failures.append(f"C1 count wrong: {missing.get('w1-ghost.md')} != 1")
        if "w1-present.md" in missing:
            failures.append("C2 FAILED: a worker report that IS on disk was called missing")
        if "SKILL.md" in missing:
            failures.append("C3 FAILED: an external-repo citation was gated; that is the "
                            "permanent-red cry-wolf failure this rule exists to avoid")
        if past.get("w1-short.md") != 1:
            failures.append(f"C4 FAILED: a citation to line 900 of a 3-line file did not fire "
                            f"(saw {past.get('w1-short.md')})")
        if past.get("w1-present.md"):
            failures.append("C4 FAILED: an in-range citation was called past-the-end")

        # C5, added 2026-10-04. The strike stripper was `re.compile(r"~~.+?~~", re.S)` applied
        # blindly, so an ODD number of markers paired the first with some later one and deleted
        # everything between -- including live dead citations -- and the gate then said
        # PROVENANCE CLEAN. Found by an independent verifier trying to break this gate.
        (repo / "docs" / "research" / "d.md").write_text(
            "~~ half struck\nsee w1-ghost.md:213\n", encoding="utf-8")
        _m2, _t2, _, _, _, _, _, ub2 = audit(repo, [repo])
        if not ub2:
            failures.append("C5 FAILED: an odd number of ~~ markers was not reported as "
                            "unbalanced -- the surplus marker can delete live citations")
        if "w1-ghost.md" not in _m2:
            failures.append("C5 FAILED: the citation inside an unbalanced document was lost, "
                            "which is the red-turns-green this control exists to prevent")
        # ...and a fenced syntax example must NOT read as an unbalanced strike.
        (repo / "docs" / "research" / "d.md").write_text(
            "```\nAt line:1\n+     foo -split 'x' -CaseSensitive {\n"
            "+                              ~~~~~~~~~~~~~~\n```\n", encoding="utf-8")
        _m3, _t3, _, _, _, _, _, ub3 = audit(repo, [repo])
        if ub3:
            failures.append("C6 FAILED: a fenced syntax example was read as an unterminated "
                            "strike; a ParserError underline is not a strike")
        # The COUNT printed below is derived from this tuple, and C7 asserts the tuple really
        # describes the suite -- an independent verifier caught the hand-written string saying
        # "4 controls" while six were running. The summary a reader quotes had drifted from
        # what the suite does, which is the same failure this whole gate exists to catch.
        CONTROLS = ("C1 a cited-but-absent worker report is named; "
                    "C2 one that is on disk stays green; "
                    "C3 an external-repository citation is counted, never gated; "
                    "C4 a citation to line 900 of a 3-line file fires, which is the check "
                    "that makes a recovered remnant honest instead of reassuring; "
                    "C5 an odd number of ~~ markers is reported AND the citation inside it "
                    "survives; "
                    "C6 a fenced syntax example is not read as an unterminated strike; "
                    "C7 this summary's own control count is asserted, not typed by hand")
        n = len(re.findall(r"\bC[1-9]\b", CONTROLS))
        if n != 7:
            failures.append(f"C7 FAILED: the summary enumerates {n} controls, expected 7")
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
    ap.add_argument("--wiki", default=r"<private-tree>")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--count", action="store_true", help="print the numbers, exit 0")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    repo = pathlib.Path(args.repo)
    docs = repo / "docs" / "research"
    if not docs.is_dir():
        print(f"arsenal-doctrine-check: cannot run, no dossier dir at {docs}", file=sys.stderr)
        return 2

    estate = list(DEFAULT_ESTATE) + [pathlib.Path(args.wiki)]
    (missing, worker_total, external, past, bare, struck_n, struck_f,
     unbalanced_docs) = audit(repo, estate)

    missing_cites = sum(missing.values())
    past_cites = sum(past.values())
    if args.count:
        print(f"live line citations: {worker_total}  missing-file: {missing_cites} "
              f"({len(missing)} files)  past-the-end: {past_cites} ({len(past)} files)  "
              f"bare mentions: {bare}  struck (history): {struck_n}  external-repo: {external}")
        return 0

    print(f"arsenal-doctrine-check: scanned {len(list(docs.rglob('*.md')))} dossiers; "
          f"{worker_total} worker-report citations, {external} external-repo citations "
          f"(counted, not gated -- those are %TEMP% clones that were never meant to survive)")

    for line in (_r10_report(pathlib.Path(args.wiki))
                 + _r11_report(repo, pathlib.Path(args.wiki))):
        print(f"  REPORT  {line}")

    # An unparseable document is NOT a clean document. Refusing to print PROVENANCE CLEAN over
    # a dossier whose struck/live split we could not determine is the whole point: the failure
    # this fixes turned a red run green, and a green nobody earned is worse than a red.
    if unbalanced_docs:
        print(f"UNBALANCED STRIKE MARKERS in {len(unbalanced_docs)} dossier(s) -- these are NOT "
              f"counted as clean, and the run fails:")
        for nm in sorted(set(unbalanced_docs)):
            print(f"  TILDES     {nm}  -- an odd number of ~~ markers, so which spans are struck "
                  f"is undetermined. Balance the markers, or strike the citations deliberately.")
        print("arsenal-doctrine-check: refusing to report PROVENANCE CLEAN while a dossier's "
              "struck/live split is undetermined.")
        return 1

    if not missing and not past:
        print(f"PROVENANCE CLEAN: 0 live worker-report citations unresolved. "
              f"This means NO UNSTRUCK dead citation remains -- not that the evidence "
              f"exists. {struck_n} citations are struck in place across "
              f"{struck_f} dossiers and stay struck: those reports "
              f"were never written to disk. See docs/research/WORKER-REPORT-LOSS.md.")
        return 0

    for name, n in sorted(missing.items(), key=lambda kv: -kv[1]):
        print(f"  MISSING     {name}  cited {n}x, not present in either tree")
    for name, n in sorted(past.items(), key=lambda kv: -kv[1]):
        print(f"  PAST-END    {name}  cited {n}x, but the copy on disk is shorter than the "
              f"lines cited -- the report was truncated in recovery")
    print(f"arsenal-doctrine-check: {len(missing)} report(s) cited {missing_cites} times with no "
          f"file at all, and {len(past)} more cited {past_cites} times past the end of what "
          f"survives. These citations cannot be re-run, so the figures they support are claims, "
          f"not facts. Recover the reports or strike the citations.")
    return 1


if __name__ == "__main__":
    sys.exit(main())