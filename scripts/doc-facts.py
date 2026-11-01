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
  * a document that declares itself a record (`<!-- doc-facts:history -->`) is not scanned;
  * a number on a live line that contradicts the registry is a FAILURE;
  * a live line that agrees is fine, and a document with no such claim is fine.

NOT EVERY NUMBER COMES FROM THE REGISTRY. Most do -- the counts below are derived from
manifests/capabilities.json. The validator's own two, how many rule functions it carries and how
many selftest cases it fires, are not in the registry at all, so they are read by RUNNING
registry-verify.py in a subprocess and never written into this file: a constant pinned here would
stay green forever while the validator moved underneath it.

Exit 0 clean, 1 violations, 2 could not run -- and 2 now also covers "could not derive an expected
value", because skipping a claim and still printing OK is this file's own failure mode wearing a
stricter-looking coat. An error is never a zero.

ONE NAMED EXCEPTION, and it exists because the wiki is a PRIVATE SIBLING TREE that a public
checkout does not have. When the wiki directory is absent, the run prints
`SKIP: no wiki at <path> (this is expected in a public checkout)`, still prints the figures it can
derive from the registry alone, and exits 0 -- it does NOT print the OK line, because nothing was
compared to prose. The skip cannot be widened into "the wiki is empty": a wiki that EXISTS but
carries no scannable page is still exit 2, so the only thing that can degrade to a skip is an
ABSENT tree.

Run:  python scripts/doc-facts.py --repo <repo>
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

# (label, regex with one capture group, callable taking the registry -> expected int or None)
# `None` means "this claim is not derivable from the registry", so it is not checked.
CLAIMS: list[tuple[str, re.Pattern[str], object]] = []


def claim(label, pattern, fn, multiline=False):
    """Register one checkable fact.

    `multiline=True` matches against the whole LIVE TEXT of a file rather than one line at a
    time. It exists because an audit found a LIVE FALSE claim in the charter's own headline
    paragraph, split across a newline: `capabilities:` and `22` on different lines. A per-line
    checker cannot see a claim that wraps, and the line-splitting habit that markdown encourages
    is exactly what defeats it.
    """
    CLAIMS.append((label, re.compile(pattern, re.IGNORECASE), fn, multiline))


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
# MULTILINE, and the reason is a control rather than a theory: the audit's LIVE FALSE claim
# split `capabilities:` and `22` across a newline, so a per-line checker never saw it. Adding
# the multiline machinery but leaving THIS claim on the per-line path would have looked like a
# fix while reproducing the exact defect it was written for. Planted and confirmed to fire.
claim("capability count",
      r"(?:`capabilities:\s*`?\s*(\d{1,4})`)"   # `capabilities: 21`
      r"|\*\*(\d{1,4})\s+capabilit",           # **21 capabilities**
      _cap_count, multiline=True)
claim("observed count",
      r"(\d{1,4})\s+`observed`|`observed`\*{0,2}\s*[:=]?\s*(\d{1,4})", _observed)
claim("typed edge count",
      r"(\d{1,4})\s+typed\s+(?:from-)?edges", _edges)


def _invoke_count(reg):
    return sum(1 for c in reg["capabilities"] if c.get("invoke"))


def _runnable_controls(reg):
    return sum(1 for c in reg["capabilities"]
               if str(((c.get("negative_control") or {}).get("command")) or "").strip())


def _plan_controls(reg):
    return sum(1 for c in reg["capabilities"]
               if (c.get("negative_control") or {}).get("kind") == "plan")


def _families(reg):
    return len(reg["schema"]["evidence_families"])


# An audit measured this gate at 16 live claims against 1893 live lines carrying a digit --
# 0.85% coverage, with greenness a function of write order rather than correctness. Four more
# quantities take it off the list of things the wiki asserts and nothing checks. Only
# unambiguous forms are added; prose counts remain out of scope ON PURPOSE, because the second
# version of this script over-matched row counts and a gate that cries wolf gets switched off.
claim("callable count",
      r"(\d{1,4})\s+(?:capabilities\s+)?(?:declaring an `invoke`|callable capabilities|callable\b)",
      _invoke_count, multiline=True)
claim("runnable negative controls",
      r"(\d{1,4})\s+runnable negative control", _runnable_controls)
claim("declared plan controls",
      r"(\d{1,4})\s+(?:declared\s+PLANS?|declare a documented plan)", _plan_controls)
# BOLDED ONLY, after the first attempt matched `2 capabilities across 2 evidence families:
# decompiler, static-analysis` inside a QUOTED mission message and reported the registry as
# wrong. This is the over-matching failure this script has already made once, and the rule that
# survives it is the one already written at the top of this file: check two unambiguous forms
# reliably rather than five noisily, because a gate that cries wolf gets switched off.
claim("family count",
      r"\*\*(\d{1,4})\s+(?:evidence )?famil(?:y|ies)\*\*", _families)

# --------------------------------------------------------------------------- the evidence split
#
# The wiki keeps answering a question the registry answers without being asked: how much of what
# is claimed is backed by an artifact somebody kept, and how much is still a promise. Both halves
# are DERIVED, not declared, and the derivation is deliberately the one R17 already enforces -- a
# capability is bound when its probe names a run_log file AND a sha256 for it.
#
# "MATCHING" sha256 is R17's job, not this file's. registry-verify.py refuses a run_log whose hash
# does not match the file it names, so re-hashing here would be a fourth copy of a rule that
# already has an owner. This script counts bindings; it does not audit them.
def _bound_evidence(reg):
    return sum(1 for c in reg["capabilities"]
               if str(((c.get("probe") or {}).get("run_log")) or "").strip()
               and str(((c.get("probe") or {}).get("sha256")) or "").strip())


def _unverified_evidence(reg):
    """Observed capabilities with NO bound artifact.

    observed - bound, and deliberately NOT a count of `probe.evidence_binding.status ==
    "unverified"`. Those two differ, and measuring it is the whole reason this is written down:
    the status key is also present on native.crosscompare.ghidra, which is state `planned`, so
    counting it would return 3 -- and 3 is a different question from "of the 23 observed, how
    many are still unbacked". A wiki sentence that pairs the bound figure with the unverified one
    is talking about the observed set, so that is what is counted here.
    """
    return _observed(reg) - _bound_evidence(reg)


# "N still unverified" and "N unverified" are the same fact, so one form covers both: the
# `still` is optional, not a second claim, and giving them separate capture groups is exactly the
# nesting mistake the NOTE ON GROUPING above warns about. Measured on the live wiki: zero lines
# match this, so it costs no coverage today and stands ready for the sentence when it is written.
claim("bound-to-retained-artifact count",
      r"(\d{1,4})\s+bound to a retained artifact", _bound_evidence)
claim("unverified-evidence count",
      r"(\d{1,4})\s+(?:still\s+)?unverified\b", _unverified_evidence)

# "N runnable commands" as its own form, and the reason it is a SEPARATE claim from the one above
# rather than a fourth alternative inside it: the number and the word it counts are on DIFFERENT
# LINES in the wiki's own headline. wiki/INDEX.md reads
#     negative controls **23 runnable
#     commands + 4 declared plans, ...
# so a per-line form sees `23 runnable` and stops. That is the wrapping defect this file already
# built `multiline` for, and adding a per-line form here would have looked like coverage while
# reproducing the exact defect it was written for. The optional middle group lets the same form
# read "23 runnable negative control commands" without a second pattern.
claim("runnable control commands",
      r"(\d{1,4})\s+runnable\s+(?:negative\s+control\s+)?commands?", _runnable_controls,
      multiline=True)

# ------------------------------------------------------------------- the validator's own counts
#
# Two numbers the wiki asserts are not in the registry at all: how many rule functions
# registry-verify.py carries and how many selftest cases it fires. Writing either one into this
# file as a constant would be the defect this whole script exists to catch -- a pinned number
# never moves, so the check stays green forever and the first person to add a rule gets no
# warning. They are read from the validator by RUNNING it, lazily, once per invocation.
#
# MEASURED 2026-10-03 on the validator's own output: `--selftest` prints exactly one count --
#     SELFTEST OK: 80 cases each fire on a registry built to break them.
# The RULE count is printed NOWHERE: the default run prints the registry path, the capability
# count, any violations, the CLEAN line and the control split; `--json` prints ok/count/problems.
# So the rule count is measured off the validator's own RULES table by importing it. importlib,
# not `import`, because the file is named `registry-verify.py` and a hyphen is not an identifier.
_VALIDATOR_PROBE = (
    "import importlib.util, re, sys\n"
    "spec = importlib.util.spec_from_file_location('registry_verify', sys.argv[1])\n"
    "m = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(m)\n"
    # numbered first, total second -- see the rule-count note below
    "numbered = sum(1 for r in m.RULES if re.match(r'r\\d+_', r.__name__))\n"
    "print('RULES', numbered, len(m.RULES))\n"
    "raise SystemExit(m.selftest())\n"
)
_VALIDATOR: dict = {}
_REPO: pathlib.Path | None = None


# WHY THE RULE COUNT IS NOT len(RULES), measured 2026-10-03 the same day this was written:
# len(RULES) is 27 and the wiki says 26. Both are right, and the difference is `r_shape` -- the
# entry the validator's own header documents as "R-shape", a structural check with no rule
# number. Counting the tuple with len() would have declared the registry DISAGREEING with the
# wiki's one true sentence about the validator's size -- a gate that is right about the registry
# and wrong about the prose, which is the same cry-wolf failure in the other direction and would
# have been indistinguishable, from the wiki's side, from this script misfiring.
#
# So the count is derived the way the prose names it: the RULES entries whose own function name
# carries an R number, r1_not_empty .. r26_bare_braces_survive_the_shell. Both numbers are
# printed so the difference stays visible instead of being a private convention here.


def _validator_number(key: str):
    """The validator's own count for `key`, or None when it cannot be read.

    None is NOT silent. main() counts every claim it could not check and, if any were skipped,
    refuses to print OK and exits 2 -- because a gate that quietly stops checking is the
    always-green failure wearing a new hat, and this one would be wearing the costume of a
    stricter gate.
    """
    if _REPO is None:
        return None
    if not _VALIDATOR:
        path = _REPO / "scripts" / "registry-verify.py"
        out = err = ""
        code = None
        if not path.exists():
            err = f"no validator at {path}"
        else:
            try:
                p = subprocess.run([sys.executable, "-c", _VALIDATOR_PROBE, str(path)],
                                   capture_output=True, text=True, timeout=180,
                                   cwd=str(_REPO))
                out, err, code = p.stdout, p.stderr, p.returncode
            except (OSError, subprocess.SubprocessError) as e:
                err = f"{type(e).__name__}: {e}"
        rules = re.search(r"^RULES (\d+) (\d+)$", out, re.M)
        cases = re.search(r"SELFTEST OK: (\d+) cases", out)
        _VALIDATOR["rules"] = int(rules.group(1)) if rules else None
        _VALIDATOR["rules_total"] = int(rules.group(2)) if rules else None
        _VALIDATOR["cases"] = int(cases.group(1)) if cases else None
        if _VALIDATOR["cases"] is None and err.strip():
            _VALIDATOR["error"] = err.strip().splitlines()[-1][:160]
        elif code not in (0, None):
            _VALIDATOR["error"] = f"validator selftest exited {code}"
    return _VALIDATOR.get(key)


def _validator_rules(reg):
    return _validator_number("rules")


def _validator_cases(reg):
    return _validator_number("cases")


# THE RULE COUNT, in every phrasing the wiki actually uses for it. Each alternative below was
# added because it was found LIVE, and every one of them was measured against all 118 scanned
# wiki files before it was kept: six hits, all six the validator's own rule count, zero false
# positives. The set is alternatives inside ONE claim so a failure names the quantity, not the
# sentence that phrased it.
#
#   "N rule functions"        the plain form, and the one this claim started as.
#   "N **rule** functions"    bold on the inner word only. `\*{0,2}` around the noun reads
#                             INDEX.md:90 -- `a **case** count; 26 **rule** functions` -- which
#                             is the wiki's own table quoting a count.
#   "N numbered rule functions" / "N numbered rules"   the disambiguated form the wiki moved to
#                             on 2026-10-03 once 26 rules and 27 RULES entries stopped being the
#                             same sentence. "numbered" is the discriminator that keeps it out of
#                             every other rule count in the tree.
#   "`RULES` ... holds N functions"   the sentence that says what the tuple IS. `.{0,60}?` and
#                             not a negated class: the text between the two ends contains
#                             `registry-verify.py`, so a class excluding `.` matched NOTHING --
#                             a form that cannot match is not a narrow form, it is a missing one,
#                             and it looked green for a day.
#   "N-rule"                  the hyphenated compound in "the N-rule claim".
#
# THE LOOKAHEAD, and where it went wrong first. arsenal-upgrade-plan.md carries TWO sentences
# about rule counts that are not the validator's size: "10 of 11 rule functions load-bearing",
# which is the ABLATION's figure. The first attempt at excluding it made the optional group
# `(?:\s+functions?\b)?` come BEFORE the lookahead, so the pattern matched the bare `11 rule` and
# the lookahead then examined a position it had already skipped -- the exclusion silently did
# nothing, and the ablation sentence reddened. The same widening also matched `H1 rule` in
# wiki/methods/landscape.md, which is a HackerOne guideline, not a rule function: a digit inside
# an identifier. Both are why the group is now REQUIRED before the lookahead and why "numbered"
# is required for the bare-noun form. Measured after the fix: 6 hits, 0 wrong.
#
# NOT CHECKED, declared rather than half-handled: "`RULES` holds 27 entries" is the length of the
# tuple, which is a DIFFERENT number from the 26 numbered rules and would redden if compared to
# it. That quantity has no claim of its own; it is printed in the summary below instead.
claim("validator rule count",
      r"(\d{1,4})\s+(?:numbered\s+)?\*{0,2}rule\*{0,2}\s+functions?\b(?! load-bearing)"
      r"|(\d{1,4})\s+numbered\s+\*{0,2}rules?\b"
      r"|`RULES`.{0,60}?holds (\d{1,4})\s+functions"
      r"|(\d{1,4})-rule\b", _validator_rules, multiline=True)
# The case count, same discipline: three phrasings, six hits across the tree, all six the
# validator's own number. "N cases each fire" is the validator's own stdout wording quoted in the
# wiki's evidence table, and it is the only place that phrasing appears.
claim("validator selftest case count",
      r"(\d{1,4})\s+selftest cases\b"
      r"|(\d{1,4})\s+(?:is|as)\s+the case count"
      r"|(\d{1,4})\s+cases each fire", _validator_cases, multiline=True)

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
    global _REPO
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parents[1]))
    ap.add_argument("--wiki", default=None,
                    help="wiki repo root; defaults to <private-tree>, a private sibling tree "
                         "that is absent in a public checkout (an absent wiki is a SKIP, an "
                         "empty one is a failure)")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    manifest = repo / "manifests" / "capabilities.json"
    if not manifest.exists():
        print(f"doc-facts: cannot run, no registry at {manifest}", file=sys.stderr)
        return 2
    reg = json.loads(manifest.read_text(encoding="utf-8"))

    # The validator claims read this. Set before any claim runs so that a failure to read the
    # validator is visible in the exit code rather than being a claim that quietly checks
    # nothing -- see _validator_number.
    _REPO = repo

    # THE WIKI MAY SIMPLY NOT BE HERE, and until 2026-11-01 that made this script unrunnable.
    # The default is a PLACEHOLDER: history was rewritten so that no path into the private tree
    # survives, and `<`/`>` cannot name a directory on Windows, so `is_dir()` is False by
    # construction in a public checkout. The previous line here exited 2, which meant every
    # clone of this repository carried a gate that could only refuse -- the same always-green
    # failure this file exists to catch, wearing a "strict" coat, because a check that never
    # runs never goes red.
    #
    # So an ABSENT wiki is a named SKIP: the line is printed, the registry-derived figures below
    # still print, and the exit is 0. What stops that from being a hole is the page-count branch
    # right after `targets`: a wiki that EXISTS and carries nothing to scan is exit 2. Absent and
    # empty are different facts and the skip is only allowed to mean the first one.
    # Measured 2026-11-01: `pathlib.Path("<private-tree>").is_dir()` returns False on this host
    # rather than raising on the illegal characters, so no exception guard is needed here.
    wiki = pathlib.Path(args.wiki or r"<private-tree>")
    wiki_present = wiki.is_dir()
    if not wiki_present:
        print(f"SKIP: no wiki at {wiki} (this is expected in a public checkout)")
        if args.wiki:
            # --wiki was NAMED and still is not a directory. The line above is true but this
            # reader more likely has a typo than a public checkout, and the exit code can no
            # longer say so. Say it here, the one place the two cases are distinguishable.
            print(f"doc-facts: note -- --wiki was given as {wiki} and is not a directory; "
                  f"nothing was checked against prose.", file=sys.stderr)

    # SCOPE, deliberately narrow. Two classes are excluded because they are RECORDS OF WHAT WAS
    # TRUE WHEN WRITTEN, not live prose: `.agent/research/` (dated survey reports -- the
    # pentagi study says "16 capabilities, 5 typed edges", true on 2026-10-02 and not a claim
    # about today) and `literature/` (imported third-party reports, same reasoning). The same
    # reasoning governs struck-through lines, which live_lines() already skips. A gate that
    # cries wolf on archived truth is the failure this script exists to prevent, and it was
    # measured: the first run reported 16 violations of which 2 were exactly that.
    SKIP_DIRS = {".git", ".agent", "literature"}
    BACKUP_SUFFIXES = re.compile(r"(~\d*|\.bak|\.orig|\.swp|\.rej)$")
    # EDITOR BACKUPS ARE NOT PAGES. Measured 2026-10-04: a transient `INDEX.md~1` left by
    # whatever last wrote the file was scanned as a wiki page and reported a stale numeric
    # claim that no one had written -- the drift was in a backup of a file that was fine.
    # A gate that reports invented violations trains its reader to ignore it, so the filter
    # belongs here rather than in a cleanup someone has to remember. `~`, `.bak`, `.orig`,
    # `.swp` and a leading dot are all excluded; none of them is content anyone cites.
    targets = sorted(p for p in wiki.rglob("*.md")
                     if not SKIP_DIRS.intersection(p.relative_to(wiki).parts)
                     and not BACKUP_SUFFIXES.search(p.name)
                     and not p.name.startswith("."))

    # ABSENT IS A SKIP; EMPTY IS A FAILURE, and this branch is what keeps the skip from becoming
    # an off switch. Without it the two cases would produce the same run -- zero files, zero
    # claims, exit 0 -- so "somebody pointed --wiki at the wrong directory" and "the wiki lost
    # every page" would both read as a pass. The directory exists, so the caller's intent was to
    # check a wiki; finding nothing in it is the one outcome that must not be silent.
    if wiki_present and not targets:
        print(f"doc-facts: cannot run, no wiki pages under {wiki} -- the directory exists but "
              f"carries nothing scannable (no .md outside .git/.agent/literature and editor "
              f"backups). An empty wiki is a broken wiki, not an absent one.", file=sys.stderr)
        return 2

    # HISTORY IS DECLARED BY THE DOCUMENT, NOT GUESSED BY THE GATE. A session ledger records
    # what was true on a date and quotes old figures on purpose -- SEMANTICS.md's own contract
    # is "编年止于 2026-10-21。更正用〔更正〕块，不改历史行", so the gate cannot be answered by
    # rewriting those lines, and the alternative (a directory in SKIP_DIRS) would also stop checking
    # the live handoff that sits in the same directory. Measured 2026-10-31: all five violations
    # this gate reported were such quotes under `_agent-history/` and none was a live claim.
    # So the file opts out itself, and the summary NAMES every file that did -- an exclusion
    # nobody can see is the always-green failure this script exists to catch.
    # THE DECLARATION MUST BE IN THE FIRST 10 LINES, on a line of its own: a page that merely
    # DOCUMENTS this convention must not silently opt itself out of the check.
    HISTORY_MARKER = "<!-- doc-facts:history -->"
    history_only: list[pathlib.Path] = []
    live: list[pathlib.Path] = []
    for p in targets:
        try:
            head = p.read_text(encoding="utf-8", errors="replace").splitlines()[:10]
        except OSError:
            head = []
        (history_only if any(h.strip() == HISTORY_MARKER for h in head) else live).append(p)
    targets = live

    violations: list[str] = []
    unchecked = 0
    checked = 0
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines = list(live_lines(text))
        for label, rx, fn, multiline in CLAIMS:
            if multiline:
                # Match against the whole live text with newlines collapsed to spaces, so a
                # claim that WRAPS is still seen. `starts` keeps each source line's offset in
                # the blob so the reported line is the real one: the old code counted "\n" in a
                # blob that has none and therefore reported line 1 for EVERY wrapped claim --
                # measured 2026-10-31, that misread `SEMANTICS.md~1` as an editor backup file
                # rather than "line 1 of SEMANTICS.md", and sent a round of diagnosis the wrong
                # way. A diagnostic that always says "line 1" is a diagnostic nobody can use.
                blob, starts = "", []
                for lineno, text_line in lines:
                    starts.append((len(blob), lineno))
                    blob += text_line + " "
                for m in rx.finditer(blob):
                    got = next((g for g in m.groups() if g), None)
                    if got is None:
                        continue
                    want = fn(reg)
                    if want is None:
                        unchecked += 1
                        continue
                    checked += 1
                    if int(got) != want:
                        lineno = next(n for off, n in reversed(starts) if off <= m.start())
                        rel = path.relative_to(wiki)
                        violations.append(
                            f"{rel}:{lineno}: claims {got} {label}; registry says {want}\n"
                            f"    {blob[max(0, m.start()-40):m.end()+40].strip()[:110]}"
                            f"\n    (wrapped claim; line = where the match starts)")
                continue
            for lineno, line in lines:
                for m in rx.finditer(line):
                    # A line may carry the number twice (two capture groups); take the first
                    # group that actually captured something.
                    got = next((g for g in m.groups() if g), None)
                    if got is None:
                        continue
                    want = fn(reg)
                    if want is None:
                        unchecked += 1
                        continue
                    checked += 1
                    if int(got) != want:
                        rel = path.relative_to(wiki)
                        violations.append(
                            f"{rel}:{lineno}: claims {got} {label}; registry says {want}\n"
                            f"    {line.strip()[:110]}")

    print(f"doc-facts: registry has {_cap_count(reg)} capabilities "
          f"({_observed(reg)} observed, {_edges(reg)} typed edges)")
    # The evidence split, stated so the counts the new claims check are visible without turning
    # a reader into a second implementation of them. `rules_total` is the length of the
    # validator's RULES table; `rules` is the numbered subset, which is what the prose counts.
    print(f"doc-facts: evidence split -- {_bound_evidence(reg)} bound to a retained artifact, "
          f"{_unverified_evidence(reg)} unverified, "
          f"{_runnable_controls(reg)} runnable controls, {_plan_controls(reg)} declared plans")

    if wiki_present:
        def _n(key):
            v = _validator_number(key)
            return "UNREADABLE" if v is None else v

        # The validator's own counts are NOT read on the skip path: nothing would compare them to
        # prose, and reading them costs a subprocess that runs the validator's own selftest (~20 s
        # on this tree). A figure nobody checks does not belong in a run that checked nothing.
        print(f"doc-facts: validator -- {_n('rules')} numbered rules "
              f"({_n('rules_total')} in RULES), "
              f"{_n('cases')} selftest cases, both read by running it")
        print(f"doc-facts: scanned {len(targets)} wiki files, "
              f"{checked} live numeric claims checked")
        if history_only:
            print(f"doc-facts: {len(history_only)} file(s) declared history-only, NOT scanned: "
                  + ", ".join(str(p.relative_to(wiki)) for p in history_only))
    if violations:
        print(f"doc-facts: {len(violations)} STALE CLAIM(S)\n")
        for v in violations:
            print("  " + v)
        print("\nFix by editing the live figure. Do NOT delete a struck old value -- history "
              "is kept on purpose, and this check ignores struck lines precisely so that "
              "history does not read as drift.")
        return 1
    if unchecked:
        # FAIL CLOSED, and this is a change of exit code, not a new colour. Before this, a claim
        # whose expected value could not be derived was skipped and the run still printed OK --
        # so a broken validator would have produced a stricter-looking gate that checked less.
        # Printed BEFORE the OK line, because printing "OK" and then refusing to pass is two
        # contradictory sentences and the first one is the one a reader skims.
        print(f"doc-facts: REFUSING TO PASS -- {unchecked} claim(s) had no derivable expected "
              f"value and were NOT checked."
              + (f"  validator: {_VALIDATOR.get('error', 'unavailable')}" if _VALIDATOR
                 else ""))
        return 2
    if not wiki_present:
        # NOT the OK line. Nothing above was compared to prose, and a run that says "every live
        # numeric claim matches the registry" after scanning no file is exactly the overstatement
        # the header of this file complains about in other gates. Exit 0 because the caller asked
        # for a check this checkout cannot provide, and the SKIP line said so before any figure
        # printed -- a skip that announced itself is not the same thing as a green.
        print("doc-facts: SKIP -- no wiki was scanned, so no claim was compared to prose; "
              "the registry figures above are the whole result.")
        return 0
    print("doc-facts: OK, every live numeric claim matches the registry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())