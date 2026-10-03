#!/usr/bin/env python
"""Prove that every claim form scripts/doc-facts.py declares actually fires.

WHY THIS EXISTS. doc-facts.py is the only thing that reads the wiki tree and compares its numbers
with the registry, and it had no test of its own: a sweep found its own header conceding 0.85%
coverage and nothing in the tree verified that a form it claims to check can see a wrong number.
That is the always-green failure this repository keeps paying for -- a gate that cannot be shown to
fail is a gate nobody can distinguish from a gate that does nothing. The comments inside
doc-facts.py document three such incidents (an unreachable `capabilities:` alternative, a
lookahead that examined a position it had already skipped, a `.{0,60}?` class that matched
nothing) and every one of them was found by hand, after the fact.

So this file is that test, and it is a subprocess harness on purpose. It does NOT import
doc-facts.py and call its functions: the checks below are the exit codes and the words a reader
would see, because the failure mode being guarded against is a checker whose internals look right
and whose verdict is not. It drives the real script against a %TEMP% copy of a real wiki file and
asserts four things per form:

  1. RED   -- a wrong number, in that form, in a copy of a real wiki file, is reported. The
              violation line is printed verbatim so the transcript is quotable.
  2. GREEN -- the same sentence with the CORRECT number passes. This is the half that stops a
              future edit from "fixing" a broken form by deleting the alternative that catches it,
              because a deleted alternative leaves the control green for the wrong reason.
  3. QUIET -- prose that is not a claim of a registry quantity ("the table has 14 entries", "H1
              rule is a HackerOne guideline", "a verdict is not a finding") checks ZERO claims.
  4. LOAD-BEARING -- a mutant, built from a %TEMP% COPY of doc-facts.py, in which the form (or
              the multiline flag) is removed or downgraded, stops catching its own plant.

The expected numbers are derived HERE, independently, from manifests/capabilities.json, and then
cross-checked against the numbers doc-facts.py prints about itself. A harness that imported the
checker's derivations would agree with the checker by construction, which is not agreement.

WHY IT IS NOT A `--selftest` FLAG INSIDE doc-facts.py. It would have been fewer lines. The reason
it is a separate file is that a self-test sharing code with the thing it tests inherits that code's
bugs: a `--selftest` that walked the tree through the same live_lines(), the same summary regex and
the same claim table would go GREEN on exactly the defects this file exists to catch -- the
unreachable alternative, the dead lookahead, the class that matches nothing -- because in all three
cases the mistake is in the code the test would be sharing. Only a process boundary can ask the
question a reader asks: "run the real command, did it catch this?"


The repo's own doc-facts.py is NEVER modified. Mutants are written under %TEMP% only.

Run:  python scripts/verify-doc-facts-selftest.py [--repo DIR] [--wiki DIR] [--keep]
Exit: 0 every control held; 1 at least one did not; 2 the harness could not run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve()
DEFAULT_REPO = HERE.parents[1]
DEFAULT_WIKI = pathlib.Path(r"<private-tree>")
PY = sys.executable

# doc-facts.py's own scope. Copied here because the coverage denominator has to be counted over
# exactly the set the checker inspects; a denominator wider than the scan would flatter the ratio.
SKIP = {".git", ".agent", "literature"}


# --------------------------------------------------------------------------- expected numbers
def derive(manifest: pathlib.Path) -> dict:
    """Every registry-derived quantity doc-facts.py checks, computed from the manifest alone.

    Deliberately a second implementation. If this function and doc-facts.py's `_cap_count` family
    ever disagree, the harness says so instead of repeating the checker's arithmetic back at it.
    """
    reg = json.loads(manifest.read_text(encoding="utf-8"))
    caps = reg["capabilities"]

    def text(v) -> str:
        return str(v or "").strip()

    observed = sum(1 for c in caps if c.get("state") == "observed")
    bound = sum(1 for c in caps
                if text((c.get("probe") or {}).get("run_log")) and text((c.get("probe") or {}).get("sha256")))
    return {
        "capabilities": len(caps),
        "observed": observed,
        "typed edges": sum(1 for c in caps
                           for i in ((c.get("consumes") or {}).get("inputs") or []) if i.get("from")),
        "callable": sum(1 for c in caps if c.get("invoke")),
        "runnable controls": sum(1 for c in caps
                                 if text((c.get("negative_control") or {}).get("command"))),
        "declared plans": sum(1 for c in caps
                              if (c.get("negative_control") or {}).get("kind") == "plan"),
        "families": len(reg["schema"]["evidence_families"]),
        "bound": bound,
        # observed - bound, and not a count of probe.evidence_binding.status == "unverified";
        # doc-facts.py documents why, and the harness must not quietly use the other question.
        "unverified": observed - bound,
    }


# ------------------------------------------------------------------------------- the case table
# (id, claim label as doc-facts.py spells it, what the form is, the planted lines, which derived
#  number the correct plant must carry, extra labels that redden with it)
#
# One row per ALTERNATIVE, not per claim: doc-facts.py packs up to four phrasings into one claim
# so that a failure names the quantity instead of the sentence. Each of those alternatives is a
# separate thing that can silently stop matching, and the alternative that a future editor deletes
# is exactly the one no aggregate count would notice.
CASES: list[tuple] = [
    ("1a", "capability count", "`capabilities: N`",
     ["selftest plant: `capabilities: {w}` in this station."], "capabilities", ()),
    ("1b", "capability count", "**N capabilities**",
     ["selftest plant: **{w} capabilities** in this station."], "capabilities", ()),
    ("1c", "capability count", "WRAPPED **N capabilities**",
     ["selftest plant: **{w}", "capabilities** in this station, and the wrap is the point."],
     "capabilities", ()),

    ("2a", "observed count", "N `observed`",
     ["selftest plant: {w} `observed` in this station."], "observed", ()),
    ("2b", "observed count", "`observed`: N",
     ["selftest plant: `observed`: {w} in this station."], "observed", ()),

    ("3a", "typed edge count", "N typed edges",
     ["selftest plant: {w} typed edges in this station."], "typed edges", ()),
    ("3b", "typed edge count", "N typed from-edges",
     ["selftest plant: {w} typed from-edges in this station."], "typed edges", ()),

    ("4a", "callable count", "N declaring an `invoke`",
     ["selftest plant: {w} declaring an `invoke` in this station."], "callable", ()),
    ("4b", "callable count", "N capabilities declaring an `invoke`",
     ["selftest plant: {w} capabilities declaring an `invoke` in this station."], "callable", ()),
    ("4c", "callable count", "N callable capabilities",
     ["selftest plant: {w} callable capabilities in this station."], "callable", ()),
    ("4d", "callable count", "N callable",
     ["selftest plant: {w} callable in this station."], "callable", ()),
    ("4e", "callable count", "WRAPPED N callable capabilities",
     ["selftest plant: {w}", "callable capabilities in this station, and the wrap is the point."],
     "callable", ()),

    ("5a", "runnable negative controls", "N runnable negative control",
     ["selftest plant: {w} runnable negative control in this station."], "runnable controls", ()),

    ("6a", "declared plan controls", "N declared PLANS",
     ["selftest plant: {w} declared PLANS in this station."], "declared plans", ()),
    ("6b", "declared plan controls", "N declare a documented plan",
     ["selftest plant: {w} declare a documented plan in this station."], "declared plans", ()),

    ("7a", "family count", "**N families**",
     ["selftest plant: **{w} families** in this schema."], "families", ()),
    ("7b", "family count", "**N evidence families**",
     ["selftest plant: **{w} evidence families** in this schema."], "families", ()),

    ("8a", "bound-to-retained-artifact count", "N bound to a retained artifact",
     ["selftest plant: {w} bound to a retained artifact in this station."], "bound", ()),

    ("9a", "unverified-evidence count", "N unverified",
     ["selftest plant: {w} unverified in this station."], "unverified", ()),
    ("9b", "unverified-evidence count", "N still unverified",
     ["selftest plant: {w} still unverified in this station."], "unverified", ()),

    # 10b is the one case where one sentence legitimately trips two claims: "23 runnable negative
    # control commands" contains the whole of 5a's form as a prefix. Both are correct about it, so
    # both must redden on a wrong number, and the harness expects both rather than hiding one.
    ("10a", "runnable control commands", "N runnable commands",
     ["selftest plant: {w} runnable commands in this station."], "runnable controls", ()),
    ("10b", "runnable control commands", "N runnable negative control commands",
     ["selftest plant: {w} runnable negative control commands in this station."],
     "runnable controls", ("runnable negative controls",)),
    ("10c", "runnable control commands", "WRAPPED N runnable commands",
     ["selftest plant: {w} runnable", "commands in this station, and the wrap is the point."],
     "runnable controls", ()),

    ("11a", "validator rule count", "N rule functions",
     ["selftest plant: {w} rule functions in the validator."], "rules", ()),
    ("11b", "validator rule count", "N numbered rule functions",
     ["selftest plant: {w} numbered rule functions in the validator."], "rules", ()),
    ("11c", "validator rule count", "N **rule** functions",
     ["selftest plant: {w} **rule** functions in the validator."], "rules", ()),
    ("11d", "validator rule count", "N numbered rules",
     ["selftest plant: {w} numbered rules in the validator."], "rules", ()),
    ("11e", "validator rule count", "`RULES` ... holds N functions",
     ["selftest plant: `RULES` in registry-verify.py holds {w} functions today."], "rules", ()),
    ("11f", "validator rule count", "N-rule",
     ["selftest plant: the {w}-rule claim in this harness."], "rules", ()),
    ("11g", "validator rule count", "WRAPPED N rule functions",
     ["selftest plant: {w}", "rule functions in the validator, and the wrap is the point."],
     "rules", ()),

    ("12a", "validator selftest case count", "N selftest cases",
     ["selftest plant: {w} selftest cases in the validator."], "cases", ()),
    ("12b", "validator selftest case count", "N is the case count",
     ["selftest plant: {w} is the case count printed by the validator."], "cases", ()),
    ("12c", "validator selftest case count", "N cases each fire",
     ["selftest plant: {w} cases each fire on a registry built to break them."], "cases", ()),
    ("12d", "validator selftest case count", "WRAPPED N selftest cases",
     ["selftest plant: {w}", "selftest cases in the validator, and the wrap is the point."],
     "cases", ()),
]

# Prose that is NOT a claim of a registry quantity. Each line is a shape that a looser regex would
# turn into drift; the harness asserts the checker reports ZERO claims for the file, so a future
# widening that starts crying wolf fails here instead of in somebody's face.
QUIET_PROSE = [
    "selftest prose: the table has 14 entries.",
    "selftest prose: the H1 rule is a HackerOne guideline, not a registry rule function.",
    "selftest prose: a verdict is not a finding.",
    # Carried live in wiki/methods/arsenal-upgrade-plan.md; the rule-count lookahead exists for it.
    "selftest prose: 10 of 11 rule functions load-bearing.",
    # The house style is to strike an old figure rather than delete it, so struck text is history.
    "selftest prose: ~~selftest struck history: **31 capabilities**~~ and nothing live follows.",
]

CLAIM_LINE = re.compile(r"claims (\d+) (.+?); registry says (-?\d+)")
CHECKED_LINE = re.compile(r"scanned (\d+) wiki files, (\d+) live numeric claims checked")


# ------------------------------------------------------------------------- running the checker
def run_doc_facts(script: pathlib.Path, repo: pathlib.Path, wiki: pathlib.Path) -> tuple[int, str, str]:
    p = subprocess.run([PY, str(script), "--repo", str(repo), "--wiki", str(wiki)],
                       capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout, p.stderr


def checked_count(out: str) -> int | None:
    m = CHECKED_LINE.search(out)
    return int(m.group(2)) if m else None


def scanned_count(out: str) -> int | None:
    m = CHECKED_LINE.search(out)
    return int(m.group(1)) if m else None


def summary(out: str) -> dict:
    """The numbers doc-facts.py prints about itself, for cross-checking the harness's own."""
    got = {}
    m = re.search(r"registry has (\d+) capabilities \((\d+) observed, (\d+) typed edges\)", out)
    if m:
        got["capabilities"], got["observed"], got["typed edges"] = (int(g) for g in m.groups())
    m = re.search(r"evidence split -- (\d+) bound to a retained artifact, (\d+) unverified, "
                  r"(\d+) runnable controls, (\d+) declared plans", out)
    if m:
        got["bound"], got["unverified"], got["runnable controls"], got["declared plans"] = (
            int(g) for g in m.groups())
    m = re.search(r"validator -- (\d+) numbered rules \((\d+) in RULES\), (\d+) selftest cases", out)
    if m:
        got["rules"], got["rules_total"], got["cases"] = (int(g) for g in m.groups())
    return got


# --------------------------------------------------------------------- mutants of the checker
def claim_spans(src: str) -> list[tuple[str, int, int]]:
    """(label, start, end) for every `claim(...)` registration, in source order."""
    spans = []
    for m in re.finditer(r"^claim\(\s*\n?\s*[\"']([^\"']+)[\"']", src, re.M):
        start = m.start()
        i, depth, in_str, esc, comment = src.index("(", m.start()), 0, False, False, False
        while i < len(src):
            ch = src[i]
            if comment:
                if ch == "\n":
                    comment = False
            elif in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "\"":
                    in_str = False
            elif ch == "#":
                comment = True
            elif ch == "\"":
                in_str = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    spans.append((m.group(1), start, i + 1))
                    break
            i += 1
        else:
            raise AssertionError(f"unbalanced claim() call for {m.group(1)!r}")
    return spans


def mutant_drop_claim(src: str, label: str) -> str:
    """Delete one `claim(...)` registration. The form stops existing; that is the mutation."""
    spans = [s for s in claim_spans(src) if s[0] == label]
    assert len(spans) == 1, f"expected exactly one claim({label!r}), found {len(spans)}"
    _, start, end = spans[0]
    return src[:start] + src[end:].lstrip("\n")


def mutant_drop_multiline(src: str, label: str) -> str:
    """Turn one claim's `multiline=True` into `multiline=False`.

    A different load-bearing mechanism from dropping the form: the claim still exists and still
    matches on one line, so a wrapped claim -- the shape the multiline machinery was added for --
    stops being seen. Removing the form is caught by any plant; removing the flag is caught only by
    a WRAPPED plant, which is why the WRAPPED cases are in the table at all.
    """
    spans = [s for s in claim_spans(src) if s[0] == label]
    assert len(spans) == 1, f"expected exactly one claim({label!r}), found {len(spans)}"
    _, start, end = spans[0]
    body = src[start:end]
    assert body.count("multiline=True") == 1, f"{label}: expected one multiline=True in the call"
    return src[:start] + body.replace("multiline=True", "multiline=False") + src[end:]


def write_mutant(src: str, path: pathlib.Path, label: str, kind: str) -> None:
    """Write a mutant to %TEMP% and prove it is the mutation it claims to be.

    The count assertion is the part worth keeping: a `drop` that silently matched the wrong span
    would produce a script with one fewer claim that is not the one under test, and the plant
    would then go green for a reason that has nothing to do with the form being measured.
    """
    out = mutant_drop_claim(src, label) if kind == "drop" else mutant_drop_multiline(src, label)
    compile(out, str(path), "exec")  # a mutant that does not parse proves nothing
    want = src.count("\nclaim(") - (1 if kind == "drop" else 0)
    if out.count("\nclaim(") != want:
        raise AssertionError(f"mutant {path.name}: {out.count(chr(10) + 'claim(')} claim() "
                             f"registrations, wanted {want}")
    labels_after = [s[0] for s in claim_spans(out)]
    if kind == "drop" and label in labels_after:
        raise AssertionError(f"mutant {path.name}: claim({label!r}) survived a drop mutation")
    if kind == "multiline":
        after = [s for s in claim_spans(out) if s[0] == label]
        if len(after) != 1 or "multiline=False" not in out[after[0][1]:after[0][2]]:
            raise AssertionError(f"mutant {path.name}: {label} did not lose multiline=True")
    path.write_text(out, encoding="utf-8")


# ------------------------------------------------------------------------------ the plant tree
class Sandbox:
    """One %TEMP% wiki root per case, holding a copy of a real wiki file plus the plant.

    Per case rather than shared, so a plant can never be seen by a check that is not about it: a
    shared tree would let a leftover sentence from case 3 explain case 4's red.
    """

    def __init__(self, root: pathlib.Path, base_rel: str, base_text: str):
        self.root = root
        self.base_rel = base_rel
        self.base_text = base_text

    def case(self, cid: str, plant_lines: list[str] | None = None,
             verbatim: list[str] | None = None) -> pathlib.Path:
        d = self.root / f"case-{cid}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        if verbatim is not None:
            (d / "selftest.md").write_text("\n".join(verbatim) + "\n", encoding="utf-8")
        else:
            # The copy keeps its REAL path inside the wiki, so the violation line the transcript
            # quotes names the same file a reader would open.
            target = d / self.base_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(self.base_text.rstrip("\n") + "\n\n" + "\n".join(plant_lines) + "\n",
                              encoding="utf-8")
        return d



def show_plant(tag: str, lines: list[str], tail: str = "") -> None:
    """Print a plant one source line per transcript line.

    Half these cases are WRAPPED plants, and joining their two lines into one printed line would
    show the reader the one sentence shape the case exists to prove the checker cannot see.
    """
    pad = " " * 19
    print(f"        {tag:<9}: {lines[0]}")
    for extra in lines[1:]:
        print(f"{pad}{extra}")
    if tail:
        print(f"{pad}{tail}")


class Report:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.red = 0
        self.green = 0

    def check(self, ok: bool, cid: str, what: str, detail: str = "") -> bool:
        if not ok:
            self.fails.append(f"{cid}: {what}" + (f" -- {detail}" if detail else ""))
        return ok


def quote(text: str, indent: str = "        ") -> None:
    for line in text.rstrip("\n").splitlines():
        print(indent + line)


def drift_note(out: str, live: dict) -> str:
    """Name the OTHER reason a control can fail: the validator moved while this run was going.

    The two validator counts are read by RUNNING registry-verify.py, once per checker invocation,
    and this harness makes ~90 invocations. If somebody edits the validator while it runs, the
    baseline numbers are stale and every control that uses them fails for a reason that has nothing
    to do with the form. Saying so is the difference between a re-run and a wild goose chase.
    """
    now = summary(out)
    moved = [f"{k} {live.get(k)}->{now[k]}" for k in ("rules", "cases")
             if k in now and live.get(k) is not None and now[k] != live[k]]
    if not moved:
        return ""
    return ("        NOTE: the validator moved DURING this run (" + ", ".join(moved)
            + "). Re-run before believing this failure; it is not evidence about the form.")


# --------------------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=str(DEFAULT_REPO))
    ap.add_argument("--wiki", default=str(DEFAULT_WIKI))
    ap.add_argument("--keep", action="store_true",
                    help="leave the TEMP tree behind for inspection")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    wiki = pathlib.Path(args.wiki)
    checker = repo / "scripts" / "doc-facts.py"
    manifest = repo / "manifests" / "capabilities.json"
    for p in (checker, manifest, wiki):
        if not p.exists():
            print(f"verify-doc-facts-selftest: cannot run, missing {p}", file=sys.stderr)
            return 2

    src = checker.read_text(encoding="utf-8")
    declared = [lbl for lbl, _, _ in claim_spans(src)]
    rep = Report()
    started = time.monotonic()

    print("=" * 100)
    print("doc-facts self-test -- every declared claim form must fire on a plant")
    print("=" * 100)

    # ---------------------------------------------------------------- 0. the harness's own numbers
    code, out, err = run_doc_facts(checker, repo, wiki)
    if code == 2:
        # Exit 2 is doc-facts.py refusing to run or refusing to derive an expected value. That IS
        # fatal here: this harness takes its correct numbers from that summary, and a summary it
        # cannot read means it would be planting numbers it guessed.
        print(f"verify-doc-facts-selftest: the checker cannot run or cannot derive its expected "
              f"values (exit 2), so its numbers cannot be used as this harness's controls.")
        quote(out + err)
        return 2
    live_stale = CLAIM_LINE.findall(out)
    base_total = checked_count(out)
    base_scanned = scanned_count(out)
    printed = summary(out)
    derived = derive(manifest)
    # The two validator quantities are NOT in the registry -- doc-facts.py reads them by RUNNING
    # registry-verify.py, and writing either down here as a constant is the defect this repository
    # keeps paying for: a pinned number never moves, so the control stays green forever. The
    # harness therefore takes them from what the checker prints and says so on the transcript.
    live = dict(derived)
    for key in ("rules", "cases"):
        if key not in printed:
            print(f"verify-doc-facts-selftest: the checker did not print its {key} count",
                  file=sys.stderr)
            return 2
        live[key] = printed[key]

    print("\n-- 0. the harness's own numbers, derived independently and cross-checked ------------")
    print(f"   checker on the live wiki: exit {code}, {base_scanned} files scanned, "
          f"{base_total} live numeric claims checked")
    if live_stale:
        # A stale wiki is a NORMAL event here -- a rule was added, the prose was not updated -- and
        # it is not this harness's business to fix. What matters is that the self-test keeps
        # running: its base copy of wiki/INDEX.md then carries whatever INDEX.md itself says, and
        # every assertion below states its expectation as an INCREMENT over the base's own output.
        print(f"   LIVE WIKI IS RED: {len(live_stale)} stale claim(s) in the wiki right now. They "
              f"are NOT this harness's failure; the base copy's own output is subtracted below.")
        for got, lbl, want in live_stale:
            print(f"      live wiki: claims {got} {lbl}; registry says {want}")
    shared = sorted(set(derived) & set(printed))
    for key in shared:
        agree = derived[key] == printed[key]
        print(f"   {key:<18} harness {derived[key]:>3}   checker {printed[key]:>3}   "
              f"{'agree' if agree else 'DISAGREE'}")
        if not agree:
            rep.fails.append(f"0: {key}: harness derives {derived[key]}, checker prints "
                             f"{printed[key]}")
    for key in ("callable", "families"):
        print(f"   {key:<18} harness {derived[key]:>3}   (the checker does not print it; proved "
              f"by the cases that go red / stay green below)")
    for key in ("rules", "cases"):
        print(f"   {key:<18} checker {printed[key]:>3}   (not in the registry; read by running "
              f"registry-verify.py, taken from the checker's own summary)")

    # The families number is the one expectation the checker never prints, so a wrong derivation
    # would show up as a case that refuses to go red. Prove the derivation independently instead.
    fams = json.loads(manifest.read_text(encoding="utf-8"))["schema"]["evidence_families"]
    rep.check(len(fams) == live["families"], "0", "families derivation is the manifest's own length")

    # ------------------------------------------------------------- 1/2. plant + control per form
    print("\n-- 1/2. every declared form: a wrong number goes RED, the right number stays GREEN ---")
    base_rel = "wiki/INDEX.md"
    sandbox = Sandbox(pathlib.Path(tempfile.mkdtemp(prefix="doc-facts-selftest-")),
                      base_rel, (wiki / base_rel).read_text(encoding="utf-8"))

    # The base copy, unplanted, measured. Every assertion below is an INCREMENT over this output:
    # the number of claims checked, and the set of violations reported. That is what makes the
    # harness runnable while the live wiki is drifting -- the base copy carries whatever
    # wiki/INDEX.md itself says, and is subtracted rather than assumed away.
    base_dir = sandbox.case("base", plant_lines=["selftest base copy, no plant on this line."])
    bcode, bout, berr = run_doc_facts(checker, repo, base_dir)
    base_claims = checked_count(bout)
    base_stale = sorted(CLAIM_LINE.findall(bout))
    if not rep.check(base_claims is not None, "base",
                     f"the unplanted copy of {base_rel} could be checked",
                     f"exit {bcode}, checked {base_claims}"):
        quote(bout + berr)
        return 2
    print(f"   base: copy of {base_rel} alone -> exit {bcode}, {base_claims} live claims checked, "
          f"{len(base_stale)} stale claim(s) of its own"
          + ("" if bcode == 0 else "  (the live wiki is drifting; those are carried, not ignored)"))

    seen_labels = {c[1] for c in CASES}
    missing = sorted(set(declared) - seen_labels)
    extra = sorted(seen_labels - set(declared))
    if rep.check(not missing, "table", "every declared claim label has at least one plant",
                 f"no plant for {missing}"):
        print(f"   table: {len(declared)} claim labels in doc-facts.py, "
              f"{len(CASES)} plant forms, every label covered")
    if rep.check(not extra, "table", "no plant names a claim that does not exist", f"{extra}"):
        print(f"   table: every planted label exists in the script")
    unreferenced = [lbl for lbl in declared if lbl not in seen_labels]
    if unreferenced:
        print(f"   table: labels with NO plant: {unreferenced}")

    for cid, label, form, lines, key, also in CASES:
        right = live[key]
        wrong = right + 7
        plant_red = sandbox.case(cid, [ln.format(w=wrong) for ln in lines])
        plant_green = sandbox.case(cid + "g", [ln.format(w=right) for ln in lines])

        rcode, rout, rerr = run_doc_facts(checker, repo, plant_red)
        found = CLAIM_LINE.findall(rout)
        want_labels = [label, *also]
        planted = [(str(wrong), lbl, str(right)) for lbl in want_labels]
        # EXACT multiset equality, base claims included: nothing but the base copy and this plant
        # may be visible, and every label this plant should trip must be in it.
        rc_ok = (rcode == 1
                 and sorted(found) == sorted(base_stale + planted)
                 and checked_count(rout) == base_claims + len(planted))
        print(f"\n   [{'RED  ' if rc_ok else 'FAIL '}] {cid:<4} {label} / {form}")
        if rc_ok:
            rep.red += 1
            show_plant("plant", [ln.format(w=wrong) for ln in lines])
            # Only the planted verdict is quoted. The base copy's own stale claims, if the live wiki
            # is drifting, are counted in the exit line instead of reprinted under every case.
            for v in planted:
                quote(f"verdict  : claims {v[0]} {v[1]}; registry says {v[2]}")
            print(f"        exit {rcode}, {len(found)} violation(s) ({len(planted)} planted + "
                  f"{len(base_stale)} carried from the base copy), "
                  f"{checked_count(rout)} claims checked (base {base_claims} + {len(planted)})")
        else:
            show_plant("plant", [ln.format(w=wrong) for ln in lines])
            print(f"        exit {rcode} (want 1), violations {sorted(found)} "
                  f"(want {sorted(base_stale + planted)}), checked {checked_count(rout)} "
                  f"(want {base_claims + len(planted)})")
            note = drift_note(rout, live)
            if note:
                print(note)
            quote(rout + rerr)
        rep.check(rc_ok, cid, "wrong number goes red")

        gcode, gout, gerr = run_doc_facts(checker, repo, plant_green)
        # The control's verdict must be indistinguishable from the base copy's own: the right
        # number is INSPECTED (checked goes up) and adds no violation. That is the half that stops
        # a future edit from "fixing" a broken form by deleting the alternative that catches it.
        gfound = CLAIM_LINE.findall(gout)
        gc_ok = (gcode == bcode
                 and sorted(gfound) == base_stale
                 and checked_count(gout) == base_claims + len(planted))
        if gc_ok:
            rep.green += 1
            show_plant("control", [ln.format(w=right) for ln in lines],
                       f"-> exit {gcode} (same as the base copy), inspected and adding nothing")
        else:
            print(f"        FAIL     control did not stay green: exit {gcode} (want {bcode}), "
                  f"violations {sorted(gfound)} (want {base_stale}), "
                  f"checked {checked_count(gout)} (want {base_claims + len(planted)})")
            note = drift_note(gout, live)
            if note:
                print(note)
            quote(gout + gerr)
        rep.check(gc_ok, cid, "correct number stays green")

    # --------------------------------------------------------------------------- 3. quiet prose
    print("\n-- 3. prose that is not a registry claim must check ZERO claims -----------------------")
    qdir = sandbox.case("quiet", verbatim=QUIET_PROSE)
    qcode, qout, qerr = run_doc_facts(checker, repo, qdir)
    qchecked = checked_count(qout)
    quiet_ok = qcode == 0 and qchecked == 0
    print(f"   {'QUIET' if quiet_ok else 'FAIL '} {len(QUIET_PROSE)} sentences -> exit {qcode}, "
          f"{qchecked} live numeric claims checked (want 0)")
    for line in QUIET_PROSE:
        print(f"        {line}")
    if quiet_ok:
        quote(qout.strip())
    else:
        quote(qout + qerr)
    rep.check(quiet_ok, "quiet", "non-claim prose checks zero claims")

    # ----------------------------------------------------------------------- 4. mutation proof
    print("\n-- 4. mutation: with the mechanism removed, the plant stops being caught -------------")
    mutants_dir = sandbox.root / "mutants"
    mutants_dir.mkdir(exist_ok=True)
    mutations = [
        ("M1", "family count", "drop",
         "7a", "deleting claim(\"family count\") from a %TEMP% copy"),
        ("M2", "validator selftest case count", "drop",
         "12a", "deleting claim(\"validator selftest case count\") from a %TEMP% copy"),
        ("M3", "capability count", "multiline",
         "1c", "setting multiline=False on claim(\"capability count\") in a %TEMP% copy"),
    ]
    # The wrapped control for M3: the same form, NOT wrapped, must still be caught, or the mutant
    # would pass for the trivial reason that the whole claim is gone.
    m3_unwrapped = "1a"
    for mid, label, kind, cid, why in mutations:
        target = next(c for c in CASES if c[0] == cid)
        right = live[target[4]]
        wrong = right + 7
        mpath = mutants_dir / f"{mid}-doc-facts.py"
        try:
            write_mutant(src, mpath, label, kind)
        except AssertionError as e:
            # Reachable when the checker under test no longer declares this form at all -- which is
            # exactly what happens if this harness is pointed at a checker that has lost one. It
            # must be a reported FAILURE, not a traceback: a self-test that crashes on the defect
            # it exists to name is a self-test whose verdict nobody can read.
            print(f"\n   [FAIL] {mid}: {why} -- the checker under test does not declare "
                  f"claim({label!r}), so this mutation cannot be built: {e}")
            rep.fails.append(f"{mid}: cannot build the mutation -- {label!r} is not declared")
            continue
        pdir = sandbox.case(mid, [ln.format(w=wrong) for ln in target[3]])

        ccode, cout, cerr = run_doc_facts(checker, repo, pdir)
        mcode, mout, merr = run_doc_facts(mpath, repo, pdir)
        # The same mutant against the UNPLANTED base copy. Dropping a form also stops it inspecting
        # that form's real claims in wiki/INDEX.md -- two of them, for the case count -- so the
        # mutant's own baseline is measured rather than assumed to equal the intact one's.
        _ub, ubout, _ube = run_doc_facts(mpath, repo, base_dir)
        mutant_base = checked_count(ubout)
        mutant_stale = sorted(CLAIM_LINE.findall(ubout))
        m_planted = [(str(wrong), lbl, str(right)) for lbl in (target[1], *target[5])]
        survived = (mcode == bcode
                    and sorted(CLAIM_LINE.findall(mout)) == mutant_stale
                    and mutant_base is not None
                    and checked_count(mout) == mutant_base
                    and ccode == 1
                    and sorted(CLAIM_LINE.findall(cout)) == sorted(base_stale + m_planted))
        print(f"\n   [{'LOAD-BEARING' if survived else 'FAIL'}] {mid}: {why}")
        show_plant("planted", [ln.format(w=wrong) for ln in target[3]])
        # The plant's OWN verdict, or a plain statement that there was none. Quoting the first
        # violation instead would print a carried claim from the base copy and read like a pass.
        plant_hit = next((v for v in CLAIM_LINE.findall(cout) if v[0] == str(wrong)), None)
        quote("intact : exit " + str(ccode) + ", "
              + (f"claims {plant_hit[0]} {plant_hit[1]}; registry says {plant_hit[2]}"
                 if plant_hit else "NO VIOLATION FOR THE PLANT"))
        print(f"        mutant   : exit {mcode}, {checked_count(mout)} claims checked "
              f"(its own baseline on the unplanted copy is {mutant_base}, i.e. {base_claims - mutant_base} "
              f"of the base file's claims are this form and are no longer inspected)")
        if mid == "M3":
            ocid = m3_unwrapped
            oth = next(c for c in CASES if c[0] == ocid)
            odir = sandbox.case(mid + "b", [ln.format(w=wrong) for ln in oth[3]])
            ocode, oout, oerr = run_doc_facts(mpath, repo, odir)
            ok = (ocode == 1
                  and sorted(CLAIM_LINE.findall(oout))
                  == sorted(base_stale + [(str(wrong), oth[1], str(right))]))
            print(f"        control  : the SAME mutant still catches the unwrapped form ({ocid})"
                  f" -> exit {ocode}")
            survived = survived and ok
            if not ok:
                quote(oout + oerr)
        if not survived:
            quote(mout + merr)
        rep.check(survived, mid, f"mutant {mid} still catches a plant it should not")
    print(f"\n   repo script untouched: {checker} mtime {int(checker.stat().st_mtime)}, "
          f"sha {hashlib.sha256(checker.read_bytes()).hexdigest()[:12]}")

    # -------------------------------------------------------------------------- 5. coverage
    print("\n-- 5. measured coverage --------------------------------------------------------------")
    denominator = 0
    digit_files = 0
    for p in sorted(w for w in wiki.rglob("*.md") if not SKIP.intersection(w.relative_to(wiki).parts)):
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        digit_files += 1
        denominator += sum(1 for line in text.splitlines() if re.search(r"[0-9]", line))
    pct = 100.0 * base_total / denominator if denominator else 0.0
    print(f"   denominator: {denominator} live lines carrying a digit, over {digit_files} scanned "
          f"wiki files (same SKIP set as the checker)")
    print(f"   numerator  : {base_total} live numeric claims the checker inspected"
          + (f", of which {len(live_stale)} it reported stale"
             if live_stale else ", all of which it agreed with"))
    print(f"   COVERAGE   : {base_total}/{denominator} = {pct:.2f}% of live digit lines")
    verdict = ("CONFIRMS" if abs(pct - 0.85) < 0.05 else "CORRECTS")
    print(f"   header claim: doc-facts.py says \"16 live claims against 1893 live lines carrying a "
          f"digit -- 0.85% coverage\"")
    print(f"   -> {verdict}: 16/1893 = {100.0*16/1893:.2f}% is what the audit wrote, not today's "
          f"figure. Measured {base_total}/{denominator} = {pct:.2f}%.")
    print(f"   -> the arithmetic, stated so a reader can check it: the numerator moved 16 -> "
          f"{base_total} (+{base_total - 16}) and the denominator 1893 -> {denominator} "
          f"(+{denominator - 1893}). Both ends moved, so the ratio is not comparable to the "
          f"audit's without re-measuring, which is what this line does.")

    # Per-form live coverage, measured by the deletion trick: with one claim removed from a %TEMP%
    # copy, the checker's own "N live numeric claims checked" must fall by exactly that form's live
    # hits. Uses the checker's arithmetic, not a second copy of it.
    print("\n   per-form live hits (measured by deleting each form and diffing the checked count):")
    total_hits = 0
    zero_forms = []
    for label in declared:
        mpath = mutants_dir / f"cov-{re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')}.py"
        write_mutant(src, mpath, label, "drop")
        ccode, cout, cerr = run_doc_facts(mpath, repo, wiki)
        n = checked_count(cout)
        # `checked` is printed before the violation list, so a stale wiki does not stop this: the
        # number of claims the mutant INSPECTED is the measurement, not its verdict.
        hits = (base_total - n) if n is not None else None
        total_hits += hits or 0
        if hits == 0:
            zero_forms.append(label)
        flag = "" if hits is not None else f"  (exit {ccode})"
        print(f"      {label:<38} {hits if hits is not None else '?':>3} live claim(s) inspected{flag}")
    print(f"      {'SUM':<38} {total_hits:>3}   (must equal the live total {base_total})")
    rep.check(total_hits == base_total, "coverage",
              "per-form hits sum to the live total",
              f"{total_hits} != {base_total}")
    if zero_forms:
        print(f"   forms that inspect ZERO live claims today (declared, load-bearing, unexercised): "
              f"{zero_forms}")

    # ------------------------------------------------------------------------------- verdict
    print("\n" + "=" * 100)
    print(f"RESULT: {rep.red} red plants, {rep.green} green controls, "
          f"{len(mutations)} load-bearing mutations, coverage {base_total}/{denominator} = {pct:.2f}%")
    if rep.fails:
        print(f"FAILURES ({len(rep.fails)}):")
        for f in rep.fails:
            print("  - " + f)
    else:
        print("ALL CONTROLS HELD: every declared form fires on a plant, every correct figure stays "
              "green, prose stays quiet, and each mutation is caught.")
    print(f"elapsed {time.monotonic() - started:.1f}s, temp tree {sandbox.root}")
    print("=" * 100)
    if not args.keep:
        shutil.rmtree(sandbox.root, ignore_errors=True)
    return 1 if rep.fails else 0


if __name__ == "__main__":
    sys.exit(main())