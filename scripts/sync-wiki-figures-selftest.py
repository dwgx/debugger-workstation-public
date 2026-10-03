#!/usr/bin/env python
"""Prove that scripts/sync-wiki-figures.py can rewrite every claim doc-facts.py checks.

WHY THIS EXISTS. `doc-facts.py` is the gate: it fails when the wiki asserts a number the registry
no longer produces. `sync-wiki-figures.py` is the writer that answers it. Between them there was a
silent hole, and this file exists because the hole was invisible from both ends:

  * the writer's FIRST version carried its own nine regexes. Measured by
    `verify-doc-facts-selftest.py`, those nine sentence shapes covered only 2 of doc-facts.py's 12
    claim labels, and one of the nine was a DEAD SHAPE with zero live matches -- drift could return
    through it with the writer saying nothing.
  * the writer's SECOND version imports doc-facts.py and iterates `doc-facts.CLAIMS`, so it cannot
    hold a stale list. That fixed the dead shape and made the coverage structural.

Structural coverage is only worth something if it is TESTED, though: "the writer iterates the
checker's claims" is a claim, and the failure mode for a writer is the one nobody looks for -- it
reports a wiki with stale figures as CURRENT. So this harness plants a stale figure per claim
label, derived from `doc-facts.CLAIMS` at runtime, and requires the real `sync-wiki-figures.py` to
notice. A claim added to doc-facts.py without a working writer fails HERE rather than silently
later.

THREE PROPERTIES, in the order they matter:

  1. COVERAGE -- every label in `doc-facts.CLAIMS` has a plant, and every plant is caught. The
     label list is read from the checker at runtime, never written here, so adding a claim to
     doc-facts.py adds a case here automatically. A label with no plant defined is a FAILURE, not a
     skipped test.
  2. DEAD-SHAPE -- a writer whose rewriting has been removed (mutated away in a %TEMP% COPY) must
     make this harness go RED. Three mutations, all writer-side: `rewrite()` neutered, one label
     skipped, and the claim list emptied entirely.
  3. %TEMP% ONLY -- the writer is pointed at a copy of the wiki under %TEMP%, and the real wiki's
     hashes are compared before and after the whole run. Mutating the real wiki to test a writer is
     how a good edit gets reverted forty seconds later; this file refuses to be able to.

Each plant is checked three ways, because an exit code alone proves too little:
  * `--check` exits 1 (the gate form),
  * a real rewrite puts the EXPECTED number back, derived here from doc-facts.py's own function,
  * and with the CORRECT number planted, `--check` exits 0 (so a writer that cries wolf on a
    current wiki fails too).

Run:  python scripts/sync-wiki-figures-selftest.py [--repo DIR] [--wiki DIR] [--keep]
Exit: 0 every property held; 1 at least one did not; 2 the harness could not run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
DEFAULT_WIKI = pathlib.Path(r"<private-tree>\wiki")
PY = sys.executable

# The writer's own file list, mirrored here ONLY to decide which %TEMP% copies to make. Coverage is
# decided by doc-facts.CLAIMS, never by this tuple -- see property 1.
WRITER_FILES = ("INDEX.md", "CHARTER-ARSENAL.md", "methods/arsenal-inventory.md",
                "methods/arsenal-upgrade-plan.md")
# Every plant goes into this one file: it is on the writer's list, so detection does not depend on
# the shape's natural home, and no per-label file map can go stale as the wiki is edited.
PLANT_FILE = "INDEX.md"
MARK = "selftest plant:"

# (label -> the planted sentence, with the figure written @N@). One per claim label in
# doc-facts.CLAIMS. If a claim is added to the checker and has no entry here, property 1 fails and
# says which label is missing.
#
# @N@ and not `{n}` + str.format: the capability-count sentence contains literal braces -- it IS
# "`capabilities: N`" -- and escaping those inside a format string is exactly the kind of silent
# typo a self-test should not contain. Measured: it raised ValueError on the first run.
PLANTS: dict[str, str] = {
    "capability count": MARK + " `capabilities: @N@` in this station.",
    "observed count": MARK + " @N@ `observed` in this station.",
    "typed edge count": MARK + " @N@ typed edges in this station.",
    "callable count": MARK + " @N@ callable capabilities in this station.",
    "runnable negative controls": MARK + " @N@ runnable negative control in this station.",
    "declared plan controls": MARK + " @N@ declared PLANS in this station.",
    "family count": MARK + " **@N@ evidence families** in this schema.",
    "bound-to-retained-artifact count":
        MARK + " @N@ bound to a retained artifact in this station.",
    "unverified-evidence count": MARK + " @N@ still unverified in this station.",
    "runnable control commands": MARK + " @N@ runnable commands in this station.",
    "validator rule count": MARK + " @N@ numbered rule functions in the validator.",
    "validator selftest case count": MARK + " @N@ selftest cases in the validator.",
}

# The one sentence no claim covers. The writer still rewrites it, so it is tested -- but it is
# tested against the writer's OWN arithmetic, because nothing in the tree can referee it. Stated
# rather than hidden: see the doc-facts header's "NOT CHECKED, declared rather than half-handled".
UNCHECKED_SEGMENT = {
    "label": "(unchecked) RULES holds N entries",
    "plant": MARK + " RULES in `scripts/registry-verify.py` holds **@N@ entries, "
                    "@N@ of them numbered R1..R@N@**",
}


def with_figure(template: str, n: int) -> str:
    """Substitute the figure into a plant template. A literal token, never str.format."""
    return template.replace("@N@", str(n))


def load_doc_facts_as_the_writer_does(repo: pathlib.Path):
    """doc-facts.py loaded the way sync-wiki-figures.py loads it: module executed, state untouched.

    Kept separate on purpose. This harness sets `_REPO` so it can derive every expected value
    itself; the writer does not, and the difference is the whole story behind a false green. A
    claim whose fn returns None here is a claim the writer's `if expected is None: continue`
    skips without a word.
    """
    spec = importlib.util.spec_from_file_location("doc_facts_writer_path",
                                                  repo / "scripts" / "doc-facts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_doc_facts(repo: pathlib.Path):
    """doc-facts.py by path, with the one piece of state its validator claims need.

    `_validator_number` returns None unless `_REPO` is set -- doc-facts.py's own main() sets it.
    A caller that imports the module and calls a claim function without setting it gets None for
    the two validator claims and no error, which is the whole hazard this harness now measures.
    """
    spec = importlib.util.spec_from_file_location("doc_facts_selftest_probe", repo / "scripts" / "doc-facts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._REPO = repo
    return mod


class Report:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.caught = 0

    def check(self, ok: bool, cid: str, what: str, detail: str = "") -> bool:
        if not ok:
            self.fails.append(f"{cid}: {what}" + (f" -- {detail}" if detail else ""))
        return ok


def run(cmd: list[str], cwd: pathlib.Path | None = None, timeout: int = 300) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd and str(cwd))
    return p.returncode, p.stdout, p.stderr


def wiki_hashes(wiki: pathlib.Path) -> dict[str, str]:
    """sha256 of every markdown file in the REAL wiki, for the %TEMP%-only property."""
    return {str(p.relative_to(wiki)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(wiki.rglob("*.md"))}


class Skeleton:
    """A %TEMP% repo + wiki the writer can be pointed at without touching either real tree.

    `REPO` in the writer is derived from `__file__`, so a copy of the writer placed anywhere else
    resolves its registry to the wrong place -- measured: it raised FileNotFoundError and exited 1,
    which is indistinguishable from "found stale figures" if you only look at the exit code. So the
    copy lives in a repo skeleton that has manifests/ and scripts/ beside it, exactly like the real
    one, and the harness asserts the writer's WIKI constant points inside %TEMP% before every run.
    """

    def __init__(self, root: pathlib.Path, repo: pathlib.Path, wiki: pathlib.Path):
        self.root = root
        self.repo_src = repo
        self.wiki_src = wiki
        self.repo = root / "repo"
        self.wiki = root / "wiki"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "manifests").mkdir(parents=True)
        shutil.copy2(repo / "manifests" / "capabilities.json", self.repo / "manifests")
        for name in ("doc-facts.py", "registry-verify.py", "sync-wiki-figures.py"):
            shutil.copy2(repo / "scripts" / name, self.repo / "scripts" / name)
        self.repoint_wiki(self.repo / "scripts" / "sync-wiki-figures.py")
        for rel in WRITER_FILES:
            dst = self.wiki / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(wiki / rel, dst)

    def repoint_wiki(self, writer: pathlib.Path) -> None:
        """Point the writer's copy at this skeleton's wiki. The ONLY edit made to any script here."""
        src = writer.read_text(encoding="utf-8")
        m = re.search(r'^WIKI = Path\(r?"([^"]+)"\)\s*$', src, re.M)
        if not m:
            raise AssertionError(f"{writer.name}: no WIKI constant to repoint; the harness must be "
                                 f"updated rather than pointed at the real wiki by accident")
        writer.write_text(src[:m.start()] + f'WIKI = Path(r"{self.wiki}")' + src[m.end():],
                          encoding="utf-8")
        self.writer = writer

    def assert_wiki_is_temp(self) -> None:
        """Property 3, enforced before every single writer run, not just once at the end."""
        m = re.search(r'^WIKI = Path\(r?"([^"]+)"\)\s*$', self.writer.read_text(encoding="utf-8"), re.M)
        if not m or not pathlib.Path(m.group(1)).resolve().is_relative_to(pathlib.Path(tempfile.gettempdir()).resolve()):
            raise AssertionError(f"writer copy would read {m.group(1) if m else '?'}, which is NOT "
                                 f"under %TEMP%; refusing to run")

    def plant(self, line: str) -> pathlib.Path:
        target = self.wiki / PLANT_FILE
        target.write_text(target.read_text(encoding="utf-8").rstrip("\n") + "\n\n" + line + "\n",
                          encoding="utf-8")
        return target

    def mutate_writer(self, old: str, new: str, why: str) -> None:
        """Mutate the %TEMP% COPY of the writer. Never the repo's."""
        src = self.writer.read_text(encoding="utf-8")
        if src.count(old) != 1:
            raise AssertionError(f"mutation {why!r} expected exactly one {old!r} in the writer copy")
        self.writer.write_text(src.replace(old, new), encoding="utf-8")

    def check(self) -> tuple[int, str, str]:
        self.assert_wiki_is_temp()
        return run([PY, str(self.writer), "--check"])

    def rewrite(self) -> tuple[int, str, str]:
        self.assert_wiki_is_temp()
        return run([PY, str(self.writer)])


def planted_line(wiki: pathlib.Path) -> str:
    for line in (wiki / PLANT_FILE).read_text(encoding="utf-8").splitlines():
        if line.startswith(MARK):
            return line
    return ""


def show(tag: str, text: str, indent: str = "        ") -> None:
    for line in text.rstrip("\n").splitlines():
        print(f"{indent}{tag}: {line}" if line.strip() else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=str(DEFAULT_REPO))
    ap.add_argument("--wiki", default=str(DEFAULT_WIKI))
    ap.add_argument("--keep", action="store_true", help="leave the TEMP tree behind for inspection")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    wiki = pathlib.Path(args.wiki)
    for p in (repo / "scripts" / "sync-wiki-figures.py", repo / "scripts" / "doc-facts.py",
              repo / "manifests" / "capabilities.json", wiki):
        if not p.exists():
            print(f"sync-wiki-figures-selftest: cannot run, missing {p}", file=sys.stderr)
            return 2

    started = time.monotonic()
    rep = Report()
    print("=" * 100)
    print("sync-wiki-figures self-test -- every claim doc-facts checks must be rewritable")
    print("=" * 100)

    before = wiki_hashes(wiki)

    # ------------------------------------------------- expected values, from the checker's own fn
    df = load_doc_facts(repo)
    reg = json.loads((repo / "manifests" / "capabilities.json").read_text(encoding="utf-8"))
    labels = [lbl for lbl, _, _, _ in df.CLAIMS]
    expected: dict[str, int | None] = {}
    for lbl, _rx, fn, _ml in df.CLAIMS:
        try:
            v = fn(reg)
        except Exception as exc:                                  # noqa: BLE001
            print(f"sync-wiki-figures-selftest: cannot derive {lbl!r}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 2
        expected[lbl] = None if v is None else int(v)

    print(f"\n-- 0. what the writer has to cover: doc-facts.CLAIMS, read at runtime ---------------")
    print(f"   {len(labels)} claim labels: {labels}")
    print(f"   plants defined here: {len(PLANTS)}")
    # The writer derives expected values by calling the SAME fn. A label whose fn returns None is a
    # label the writer skips by construction -- `if expected is None: continue` -- so it is named
    # here rather than discovered as a mystery later.
    underivable = [lbl for lbl, v in expected.items() if v is None]
    if underivable:
        print(f"   UNDERIVABLE for a caller that imports doc-facts.py: {underivable}")
        print(f"      (fn(reg) returns None because doc-facts._REPO is unset in an imported module;"
              f" the writer's own loop skips these with `if expected is None: continue`)")

    writer_path = load_doc_facts_as_the_writer_does(repo)
    writer_blank = [lbl for lbl, _rx, fn, _ml in writer_path.CLAIMS if fn(reg) is None]
    if writer_blank:
        print(f"   THE WRITER CANNOT DERIVE: {writer_blank}")
        print(f"      Its `fn(reg)` returns None for these, and its loop then runs "
              f"`if expected is None: continue` --")
        print(f"      so these claims are skipped SILENTLY and their figures are never rewritten. "
              f"doc-facts._REPO is unset in a")
        print(f"      freshly exec'd module, and `_validator_number` returns None without it. This "
              f"harness sets it, which is why")
        print(f"      the cases below are measured as FALSE GREEN rather than as absent.")

    missing = [lbl for lbl in labels if lbl not in PLANTS]
    stale = [lbl for lbl in PLANTS if lbl not in labels]
    if not rep.check(not missing, "property-1",
                     "every doc-facts claim label has a plant in this harness",
                     f"no plant for {missing}"):
        print(f"   PROPERTY 1 FAILS: doc-facts.py declares {len(labels)} labels and this harness "
              f"has plants for {len(PLANTS)}. Missing: {missing}")
    else:
        print(f"   PROPERTY 1 HOLDS (so far): every declared label has a plant; adding a claim to "
              f"doc-facts.py adds a case here.")
    if rep.check(not stale, "property-1", "no plant names a claim that no longer exists", f"{stale}"):
        print(f"   and no plant names a claim that has been deleted from the checker: {stale or 'none'}")

    root = pathlib.Path(tempfile.mkdtemp(prefix="sync-figures-selftest-"))

    # ---------------------------------------------------------- baseline: is the %TEMP% copy green?
    base = Skeleton(root / "baseline", repo, wiki)
    bcode, bout, berr = base.check()
    baseline_ok = bcode == 0
    print(f"\n   baseline: unplanted copy of the {len(WRITER_FILES)} writer files -> "
          f"--check exit {bcode}")
    if not baseline_ok:
        print("   BASELINE IS NOT GREEN, so no case below can be attributed to its plant. This is a"
              "\n   drift in the real wiki, not a writer defect; fix the wiki and re-run.")
        show("baseline", bout + berr)
        return 1
    show("baseline", "\n".join(l for l in bout.splitlines() if "already current" in l or "->" in l))

    # ------------------------------------------------------------- property 1: a plant per label
    print("\n-- 1. PROPERTY 1: every claim label must be caught, then correctly rewritten ---------")
    for label in labels:
        want = expected[label]
        template = PLANTS.get(label)
        if template is None or want is None:
            verdict = "NO PLANT" if template is None else "UNDERIVABLE"
            print(f"\n   [FAIL ] {label:<34} {verdict}: the writer cannot be shown to handle this"
                  f" claim")
            rep.check(False, label, "writer coverage could not be established")
            continue
        stale_n = want + 7
        skel = Skeleton(root / re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-"), repo, wiki)
        skel.plant(with_figure(template, stale_n))

        ccode, cout, cerr = skel.check()
        rcode, rout, rerr = skel.rewrite()
        after = planted_line(skel.wiki)
        wrote = (str(want) in after) and (str(stale_n) not in after)
        named = label in rout
        caught_ok = ccode == 1 and rcode == 0 and wrote and named

        # The false-green test, stated as its own line because it is the failure that matters: a
        # writer that says "already current" about a wiki the checker calls stale.
        false_green = ccode == 0
        print(f"\n   [{'CAUGHT' if caught_ok else 'FAIL  '}] {label:<34} expected {want}, planted {stale_n}")
        print(f"        plant    : {with_figure(template, stale_n)}")
        print(f"        --check  : exit {ccode} (want 1)"
              + ("   <-- FALSE GREEN: the writer calls a wiki the checker calls stale CURRENT"
                 if false_green else ""))
        print(f"        rewrite  : exit {rcode}, plant line is now "
              f"{'correct' if wrote else 'WRONG'}"
              + (f" -> {after.strip()}" if after else ""))
        print(f"        attributed to {label!r} in the writer's output: {named}")
        if not caught_ok:
            show("writer said", cout + rout + cerr + rerr)
            # The checker is run with --repo pointing at the REAL station and --wiki at the %TEMP%
            # copy: it needs the real registry and the real validator (which needs evidence/ and a
            # git tree), and only the wiki is a copy. Measured: pointing --repo at the skeleton made
            # it exit 2 "REFUSING TO PASS" for want of a run_log, which reads like "nothing is
            # stale" and is the opposite meaning.
            doc = run([PY, str(repo / "scripts" / "doc-facts.py"), "--repo", str(repo),
                       "--wiki", str(skel.wiki)])
            meaning = {1: "  <-- the CHECKER calls it stale: this is a writer gap, not a bad fixture",
                       0: "  <-- the checker does not call it stale either: the FIXTURE matches nothing",
                       2: "  <-- the checker could not run; inconclusive"}[doc[0]]
            print(f"        doc-facts.py on the SAME wiki, real repo: exit {doc[0]}{meaning}")
            show("doc-facts", "\n".join(l for l in doc[1].splitlines() if "claims" in l))

        if caught_ok:
            rep.caught += 1
        else:
            rep.check(False, label, "stale plant not caught, or not rewritten correctly")

        # Control: the CORRECT number planted must leave the writer silent. Without this, a writer
        # that always exits 1 would pass every case above.
        skel2 = Skeleton(skel.root / "control", repo, wiki)
        skel2.plant(with_figure(template, want))
        gcode, gout, _gerr = skel2.check()
        control_ok = gcode == 0
        print(f"        control  : correct figure planted -> --check exit {gcode} (want 0)"
              + ("" if control_ok else "   <-- the writer cries wolf on a current wiki"))
        rep.check(control_ok, label, "correct figure leaves the writer silent")

    # --------------------------------------- the unreferenced sentence, tested against its own maths
    print("\n-- 1b. the one sentence no claim covers, tested against the writer's own arithmetic ---")
    seg = UNCHECKED_SEGMENT
    n_ent = rules_total(repo)
    skel = Skeleton(root / "unchecked-segment", repo, wiki)
    skel.plant(with_figure(seg["plant"], n_ent + 6))
    ccode, cout, _ = skel.check()
    rcode, rout, _ = skel.rewrite()
    after = planted_line(skel.wiki)
    wrote = f"holds **{n_ent} entries" in after
    seg_ok = ccode == 1 and rcode == 0 and wrote
    print(f"\n   [{'CAUGHT' if seg_ok else 'FAIL  '}] {seg['label']}")
    print(f"        planted  : {with_figure(seg['plant'], n_ent + 6)}")
    print(f"        --check  : exit {ccode} (want 1); rewrite exit {rcode}; "
          f"now reads {after.strip()[:90]}")
    print(f"        REFEE: none. No doc-facts claim matches this segment, so the writer's value for")
    print(f"        it is unfalsifiable from the tree. It is tested here only for 'the writer fires'.")
    rep.check(seg_ok, "unchecked-segment", "the unreferenced segment is rewritten")

    # ------------------------------------------------------------------ property 2: dead shape
    print("\n-- 2. PROPERTY 2: a writer that cannot write must make THIS harness go RED -----------")
    probes = [lbl for lbl in ("capability count", "typed edge count", "observed count")
              if lbl in PLANTS and expected.get(lbl) is not None]
    mutations = [
        ("M1", "rewrite() neutered -- no figure can ever be replaced",
         "        if gi is None or m.group(gi) == str(expected):",
         "        if True:  # MUTANT: never rewrite anything"),
        ("M2", "one claim label skipped -- the writer lost a claim",
         "        for label, pattern, fn, multiline in df.CLAIMS:",
         "        for label, pattern, fn, multiline in df.CLAIMS:\n"
         "            if label == 'typed edge count':\n"
         "                continue  # MUTANT: this claim is no longer written"),
        ("M3", "the claim list emptied -- the writer holds no patterns at all",
         "    df = load_doc_facts()",
         "    df = load_doc_facts()\n    df.CLAIMS = []  # MUTANT: the writer has no list"),
    ]
    for mid, why, old, new in mutations:
        skel = Skeleton(root / mid, repo, wiki)
        skel.mutate_writer(old, new, why)
        undetected = []
        for label in probes:
            want = expected[label]
            s = Skeleton(skel.root / f"probe-{label}", repo, wiki)
            # The mutation is copied in, then the copy is re-pointed at THIS probe's wiki: the
            # mutated file carries its own WIKI constant, so copying it verbatim made every probe
            # check the parent's empty tree and exit 0. Measured -- the harness's own false green.
            shutil.copy2(skel.writer, s.writer)
            s.repoint_wiki(s.writer)
            s.plant(with_figure(PLANTS[label], want + 7))
            pcode, _pout, _perr = s.check()
            if pcode == 0:
                undetected.append(label)
        went_red = bool(undetected)
        exact = (undetected == ["typed edge count"]) if mid == "M2" else len(undetected) == len(probes)
        print(f"\n   [{'GOES RED' if went_red and exact else 'FAIL    '}] {mid}: {why}")
        print(f"        plants the mutated writer no longer catches: {undetected or 'none'}"
              + (f" (expected {'all of them' if mid != 'M2' else 'exactly typed edge count'})"
                 if not exact else ""))
        rep.check(went_red and exact, mid,
                  "the dead-shape mutation was not detected by this harness",
                  f"undetected={undetected}")

    # ------------------------------------------------------------------ property 3: %TEMP% only
    print("\n-- 3. PROPERTY 3: the real wiki was never touched -----------------------------------")
    after_hashes = wiki_hashes(wiki)
    changed = sorted(k for k in set(before) | set(after_hashes)
                     if before.get(k) != after_hashes.get(k))
    ok3 = not changed
    print(f"   [{'UNTOUCHED' if ok3 else 'VIOLATED '}] {len(before)} real wiki files hashed before "
          f"and after: {'identical' if ok3 else 'CHANGED: ' + str(changed)}")
    print(f"   every writer run asserted its WIKI constant is under %TEMP% before executing")
    print(f"   temp tree: {root}")
    rep.check(ok3, "property-3", "the real wiki was modified", str(changed))

    print("\n" + "=" * 100)
    print(f"RESULT: {rep.caught}/{len(labels)} claim labels provably caught, corrected and "
          f"attributed; 3 dead-shape mutations; real wiki "
          f"{'untouched' if ok3 else 'VIOLATED'}")
    if rep.fails:
        print(f"FAILURES ({len(rep.fails)}):")
        for f in rep.fails:
            print("  - " + f)
    else:
        print("ALL PROPERTIES HELD.")
    print(f"elapsed {time.monotonic() - started:.1f}s")
    print("=" * 100)
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if rep.fails else 0


def rules_total(repo: pathlib.Path) -> int:
    """The writer's own source for `RULES` length, read the same way it reads it."""
    code, out, _ = run([PY, str(repo / "scripts" / "registry-verify.py"), "--count"], cwd=repo)
    m = re.search(r"(\d+) entries", out)
    if code != 0 or not m:
        raise AssertionError(f"cannot read the RULES entry count: exit {code}, {out!r}")
    return int(m.group(1))


if __name__ == "__main__":
    sys.exit(main())