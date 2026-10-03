#!/usr/bin/env python3
"""Report what a fresh clone of this station is missing, without running one expensive instrument.

WHY THIS EXISTS. `scripts/assert-probes.py` now classifies a sweep failure as PREREQ when the
probe had nothing to read, which is the DETECTION half of a known clone defect. This is the
REPORTING half, and it is a different file on purpose: assert-probes.py runs instruments (it
takes minutes and a Ghidra JVM); this runs `os.path.exists` and `shutil.which`, so a clone can
be told what it lacks in under a second, before anybody spends a machine-hour discovering it.

Three of the six ways a clone silently diverges from the station it claims to be are still open
(the other three -- absolute paths, hardcoded tool paths, empty-scan-pass -- are fixed):

  R3  `crackme-corpus/out/` is gitignored and nothing in `scripts/` builds it. A clone has an
      empty corpus, and 11 of the 21 evidence-bound proofs read a binary out of it.
  R5  Some tools live outside the repo, and at least one is absent from `manifests/tools.json`,
      so a clone cannot know it must install it.
  R6  The wiki publishes %TEMP% recipes as if they were reproduction steps.

What it checks, all of it static:

  1. CORPUS     does `crackme-corpus/out/` exist, how many entries are in it, which capabilities
                name a path inside it, and does each named artefact exist. Exits NON-ZERO when
                the corpus is empty/missing AND at least one capability needs it, because that
                clone cannot run its own proofs. It then prints the one command that would
                populate it, located by reading the repo -- or states plainly that no such
                command exists today, rather than inventing one.
  2. TOOLS      every binary a capability's probe or its `requires.tools[].probe` invokes: is it
                on PATH, or is it at its declared location? And which of them are NOT declared in
                `manifests/tools.json` (R5: a clone has no way to know it must install them).
  3. WIKI       read-only scan of the wiki tree for a %TEMP% path inside a line that reads like a
                reproduction step (R6). Reports file:line. It NEVER edits the wiki.

    python scripts/verify-clone-freshness.py            # the station
    python scripts/verify-clone-freshness.py --repo D:/tmp/clone
    python scripts/verify-clone-freshness.py --strict    # missing tools / wiki recipes also fail

EXIT CODES. 0 nothing fatal. 1 the corpus gate fired (or, under --strict, any finding). 2 this
script's own fault -- the repo or a manifest could not be read.

WHAT IT DOES NOT DO. It does not build anything, install anything, run a probe, decompile a
binary, or write a single byte outside its own stdout. The wiki section is a reader. A %TEMP%
recipe in the wiki is a defect in the wiki, and a script that fixes it would be a second writer
in a tree whose other writers are mid-edit.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import sys
from pathlib import Path

EXIT_OK, EXIT_GATE, EXIT_OWN_FAULT = 0, 1, 2

# ---------------------------------------------------------------------------
# The arsenal wiki lives OUTSIDE this repository (<project>/<private-tree>/wiki), so a clone has no
# wiki/ directory at all and "walk ./wiki" would silently scan nothing. The candidate list is
# explicit rather than clever, and --wiki-root / DEBUGGER_WIKI_ROOT overrides it.
# ---------------------------------------------------------------------------
EXTERNAL_WIKI_CANDIDATES = ("<project>/<private-tree>/wiki",)

CORPUS_REL = Path("crackme-corpus") / "out"
CORPUS_REF_RE = re.compile(r"crackme[-/\\]corpus[\\/]out(?![A-Za-z0-9_])(?:[\\/][^\s'\"`|;&)]*)?", re.I)
TEST_PATH_RE = re.compile(r"Test-Path\s+['\"]([^'\"]+)['\"]")
AMP_QUOTE_RE = re.compile(r"&(?:\s+[^\s'\"`]+)*\s+['\"]([^'\"]+)['\"]")
# `$py='.\path\python.exe'; ... ; & $py ...` -- the assignment form names a path the call
# operator never repeats, so it has to be read or dynamic.win.frida.intercept looks tool-less.
ASSIGN_QUOTE_RE = re.compile(r"\$\w+\s*=\s*['\"]([^'\"]+)['\"]")
PS_BUILTINS = {
    "test-path", "&", "new-item", "copy-item", "remove-item", "out-null", "join-path",
    "set-location", "write-error", "write-host", "convertto-json", "select-object",
    "cd", "chdir", "start-process", "echo", "set", "if", "for", "foreach",
}
# A repo-relative script a probe command hands control to, e.g. `powershell -File scripts\ghidra-failopen-regress.ps1`.
SCRIPT_REF_RE = re.compile(
    r"['\"]?((?:\.\.?[\\/])?[A-Za-z0-9_.\-]+(?:[\\/][A-Za-z0-9_.\-*]+)+"
    r"\.(?:ps1|py|mjs|js|bat|cmd))['\"]?", re.I)
ENV_VAR_RE = re.compile(r"\$(?:env:)?(?P<v>[A-Za-z_][A-Za-z0-9_]*)|%(?P<v2>[A-Za-z_][A-Za-z0-9_]*)%")

# A %TEMP% reference anywhere: R6 is about the path, whatever spelling carries it.
TEMP_MARKER_RE = re.compile(r"%TEMP%|%TMP%|\$env:TEMP|\$[A-Za-z_]*TEMP\b|AppData[\\/]+Local[\\/]+Temp|(?<![\w.])/tmp/", re.I)
# ... and the shape that turns that reference into a recipe the reader is told to run.
RECIPE_HEAD_RE = re.compile(
    r"^\s*(?:#+\s*|\d+[.)]\s*|[-*+]\s*)?(?:\$\w+\s*=\s*)?(?:&\s+|call\s+|cmd\s+/c\s+|sudo\s+)?"
    r"(?:python\d*|py\b|node\b|npm\b|pwsh\b|powershell\b|bash\b|sh\b|cd\b|mkdir\b|md\b|copy-item\b|new-item\b|"
    r"remove-item\b|del\b|rm\b|curl\b|wget\b|head\b|tail\b|javac\b|java\b|dotnet\b|adb\b|frida\b|openssh\b|"
    r"scp\b|robocopy\b|xcopy\b|setx\b|reg\b|mount\b|copy\b|cp\b|mv\b|tar\b|git\b|export\b|import\b)\b",
    re.I,
)
# A line that says out loud that it is not the runnable recipe any more. Reported, not hidden.
RETIRED_MARKER_RE = re.compile(r"\[(DEAD|HISTORICAL|REPLACED BY|NON-RUNNABLE|RETRACTED|ARCHIVED|OBSOLETE)[^\]]*\]", re.I)


def env_expand(text: str) -> str:
    """Expand $env:X, $X and %X% the way cmd/PowerShell would, so a declared path resolves."""
    def sub(m: re.Match) -> str:
        name = m.group("v") or m.group("v2")
        return os.environ.get(name.upper(), m.group(0))
    prev = None
    out = text
    # %VAR% must not eat the text around it; loop because a value may itself contain one.
    for _ in range(4):
        prev = out
        out = ENV_VAR_RE.sub(sub, out)
        if out == prev:
            break
    return out


def is_abs(p: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", p)) or p.startswith(("/", "\\"))


def inside_repo(p: Path, repo: Path) -> bool:
    try:
        p.resolve().relative_to(repo.resolve())
        return True
    except (ValueError, OSError):
        return False


def rel(p: Path, root: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


class Report:
    """Collects findings. FAIL is the gate; WARN is a report; INFO is a measured fact."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, check: str, status: str, detail: str, evidence: str = "") -> None:
        self.rows.append((check, status, detail, evidence))

    def fails(self) -> list[tuple[str, str, str, str]]:
        return [r for r in self.rows if r[1] == "FAIL"]

    def warns(self) -> list[tuple[str, str, str, str]]:
        return [r for r in self.rows if r[1] == "WARN"]


def head(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def line(*parts: str) -> None:
    print("  " + "  ".join(str(p) for p in parts))


def cap_table(doc: dict) -> list[dict]:
    return [c for c in doc.get("capabilities", []) if isinstance(c, dict)]


# ---------------------------------------------------------------------------
# 1. CORPUS  (R3)
# ---------------------------------------------------------------------------

def corpus_refs(caps: list[dict], repo: Path) -> list[tuple[str, str, str]]:
    """(capability id, where it was named, repo-relative path) for every corpus path.

    Two hops, because the second one is exactly the miss a string search makes:
    `native.ghidra.decompile` names no corpus path at all -- its probe runs
    `scripts/ghidra-failopen-regress.ps1`, and THAT file names the binary (README.md:134-137).
    A capability that already names the corpus directly is not followed again, so this counts
    CAPABILITIES, not occurrences of the string.
    """
    found: list[tuple[str, str, str]] = []
    deferred: list[tuple[str, str, str]] = []
    for c in caps:
        cid = c.get("id", "?")
        probe = c.get("probe") or {}
        sources: list[tuple[str, str]] = [
            (f"probe.{k}", probe[k]) for k in ("command", "prepare") if isinstance(probe.get(k), str)
        ]
        sources += [(f"requires.tools[{t.get('name', '?')}].probe", t["probe"])
                    for t in (c.get("requires") or {}).get("tools", [])
                    if isinstance(t.get("probe"), str)]
        direct = False
        for where, text in sources:
            for m in CORPUS_REF_RE.finditer(text):
                found.append((cid, where, m.group(0).replace("\\", "/")))
                direct = True
            if not direct:
                deferred += [(cid, where, m.group(1).replace("\\", "/")) for m in SCRIPT_REF_RE.finditer(text)]
    seen_caps = {cid for cid, _w, _p in found}
    for cid, where, sref in deferred:
        if cid in seen_caps:
            continue
        spath = repo / sref
        try:
            if not spath.is_file() or spath.stat().st_size > 400_000:
                continue
            body = spath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, ln in enumerate(body.splitlines(), 1):
            m = CORPUS_REF_RE.search(ln)
            if m:
                found.append((cid, f"{where} -> {sref}:{i}", m.group(0).replace("\\", "/")))
                break
        seen_caps.add(cid)
    seen, uniq = set(), []
    for cid, where, p in found:
        key = (cid, where, p)
        if key not in seen:
            seen.add(key)
            uniq.append(key)
    return uniq


def count_entries(d: Path) -> tuple[int, int]:
    """(files, directories) under d, one walk. 5000+ files is the normal station number."""
    files = dirs = 0
    for _root, dirnames, filenames in os.walk(d):
        dirs += len(dirnames)
        files += len(filenames)
    return files, dirs


def find_build_command(repo: Path) -> tuple[str, list[str]]:
    """Locate, by READING the repo, the command that would populate crackme-corpus/out/.

    Returns (remedy, evidence lines). An empty remedy means no such command exists today --
    which is a finding, not something to paper over with an invented step.
    """
    evidence: list[str] = []
    runner = repo / "crackme-corpus" / "tools" / "loop.py"
    readme = repo / "crackme-corpus" / "README.md"

    documented = ""
    if readme.is_file():
        for i, ln in enumerate(readme.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = ln.strip()
            if re.match(r"^python\s+tools[\\/]loop\.py", s):
                documented = s
                evidence.append(f"crackme-corpus/README.md:{i}  {s!r}")
                break
    # The top-level README is where a fresh clone is actually pointed at this. Quote it rather
    # than paraphrase it: the question "what does the bootstrap slice say today" is answered by
    # the file, not by a summary of the file.
    root_readme = repo / "README.md"
    if root_readme.is_file():
        for i, ln in enumerate(root_readme.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = ln.strip()
            if re.match(r"^(cd\s+crackme-corpus|python\s+tools[\\/]loop\.py)", s):
                evidence.append(f"README.md:{i}  {s!r}")

    dispatcher = None
    dispatcher_cd = False
    for ps1 in sorted((repo / "scripts").glob("*corpus*.ps1")):
        text = ps1.read_text(encoding="utf-8", errors="replace")
        dispatcher = ps1
        dispatcher_cd = bool(re.search(r"Set-Location|Push-Location|^\s*cd\s", text, re.M))
        evidence.append(f"{rel(ps1, repo)}  exists; changes working directory: {dispatcher_cd}")
        break

    if not runner.is_file():
        return "", evidence + ["crackme-corpus/tools/loop.py: NOT PRESENT"]

    if documented:
        return "cd crackme-corpus ; python tools\\loop.py", evidence

    if dispatcher is not None:
        # The dispatcher runs the same runner but resolves -OutDir against the CURRENT directory,
        # so it is only correct when the caller is already inside crackme-corpus/.
        if dispatcher_cd:
            return f'powershell -NoProfile -ExecutionPolicy Bypass -File "{rel(dispatcher, repo)}"', evidence
        return "cd crackme-corpus ; python tools\\loop.py", evidence

    return "cd crackme-corpus ; python tools\\loop.py", evidence

def sweep_skip_ids(repo: Path) -> set[str]:
    """Ids `scripts/assert-probes.py` never runs, read out of that file rather than copied here.

    A second copy of that list is a list that drifts, and the difference matters here: three of
    the capabilities that name a corpus path are on the sweep's SKIP list, so counting them
    alongside the ones the sweep actually runs would overstate what an empty corpus breaks.
    Parsed, not imported -- importing would execute the sibling module.
    """
    src = repo / "scripts" / "assert-probes.py"
    try:
        tree = ast.parse(src.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "SKIP" for t in node.targets):
            try:
                return set(ast.literal_eval(node.value))
            except (ValueError, TypeError):
                return set()
    return set()



def check_corpus(repo: Path, caps: list[dict], rep: Report) -> None:
    head("1. CORPUS   crackme-corpus/out/   (R3)")
    out = repo / CORPUS_REL
    refs = corpus_refs(caps, repo)
    cap_ids = sorted({cid for cid, _w, _p in refs})

    if not out.is_dir():
        state, files, dirs = "MISSING", 0, 0
    else:
        files, dirs = count_entries(out)
        state = "EMPTY" if files == 0 else "present"

    skip = sweep_skip_ids(repo)
    checked = [c for c in cap_ids if c not in skip]
    skipped = [c for c in cap_ids if c in skip]
    n_checked_total = len(caps) - len(skip)

    line(f"directory : {rel(out, repo)}  [{state}]")
    line(f"entries   : {files} files, {dirs} directories")
    line(f"needed by : {len(cap_ids)} capabilities name a path inside it")
    line(f"            {len(checked)} of those are CHECKED by scripts/assert-probes.py "
         f"(out of {n_checked_total} checked); {len(skipped)} are on its SKIP list")
    if checked:
        line(f"  checked -> {', '.join(checked)}")
    if skipped:
        line(f"  skipped -> {', '.join(skipped)}")
    for cid, where, p in refs:
        mark = "  " if cid in skip else "* "
        line(f"        {mark}{cid}  {where}  {p}")
    line("        (* = a capability the evidence sweep actually runs)")

    # Each named artefact individually: "corpus is not empty" and "the binary the proof reads
    # exists" are different claims, and only the first is answered by a count.
    missing_art = []
    for _cid, _where, p in refs:
        target = repo / p.replace("/", os.sep)
        if any(ch in p for ch in "*?"):
            if not list((repo / "crackme-corpus" / "out").glob(Path(p).name)):
                missing_art.append(p)
        elif not target.exists():
            missing_art.append(p)
    missing_art = sorted(set(missing_art))

    needed = len(cap_ids)
    if state == "present" and not missing_art:
        rep.add("corpus", "OK", f"{files} files present; every {len(refs)} path named by the registry exists")
    elif needed == 0:
        rep.add("corpus", "OK", f"corpus is {state} but no capability names a path inside it")
    else:
        rep.add("corpus", "FAIL",
                f"corpus {state} and {needed} capabilities read it; {len(missing_art)} named "
                f"artefact(s) absent -> this clone cannot run its own proofs")
        for p in missing_art[:20]:
            line(f"MISSING   {p}")
        if len(missing_art) > 20:
            line(f"... and {len(missing_art) - 20} more")

    remedy, evidence = find_build_command(repo)
    if remedy:
        line("")
        line(f"REMEDY    : {remedy}      (run from the repo root)")
        for e in evidence:
            line(f"            {e}")
        line("NOTE      : this command is NOT run by any script in scripts/; a clone must be told "
             "to run it by hand.")
    else:
        line("")
        line("REMEDY    : NO SUCH COMMAND EXISTS TODAY. Nothing in this repository builds "
             "crackme-corpus/out/.")

    if out.is_dir() and files == 0 and needed:
        rep.add("corpus-gate", "FAIL", "out/ exists but is empty while capabilities depend on it")
    elif not out.is_dir() and needed:
        rep.add("corpus-gate", "FAIL", f"{rel(out, repo)} does not exist while {needed} capabilities depend on it")


# ---------------------------------------------------------------------------
# 2. TOOLS  (R5)
# ---------------------------------------------------------------------------

def probe_targets(text: str) -> list[str]:
    """Every filesystem path or bare command name a PowerShell-ish probe string invokes."""
    out: list[str] = (list(TEST_PATH_RE.findall(text)) + list(AMP_QUOTE_RE.findall(text))
                      + list(ASSIGN_QUOTE_RE.findall(text)))
    head_tok = text.strip().split(None, 1)[0] if text.strip() else ""
    if head_tok and head_tok.lower() not in PS_BUILTINS and not head_tok.startswith(("{", "&", "see")):
        out.append(head_tok)
    return [t.strip().rstrip(";").strip() for t in out]


def classify(token: str) -> tuple[str, str] | None:
    """('path', p) for anything with a separator or a drive; ('cmd', name) for a bare name."""
    t = env_expand(re.sub(r"^\$\w+\s*=\s*", "", token)).strip().strip("'\"")
    if not t or t.lower() in PS_BUILTINS:
        return None
    if re.match(r"^[A-Za-z]:[\\/]", t) or t.startswith(("/", "\\")) or t.startswith(("./", "../", ".\\", "..\\")):
        return ("path", t)
    if "\\" in t or "/" in t:
        return ("path", t)
    return ("cmd", t)


def install_roots(repo: Path, tools_doc: dict) -> list[Path]:
    """Roots a relative tool path may legitimately hang off: the repo, then each tool's declared
    dir, then that dir's install root (Ghidra names `Ghidra/Features/...`, which is relative to
    `Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC`, NOT to the repo)."""
    roots = [repo]
    for entries in (tools_doc.get("tools") or {}).values():
        for t in entries or []:
            if not isinstance(t, dict) or not t.get("dir"):
                continue
            d = repo / str(t["dir"]).replace("/", os.sep)
            if d not in roots:
                roots.append(d)
            entry = str(t.get("entry", "")).replace("\\", "/").split("/")[0]
            if entry:
                r = d / entry
                if r not in roots:
                    roots.append(r)
    return roots


def resolve(kind: str, val: str, repo: Path, roots: list[Path]) -> Path | None:
    if kind == "cmd":
        hit = shutil.which(val)
        return Path(hit) if hit else None
    p = Path(val)
    if p.is_absolute():
        return p
    for root in roots:
        cand = root / p
        if cand.exists():
            return cand
    return (repo / p).resolve()


# Interpreters and shells. A probe that calls `python` or `node` is not asking a clone to install a
# tool; flagging them would bury the finding that matters (a real instrument nobody declared).
RUNTIME_CMDS = {"python", "python3", "py", "node", "npm", "java", "javac", "dotnet",
                "powershell", "pwsh", "cmd", "bash", "sh", "wsl", "git", "make", "cmake"}


def norm_path(p: str) -> str:
    return env_expand(str(p)).replace("/", "\\").rstrip("\\").lower()


def declared_index(tools_doc: dict) -> tuple[set[str], list[str]]:
    """(name tokens, declared dir prefixes). A declared dir is the tool's OWN location: `ops`
    declares SkillSpector by giving the full path of its .exe, which is why matching on names
    alone would call a declared tool undeclared."""
    names: set[str] = set()
    dirs: list[str] = []
    for entries in (tools_doc.get("tools") or {}).values():
        for t in entries or []:
            if not isinstance(t, dict):
                continue
            if t.get("name"):
                names.add(str(t["name"]).lower())
            for key in ("entry", "dir"):
                v = t.get(key)
                if not v:
                    continue
                leaf = str(v).rstrip("/\\").replace("\\", "/").split("/")[-1]
                names.add(leaf.lower())
                names.add(Path(leaf).stem.lower())
                if key == "dir":
                    dirs.append(norm_path(v))
    return names, dirs


def is_declared(kind: str, val: str, resolved: Path | None, names: set[str], dirs: list[str]) -> bool:
    if kind == "cmd":
        return val.lower() in names
    n = norm_path(str(resolved) if resolved else val)
    return any(n == d or n.startswith(d + "\\") for d in dirs)


def check_tools(repo: Path, caps: list[dict], tools_doc: dict, rep: Report) -> None:
    head("2. TOOLS    binaries a probe invokes   (R5)")
    wanted: dict[tuple[str, str], dict] = {}

    for c in caps:
        cid = c.get("id", "?")
        sources: list[tuple[str, str]] = []
        for t in (c.get("requires") or {}).get("tools", []):
            if isinstance(t.get("probe"), str):
                sources.append((f"requires.tools[{t.get('name', '?')}].probe", t["probe"]))
        probe = c.get("probe") or {}
        for key in ("command", "prepare"):
            if isinstance(probe.get(key), str):
                sources.append((f"probe.{key}", probe[key]))
        for where, text in sources:
            for tok in probe_targets(text):
                cl = classify(tok)
                if not cl:
                    continue
                key = cl
                rec = wanted.setdefault(key, {"by": [], "where": set()})
                rec["by"].append(cid)
                rec["where"].add(where)

    declared_names, declared_dirs = declared_index(tools_doc)
    roots = install_roots(repo, tools_doc)
    missing, undeclared, foreign = [], [], []
    for (kind, val), rec in sorted(wanted.items()):
        hit = resolve(kind, val, repo, roots)
        present = bool(hit and hit.exists())
        who = ",".join(sorted(set(rec["by"])))
        if not present:
            missing.append((kind, val, who, sorted(rec["where"])))
        # R5 is about DECLARATION, not presence: a tool installed here and named in no manifest is
        # exactly what a clone cannot act on, and it is invisible if you only inspect what is
        # missing on THIS box. Two filters keep the finding legible -- interpreters are not
        # tools, and a repo-relative path is a file the clone already has (or visibly lacks).
        external = (kind == "cmd" and val.lower() not in RUNTIME_CMDS) or (
            kind == "path" and is_abs(env_expand(val)))
        if external and not is_declared(kind, val, hit if present else None, declared_names, declared_dirs):
            undeclared.append((val, who, present))
        # A probe path that is absolute, resolves on this box, and lands outside the repo AND
        # outside every declared tool dir is reading somebody ELSE's tree. In a clone that is the
        # difference between a proof and a lie, so it is named rather than counted as present.
        if kind == "path" and present and not inside_repo(hit, repo) \
                and not is_declared(kind, val, hit, declared_names, declared_dirs):
            foreign.append((val, who, hit))
        line(f"{'OK  ' if present else 'MISS'} {kind:4} {val}"
             + (f"  ->  {hit}" if present else "")
             + f"   [{who}]")

    line("")
    line(f"{len(wanted)} distinct targets, {len(missing)} absent.")
    for kind, val, who, where in missing:
        rep.add("tool", "WARN", f"not present: {val} (PATH={kind})  needed by {who}")
    if undeclared:
        line("")
        line(f"UNDECLARED IN manifests/tools.json ({len(undeclared)}) -- invoked by a probe, named "
             "in no manifest, so a clone has no way to learn it must install them:")
        for val, who, present in undeclared:
            where_now = "present HERE, unknown to a clone" if present else "absent here AND undeclared"
            line(f"  {val}   needed by {who}   [{where_now}]")
            rep.add("tool-undeclared", "WARN",
                    f"{val} is invoked by a probe but is absent from manifests/tools.json "
                    f"({'present on this station' if present else 'absent on this station too'})")
    if foreign:
        line("")
        line(f"HARDCODED PATH OUTSIDE THIS CLONE ({len(foreign)}) -- the probe resolves and the "
             "target EXISTS, so it reports success while reading somebody else's tree:")
        for val, who, hit in foreign:
            line(f"  {val}")
            line(f"      -> {hit}   [{who}]")
            rep.add("tool-foreign", "WARN",
                    f"{val} resolves to {hit}, outside this clone -- the probe reads a foreign tree")

    # The declared side: every entry with a dir+entry that is supposed to be on disk.
    head("2b. TOOLS   manifests/tools.json declared locations")
    ok = absent = 0
    absent_rows = []
    for cat, entries in (tools_doc.get("tools") or {}).items():
        for t in entries or []:
            if not isinstance(t, dict) or not t.get("dir") or not t.get("entry"):
                continue
            p = repo / str(t["dir"]).replace("/", os.sep) / str(t["entry"]).replace("/", os.sep)
            if p.exists():
                ok += 1
            else:
                absent += 1
                absent_rows.append((cat, t.get("name"), f"{t['dir']}/{t['entry']}"))
    line(f"declared with dir+entry: {ok} present, {absent} absent")
    for cat, name, where in absent_rows[:20]:
        line(f"  ABSENT  {cat}/{name}: {where}")
        rep.add("tool-declared", "WARN", f"{cat}/{name} declared at {where} but absent")
    if len(absent_rows) > 20:
        line(f"  ... and {len(absent_rows) - 20} more")


# ---------------------------------------------------------------------------
# 3. WIKI  (R6)  -- read-only, never writes.
# ---------------------------------------------------------------------------

def wiki_roots(repo: Path, explicit: list[str]) -> list[Path]:
    roots: list[Path] = []
    for r in explicit:
        p = Path(env_expand(r))
        if p.is_dir():
            roots.append(p)
        else:
            print(f"  --wiki-root {r}: not a directory, ignored")
    if roots:
        return roots
    env = os.environ.get("DEBUGGER_WIKI_ROOT")
    if env and Path(env).is_dir():
        roots.append(Path(env))
    for cand in (repo / "wiki", repo.parent / "wiki", *(Path(c) for c in EXTERNAL_WIKI_CANDIDATES)):
        if cand.is_dir() and cand not in roots:
            roots.append(cand)
    return roots


def check_wiki(repo: Path, explicit: list[str], rep: Report) -> None:
    head("3. WIKI     %TEMP% in a reproduction step   (R6, READ-ONLY)")
    roots = wiki_roots(repo, explicit)
    if not roots:
        rep.add("wiki", "WARN", "no wiki tree found; the R6 scan did NOT run")
        line("no wiki tree found (looked at <repo>/wiki, <repo>/../wiki and "
             f"{', '.join(EXTERNAL_WIKI_CANDIDATES)}).")
        line("The R6 scan did NOT run. Pass --wiki-root PATH or set DEBUGGER_WIKI_ROOT.")
        return

    total_lines = 0
    recipes, prose = [], []
    for root in roots:
        for p in sorted(root.rglob("*.md")):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                line(f"UNREADABLE {p}: {e}")
                continue
            total_lines += 1
            in_fence = False
            for i, ln in enumerate(text.splitlines(), 1):
                s = ln.strip()
                if s.startswith("```"):
                    in_fence = not in_fence
                if not TEMP_MARKER_RE.search(ln):
                    continue
                fenced = in_fence or s.startswith("```")
                recipe = fenced or bool(RECIPE_HEAD_RE.match(ln))
                row = (str(p), i, s[:120], bool(RETIRED_MARKER_RE.search(ln)))
                (recipes if recipe else prose).append(row)

    line(f"roots    : {', '.join(str(r) for r in roots)}")
    line(f"scanned  : {total_lines} markdown file(s); {len(recipes)} %TEMP% line(s) shaped like a "
         f"reproduction step, {len(prose)} prose mention(s)")
    if not recipes:
        rep.add("wiki", "OK", f"no %TEMP% reproduction step in {total_lines} wiki file(s)")
    for path, i, s, retired in recipes:
        tag = "  [self-declared dead/historical]" if retired else ""
        line(f"{rel(Path(path), Path(path).anchor and Path(path).parent) or path}:{i}{tag}")
        line(f"    {s}")
        rep.add("wiki", "WARN",
                f"{Path(path).name}:{i} publishes a %TEMP% path as a reproduction step"
                + (" (already marked dead/historical)" if retired else ""))
    line("")
    line(f"context: {len(prose)} further %TEMP% mention(s) are prose (provenance, stop-lines, "
         "fixture notes), not steps. Listed, not counted against the wiki.")


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Report what a fresh clone is missing (static checks only).")
    ap.add_argument("--repo", default=None, help="repo root to inspect (default: this script's parent parent)")
    ap.add_argument("--wiki-root", action="append", default=[], help="wiki tree to scan; repeatable")
    ap.add_argument("--strict", action="store_true", help="a missing tool or a wiki recipe also fails")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parent.parent
    if not repo.is_dir():
        print(f"verify-clone-freshness: repo not found: {repo}", file=sys.stderr)
        return EXIT_OWN_FAULT

    reg = repo / "manifests" / "capabilities.json"
    tl = repo / "manifests" / "tools.json"
    for m in (reg, tl):
        if not m.is_file():
            print(f"verify-clone-freshness: missing manifest: {rel(m, repo)}", file=sys.stderr)
            return EXIT_OWN_FAULT
    try:
        caps = cap_table(json.loads(reg.read_text(encoding="utf-8")))
        tools_doc = json.loads(tl.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"verify-clone-freshness: manifest is not valid JSON: {e}", file=sys.stderr)
        return EXIT_OWN_FAULT

    print("verify-clone-freshness")
    print(f"  repo : {repo}")
    print(f"  python {sys.version.split()[0]}  static checks only -- no probe is executed")

    rep = Report()
    check_corpus(repo, caps, rep)
    check_tools(repo, caps, tools_doc, rep)
    check_wiki(repo, args.wiki_root, rep)

    head("VERDICT")
    fails, warns = rep.fails(), rep.warns()
    for chk, status, detail, _ev in fails:
        print(f"  FAIL {chk}: {detail}")
    for chk, status, detail, _ev in warns:
        print(f"  WARN {chk}: {detail}")

    fatal = bool(fails)
    if args.strict and warns:
        fatal = True

    if fatal and not fails:
        print("  FAIL --strict: warnings promoted to failures")
    print(f"\n  findings: {len(fails)} FAIL, {len(warns)} WARN -> exit "
          f"{EXIT_GATE if fatal else EXIT_OK}")
    if fatal:
        print("  This clone/station cannot be trusted to run its own proofs until the FAILs above "
              "are cleared.")
    return EXIT_GATE if fatal else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())