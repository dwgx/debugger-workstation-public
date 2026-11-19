# OWNER: Round2Entry (entry slice, 2026-11-12) | package/tests/package_contract.py
"""Single production validator for the portable-core package (READ-ONLY, stdlib only).

Why one module. Until 2026-11-12 the package carried two parallel checkers:
`tests/verify.py` (9 honesty checks) and `tests/entry_checks.py` (5 install
assertions). They disagreed with each other, and both disagreed with the package:

  P2-01  `LICENSE` deleted -> BOTH printed PASS (nothing required it);
         `references/INSTALL.md` deleted -> legacy verifier PASS, entry checker
         died with a `FileNotFoundError` traceback instead of a diagnosis.
  P2-02  a legal 14th FIX-KB row -> entry checker FAIL (`rows == 13` hardcoded).
  P2-03  the same TSV content checked out LF -> entry checker FAIL (`crlf_ok`).
  P2-04  fixing the legacy verifier's INSTALL omission -> entry checker FAIL,
         because its E01 case demanded `old_verifier_exit == 0`.

`verify.py`, `scripts/verify.py`, `tests/verify.py` and `tests/entry_checks.py` all
call `validate()` here, so one contract decides and no second implementation can
drift green.

Contract
  * `REQUIRED_FILES` is the real dependency closure. A missing or empty item yields
    a structured `MISSING_REQUIRED=<path>` / `EMPTY_REQUIRED=<path>` failure and is
    reported as data — never as a traceback.
  * FIX-KB is judged by structure (9 columns, unique id, non-empty
    symptom/cause/fix/verify_command/source/date/trust/status), not by a fixed row
    total: a legal 14th row passes. Minimums stay 6 official / 4 community.
  * LF and CRLF are text-equivalent: text is newline-normalised before comparison.
    Raw evidence bytes keep their own rule — see `references/VERIFY.md`.
  * Version/hash pinning belongs to dependency and evidence identity. A past publish
    SHA is NOT a success token; its presence in an executable command is a failure.
"""
import pathlib
import re

CANONICAL = "portable-core"
AS_OF = "2026-11-12"
TAB = "\t"
MIN_OFFICIAL = 6
MIN_COMMUNITY = 4
TEXT_SUFFIXES = {".md", ".tsv", ".py"}
# Tokens are assembled at runtime so this validator never flags its own source.
PATH_TOKEN = "F:" + "/GENESIS-ARCHIVE"
SHA_TOKEN = "875" + "cd108"
LABELS = ("NOT a live command", "dated provenance", "archived")
CRED_RE = re.compile(
    r"(?i)(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"BEGIN [A-Z ]*PRIVATE KEY)")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# The closure the package promises: entry, references, licence, both validators and
# the frozen historical evidence the install contract needs. Order is stable and is
# the order failures are printed in.
REQUIRED_FILES = (
    "SKILL.md",
    "AGENTS.md",
    "SELF-DEPLOY.md",
    "SELF-REPAIR.md",
    "LICENSE",
    "README.md",
    "README.zh-CN.md",
    "verify.py",
    "scripts/verify.py",
    "tests/package_contract.py",
    "tests/verify.py",
    "tests/entry_checks.py",
    "references/INSTALL.md",
    "references/VERIFY.md",
    "references/FIX-KB.md",
    "references/PRIOR-WAVE.md",
    "references/frozen/legacy-verify-2026-11-11.py.txt",
    "FIX-KB/OFFICIAL.tsv",
    "FIX-KB/COMMUNITY.tsv",
)
# A licence text must not carry an OWNER banner: editing the grant is not a header fix.
NO_BANNER = ("LICENSE",)


def read_bytes(path):
    """Raw bytes, or None when the path is absent/unreadable. Never raises."""
    try:
        return pathlib.Path(path).read_bytes()
    except OSError:
        return None


def read_text(path):
    """Decoded, newline-normalised text, or None. LF and CRLF compare equal."""
    raw = read_bytes(path)
    if raw is None:
        return None
    return raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


def text_lines(path):
    text = read_text(path)
    return [] if text is None else text.split("\n")


def iter_text_files(pkg):
    pkg = pathlib.Path(pkg)
    if not pkg.is_dir():
        return
    for p in sorted(pkg.rglob("*")):
        if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES:
            yield p


def missing_required(pkg):
    pkg = pathlib.Path(pkg)
    return [r for r in REQUIRED_FILES if not (pkg / r).is_file()]


def empty_required(pkg):
    pkg = pathlib.Path(pkg)
    return [r for r in REQUIRED_FILES
            if (pkg / r).is_file() and not (read_text(pkg / r) or "").strip()]


def frontmatter(pkg):
    """Minimal frontmatter reader: name, license and the metadata string map."""
    text = read_text(pathlib.Path(pkg) / "SKILL.md") or ""
    name = re.search(r"(?m)^name:\s*(\S+)\s*$", text)
    lic = re.search(r"(?m)^license:\s*(\S[^\n]*?)\s*$", text)
    meta = dict(re.findall(r"(?m)^\s{2}([a-z][a-z-]*):\s*\"?([^\"\n]+?)\"?\s*$", text))
    return {"name": name.group(1) if name else "", "license": lic.group(1) if lic else "",
            "metadata": meta}


def name_problem(pkg):
    """Structured code for a bad install identity, or None when it is canonical."""
    pkg = pathlib.Path(pkg)
    name = frontmatter(pkg)["name"]
    if not name:
        return "NAME_MISSING"
    if len(name) > 64 or not NAME_RE.match(name):
        return "NAME_INVALID=%s" % name
    if name != pkg.name:
        return "NAME_DIR_MISMATCH=%s!=%s" % (name, pkg.name)
    if name != CANONICAL:
        return "NAME_NOT_CANONICAL=%s" % name
    return None


def code_lines(text):
    """Yield (lineno, line) for every line inside a ``` fence."""
    inside = False
    for i, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            yield i, line


def has_live_token(s):
    return PATH_TOKEN in s or SHA_TOKEN in s


def live_violations(pkg):
    """Executable contexts only: fenced commands, TSV verify_command cells, .py lines.
    A prose mention is allowed when the SAME line carries an explicit provenance label.
    """
    out = []
    for p in iter_text_files(pkg):
        rel = p.relative_to(pathlib.Path(pkg)).as_posix()
        text = read_text(p)
        if text is None:
            continue
        suffix = p.suffix.lower()
        if suffix == ".tsv":
            for i, line in enumerate(text.split("\n"), 1):
                if line.startswith("#") or line.startswith("id" + TAB):
                    continue
                cells = line.split(TAB)
                if len(cells) > 4 and has_live_token(cells[4]):
                    out.append({"rel": rel, "line": i, "kind": "verify_command",
                                "text": cells[4]})
            continue
        seen = set()
        for i, line in code_lines(text):
            if has_live_token(line):
                seen.add(i)
                out.append({"rel": rel, "line": i, "kind": "code-fence", "text": line})
        for i, line in enumerate(text.split("\n"), 1):
            if i in seen or not has_live_token(line):
                continue
            if suffix == ".py":
                out.append({"rel": rel, "line": i, "kind": "py-source", "text": line})
            elif not any(label in line for label in LABELS):
                out.append({"rel": rel, "line": i, "kind": "unlabelled-prose",
                            "text": line})
    return out


def install_doc_ok(pkg):
    text = read_text(pathlib.Path(pkg) / "references" / "INSTALL.md")
    return bool(text and text.strip()) and CANONICAL in text


def license_ok(pkg):
    """The licence file exists, has text and names a licence."""
    text = read_text(pathlib.Path(pkg) / "LICENSE")
    if not text or not text.strip():
        return False
    return any(tok in text for tok in ("MIT", "CC BY-SA", "Apache", "BSD"))


def row_problem(cells):
    """Production FIX-KB row validator. Returns a structured code, or None if legal."""
    if len(cells) != 9:
        return "COLS=%d" % len(cells)
    if not cells[0].strip():
        return "ID_EMPTY"
    for idx, label in ((1, "SYMPTOM"), (2, "CAUSE"), (3, "FIX"), (4, "VERIFY_COMMAND")):
        if not cells[idx].strip():
            return "%s_EMPTY" % label
    if not cells[5].strip():
        return "SOURCE_EMPTY"
    if not DATE_RE.match(cells[6].strip()):
        return "DATE_INVALID"
    if not cells[7].strip():
        return "TRUST_EMPTY"
    if not cells[8].strip():
        return "STATUS_EMPTY"
    return None


def fix_kb(pkg):
    """Structure, uniqueness and minimums — never a fixed total row count."""
    pkg = pathlib.Path(pkg)
    out = {"official": 0, "community": 0, "rows": 0, "cols_ok": True, "nonempty": 0,
           "eol": {}, "ids": [], "duplicate_ids": [], "row_failures": [],
           "minimums_ok": False}
    for key, name, minimum in (("official", "OFFICIAL.tsv", MIN_OFFICIAL),
                               ("community", "COMMUNITY.tsv", MIN_COMMUNITY)):
        raw = read_bytes(pkg / "FIX-KB" / name)
        if raw is None:
            out["row_failures"].append("FIX_KB_MISSING=FIX-KB/%s" % name)
            out["cols_ok"] = False
            continue
        crlf = raw.count(b"\r\n")
        out["eol"][name] = "CRLF" if crlf and crlf == raw.count(b"\n") else "LF"
        count = 0
        for lineno, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
            if not line.strip() or line.startswith("#") or line.startswith("id" + TAB):
                continue
            cells = line.split(TAB)
            count += 1
            if len(cells) != 9:
                out["cols_ok"] = False
            out["ids"].append(cells[0].strip())
            if len(cells) > 4 and cells[4].strip():
                out["nonempty"] += 1
            problem = row_problem(cells)
            if problem:
                out["row_failures"].append("%s:%d:%s" % (name, lineno, problem))
        out[key] = count
    out["rows"] = out["official"] + out["community"]
    seen, dups = set(), []
    for i in out["ids"]:
        if i in seen and i not in dups:
            dups.append(i)
        seen.add(i)
    out["duplicate_ids"] = dups
    out["minimums_ok"] = (out["official"] >= MIN_OFFICIAL
                          and out["community"] >= MIN_COMMUNITY)
    return out


def honesty(pkg):
    """The standing honesty invariants, read from the files that own them."""
    pkg = pathlib.Path(pkg)
    skill = read_text(pkg / "SKILL.md") or ""
    readme = read_text(pkg / "README.md") or ""
    readme_zh = read_text(pkg / "README.zh-CN.md") or ""
    blob = "\n".join(read_text(pkg / r) or "" for r in REQUIRED_FILES)
    headered = []
    for r in REQUIRED_FILES:
        if r in NO_BANNER:
            continue
        text = read_text(pkg / r) or ""
        headered.append(text.lstrip().startswith(("OWNER:", "# OWNER:", "---", "<!--"))
                        or "OWNER:" in text[:200])
    return {
        "red_gate": ("RELEASE_GATE=RED" in skill and "268" in skill and "0/27" in skill),
        "vrc_ban": ("vrc-dcc" in skill and "HARD BAN" in skill),
        "no_credentials": CRED_RE.search(blob) is None,
        "switcher": ("README.zh-CN.md" in readme and "README.md" in readme_zh),
        "owner_headed": all(headered),
    }


def validate(pkg):
    """One report for every caller. Never raises for a missing file: absence is data."""
    pkg = pathlib.Path(pkg)
    report = {"pkg": str(pkg), "as_of": AS_OF, "dir_name": pkg.name, "name": "",
              "required": list(REQUIRED_FILES), "present": [], "missing": [],
              "empty": [], "violations": [], "kb": {}, "honesty": {},
              "checks": {}, "failures": [], "all_ok": False}
    try:
        report["missing"] = missing_required(pkg)
        report["present"] = [r for r in REQUIRED_FILES if r not in report["missing"]]
        report["empty"] = empty_required(pkg)
        report["name"] = frontmatter(pkg)["name"]
        report["violations"] = live_violations(pkg)
        report["kb"] = fix_kb(pkg)
        report["honesty"] = honesty(pkg)
    except OSError as exc:                      # pragma: no cover - defensive only
        report["failures"].append("IO_ERROR=%s" % exc.__class__.__name__)

    kb = report["kb"] or {}
    h = report["honesty"] or {}
    report["checks"] = {
        "required_present": not report["missing"],
        "required_nonempty": not report["empty"],
        "name_match_dir": name_problem(pkg) is None,
        "install_doc_present": install_doc_ok(pkg),
        "license_declared": license_ok(pkg),
        "no_live_abs_path": not any(PATH_TOKEN in v["text"] for v in report["violations"]),
        "no_old_sha": not any(SHA_TOKEN in v["text"] for v in report["violations"]),
        "fix_kb_contract": (not kb.get("row_failures") and bool(kb.get("minimums_ok"))
                            and bool(kb.get("cols_ok"))
                            and kb.get("nonempty") == kb.get("rows")
                            and not kb.get("duplicate_ids")),
        "red_gate_caveat": bool(h.get("red_gate")),
        "vrc_ban": bool(h.get("vrc_ban")),
        "no_credentials": bool(h.get("no_credentials")),
        "switcher_reciprocal": bool(h.get("switcher")),
        "owner_headed": bool(h.get("owner_headed")),
    }
    failures = report["failures"]
    failures += ["MISSING_REQUIRED=%s" % r for r in report["missing"]]
    failures += ["EMPTY_REQUIRED=%s" % r for r in report["empty"]]
    problem = name_problem(pkg)
    if problem:
        failures.append(problem)
    for v in report["violations"]:
        if PATH_TOKEN in v["text"]:
            failures.append("LIVE_ABS_PATH=%s:%d" % (v["rel"], v["line"]))
        if SHA_TOKEN in v["text"]:
            failures.append("OLD_SHA=%s:%d" % (v["rel"], v["line"]))
    failures += list(kb.get("row_failures") or [])
    for dup in kb.get("duplicate_ids") or []:
        failures.append("DUPLICATE_ID=%s" % dup)
    if not kb.get("minimums_ok"):
        failures.append("FIX_KB_BELOW_MINIMUM=official:%d/%d,community:%d/%d"
                        % (kb.get("official", 0), MIN_OFFICIAL,
                           kb.get("community", 0), MIN_COMMUNITY))
    report["failures"] = failures
    report["all_ok"] = all(report["checks"].values()) and not failures
    return report


def gate_accepts(report):
    """Acceptance predicate shared by every caller: green AND the licence shipped."""
    return (bool(report.get("all_ok")) and not report.get("missing")
            and "LICENSE" in report.get("present", []))


def main(argv=None):
    """`python tests/package_contract.py [pkg]` — diagnostic dump, exit 0/1."""
    import sys
    pkg = pathlib.Path((argv or sys.argv[1:] or ["."])[0]).resolve()
    rep = validate(pkg)
    print("pkg=%s as_of=%s" % (rep["pkg"], rep["as_of"]))
    print("required_files=%d/%d missing=%d empty=%d"
          % (len(rep["present"]), len(rep["required"]), len(rep["missing"]),
             len(rep["empty"])))
    for line in rep["failures"]:
        print("failure=%s" % line)
    failed = [k for k, v in rep["checks"].items() if not v]
    print("checks_run=%d checks_failed=%d" % (len(rep["checks"]), len(failed)))
    print("VERDICT=%s" % ("PASS" if gate_accepts(rep) else "FAIL"))
    return 0 if gate_accepts(rep) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
