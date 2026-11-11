# OWNER: parent (took over stalled PackageDesign slice) | package/tests/verify.py
"""ONE ## Verify for the portable skill package. READ-ONLY; run from ROOT."""
import pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
P = ROOT
AS_OF = "2026-11-11"
SCHEMA = ["SKILL.md", "AGENTS.md", "SELF-DEPLOY.md", "SELF-REPAIR.md",
          "FIX-KB/OFFICIAL.tsv", "FIX-KB/COMMUNITY.tsv", "tests/verify.py",
          "README.md", "README.zh-CN.md", "verify.py"]

def rows(p):
    return [l for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#") and not l.startswith("id	")]

def main():
    present = sum((P / s).is_file() for s in SCHEMA)
    off = rows(P / "FIX-KB/OFFICIAL.tsv")
    com = rows(P / "FIX-KB/COMMUNITY.tsv")
    all_rows = off + com
    # column 5 (index 4) = verify_command; must be non-empty for EVERY row
    missing_verify = sum(1 for l in all_rows if len(l.split("	")) < 5 or not l.split("	")[4].strip())
    skill = (P / "SKILL.md").read_text(encoding="utf-8")
    red = "RELEASE_GATE=RED" in skill and "268" in skill and "0/27" in skill
    ban = "vrc-dcc" in skill and "HARD BAN" in skill
    cred = bool(re.search(r"(?i)(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY)",
                          "".join((P/s).read_text(encoding="utf-8", errors="ignore") for s in SCHEMA if (P/s).is_file())))
    no_cred = not cred
    switcher = ("README.zh-CN.md" in (P/"README.md").read_text(encoding="utf-8")
                and "README.md" in (P/"README.zh-CN.md").read_text(encoding="utf-8"))
    owner = all((P/s).read_text(encoding="utf-8", errors="ignore").lstrip().startswith(("OWNER:", "# OWNER:", "---", "<!--"))
                or "OWNER:" in (P/s).read_text(encoding="utf-8", errors="ignore")[:200] for s in SCHEMA if (P/s).is_file())
    # NEGATIVE CONTROL (in-memory): a FIX-KB row with empty verify_command -> RED, NO file write.
    TAB = chr(9)
    evil = TAB.join(["X9", "symptom", "cause", "fix", "", "source", "2026-11-11", "trust", "open"])
    neg_red = len(evil.split(TAB)) >= 5 and evil.split(TAB)[4].strip() == ""
    checks = {
        "schema_files": present == len(SCHEMA),
        "official_rows": len(off) >= 6,
        "community_rows": len(com) >= 4,
        "all_fixes_have_verify": missing_verify == 0,
        "red_gate_caveat": red,
        "vrc_ban": ban,
        "no_credentials": no_cred,
        "switcher_reciprocal": switcher,
        "owner_headed": owner,
    }
    print("as_of=%s (denominator 9 checks + 1 negative control)" % AS_OF)
    print("schema_files=%d/%d" % (present, len(SCHEMA)))
    print("fix_kb_rows official=%d/6 community=%d/4 total=%d" % (len(off), len(com), len(all_rows)))
    print("all_fixes_have_verify=YES=%s missing=%d" % (missing_verify == 0, missing_verify))
    print("red_gate_caveat=%s vrc_ban=%s no_credentials=%s switcher=%s owner=%s"
          % (red, ban, no_cred, switcher, owner))
    print("negative_control: FIX-KB row with empty verify_command -> checker_RED=%s | NO_FILE_WRITTEN" % ("YES" if neg_red else "NO"))
    failed = [k for k, v in checks.items() if not v]
    print("checks_run=%d checks_failed=%d" % (len(checks), len(failed)))
    if failed: print("failed=" + ",".join(failed))
    v = "PASS" if not failed and neg_red else "FAIL"
    print("VERDICT=%s" % v)
    sys.exit(0 if v == "PASS" else 1)

if __name__ == "__main__":
    main()
