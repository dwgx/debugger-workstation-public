# OWNER: Round2Entry (entry slice, 2026-11-12) | package/tests/entry_checks.py
"""Install / entry contract for the portable-core package (READ-ONLY, stdlib only).

Every case runs on a TEMP COPY; the source package is never modified. Each case is
judged by the production gate (`verify.py` -> `tests/verify.py` ->
`tests/package_contract.py`), never by a second checker.

Round-2 rewrite (2026-11-12). The 2026-11-11 version encoded four defects as
invariants and the round-2 review reproduced all four:

  P2-01  `LICENSE` deleted -> this file printed PASS (nothing required LICENSE);
         `references/INSTALL.md` deleted -> FileNotFoundError traceback from
         `fix_kb_stats()` instead of a diagnosis.
  P2-02  a legal 14th FIX-KB row -> FAIL (`fix_kb_contract` demanded `rows == 13`).
  P2-03  the same TSV content as LF -> FAIL (`crlf_ok` treated EOL as content).
  P2-04  fixing the legacy verifier's INSTALL omission -> FAIL, because E01
         required `old_verifier_exit == 0`: the old bug was a product invariant.

The defects stay provable: the 2026-11-11 verifier bytes are frozen at
`references/frozen/legacy-verify-2026-11-11.py.txt` and are executed here on the
temp copies, so `old_verifier_exit=0` is a dated observation about the FROZEN
snapshot, not a requirement on the live gate.

Retained real counterexamples (still RED): missing `references/INSTALL.md`,
install dir name != frontmatter `name`, an injected live absolute research path,
an injected stale publish SHA. Added: missing `LICENSE`, legal 14th row, LF
checkout, legacy INSTALL fix.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import package_contract as pc

ROOT = pathlib.Path(__file__).resolve().parent.parent
CANONICAL = pc.CANONICAL
FROZEN_LEGACY = pathlib.Path("references") / "frozen" / "legacy-verify-2026-11-11.py.txt"
AS_OF = pc.AS_OF
TAB = pc.TAB
TAB_B = pc.TAB.encode()
TIMEOUT = 120


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                          timeout=TIMEOUT)


def live_gate(pkg):
    """Run the production gate (`verify.py`) inside a package copy."""
    r = run([sys.executable, "-X", "utf8", "-B", str(pkg / "verify.py")], pkg)
    return r


def gate_summary(r):
    out = r.stdout or ""
    missing = []
    for line in out.splitlines():
        if "MISSING_REQUIRED=" in line:
            item = line.split("MISSING_REQUIRED=")[1].strip()
            if item not in missing:
                missing.append(item)
    m = re.search(r"total=(\d+)", out)
    return {"exit": r.returncode,
            "verdict": "PASS" if "VERDICT=PASS" in out else "FAIL",
            "missing": missing,
            "traceback": "Traceback (most recent call last)" in (out + (r.stderr or "")),
            "rows": int(m.group(1)) if m else -1,
            "contract_failed": next((line.split("=", 1)[1].split(",")
                                     for line in out.splitlines()
                                     if line.startswith("contract_failed=")), [])}


def frozen_legacy_exit(pkg):
    """Exit code of the FROZEN 2026-11-11 verifier on this copy (dated evidence)."""
    src = pkg / FROZEN_LEGACY
    if not src.is_file():
        return None
    dst = pkg / "tests" / "_frozen_legacy_verify.py"
    shutil.copyfile(src, dst)
    return run([sys.executable, "-X", "utf8", "-B", str(dst)], pkg).returncode


def copy_case(fn, dirname=CANONICAL):
    with tempfile.TemporaryDirectory(prefix="pc_entry_") as td:
        dst = pathlib.Path(td) / dirname
        shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns("__pycache__"))
        return fn(dst)


def case_clean(dst):
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_install_missing(dst):
    (dst / "references" / "INSTALL.md").unlink()
    return {"gate": gate_summary(live_gate(dst)), "old_exit": frozen_legacy_exit(dst)}


def case_license_missing(dst):
    (dst / "LICENSE").unlink()
    return {"gate": gate_summary(live_gate(dst)), "old_exit": frozen_legacy_exit(dst)}


def case_license_invalid(dst):
    # A nonempty file is not sufficient: all entry points must use the same gate.
    (dst / "LICENSE").write_text("Fixture with no license declaration.\n", encoding="utf-8")
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_name_mismatch(dst):
    # `copy_case(..., "portable-core-renamed")` already broke the dir/name agreement.
    return {"gate": gate_summary(live_gate(dst)), "old_exit": frozen_legacy_exit(dst)}


def append_bytes(p, chunk):
    p.write_bytes(p.read_bytes() + chunk)


def case_live_path(dst):
    append_bytes(dst / "SELF-DEPLOY.md",
                 b"\n```sh\ncd " + pc.PATH_TOKEN.encode()
                 + b"/10-STORE && python -X utf8 x.py\n```\n")
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_old_sha(dst):
    append_bytes(dst / "SELF-DEPLOY.md",
                 b"\n```sh\npython -X utf8 x.py --expect " + pc.SHA_TOKEN.encode()
                 + b"\n```\n")
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_legal_row14(dst):
    f = dst / "FIX-KB" / "COMMUNITY.tsv"
    raw = f.read_bytes()
    eol = b"\r\n" if raw.count(b"\r\n") == raw.count(b"\n") else b"\n"
    if not raw.endswith(b"\n"):
        raw += eol
    # A fresh id, so the case is legal on a package that already carries row 14.
    used = set()
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("CM") and TAB in line:
            used.add(line.split(TAB)[0].strip())
    n = 1
    while "CM%d" % n in used:
        n += 1
    row = [("CM%d" % n).encode(), b"another observed test symptom",
           b"cause recorded in a prior wave",
           b"apply the recorded fix and re-run the package check",
           b"python -X utf8 verify.py", b"prior waves 2026-11-12", b"2026-11-12",
           b"community-unverified", b"open"]
    f.write_bytes(raw + TAB_B.join(row) + eol)
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_lf_checkout(dst):
    for f in sorted((dst / "FIX-KB").glob("*.tsv")):
        f.write_bytes(f.read_bytes().replace(b"\r\n", b"\n"))
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def case_legacy_install_fix(dst):
    """The exact semantic edit the 2026-11-11 legacy fix made: add
    `references/INSTALL.md` to the required set. With one validator this must be a
    no-op (deduped), not a regression."""
    append_bytes(dst / "tests" / "package_contract.py",
                 b'\nREQUIRED_FILES = tuple(dict.fromkeys(\n'
                 b'    REQUIRED_FILES + ("references/INSTALL.md",)))\n')
    return {"gate": gate_summary(live_gate(dst)), "old_exit": None}


def main():
    real = pc.validate(ROOT)
    kb = real["kb"]
    r = {
        "clean": copy_case(case_clean),
        "install_missing": copy_case(case_install_missing),
        "license_missing": copy_case(case_license_missing),
        "license_invalid": copy_case(case_license_invalid),
        "name_mismatch": copy_case(case_name_mismatch, "portable-core-renamed"),
        "live_path": copy_case(case_live_path),
        "old_sha": copy_case(case_old_sha),
        "row14": copy_case(case_legal_row14),
        "lf": copy_case(case_lf_checkout),
        "legacy_fix": copy_case(case_legacy_install_fix),
    }
    g = {k: v["gate"] for k, v in r.items()}

    pkg_checks = {
        "required_present": not real["missing"] and not real["empty"],
        "name_match_dir": real["checks"]["name_match_dir"],
        "install_doc_present": real["checks"]["install_doc_present"],
        "license_declared": real["checks"]["license_declared"],
        "no_live_abs_path": real["checks"]["no_live_abs_path"],
        "no_old_sha": real["checks"]["no_old_sha"],
        "fix_kb_contract": real["checks"]["fix_kb_contract"],
    }
    cases = {
        "LICENSE_invalid_contract_red":
            g["license_invalid"]["exit"] == 1
            and not g["license_invalid"]["traceback"]
            and "license_declared" in g["license_invalid"]["contract_failed"],
        "E01_install_missing_structured_red":
            g["install_missing"]["exit"] == 1
            and "references/INSTALL.md" in g["install_missing"]["missing"]
            and not g["install_missing"]["traceback"]
            and r["install_missing"]["old_exit"] == 0,
        "E02_name_mismatch_red":
            g["name_mismatch"]["exit"] == 1 and not g["name_mismatch"]["traceback"],
        "E03_live_path_red": g["live_path"]["exit"] == 1,
        "E03_old_sha_red": g["old_sha"]["exit"] == 1,
        "E04_clean_green": g["clean"]["exit"] == 0 and g["clean"]["verdict"] == "PASS",
        "L14_legal_row_green":
            g["row14"]["exit"] == 0 and g["row14"]["rows"] == kb["rows"] + 1,
        "LF_eol_green": g["lf"]["exit"] == 0,
        "LEGACY_install_fix_green": g["legacy_fix"]["exit"] == 0,
        "LICENSE_missing_structured_red":
            g["license_missing"]["exit"] == 1
            and "LICENSE" in g["license_missing"]["missing"]
            and not g["license_missing"]["traceback"]
            and r["license_missing"]["old_exit"] == 0,
    }

    # NEGATIVE CONTROL (in-memory, nothing written): a report that claims green while
    # LICENSE is absent must be rejected, and a legal 14th row must be accepted — a
    # hardcoded `rows == 13` gate is the defect, not the row.
    doctored = dict(real)
    doctored["present"] = [f for f in real["present"] if f != "LICENSE"]
    doctored["missing"] = []
    doctored["all_ok"] = True
    neg_license_green = not pc.gate_accepts(doctored)
    accept_rows = lambda n: n >= pc.MIN_OFFICIAL + pc.MIN_COMMUNITY
    hardcoded13 = lambda n: n == 13
    neg_row14_red = accept_rows(14) and not hardcoded13(14) and not accept_rows(5)
    neg_red = neg_license_green and neg_row14_red

    checks = dict(pkg_checks)
    checks.update(cases)

    print("as_of=%s (denominator 7 package assertions + 10 case results + 1 negative "
          "control)" % AS_OF)
    print("canonical_name=%s dir_name=%s name_match_dir=%s"
          % (real["name"] or "(none)", ROOT.name,
             "YES" if pkg_checks["name_match_dir"] else "NO"))
    print("required_files=%d/%d missing=%d empty=%d"
          % (len(real["present"]), len(real["required"]), len(real["missing"]),
             len(real["empty"])))
    for line in real["failures"]:
        print("  failure=%s" % line)
    print("install_doc_present=%s license_declared=%s"
          % ("YES" if pkg_checks["install_doc_present"] else "NO",
             "YES" if pkg_checks["license_declared"] else "NO"))
    print("no_live_abs_path=%s no_old_sha=%s violations=%d"
          % ("YES" if pkg_checks["no_live_abs_path"] else "NO",
             "YES" if pkg_checks["no_old_sha"] else "NO", len(real["violations"])))
    print("fix_kb_rows=%d columns_9=%s verify_command_nonempty=%d/%d eol=%s,%s "
          "duplicate_ids=%d"
          % (kb["rows"], "YES" if kb["cols_ok"] else "NO", kb["nonempty"], kb["rows"],
             kb["eol"].get("OFFICIAL.tsv", "?"), kb["eol"].get("COMMUNITY.tsv", "?"),
             len(kb["duplicate_ids"])))
    print("case_E01_install_missing: entry_checks=%s old_verifier_exit=%s "
          "fake_green_reproduced=%s missing_required=%s traceback=%s "
          "(old_verifier=frozen legacy snapshot)"
          % ("FAIL" if g["install_missing"]["exit"] else "PASS",
             r["install_missing"]["old_exit"],
             "YES" if r["install_missing"]["old_exit"] == 0 else "NO",
             ",".join(g["install_missing"]["missing"]) or "-",
             "YES" if g["install_missing"]["traceback"] else "NO"))
    print("case_E02_name_mismatch: entry_checks=%s old_verifier_exit=%s"
          % ("FAIL" if g["name_mismatch"]["exit"] else "PASS",
             r["name_mismatch"]["old_exit"]))
    print("case_E03_live_path: entry_checks=%s"
          % ("FAIL" if g["live_path"]["exit"] else "PASS"))
    print("case_E03_old_sha: entry_checks=%s"
          % ("FAIL" if g["old_sha"]["exit"] else "PASS"))
    print("case_E04_clean: entry_checks=%s"
          % ("PASS" if g["clean"]["exit"] == 0 else "FAIL"))
    print("case_L14_legal_row: gate_exit=%d rows=%d entry_checks=%s"
          % (g["row14"]["exit"], g["row14"]["rows"],
             "PASS" if g["row14"]["exit"] == 0 else "FAIL"))
    print("case_LF_eol: gate_exit=%d entry_checks=%s"
          % (g["lf"]["exit"], "PASS" if g["lf"]["exit"] == 0 else "FAIL"))
    print("case_LEGACY_install_fix: gate_exit=%d entry_checks=%s"
          % (g["legacy_fix"]["exit"], "PASS" if g["legacy_fix"]["exit"] == 0 else "FAIL"))
    print("case_LICENSE_missing: gate_exit=%d missing_required=%s structured=%s "
          "old_verifier_exit=%s"
          % (g["license_missing"]["exit"],
             ",".join(g["license_missing"]["missing"]) or "-",
             "YES" if not g["license_missing"]["traceback"] else "NO",
             r["license_missing"]["old_exit"]))
    print("case_LICENSE_invalid: gate_exit=%d contract_failed=%s"
          % (g["license_invalid"]["exit"], ",".join(g["license_invalid"]["contract_failed"])))
    print("negative_control: missing-LICENSE-as-green rejected=%s "
          "legal-row-14-accepted=%s hardcoded-13-accepts-14=%s | NO_FILE_WRITTEN"
          % ("YES" if neg_license_green else "NO",
             "YES" if accept_rows(14) else "NO",
             "YES" if hardcoded13(14) else "NO"))
    failed = [k for k, v in checks.items() if not v]
    print("checks_run=%d checks_failed=%d" % (len(checks), len(failed)))
    if failed:
        print("failed=" + ",".join(failed))
    verdict = "PASS" if not failed and neg_red else "FAIL"
    print("VERDICT=%s" % verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
