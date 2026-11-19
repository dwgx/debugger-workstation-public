# OWNER: Round2Entry (entry slice, 2026-11-12) | package/tests/verify.py
"""ONE ## Verify for the portable skill package. READ-ONLY; run from ROOT.

Every check below is derived from `package_contract.validate()` — the same
validator `verify.py`, `scripts/verify.py` and `tests/entry_checks.py` call, so
there is one contract and no second implementation that can drift green.

What changed on 2026-11-12 (round-2 P2-01/P2-03): the required-file closure now
includes `LICENSE` and the reference files, so deleting either is a structured
FAIL instead of a silent PASS; FIX-KB is judged by row structure, unique ids and
minimums (6 official / 4 community), not by a hardcoded 13; LF and CRLF are
text-equivalent. The negative control now feeds a bad row through the production
row validator instead of re-checking a string it just built.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import package_contract as pc

ROOT = pathlib.Path(__file__).resolve().parent.parent
AS_OF = pc.AS_OF


def main():
    rep = pc.validate(ROOT)
    kb = rep["kb"]
    h = rep["honesty"]
    checks = {
        "schema_files": len(rep["present"]) == len(rep["required"]) and not rep["empty"],
        "official_rows": kb["official"] >= pc.MIN_OFFICIAL,
        "community_rows": kb["community"] >= pc.MIN_COMMUNITY,
        "all_fixes_have_verify": kb["rows"] > 0 and kb["nonempty"] == kb["rows"],
        "red_gate_caveat": h["red_gate"],
        "vrc_ban": h["vrc_ban"],
        "no_credentials": h["no_credentials"],
        "switcher_reciprocal": h["switcher"],
        "owner_headed": h["owner_headed"],
    }
    # NEGATIVE CONTROL (in-memory): a FIX-KB row with an empty verify_command must be
    # rejected by the PRODUCTION row validator, and a legal row accepted. NO file write.
    evil = pc.TAB.join(["X9", "symptom", "cause", "fix", "", "source", "2026-11-11",
                        "trust", "open"])
    good = pc.TAB.join(["X10", "symptom", "cause", "fix", "run the check", "source",
                        "2026-11-11", "trust", "open"])
    neg_red = (pc.row_problem(evil.split(pc.TAB)) == "VERIFY_COMMAND_EMPTY"
               and pc.row_problem(good.split(pc.TAB)) is None)

    print("as_of=%s (denominator 9 checks + 1 negative control)" % AS_OF)
    print("schema_files=%d/%d missing=%d empty=%d"
          % (len(rep["present"]), len(rep["required"]), len(rep["missing"]),
             len(rep["empty"])))
    for line in rep["failures"]:
        print("  failure=%s" % line)
    print("fix_kb_rows official=%d/%d community=%d/%d total=%d"
          % (kb["official"], pc.MIN_OFFICIAL, kb["community"], pc.MIN_COMMUNITY,
             kb["rows"]))
    print("fix_kb_eol official=%s community=%s duplicate_ids=%d"
          % (kb["eol"].get("OFFICIAL.tsv", "?"), kb["eol"].get("COMMUNITY.tsv", "?"),
             len(kb["duplicate_ids"])))
    print("all_fixes_have_verify=YES=%s missing=%d"
          % (kb["nonempty"] == kb["rows"], kb["rows"] - kb["nonempty"]))
    print("red_gate_caveat=%s vrc_ban=%s no_credentials=%s switcher=%s owner=%s"
          % (h["red_gate"], h["vrc_ban"], h["no_credentials"], h["switcher"],
             h["owner_headed"]))
    print("negative_control: FIX-KB row with empty verify_command -> checker_RED=%s "
          "legal_row_accepted=%s | NO_FILE_WRITTEN"
          % ("YES" if pc.row_problem(evil.split(pc.TAB)) == "VERIFY_COMMAND_EMPTY" else "NO",
             "YES" if pc.row_problem(good.split(pc.TAB)) is None else "NO"))
    failed = [k for k, v in checks.items() if not v]
    structured = rep["failures"]
    print("checks_run=%d checks_failed=%d structured_failures=%d"
          % (len(checks), len(failed), len(structured)))
    if failed or structured:
        print("failed=" + ",".join(failed + structured))
    # The 9 named checks are the 2026-11-11 denominator; the validator's structured
    # failures (missing/empty required file, name identity, live path, stale SHA,
    # FIX-KB row) gate the verdict too, so no defect can hide behind a green count.
    verdict = "PASS" if not failed and not structured and neg_red else "FAIL"
    print("VERDICT=%s" % verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
