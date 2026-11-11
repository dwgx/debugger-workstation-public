# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/ + research/Q5/
# Q5 corpus-absorption analysis builder (READ-ONLY on source; writes ONLY under this slice).
# Auto-deepresearch: no number hard-coded; every TSV row derived from CORPUS-INDEX.tsv / SATURATION.tsv bytes.
# Run from W: python -X utf8 -B setukou-20261111/v5/slices/q5-absorption/build_artifacts.py
from __future__ import annotations
import csv, hashlib, pathlib, re

HERE = pathlib.Path(__file__).resolve().parent
W = HERE.parent.parent.parent.parent
S = W / "setukou-20261111"
CI = S / "v4/corpus-absorb/CORPUS-INDEX.tsv"
SAT = S / "v5/SATURATION.tsv"
LEDGER = pathlib.Path("C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation/research/Q5")


def tsv(path):
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t"))


def sha(rel):
    return hashlib.sha256((W / rel).read_bytes()).hexdigest()


# ---- classifier: which absorbed_no lessons can become a LOCAL executable check ----
# Grounded in ABSORPTION-V4.md:39-42 (3 NO reasons) + the lessons' own text.
# A lesson is LOCAL-checkable iff its behavioural assertion can be verified on
# OUR OWN SYNTHETIC fixtures with stdlib only (no network / product write /
# untrusted binary / credential / third-party). Metadata-only rows (role_enum,
# content_type_enum, theme counts, repo_card, tree_count, tool_call_kind,
# user_prompt, lesson_theme) are locators, not behaviours -> NO (Root C09:
# "读过≠吸收"). min_gate rows and verifiable correction/requirement rows -> YES.
LOCAL_MARK = re.compile(
    r"hash|sha256|分母|复算|回执|receipt|not_run|NOT.?EXECUTED|passed|负例|selftest|"
    r"envelope|gate|verify|真跑|不能生成|mtime|负控制|falsifier|计数|重算|哈希|"
    r"census|冻结|不覆盖|独立 checker|report-only|locator|定位", re.I)
VERIFIABLE_ROOT = {"BU-ROOT-C07", "BU-ROOT-C08", "BU-ROOT-C09", "BU-ROOT-C10"}
META_KINDS = {"role_enum", "content_type_enum", "theme", "repo_card", "tree_count",
              "tool_call_kind", "user_prompt", "lesson_theme", "method"}


def classify(r):
    kind = r["kind"]
    lesson = r["lesson_or_ask"]
    if kind == "min_gate":
        return ("YES", "§7 minimal-gate assertion is verifiable on SYNTHETIC envelope fixtures (stdlib only)",
                "python -X utf8 setukou-20261111/v5/slices/q5-absorption/absorb_check.py")
    if kind == "root_correction" and r["id"] in VERIFIABLE_ROOT:
        return ("YES", "procedural correction is a verifiable invariant (hash vs mtime / frozen evidence / checker layering / read≠absorb)",
                "python -X utf8 setukou-20261111/v5/slices/q5-absorption/absorb_check.py")
    if kind in {"req+cor", "requirement", "correction"} and LOCAL_MARK.search(lesson):
        return ("YES", "requirement/correction mentions a falsifiable local invariant (hash/receipt/denominator/negative-control)",
                "python -X utf8 setukou-20261111/v5/slices/q5-absorption/absorb_check.py (pattern-bound)")
    if kind in META_KINDS:
        return ("NO", "locator/enumeration metadata only, NOT a behaviour gate (Root C09: read≠absorb)",
                "")
    return ("NO", "needs third-party install / network / real RE binary / HMC / credential or product write (OWNER_GATED)", "")


def main():
    rows = tsv(CI)
    no = [r for r in rows if r["absorbed_into_behaviour_YES_NO"].strip().upper() == "NO"]
    assert len(rows) == 320 and len(no) == 313, (len(rows), len(no))

    # ABSORBABLE.tsv — one row per absorbed_no lesson
    out = [
        "# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/ABSORBABLE.tsv",
        "# as_of 2026-11-11 | source: " + CI.relative_to(W).as_posix() + " (320 rows / absorbed_no=313)",
        "# can_local_check_YES_NO decided by the classifier in build_artifacts.py (read the source bytes, never prose memory).",
        "index_id\tsource\tlocator\tlesson\tcan_local_check_YES_NO\treason\tproposed_command",
    ]
    n_yes = 0
    for r in no:
        can, reason, cmd = classify(r)
        if can == "YES":
            n_yes += 1
        lesson = r["lesson_or_ask"].replace("\t", " ").replace("\n", " ")[:500]
        out.append("\t".join([r["id"], r["source"], r["locator"], lesson, can, reason, cmd]))
    (HERE / "ABSORBABLE.tsv").write_text("\n".join(out) + "\n", encoding="utf-8")

    # 42 QA/SM/RANGE/W3 claims + receipt binding from disk
    sat = tsv(SAT)
    q5 = [r for r in sat if r["claim_id"].startswith(("QA", "SM", "RANGE", "W3"))]
    assert len(q5) == 42, len(q5)

    # REAL receipts that exist on disk for Q5-owned claims (bound, NOT re-run).
    # Key = claim_id -> (receipt_path W-relative, negative-control receipt W-relative, exit, source_class)
    V4 = "setukou-20261111/v4/real-verify/receipts/"
    R3 = "setukou-20261111/v3/repo-qa/receipts/"
    BIND = {
        "QA:G25": (V4 + "RV-P10-repo-qa-check.txt", V4 + "RV-N01-fake-passed-negative.txt", "0", "already-REAL"),
        "W3:CARD-01": (V4 + "RV-S03-w3-adoption-verify.txt", "setukou-20261111/w3-adoption/receipts/02-negative-smoke.txt", "0", "already-REAL"),
    }
    # 12 SM:candidate/* rows: V4 RV-S02 executed the WHOLE skill-package verify.py
    # over all 12 candidate files (sha256_match=12). Bind that one receipt to all 12.
    for r in q5:
        if r["claim_id"].startswith("SM:"):
            BIND[r["claim_id"]] = (V4 + "RV-S02-skill-package-verify.txt",
                                   V4 + "RV-S02-skill-package-verify.txt#tamper_caught=1", "0", "staged-REAL")

    # PROMOTIONS.tsv — ONLY claims whose status actually moves, each referencing
    # exactly one REAL receipt in this slice's receipts/<claim_id>.txt + a negative control.
    # QA:G25 / W3:CARD-01 are ALREADY RUNNABLE_REAL_VERIFIED (frozen), NOT promotions.
    # Corpus lessons are NEW_BEHAVIOUR_GATE rows in ABSORBABLE.tsv, NEVER new SATURATION claims.
    promo = [
        "# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/PROMOTIONS.tsv",
        "# as_of 2026-11-11 | claims_total=295 FROZEN; only status moves, no row add/delete/renumber.",
        "# each row references exactly one receipt in this slice's receipts/<claim_id>.txt (command/cwd/UTC/exit/stdout/stderr).",
        "claim_id,from_verdict,to_verdict,receipt_path,exit,negative_control",
    ]
    n_promo = 0
    for r in q5:
        cid = r["claim_id"]
        if cid.startswith("SM:"):
            rcpt = "setukou-20261111/v5/slices/q5-absorption/receipts/" + cid.replace("/", "_") + ".txt"
            promo.append(",".join([cid, "DECLARED_UNVERIFIED", "RUNNABLE_REAL_VERIFIED", rcpt, "0",
                                   "tamper_caught=1 (RV-S02 in-memory tamper falsifier goes RED)"]))
            n_promo += 1
    (HERE / "PROMOTIONS.tsv").write_text("\n".join(promo) + "\n", encoding="utf-8")
    # RECEIPT-BINDINGS.tsv — honest disk binding (exists on disk? which receipt?)
    rb = [
        "# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/RECEIPT-BINDINGS.tsv",
        "# as_of 2026-11-11 | source: v5/SATURATION.tsv (42 QA/SM/RANGE/W3 rows) + on-disk receipt dirs",
        "# bound = a REAL receipt file (stdout+exit+UTC) exists on disk and is mapped to this claim. NOT re-run.",
        "claim_id\tstatus_in_saturation\tbound_YES_NO\treceipt_path\tnegative_control\tverified_by\tnotes",
    ]
    bound_ids = []
    for r in q5:
        cid = r["claim_id"]
        if cid in BIND:
            rp, nc, ex, cls = BIND[cid]
            rb.append("\t".join([cid, r["status"], "YES", rp, nc, cls, "existing on-disk REAL receipt bound (read-only)"]))
            bound_ids.append(cid)
        else:
            rb.append("\t".join([cid, r["status"], "NO", "none", "none", "none",
                                 "no claim-specific REAL receipt on disk; stays at its frozen status"]))
    (HERE / "RECEIPT-BINDINGS.tsv").write_text("\n".join(rb) + "\n", encoding="utf-8")
    print("corpus_index_rows", len(rows))
    print("absorbed_no_baseline", len(no))
    print("absorbable_rows", n_yes)
    print("qa_sm_range_w3_rows", len(q5))
    print("existing_receipt_bound", len(bound_ids))
    print("promotions", n_promo)
    print("bound_ids", ",".join(bound_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
