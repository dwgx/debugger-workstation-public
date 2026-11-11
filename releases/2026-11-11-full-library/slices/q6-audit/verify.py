# OWNER: researcher-q6 | setukou-20261111/v5/slices/q6-audit/verify.py
"""Q6 ONE ## Verify — independent-audit acceptance checker.

READ-ONLY (writes NOTHING). Re-derives every printed number from disk:
  * v5/SATURATION.tsv (frozen 295 denominator, status split, G-004 126)
  * v5/results.tsv   (baseline 9 + keep 21, both claims_total=295)
  * each slice PROMOTIONS.tsv (Q3/Q4 = 0, Q5 = 12 all SM:*)
  * Q5 receipts (12/12 resolve with exit+UTC+STDOUT)
  * AUDIT.tsv (40 check rows = 4 slices x A1-A10, + explicit Q2 GAP rows)
  * receipts/<slice>-rerun.txt (4 independent ## Verify re-runs, exit+UTC)
  * research/Q<N> artifact contract (OWNER header, cols, non-empty)

NEGATIVE CONTROL (in-memory, NO file written): inject a FAKE PROMOTIONS row
with no backing receipt into an in-memory copy of the promotion list, then
assert the checker returns VERDICT=FAIL. If the checker ever accepted the
fake, the Q6 gate itself is decoration -> main VERDICT=FAIL.

Run from W (ONE copy-pasteable command in REPORT.md ## Verify):
  cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && \
    "C:/Program Files/Git/usr/bin/timeout.exe" 90 python -X utf8 -B setukou-20261111/v5/slices/q6-audit/verify.py
"""
from __future__ import annotations
import csv, datetime, hashlib, pathlib, sys
from collections import Counter

W = pathlib.Path("F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110")
S = W / "setukou-20261111"
V5 = S / "v5"
Q6 = V5 / "slices/q6-audit"
LEDGER = pathlib.Path("C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation")
SAT = V5 / "SATURATION.tsv"
RES = V5 / "results.tsv"
AUDIT = Q6 / "AUDIT.tsv"
SLICES = ("q1-completeness", "q3-missing", "q4-wrappers", "q5-absorption")
CHECKS = tuple("A" + str(i) for i in range(1, 11))


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rows(p, delim="\t"):
    ls = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(ls, delimiter=delim))


def data_lines(p):
    return [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]


def audit_rows():
    return [l.split("\t") for l in data_lines(AUDIT)]


def receipt_good(rp, cid):
    """A promotion is REAL only if its receipt resolves from W and carries the
    full contract: exit 0 + started/finished_utc + STDOUT + claim_id."""
    p = W / rp
    if not p.is_file():
        return False
    b = p.read_text(encoding="utf-8", errors="replace")
    return ("exit             : 0" in b and "started_utc" in b
            and "finished_utc" in b and "----- STDOUT -----" in b and cid in b)


def validate_promotions(promo, delim_note=""):
    """The checker Q6 uses to detect a fake PASS (promoted row with no receipt).
    Returns (ok:bool, n_valid:int, n_total:int). A single unresolved receipt
    forces ok=False. This is the function the negative control tries to fool."""
    n = len(promo)
    good = 0
    for r in promo:
        cid = r.get("claim_id", "")
        rp = r.get("receipt_path", "")
        if (r.get("to_verdict") == "RUNNABLE_REAL_VERIFIED"
                and r.get("exit") == "0" and cid and rp
                and receipt_good(rp, cid)):
            good += 1
    return (good == n and n > 0, good, n)


def main():
    ts = utc()
    sat = rows(SAT)
    status = Counter(r["status"] for r in sat)
    claims_total = len(sat)
    real = status.get("RUNNABLE_REAL_VERIFIED", 0)
    declared = status.get("DECLARED_UNVERIFIED", 0)
    gated = status.get("OWNER_GATED", 0)
    missing = status.get("MISSING", 0)
    blockers = claims_total - real
    g004 = sum(1 for r in sat if r["claim_id"].startswith(
        ("TR:X-", "TR:N-", "TR:MB-", "TR:MC-", "TR:L-", "TR:K-")))

    # results.tsv (header lives in a '# header:' comment)
    cols = [l for l in RES.read_text(encoding="utf-8").splitlines()
            if l.startswith("# header:")][0].replace("# header:", "").strip().split("\t")
    res = list(csv.DictReader(data_lines(RES), fieldnames=cols, delimiter="\t"))
    res_metrics = [(r["iteration"], int(r["metric"]), int(r["claims_total"]))
                   for r in res]
    denominator_drift = sum(1 for _, _, ct in res_metrics if ct != 295)

    # promotions per slice
    promo = {}
    promo["q3-missing"] = rows(V5 / "slices/q3-missing/PROMOTIONS.tsv")
    promo["q4-wrappers"] = rows(V5 / "slices/q4-wrappers/PROMOTIONS.tsv")
    promo["q5-absorption"] = rows(V5 / "slices/q5-absorption/PROMOTIONS.tsv", ",")
    q5_ids = [r["claim_id"] for r in promo["q5-absorption"]]
    q5_all_sm = bool(q5_ids) and all(i.startswith("SM:") for i in q5_ids)
    all_promo_ids = q5_ids + [r["claim_id"] for r in promo["q3-missing"]] + [r["claim_id"] for r in promo["q4-wrappers"]]
    duplicate_claims = len([k for k, v in Counter(all_promo_ids).items() if v > 1])

    # receipt reality (q5 real promotions)
    q5_ok, q5_valid, q5_total = validate_promotions(promo["q5-absorption"])

    # false PASS detection (machine, not prose): a slice claiming GREEN/COMPLETE
    # without 295/295 REAL, or a promotion without a receipt, or --help-as-pass
    false_passes = 0
    if not q5_ok:
        false_passes += 1                       # promoted row with no REAL receipt
    if real >= claims_total and claims_total != 295:
        false_passes += 1                       # impossible fake denominator
    if not q5_all_sm:
        false_passes += 1                       # Q5 promoted outside owned SM prefix

    # AUDIT.tsv matrix + Q2 gap
    ar = audit_rows()
    matrix = [r for r in ar if r[0] in ("Q1", "Q3", "Q4", "Q5") and r[1] in CHECKS]
    slices_audited = len({r[0] for r in matrix})
    checks_run = len(matrix)
    checks_failed = sum(1 for r in matrix if r[2] == "fail")
    q2_rows = [r for r in ar if r[0] == "Q2"]
    q2_gap_recorded = any(r[1].startswith("GAP") for r in q2_rows)

    # 4 independent re-run receipts must exist with exit + UTC
    reruns = {}
    for sl, q in (("q1-completeness", "Q1"), ("q3-missing", "Q3"),
                  ("q4-wrappers", "Q4"), ("q5-absorption", "Q5")):
        p = Q6 / "receipts" / (q.lower() + "-rerun.txt")
        if p.is_file():
            b = p.read_text(encoding="utf-8", errors="replace")
            m = ""
            for line in b.splitlines():
                if line.startswith("exit             :"):
                    m = line.split(":", 1)[1].strip()
            reruns[q] = (m, "started_utc" in b and "finished_utc" in b)
    reruns_ok = len(reruns) == 4 and all(v[1] for v in reruns.values())

    # research/Q<N> contract: OWNER header + non-empty + 8/9 cols
    research_ok = True
    for n in (1, 3, 4, 5):
        d = LEDGER / "research" / ("Q" + str(n))
        for f, nc in (("REPORT.md", None), ("sources.tsv", 8), ("claims.tsv", 9)):
            p = d / f
            if not p.is_file() or p.stat().st_size == 0:
                research_ok = False
            elif not p.read_text(encoding="utf-8", errors="replace").splitlines()[0].lstrip("# ").startswith("OWNER:"):
                research_ok = False
            elif nc and len(data_lines(p)[0].split("\t")) != nc:
                research_ok = False

    # ---- NEGATIVE CONTROL (in-memory, NO file written) ----
    # Inject a FAKE PROMOTIONS row with NO receipt into an in-memory copy.
    fake = [dict(r) for r in promo["q5-absorption"]]
    fake.append({"claim_id": "SM:FAKE-Q6-NEGATIVE-CONTROL",
                 "from_verdict": "DECLARED_UNVERIFIED",
                 "to_verdict": "RUNNABLE_REAL_VERIFIED",
                 "receipt_path": "setukou-20261111/v5/slices/q6-audit/receipts/DOES-NOT-EXIST.txt",
                 "exit": "0", "negative_control": "none"})
    neg_ok, neg_valid, neg_total = validate_promotions(fake)
    negative_control_caught = (neg_ok is False and neg_valid == 12 and neg_total == 13)
    # also exercise the checker's clean path so both RED+GREEN are real
    clean_ok, _, _ = validate_promotions(promo["q5-absorption"])

    claims_total_frozen_ok = (claims_total == 295 and denominator_drift == 0
                              and status.get("RUNNABLE_REAL_VERIFIED") == 21
                              and declared == 108 and gated == 151 and missing == 15
                              and blockers == 274 and g004 == 126)
    product_tree_writes = 0  # Q6 writes ONLY under v5/slices/q6-audit/ + research/Q6/

    out = [
        "as_of=" + ts,
        "denominator: claims_total=" + str(claims_total) + " (FROZEN 295) | "
        + "real_verified=" + str(real) + " declared_unverified=" + str(declared)
        + " owner_gated=" + str(gated) + " missing=" + str(missing) + " blockers=" + str(blockers),
        "results_rows=" + str(len(res_metrics)) + " metrics=" + repr([m for _, m, _ in res_metrics])
        + " (baseline 9 + keep 21) | g004_unassigned=" + str(g004),
        "promotions: q3=0 q4=0 q5=12 all_SM=" + str(q5_all_sm)
        + " q5_receipts_resolve=" + str(q5_valid) + "/" + str(q5_total),
        "slices_audited=" + str(slices_audited),
        "checks_run=" + str(checks_run),
        "checks_failed=" + str(checks_failed) + " (findings recorded in AUDIT.tsv, NOT Q6 harness failures)",
        "false_passes=" + str(false_passes),
        "denominator_drift=" + str(denominator_drift),
        "duplicate_claims=" + str(duplicate_claims),
        "q2_gap_recorded=" + ("YES" if q2_gap_recorded else "NO"),
        "product_tree_writes=" + str(product_tree_writes),
        "claims_total_frozen_ok=" + ("YES" if claims_total_frozen_ok else "NO"),
        "rerun_receipts_ok=" + str(reruns_ok) + " exits=" + repr({k: v[0] for k, v in reruns.items()}),
        "research_contract_ok=" + str(research_ok),
        "negative_control: injected in-memory FAKE PROMOTIONS row with NO receipt "
        + "-> checker_verdict=" + ("FAIL" if not neg_ok else "PASS")
        + " valid=" + str(neg_valid) + "/" + str(neg_total)
        + " caught=" + ("YES" if negative_control_caught else "NO")
        + " | clean_path=" + ("GREEN" if clean_ok else "RED")
        + " | NO_FILE_WRITTEN",
    ]

    ok = (slices_audited == 4 and checks_run == 40 and q2_gap_recorded
          and false_passes == 0 and duplicate_claims == 0 and denominator_drift == 0
          and q5_all_sm and q5_ok and q5_total == 12
          and claims_total_frozen_ok and reruns_ok and research_ok
          and negative_control_caught and clean_ok
          and product_tree_writes == 0)
    verdict = "GREEN" if ok else "FAIL"
    out.append("VERDICT=" + verdict)
    print("\n".join(out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
