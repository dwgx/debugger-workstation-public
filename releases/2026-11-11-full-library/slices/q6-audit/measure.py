# OWNER: researcher-q6 | setukou-20261111/v5/slices/q6-audit/measure.py
"""Q6 re-derive-from-disk: measure every number the audit asserts. No prose trust.
Prints a flat key=value report used to populate AUDIT.tsv + verify.py.
"""
from __future__ import annotations
import csv, pathlib, re
from collections import Counter

W = pathlib.Path("F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110")
S = W / "setukou-20261111"
V5 = S / "v5"
LEDGER = pathlib.Path("C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation")
SAT = V5 / "SATURATION.tsv"
RES = V5 / "results.tsv"

def rows(p, delim="\t"):
    ls = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(ls, delimiter=delim))

def data_lines(p):
    return [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]

def ncol(p, delim="\t"):
    ls = data_lines(p)
    return len(ls[0].split(delim)) if ls else 0

sat = rows(SAT)
status = Counter(r["status"] for r in sat)
print("claims_total", len(sat))
for k in ("RUNNABLE_REAL_VERIFIED", "DECLARED_UNVERIFIED", "OWNER_GATED", "MISSING"):
    print("status_" + k, status.get(k, 0))
print("blockers", sum(v for k, v in status.items() if k != "RUNNABLE_REAL_VERIFIED"))

# prefix buckets
pref = Counter(re.match(r"^([A-Za-z0-9_-]+?)[:\-]", r["claim_id"]).group(1)
               if re.match(r"^([A-Za-z0-9_-]+?)[:\-]", r["claim_id"]) else r["claim_id"].split(":")[0].split("-")[0]
               for r in sat)
print("g004_prefixes", {k: sum(1 for r in sat if r["claim_id"].startswith(k + "-")) for k in ("TR:X", "TR:N", "TR:MB", "TR:MC", "TR:L", "TR:K")})
print("g004_sum", sum(sum(1 for r in sat if r["claim_id"].startswith(k + "-")) for k in ("TR:X", "TR:N", "TR:MB", "TR:MC", "TR:L", "TR:K")))

# results.tsv: header is a '# header: iteration<TAB>...' comment; data rows are tab-separated
cols = [l for l in RES.read_text(encoding="utf-8").splitlines() if l.startswith("# header:")][0].replace("# header:", "").strip().split("\t")
res = list(csv.DictReader([l for l in data_lines(RES)], fieldnames=cols, delimiter="\t"))
print("results_rows", len(res))
for r in res:
    print("  iter", r["iteration"], "metric", r["metric"], "claims_total", r["claims_total"], "status", r["status"])
# PROMOTIONS per slice (data rows, ignoring # comment lines)
for sl, delim in (("q3-missing", "\t"), ("q4-wrappers", "\t"), ("q5-absorption", ",")):
    p = V5 / "slices" / sl / "PROMOTIONS.tsv"
    pr = rows(p, delim)
    print("promo_" + sl, len(pr))
    if sl == "q5-absorption":
        ids = [r["claim_id"] for r in pr]
        print("q5_promo_all_SM", all(i.startswith("SM:") for i in ids))
        print("q5_promo_ids", len(ids), "unique", len(set(ids)))
        # receipts resolve from W root
        ok = 0
        detail = []
        for r in pr:
            rp = W / r["receipt_path"]
            exists = rp.is_file()
            body = rp.read_text(encoding="utf-8", errors="replace") if exists else ""
            good = exists and ("exit             : 0" in body and "started_utc" in body
                               and "finished_utc" in body and "----- STDOUT -----" in body
                               and r["claim_id"] in body)
            if good: ok += 1
            detail.append((r["claim_id"], exists, good))
        print("q5_receipts_resolve", ok, "/", len(pr))
        for d in detail:
            print("  rcpt", d[0], "exists", d[1], "good", d[2])

# duplicate claim_id across slices' PROMOTIONS
all_promo = []
for sl, delim in (("q3-missing", "\t"), ("q4-wrappers", "\t"), ("q5-absorption", ",")):
    for r in rows(V5 / "slices" / sl / "PROMOTIONS.tsv", delim):
        all_promo.append(r["claim_id"])
dups = [k for k, v in Counter(all_promo).items() if v > 1]
print("duplicate_promoted_claim_ids", dups)

# research/Q<N> contracts + OWNER headers + ONE ## Verify
for n in (1, 3, 4, 5):
    d = LEDGER / "research" / ("Q" + str(n))
    for f in ("REPORT.md", "sources.tsv", "claims.tsv"):
        p = d / f
        print(f"Q{n}_{f}", "exists" if p.is_file() else "MISSING", p.stat().st_size if p.is_file() else 0)
    rp = d / "REPORT.md"
    if rp.is_file():
        t = rp.read_text(encoding="utf-8", errors="replace")
        print(f"Q{n}_owner_header", t.splitlines()[0].startswith("OWNER:") if t.strip() else False)
        print(f"Q{n}_verify_headers", sum(1 for l in t.splitlines() if l.strip() == "## Verify"))
    for f, nc in (("sources.tsv", 8), ("claims.tsv", 9)):
        p = d / f
        if p.is_file():
            print(f"Q{n}_{f}_cols", ncol(p), "expect", nc)
            print(f"Q{n}_{f}_datarows", len(rows(p)))

# slice REPORT.md ONE ## Verify
for sl in ("q1-completeness", "q3-missing", "q4-wrappers", "q5-absorption"):
    rp = V5 / "slices" / sl / ( "COMPLETENESS.md" if sl == "q1-completeness" else "REPORT.md")
    if rp.is_file():
        t = rp.read_text(encoding="utf-8", errors="replace")
        print("slice_" + sl + "_verify_headers", sum(1 for l in t.splitlines() if l.strip() == "## Verify"))
        print("slice_" + sl + "_owner_header", t.splitlines()[0].startswith("OWNER:"))
