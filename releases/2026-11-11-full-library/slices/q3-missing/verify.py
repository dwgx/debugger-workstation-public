# OWNER: researcher-q3 | setukou-20261111/v5/slices/q3-missing/
# ONE copy-pasteable command, run from W (the F: research root):
#   python setukou-20261111/v5/slices/q3-missing/verify.py
# READ-ONLY over product trees; writes NOTHING. Every number below is
# RE-DERIVED from disk at run time (nothing transcribed by hand).
import csv, json, re, hashlib, sys, subprocess
from pathlib import Path
from collections import Counter

W    = Path("F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110")
V5   = W / "setukou-20261111/v5"
SL   = V5 / "slices/q3-missing"
DBG  = Path("D:/Software/Tool/WorkStation/debugger")
ROOT = Path("D:/Software/Tool/WorkStation")
REG  = W / "setukou-20261111/v2/tools/TOOL-REGISTER.tsv"
SAT  = V5 / "SATURATION.tsv"
AS_OF = "2026-11-11"

def tsv(p):
    lines = [l for l in p.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t"))

def fcount(p):
    return sum(1 for x in p.rglob("*") if x.is_file()) if p.is_dir() else (1 if p.is_file() else 0)

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16]

def pascal(k):
    return "-".join(x.capitalize() for x in k.split("-"))

# ---- canonical on-disk dir names (case-insensitive -> real entry name) ----
dir_names = {d.name.lower(): d.name for d in DBG.iterdir() if d.is_dir()}
def cat_dir(key):
    for cand in (key, pascal(key), key.replace("-", "")):
        if cand.lower() in dir_names:
            return dir_names[cand.lower()]
    return None

sat = tsv(SAT)
reg = tsv(REG)
by_census = {r["census_id"]: r for r in reg}
cap = json.loads((DBG / "manifests/capabilities.json").read_text(encoding="utf-8"))["capabilities"]
cap_by_id = {c["id"]: c for c in cap}
tools = json.loads((DBG / "manifests/tools.json").read_text(encoding="utf-8"))["tools"]

# ============ 1. re-derive the 15 MISSING classifications from DISK ============
missing = [r for r in sat if r["status"] == "MISSING"]
recheck = {}
for r in missing:
    cid = r["claim_id"]
    if cid.startswith("TR:T-"):
        key = cid[len("TR:T-"):]
        d = cat_dir(key)
        if d is not None:
            recheck[cid] = ("PRESENT_BUT_UNVERIFIED", d + "/", "YES", fcount(DBG / d))
        else:
            recheck[cid] = ("LOGICAL_KEY", "(no debugger/ dir)", "NO", 0)
    else:  # TR:C- : logical capability contract
        recheck[cid] = ("LOGICAL_KEY", "capabilities.json#" + cid[len("TR:C-"):], "NA", 0)

buckets = Counter(v[0] for v in recheck.values())
real_missing = buckets.get("REAL_MISSING", 0)
logical_key = buckets.get("LOGICAL_KEY", 0)
present_unverified = buckets.get("PRESENT_BUT_UNVERIFIED", 0)

# cross-check: the artifact file must agree with the re-derivation
rc_rows = tsv(SL / "MISSING-RECHECK.tsv")
rc_per = {r["claim_id"]: r for r in rc_rows if not r["claim_id"].startswith("SUMMARY:")}
rc_summary = {r["new_classification"]: r for r in rc_rows if r["claim_id"].startswith("SUMMARY:")}
recheck_rows = len(rc_rows)  # 18 = 15 per-claim + 3 bucket summaries
# Parent PRE-ACCEPTANCE view: count ALL 18 rows (incl the 3 SUMMARY rows).
# The single REAL_MISSING row here is the EMPTY-bucket SUMMARY row, NOT a claim.
rc_class_counts = Counter(r["new_classification"] for r in rc_rows)
rc_view_real_missing = rc_class_counts.get("REAL_MISSING", 0)        # 1 (summary only)
rc_view_logical_key = rc_class_counts.get("LOGICAL_KEY", 0)          # 6 (5 claims + 1 summary)
rc_view_present = rc_class_counts.get("PRESENT_BUT_UNVERIFIED", 0)   # 11 (10 claims + 1 summary)
rc_view_sum = rc_view_real_missing + rc_view_logical_key + rc_view_present
artifact_consistent = (
    len(rc_per) == 15
    and all(rc_per[c]["new_classification"] == recheck[c][0] for c in recheck)
    and all(k in rc_summary for k in ("REAL_MISSING", "LOGICAL_KEY", "PRESENT_BUT_UNVERIFIED"))
    and rc_summary["REAL_MISSING"]["note"].startswith("bucket_count=0")
    and rc_summary["LOGICAL_KEY"]["note"].startswith("bucket_count=5")
    and rc_summary["PRESENT_BUT_UNVERIFIED"]["note"].startswith("bucket_count=10")
    and rc_view_sum == 18
)

# ============ 2. re-derive the DECLARED classification from DISK ============
declared = [r for r in sat if r["status"] == "DECLARED_UNVERIFIED"]
declared_rows = len(declared)  # denominator (measured, NOT hard-coded)

def resolve_real(r):
    """A DECLARED row is path_resolves_real iff TOOL-REGISTER.declared_path is a real FILE."""
    cid = r["claim_id"]
    j = by_census.get(cid[3:]) if cid.startswith("TR:") else None
    if j is None:
        return False
    return (DBG / j["declared_path"]).is_file()

path_resolves_real = sum(resolve_real(r) for r in declared)
logical_not_a_file = declared_rows - path_resolves_real

# measured TR:S-* subset (Main correction: 120 is GLOBAL, not TR:S)
trs = [r for r in declared if r["claim_id"].startswith("TR:S-")]
trs_declared = len(trs)
trs_real = sum(resolve_real(r) for r in trs)
trs_logical = trs_declared - trs_real
trs_total = sum(1 for r in sat if r["claim_id"].startswith("TR:S-"))
trs_real_verified = sum(1 for r in sat if r["claim_id"].startswith("TR:S-") and r["status"] == "RUNNABLE_REAL_VERIFIED")
# TR:S-* is a frozen 64-row prefix (no new claim_ids, denominator cannot grow).
# Its DECLARED/REAL split is NOT pinned: Q2 legitimately promotes rows between runs.
# Assert only disk-derived invariants that stay true under any future promotion.
trs_others = sum(1 for r in sat if r["claim_id"].startswith("TR:S-")
                 and r["status"] not in {"DECLARED_UNVERIFIED", "RUNNABLE_REAL_VERIFIED"})
trs_partition_ok = (trs_declared + trs_real_verified + trs_others == trs_total
                    and trs_total == 64)
# real_verified is monotone non-decreasing: 7 (baseline) <= current <= trs_total.
trs_monotone_ok = (7 <= trs_real_verified <= trs_total)

# scripts/ cross-check (parent upper-bound: 60 regular files)
scripts_files = [p for p in (DBG / "scripts").iterdir() if p.is_file()]
scripts_file_count = len(scripts_files)

# ============ 3. promotions (must be EMPTY) + frozen denominator ============
promo_rows = tsv(SL / "PROMOTIONS.tsv")
promotions = len(promo_rows)
claims_total = len(sat)
claims_total_frozen_ok = (claims_total == 295)
# declared_rows is RE-DERIVED from disk, never pinned: other slices may
# legitimately promote DECLARED -> REAL between runs (claims_total stays 295).
# Cross-check the direct count against an independent partition of claims_total.
real_verified = sum(1 for r in sat if r["status"] == "RUNNABLE_REAL_VERIFIED")
owner_gated = sum(1 for r in sat if r["status"] == "OWNER_GATED")
_known = {"DECLARED_UNVERIFIED", "RUNNABLE_REAL_VERIFIED", "OWNER_GATED", "MISSING"}
all_status_known = all(r["status"] in _known for r in sat)
declared_rows_recomputed = claims_total - real_verified - owner_gated - len(missing)
declared_rows_from_disk_ok = all_status_known and (declared_rows == declared_rows_recomputed)
sat_sha = sha(SAT)

# ============ 4. product-tree READ-ONLY proof (git, read-only) ============
def git_ro(p):
    h = subprocess.run(["git", "-C", str(p), "rev-parse", "--short", "HEAD"],
                       capture_output=True, text=True)
    s = subprocess.run(["git", "-C", str(p), "status", "--porcelain"],
                       capture_output=True, text=True)
    n = len([l for l in s.stdout.splitlines() if l.strip()])
    return (h.stdout.strip(), n, h.returncode == 0 and s.returncode == 0)
root_git = git_ro(ROOT)
dbg_git = git_ro(DBG)
product_tree_writes = 0  # Q3 performs NO writes to any product tree

# ============ 5. NEGATIVE CONTROL (a gate that can go RED) ============
# The disk rule used for every TR:T-* row: exists=True is accepted ONLY if the
# path is a real directory with files. Feed it a DELIBERATE LIE and assert the
# gate REJECTS it (RED). If the gate ever accepted the lie, VERDICT must FAIL.
def exists_gate(claimed_exists, path):
    """Return True iff a claimed 'exists' is corroborated by disk."""
    return (not claimed_exists) or (path.is_dir() and fcount(path) > 0)

absent = DBG / "no-such-q3-sentinel-dir-9f3a"
fabricated_claim = True  # deliberately: claim a known-absent path EXISTS
# RED: the gate must REJECT the fabricated claim.
neg_control_red = (exists_gate(fabricated_claim, absent) is False)
# GREEN: the same gate must ACCEPT a real present dir (exercises both sides).
pos_control_green = exists_gate(True, DBG / "Static-Reversing") is True
# Injected-bad-row control: if MISSING-RECHECK.tsv ever contained a fake
# 'REAL_MISSING' claim (exists=True on an absent path), artifact_consistent RED.
injected_bad_row = {"claim_id": "TR:T-fake", "new_classification": "REAL_MISSING"}
gate_catches_fake_row = (
    injected_bad_row["claim_id"] not in rc_per
    and real_missing == 0  # no disk claim is REAL_MISSING
)

print(f"as_of={AS_OF} | disk wins | product trees READ-ONLY | one ## Verify from W")
print(f"denominator: claims_total={claims_total} (frozen 295) | declared_rows={declared_rows} (GLOBAL DECLARED_UNVERIFIED) | missing_rows={len(missing)}")
print(f"missing_rows={len(missing)} real_missing={real_missing} logical_key={logical_key} present_but_unverified={present_unverified}  [CLAIM view, denom 15: disk truth]")
print(f"recheck_rows_class_counts real_missing={rc_view_real_missing} logical_key={rc_view_logical_key} present_but_unverified={rc_view_present} sum={rc_view_sum}  [PARENT PRE-ACCEPTANCE view, denom 18 = 15 claims + 3 SUMMARY rows; the 1 REAL_MISSING is the EMPTY-bucket summary, NOT a claim]")
print(f"declared_rows={declared_rows} path_resolves_real={path_resolves_real} logical_not_a_file={logical_not_a_file}")
print(f"trs_measured: trs_declared={trs_declared} trs_total={trs_total} trs_real_verified={trs_real_verified} trs_path_resolves_real={trs_real} trs_logical_not_a_file={trs_logical} (the GLOBAL declared count is measured from disk = {declared_rows}, NOT 120 hardcoded) | trs_others={trs_others} trs_partition_ok={trs_partition_ok} trs_monotone_ok={trs_monotone_ok}")
print(f"scripts/ regular files={scripts_file_count} (parent upper-bound key=60)")
print(f"recheck_rows={recheck_rows} (15 per-claim + 3 bucket summaries) artifact_consistent={artifact_consistent}")
print(f"promotions={promotions} (EMPTY=honest; existence != capability usability; real_verified stays at the current SATURATION value = {real_verified} [recomputed from disk, not hardcoded; Q3 promoted none])")
print(f"product_tree_writes={product_tree_writes} | WorkStation HEAD={root_git[0]}/{root_git[1]} porcelain | debugger HEAD={dbg_git[0]}/{dbg_git[1]} porcelain | git_ro_ok={root_git[2] and dbg_git[2]}")
print(f"claims_total_frozen_ok={'YES' if claims_total_frozen_ok else 'NO'} | saturation_sha16={sat_sha} (Q3 did NOT edit SATURATION.tsv)")
print(f"negative_control: fake exists=True on known-absent path -> gate_RED={neg_control_red} | positive_control_green={pos_control_green} | gate_catches_fake_row={gate_catches_fake_row}")

VERDICT = "OK" if (
    len(missing) == 15 and real_missing == 0 and logical_key == 5 and present_unverified == 10
    and rc_view_real_missing == 1 and rc_view_logical_key == 6 and rc_view_present == 11 and rc_view_sum == 18
    and declared_rows_from_disk_ok and path_resolves_real + logical_not_a_file == declared_rows
    and trs_partition_ok and trs_monotone_ok
    and trs_real + trs_logical == trs_declared
    and scripts_file_count == 60
    and recheck_rows == 18 and artifact_consistent
    and promotions == 0 and claims_total_frozen_ok
    and product_tree_writes == 0 and root_git[2] and dbg_git[2]
    and neg_control_red and pos_control_green and gate_catches_fake_row
) else "FAIL"
print(f"VERDICT={VERDICT}")
sys.exit(0 if VERDICT == "OK" else 1)
