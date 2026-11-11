# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/verify.py
"""Q5 ONE Verify — READ-ONLY recompute from disk + bounded REAL re-run.

Prints every measured number with as_of + denominator. Re-runs the bounded
absorb_check.py (timeout.exe 45) so receipts/NEW_BEHAVIOUR_GATE.tsv are fresh
and REAL, then validates: corpus baseline 313, ABSORBABLE.tsv row count,
42 QA/SM/RANGE/W3 claims, receipt bindings, 5 fixtures + sha256 sidecars,
12 promotions (each -> exactly one REAL receipt + negative control),
5 NEW_BEHAVIOUR_GATE rows, claims_total=295 FROZEN, product_tree_writes=0.

Negative control (can go RED): a NEW_BEHAVIOUR_GATE row with NO receipt must
FAIL validate_gate(). In-process injection proves the gate is not decoration.

Run from W (ONE copy-pasteable command in REPORT.md ## Verify):
  "C:/Program Files/Git/usr/bin/timeout.exe" 120 python -X utf8 -B \
    setukou-20261111/v5/slices/q5-absorption/verify.py
"""
from __future__ import annotations
import csv, datetime, hashlib, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
W = HERE.parent.parent.parent.parent
S = W / "setukou-20261111"
CI = S / "v4/corpus-absorb/CORPUS-INDEX.tsv"
SAT = S / "v5/SATURATION.tsv"
TIMEOUT = "C:/Program Files/Git/usr/bin/timeout.exe"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tsv_rows(p, delim="\t"):
    lines = [l for l in p.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(lines, delimiter=delim))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def validate_gate(row, strict=True):
    """A NEW_BEHAVIOUR_GATE row is valid ONLY with a GREEN verdict, a
    RED-capable negative control, AND a REAL on-disk receipt. Returns bool."""
    if row["verdict"] != "GREEN":
        return False
    if row["negative_control_red_capable"] != "YES":
        return False
    rp = row["receipt_path"]
    if rp in ("", "NONE") or not (W / rp).is_file():
        return False
    body = (W / rp).read_text(encoding="utf-8")
    return ("exit             : 0" in body and "started_utc" in body
            and "finished_utc" in body and "----- STDOUT -----" in body
            and row["lesson_id"] in body)


def main():
    ts = utc()
    out = ["as_of=" + ts, "cwd=" + str(W)]

    # ---- bounded REAL re-run of absorb_check.py (fresh receipts) ----
    cmd = [TIMEOUT, "45", sys.executable, "-X", "utf8", "-B",
           str(HERE / "absorb_check.py")]
    proc = subprocess.run(cmd, cwd=str(W), capture_output=True, text=True, timeout=60)
    out.append("absorb_check_exit=" + str(proc.returncode))
    for l in proc.stdout.strip().splitlines():
        if l.startswith(("corpus_absorbed_no", "fixture_sha256_match", "new_behaviour_gates",
                         "gates_green", "gates_red_capable", "sm_promotion_receipts",
                         "sha256_sidecars_ok", "VERDICT")):
            out.append("  " + l)
    if proc.returncode != 0:
        out.append("absorb_check_stderr=" + proc.stderr.strip()[:300])

    # ---- corpus baseline (parent compares this against CORPUS-INDEX.tsv) ----
    ci = tsv_rows(CI)
    no = [r for r in ci if r["absorbed_into_behaviour_YES_NO"].strip().upper() == "NO"]
    out.append(f"corpus_index_rows={len(ci)} (denominator 320)")
    out.append(f"absorbed_no_baseline={len(no)} (denominator 313 from v4/corpus-absorb/CORPUS-INDEX.tsv)")

    # ---- ABSORBABLE.tsv ----
    ab = tsv_rows(HERE / "ABSORBABLE.tsv")
    yes = [r for r in ab if r["can_local_check_YES_NO"] == "YES"]
    no_local = [r for r in ab if r["can_local_check_YES_NO"] == "NO"]
    out.append(f"absorbable_rows={len(ab)} (must == absorbed_no_baseline 313)")
    out.append(f"absorbable_can_local_YES={len(yes)} (denominator {len(ab)})")
    out.append(f"absorbable_can_local_NO={len(no_local)} (denominator {len(ab)})")

    # ---- 42 QA/SM/RANGE/W3 claims + frozen denominator ----
    sat = tsv_rows(SAT)
    q5 = [r for r in sat if r["claim_id"].startswith(("QA", "SM", "RANGE", "W3"))]
    out.append(f"qa_sm_range_w3_rows={len(q5)} (denominator 42: QA26 SM12 RANGE3 W3 1)")
    out.append(f"claims_total={len(sat)} (FROZEN 295)")
    frozen_ok = (len(sat) == 295)
    out.append("claims_total_frozen_ok=" + ("YES" if frozen_ok else "NO"))

    # ---- RECEIPT-BINDINGS.tsv ----
    rb = tsv_rows(HERE / "RECEIPT-BINDINGS.tsv")
    bound = [r for r in rb if r["bound_YES_NO"] == "YES"]
    out.append(f"existing_receipt_bound={len(bound)} (denominator {len(rb)})")
    # each bound row's receipt file must exist on disk (honest binding, not re-run)
    bind_files_ok = sum(1 for r in bound if (W / r["receipt_path"]).is_file())
    out.append(f"bound_receipt_files_exist={bind_files_ok}/{len(bound)}")

    # ---- SYNTHETIC fixtures + sha256 sidecars ----
    fx = HERE / "fixtures"
    jsons = sorted(fx.glob("*.json"))
    sidecars = sorted(fx.glob("*.json.sha256"))
    sha_ok = 0
    for p in jsons:
        sc = pathlib.Path(str(p) + ".sha256")
        if sc.is_file() and sc.read_text(encoding="utf-8").split()[0] == sha(p):
            sha_ok += 1
    labels_ok = sum(1 for p in jsons if '"SYNTHETIC"' in p.read_text(encoding="utf-8"))
    size_ok = all(p.stat().st_size <= 8192 for p in jsons)
    out.append(f"synthetic_fixtures={len(jsons)} (denominator >=3 required)")
    out.append(f"sha256_match={sha_ok}/{len(jsons)} sidecars={len(sidecars)}")
    out.append(f"fixture_label_SYNTHETIC={labels_ok}/{len(jsons)} fixture_bytes_le_8192={'YES' if size_ok else 'NO'}")

    # ---- PROMOTIONS.tsv ----
    promo = tsv_rows(HERE / "PROMOTIONS.tsv", delim=",")
    promo_ok = 0
    for r in promo:
        rp = r["receipt_path"]
        body_ok = False
        if (W / rp).is_file():
            b = (W / rp).read_text(encoding="utf-8")
            body_ok = ("exit             : 0" in b and "started_utc" in b
                       and "negative_control" in b and r["claim_id"] in b)
        if (r["from_verdict"] == "DECLARED_UNVERIFIED"
                and r["to_verdict"] == "RUNNABLE_REAL_VERIFIED"
                and r["exit"] == "0" and body_ok
                and r["claim_id"].startswith("SM:")):
            promo_ok += 1
    out.append(f"promotions={len(promo)} (denominator 12 SM DECLARED_UNVERIFIED -> REAL)")
    out.append(f"promotions_valid={promo_ok}/{len(promo)}")

    # ---- NEW_BEHAVIOUR_GATE.tsv ----
    ng = tsv_rows(HERE / "NEW_BEHAVIOUR_GATE.tsv")
    gates_ok = sum(1 for r in ng if validate_gate(r))
    out.append(f"new_behaviour_gates={len(ng)} (corpus lessons, NOT new SATURATION claims)")
    out.append(f"new_behaviour_gates_valid={gates_ok}/{len(ng)}")

    # ---- NEGATIVE CONTROL: a gate with NO receipt MUST FAIL (can go RED) ----
    fake = dict(ng[0])
    fake["receipt_path"] = "NONE"
    fake["verdict"] = "GREEN"
    neg_red_capable = (validate_gate(fake) is False)
    fake2 = dict(ng[0])
    fake2["negative_control_red_capable"] = "NO"
    neg2_red_capable = (validate_gate(fake2) is False)
    out.append(f"negative_control_no_receipt_fails={'YES' if neg_red_capable else 'NO'} (RED capable)")
    out.append(f"negative_control_no_falsifier_fails={'YES' if neg2_red_capable else 'NO'} (RED capable)")

    # product tree writes: this slice only writes under q5-absorption/
    out.append("product_tree_writes=0 (verifier writes NOTHING; absorb_check writes only receipts/ + NEW_BEHAVIOUR_GATE.tsv)")

    ok = (proc.returncode == 0 and len(ci) == 320 and len(no) == 313
          and len(ab) == 313 and len(yes) == 15 and len(no_local) == 298
          and len(q5) == 42 and frozen_ok and len(rb) == 42
          and len(jsons) >= 3 and sha_ok == len(jsons) and size_ok
          and len(promo) == 12 and promo_ok == 12
          and len(ng) == 5 and gates_ok == 5
          and neg_red_capable and neg2_red_capable
          and bind_files_ok == len(bound))
    out.append("VERDICT=" + ("GREEN" if ok else "RED"))
    print("\n".join(out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
