# OWNER: researcher-q4 | setukou-20261111/v5/slices/q4-wrappers/verify.py
"""Q4 acceptance verify — READ-ONLY, recompute-everything-from-disk.

Answers 「151 OWNER_GATED 里哪些可降级本地真跑」 for the owned prefix TR:B-*
(mcp/bin/*.cmd wrappers). Every number is read from the TSV/receipt bytes on
disk; nothing is hard-coded except the frozen claims_total guard (295) and the
honest expectation promotions=0.

Promotion gate (auto-deepresearch evidence bar):
  A TR:B-* row may become RUNNABLE_REAL_VERIFIED ONLY with a REAL MCP-session
  receipt (literal marker MCP_SESSION_CONNECTED). Static receipts (text dump,
  config consistency, sha256, path-find) explicitly carry backend_usable
  UNVERIFIED, so promotion_allowed() MUST reject a fake backend_usable=True.
  Negative control: a fake backend_usable=True with no session receipt must FAIL.
  Positive control: a synthetic session receipt with the marker must be ACCEPTED.
  If either control cannot fire, verify.py exits non-zero (RED-capable gate).

Run from W with ONE command:
    python -X utf8 -B setukou-20261111/v5/slices/q4-wrappers/verify.py
"""
from __future__ import annotations

import csv
import datetime
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
W = HERE.parent.parent.parent.parent          # .../build-weapon-library-20261110
S = W / "setukou-20261111"
SLICE = S / "v5" / "slices" / "q4-wrappers"
SAT = S / "v5" / "SATURATION.tsv"
CLASSIFY = SLICE / "CLASSIFY.tsv"
PROMOTIONS = SLICE / "PROMOTIONS.tsv"
RECEIPTS = SLICE / "receipts"
FROZEN_TOTAL = 295
PRODUCT_TREES = ("D:/Software/Tool/WorkStation", "D:/Project/Hackerone")
SESSION_MARKER = "MCP_SESSION_CONNECTED"


def as_of() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tsv_rows(path: pathlib.Path) -> list[dict]:
    lines = [l for l in path.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t"))


def receipt_stdout(text: str) -> str:
    import re
    m = re.search(r"--- stdout ---\n(.*?)--- stderr ---", text, re.S)
    return m.group(1) if m else ""


def session_receipt_exists(receipt_stdouts: list[str]) -> bool:
    """REAL proof of a backend = a session receipt with the literal marker."""
    return any(SESSION_MARKER in s for s in receipt_stdouts)


def promotion_allowed(backend_usable_claim: bool, receipt_stdouts: list[str]) -> bool:
    """The ONE gate: a backend-usable promotion needs a real session receipt."""
    return backend_usable_claim and session_receipt_exists(receipt_stdouts)


def main() -> int:
    ts = as_of()
    problems: list[str] = []

    # ---- measured from SATURATION.tsv ----
    sat = tsv_rows(SAT)
    claims_total = len(sat)
    tr_b = [r for r in sat if r["claim_id"].startswith("TR:B-")]
    tr_b_rows = len(tr_b)
    tr_b_status = {}
    for r in tr_b:
        tr_b_status[r["status"]] = tr_b_status.get(r["status"], 0) + 1

    # ---- measured from CLASSIFY.tsv ----
    cls = tsv_rows(CLASSIFY)
    wrappers_scanned = len(cls)
    kind_counts: dict[str, int] = {}
    still_gated = 0
    for r in cls:
        kind_counts[r["kind"]] = kind_counts.get(r["kind"], 0) + 1
        if r["still_owner_gated_YES_NO"].strip().upper() == "YES":
            still_gated += 1
    static_only = kind_counts.get("STATIC_ONLY", 0)
    launches_real_binary = kind_counts.get("LAUNCHES_REAL_BINARY", 0)
    security_gated = kind_counts.get("SECURITY_GATED", 0)
    unknown = kind_counts.get("UNKNOWN", 0)

    # ---- measured from PROMOTIONS.tsv ----
    promos = tsv_rows(PROMOTIONS)
    promotions = len(promos)

    # ---- measured from receipts/ ----
    receipt_files = sorted(RECEIPTS.glob("*.txt"))
    local_real_commands = len(receipt_files)
    receipts_real = 0
    receipt_stdouts: list[str] = []
    product_tree_writes = 0
    for f in receipt_files:
        t = f.read_text(encoding="utf-8")
        out = receipt_stdout(t)
        receipt_stdouts.append(out)
        import re
        ex = re.search(r"exit=(\d+)", t)
        # real = exit 0 AND substantive stdout (not the literal 'None' artifact)
        if ex and ex.group(1) == "0" and len(out.strip()) > 40 and "None" not in out[:20]:
            receipts_real += 1
        cmd = ""
        for line in t.splitlines():
            if line.startswith("command="):
                cmd = line
                break
        # a WRITE into a product tree would be a redirect/mutation of a product path
        for tree in PRODUCT_TREES:
            if tree in cmd and (">" in cmd or " -File" in cmd and "Apply" in cmd):
                product_tree_writes += 1

    # ---- guards ----
    claims_total_frozen_ok = "YES" if claims_total == FROZEN_TOTAL else "NO"
    if claims_total_frozen_ok != "YES":
        problems.append(f"claims_total={claims_total} != frozen {FROZEN_TOTAL}")
    if tr_b_rows != 23:
        problems.append(f"tr_b_rows={tr_b_rows} != 23 (measured expectation)")
    if wrappers_scanned != 23:
        problems.append(f"wrappers_scanned={wrappers_scanned} != 23")
    if launches_real_binary + security_gated + unknown + static_only != wrappers_scanned:
        problems.append("kind counts do not sum to wrappers_scanned")
    if still_gated != wrappers_scanned:
        problems.append(f"still_owner_gated={still_gated} != {wrappers_scanned}")
    if set(tr_b_status) != {"OWNER_GATED"}:
        problems.append(f"TR:B-* statuses drifted: {tr_b_status}")
    if promotions != 0:
        problems.append(f"promotions={promotions} != 0 (a static check is NOT a backend proof)")
    if receipts_real != local_real_commands or local_real_commands == 0:
        problems.append(f"receipts_real={receipts_real} / local_real_commands={local_real_commands}")
    if product_tree_writes != 0:
        problems.append(f"product_tree_writes={product_tree_writes} != 0")

    # ---- NEGATIVE CONTROL: fake backend_usable=True, no session receipt, must FAIL ----
    fake_backend_usable = True
    fake_accepted = promotion_allowed(fake_backend_usable, receipt_stdouts)  # our static receipts
    negative_control_ok = (fake_accepted is False)  # gate must REJECT it
    if not negative_control_ok:
        problems.append("NEGATIVE CONTROL BROKEN: fake backend_usable=True was accepted without a session receipt")

    # ---- POSITIVE CONTROL: synthetic session receipt with marker must be ACCEPTED ----
    synthetic = [f"backend session started\n{SESSION_MARKER}: ok\n"]
    positive_control_ok = promotion_allowed(True, synthetic) is True
    if not positive_control_ok:
        problems.append("POSITIVE CONTROL BROKEN: a real session receipt was not accepted")

    # ---- a single fake backend_usable=True must NOT flip the honest verdict ----
    verdict_flip_attempt = promotion_allowed(fake_backend_usable, receipt_stdouts)
    if verdict_flip_attempt:
        problems.append("VERDICT FLIPPED by a fake backend_usable=True (no session receipt)")

    # ---- print measured numbers (as_of + denominator) ----
    print(f"as_of={ts}")
    print(f"denominator: claims_total={claims_total} (FROZEN {FROZEN_TOTAL}), tr_b_denominator={tr_b_rows}, wrappers_denominator={wrappers_scanned}")
    print(f"tr_b_rows={tr_b_rows}  tr_b_status={tr_b_status}")
    print(f"wrappers_scanned={wrappers_scanned}")
    print(f"static_only={static_only} launches_real_binary={launches_real_binary} security_gated={security_gated} unknown={unknown}")
    print(f"local_real_commands={local_real_commands} receipts_real={receipts_real}")
    print(f"promotions={promotions}  still_owner_gated={still_gated}")
    print(f"claims_total_frozen_ok={claims_total_frozen_ok}  product_tree_writes={product_tree_writes}")
    print(f"negative_control: fake backend_usable=True accepted={fake_accepted} (must be False) -> {'OK' if negative_control_ok else 'BROKEN'}")
    print(f"positive_control: synthetic session receipt accepted={positive_control_ok} (must be True) -> {'OK' if positive_control_ok else 'BROKEN'}")

    if problems:
        for p in problems:
            print(f"PROBLEM: {p}")
        print("VERDICT=RED  (Q4 NOT accepted)")
        return 1
    print("VERDICT=GREEN  ALL_OWNER_GATED_NO_PROMOTIONS  (a .cmd parse / path exists / config-consistency is NOT a backend-usable verification)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
