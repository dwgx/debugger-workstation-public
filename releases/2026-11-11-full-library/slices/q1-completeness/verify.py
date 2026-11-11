# OWNER: researcher-q1 | setukou-20261111/v5/slices/q1-completeness/verify.py
"""Q1 completeness judgment — READ-ONLY, recompute-everything-from-disk.

Answers 「现在是不是全部都好了」 by merging the 295 claim rows, 28-row gap
matrix, v1-v4 sealed counts, corpus absorption rate, RELEASE_GATE, external
actions and live product-tree porcelain into ONE re-runnable command.

Rules (auto-deepresearch evidence bar):
  * No number is hard-coded. Every count is read from the TSV/MD bytes on disk.
  * Every number prints with as_of + denominator.
  * Verdict = COMPLETE only if ALL of:
        real_verified == claims_total AND blockers == 0 AND gap_no == 0
        AND absorbed_no == 0 AND RELEASE_GATE == GREEN.
    Otherwise NOT_COMPLETE. A single fake 'real_verified=295' cannot flip it
    (negative control): gap_no=20 / absorbed_no=313 / RED still disagree.

COMPLETENESS_VERDICT can go RED (NOT_COMPLETE) on current disk; the in-process
negative control proves a gate that cannot fail is decoration. A GREEN path is
exercised on a synthetic in-memory all-green candidate (both red + green).

No writes, no network, no product-tree mutation, no push, no token output,
no untrusted binary exec, no whole .jsonl. Run from W with:
    python -X utf8 setukou-20261111/v5/slices/q1-completeness/verify.py
"""
from __future__ import annotations

import csv
import datetime
import hashlib
import pathlib
import re
import subprocess
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
W = HERE.parent.parent.parent.parent          # .../build-weapon-library-20261110
S = W / "setukou-20261111"


def as_of() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_rows(rel: str) -> tuple[list[dict], list[str] | None]:
    """Read an OWNER-#-comment TSV; return data rows + header fields. Never hard-coded."""
    p = W / rel
    lines = [l for l in p.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    r = csv.DictReader(lines, delimiter="\t")
    return list(r), r.fieldnames


def sha16(rel: str) -> str:
    return hashlib.sha256((W / rel).read_bytes()).hexdigest()[:16]


def decide(real_verified: int, claims_total: int, blockers: int,
           gap_no: int, absorbed_no: int, release_gate: str) -> str:
    """Single completeness rule. COMPLETE only if ALL five conditions hold."""
    complete = (
        real_verified == claims_total
        and claims_total > 0
        and blockers == 0
        and gap_no == 0
        and absorbed_no == 0
        and release_gate == "GREEN"
    )
    return "COMPLETE" if complete else "NOT_COMPLETE"


def main() -> int:
    ts = as_of()

    # ---- 1. 295 claims (v5 SATURATION.tsv working copy; frozen denominator) ----
    sat, _ = read_rows("setukou-20261111/v5/SATURATION.tsv")
    claims_total = len(sat)
    sat_status = Counter(x["status"] for x in sat)
    real_verified = sat_status.get("RUNNABLE_REAL_VERIFIED", 0)
    blockers = sum(1 for x in sat if x["status"] != "RUNNABLE_REAL_VERIFIED")

    # Cross-check frozen denominator against v4 baseline (disk wins).
    rv, _ = read_rows("setukou-20261111/v4/real-verify/REAL-VERIFY.tsv")
    rv_total = len(rv)
    denominator_ok = (rv_total == claims_total)

    # ---- 2. RELEASE_GATE recomputed from the SAME claim statuses ----
    # GREEN iff EVERY publishable claim is RUNNABLE_REAL_VERIFIED (v4 rule, line 74).
    release_gate = "GREEN" if real_verified == claims_total and blockers == 0 else "RED"

    # ---- 3. 28-row gap matrix ----
    gap, _ = read_rows("setukou-20261111/v3/history-gap/GAP-MATRIX.tsv")
    gap_rows = len(gap)
    gap_yes = sum(1 for x in gap if x["behaviour_gate_YES_NO"] == "YES")
    gap_no = sum(1 for x in gap if x["behaviour_gate_YES_NO"] == "NO")

    # ---- 4. 320-row corpus absorption index ----
    cor, _ = read_rows("setukou-20261111/v4/corpus-absorb/CORPUS-INDEX.tsv")
    absorved_rows = len(cor)          # contract's spelling: absorved_rows
    absorbed_yes = sum(1 for x in cor if x["absorbed_into_behaviour_YES_NO"] == "YES")
    absorbed_no = sum(1 for x in cor if x["absorbed_into_behaviour_YES_NO"] == "NO")

    # ---- 5. v1-v4 sealed acceptance counts (v2 5/5, v3 5/5, v4 6/6) ----
    accept_re = re.compile(r"\|\s*\*\*ACCEPTED\*\*\s*\|")
    sealed = {}
    for v in ("v2", "v3", "v4"):
        f = f"setukou-20261111/{v}/ACCEPTANCE-{v.upper()}.md"
        sealed[v] = sum(1 for l in (W / f).read_text(encoding="utf-8").splitlines()
                        if accept_re.search(l))
    v2_v3_v4_accepted_rows = sum(sealed.values())

    # ---- 6. 36 external OWNER-DECISION-REQUIRED actions, all UNEXECUTED ----
    # Primary denominator = the 36 `OWNER DECISION REQUIRED` markers across the
    # two authority decision surfaces (v3 PARENT-V3-SOURCE-KEY.md:22 "all 36").
    #
    # Authoritative state (parent pre-acceptance steer, 2026-11-11): do NOT scan
    # literal `EXECUTED` prose — that is the P09 negation-regex defect
    # (PARENT-PUSH-DETECTOR-FIXTURE.md:5): "No push has been executed" must score
    # positive=0. An action is EXECUTED only if a state surface affirmatively
    # asserts `push_executed=YES` OR a DECISIONS.tsv row loses its
    # NOT-EXECUTED disposition. We recompute from those 4 surfaces only.
    ea = (S / "w5-interface/EXTERNAL-ACTIONS.md").read_text(encoding="utf-8")
    pd = (S / "w0-public/candidate/PUBLISH-DECISIONS.md").read_text(encoding="utf-8")
    rg = (S / "v4/release-gate/RELEASE-GATE.md").read_text(encoding="utf-8")
    dec_text = (S / "v2/owner-card/DECISIONS.tsv").read_text(encoding="utf-8")
    odr_markers = len(re.findall(r"OWNER DECISION REQUIRED", ea)) + \
                  len(re.findall(r"OWNER DECISION REQUIRED", pd))

    # Affirmative executed-state detector: ONLY an unnegated `push_executed=YES`
    # token on the 4 authoritative state surfaces counts as an executed action.
    # Negated / proposed / historical prose is deliberately NOT parsed.
    STATE_SURFACES = {
        "EXTERNAL-ACTIONS.md": ea,
        "PUBLISH-DECISIONS.md": pd,
        "RELEASE-GATE.md": rg,
        "DECISIONS.tsv": dec_text,
    }
    def affirm_push_yes(surfaces: dict[str, str]) -> int:
        return sum(len(re.findall(r"push_executed\s*=\s*YES", t, re.I))
                   for t in surfaces.values())

    # DECISIONS.tsv disposition: a row is EXECUTED only if its
    # proposed_command_NOT_executed column does NOT carry NOT EXECUTED /
    # NOT_EXECUTED / PROPOSED_ONLY. (All 18 currently carry it.)
    dec, _ = read_rows("setukou-20261111/v2/owner-card/DECISIONS.tsv")
    dec_executed = sum(1 for x in dec
                       if not re.search(r"NOT EXECUTED|NOT_EXECUTED|PROPOSED_ONLY|PROPOSED ONLY",
                                        x["proposed_command_NOT_executed"], re.I))
    dec_rows = len(dec)              # independent cross-check denominator (18)

    push_affirm = affirm_push_yes(STATE_SURFACES)
    external_actions_total = odr_markers
    external_actions_executed = dec_executed + (1 if push_affirm > 0 else 0)
    external_actions_unexecuted = external_actions_total - external_actions_executed
    push_executed = "YES" if push_affirm > 0 else "NO"

    # ---- NEGATIVE CONTROL (parent requirement): inject a fake `push_executed=YES`
    # into an in-memory copy of the surface text; the detector MUST fire, proving
    # the checker would FAIL (not silently pass) if a fake execution appeared.
    fake_surfaces = dict(STATE_SURFACES)
    fake_surfaces["EXTERNAL-ACTIONS.md"] = ea + "\nINJECTED_FAKE: push_executed=YES\n"
    fake_push_detected = affirm_push_yes(fake_surfaces) > 0
    fake_control_ok = fake_push_detected   # a gate that cannot catch a fake is decoration

    # ---- 8. live product-tree porcelain 11 / 2 (READ-ONLY) ----
    def porcelain(repo: str) -> int:
        try:
            r = subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                               capture_output=True, text=True, timeout=30)
            return len([x for x in r.stdout.splitlines() if x.strip()])
        except Exception:
            return -1
    pw = porcelain("D:/Software/Tool/WorkStation")
    pdg = porcelain("D:/Software/Tool/WorkStation/debugger")
    live_porcelain_11_2_ok = (pw == 11 and pdg == 2)

    # ---- PRINT: every number with as_of + denominator ----
    print(f"as_of={ts}")
    print(f"source=SATURATION.tsv sha16={sha16('setukou-20261111/v5/SATURATION.tsv')}")
    print(f"claims_total={claims_total} (denominator=rows of v5/SATURATION.tsv) as_of={ts}")
    print(f"  status_split: declared_unverified={sat_status.get('DECLARED_UNVERIFIED',0)} "
          f"missing={sat_status.get('MISSING',0)} owner_gated={sat_status.get('OWNER_GATED',0)} "
          f"runnable_real_verified={real_verified} (denominator={claims_total})")
    print(f"real_verified={real_verified} (denominator={claims_total}) as_of={ts}")
    print(f"blockers={blockers} (denominator={claims_total}; =claims_total-real_verified) as_of={ts}")
    print(f"denominator_frozen_ok={denominator_ok} (v4 REAL-VERIFY rows={rv_total} vs SATURATION rows={claims_total}) as_of={ts}")
    print(f"RELEASE_GATE={release_gate} (denominator={claims_total}; GREEN iff every claim RUNNABLE_REAL_VERIFIED) as_of={ts}")
    print(f"gap_rows={gap_rows} gap_yes={gap_yes} gap_no={gap_no} (denominator={gap_rows}; v3 GAP-MATRIX.tsv) as_of={ts}")
    print(f"absorved_rows={absorved_rows} absorbed_yes={absorbed_yes} absorbed_no={absorbed_no} "
          f"(denominator={absorved_rows}; v4 CORPUS-INDEX.tsv) as_of={ts}")
    print(f"v2_v3_v4_accepted_rows={v2_v3_v4_accepted_rows} "
          f"(denominator=ACCEPTED cells; v2={sealed['v2']} v3={sealed['v3']} v4={sealed['v4']}) as_of={ts}")
    print(f"external_actions_total={external_actions_total} "
          f"external_actions_executed={external_actions_executed} "
          f"external_actions_unexecuted={external_actions_unexecuted} "
          f"(denominator={external_actions_total} OWNER DECISION REQUIRED markers; "
          f"cross_check DECISIONS.tsv rows={dec_rows} executed={dec_executed}) as_of={ts}")
    print(f"odr_markers={odr_markers} (denominator=EXTERNAL-ACTIONS.md + PUBLISH-DECISIONS.md OWNER DECISION REQUIRED strings) as_of={ts}")
    print(f"push_executed={push_executed} (denominator=4 decision/state surfaces) as_of={ts}")
    print(f"live_porcelain WorkStation={pw} debugger={pdg} "
          f"live_porcelain_11_2_ok={live_porcelain_11_2_ok} (denominator=expected 11/2) as_of={ts}")
    verdict = decide(real_verified, claims_total, blockers, gap_no, absorbed_no, release_gate)
    print(f"COMPLETENESS_VERDICT={verdict}")

    # ---- NEGATIVE CONTROL 1: a fake real_verified=295 STILL says NOT_COMPLETE ----
    # because gap_no / absorbed_no / RED disagree. Proves the gate can go RED.
    fake_real = 295
    fake_blockers = claims_total - fake_real
    nc_verdict = decide(fake_real, claims_total, fake_blockers, gap_no, absorbed_no, release_gate)
    nc_ok = (nc_verdict == "NOT_COMPLETE")
    print(f"negative_control: inject real_verified={fake_real} blockers={fake_blockers} "
          f"-> COMPLETENESS_VERDICT={nc_verdict} (expected NOT_COMPLETE; "
          f"gap_no={gap_no} absorbed_no={absorbed_no} RELEASE_GATE={release_gate} disagree) "
          f"negative_control_red_capable={nc_ok} as_of={ts}")

    # ---- NEGATIVE CONTROL 2 (parent requirement): a fake `push_executed=YES`
    # injected into in-memory surface text MUST be detected (checker would FAIL
    # on real disk if such a token appeared). Proves the no-push detector can RED.
    print(f"fake_push_negative_control: inject push_executed=YES into in-memory surface "
          f"-> fake_push_detected={fake_push_detected} (expected True; "
          f"P09 negation defect: 'No push has been executed' scores positive=0) "
          f"fake_control_ok={fake_control_ok} as_of={ts}")

    # ---- GREEN path (both sides exercised): synthetic all-green candidate ----
    green_verdict = decide(claims_total, claims_total, 0, 0, 0, "GREEN")
    green_ok = (green_verdict == "COMPLETE")
    print(f"positive_control: synthetic all-green (real_verified={claims_total} blockers=0 "
          f"gap_no=0 absorbed_no=0 RELEASE_GATE=GREEN) -> COMPLETENESS_VERDICT={green_verdict} "
          f"green_capable={green_ok} as_of={ts}")

    ok = (verdict == "NOT_COMPLETE" and nc_ok and green_ok and denominator_ok
          and fake_control_ok and external_actions_executed == 0 and push_executed == "NO")
    print(f"CHECKER_SELFTEST={'OK' if ok else 'FAIL'} as_of={ts}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
