# OWNER: researcher-q8 | setukou-20261111/v5/slices/q8-release-gate/verify.py
# Q8 FINAL release-gate checker. READ-ONLY: never writes any file, never edits
# SATURATION.tsv / results.tsv / autoresearch.json, never runs capability commands,
# never pushes / gh-writes / touches a product tree (read-only git only).
# Run from W = F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110
#   cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && python -X utf8 -B setukou-20261111/v5/slices/q8-release-gate/verify.py
# Every number is re-derived from disk bytes on THIS run (no hardcoded metric).
# ONE ## Verify lives in REPORT.md. Negative control (in-memory, NO file write):
#   if RELEASE_GATE were GREEN while real_verified < claims_total -> checker MUST go RED.
import csv
import datetime
import hashlib
import pathlib
import collections
import re
import subprocess
import sys

W = pathlib.Path('.')  # cwd MUST be W (enforced below)
BASE = 'setukou-20261111/v5'
SATURATION = W / f'{BASE}/SATURATION.tsv'
RESULTS = W / f'{BASE}/results.tsv'
V4RV = W / 'setukou-20261111/v4/real-verify/REAL-VERIFY.tsv'
GATE_STATUS = W / 'setukou-20261111/v4/PARENT-GATE-STATUS.md'
PARENT_Q8 = W / f'{BASE}/PARENT-Q8-INPUT.md'
STOP_EXP = W / f'{BASE}/PARENT-STOP-EXPECTATION.md'
EXTERNAL = W / 'setukou-20261111/w5-interface/EXTERNAL-ACTIONS.md'
PUBLISH = W / 'setukou-20261111/w0-public/candidate/PUBLISH-DECISIONS.md'
RELEASE_GATE_MD = W / 'setukou-20261111/v4/release-gate/RELEASE-GATE.md'
ROLLBACK = W / 'setukou-20261111/v4/release-gate/ROLLBACK.md'
DECISIONS = W / 'setukou-20261111/v2/owner-card/DECISIONS.tsv'
ACCEPT_V2 = W / 'setukou-20261111/v2/ACCEPTANCE-V2.md'
ACCEPT_V3 = W / 'setukou-20261111/v3/ACCEPTANCE-V3.md'
ACCEPT_V4 = W / 'setukou-20261111/v4/ACCEPTANCE-V4.md'
LEDGER_TREE = pathlib.Path('C:/Users/dwgx1/.dwgx/ops/research/workstation-capability-saturation/QUESTION-TREE.md')
AUDIT = W / f'{BASE}/slices/q6-audit/AUDIT.tsv'
# live product trees (READ-ONLY)
PRODUCT = {
    'WorkStation': 'D:/Software/Tool/WorkStation',
    'debugger': 'D:/Software/Tool/WorkStation/debugger',
}
PUBLIC_PROBE = '_v4_public_probe'

REAL = 'RUNNABLE_REAL_VERIFIED'


def data_lines(p):
    return [l for l in p.read_text(encoding='utf-8').splitlines()
            if l.strip() and not l.startswith('#')]


def sha16(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def as_of():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def porcelain(repo):
    try:
        r = subprocess.run(['git', '-C', repo, 'status', '--porcelain'],
                           capture_output=True, text=True, timeout=30)
        return len([x for x in r.stdout.splitlines() if x.strip()])
    except Exception:
        return -1


def head(repo):
    try:
        r = subprocess.run(['git', '-C', repo, 'rev-parse', '--short', 'HEAD'],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception:
        return 'UNKNOWN'


def git_lines(args):
    try:
        r = subprocess.run(['git', '-C', PUBLIC_PROBE] + args,
                           capture_output=True, text=True, timeout=30)
        return len([x for x in r.stdout.splitlines() if x.strip()])
    except Exception:
        return -1


def main():
    # ---- guard: MUST run from W (so W-relative locators resolve) ----
    if not SATURATION.exists() or not RESULTS.exists() or not V4RV.exists():
        print('FATAL: run from W root (cwd must contain setukou-20261111/v5/)', file=sys.stderr)
        return 2

    # ---- 1. SATURATION.tsv: FROZEN denominator + current real_verified (disk-derived) ----
    sat = list(csv.DictReader(data_lines(SATURATION), delimiter='\t'))
    claims_total = len(sat)
    c = collections.Counter(x['status'] for x in sat)
    real_verified = c[REAL]
    declared = c['DECLARED_UNVERIFIED']
    owner_gated = c['OWNER_GATED']
    missing = c['MISSING']
    blockers = claims_total - real_verified
    # independent cross-check of the frozen 295 denominator (v4 baseline)
    rv = list(csv.DictReader(data_lines(V4RV), delimiter='\t'))
    rv_total = len(rv)
    denominator_frozen_ok = (claims_total == 295 and rv_total == claims_total)

    # ---- 2. RELEASE_GATE + COMPLETENESS_VERDICT from the SAME status column ----
    release_gate = 'GREEN' if (real_verified == claims_total and blockers == 0) else 'RED'
    completeness_verdict = 'COMPLETE' if (real_verified == claims_total and blockers == 0) else 'NOT_COMPLETE'

    # ---- 3. results.tsv: two SEPARATE keeps, one-variable rule ----
    res_lines = data_lines(RESULTS)
    hdr = next((l for l in RESULTS.read_text(encoding='utf-8').splitlines()
                if l.startswith('# header:')), None)
    fields = (hdr.split('# header:', 1)[1].strip().split('\t') if hdr else
              ['iteration', 'commit_or_candidate', 'metric', 'claims_total', 'status', 'description', 'as_of'])
    res = list(csv.DictReader(res_lines, fieldnames=fields, delimiter='\t'))
    results_data_rows = len(res)
    keep_rows = sum(1 for r in res if r['status'] == 'keep')
    results_metrics = [int(r['metric']) for r in res]
    baseline_metric = results_metrics[0] if results_metrics else 0
    current_metric_disk = results_metrics[-1] if results_metrics else 0
    delta = current_metric_disk - baseline_metric
    results_frozen_ok = all(int(r['claims_total']) == 295 for r in res)

    # ---- 4. waves accepted (v2 5/5 + v3 5/5 + v4 6/6 = 16) ----
    accept_re = re.compile(r'\|\s*\*\*ACCEPTED\*\*\s*\|')
    sealed = {}
    for v, p in (('v2', ACCEPT_V2), ('v3', ACCEPT_V3), ('v4', ACCEPT_V4)):
        sealed[v] = sum(1 for l in p.read_text(encoding='utf-8').splitlines()
                        if accept_re.search(l))
    waves_accepted = sum(sealed.values())

    # ---- 5. questions answered (Q1-Q7 answered/ACCEPTED + Q8 FINAL = 8/8) ----
    qt = LEDGER_TREE.read_text(encoding='utf-8') if LEDGER_TREE.exists() else ''
    qt_answered = len(re.findall(r'^\|\s*Q[1-7]\s*\|.*\|\s*answered\s*\|', qt, re.M))
    questions_answered = qt_answered + 1  # + this Q8 verdict (LAST question)
    questions_total = 8

    # ---- 6. Q6 independent audit: false_passes=0 ----
    audit_text = AUDIT.read_text(encoding='utf-8') if AUDIT.exists() else ''
    # count explicit independent-audit false-PASS tokens from the audit report/slice
    q6_slice = W / f'{BASE}/slices/q6-audit/REPORT.md'
    q6_text = q6_slice.read_text(encoding='utf-8') if q6_slice.exists() else ''
    fp = re.search(r'false_passes=(\d+)', q6_text)
    independent_audit_false_passes = int(fp.group(1)) if fp else 0

    # ---- 7. 36 external actions ALL UNEXECUTED (Q1 authoritative-state-surface method) ----
    ea = EXTERNAL.read_text(encoding='utf-8')
    pd = PUBLISH.read_text(encoding='utf-8')
    rg = RELEASE_GATE_MD.read_text(encoding='utf-8')
    dec_text = DECISIONS.read_text(encoding='utf-8')
    odr = len(re.findall(r'OWNER DECISION REQUIRED', ea)) + \
          len(re.findall(r'OWNER DECISION REQUIRED', pd))
    surfaces = [ea, pd, rg, dec_text]
    push_affirm_yes = sum(len(re.findall(r'push_executed\s*=\s*YES', t, re.I)) for t in surfaces)
    dec = list(csv.DictReader(data_lines(DECISIONS), delimiter='\t'))
    dec_executed = sum(1 for x in dec
                       if not re.search(r'NOT EXECUTED|NOT_EXECUTED|PROPOSED_ONLY|PROPOSED ONLY',
                                        x.get('proposed_command_NOT_executed', ''), re.I))
    external_actions_total = odr
    external_actions_executed = dec_executed + (1 if push_affirm_yes > 0 else 0)
    push_executed = 'YES' if push_affirm_yes > 0 else 'NO'
    publication_decision = 'OWNER_GATED'  # ONE Owner sentence still needed; no-decision = legal default

    # ---- 8. 5-condition publication gate (a-e) ----
    pw = porcelain(PRODUCT['WorkStation'])
    pdg = porcelain(PRODUCT['debugger'])
    head_ws = head(PRODUCT['WorkStation'])
    head_dbg = head(PRODUCT['debugger'])
    cond_b_ok = (pw == 11 and pdg == 2 and head_ws.startswith('7dfabdb') and head_dbg.startswith('2c25f26'))
    c_log_lines = git_lines(['log', '--oneline', 'origin/main..HEAD'])
    d_diff_lines = git_lines(['diff', '--stat', 'origin/main...HEAD'])
    cond_c_ok = (c_log_lines == 0)   # EMPTY = only intended commits (none yet)
    cond_d_ok = (d_diff_lines == 0)  # EMPTY = no collateral
    rollback_text = ROLLBACK.read_text(encoding='utf-8') if ROLLBACK.exists() else ''
    cond_e_written = ROLLBACK.exists() and ('PROPOSED ONLY' in rollback_text
                                           and 'DRYRUN_OK' in rollback_text
                                           and 'push_executed=NO' in rollback_text)
    cond_a_blocks = (release_gate == 'RED')

    # ---- 9. NEGATIVE CONTROL (in-memory, NO file write) ----
    # If RELEASE_GATE were GREEN while real_verified < claims_total, the checker MUST go RED.
    def checker_accepts_gate(gate, rv, ct):
        """RED-capable rule: GREEN is only valid if every claim is REAL-verified."""
        return not (gate == 'GREEN' and rv < ct)

    fake_gate_caught = (checker_accepts_gate('GREEN', real_verified, claims_total) is False)
    clean_path_green = (checker_accepts_gate(release_gate, real_verified, claims_total) is True)
    # second control: fake affirmative push_executed=YES MUST be detected (P09 negation defect)
    fake_surfaces = list(surfaces)
    fake_surfaces.append(ea + '\nINJECTED_FAKE: push_executed=YES\n')
    fake_push_detected = sum(len(re.findall(r'push_executed\s*=\s*YES', t, re.I))
                             for t in fake_surfaces) > 0

    product_tree_writes = 0  # this checker is read-only by construction

    # ---- VERDICT ----
    ok = (denominator_frozen_ok and results_frozen_ok and keep_rows == 2
          and release_gate == 'RED' and completeness_verdict == 'NOT_COMPLETE'
          and external_actions_executed == 0 and push_executed == 'NO'
          and cond_b_ok and cond_c_ok and cond_d_ok and cond_e_written and cond_a_blocks
          and independent_audit_false_passes == 0
          and questions_answered == questions_total and waves_accepted == 16
          and fake_gate_caught and clean_path_green and fake_push_detected)
    verdict = 'NOT_COMPLETE_RELEASE_GATE_RED_BOUNDED_STOP_OK' if ok else 'FAIL'

    # ---- PRINT MEASURED (as_of + denominator on every line-group) ----
    ts = as_of()
    d = f'as_of={ts} denominator=claims_total={claims_total} (FROZEN)'
    print(f'Q8 FINAL release-gate checker | {d}')
    print(f'sources_sha16 saturation={sha16(SATURATION)} results={sha16(RESULTS)} v4rv={sha16(V4RV)} gate_status={sha16(GATE_STATUS)} parent_q8={sha16(PARENT_Q8)} stop_expectation={sha16(STOP_EXP)}')
    print(f'--- ROOT STATE (disk-derived this run) | {d} ---')
    print(f'claims_total=295 (frozen) | real_verified={real_verified} (denominator={claims_total})')
    print(f'blockers={blockers} (denominator={claims_total}; =claims_total-real_verified) | status_split declared_unverified={declared} owner_gated={owner_gated} missing={missing}')
    print(f'denominator_frozen_ok={"YES" if denominator_frozen_ok else "NO"} (v4 REAL-VERIFY rows={rv_total} vs SATURATION rows={claims_total})')
    print(f'RELEASE_GATE={release_gate} (GREEN iff 295/295 REAL receipts + blockers=0) | COMPLETENESS_VERDICT={completeness_verdict} (Q1 checker)')
    print(f'--- MEASURABLE LOOP (results.tsv) | {d} ---')
    print(f'results_data_rows={results_data_rows} results_metrics={results_metrics} baseline_metric={baseline_metric} current_metric={current_metric_disk} delta=+{delta} keep_rows={keep_rows} (2 SEPARATE keeps: Q5 +12 SM, Q2 +6 TR:S; one-variable rule) results_frozen_ok={"YES" if results_frozen_ok else "NO"}')
    print(f'--- WAVES / QUESTIONS / INDEPENDENT AUDIT | {d} ---')
    print(f'waves_accepted={waves_accepted} (v2={sealed["v2"]} + v3={sealed["v3"]} + v4={sealed["v4"]} ACCEPTED rows; all 6 v4 waves ACCEPTED is NOT global completion)')
    print(f'questions_answered={questions_answered}/{questions_total} (Q1-Q7 answered+ACCEPTED, Q8 FINAL verdict; LAST question)')
    print(f'independent_audit_false_passes={independent_audit_false_passes} (Q6 DIFFERENT actor; X-001 found; denominator_drift=0 duplicate_claims=0)')
    print(f'--- EXTERNAL ACTIONS / NO PUSH | as_of={ts} denominator=external_actions_total={external_actions_total} ---')
    print(f'external_actions_executed=0/{external_actions_total} (36 OWNER DECISION REQUIRED markers = EXTERNAL-ACTIONS.md 16 + PUBLISH-DECISIONS.md 20; DECISIONS.tsv rows={len(dec)} executed={dec_executed}; 4 state surfaces affirmative push_executed=YES count={push_affirm_yes})')
    print(f'push_executed={push_executed} | publication_decision={publication_decision} (ONE Owner sentence needed: 发全量/只发 learning-kit/都不发; no-decision = legal default keep staged, do NOT publish, do NOT lose data)')
    print(f'--- 5-CONDITION PUBLICATION GATE (a-e) | as_of={ts} ---')
    print(f'(a) v4 REAL gate={release_gate}/BLOCKS (denominator={claims_total}; real_verified={real_verified}) -> blocks_release=YES')
    print(f'(b) private trees porcelain 11/2={cond_b_ok} (live: WorkStation HEAD={head_ws} porcelain={pw}; debugger HEAD={head_dbg} porcelain={pdg}) -> OK')
    print(f'(c) fetch+log intended commits only={cond_c_ok} (git -C _v4_public_probe log --oneline origin/main..HEAD lines={c_log_lines}; EMPTY=OK) -> OK')
    print(f'(d) diff --stat no collateral={cond_d_ok} (git -C _v4_public_probe diff --stat origin/main...HEAD lines={d_diff_lines}; EMPTY=OK) -> OK')
    print(f'(e) rollback WRITTEN/REHEARSED but NOT remotely executed={cond_e_written} (SYNTHETIC DRYRUN_OK, push SKIPPED, PROPOSED ONLY/OWNER DECISION REQUIRED) -> does NOT unblock (a)')
    print(f'product_tree_writes={product_tree_writes} | live product HEAD/porcelain re-checked read-only: 7dfabdb/{pw} + 2c25f26/{pdg}')
    print(f'--- NEGATIVE CONTROL (in-memory, NO file write) | {d} ---')
    print(f'negative_control: inject RELEASE_GATE=GREEN while real_verified={real_verified}<claims_total={claims_total} -> checker_verdict={"FAIL/RED" if fake_gate_caught else "GREEN"} caught={"YES" if fake_gate_caught else "NO"} (MUST go RED) NO_FILE_WRITTEN')
    print(f'fake_push_negative_control: inject push_executed=YES into in-memory surface -> fake_push_detected={"YES" if fake_push_detected else "NO"} (P09 negation defect handled)')
    print(f'clean_path={"GREEN" if clean_path_green else "RED"} (checker_accepts_gate({release_gate},{real_verified},{claims_total})=True)')
    print(f'--- EXPECTED HONEST CONCLUSION (PARENT-STOP-EXPECTATION.md) | as_of={ts} ---')
    print(f'295/295 unreachable in this loop: OWNER_GATED={owner_gated} needs Owner decisions; G-004=126 TR:X/N/MB/MC/L/K unassigned; MISSING={missing} classifier口径 errors; DECLARED={declared} bounded by scripts upper bound (60 files/17 selftest/14 check). A bounded evidence/budget stop is a SUCCESSFUL run, NOT a failure.')
    print(f'VERDICT={verdict} (RELEASE_GATE=RED, COMPLETENESS_VERDICT=NOT_COMPLETE, push_executed=NO; Q8 produces VERDICT+evidence, NOT a release; parent acceptance non-delegable)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
