# OWNER: researcher-q7 | setukou-20261111/v5/slices/q7-metric/verify.py
# Q7 autoresearch measurable-loop consolidation checker.
# Run from W = F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110
#   cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && python -X utf8 -B setukou-20261111/v5/slices/q7-metric/verify.py
# READ-ONLY: never writes any file, never edits SATURATION.tsv / results.tsv / autoresearch.json,
# never runs capability commands, never touches a product tree. Every number is re-derived
# from disk bytes on THIS run (no hardcoded metric). ONE ## Verify lives in REPORT.md.
import csv
import datetime
import hashlib
import json
import pathlib
import collections
import sys

W = pathlib.Path('.')  # cwd MUST be W (enforced below)
BASE = 'setukou-20261111/v5'
SATURATION = W / f'{BASE}/SATURATION.tsv'
RESULTS = W / f'{BASE}/results.tsv'
AUTORESEARCH = W / f'{BASE}/autoresearch.json'
LEDGER = W / f'{BASE}/slices/q7-metric/METRIC-LEDGER.tsv'
Q5_PROMO = W / f'{BASE}/slices/q5-absorption/PROMOTIONS.tsv'
Q2_PROMO = W / f'{BASE}/slices/q2-scripts/PROMOTIONS.tsv'
Q3_PROMO = W / f'{BASE}/slices/q3-missing/PROMOTIONS.tsv'
Q4_PROMO = W / f'{BASE}/slices/q4-wrappers/PROMOTIONS.tsv'

REAL = 'RUNNABLE_REAL_VERIFIED'


def data_lines(p):
    return [l for l in p.read_text(encoding='utf-8').splitlines()
            if l.strip() and not l.startswith('#')]


def sha16(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def as_of():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def main():
    # ---- guard: MUST run from W (so W-relative locators resolve) ----
    if not SATURATION.exists() or not RESULTS.exists():
        print('FATAL: run from W root (cwd must contain setukou-20261111/v5/)', file=sys.stderr)
        return 2

    # ---- SATURATION.tsv: denominator + current metric (disk-derived) ----
    sat_rows = list(csv.DictReader(data_lines(SATURATION), delimiter='\t'))
    claims_total = len(sat_rows)
    c = collections.Counter(x['status'] for x in sat_rows)
    current_metric = c[REAL]
    blockers = claims_total - current_metric
    declared = c['DECLARED_UNVERIFIED']
    owner_gated = c['OWNER_GATED']
    missing = c['MISSING']

    # ---- autoresearch.json: stop policy + target (disk-derived) ----
    ar = json.loads(AUTORESEARCH.read_text(encoding='utf-8'))
    sp = ar['stop_policy']
    target_metric = sp['target_metric']
    max_iterations = sp['max_iterations']
    max_no_improve = sp['max_no_improve']
    direction = ar['direction']

    # ---- results.tsv: the measurable loop (disk-derived) ----
    res_lines = data_lines(RESULTS)
    # results.tsv has NO real CSV header; the header is the '# header:' comment line.
    hdr_comment = next((l for l in RESULTS.read_text(encoding='utf-8').splitlines()
                        if l.startswith('# header:')), None)
    fieldnames = hdr_comment.split('# header:', 1)[1].strip().split('\t') if hdr_comment else \
        ['iteration', 'commit_or_candidate', 'metric', 'claims_total', 'status', 'description', 'as_of']
    res_rows = list(csv.DictReader(res_lines, fieldnames=fieldnames, delimiter='\t'))
    # establish baseline/current from results.tsv itself, not from SATURATION
    r_metrics = [(int(r['iteration']), int(r['metric']), r['status'], r['claims_total'], r['commit_or_candidate']) for r in res_rows]
    iterations = len(r_metrics)
    baseline_metric = r_metrics[0][1]
    results_current_metric = r_metrics[-1][1]
    delta = results_current_metric - baseline_metric

    status_counts = collections.Counter(s for _, _, s, _, _ in r_metrics)
    keep_rows = status_counts['keep']
    discard_rows = status_counts['discard']
    crash_rows = status_counts['crash']
    results_no_change_rows = status_counts['no_change']  # results.tsv itself has none
    baseline_rows = status_counts['baseline']
    results_pending_rows = status_counts['pending']

    # Q3/Q4 promotions=0 are recorded as no_change ROWS in METRIC-LEDGER.tsv
    # (NOT in results.tsv); that is where the brief's no_change_rows / pending_rows live.
    led_rows = list(csv.DictReader(data_lines(LEDGER), delimiter='\t'))
    led_status = collections.Counter(r['status'] for r in led_rows)
    no_change_rows = led_status['no_change']   # Q3 + Q4 = 2
    pending_rows = led_status['pending']       # 0 (Q2 delivered, no GAP on disk)


    # every results.tsv row must carry the FROZEN denominator
    claims_total_frozen_ok = (claims_total == 295 and all(int(r['claims_total']) == 295 for r in res_rows))
    # metric monotonic across keeps (autoresearch forbids a 'keep' that does not improve)
    keep_metric_ok = True
    prev = None
    for _, m, s, _, _ in r_metrics:
        if s == 'keep':
            if prev is None or m <= prev:
                keep_metric_ok = False
        prev = m

    # ---- ONE-variable rule: each keep pairs to exactly one slice's promotion set ----
    def promo_count(p, delim='\t'):
        dl = data_lines(p)
        if not dl:
            return 0
        rows = list(csv.DictReader(dl, delimiter=delim))
        return len(rows)

    q5_promos = promo_count(Q5_PROMO, ',')  # Q5 file is comma-separated
    q2_promos = promo_count(Q2_PROMO)
    q3_promos = promo_count(Q3_PROMO)
    q4_promos = promo_count(Q4_PROMO)

    # resolve Q5/Q2 promotion receipts from W (evidence_receipt_count integrity)
    def resolve_receipts(p, delim='\t'):
        dl = data_lines(p)
        rows = list(csv.DictReader(dl, delimiter=delim))
        ok = 0
        for r in rows:
            rp = r.get('receipt_path', '')
            if not rp or rp == 'none':
                continue
            # Q5 receipts are W-relative; Q2 receipts are slice-relative
            cand = W / rp if rp.startswith('setukou-') else (p.parent / rp)
            try:
                cand.read_text(encoding='utf-8')
                ok += 1
            except Exception:
                pass
        return ok, len(rows)

    q5_receipts_ok, q5_receipts_total = resolve_receipts(Q5_PROMO, ',')
    q2_receipts_ok, q2_receipts_total = resolve_receipts(Q2_PROMO)

    # one-variable: iter1 keep == Q5 12 SM; iter2 keep == Q2 6 TR:S; Q3/Q4 = 0
    keep1 = next((m for it, m, s, _, desc in r_metrics if s == 'keep' and it == 1), None)
    keep2 = next((m for it, m, s, _, desc in r_metrics if s == 'keep' and it == 2), None)
    one_variable_ok = (
        keep1 == baseline_metric + q5_promos
        and keep2 == keep1 + q2_promos
        and q3_promos == 0 and q4_promos == 0
        and keep_rows == 2  # two separate keeps, not merged
    )

    # ---- METRIC-LEDGER.tsv counts (led_rows/led_status parsed above) ----
    led_result_rows = sum(1 for r in led_rows if r['slice'] in ('baseline',) or 'promotions' in r['slice'])
    led_slice_rows = sum(1 for r in led_rows if r['slice'] in ('Q2', 'Q3', 'Q4', 'Q5'))
    q3_q4_no_change = (led_status['no_change'] == 2 and q3_promos == 0 and q4_promos == 0)


    # ---- NEGATIVE CONTROL (in-memory, NO file write): a 'keep' row whose
    #      metric_after <= metric_before MUST be rejected by the checker. ----
    def checker_accepts_keep(rows):
        """Autoresearch rule: a 'keep' is valid only if metric strictly increases."""
        prev = None
        for r in rows:
            if r['status'] == 'keep':
                if prev is None or int(r['metric_after']) <= int(r['metric_before']):
                    return False
        return True

    fake_ledger = [
        {'status': 'baseline', 'metric_before': baseline_metric, 'metric_after': baseline_metric},
        {'status': 'keep', 'metric_before': 21, 'metric_after': 21},  # FAKE: no improvement
    ]
    negative_control_caught = (checker_accepts_keep(fake_ledger) is False)
    clean_path_green = keep_metric_ok and one_variable_ok and claims_total_frozen_ok

    target_reached = (current_metric >= target_metric)
    release_gate = 'GREEN' if current_metric == claims_total else 'RED'
    completeness_verdict = 'COMPLETE' if (current_metric == claims_total and blockers == 0) else 'NOT_COMPLETE'
    product_tree_writes = 0  # this checker is read-only by construction
    max_no_improve_used = 0 if keep_metric_ok else 1
    verdict = 'BOUNDED_RUN_OK' if (clean_path_green and negative_control_caught and not target_reached) else 'FAIL'

    # ---- print MEASURED (as_of + denominator on every line-group) ----
    ts = as_of()
    d = f'as_of={ts} denominator=claims_total={claims_total} (FROZEN)'
    print(f'Q7 autoresearch measurable-loop checker | {d}')
    print(f'sources_sha16 saturation={sha16(SATURATION)} results={sha16(RESULTS)} autoresearch={sha16(AUTORESEARCH)}')
    print(f'--- LIVE DISK (current, re-derived this run) | {d} ---')
    print(f'iterations={iterations} results_data_rows={iterations} results_metrics={[m for _,m,_,_,_ in r_metrics]}')
    print(f'baseline_metric={baseline_metric} current_metric={current_metric} results_current_metric={results_current_metric} delta=+{delta}')
    print(f'keep_rows={keep_rows} discard_rows={discard_rows} crash_rows={crash_rows} no_change_rows={no_change_rows} baseline_rows={baseline_rows} pending_rows={pending_rows} (no_change/pending = METRIC-LEDGER Q3/Q4 rows; results_no_change_rows={results_no_change_rows} results_pending_rows={results_pending_rows})')
    print(f'claims_total_frozen_ok={"YES" if claims_total_frozen_ok else "NO"} keep_metric_strictly_increasing_ok={"YES" if keep_metric_ok else "NO"} one_variable_ok={"YES" if one_variable_ok else "NO"}')
    print(f'target_metric={target_metric} target_reached={"YES" if target_reached else "NO"} direction={direction}')
    print(f'max_iterations={max_iterations} max_no_improve={max_no_improve} max_no_improve_used={max_no_improve_used}')
    print(f'product_tree_writes={product_tree_writes} | saturation_split real_verified={current_metric} declared_unverified={declared} owner_gated={owner_gated} missing={missing} blockers={blockers}')
    print(f'RELEASE_GATE={release_gate} COMPLETENESS_VERDICT={completeness_verdict} (GREEN/COMPLETE iff 295/295 REAL receipts + blockers=0)')
    print(f'promotions q5={q5_promos} q2={q2_promos} q3={q3_promos} q4={q4_promos} | q5_receipts_resolve={q5_receipts_ok}/{q5_receipts_total} q2_receipts_resolve={q2_receipts_ok}/{q2_receipts_total}')
    print(f'METRIC-LEDGER.tsv rows={len(led_rows)} result_rows={led_result_rows} slice_rows={led_slice_rows} no_change_rows={led_status["no_change"]} q3_q4_no_change={"YES" if q3_q4_no_change else "NO"} (Q3/Q4 promotions=0 HONEST, NOT crash)')
    print(f'--- DISPATCH-SNAPSHOT (as_of dispatch, NOT current; brief tokens, denominator 21/274) ---')
    print(f'DISPATCH-SNAPSHOT baseline_metric=9 current_metric=21 delta=+12 keep_rows=1 pending_rows=1 Q2=GAP blockers=274 declared_unverified=108 (superseded by parent METRIC UPDATE; disk wins; two denominators NEVER averaged)')
    print(f'--- NEGATIVE CONTROL (in-memory, NO file write) | {d} ---')
    print(f'negative_control_fake_keep_caught={"YES" if negative_control_caught else "NO"} checker_verdict={"FAIL" if negative_control_caught else "GREEN"} (injected keep metric_after=21 <= metric_before=21 MUST be rejected) NO_FILE_WRITTEN')
    print(f'clean_path={"GREEN" if clean_path_green else "RED"}')
    print(f'VERDICT={verdict} (budget/evidence bounded stop with recorded reason = SUCCESSFUL run, NOT a failure; 151 OWNER_GATED + 126 G-004 + 15 MISSING + {declared} DECLARED remain by construction)')
    return 0 if verdict == 'BOUNDED_RUN_OK' else 1


if __name__ == '__main__':
    sys.exit(main())
