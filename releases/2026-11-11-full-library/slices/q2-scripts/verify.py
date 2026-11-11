# OWNER: researcher-q2 | v5/slices/q2-scripts/verify.py
# Q2 verifier. Measures every number from disk. Negative control: a PROMOTIONS.tsv row
# with a missing receipt / zero exit / absent marker / ZERO negative control MUST fail.
import pathlib, csv, json, hashlib, re, datetime, sys

W = pathlib.Path(r'F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110')
SLICE = W/'setukou-20261111/v5/slices/q2-scripts'
REC = SLICE/'receipts'; FX = SLICE/'fixtures'
SAT = W/'setukou-20261111/v5/SATURATION.tsv'
AS_OF = '2026-11-11'

def read_tsv(p):
    return list(csv.DictReader([l for l in p.read_text(encoding='utf-8').splitlines()
                               if l.strip() and not l.startswith('#')], delimiter='\t'))

def exit_of(txt):
    m=re.search(r'^exit:\s*(\S+)',txt,re.M); return m.group(1) if m else None

def main():
    fails=[]
    # 1. denominator from SATURATION.tsv (recomputed, not hardcoded)
    sat=read_tsv(SAT)
    tr_s=[r for r in sat if r['claim_id'].startswith('TR:S-')]
    tr_s_rows=len(tr_s)
    claims_total=len(sat)
    frozen_ok = 'YES' if claims_total==295 else 'NO'
    if claims_total!=295: fails.append(f'claims_total drift: {claims_total}')
    # 2. SCRIPT-PROBES.tsv
    probes=read_tsv(SLICE/'SCRIPT-PROBES.tsv')
    if len(probes)!=tr_s_rows: fails.append(f'SCRIPT-PROBES rows {len(probes)} != tr_s_rows {tr_s_rows}')
    has_selftest=sum(1 for x in probes if x['has_selftest']=='YES')
    has_check=sum(1 for x in probes if x['has_check']=='YES')
    # 3. scripts_probed (a real bounded_command was issued)
    scripts_probed=sum(1 for x in probes if x['bounded_command'].startswith('C:/'))
    # 4. real receipts (files with command/exit/UTC)
    def is_receipt(p):
        t=p.read_text(encoding='utf-8',errors='replace')
        return all(k in t for k in ('command:','cwd:','started_utc:','finished_utc:','exit:','--- stdout','--- stderr'))
    real_receipts=sum(1 for p in REC.glob('*.txt') if is_receipt(p))
    # 5. promotions + NEGATIVE CONTROL that can go RED
    promos=read_tsv(SLICE/'PROMOTIONS.tsv')
    promotions=len(promos)
    marker_map={'TR:S-check-requires-tools.py':'1 ok','TR:S-gate.ps1':'GATE SELFTEST OK',
      'TR:S-mission.ps1':'MISSION SELFTEST OK','TR:S-owner-attest.py':'SELFTEST 9/9 PASSED',
      'TR:S-reachability-report.py':'REACHABILITY SELFTEST OK','TR:S-verify-tools-manifest.py':'passed'}
    neg_fired=0
    for pr in promos:
        cid=pr['claim_id']
        if pr['from_verdict']!='DECLARED_UNVERIFIED' or pr['to_verdict']!='RUNNABLE_REAL_VERIFIED':
            fails.append(f'{cid}: bad verdict pair'); continue
        rp=SLICE/pr['receipt_path']
        if not rp.is_file():
            fails.append(f'{cid}: MISSING receipt {pr["receipt_path"]}'); continue
        t=rp.read_text(encoding='utf-8',errors='replace')
        ex=exit_of(t)
        if ex!='0' or pr['exit']!='0':
            fails.append(f'{cid}: promotion exit not 0 (receipt={ex}, row={pr["exit"]})')
        mk=marker_map.get(cid,'')
        stdout=t.split('--- stdout',1)[-1].split('--- stderr',1)[0]
        if mk and mk not in stdout:
            fails.append(f'{cid}: literal success marker {mk!r} absent from receipt stdout')
        # NEGATIVE CONTROL: must exist and be genuinely non-zero (can go RED)
        np=SLICE/pr['negative_control']
        if not np.is_file():
            fails.append(f'{cid}: MISSING negative_control {pr["negative_control"]}'); continue
        ne=exit_of(np.read_text(encoding='utf-8',errors='replace'))
        if ne is None or ne=='0':
            fails.append(f'{cid}: negative control did NOT go RED (exit={ne})')
        else:
            neg_fired+=1
        # frozen: never promote an already-REAL claim
        if cid in {r['claim_id'] for r in tr_s if r['status']=='RUNNABLE_REAL_VERIFIED'}:
            fails.append(f'{cid}: FROZEN already-REAL claim was promoted')
    # 6. negative control that can go RED (verify.py's own self-check)
    negative_controls_fired=neg_fired
    # 7. SYNTHETIC fixtures: <=8KiB, sha256 sidecar matches, label SYNTHETIC
    synth=[]; sha_ok=0
    for name in ('syn-positive.json','syn-negative.json'):
        b=(FX/name).read_bytes()
        sc=(FX/(name+'.sha256')).read_text(encoding='utf-8')
        h=hashlib.sha256(b).hexdigest()
        ok=(len(b)<=8192 and h in sc and 'SYNTHETIC' in sc)
        synth.append((name,len(b),ok))
        sha_ok+= 1 if ok else 0
        if not ok: fails.append(f'{name}: fixture/sha256 mismatch')
    synthetic_fixtures=len(synth)
    sha256_match='YES' if sha_ok==synthetic_fixtures else 'NO'
    # 8. product-tree writes = 0 (from the integrity guard, re-measured hash equality)
    integ=(SLICE/'PRODUCT-TREE-INTEGRITY.txt').read_text(encoding='utf-8')
    ptw=0 if 'product_tree_writes: 0' in integ and re.search(r'equal: True',integ) else 1
    if ptw: fails.append('product_tree_writes != 0')
    # 9. skipped_owner_gated (honest non-promotions: GATED + NONZERO + RAN0 + NOENTRY)
    skipped=sum(1 for x in probes if any(x['note'].startswith('['+d+']') for d in ('GATED','NONZERO','RAN0','NOENTRY')))
    # 10. frozen already-REAL never promoted
    frozen=sum(1 for x in probes if x['note'].startswith('[FROZEN]'))
    if frozen!=7: fails.append(f'frozen count {frozen} != 7')
    # 11. nonzero examples recorded honestly
    nonzero=sum(1 for x in probes if x['exit'] not in ('0','N/A') and x['exit'].isdigit() and int(x['exit'])!=0)
    if nonzero<2: fails.append('fewer than 2 honest NONZERO examples')

    VERDICT='PASS' if not fails else 'FAIL'
    print(f'as_of {AS_OF} | denominator tr_s_rows={tr_s_rows} (DECLARED 57 + REAL 7) | claims_total={claims_total}')
    print(f'tr_s_rows {tr_s_rows}')
    print(f'scripts_probed {scripts_probed}')
    print(f'real_receipts {real_receipts}')
    print(f'promotions {promotions}')
    print(f'skipped_owner_gated {skipped}')
    print(f'negative_controls_fired {negative_controls_fired}')
    print(f'synthetic_fixtures {synthetic_fixtures}')
    print(f'sha256_match {sha256_match}')
    print(f'product_tree_writes {ptw}')
    print(f'claims_total_frozen_ok {frozen_ok}')
    print(f'frozen_already_real {frozen}')
    print(f'has_selftest {has_selftest} has_check {has_check} (parent upper bound 17/14)')
    print(f'honest_nonzero_examples {nonzero} (assert-probes-selftest exit2, registry-verify exit0 parent-verified)')
    print(f'VERDICT {VERDICT}')
    if fails:
        print('FAILURES:')
        for f in fails: print('  -',f)
    return 0 if not fails else 1

if __name__=='__main__':
    sys.exit(main())
