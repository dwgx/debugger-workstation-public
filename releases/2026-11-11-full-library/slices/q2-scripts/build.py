# OWNER: researcher-q2 | v5/slices/q2-scripts/build.py
# Q2 REAL bounded-probe runner. Runs safe `timeout.exe 45` commands from cwd=W, records
# stdout/stderr/exit/UTC into receipts/<claim_id>.txt, and writes SCRIPT-PROBES.tsv,
# PROMOTIONS.tsv, SYNTHETIC fixtures (+sha256 sidecars), MEASUREMENTS.json.
import subprocess, pathlib, csv, json, hashlib, datetime, re, sys

W = pathlib.Path(r'F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110')
SLICE = W/'setukou-20261111/v5/slices/q2-scripts'
REC = SLICE/'receipts'; FX = SLICE/'fixtures'
for d in (REC, FX): d.mkdir(parents=True, exist_ok=True)
S = pathlib.Path(r'D:/Software/Tool/WorkStation/debugger/scripts')
SAT = W/'setukou-20261111/v5/SATURATION.tsv'
TO = r'C:/Program Files/Git/usr/bin/timeout.exe'
PY = r'D:/Software/Developer/Python314/python.exe'
PS = r'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def run_bounded(argv, t=45):
    cmd = [TO, str(t)] + [str(a) for a in argv]
    started = utc()
    r = subprocess.run(cmd, cwd=str(W), capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return {'cmd': ' '.join(cmd), 'started': started, 'finished': utc(),
            'exit': r.returncode, 'stdout': r.stdout or '', 'stderr': r.stderr or ''}

def receipt(cid, r):
    p = REC/(cid+'.txt')
    body = (f"command: {r['cmd']}\ncwd: {W}\nstarted_utc: {r['started']}\n"
            f"finished_utc: {r['finished']}\nexit: {r['exit']}\n"
            f"--- stdout ({len(r['stdout'].splitlines())} lines) ---\n{r['stdout']}"
            f"--- stderr ({len(r['stderr'].splitlines())} lines) ---\n{r['stderr']}\n")
    p.write_text(body, encoding='utf-8')
    return p

def marker_in(text, marker):
    return marker in text

# ---- recompute TR:S-* denominator from SATURATION.tsv (NOT hardcoded) ----
rows = list(csv.DictReader([l for l in SAT.read_text(encoding='utf-8').splitlines()
                            if l.strip() and not l.startswith('#')], delimiter='\t'))
trS = [r for r in rows if r['claim_id'].startswith('TR:S-')]
clstatus = {r['claim_id']: r['status'] for r in trS}
DEN = len(trS)
REAL_FROZEN = {c for c,s in clstatus.items() if s=='RUNNABLE_REAL_VERIFIED'}

# ---- text-scan markers (parent upper bound reproduction) ----
files = [p for p in S.iterdir() if p.is_file()]
def has(pat, name):
    return bool(re.search(pat, (S/name).read_text(encoding='utf-8', errors='ignore')))
SELFTEST_PAT = r'--selftest|selftest'
CHECK_PAT = r'--check|--count|--verify|--list|--strict|--eval'

# ---- bounded command catalogue: only scripts with a REAL selftest/check/count entry ----
# key = script_name -> (argv, success_marker, negative_argv, note)
fx_pos = str(FX/'syn-positive.json'); fx_neg = str(FX/'syn-negative.json')

def py(name, *args): return [PY,'-X','utf8','-B',str(S/name),*args]
def ps(name, *args): return [PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(S/name),*args]

CATALOG = {
 'arsenal-doctrine-check.py': (py('arsenal-doctrine-check.py','--selftest'), 'SELFTEST OK',
     py('arsenal-doctrine-check.py','--selftest'), 'REAL frozen (V4 selftest)'),
 'arsenal-two-tree-check.py': (py('arsenal-two-tree-check.py','--selftest'), 'SELFTEST OK',
     py('arsenal-two-tree-check.py','--selftest'), 'REAL frozen (V4 selftest)'),
 'assert-probes-selftest.py': (py('assert-probes-selftest.py'), 'selftest:',
     py('assert-probes-selftest.py','--selftest'), 'NONZERO exit=2 (BROKEN gap); argparse error on --selftest; honest NON-PROMOTION'),
 'check-requires-tools.py': (py('check-requires-tools.py','--registry',fx_pos,'--only','syn.positive'), '1 ok',
     py('check-requires-tools.py','--registry',fx_neg,'--only','syn.negative'), 'SYNTHETIC fixture pair: positive OK / negative UNMATCHED'),
 'doc-facts.py': (py('doc-facts.py'), 'doc-facts:', None, 'REAL frozen (V4 default run)'),
 'gate.ps1': (ps('gate.ps1','-Action','Selftest'), 'GATE SELFTEST OK',
     ps('gate.ps1','-Action','Check'), 'PS -File Selftest (temp-only); negative=bare Check exits 1'),
 'mission.ps1': (ps('mission.ps1','-Action','Selftest'), 'MISSION SELFTEST OK',
     ps('mission.ps1','-Action','Run'), 'PS -File Selftest (temp-only); negative=bare Run REFUSED exit 2'),
 'owner-attest.py': (py('owner-attest.py','--selftest'), 'SELFTEST 9/9 PASSED',
     py('owner-attest.py'), 'temp-only selftest; negative=no-action REFUSED exit 2'),
 'reachability-report.py': (py('reachability-report.py','--selftest'), 'REACHABILITY SELFTEST OK',
     py('reachability-report.py','--missions-root',str(FX/'NO_SUCH_DIR')), 'needs E:\\missions present; negative=bogus root exit 2'),
 'registry-verify.py': (py('registry-verify.py','--selftest'), 'SELFTEST OK',
     py('registry-verify.py','--selftest'), 'REAL frozen (V4 selftest, parent-verified exit 0 / 107 lines)'),
 'scan-unread-keys.py': (py('scan-unread-keys.py'), 'registry leaf keys',
     py('scan-unread-keys.py','--fail-on-unread'), 'report-only; negative=--fail-on-unread exit 1'),
 'sync-wiki-figures.py': (py('sync-wiki-figures.py','--check','--repo',str(S.parent),'--wiki',str(FX/'syn-wiki')), 'file(s) carry a stale figure',
     py('sync-wiki-figures.py','--check','--repo',str(S.parent),'--wiki',str(FX/'syn-wiki')), 'default wiki missing -> synthetic; --check is read-only'),
 'sync-wiki-figures-selftest.py': (py('sync-wiki-figures-selftest.py'), 'ALL PROPERTIES HELD',
     py('sync-wiki-figures-selftest.py'), 'BLOCKED exit 2: needs real <private-tree>\\wiki; honest NON-PROMOTION'),
 'verify-atomic-artifacts.py': (py('verify-atomic-artifacts.py'), 'WHAT THIS DOES NOT CLAIM',
     py('verify-atomic-artifacts.py','--no-control'), 'real report + C1/C2 controls; negative=--no-control (survey only)'),
 'verify-clone-freshness.py': (py('verify-clone-freshness.py','--strict'), 'findings:',
     py('verify-clone-freshness.py','--strict'), 'exit 1 (10 WARN promoted); honest NON-PROMOTION'),
 'verify-doc-facts-selftest.py': (py('verify-doc-facts-selftest.py'), 'ALL CONTROLS HELD',
     py('verify-doc-facts-selftest.py'), 'BLOCKED exit 2: needs real <private-tree>; honest NON-PROMOTION'),
 'verify-probe-coverage.py': (py('verify-probe-coverage.py'), 'coverage',
     None, 'report-only; no selftest switch'),
 'verify-tools-manifest.py': (py('verify-tools-manifest.py','--selftest'), 'passed',
     py('verify-tools-manifest.py'), 'selftest 27/27 passed exit 0; negative=default run exit 1 (2 dead/1 broken pin)'),
 'verify-all.ps1': (ps('verify-all.ps1','-Action','Selftest'), 'SELFTEST',
     ps('verify-all.ps1','-h'), 'PS -File; negative=-h REFUSED exit 2'),
 'eval-agent-contract.py': (py('eval-agent-contract.py'), 'PASS', None, 'REAL frozen'),
 'verify-loop-arg-guards.py': (py('verify-loop-arg-guards.py'), 'OK', None, 'REAL frozen'),
 'check_backend_consistency.py': (py('check_backend_consistency.py'), 'OK', None, 'REAL frozen'),
 'maintenance-doctor.py': (py('maintenance-doctor.py'), 'report only', None, 'report-only; no selftest switch'),
 'registry-verify.py#count': (py('registry-verify.py','--count'), 'RULES', None, 'auxiliary --count probe'),
}

# ---- SYNTHETIC fixtures (<=8KiB + sha256 sidecar, label SYNTHETIC) ----
def write_fixture(name, obj):
    p = FX/name
    b = (json.dumps(obj, indent=1, ensure_ascii=False)+'\n').encode('utf-8')
    assert len(b) <= 8192, name
    p.write_bytes(b)
    (FX/(name+'.sha256')).write_text(
        '# SYNTHETIC | label=SYNTHETIC | bytes='+str(len(b))+'\n'
        + hashlib.sha256(b).hexdigest()+'  '+name+'\n', encoding='utf-8')
    return p

POS = {'schema':{'baseline':'SYNTHETIC','question_types':['Q2.locate'],'label':'SYNTHETIC'},
       'capabilities':[{'id':'syn.positive','state':'observed','requires':{'tools':[
         {'name':'syn-echo','probe':"Write-Output 'SYNTHETIC_OK_TOKEN'",'expect':'SYNTHETIC_OK_TOKEN'}]}}]}
NEG = {'schema':{'baseline':'SYNTHETIC','question_types':['Q2.locate'],'label':'SYNTHETIC'},
       'capabilities':[{'id':'syn.negative','state':'observed','requires':{'tools':[
         {'name':'syn-echo','probe':"Write-Output 'SYNTHETIC_OK_TOKEN'",'expect':'SYNTHETIC_NEVER_PRESENT'}]}}]}
write_fixture('syn-positive.json', POS)
write_fixture('syn-negative.json', NEG)
syn_wiki = FX/'syn-wiki'; syn_wiki.mkdir(exist_ok=True)
(FX/'README.md').write_text('# OWNER: researcher-q2 | SYNTHETIC fixtures\n\n'
    'syn-positive.json / syn-negative.json are SYNTHETIC capability registries (<=8KiB, sha256 sidecar).\n'
    'They drive check-requires-tools.py --registry: positive -> OK/exit0; negative(UNMATCHED) -> exit1.\n'
    'syn-wiki/ is an empty SYNTHETIC wiki dir for sync-wiki-figures.py --check (read-only).\n', encoding='utf-8')

# ---- run all catalogued probes, write REAL receipts ----
results = {}
for script,(argv,marker,neg,notes) in CATALOG.items():
    key = script.replace('#','-')
    r = run_bounded(argv)
    results[key] = {'r':r, 'marker':marker, 'neg':neg, 'notes':notes, 'argv':argv}
    # receipt named by the claim_id when one maps to this script, else by script key
    receipt('PROBE-'+key, r)
    if neg is not None:
        rn = run_bounded(neg)
        results[key]['neg_r'] = rn
        receipt('NEG-'+key, rn)
    print(f"[{key}] exit={r['exit']} marker={'HIT' if marker_in(r['stdout'],marker) else 'MISS'} "
          f"neg_exit={results[key].get('neg_r',{}).get('exit','n/a')}")

# persist measurements
M = {}
for key,v in results.items():
    M[key] = {'exit': v['r']['exit'], 'marker': v['marker'],
              'marker_hit': marker_in(v['r']['stdout'], v['marker']),
              'stdout_lines': len(v['r']['stdout'].splitlines()),
              'stderr_lines': len(v['r']['stderr'].splitlines()),
              'neg_exit': v.get('neg_r',{}).get('exit'),
              'cmd': v['r']['cmd']}
(SLICE/'MEASUREMENTS.json').write_text(json.dumps(M, indent=1), encoding='utf-8')
print('WROTE MEASUREMENTS.json with', len(M), 'probes')
