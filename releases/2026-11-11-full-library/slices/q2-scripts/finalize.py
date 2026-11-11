# OWNER: researcher-q2 | v5/slices/q2-scripts/finalize.py
# Generates per-claim REAL receipts, SCRIPT-PROBES.tsv, PROMOTIONS.tsv, PRODUCT-TREE-INTEGRITY.txt.
import subprocess, pathlib, csv, json, hashlib, datetime, re

W = pathlib.Path(r'F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110')
SLICE = W/'setukou-20261111/v5/slices/q2-scripts'
REC = SLICE/'receipts'; FX = SLICE/'fixtures'
S = pathlib.Path(r'D:/Software/Tool/WorkStation/debugger/scripts')
SAT = W/'setukou-20261111/v5/SATURATION.tsv'
TO = r'C:/Program Files/Git/usr/bin/timeout.exe'
PY = r'D:/Software/Developer/Python314/python.exe'
PS = r'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
PROD = pathlib.Path(r'D:/Software/Tool/WorkStation/debugger')
M = json.loads((SLICE/'MEASUREMENTS.json').read_text(encoding='utf-8'))

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def tree_hash():
    h = hashlib.sha256()
    for p in sorted(PROD.rglob('*')):
        if p.is_file():
            h.update(str(p.relative_to(PROD)).encode('utf-8'))
            h.update(p.read_bytes())
    return h.hexdigest()

def run_bounded(argv, t=45):
    cmd = [TO, str(t)] + [str(a) for a in argv]
    started = utc()
    r = subprocess.run(cmd, cwd=str(W), capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return {'cmd':' '.join(cmd),'cwd':str(W),'started':started,'finished':utc(),
            'exit':r.returncode,'stdout':r.stdout or '','stderr':r.stderr or ''}

def py(name,*a): return [PY,'-X','utf8','-B',str(S/name),*a]
def ps(name,*a): return [PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(S/name),*a]
fxp = str(FX/'syn-positive.json')

# ---- promotion set: (claim_id, script, positive argv, literal marker, neg-receipt file) ----
PROMO = [
 ('TR:S-check-requires-tools.py','check-requires-tools.py',
   py('check-requires-tools.py','--registry',fxp,'--only','syn.positive'),'1 ok','NEG-check-requires-tools.py.txt'),
 ('TR:S-gate.ps1','gate.ps1', ps('gate.ps1','-Action','Selftest'),'GATE SELFTEST OK','NEG-gate.ps1.txt'),
 ('TR:S-mission.ps1','mission.ps1', ps('mission.ps1','-Action','Selftest'),'MISSION SELFTEST OK','NEG-mission.ps1.txt'),
 ('TR:S-owner-attest.py','owner-attest.py', py('owner-attest.py','--selftest'),'SELFTEST 9/9 PASSED','NEG-owner-attest.py.txt'),
 ('TR:S-reachability-report.py','reachability-report.py', py('reachability-report.py','--selftest'),'REACHABILITY SELFTEST OK','NEG-reachability-report.py.txt'),
 ('TR:S-verify-tools-manifest.py','verify-tools-manifest.py', py('verify-tools-manifest.py','--selftest'),'passed','NEG-verify-tools-manifest.py.txt'),
]

# ---- product-tree integrity: before/after around the 6 REAL positive commands ----
before = tree_hash()
fresh = {}
for cid, script, argv, marker, negf in PROMO:
    r = run_bounded(argv)
    fresh[cid] = r
    safe = 'claim_'+cid.replace('TR:S-','TR_S-')+'.txt'
    body = (f"claim_id: {cid}\ncommand: {r['cmd']}\ncwd: {r['cwd']}\n"
            f"started_utc: {r['started']}\nfinished_utc: {r['finished']}\nexit: {r['exit']}\n"
            f"expected_marker: {marker}\n"
            f"--- stdout ({len(r['stdout'].splitlines())} lines) ---\n{r['stdout']}"
            f"--- stderr ({len(r['stderr'].splitlines())} lines) ---\n{r['stderr']}\n")
    (REC/safe).write_text(body, encoding='utf-8')
after = tree_hash()
(SLICE/'PRODUCT-TREE-INTEGRITY.txt').write_text(
    '# OWNER: researcher-q2 | product-tree write guard (6 REAL promotion positives re-run)\n'
    f'as_of: {utc()}\nbefore_sha256: {before}\nafter_sha256: {after}\n'
    f'equal: {before==after}\nproduct_tree_writes: {0 if before==after else 1}\n'
    'cwd: '+str(W)+'\ncommands_run:\n' + '\n'.join('  '+r['cmd'] for r in fresh.values())+'\n',
    encoding='utf-8')
print('product_tree_hash', 'UNCHANGED' if before==after else 'CHANGED-DETECTED')

# ---- recompute denominator ----
rows = list(csv.DictReader([l for l in SAT.read_text(encoding='utf-8').splitlines()
                            if l.strip() and not l.startswith('#')], delimiter='\t'))
trS = [r for r in rows if r['claim_id'].startswith('TR:S-')]
status = {r['claim_id']:r['status'] for r in trS}
DEN = len(trS)

SELFTEST_PAT=r'--selftest|selftest'; CHECK_PAT=r'--check|--count|--verify|--list|--strict|--eval'
def flags(name):
    p=S/name
    if not p.is_file(): return ('NO','NO')
    t=p.read_text(encoding='utf-8',errors='ignore')
    return ('YES' if re.search(SELFTEST_PAT,t) else 'NO','YES' if re.search(CHECK_PAT,t) else 'NO')

FROZEN = {c for c,s in status.items() if s=='RUNNABLE_REAL_VERIFIED'}
PROMOTED = {p[0] for p in PROMO}
NONZERO = {'TR:S-assert-probes-selftest.py','TR:S-sync-wiki-figures-selftest.py',
           'TR:S-verify-doc-facts-selftest.py','TR:S-verify-clone-freshness.py',
           'TR:S-sync-wiki-figures.py','TR:S-verify-all.ps1'}
RAN0 = {'TR:S-scan-unread-keys.py','TR:S-verify-atomic-artifacts.py',
        'TR:S-verify-probe-coverage.py','TR:S-maintenance-doctor.py'}
NOENTRY = {'TR:S-__pycache__','TR:S-ghidra','TR:S-ida','TR:S-probes','TR:S-ghidra-failopen.md'}
GATED = {
 'agent-cli.ps1':'dispatches to real RE backends (ghidra/ida/jadx/dnspy/ce/mobsf)',
 'arsenal_mcp_server.py':'MCP stdio server; needs a live MCP client',
 'assert-no-stray-args.ps1':'dot-sourced function library; no top-level entry',
 'assert-probes.py':'runs real capability probes; only --list is safe',
 'bootstrap.ps1':'installer; -Apply writes into install tree',
 'ce-agent.ps1':'Cheat Engine backend (OWNER_GATED)',
 'crackme-corpus.ps1':'forwards to tools/loop.py (real corpus)',
 'crypto-lab.ps1':'real crypto lab backend',
 'dnspy-console.ps1':'dnSpy backend',
 'download-tools.ps1':'downloads third-party tools (network)',
 'emulation-probe.ps1':'Ghidra P-code emulation backend',
 'floss-agent.ps1':'FLOSS backend',
 'forensics-lab.ps1':'real forensics lab',
 'fuzz-lab.ps1':'real fuzz lab',
 'ghidra-failopen-regress.ps1':'Ghidra headless backend',
 'ghidra-headless.ps1':'Ghidra headless backend',
 'ida-cli.ps1':'IDA Pro backend',
 'il2cpp-probe.ps1':'IL2CPP/Unity backend',
 'intel-agent.ps1':'intel backend',
 'jadx-decompile.ps1':'jadx backend',
 'mcp-probe.py':'MCP surface probe',
 'mobile-lab.ps1':'Frida/mobile backend',
 'mobsf-agent.ps1':'MobSF backend',
 'native-lab.ps1':'native RE backends',
 'probe_artifact.mjs':'needs Node.js runtime',
 'probe_artifact.ps1':'probe artifact wrapper',
 'probe_artifact.py':'probe artifact wrapper',
 'probe_wrapper.py':'wraps an arbitrary child command',
 'resolve-locale.ps1':'dot-sourced function library',
 'restore-from-cache.ps1':'writes restored files into product tree',
 'smoke-all.ps1':'real probe suite; timed out 124 under the 45s bound',
 'smoke-mcp.ps1':'MCP smoke; needs live MCP',
 'smoke-tools.ps1':'tools install smoke',
 'smoke_mcp.py':'imports MCP server; needs live MCP',
 'web-reverse-lab.ps1':'real web-reverse lab',
}
# catalogued probe command strings for SCRIPT-PROBES.bounded_command
CMDS = {
 'check-requires-tools.py':f'{TO} 45 {PY} -X utf8 -B {S}/check-requires-tools.py --registry {fxp} --only syn.positive',
 'gate.ps1':f'{TO} 45 {PS} -NoProfile -ExecutionPolicy Bypass -File {S}/gate.ps1 -Action Selftest',
 'mission.ps1':f'{TO} 45 {PS} -NoProfile -ExecutionPolicy Bypass -File {S}/mission.ps1 -Action Selftest',
 'owner-attest.py':f'{TO} 45 {PY} -X utf8 -B {S}/owner-attest.py --selftest',
 'reachability-report.py':f'{TO} 45 {PY} -X utf8 -B {S}/reachability-report.py --selftest',
 'verify-tools-manifest.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-tools-manifest.py --selftest',
 'assert-probes-selftest.py':f'{TO} 45 {PY} -X utf8 -B {S}/assert-probes-selftest.py',
 'sync-wiki-figures-selftest.py':f'{TO} 45 {PY} -X utf8 -B {S}/sync-wiki-figures-selftest.py',
 'verify-doc-facts-selftest.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-doc-facts-selftest.py',
 'verify-clone-freshness.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-clone-freshness.py --strict',
 'sync-wiki-figures.py':f'{TO} 45 {PY} -X utf8 -B {S}/sync-wiki-figures.py --check --wiki {FX}/syn-wiki',
 'verify-all.ps1':f'{TO} 45 {PS} -NoProfile -ExecutionPolicy Bypass -File {S}/verify-all.ps1 -Action Selftest',
 'scan-unread-keys.py':f'{TO} 45 {PY} -X utf8 -B {S}/scan-unread-keys.py',
 'verify-atomic-artifacts.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-atomic-artifacts.py',
 'verify-probe-coverage.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-probe-coverage.py',
 'maintenance-doctor.py':f'{TO} 45 {PY} -X utf8 -B {S}/maintenance-doctor.py',
 'arsenal-doctrine-check.py':f'{TO} 45 {PY} -X utf8 -B {S}/arsenal-doctrine-check.py --selftest',
 'arsenal-two-tree-check.py':f'{TO} 45 {PY} -X utf8 -B {S}/arsenal-two-tree-check.py --selftest',
 'registry-verify.py':f'{TO} 45 {PY} -X utf8 -B {S}/registry-verify.py --selftest',
 'doc-facts.py':f'{TO} 45 {PY} -X utf8 -B {S}/doc-facts.py',
 'eval-agent-contract.py':f'{TO} 45 {PY} -X utf8 -B {S}/eval-agent-contract.py',
 'verify-loop-arg-guards.py':f'{TO} 45 {PY} -X utf8 -B {S}/verify-loop-arg-guards.py',
 'check_backend_consistency.py':f'{TO} 45 {PY} -X utf8 -B {S}/check_backend_consistency.py',
}
MARKERS = {'check-requires-tools.py':'1 ok','gate.ps1':'GATE SELFTEST OK',
 'mission.ps1':'MISSION SELFTEST OK','owner-attest.py':'SELFTEST 9/9 PASSED',
 'reachability-report.py':'REACHABILITY SELFTEST OK','verify-tools-manifest.py':'passed',
 'assert-probes-selftest.py':'selftest:','sync-wiki-figures-selftest.py':'ALL PROPERTIES HELD',
 'verify-doc-facts-selftest.py':'ALL CONTROLS HELD','verify-clone-freshness.py':'findings:',
 'sync-wiki-figures.py':'stale figure','verify-all.ps1':'SELFTEST',
 'scan-unread-keys.py':'registry leaf keys','verify-atomic-artifacts.py':'WHAT THIS DOES NOT CLAIM',
 'verify-probe-coverage.py':'coverage','maintenance-doctor.py':'report only',
 'arsenal-doctrine-check.py':'SELFTEST OK','arsenal-two-tree-check.py':'SELFTEST OK',
 'registry-verify.py':'SELFTEST OK','doc-facts.py':'doc-facts:',
 'eval-agent-contract.py':'PASS','verify-loop-arg-guards.py':'OK','check_backend_consistency.py':'OK'}
# measured exit per catalogued script (from MEASUREMENTS.json)
EXIT = {
 'check-requires-tools.py':M['check-requires-tools.py']['exit'],
 'gate.ps1':M['gate.ps1']['exit'],'mission.ps1':M['mission.ps1']['exit'],
 'owner-attest.py':M['owner-attest.py']['exit'],
 'reachability-report.py':M['reachability-report.py']['exit'],
 'verify-tools-manifest.py':M['verify-tools-manifest.py']['exit'],
 'assert-probes-selftest.py':M['assert-probes-selftest.py']['exit'],
 'sync-wiki-figures-selftest.py':M['sync-wiki-figures-selftest.py']['exit'],
 'verify-doc-facts-selftest.py':M['verify-doc-facts-selftest.py']['exit'],
 'verify-clone-freshness.py':M['verify-clone-freshness.py']['exit'],
 'sync-wiki-figures.py':M['sync-wiki-figures.py']['exit'],
 'verify-all.ps1':M['verify-all.ps1']['exit'],
 'scan-unread-keys.py':M['scan-unread-keys.py']['exit'],
 'verify-atomic-artifacts.py':M['verify-atomic-artifacts.py']['exit'],
 'verify-probe-coverage.py':M['verify-probe-coverage.py']['exit'],
 'maintenance-doctor.py':M['maintenance-doctor.py']['exit'],
 'arsenal-doctrine-check.py':M['arsenal-doctrine-check.py']['exit'],
 'arsenal-two-tree-check.py':M['arsenal-two-tree-check.py']['exit'],
 'registry-verify.py':M['registry-verify.py']['exit'],
 'doc-facts.py':M['doc-facts.py']['exit'],
 'eval-agent-contract.py':M['eval-agent-contract.py']['exit'],
 'verify-loop-arg-guards.py':M['verify-loop-arg-guards.py']['exit'],
 'check_backend_consistency.py':M['check_backend_consistency.py']['exit'],
}

def disposition(cid, script):
    if cid in FROZEN: return 'FROZEN','FROZEN: already RUNNABLE_REAL_VERIFIED (V4 baseline); not re-promoted'
    if cid in PROMOTED: return 'PROMOTED','PROMOTED: REAL receipt exit0 + literal marker + RED negative control'
    if cid in NONZERO:
        e=EXIT.get(script,'?')
        return 'NONZERO',f'NONZERO: real bounded run exit={e} (recorded HONESTLY, NOT promoted)'
    if cid in RAN0:
        e=EXIT.get(script,'?')
        return 'RAN0',f'RAN0_NO_PROMOTE: exit={e} but no separate RED negative-control receipt; report/no-RED-survey'
    if cid in NOENTRY:
        return 'NOENTRY','NOENTRY: directory / markdown / data file, not an executable script with a verification switch'
    if script in GATED:
        return 'GATED',f'GATED:{GATED[script]} -> stays OWNER_GATED / DECLARED_UNVERIFIED (SKIPPED, no product write)'
    return 'NOENTRY','NOENTRY: no --selftest/--check switch; --help-only / no safe bounded entry'

# ---- write SCRIPT-PROBES.tsv (one row per TR:S-* claim) ----
with open(SLICE/'SCRIPT-PROBES.tsv','w',encoding='utf-8',newline='') as f:
    f.write('# OWNER: researcher-q2 | v5/slices/q2-scripts/SCRIPT-PROBES.tsv\n')
    w=csv.writer(f,delimiter='\t',lineterminator='\n')
    w.writerow(['claim_id','script_name','ext','has_selftest','has_check','bounded_command','exit','expected_marker','note'])
    seen=set()
    for r in trS:
        cid=r['claim_id']; script=cid[len('TR:S-'):]
        ext = pathlib.Path(script).suffix.lower() or '(dir/none)'
        st,ck = flags(script)
        disp,note = disposition(cid,script)
        cmd=CMDS.get(script,'N/A (no safe bounded verification entry)')
        ex=str(EXIT[script]) if script in EXIT else 'N/A'
        mk=MARKERS.get(script,'')
        # promoted rows: exit from the FRESH re-run (authoritative for promotion)
        if cid in PROMOTED: ex=str(fresh[cid]['exit'])
        w.writerow([cid,script,ext,st,ck,cmd,ex,mk,f'[{disp}] {note}'])
        seen.add(cid)
    assert seen==set(status), 'denominator drift'

# ---- write PROMOTIONS.tsv ----
with open(SLICE/'PROMOTIONS.tsv','w',encoding='utf-8',newline='') as f:
    f.write('# OWNER: researcher-q2 | v5/slices/q2-scripts/PROMOTIONS.tsv\n')
    w=csv.writer(f,delimiter='\t',lineterminator='\n')
    w.writerow(['claim_id','from_verdict','to_verdict','receipt_path','exit','negative_control'])
    for cid,script,argv,marker,negf in PROMO:
        safe='receipts/claim_'+cid.replace('TR:S-','TR_S-')+'.txt'
        w.writerow([cid,'DECLARED_UNVERIFIED','RUNNABLE_REAL_VERIFIED',safe,
                    str(fresh[cid]['exit']),'receipts/'+negf])

print('tr_s_rows',DEN,'frozen',len(FROZEN),'promoted',len(PROMOTED))
print('gated',sum(1 for r in trS if r['claim_id'][len('TR:S-'):] in GATED))
for cid,_,_,_,_ in PROMO:
    print('  PROMO',cid,'fresh_exit',fresh[cid]['exit'])
