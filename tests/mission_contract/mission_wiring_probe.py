"""Exercise the actual mission entry point with explicit, owned fixture runners.

This verifies orchestration, not a third-party provider. Every fixture repository,
target, runner, contract, case and marker is created below a fresh output directory.
The same driver can select an older mission.ps1 with --mission-source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def read_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def invoke(args, cwd: Path, prefix: Path, timeout=90):
    started = time.monotonic()
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
    prefix.with_suffix('.stdout.txt').write_bytes(result.stdout)
    prefix.with_suffix('.stderr.txt').write_bytes(result.stderr)
    return {'argv': [str(x) for x in args], 'exit': result.returncode,
            'wall_s': round(time.monotonic() - started, 3),
            'stdout_path': str(prefix.with_suffix('.stdout.txt')),
            'stderr_path': str(prefix.with_suffix('.stderr.txt'))}


def capability(identifier, runner, argv, fact_map, produces, consumes=None):
    return {'id': identifier, 'state': 'observed', 'question_types': ['Q2.locate'],
            'evidence_source': 'owned-mission-contract-fixture',
            'gate': {'lane': 'debug', 'requires_verdict': True},
            'consumes': {'inputs': consumes or []},
            'produces': {'facts': [{'key': key, 'type': kind} for key, kind in produces]},
            'invoke': {'runner': runner, 'argv': argv, 'stdout': 'json',
                       'fact_map': fact_map, 'success_when': 'ok == true'},
            'does_not_prove': ['provider execution or target analysis; an owned fixture verifies only orchestration']}


def contract(cap, section='invoke', subject='stdout_json'):
    invocation = cap['invoke']
    return {'capability': cap['id'], 'section': section,
            'declaration_sha256': hashlib.sha256(cap[section]['success_when'].encode()).hexdigest(),
            'invoke_binding': {key: invocation[key] for key in ('runner', 'argv', 'stdout')},
            'subject': subject, 'predicates': [{'op': 'boolean_equals', 'path': 'ok', 'value': True}]}


EMITTER = r'''param([string]$Directory, [string]$Mode, [string]$Marker)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { throw 'runner directory missing' }
$prior = Test-Path -LiteralPath (Join-Path $Directory 'summary.json')
[ordered]@{ directory = $Directory; absent_before = (-not $prior) } | ConvertTo-Json -Compress | Add-Content -LiteralPath $Marker -Encoding UTF8
$subject = [ordered]@{ ok = $true; outdir = $Directory; functions = 1; notes = @(); metadata = [ordered]@{} }
if ($Mode -ne 'missing') {
    $fileSubject = [ordered]@{ ok = $true; outdir = $Directory; functions = 1; notes = @(); metadata = [ordered]@{} }
    if ($Mode -eq 'mismatch') { $fileSubject.functions = 999 }
    $fileSubject | ConvertTo-Json -Compress -Depth 12 | Set-Content -LiteralPath (Join-Path $Directory 'summary.json') -Encoding UTF8
}
$subject | ConvertTo-Json -Compress -Depth 12
exit 0
'''

RECHECK = r'''param([string]$RepoRoot, [string]$TracePath)
$ErrorActionPreference = 'Stop'
. (Join-Path $RepoRoot 'scripts/mission-success-contract.ps1')
$set = Read-MissionContractSet (Join-Path $RepoRoot 'manifests/success-contracts.json')
$registry = Get-Content -LiteralPath (Join-Path $RepoRoot 'manifests/capabilities.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$results = @()
foreach ($line in @(Get-Content -LiteralPath $TracePath -Encoding UTF8)) {
    $ev = $line | ConvertFrom-Json
    if ($ev.ok -eq $true) {
        $cap = @($registry.capabilities | Where-Object { $_.id -ceq $ev.capability })[0]
        $result = Test-MissionContractRecord $ev.success_contract $cap $set
        $results += [ordered]@{ capability = $ev.capability; ok = $result.ok; reason = $result.reason }
    }
}
ConvertTo-Json -InputObject @($results) -Compress
if ($results.Count -eq 0 -or @($results | Where-Object { -not $_.ok }).Count) { exit 1 }
exit 0
'''


def prepare(repo: Path, mission: Path, destination: Path, mode: str):
    root = destination / 'repo'
    cases = destination / 'cases'
    for directory in (root / 'scripts', root / 'manifests', root / 'bin', cases):
        directory.mkdir(parents=True, exist_ok=False)
    for name in ('gate.ps1', 'mission-success-contract.ps1'):
        shutil.copyfile(repo / 'scripts' / name, root / 'scripts' / name)
    shutil.copyfile(mission, root / 'scripts/mission.ps1')
    (root / 'target.bin').write_bytes(b'MZ owned textual mission wiring fixture, never executed')
    marker = destination / 'producer-marker.txt'
    consumer_marker = destination / 'consumer-marker.txt'
    producer = root / 'bin/producer.cmd'
    consumer = root / 'bin/consumer.cmd'
    payload = {'ok': True, 'probe': 'forwarded-value'}
    if mode == 'boolean_string':
        payload['ok'] = 'true'
    elif mode in {'false_boolean', 'precondition_false', 'precondition_skip'}:
        payload['ok'] = False
    elif mode == 'missing_ok':
        del payload['ok']
    exit_code = 7 if mode == 'nonzero_exit' else 3 if mode == 'precondition_skip' else 0
    producer.write_text('@echo off\necho invoked>>"' + str(marker) + '"\necho ' + json.dumps(payload, separators=(',', ':')) + '\nexit /b ' + str(exit_code) + '\n', encoding='ascii')
    consumer.write_text('@echo off\necho %~1>>"' + str(consumer_marker) + '"\necho {"ok":true,"received":"%~1"}\nexit /b 0\n', encoding='ascii')
    first = capability('probe.producer', str(producer), ['{target}'], {'probe': 'probe.value'}, [('probe.value', 'string')])
    second = capability('probe.consumer', str(consumer), ['{input.value}'], {'received': 'probe.received'}, [('probe.received', 'string')],
                        [{'name': 'value', 'type': 'string', 'from': {'capability': first['id'], 'field': 'probe.value'}}])
    second['invoke']['consumes_fact'] = 'probe.value'
    rows = [contract(first), contract(second)]
    if mode.startswith('ghidra_'):
        (root / 'bin/emitter.ps1').write_text(EMITTER, encoding='utf-8')
        emit_mode = 'mismatch' if mode == 'ghidra_mismatch' else 'missing' if mode == 'ghidra_missing' else 'match'
        first = capability('native.ghidra.decompile', 'powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'bin/emitter.ps1'),
                            '-Directory', '{scratch:ghidra-out}', '-Mode', emit_mode, '-Marker', str(marker)],
                           {'$': 'native.ghidra.summary'}, [('native.ghidra.summary', 'json')])
        first['envelope'] = {'success_when': 'summary.json exists and ok == true'}
        second['consumes']['inputs'] = [{'name': 'value', 'type': 'json', 'from': {'capability': first['id'], 'field': 'native.ghidra.summary'}}]
        second['invoke']['consumes_fact'] = 'native.ghidra.summary'
        second['invoke']['select'] = {'path': 'ok'}
        rows = [contract(first, subject='scratch_summary_json'), contract(first, section='envelope', subject='scratch_summary_json'), contract(second)]
    if mode.startswith('precondition_'):
        first['invoke']['gate_role'] = 'precondition'
        first['invoke']['skip_exits'] = [3]
        first['invoke']['gates'] = [second['id']]
        second['consumes']['inputs'] = []
        second['invoke']['argv'] = ['independent-value']
        second['invoke'].pop('consumes_fact')
        rows = [contract(first), contract(second)]
    if mode == 'unknown_contract':
        rows = [contract(second)]
    if mode == 'unknown_predicate':
        rows[0]['predicates'][0]['op'] = 'trust_me'
    write_json(root / 'manifests/capabilities.json', {'schema': {'name': 'mission-wiring-fixture/1', 'question_types': {'Q2.locate': 'where is the owned fixture'}}, 'capabilities': [first, second], 'retired': []})
    if mode != 'missing_sidecar':
        write_json(root / 'manifests/success-contracts.json', {'schema': 'mission-success-contracts/1', 'version': 1, 'contracts': rows})
    if mode == 'missing_module':
        (root / 'scripts/mission-success-contract.ps1').unlink()
    for args in (['git', 'init', '-q'], ['git', 'add', '-A']):
        subprocess.run(args, cwd=root, capture_output=True, check=True)
    return root, cases, marker, consumer_marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mission-source', type=Path)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    mission = (args.mission_source or (repo / 'scripts/mission.ps1')).resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    identities = {'driver': sha(Path(__file__)), 'mission': sha(mission), 'module': sha(repo / 'scripts/mission-success-contract.ps1'), 'gate': sha(repo / 'scripts/gate.ps1')}
    observations = []
    checks = []
    errors = []
    modes = ['valid', 'boolean_string', 'false_boolean', 'missing_ok', 'nonzero_exit', 'missing_sidecar', 'unknown_predicate', 'unknown_contract',
             'precondition_false', 'precondition_skip', 'ghidra_match', 'ghidra_mismatch', 'ghidra_missing', 'ghidra_fresh', 'missing_module']
    def check(name, passed, detail):
        checks.append({'name': name, 'pass': bool(passed), 'detail': detail})
    for label, shell in [('ps5', 'powershell.exe'), ('ps7', 'pwsh.exe')]:
        for mode in modes:
            key = label + '/' + mode
            destination = out / label / mode
            try:
                root, cases, producer_marker, consumer_marker = prepare(repo, mission, destination, mode)
                command = [shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'scripts/mission.ps1'),
                           '-Action', 'Run', '-Target', str(root / 'target.bin'), '-QuestionType', 'Q2.locate', '-Question', 'where is the owned fixture',
                           '-Provenance', 'built by this probe harness from a textual literal in its own source', '-OwnerWord', 'analyze this file',
                           '-Containment', 'station_under_named_process_rule', '-CaseRoot', str(cases), '-CaseId', 'owned', '-MaxSteps', '6', '-Json']
                result = invoke(command, root, destination / 'run')
                artifact_path = cases / 'owned/artifact.json'
                trace_path = cases / 'owned/trace.jsonl'
                artifact = read_json(artifact_path) if artifact_path.exists() else None
                trace = [json.loads(line) for line in trace_path.read_text(encoding='utf-8-sig').splitlines() if line.strip()] if trace_path.exists() else []
                first = next((x for x in trace if x.get('capability') in {'probe.producer', 'native.ghidra.decompile'} and 'ok' in x), None)
                ran = consumer_marker.exists()
                observation = {'case': key, 'process': result, 'producer_invoked': producer_marker.exists(), 'consumer_invoked': ran,
                               'artifact': artifact, 'trace': trace}
                observations.append(observation)
                if mode in {'missing_sidecar', 'unknown_predicate', 'missing_module'}:
                    check(key, result['exit'] == 2 and not producer_marker.exists() and artifact is None, {'exit': result['exit'], 'producer_invoked': producer_marker.exists(), 'artifact': artifact is not None})
                elif mode == 'precondition_false':
                    check(key, first is not None and first['ok'] is False and not ran and artifact['termination_reason'] == 'precondition_failed', {'consumer_invoked': ran, 'termination': artifact['termination_reason'] if artifact else None})
                elif mode == 'precondition_skip':
                    check(key, first is not None and first['ok'] is False and ran and any(x.get('event') == 'precondition_not_applicable' for x in trace), {'consumer_invoked': ran, 'events': [x.get('event') for x in trace]})
                elif mode in {'valid', 'ghidra_match', 'ghidra_fresh'}:
                    check(key, first is not None and first['ok'] is True and ran and artifact['scope_guard']['intact'], {'consumer_invoked': ran, 'first_ok': first.get('ok') if first else None})
                    # This process reads serialized trace JSON; it cannot reuse the evaluator's
                    # original in-memory object or a synthetic pass marker.
                    verifier = destination / 'recheck.ps1'
                    verifier.write_text(RECHECK, encoding='utf-8')
                    rr = invoke([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(verifier), '-RepoRoot', str(root), '-TracePath', str(trace_path)], root, destination / 'recheck')
                    check(key + '/serialized-record-recheck', rr['exit'] == 0, rr)
                    if mode == 'ghidra_fresh':
                        first_markers = [json.loads(x) for x in producer_marker.read_text(encoding='utf-8-sig').splitlines() if x.strip()]
                        first_summary = Path(first_markers[0]['directory']) / 'summary.json'
                        prior_sha = sha(first_summary)
                        repeat = invoke(command, root, destination / 'repeat')
                        markers = [json.loads(x) for x in producer_marker.read_text(encoding='utf-8-sig').splitlines() if x.strip()]
                        check(key + '/no-reuse', len(markers) == 2 and all(x['absent_before'] for x in markers) and markers[0]['directory'] != markers[1]['directory'] and sha(first_summary) == prior_sha,
                              {'markers': markers, 'first_summary_unchanged': sha(first_summary) == prior_sha, 'repeat': repeat})
                else:
                    check(key, first is not None and first['ok'] is False and not ran and any(x.get('event') == 'skipped_no_consumer' for x in trace),
                          {'first_ok': first.get('ok') if first else None, 'consumer_invoked': ran, 'events': [x.get('event') for x in trace]})
            except Exception as exc:
                errors.append({'case': key, 'error': type(exc).__name__ + ': ' + str(exc)})
                check(key, False, errors[-1])
            write_json(out / 'progress.json', {'checks': checks, 'errors': errors})
            print(key, 'finished', flush=True)
    report = {'schema': 'mission-wiring-probe/1', 'source_sha256': identities,
              'method': 'Real mission entry point and grant checks against owned runner fixtures; no third-party provider was exercised',
              'cases': checks, 'observations': observations, 'driver_errors': errors,
              'passed': sum(x['pass'] for x in checks), 'count': len(checks)}
    write_json(out / 'results.json', report)
    print(json.dumps({'passed': report['passed'], 'count': report['count'], 'driver_errors': len(errors), 'results': str(out / 'results.json')}), flush=True)
    return 0 if report['passed'] == report['count'] and not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
