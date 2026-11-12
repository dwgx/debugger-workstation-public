#!/usr/bin/env python3
"""Real Node CLI output contracts against an explicitly owned synthetic fixture.

This does not run payloads, acquire host memory, or invoke external forensic tools.
Use the frozen target shipped with the closeout evidence, or generate an identical
handbuilt target with forensics-lab/lab/mkimage.mjs --out <fresh-directory>.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

IMAGE_SHA = '892cc5802fa8f84cfc2e16ed10542f11fa8d93d5bed47927bb0c9c8802202da5'
COUNTS = {'findings': 3, 'unconfirmed': 1, 'rejected': 2, 'claims': 6}
FINDINGS = {'UNLINKED_PROCESS', 'INJECTED_PRIVATE_RWX_REGION', 'OUTBOUND_CONNECTION:pid-4120'}
TRIAGE_KEYS = {'pslist', 'psscan', 'netscan', 'malfind', 'handlescan'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    a.root, a.fixture, a.out = a.root.resolve(), a.fixture.resolve(), a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    before = inventory(a.fixture)
    if sha(a.fixture / 'd12-lab-image.raw') != IMAGE_SHA:
        raise SystemExit('fixture mismatch: this contract is limited to the frozen handbuilt synthetic image')
    source = a.root / 'forensics-lab/tools/analyze.mjs'
    registry_path = a.root / 'manifests/capabilities.json'
    cap = next(c for c in json.loads(registry_path.read_text(encoding='utf-8-sig'))['capabilities']
               if c['id'] == 'forensics.memory.artefact')
    base = ['node', str(source), '--target', str(a.fixture)]
    declared = [cap['invoke']['runner']] + [v.replace('{target}', str(a.fixture)) for v in cap['invoke']['argv']]
    cases = [
        ('registry_invocation', declared, 0, 'full'),
        ('json', base + ['--json'], 0, 'full'),
        ('legacy_header', base + ['--print-header'], 0, 'header'),
        ('human', base, 0, 'human'),
        ('expect_exact', base + ['--expect', ','.join(sorted(FINDINGS)), '--json'], 0, 'full'),
        ('expect_wrong', base + ['--expect', 'NOT_A_FINDING', '--json'], 4, 'empty'),
        ('ambiguous_output', base + ['--json', '--print-header'], 2, 'empty'),
    ]
    rows = []
    for name, cmd, code, kind in cases:
        run = subprocess.run(cmd, cwd=a.root, capture_output=True, timeout=30)
        (a.out / (name + '.stdout.bin')).write_bytes(run.stdout)
        (a.out / (name + '.stderr.bin')).write_bytes(run.stderr)
        checks = {'exit': run.returncode == code}
        text = run.stdout.decode('utf-8', errors='replace')
        try:
            if kind == 'full':
                obj = json.loads(text)
                checks.update(ok=obj.get('ok') is True,
                              schema=obj.get('schema') == 'forensics-lab/analysis@1',
                              triage=isinstance(obj.get('triage'), dict) and set(obj['triage']) == TRIAGE_KEYS,
                              counts=obj.get('counts') == COUNTS,
                              findings={f['id'] for f in obj.get('findings', [])} == FINDINGS)
            elif kind == 'header':
                obj = json.loads(text)
                checks['unchanged_header_shape'] = set(obj) == TRIAGE_KEYS and 'ok' not in obj
            elif kind == 'human':
                checks['human_summary'] = 'D12 forensics lab' in text and 'FINDINGS (3)' in text
            elif kind == 'empty':
                checks['no_success_output'] = not text.strip()
        except (ValueError, TypeError, KeyError):
            checks['structured_contract'] = False
        rows.append({'id': name, 'argv': cmd, 'expected_exit': code, 'exit': run.returncode,
                     'checks': checks, 'pass': all(checks.values())})
    unchanged = inventory(a.fixture) == before
    result = {'contract': 'forensics-output.2', 'platform': sys.platform, 'synthetic_only': True,
              'source_sha256': sha(source), 'registry_sha256': sha(registry_path),
              'driver_sha256': sha(Path(__file__)), 'fixture': before, 'fixture_unchanged': unchanged,
              'cases': rows, 'passed': sum(r['pass'] for r in rows), 'count': len(rows)}
    (a.out / 'results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ['contract', 'platform', 'source_sha256', 'registry_sha256',
                                          'driver_sha256', 'fixture_unchanged', 'passed', 'count']}))
    return 0 if unchanged and result['passed'] == result['count'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
