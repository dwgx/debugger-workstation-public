#!/usr/bin/env python3
"""Frozen real JSON-RPC frontend tests for Router descriptor behavior; no SDK mocking."""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import queue
import shlex
import subprocess
import sys
import threading
import time


def dump(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def payload(response):
    result = response.get('result', {})
    if result.get('isError'):
        return {'error': '\n'.join(x.get('text', '') for x in result.get('content', []))}
    if 'structuredContent' in result:
        return result['structuredContent']
    for item in result.get('content', []):
        if item.get('type') == 'text':
            try:
                return json.loads(item['text'])
            except ValueError:
                pass
    return response


class Frontend:
    def __init__(self, source, root, configs):
        self.root = root
        self.config_path = root / 'MCP/.mcp.json'
        self.config_path.parent.mkdir(parents=True)
        self.write_config(configs)
        outside = root / 'caller elsewhere'
        outside.mkdir()
        env = os.environ.copy()
        env.update(DEBUGGER_ROOT=str(root), PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1',
                   DEBUGGER_ROUTER_STARTUP_TIMEOUT='5', DEBUGGER_ROUTER_TIMEOUT='10',
                   DESCRIPTOR_PRIVATE='synthetic-parent-secret', DESCRIPTOR_INHERITED='selected-parent',
                   DESCRIPTOR_OVERRIDE='from-parent')
        self.stderr = (root / 'router-stderr.bin').open('wb')
        self.proc = subprocess.Popen([sys.executable, '-X', 'utf8', '-B', str(source)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                                     env=env, cwd=outside, start_new_session=os.name != 'nt')
        self.rows = queue.Queue()
        self.sent, self.received = [], []
        self.counter = 0
        def reader():
            for raw in iter(self.proc.stdout.readline, b''):
                try:
                    value = json.loads(raw)
                except ValueError:
                    value = {'invalid_json': raw.decode('utf-8', 'replace')}
                self.received.append(value)
                self.rows.put(value)
        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()
        self.request('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                     'clientInfo': {'name': 'descriptor-acceptance', 'version': '1'}})
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def write_config(self, configs):
        dump(self.config_path, {'mcpServers': configs})

    def send(self, value):
        self.sent.append(value)
        self.proc.stdin.write((json.dumps(value) + '\n').encode('utf-8'))
        self.proc.stdin.flush()

    def request(self, method, params):
        self.counter += 1
        ident = self.counter
        self.send({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params})
        deadline = time.monotonic() + 20
        while True:
            value = self.rows.get(timeout=max(0.01, deadline - time.monotonic()))
            if value.get('id') == ident:
                return value

    def tool(self, name, arguments=None):
        return payload(self.request('tools/call', {'name': name, 'arguments': arguments or {}}))

    def snapshot(self, backend, session_id=None):
        value = self.tool('call_backend_tool', {'backend': backend, 'tool_name': 'snapshot',
                          'arguments_json': '{}', 'session_id': session_id or backend})
        if 'error' in value:
            return value
        return json.loads(value['content'][0]['text'])

    def finish(self):
        rescued = False
        try:
            if self.proc.poll() is None:
                self.tool('close_backend_session', {'session_id': '*'})
                self.proc.stdin.close()
                self.proc.wait(timeout=20)
        except Exception:
            rescued = True
            self.proc.kill()
            self.proc.wait(timeout=5)
        finally:
            self.stderr.close()
            dump(self.root / 'wire-sent.json', self.sent)
            dump(self.root / 'wire-received.json', self.received)
            cleanup = {'router_exit': self.proc.returncode, 'driver_router_rescue': rescued}
            dump(self.root / 'cleanup.json', cleanup)
        return cleanup


def launcher(root, name):
    fixture = Path(__file__).with_name('fixture_backend.py').resolve()
    target = root / (name + '-startup.json')
    path = root / (name + (' launcher.cmd' if os.name == 'nt' else ' launcher.sh'))
    if os.name == 'nt':
        path.write_text('@echo off\r\n"' + sys.executable + '" -X utf8 -B "' + str(fixture) + '" "' + str(target) + '" %*\r\n', encoding='utf-8')
    else:
        path.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -X utf8 -B ' + shlex.quote(str(fixture)) + ' ' + shlex.quote(str(target)) + ' "$@"\n')
        path.chmod(0o700)
    return path


INVALID = [
    ('args_type', 'args', 'bad'), ('args_item', 'args', [1]), ('args_nul', 'args', ['a\x00b']),
    ('cwd_type', 'cwd', []), ('cwd_empty', 'cwd', ''), ('cwd_missing', 'cwd', 'absent-directory'),
    ('env_type', 'env', []), ('env_value', 'env', {'X': 1}), ('env_emptykey', 'env', {'': 'x'}),
    ('env_equalskey', 'env', {'A=B': 'x'}), ('env_nulkey', 'env', {'A\x00B': 'x'}),
    ('env_nulvalue', 'env', {'X': 'a\x00b'}), ('inherit_type', 'env_inherit', '*'),
    ('inherit_item', 'env_inherit', [True]), ('inherit_emptykey', 'env_inherit', ['']),
    ('inherit_equalskey', 'env_inherit', ['A=B']), ('inherit_nulkey', 'env_inherit', ['A\x00B']),
    ('unknown_policy', 'env_policy', 'anything'), ('inherit_missing', 'env_inherit', ['DESCRIPTOR_ABSENT_REQUIRED']),
    ('command_type', 'command', ['bad']), ('command_empty', 'command', ''), ('command_nul', 'command', 'bad\x00command'),
]
if os.name == 'nt':
    INVALID += [('env_case_collision', 'env', {'Path': 'a', 'PATH': 'b'}),
                ('inherit_case_collision', 'env_inherit', ['Path', 'PATH']),
                ('batch_shell_meta', 'args', ['x&echo injected']),
                ('batch_quote', 'args', ['embedded"quote'])]


def run_case(name, source, out):
    root = out / name
    root.mkdir()
    command = str(launcher(root, 'subject'))
    (root / '工作 目录').mkdir()
    configs = {'subject': {'command': command}}
    if name == 'direct_executable_argv':
        configs['subject'] = {'command': sys.executable, 'args': ['-X', 'utf8', '-B', str(Path(__file__).with_name('fixture_backend.py').resolve()), str(root / 'subject-startup.json'), 'embedded\"quote', 'amp&literal', '', '中文'], 'env': {}}
    elif name == 'args_cwd_env':
        configs['subject'].update(args=['space value', '', '中文', 'plain', 'C:\\path with spaces\\tail\\'],
                                  cwd='工作 目录', env={'DESCRIPTOR_OVERRIDE': 'from-descriptor'},
                                  env_inherit=['DESCRIPTOR_INHERITED'])
    elif name == 'strict_empty_args':
        configs['subject']['args'] = []
    elif name == 'isolation_across_backends':
        configs = {'a': {'command': str(launcher(root, 'a')), 'env': {'DESCRIPTOR_BACKEND_ONLY': 'A', 'DESCRIPTOR_OVERRIDE': 'override-A'}},
                   'b': {'command': str(launcher(root, 'b')), 'env': {}},
                   'legacy': {'command': str(launcher(root, 'legacy'))}}
    elif name == 'catalog_redacts_env':
        configs['subject']['env'] = {'DESCRIPTOR_BACKEND_ONLY': 'catalog-must-not-show-this-value'}
    elif name == 'descriptor_change_warm':
        configs['subject']['args'] = ['version-A']
    elif name.startswith('invalid_'):
        _, field, value = next(x for x in INVALID if 'invalid_' + x[0] == name)
        configs['subject'][field] = value
    wire = Frontend(source, root, configs)
    try:
        if name == 'catalog_redacts_env':
            obs = wire.tool('list_backends')
            entry = obs.get('backends', [{}])[0]
            checks = {'policy_reported': entry.get('env_policy') == 'platform-safe',
                      'names_only': entry.get('env_keys') == ['DESCRIPTOR_BACKEND_ONLY'],
                      'value_redacted': 'catalog-must-not-show-this-value' not in json.dumps(obs),
                      'no_spawn': not (root / 'subject-startup.json').exists()}
        elif name.startswith('invalid_'):
            obs = wire.snapshot('subject')
            checks = {'structured_descriptor_rejection': 'INVALID_BACKEND_DESCRIPTOR' in obs.get('error', ''),
                      'no_spawn': not (root / 'subject-startup.json').exists()}
        elif name == 'isolation_across_backends':
            a, b, c = wire.snapshot('a'), wire.snapshot('b'), wire.snapshot('legacy')
            obs = {'a': a, 'b': b, 'legacy': c}
            checks = {'a_override': a.get('env', {}).get('DESCRIPTOR_OVERRIDE') == 'override-A',
                      'b_no_a_value': b.get('env', {}).get('DESCRIPTOR_BACKEND_ONLY') is None,
                      'a_no_private': a.get('env', {}).get('DESCRIPTOR_PRIVATE') is None,
                      'b_no_private': b.get('env', {}).get('DESCRIPTOR_PRIVATE') is None,
                      'parent_unchanged': c.get('env', {}).get('DESCRIPTOR_OVERRIDE') == 'from-parent',
                      'legacy_still_inherits': c.get('env', {}).get('DESCRIPTOR_PRIVATE') == 'synthetic-parent-secret'}
        elif name == 'descriptor_change_warm':
            first = wire.snapshot('subject')
            configs['subject']['args'] = ['version-B']
            wire.write_config(configs)
            old_id = wire.snapshot('subject')
            new_id = wire.snapshot('subject', 'fresh')
            obs = {'first': first, 'old_id': old_id, 'new_id': new_id}
            checks = {'first_args': first.get('argv') == ['version-A'],
                      'changed_same_id_refused': 'DESCRIPTOR_CHANGED' in old_id.get('error', ''),
                      'new_id_uses_new_spec': new_id.get('argv') == ['version-B'],
                      'new_pid': first.get('pid') != new_id.get('pid')}
        else:
            obs = wire.snapshot('subject')
            if name == 'direct_executable_argv':
                checks = {'argv_literal': obs.get('argv') == ['embedded\"quote', 'amp&literal', '', '中文'], 'private_not_inherited': obs.get('env', {}).get('DESCRIPTOR_PRIVATE') is None}
            elif name == 'legacy_command':
                checks = {'no_args': obs.get('argv') == [],
                          'cwd_preserved': obs.get('cwd') == str((root / 'caller elsewhere').resolve()),
                          'legacy_environment': obs.get('env', {}).get('DESCRIPTOR_PRIVATE') == 'synthetic-parent-secret'}
            elif name == 'strict_empty_args':
                checks = {'empty_args': obs.get('argv') == [],
                          'private_not_inherited': obs.get('env', {}).get('DESCRIPTOR_PRIVATE') is None,
                          'path_available': obs.get('system_env_present', {}).get('PATH') is True}
            else:
                checks = {'argv_exact': obs.get('argv') == configs['subject']['args'],
                          'cwd_root_relative': obs.get('cwd') == str((root / '工作 目录').resolve()),
                          'override': obs.get('env', {}).get('DESCRIPTOR_OVERRIDE') == 'from-descriptor',
                          'selected_inheritance': obs.get('env', {}).get('DESCRIPTOR_INHERITED') == 'selected-parent',
                          'private_not_inherited': obs.get('env', {}).get('DESCRIPTOR_PRIVATE') is None,
                          'path_available': obs.get('system_env_present', {}).get('PATH') is True}
        result = {'id': name, 'checks': checks, 'observations': obs, 'pass': all(checks.values())}
    finally:
        cleanup = wire.finish()
    result['cleanup'] = cleanup
    result['pass'] = result['pass'] and cleanup['router_exit'] == 0 and not cleanup['driver_router_rescue']
    dump(root / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    options = parser.parse_args()
    source, out = options.source.resolve(), options.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cases = ['legacy_command', 'direct_executable_argv', 'args_cwd_env', 'strict_empty_args', 'isolation_across_backends',
             'catalog_redacts_env', 'descriptor_change_warm'] + ['invalid_' + x[0] for x in INVALID]
    contract = {'name': 'router-descriptor.2', 'platform': sys.platform, 'case_ids': cases,
                'required_cases': len(cases), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'fixture_sha256': hashlib.sha256(Path(__file__).with_name('fixture_backend.py').read_bytes()).hexdigest(),
                'python': sys.version, 'mcp_version': importlib.metadata.version('mcp'), 'sdk_mocked': False}
    dump(out / 'contract.json', contract)
    results = []
    for name in cases:
        try:
            result = run_case(name, source, out)
        except Exception as error:
            result = {'id': name, 'pass': False, 'driver_error': type(error).__name__ + ': ' + str(error)}
        results.append(result)
        print(name, 'PASS' if result['pass'] else 'FAIL', flush=True)
    report = {'contract': contract, 'results': results, 'passed': sum(r['pass'] for r in results),
              'driver_errors': sum('driver_error' in r for r in results), 'count': len(cases)}
    dump(out / 'results.json', report)
    print(json.dumps({'passed': report['passed'], 'count': report['count'], 'driver_errors': report['driver_errors']}))
    return 0 if report['passed'] == len(cases) else 1


if __name__ == '__main__':
    raise SystemExit(main())
