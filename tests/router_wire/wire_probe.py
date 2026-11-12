#!/usr/bin/env python3
"""Real stdio frontend + real MCP SDK + owned synthetic backend. No real provider."""
from __future__ import annotations
import argparse, ctypes, hashlib, importlib.metadata, json, os, queue, shlex
import signal, subprocess, sys, threading, time
from pathlib import Path


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


class Wire:
    def __init__(self, source, root, grandchild=False):
        self.root = root
        root.mkdir(parents=True, exist_ok=False)
        (root / 'MCP').mkdir()
        (root / 'control').mkdir()
        self.events = root / 'events.jsonl'
        backend = Path(__file__).with_name('wire_backend.py').resolve()
        command = root / ('backend launcher.cmd' if os.name == 'nt' else 'backend-launcher.sh')
        if os.name == 'nt':
            command.write_text('@echo off\r\n"' + sys.executable + '" -X utf8 -B "' + str(backend) + '"\r\n', encoding='utf-8')
        else:
            command.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -B ' + shlex.quote(str(backend)) + '\n')
            command.chmod(0o700)
        write_json(root / 'MCP' / '.mcp.json', {'mcpServers': {'fixture': {'command': str(command)}}})
        env = os.environ.copy()
        env.update(DEBUGGER_ROOT=str(root), DEBUGGER_ROUTER_STARTUP_TIMEOUT='5',
                   DEBUGGER_ROUTER_TIMEOUT='30', DEBUGGER_ROUTER_IDLE_TIMEOUT='60',
                   ROUTER_AUDIT_CONTROL=str(root / 'control'), ROUTER_AUDIT_EVENTS=str(self.events),
                   ROUTER_AUDIT_MODE='normal', ROUTER_WIRE_GRANDCHILD='1' if grandchild else '0',
                   PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
        self.err = (root / 'router-stderr.bin').open('wb')
        self.proc = subprocess.Popen([sys.executable, '-X', 'utf8', '-B', str(source)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                     env=env, cwd=root, start_new_session=os.name != 'nt')
        self.messages = queue.Queue()
        self.pending = {}
        self.sent = []
        self.received = []
        self.handles = {}
        self.counter = 1
        def read():
            for raw in iter(self.proc.stdout.readline, b''):
                try:
                    obj = json.loads(raw)
                except Exception:
                    obj = {'unparsed': raw.decode('utf-8', errors='replace')}
                self.received.append({'monotonic': time.monotonic(), 'message': obj})
                self.messages.put(obj)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def initialize(self):
        self.call('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                 'clientInfo': {'name': 'independent-wire-audit', 'version': '1'}})
        self.notify('notifications/initialized', {})

    def send(self, obj):
        self.sent.append({'monotonic': time.monotonic(), 'message': obj})
        self.proc.stdin.write((json.dumps(obj) + '\n').encode('utf-8'))
        self.proc.stdin.flush()

    def notify(self, method, params):
        self.send({'jsonrpc': '2.0', 'method': method, 'params': params})

    def request(self, method, params):
        rid = self.counter
        self.counter += 1
        self.send({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params})
        return rid

    def receive(self, rid, timeout=25):
        end = time.monotonic() + timeout
        while rid not in self.pending:
            obj = self.messages.get(timeout=max(0.01, end - time.monotonic()))
            if 'id' in obj:
                self.pending[obj['id']] = obj
            if time.monotonic() > end:
                raise TimeoutError(f'No response for {rid}')
        return self.pending.pop(rid)

    def call(self, method, params, timeout=25):
        return self.receive(self.request(method, params), timeout)

    def tool(self, name, args=None, timeout=25):
        return self.call('tools/call', {'name': name, 'arguments': args or {}}, timeout)

    def backend(self, args, timeout=25):
        return self.tool('call_backend_tool', {'backend': 'fixture', 'tool_name': 'audit',
                       'arguments_json': json.dumps(args), 'timeout_seconds': timeout, 'session_id': 'subject'})

    def begin_backend(self, args, timeout=20):
        return self.request('tools/call', {'name': 'call_backend_tool', 'arguments': {
            'backend': 'fixture', 'tool_name': 'audit', 'arguments_json': json.dumps(args),
            'timeout_seconds': timeout, 'session_id': 'subject'}})

    def rows(self):
        if not self.events.exists():
            return []
        result = []
        for line in self.events.read_text('utf-8').splitlines():
            try:
                result.append(json.loads(line))
            except ValueError:
                pass
        return result

    def wait_event(self, event, mark=None, timeout=20):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            found = [x for x in self.rows() if x['event'] == event and (mark is None or x.get('mark') == mark)]
            if found:
                self.capture_handles()
                return found[-1]
            time.sleep(0.02)
        raise TimeoutError(f'{event}:{mark}')

    def capture_handles(self):
        if os.name != 'nt':
            return
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
        k.OpenProcess.restype = ctypes.c_void_p
        for row in self.rows():
            for key in ('pid', 'child_pid'):
                pid = row.get(key)
                if pid and pid not in self.handles:
                    h = k.OpenProcess(0x00100000 | 0x1000 | 0x0001, False, pid)
                    if h:
                        self.handles[pid] = h

    def dead(self, pid):
        if os.name == 'nt':
            k = ctypes.WinDLL('kernel32', use_last_error=True)
            k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            k.WaitForSingleObject.restype = ctypes.c_uint
            if pid not in self.handles:
                raise AssertionError('Cannot prove Windows process death without retained handle')
            return k.WaitForSingleObject(self.handles[pid], 0) == 0
        try:
            os.kill(pid, 0)
            stat = Path(f'/proc/{pid}/stat')
            return stat.exists() and stat.read_text().split(') ', 1)[1].split()[0] == 'Z'
        except ProcessLookupError:
            return True

    def wait_closed(self, timeout=25):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            last = payload(self.tool('list_backend_sessions'))
            if any(x['session_id'] == 'subject' for x in last.get('recently_closed', [])):
                return last
            time.sleep(0.05)
        raise TimeoutError(f'No retired session: {last}')

    def finish(self):
        self.capture_handles()
        router_rescue_used = False
        try:
            if self.proc.poll() is None:
                try:
                    self.tool('close_backend_session', {'session_id': '*'}, timeout=22)
                except Exception:
                    pass
                self.proc.stdin.close()
                try:
                    self.proc.wait(20)
                except subprocess.TimeoutExpired:
                    router_rescue_used = True
                    self.proc.terminate()
                    self.proc.wait(5)
        finally:
            self.err.close()
            cleanup = []
            pids = {row[key] for row in self.rows() for key in ('pid', 'child_pid') if key in row}
            for pid in pids:
                try:
                    before = self.dead(pid)
                    if not before:
                        if os.name == 'nt':
                            k = ctypes.WinDLL('kernel32', use_last_error=True)
                            k.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                            k.TerminateProcess(self.handles[pid], 1)
                        else:
                            os.kill(pid, signal.SIGKILL)
                        until = time.monotonic() + 3
                        while not self.dead(pid) and time.monotonic() < until:
                            time.sleep(0.02)
                    cleanup.append({'pid': pid, 'dead_before_driver_cleanup': before, 'dead_after': self.dead(pid)})
                except Exception as exc:
                    cleanup.append({'pid': pid, 'error': repr(exc)})
            if os.name == 'nt':
                k = ctypes.WinDLL('kernel32', use_last_error=True)
                k.CloseHandle.argtypes = [ctypes.c_void_p]
                for h in self.handles.values():
                    k.CloseHandle(h)
            report = {'router_exit': self.proc.returncode, 'router_rescue_used': router_rescue_used,
                      'owned': cleanup,
                      'all_reaped': self.proc.returncode is not None and all(x.get('dead_after') is True for x in cleanup),
                      'all_reaped_without_rescue': self.proc.returncode == 0 and not router_rescue_used
                           and all(x.get('dead_before_driver_cleanup') is True for x in cleanup)}
            write_json(self.root / 'cleanup.json', report)
            write_json(self.root / 'wire-sent.json', self.sent)
            write_json(self.root / 'wire-received.json', self.received)
        return report


def payload(message):
    result = message.get('result', {})
    if 'structuredContent' in result:
        return result['structuredContent']
    blocks = result.get('content', [])
    for block in blocks:
        if block.get('type') == 'text':
            try:
                return json.loads(block['text'])
            except ValueError:
                return {'error_text': block['text'], 'isError': result.get('isError')}
    return message


def case_run(name, wire):
    if name == 'warm_control':
        first = payload(wire.backend({'action': 'set_target', 'target': 'alpha'}))
        second = payload(wire.backend({'action': 'echo'}))
        a, b = json.loads(first['content'][0]['text']), json.loads(second['content'][0]['text'])
        return {'checks': {'same_pid': a['pid'] == b['pid'], 'state_retained': b['target'] == 'alpha'}, 'observed': [first, second]}
    if name in ('wire_inflight_cancel', 'natural_timeout_unknown', 'transport_loss_unknown'):
        action = 'exit_after_write' if name == 'transport_loss_unknown' else 'hold'
        rid = wire.begin_backend({'action': action, 'token': 'never', 'mark': name}, timeout=5)
        wire.wait_event('call_start', name)
        if name == 'transport_loss_unknown':
            (wire.root / 'control' / 'release_exit').write_text('release')
        if name == 'wire_inflight_cancel':
            wire.notify('notifications/cancelled', {'requestId': rid, 'reason': 'owned independent wire audit'})
            ping = wire.call('ping', {})
        else:
            ping = wire.receive(rid, timeout=24)
        closed = wire.wait_closed()
        records = [x for x in closed['recently_closed'] if x['session_id'] == 'subject']
        record = records[-1]
        checks = {'retired': closed['count'] == 0, 'one_closed_generation': len(records) == 1,
                  'unknown_once': record['outcome_unknown'] == 1}
        if name != 'wire_inflight_cancel':
            error = payload(ping)
            checks['request_returned_error'] = ping.get('id') == rid and error.get('isError') is True
            checks['correct_failure_reason'] = ('Connection closed' if name == 'transport_loss_unknown'
                                                else 'call exceeded 5s') in error.get('error_text', '')
        if name == 'transport_loss_unknown':
            side_effect = wire.root / 'control' / 'side_effect_happened'
            checks['side_effect_observed'] = side_effect.is_file() and side_effect.read_text('utf-8') == name
        pids = {x['pid'] for x in wire.rows() if 'pid' in x}
        until = time.monotonic() + 20
        while any(not wire.dead(pid) for pid in pids) and time.monotonic() < until:
            time.sleep(0.02)
        checks['retired_processes_dead_before_finish'] = bool(pids) and all(wire.dead(pid) for pid in pids)
        return {'checks': checks, 'observed': record, 'response': ping}
    if name == 'wire_queued_cancel':
        active = wire.begin_backend({'action': 'hold', 'token': 'release', 'mark': 'first'})
        wire.wait_event('call_start', 'first')
        queued = wire.begin_backend({'action': 'set_target', 'target': 'must-not-set', 'mark': 'queued'})
        wire.call('ping', {})
        wire.notify('notifications/cancelled', {'requestId': queued, 'reason': 'cancel before backend dispatch'})
        wire.call('ping', {})
        (wire.root / 'control' / 'release').write_text('release')
        wire.receive(active)
        result = payload(wire.backend({'action': 'echo', 'mark': 'after'}))
        actual = json.loads(result['content'][0]['text'])
        return {'checks': {'queued_not_executed': not any(x.get('mark') == 'queued' for x in wire.rows()), 'target_unchanged': actual['target'] is None}, 'observed': result}
    if name == 'windows_cmd_grandchild':
        wire.backend({'action': 'echo', 'mark': 'tree'})
        row = wire.wait_event('grandchild_spawn')
        wire.capture_handles()
        pid = row['child_pid']
        alive_before = not wire.dead(pid)
        closed = payload(wire.tool('close_backend_session', {'session_id': 'subject'}))
        end = time.monotonic() + 20
        while not wire.dead(pid) and time.monotonic() < end:
            time.sleep(0.05)
        return {'checks': {'child_was_alive': alive_before, 'child_reaped_before_driver_cleanup': wire.dead(pid)}, 'observed': {'pid': pid, 'closed': closed}}
    raise ValueError(name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--cases', nargs='+', default=['warm_control', 'wire_queued_cancel', 'wire_inflight_cancel', 'natural_timeout_unknown', 'transport_loss_unknown'])
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = []
    for case in args.cases:
        wire = None
        start = time.monotonic()
        try:
            wire = Wire(args.source.resolve(), (args.out / case).resolve(), grandchild=case == 'windows_cmd_grandchild')
            wire.initialize()
            row = case_run(case, wire)
            row['pass'] = all(row['checks'].values())
        except Exception as exc:
            row = {'pass': False, 'error': repr(exc)}
        finally:
            if wire is not None:
                try:
                    cleanup = wire.finish()
                    row['cleanup'] = cleanup
                    row['pass'] = row['pass'] and cleanup['all_reaped_without_rescue']
                except Exception as exc:
                    row['pass'] = False
                    row['cleanup_error'] = repr(exc)
        row.update(case=case, seconds=round(time.monotonic() - start, 3))
        results.append(row)
        print(json.dumps(row), flush=True)
    result = {'contract': 'real-mcp-frontend-owned-synthetic-backend', 'source_sha256': hashlib.sha256(args.source.read_bytes()).hexdigest(),
              'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'backend_sha256': hashlib.sha256(Path(__file__).with_name('wire_backend.py').read_bytes()).hexdigest(),
              'platform': sys.platform, 'mcp': importlib.metadata.version('mcp'), 'SDK_MOCKED': False, 'results': results}
    write_json(args.out / 'results.json', result)
    return 0 if all(x['pass'] for x in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
