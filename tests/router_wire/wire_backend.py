#!/usr/bin/env python
"""Offline JSON-RPC/MCP fixture. No network, samples, GUI, or third-party tools."""
import json
import os
from pathlib import Path
import sys
import subprocess
import time

control = Path(os.environ['ROUTER_AUDIT_CONTROL'])
events = Path(os.environ['ROUTER_AUDIT_EVENTS'])
mode = os.environ.get('ROUTER_AUDIT_MODE', 'normal')
target = None


def log(event, **fields):
    with events.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps({'event': event, 'pid': os.getpid(), 'monotonic': time.monotonic(), **fields}) + '\n')


def wait_release(token):
    log('waiting', token=token)
    while not (control / token).exists():
        time.sleep(0.01)


def reply(request_id, result):
    print(json.dumps({'jsonrpc': '2.0', 'id': request_id, 'result': result}), flush=True)


grandchild = None
if os.environ.get('ROUTER_WIRE_GRANDCHILD') == '1':
    grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log('grandchild_spawn', child_pid=grandchild.pid)
log('spawn')
for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    request_id = message.get('id')
    if method == 'initialize':
        log('initialize')
        if mode == 'hold_initialize':
            wait_release('release_init')
        reply(request_id, {
            'protocolVersion': message['params']['protocolVersion'],
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'offline-router-audit', 'version': '1.0'},
        })
    elif method == 'tools/list':
        reply(request_id, {'tools': [{
            'name': 'audit', 'description': 'Offline controlled state and hold fixture',
            'inputSchema': {'type': 'object', 'properties': {'action': {'type': 'string'}}, 'additionalProperties': True},
        }]})
    elif method == 'tools/call':
        arguments = message['params'].get('arguments', {})
        action = arguments.get('action', 'echo')
        mark = arguments.get('mark')
        log('call_start', action=action, mark=mark)
        if action == 'exit_after_write':
            wait_release('release_exit')
            (control / 'side_effect_happened').write_text(mark or 'yes', encoding='utf-8')
            os._exit(9)
        if action == 'hold':
            wait_release(arguments['token'])
        if action in ('set_target', 'hold') and 'target' in arguments:
            target = arguments['target']
        result = {'pid': os.getpid(), 'target': target, 'mark': mark}
        if action == 'environment':
            result['synthetic_inherited'] = os.environ.get('ROUTER_AUDIT_SYNTHETIC_SECRET') == 'synthetic-not-a-real-secret'
            result['config_env_applied'] = os.environ.get('ROUTER_AUDIT_SCOPED') == 'scoped-fixture-value'
        log('call_finish', action=action, mark=mark, target=target)
        reply(request_id, {'content': [{'type': 'text', 'text': json.dumps(result)}], 'isError': False})
    elif method == 'ping':
        reply(request_id, {})
    else:
        log('notification', method=method)
log('stdin_closed')
