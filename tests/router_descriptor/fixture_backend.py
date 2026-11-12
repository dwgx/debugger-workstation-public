#!/usr/bin/env python3
"""Owned MCP protocol fixture: observes process argv/cwd/synthetic environment."""
import json
import os
from pathlib import Path
import sys

output = Path(sys.argv[1])
snapshot = {
    'pid': os.getpid(),
    'argv': sys.argv[2:],
    'cwd': str(Path.cwd().resolve()),
    'env': {name: os.environ.get(name) for name in (
        'DESCRIPTOR_PRIVATE', 'DESCRIPTOR_INHERITED', 'DESCRIPTOR_OVERRIDE',
        'DESCRIPTOR_BACKEND_ONLY', 'DESCRIPTOR_CASE_VALUE')},
    'system_env_present': {name: bool(os.environ.get(name)) for name in (
        'PATH', 'HOME', 'SYSTEMROOT', 'USERPROFILE')},
}
output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request:
        continue
    method = request.get('method')
    if method == 'initialize':
        result = {'protocolVersion': request['params']['protocolVersion'],
                  'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'descriptor-observer', 'version': '1'}}
    elif method == 'tools/list':
        result = {'tools': [{'name': 'snapshot', 'description': 'Observe owned process inputs.',
                            'inputSchema': {'type': 'object', 'properties': {}}}]}
    elif method == 'tools/call':
        result = {'content': [{'type': 'text', 'text': json.dumps(snapshot, ensure_ascii=False)}],
                  'isError': False}
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}, ensure_ascii=False), flush=True)
