"""Compare explicit APK MCP error paths through the real, installed SDK.

Python + the provider's existing FastMCP environment are required. Fixtures are
authored inert files in a new output directory. APKTool/Java are never executed.
"""
import argparse
import asyncio
from collections import namedtuple
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from fastmcp import Client


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_source(path, name, workspace):
    argv = sys.argv[:]
    previous = os.environ.get('APKTOOL_WORKSPACE')
    try:
        sys.argv = [str(path), '--workspace', str(workspace)]
        os.environ['APKTOOL_WORKSPACE'] = str(workspace)
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.argv = argv
        if previous is None:
            os.environ.pop('APKTOOL_WORKSPACE', None)
        else:
            os.environ['APKTOOL_WORKSPACE'] = previous


def payload(result):
    if result.structuredContent is not None:
        return result.structuredContent
    text = [block.text for block in result.content if block.type == 'text']
    assert len(text) == 1, text
    return json.loads(text[0])


async def main(args):
    args.output.mkdir(parents=False, exist_ok=False)
    workspace = args.output / 'workspace'
    project = workspace / 'LabProject'
    (project / 'smali/org/example').mkdir(parents=True)
    (project / 'res/values').mkdir(parents=True)
    (project / 'res/raw').mkdir()
    (project / 'res/empty').mkdir()
    (project / 'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example"><application android:label="Error.example"/></manifest>', encoding='utf-8')
    (project / 'apktool.yml').write_text("version: '2.0'\napkFileName: 'synthetic.apk'\n", encoding='utf-8')
    (project / 'smali/org/example/App.smali').write_text('.class public Lorg/example/App;\n.super Ljava/lang/Object;\n# Error.example is successful fixture content\n', encoding='utf-8')
    (project / 'res/values/strings.xml').write_text('<resources><string name="label">Error.example</string></resources>', encoding='utf-8')
    (project / 'res/raw/negative.json').write_text('{"success":false,"error":"inert payload, not a tool failure"}', encoding='utf-8')
    (project / 'res/raw/binary.bin').write_bytes(b'\xff\xfe\x00\x00')
    apk = workspace / 'inert.apk'
    apk.write_bytes(b'authored inert fixture; never decoded by a real process')
    empty = workspace / 'NoMetadata'
    empty.mkdir()
    outside = args.output / 'OutsideWorkspace'
    outside.mkdir()
    (outside / 'AndroidManifest.xml').write_text('<manifest/>', encoding='utf-8')
    missing = workspace / 'MissingProject'
    fixture_hashes = {p.relative_to(args.output).as_posix(): sha(p) for p in args.output.rglob('*') if p.is_file()}
    baseline = load_source(args.baseline, 'apk_error_baseline', workspace)
    candidate = load_source(args.candidate, 'apk_error_candidate', workspace)
    # Pin only test observations with unavoidable timestamps/free-space variance.
    baseline.time = candidate.time = SimpleNamespace(time=lambda: 1700000000.0)
    modules = {'baseline': baseline, 'candidate': candidate}
    cases = []

    def add(name, tool, kwargs, error, **options):
        cases.append({'name': name, 'tool': tool, 'arguments': kwargs, 'expect_error': error, **options})

    required = {
        'build_apk': {}, 'get_manifest': {}, 'get_apktool_yml': {},
        'list_smali_directories': {}, 'list_smali_files': {},
        'get_smali_file': {'class_name': 'org.example.App'},
        'modify_smali_file': {'class_name': 'org.example.App', 'new_content': 'unused'},
        'list_resources': {},
        'get_resource_file': {'resource_type': 'values', 'resource_name': 'strings.xml'},
        'modify_resource_file': {'resource_type': 'values', 'resource_name': 'strings.xml', 'new_content': 'unused'},
        'search_in_files': {'search_pattern': 'missing'}, 'clean_project': {},
        'analyze_project_structure': {},
    }
    for name, extra in required.items():
        add('missing-project-' + name, name, {'project_dir': str(missing), **extra}, True)
    add('missing-apk', 'decode_apk', {'apk_path': str(workspace/'missing.apk')}, True)
    add('missing-workspace', 'get_workspace_info', {}, True, workspace=str(workspace/'Absent'))
    add('health-exception', 'health_check', {}, True, command_exception=True)
    add('manifest-absent', 'get_manifest', {'project_dir': str(empty)}, True)
    add('yaml-absent', 'get_apktool_yml', {'project_dir': str(empty)}, True)
    add('build-metadata-absent', 'build_apk', {'project_dir': str(empty)}, True)
    add('workspace-rejection', 'get_manifest', {'project_dir': str(outside)}, True)
    add('resource-empty-type', 'get_resource_file', {'project_dir': str(project), 'resource_type': '', 'resource_name': 'unused'}, True)
    add('resource-traversal', 'get_resource_file', {'project_dir': str(project), 'resource_type': '../../..', 'resource_name': 'not-read'}, True)
    add('resource-absent', 'get_resource_file', {'project_dir': str(project), 'resource_type': 'values', 'resource_name': 'missing.xml'}, True)
    add('resource-binary', 'get_resource_file', {'project_dir': str(project), 'resource_type': 'raw', 'resource_name': 'binary.bin'}, True)
    add('invalid-class', 'get_smali_file', {'project_dir': str(project), 'class_name': '../Invalid'}, True)
    add('empty-search', 'search_in_files', {'project_dir': str(project), 'search_pattern': ''}, True)
    add('read-permission-exception', 'get_manifest', {'project_dir': str(project)}, True, read_exception=True)
    add('decode-command-failure', 'decode_apk', {'apk_path': str(apk)}, True, command_failure=True)
    add('build-command-failure', 'build_apk', {'project_dir': str(project)}, True, command_failure=True)

    add('manifest-success-with-error-text', 'get_manifest', {'project_dir': str(project)}, False)
    add('yaml-success', 'get_apktool_yml', {'project_dir': str(project)}, False)
    add('smali-directory-success', 'list_smali_directories', {'project_dir': str(project)}, False)
    add('resources-success', 'list_resources', {'project_dir': str(project)}, False)
    add('resource-text-success', 'get_resource_file', {'project_dir': str(project), 'resource_type': 'values', 'resource_name': 'strings.xml'}, False)
    add('resource-false-json-is-data', 'get_resource_file', {'project_dir': str(project), 'resource_type': 'raw', 'resource_name': 'negative.json'}, False)
    add('empty-resource-list-success', 'list_resources', {'project_dir': str(project), 'resource_type': 'empty'}, False)
    add('zero-search-results-success', 'search_in_files', {'project_dir': str(project), 'search_pattern': 'NO_SUCH_AUTHORED_STRING'}, False)
    add('workspace-report-success', 'get_workspace_info', {}, False)
    add('health-available-report', 'health_check', {}, False)
    add('health-unavailable-is-report', 'health_check', {}, False, command_failure=True)
    add('decode-success-warning-unchanged', 'decode_apk', {'apk_path': str(apk)}, False)
    add('build-success-warning-unchanged', 'build_apk', {'project_dir': str(project)}, False)

    results = {'schema': 'apk-explicit-error-regression/1', 'baseline_sha256': sha(args.baseline), 'candidate_sha256': sha(args.candidate), 'runtime': {p: importlib.metadata.version(p) for p in ['fastmcp','mcp','pydantic']}, 'scope': 'Real installed SDK over in-memory MCP transport. Owned inert fixtures; run_command is mocked, no APKTool/Java/process execution. Original wrapper acceptance is separate.', 'cases': []}
    def save():
        (args.output/'RESULTS.json').write_text(json.dumps(results, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    async with Client(baseline.mcp) as old, Client(candidate.mcp) as new:
        old_tools = [t.model_dump(mode='json') for t in await old.list_tools()]
        new_tools = [t.model_dump(mode='json') for t in await new.list_tools()]
        results['catalog_identical'] = old_tools == new_tools
        results['catalog_tools'] = len(old_tools)
        assert results['catalog_identical'] and len(old_tools) == 16
        for case in cases:
            observed = {}
            for label, client in [('baseline', old), ('candidate', new)]:
                module = modules[label]
                module.WORKSPACE_DIR = case.get('workspace', str(workspace))
                command_result = {'success': False, 'error': 'Controlled APKTool command failure', 'stdout': 'retained synthetic stdout', 'stderr': 'retained synthetic stderr', 'returncode': 7, 'command': 'mock apktool'} if case.get('command_failure') else {'success': True, 'stdout': 'Error.example is successful output', 'stderr': '', 'returncode': 0, 'command': 'mock apktool'}
                with patch.object(module, 'run_command', return_value=dict(command_result), side_effect=RuntimeError('controlled health failure') if case.get('command_exception') else None), patch.object(module.shutil, 'disk_usage', return_value=namedtuple('usage', 'total used free')(1000, 300, 700)):
                    if case.get('read_exception'):
                        with patch.object(module, 'open', side_effect=PermissionError('controlled read failure'), create=True):
                            response = await client.call_tool_mcp(case['tool'], case['arguments'])
                    else:
                        response = await client.call_tool_mcp(case['tool'], case['arguments'])
                observed[label] = {'isError': response.isError, 'payload': payload(response), 'raw': response.model_dump(mode='json')}
            same_payload = observed['baseline']['payload'] == observed['candidate']['payload']
            same_success = observed['baseline']['raw'] == observed['candidate']['raw'] if not case['expect_error'] else None
            passed = observed['baseline']['isError'] is False and observed['candidate']['isError'] is case['expect_error'] and same_payload and (case['expect_error'] or same_success)
            results['cases'].append({'name': case['name'], 'tool': case['tool'], 'arguments': case['arguments'], 'expected_error': case['expect_error'], 'baseline_protocol_wrong': case['expect_error'] and observed['baseline']['isError'] is False, 'same_payload': same_payload, 'same_success_envelope': same_success, 'passed': passed, **observed})
            save()
    results['fixture_bytes_unchanged'] = all((args.output/p).is_file() and sha(args.output/p) == h for p,h in fixture_hashes.items())
    results['negative_cases'] = sum(c['expect_error'] for c in cases)
    results['positive_cases'] = len(cases) - results['negative_cases']
    results['passed_cases'] = sum(c['passed'] for c in results['cases'])
    results['denominator'] = len(cases)
    results['all_passed'] = results['passed_cases'] == len(cases) and results['fixture_bytes_unchanged']
    save()
    print(json.dumps({k: results[k] for k in ['runtime','catalog_identical','catalog_tools','negative_cases','positive_cases','passed_cases','denominator','all_passed','fixture_bytes_unchanged']}, indent=2))
    return 0 if results['all_passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    opts = parser.parse_args()
    raise SystemExit(asyncio.run(main(opts)))
