#!/usr/bin/env python3
"""Recompute coverage from selected raw LabSession evidence, never from totals."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def case_status(case, cleanup_ok):
    checks = case.get("checks", {})
    semantic = bool(checks) and all(isinstance(v, dict) and "actual" in v and "expected" in v
                                    and v["actual"] == v["expected"] for v in checks.values())
    response = case.get("response", {})
    result = response.get("result")
    protocol = isinstance(result, dict) and "error" not in response
    negative = case.get("kind") == "negative"
    if protocol:
        protocol = result.get("isError", False) is negative
    if "error" in case or not semantic or not protocol or not cleanup_ok:
        return "failed"
    return "expected_rejection" if negative else "positive_pass"


def verify_session(path):
    """Verify record/raw correspondence before accepting assertions as evidence."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    for name in ("requests.jsonl", "responses.jsonl", "stderr.txt"):
        if sha(path.parent / name) != data.get("raw_sha256", {}).get(name):
            raise ValueError("raw evidence hash mismatch: " + str(path.parent / name))
    requests = [json.loads(line) for line in (path.parent / "requests.jsonl").read_text(encoding="utf-8").splitlines() if line]
    responses = []
    noise = []
    for number, line in enumerate((path.parent / "responses.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("jsonrpc") != "2.0" or not ("id" in value or "method" in value):
                raise ValueError("not a JSON-RPC envelope")
            responses.append(value)
        except ValueError:
            noise.append({"line": number, "sha256": hashlib.sha256(line.encode()).hexdigest()})
    data["wire_protocol_clean"] = not noise
    data["stdout_noise"] = noise
    data["wire_audit_scope"] = data.get("stdout_audit", {"scope": "captured raw lines only; legacy record has no post-close queue observation"})
    response_ids = [v["id"] for v in responses if "id" in v]
    if len(response_ids) != len(set(response_ids)):
        raise ValueError("duplicate response ID in raw evidence")
    by_id = {v["id"]: v for v in responses if "id" in v}
    catalog = data.get("catalog_response", {})
    if by_id.get(catalog.get("id")) != catalog or catalog.get("result", {}).get("tools") != data.get("tools"):
        raise ValueError("catalog differs from raw evidence")
    calls = {v["id"]: v for v in requests if v.get("method") == "tools/call" and "id" in v}
    recorded = []
    for case in data.get("cases", []):
        if "response" not in case:
            continue
        ident = case.get("response_id")
        if by_id.get(ident) != case["response"]:
            raise ValueError("case response differs from raw evidence")
        request = calls.get(ident, {}).get("params", {})
        if request.get("name") != case.get("method") or request.get("arguments") != case.get("arguments"):
            raise ValueError("case request differs from raw evidence")
        recorded.append(ident)
    if len(recorded) != len(set(recorded)):
        raise ValueError("one raw call was counted as multiple cases")
    # Requests lacking a response remain failed cases, never silently omitted.
    if len(calls) != len(data.get("cases", [])):
        raise ValueError("raw call / case denominator mismatch")
    return data


def merge_sessions(sessions, catalogs=(), declarations=()):
    backends = {}
    methods = {}
    session_failures = []

    def add_tools(backend, route, tools, origin, evidence, reason=None):
        state = backends.setdefault(backend, {"runtime_observed": False, "source_declared": False, "methods": set(), "runtime_methods": set(), "routes": set()})
        state["runtime_observed" if origin == "runtime" else "source_declared"] = True
        state["routes"].add(route)
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("method declaration lacks a name")
            key = backend + "::" + route + "::" + name
            state["methods"].add(name)
            if origin == "runtime":
                state["runtime_methods"].add(name)
            row = methods.setdefault(key, {"backend": backend, "route": route, "method": name, "origin": origin,
                                            "schema": tool.get("inputSchema"), "signature": tool.get("signature"),
                                            "cases": [], "evidence": [], "safe_inputs": [], "reason": reason})
            row["evidence"].append(evidence)
            if origin == "runtime":
                row["origin"] = "runtime"

    for evidence, data in catalogs:
        for backend in data.get("backends", []):
            name = backend["backend"]
            backends.setdefault(name, {"runtime_observed": False, "source_declared": False, "methods": set(), "runtime_methods": set(), "routes": set()})
            if backend.get("catalog_status") == "observed":
                add_tools(name, "original wrapper", backend["tools"], "runtime", evidence)
            else:
                backends[name].setdefault("unavailable_observations", []).append({"evidence": evidence, "status": backend.get("catalog_status"), "error": backend.get("error"), "reason": backend.get("reason")})
    for evidence, data in declarations:
        for backend in data.get("backends", []):
            add_tools(backend["backend"], "source declaration", backend.get("tools", []), "source", evidence, backend.get("reason"))
    for evidence, data in sessions:
        backend, route = data["backend"], data["route"]
        add_tools(backend, route, data["tools"], "runtime", evidence)
        cleanup_ok = data.get("cleanup", {}).get("observed_cleanup_ok") is True and not data.get("runner_error")
        audit = data.get("stdout_audit")
        capture_complete = "stdout_audit" not in data or (isinstance(audit, dict) and audit.get("reader_stopped") is True)
        transport_ok = data.get("wire_protocol_clean", True) and capture_complete
        reasons = []
        if data.get("runner_error"):
            reasons.append("runner_error")
        if data.get("cleanup", {}).get("observed_cleanup_ok") is not True:
            reasons.append("cleanup_not_observed")
        if not transport_ok:
            reasons.append("stdout_not_clean_or_complete")
        failed_case_ids = []
        for case in data.get("cases", []):
            key = backend + "::" + route + "::" + case["method"]
            if key not in methods:
                raise ValueError("called method absent from its runtime catalog")
            status = case_status(case, cleanup_ok and transport_ok)
            methods[key]["cases"].append({"id": case["case_id"], "status": status, "kind": case.get("kind"), "evidence": evidence, "response_id": case.get("response_id"), "wire_protocol_clean": transport_ok, "wire_audit_scope": data.get("wire_audit_scope")})
            if status == "failed":
                failed_case_ids.append(case["case_id"])
            if status == "positive_pass":
                methods[key]["safe_inputs"].append(case["arguments"])
        if failed_case_ids:
            reasons.append("failed_cases")
        if reasons:
            session_failures.append({"evidence": evidence, "backend": backend, "route": route,
                                     "reasons": reasons, "runner_error": data.get("runner_error"),
                                     "failed_case_ids": failed_case_ids})
    for row in methods.values():
        statuses = [c["status"] for c in row["cases"]]
        row["status"] = ("failed" if "failed" in statuses else "positive_pass" if "positive_pass" in statuses
                         else "negative_only" if statuses else "unexecuted" if row["origin"] == "runtime" else "prerequisite_missing")
        if not row["reason"] and not statuses:
            row["reason"] = "No selected raw tools/call observation; catalog/declaration alone supplies no behavioral acceptance."
    for state in backends.values():
        state["known_unique_methods"] = len(state.pop("methods"))
        state["routes"] = sorted(state["routes"])
        runtime_methods = state.pop("runtime_methods")
        state["runtime_method_count"] = len(runtime_methods) if state["runtime_observed"] else None
    positive_original = {(r["backend"], r["method"]) for r in methods.values() if r["status"] == "positive_pass" and r["route"] in ("original wrapper", "original root-adopted wrapper")}
    return {"schema": "debugger-tool-coverage/1", "backends": backends, "methods": methods,
            "session_failures": session_failures,
            "summary": {"backend_count": len(backends), "runtime_denominator_complete": all(x["runtime_observed"] for x in backends.values()),
                        "session_count": len(sessions), "failed_sessions": len(session_failures),
                        "method_route_rows": len(methods), "original_wrapper_positive_unique_methods": len(positive_original),
                        "actual_recorded_calls": sum(len(r["cases"]) for r in methods.values()),
                        "failed_cases": sum(c["status"] == "failed" for r in methods.values() for c in r["cases"]),
                        "stdout_noise_sessions": [{"evidence": e, "lines": d["stdout_noise"]} for e, d in sessions if d.get("stdout_noise")],
                        "unexecuted_or_source_rows": sum(not r["cases"] for r in methods.values())}}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session", type=Path, action="append", default=[], help="LabSession RESULTS.json; repeat per selected run")
    ap.add_argument("--catalog", type=Path, action="append", default=[], help="catalog.py CATALOG.json")
    ap.add_argument("--source", type=Path, action="append", default=[], help="Explicit static manifest {backends:[{backend,tools,reason}]}")
    ap.add_argument("--output", type=Path, required=True, help="New output directory")
    args = ap.parse_args()
    if not args.session and not args.catalog and not args.source:
        ap.error("at least one explicit evidence input is required")
    inputs = []
    def load(paths, verify=False):
        result = []
        for p in paths:
            inputs.append({"path": str(p.resolve()), "sha256": sha(p)})
            result.append((str(p.resolve()), verify_session(p) if verify else json.loads(p.read_text(encoding="utf-8-sig"))))
        return result
    result = merge_sessions(load(args.session, True), load(args.catalog), load(args.source))
    result["inputs"] = inputs
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "COVERAGE.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"]))
    return 2 if result["summary"]["failed_cases"] or result["summary"]["failed_sessions"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
