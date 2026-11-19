#!/usr/bin/env python3
"""Exercise Reqable's original wrapper with a fresh authored HAR and owned DB."""
import argparse
import ast
import json
import os
from pathlib import Path
import socket
import sqlite3

from catalog import digest, reserve_output, write_json
from common import no_mcp_env
from fixtures import build_all, build_har, HTTP_MARKER
from lab_session import LabSession


def sql_rows(db, query, parameters=()):
    with sqlite3.connect(db) as connection:
        return connection.execute(query, parameters).fetchall()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--candidate-root", type=Path, help="Explicit package parent for isolated candidate verification")
    args = ap.parse_args()
    station = args.station.resolve()
    out = reserve_output(args.output, station)
    fixtures = build_all(out / "fixtures")
    database = out / "data/requests.db"
    database.parent.mkdir()
    (out / "temp").mkdir()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    wrapper = station / "MCP/bin/reqable-mcp-local.cmd"
    # This guard is semantic: caller-supplied owned DB must survive the wrapper.
    text = wrapper.read_text(encoding="utf-8-sig")
    if 'if not defined REQABLE_DATA_DIR set "REQABLE_DATA_DIR=' not in text:
        raise RuntimeError("wrapper does not preserve an explicit data directory; do not run against its shared default")
    argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/v:off", "/c", "call", str(wrapper)]
    env = no_mcp_env()
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(out / "temp"), "TMP": str(out / "temp"),
                "REQABLE_DATA_DIR": str(database.parent), "REQABLE_DB_PATH": str(database),
                "REQABLE_INGEST_HOST": "127.0.0.1", "REQABLE_INGEST_PORT": str(port),
                "REQABLE_INGEST_TOKEN": "owned-fixture-token", "REQABLE_RETENTION_DAYS": "3650"})
    package = station / "MCP/reqable-mcp/.venv/Lib/site-packages/reqable_mcp"
    route = "original root-adopted wrapper"
    if args.candidate_root:
        package = args.candidate_root.resolve() / "reqable_mcp"
        argv = [str(station / "MCP/reqable-mcp/.venv/Scripts/python.exe"), "-X", "utf8", "-B", "-m", "reqable_mcp"]
        env["PYTHONPATH"] = str(args.candidate_root.resolve())
        route = "isolated source candidate"
    source = {str(p): digest(p) for p in sorted(package.rglob("*.py"))}
    plan = {"schema": "tool-lab-authored-reqable/1", "fixtures": fixtures, "wrapper": str(wrapper),
            "wrapper_sha256": digest(wrapper), "provider_sources": source, "owned_db": str(database),
            "owned_listener": {"host": "127.0.0.1", "port": port}, "runner_sha256": digest(Path(__file__)),
            "scope": "Authored offline HAR import; local owned listener; no capture, outbound request, or generated code execution."}
    write_json(out / "PLAN.json", plan)
    print(json.dumps({"plan_sha256": digest(out / "PLAN.json"), "output": str(out)}), flush=True)
    with LabSession("reqable", argv, out, env, out / "session", route, timeout=25) as lab:
        c = lab.call("ingest_status", {"auto_start": False}, "owned-listener")
        lab.check(c, "listening", c["payload"].get("listening"), True)
        lab.check(c, "local_host", c["payload"].get("host"), "127.0.0.1")
        lab.check(c, "owned_port", c["payload"].get("port"), port)
        lab.check(c, "owned_db", c["payload"].get("db_path"), str(database))
        c = lab.call("import_har", {"file_path": str(out / "fixtures/owned.har")}, "import-authored")
        lab.check(c, "accepted", c["payload"].get("ok"), True)
        rows = sql_rows(database, "SELECT id,url FROM requests ORDER BY url")
        lab.check(c, "sqlite_exact_urls", [row[1] for row in rows], sorted([fixtures["har"]["http_url"], fixtures["har"]["ws_url"]]))
        ids = {url: rid for rid, url in rows}
        http_id, ws_id = ids[fixtures["har"]["http_url"]], ids[fixtures["har"]["ws_url"]]
        c = lab.call("list_requests", {"limit": 10, "detail": "full"}, "list-authored")
        lab.check(c, "exact_urls", sorted(x["url"] for x in c["payload"]), sorted(ids))
        c = lab.call("get_request", {"request_id": http_id, "include_body": True}, "http-body")
        lab.check(c, "url", c["payload"].get("url"), fixtures["har"]["http_url"])
        lab.check(c, "status", c["payload"].get("status"), 200)
        lab.check(c, "response_marker", HTTP_MARKER in json.dumps(c["payload"]), True)
        c = lab.call("search_requests", {"keyword": HTTP_MARKER, "search_in": "response_body", "limit": 10}, "search-known-body")
        lab.check(c, "one_match", len(c["payload"]), 1)
        lab.check(c, "known_url", c["payload"][0].get("url"), fixtures["har"]["http_url"])
        c = lab.call("get_domains", {}, "known-domain-count")
        lab.check(c, "domain_rows", c["payload"], [{"domain": "fixture.test", "count": 2, "methods": ["GET"]}])
        c = lab.call("analyze_api", {"domain": "fixture.test"}, "normalized-api")
        lab.check(c, "total", c["payload"].get("total_requests"), 2)
        lab.check(c, "endpoints", c["payload"].get("endpoints_count"), 1)
        lab.check(c, "normalized_path", c["payload"]["endpoints"][0].get("path"), "/api/items/{id}")
        c = lab.call("generate_code", {"request_id": http_id, "language": "python", "framework": "requests"}, "code-generation-no-execution")
        code = c["payload"]
        parsed = ast.parse(code)
        strings = [n.value for n in ast.walk(parsed) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        lab.check(c, "literal_fixture_url", fixtures["har"]["http_url"] in strings, True)
        lab.check(c, "imports_requests", any(isinstance(n, ast.Import) and any(a.name == "requests" for a in n.names) for n in ast.walk(parsed)), True)
        c = lab.call("list_websocket_sessions", {"limit": 10, "detail": "full"}, "list-owned-websocket")
        lab.check(c, "one_ws", len(c["payload"]), 1)
        lab.check(c, "ws_url", c["payload"][0].get("url"), fixtures["har"]["ws_url"])
        c = lab.call("get_websocket_session", {"request_id": ws_id, "include_messages": True}, "get-owned-websocket")
        lab.check(c, "three_messages", c["payload"].get("websocket_message_count"), 3)
        c = lab.call("tail_websocket_messages", {"request_id": ws_id, "limit": 10, "include_raw": True}, "ws-tail")
        lab.check(c, "returned", c["payload"].get("returned"), 3)
        lab.check(c, "raw_frames", [m.get("raw") for m in c["payload"]["messages"]], build_har()["log"]["entries"][1]["_webSocketMessages"])
        c = lab.call("search_websocket_messages", {"keyword": "TOOLLAB_ACK", "request_id": ws_id}, "ws-search")
        lab.check(c, "one_ack", len(c["payload"]), 1)
        lab.check(c, "ack", "TOOLLAB_ACK" in json.dumps(c["payload"][0]), True)
        c = lab.call("analyze_websocket_session", {"request_id": ws_id}, "ws-analysis")
        lab.check(c, "message_count", c["payload"].get("websocket_message_count"), 3)
        lab.check(c, "directions", c["payload"].get("directions"), {"outbound": 1, "inbound": 2})
        lab.check(c, "types", c["payload"].get("message_types"), {"text": 2, "close": 1})
        c = lab.call("export_websocket_session_raw", {"request_id": ws_id, "include_normalized": True}, "ws-raw-export")
        lab.check(c, "raw_entry", c["payload"].get("raw_entry"), build_har()["log"]["entries"][1])
        lab.check(c, "raw_count", c["payload"].get("raw_message_count"), 3)
        c = lab.call("list_active_websocket_sessions", {"limit": 10, "active_within_seconds": 60, "include_closing": False}, "closed-ws-excluded")
        lab.check(c, "no_active_closed_fixture", c["payload"], [])
        # Make exactly one owned imported row incomplete, then prove dry-run and real repair.
        with sqlite3.connect(database) as conn:
            conn.execute("UPDATE websocket_messages SET direction='unknown' WHERE request_id=? AND seq=(SELECT MIN(seq) FROM websocket_messages WHERE request_id=?)", (ws_id, ws_id))
        c = lab.call("repair_websocket_messages", {"max_rows": 20, "dry_run": True}, "repair-dry-run")
        lab.check(c, "one_proposed", c["payload"].get("repaired"), 1)
        lab.check(c, "db_unchanged_by_dry_run", sql_rows(database, "SELECT COUNT(*) FROM websocket_messages WHERE direction='unknown'")[0][0], 1)
        c = lab.call("repair_websocket_messages", {"max_rows": 20, "dry_run": False}, "repair-owned-row")
        lab.check(c, "one_repaired", c["payload"].get("repaired"), 1)
        lab.check(c, "db_repaired", sql_rows(database, "SELECT COUNT(*) FROM websocket_messages WHERE direction='unknown'")[0][0], 0)
        c = lab.call("health_report", {"detail": True, "sample_limit": 5}, "final-data-health")
        health = c["payload"].get("websocket_health", {})
        for key, value in {"total_requests": 2, "total_websocket_sessions": 1, "total_websocket_messages": 3,
                           "websocket_messages_missing_raw": 0, "websocket_messages_direction_unknown": 0}.items():
            lab.check(c, key, health.get(key), value)
        c = lab.call("import_har", {"file_path": str(out / "fixtures/missing.har")}, "missing-har", kind="negative")
        lab.check(c, "specific_missing_file_error", "File not found:" in str(c["payload"]), True)
        c = lab.call("import_har", {"file_path": str(out / "fixtures/malformed.har")}, "malformed-har", kind="negative")
        lab.check(c, "specific_parse_error", "No valid HAR or NDJSON entries found" in str(c["payload"]), True)
        lab.check(c, "no_extra_records", sql_rows(database, "SELECT COUNT(*) FROM requests")[0][0], 2)
    unchanged = all(digest(Path(p)) == sha for p, sha in source.items()) and digest(wrapper) == plan["wrapper_sha256"]
    with socket.socket() as probe:
        probe.settimeout(1)
        listener_closed = probe.connect_ex(("127.0.0.1", port)) != 0
    final = {"provider_sources_and_wrapper_unchanged": unchanged, "owned_listener_closed": listener_closed,
             "session_results_sha256": digest(out / "session/RESULTS.json"), "all_checks_pass": lab.record["all_checks_pass"] and unchanged and listener_closed,
             "methods_called": lab.record["unique_methods_called"], "positive_methods": lab.record["unique_positive_methods"]}
    write_json(out / "FINAL.json", final)
    print(json.dumps(final))
    return 0 if final["all_checks_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
