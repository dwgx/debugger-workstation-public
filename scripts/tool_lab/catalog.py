#!/usr/bin/env python3
"""Inventory selected real stdio backends without treating tools/list as a call.

Windows execution uses the separately reviewed raw_mcp Job Object supervisor.
The caller selects backends after checking their startup effects and prerequisites.
No third-party runtime or credential is installed by this command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from common import no_mcp_env
from raw_mcp import RawMcp, now_utc


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def reserve_output(path: Path, station: Path) -> Path:
    out = path.resolve()
    if out == station or station in out.parents:
        raise ValueError("output must be outside the station source tree")
    out.mkdir(parents=True, exist_ok=False)
    return out


def load_registry(station: Path, supplied: Path | None = None):
    path = (supplied or station / "MCP" / ".mcp.json").resolve()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        raise ValueError("registry must contain an mcpServers object")
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) for name in servers):
        raise ValueError("backend names must be safe single path components")
    return path, {name: item for name, item in servers.items() if name != "debugger-router"}


def launch_description(item: dict, station: Path, out: Path):
    if not isinstance(item, dict) or not isinstance(item.get("command"), str):
        raise ValueError("backend requires an explicit stdio command")
    args = item.get("args") or []
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("args must be an array of strings")
    command = item["command"].replace("{{DEBUGGER_ROOT}}", str(station))
    args = [x.replace("{{DEBUGGER_ROOT}}", str(station)) for x in args]
    path = Path(command)
    if not path.is_absolute():
        path = station / path
    if path.suffix.lower() in (".cmd", ".bat"):
        if os.name != "nt":
            raise RuntimeError("Windows wrapper requires Windows; no shell emulation")
        argv = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
                "/d", "/v:off", "/c", "call", str(path), *args]
    else:
        argv = [str(path) if path.exists() else command, *args]
    cwd = Path(item.get("cwd") or out)
    if not cwd.is_absolute():
        cwd = station / cwd
    cwd = cwd.resolve()
    env = no_mcp_env()
    supplied_env = item.get("env") or {}
    if not isinstance(supplied_env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in supplied_env.items()):
        raise ValueError("env must be a string map")
    env.update(supplied_env)
    temp = out / "temp"
    temp.mkdir()
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1",
                "TEMP": str(temp), "TMP": str(temp), "TMPDIR": str(temp),
                "FASTMCP_CHECK_FOR_UPDATES": "off", "FASTMCP_SHOW_SERVER_BANNER": "false"})
    identity = {"command": command, "argv": argv, "cwd": str(cwd),
                "explicit_env_keys": sorted(supplied_env),
                "entry_sha256": digest(path) if path.is_file() else None}
    return argv, str(cwd), env, identity


def probe_backend(name: str, item: dict, station: Path, out: Path, timeout: float):
    out.mkdir(exist_ok=False)
    record = {"backend": name, "started_utc": now_utc(), "tools": [],
              "tool_count": None, "catalog_status": "unavailable", "tool_call_count": 0,
              "schema_origin": "runtime tools/list", "cleanup": None}
    client = None
    try:
        argv, cwd, env, identity = launch_description(item, station, out)
        record["launch"] = identity
        client = RawMcp(argv, cwd=cwd, env=env, timeout=timeout, tag=name)
        deadline = time.monotonic() + timeout
        client.start()
        client.timeout = max(0.001, deadline - time.monotonic())
        initial = client.initialize(client_name="debugger-tool-lab-catalog")
        record["initialize"] = initial
        if not isinstance(initial.get("result"), dict):
            raise RuntimeError("initialize did not return a result")
        seen_cursors = set()
        cursor = None
        tools = []
        for page in range(100):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("catalog total deadline exhausted")
            response = client.send("tools/list", {} if cursor is None else {"cursor": cursor}, timeout=remaining)
            result = response.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise RuntimeError("tools/list did not return a tools array")
            tools.extend(result["tools"])
            cursor = result.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or cursor in seen_cursors:
                raise RuntimeError("invalid or repeated pagination cursor")
            seen_cursors.add(cursor)
        else:
            raise RuntimeError("catalog page limit exceeded")
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        if len(names) != len(tools) or not all(isinstance(n, str) and n for n in names) or len(names) != len(set(names)):
            raise RuntimeError("catalog includes malformed or duplicate tool names")
        if any(not isinstance(t.get("inputSchema"), dict) for t in tools):
            raise RuntimeError("catalog includes a missing inputSchema")
        record.update(tools=tools, tool_count=len(tools), catalog_status="observed")
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if client is not None:
            # start() may acquire the process/Job before a later reader setup
            # fails. Keep the owner and always attempt its bounded cleanup.
            try:
                record["cleanup"] = client.close()
            except Exception as error:
                record["cleanup"] = {"observed_cleanup_ok": False, "error": repr(error)}
            requests = "\n".join(x["raw"] for x in client.req)
            responses = "\n".join(x["raw"] for x in client.res)
            (out / "requests.jsonl").write_text(requests + ("\n" if requests else ""), encoding="utf-8")
            (out / "responses.jsonl").write_text(responses + ("\n" if responses else ""), encoding="utf-8")
            (out / "stderr.txt").write_bytes(b"".join(client.stderr_chunks))
            record["raw_sha256"] = {n: digest(out / n) for n in ("requests.jsonl", "responses.jsonl", "stderr.txt")}
        record["finished_utc"] = now_utc()
        record["bounded_observation_complete"] = bool(record.get("cleanup", {}).get("observed_cleanup_ok")) if record.get("cleanup") else False
        write_json(out / "catalog.json", record)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--station", type=Path, required=True)
    ap.add_argument("--registry", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--backends", required=True, help="Explicit comma-separated startup-reviewed backend names")
    ap.add_argument("--timeout", type=float, default=30, help="Whole initialize/list budget per backend, maximum 90 seconds")
    ns = ap.parse_args()
    station = ns.station.resolve()
    path, servers = load_registry(station, ns.registry)
    selected = ns.backends.split(",")
    if not selected or len(selected) != len(set(selected)) or any(x not in servers for x in selected):
        ap.error("backends must be a unique explicit subset of the selected registry")
    if not 0 < ns.timeout <= 90:
        ap.error("timeout must be >0 and <=90")
    out = reserve_output(ns.output, station)
    inputs = {"registry_path": str(path), "registry_sha256": digest(path),
              "client_python": str(Path(sys.executable).resolve()), "client_python_sha256": digest(Path(sys.executable)),
              "runner_sha256": digest(Path(__file__)), "raw_client_sha256": digest(Path(__file__).with_name("raw_mcp.py"))}
    write_json(out / "INPUTS.json", inputs)
    records = []
    for name, item in servers.items():
        if name in selected:
            record = probe_backend(name, item, station, out / name, ns.timeout)
            print(json.dumps({k: record.get(k) for k in ("backend", "catalog_status", "tool_count", "bounded_observation_complete", "error")}), flush=True)
        else:
            record = {"backend": name, "catalog_status": "not_selected", "tool_count": None,
                      "tools": [], "tool_call_count": 0, "reason": "startup not authorized by this explicit selection"}
        records.append(record)
    inventory = {"schema": "debugger-tool-catalog/1", "created_utc": now_utc(), "inputs": inputs,
                 "backend_count": len(servers), "selected_backend_count": len(selected), "backends": records,
                 "known_runtime_method_count": sum(x["tool_count"] or 0 for x in records),
                 "runtime_denominator_complete": all(x["catalog_status"] == "observed" for x in records),
                 "actual_tool_call_count": 0, "registry_unchanged": digest(path) == inputs["registry_sha256"]}
    write_json(out / "CATALOG.json", inventory)
    # A partial inventory is useful evidence, but it must not exit as complete.
    ok = inventory["registry_unchanged"] and all(x["catalog_status"] == "observed" and x["bounded_observation_complete"] for x in records if x["backend"] in selected)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
