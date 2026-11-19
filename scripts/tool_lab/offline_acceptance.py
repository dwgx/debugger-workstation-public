#!/usr/bin/env python3
"""Bounded offline acceptance run for the Wireshark, 7-Zip and REA MCP wrappers.

CLI:
    python scripts/tool_lab/offline_acceptance.py --station ROOT --output NEW_DIR

The runner:
  * builds authored fixtures (see offline_fixtures.py) into NEW_DIR/fixtures;
  * launches each real station wrapper through COMSPEC with the accepted
    RawMcp client (CREATE_SUSPENDED -> Job Object -> ResumeThread);
  * catalogs every advertised tool with initialize + tools/list;
  * executes bounded, exact-oracle calls, including one bad-input control per
    reusable path;
  * writes catalog.json, coverage.json, identities.json, runs/<provider>/ raw
    JSONL + parsed cases + cleanup receipts, and REPORT.md;
  * exits 0 only when every executed case passed and every provider cleanup was
    observed.

No live capture, no browser/network/ADB/process targets, no sample execution,
no station writes, no global configuration changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import offline_fixtures as build_fixtures  # noqa: E402
from raw_mcp import RawMcp, snap_all, snap_tree  # noqa: E402
from common import no_mcp_env  # noqa: E402

COMSPEC = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
SCHEMA = "tool-lab-bounded-run/2"

# Cataloged methods covered by the earlier revision-002 acceptance. This run
# does not count them as new coverage.
PRIOR_METHODS = {
    "wireshark": {"decode_protocol"},
    "sevenzip": {"mcp7zop_extract_archive", "mcp7zop_get_archive_item_list"},
    "rea": {"inspect_pe_resources"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def content_text(resp: dict) -> str:
    result = resp.get("result") or {}
    parts = []
    for item in result.get("content") or []:
        if item.get("type") == "text":
            parts.append(item.get("text", ""))
    return "\n".join(parts)


def try_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def find_field(node, key: str):
    """Find a tshark JSON field at any nesting depth."""
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for value in node.values():
            found = find_field(value, key)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = find_field(item, key)
            if found is not None:
                return found
    return None


class Checks:
    """Named boolean checks with concise details."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    def add(self, name: str, ok, detail=None) -> bool:
        ok = bool(ok)
        self.items[name] = {"pass": ok, "detail": detail}
        return ok

    def eq(self, name: str, actual, expected) -> bool:
        return self.add(name, actual == expected,
                        {"actual": trunc(actual), "expected": trunc(expected)})

    def contains(self, name: str, haystack, needle) -> bool:
        return self.add(name, isinstance(haystack, str) and needle in haystack,
                        {"needle": trunc(needle), "head": trunc(haystack)})

    def regex(self, name: str, haystack, pattern) -> bool:
        match = re.search(pattern, haystack or "", re.S)
        return self.add(name, match is not None,
                        {"pattern": pattern, "head": trunc(haystack)})

    @property
    def ok(self) -> bool:
        return bool(self.items) and all(item["pass"] for item in self.items.values())

    @property
    def failed(self) -> list[str]:
        return [name for name, item in self.items.items() if not item["pass"]]


def trunc(value, limit: int = 300):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "…"


def audit_stdout(client) -> dict:
    """Retain queued shutdown lines after close joins the owned stdout reader."""
    queued = getattr(client, "_q", None)
    trailing = 0
    if queued is not None:
        while True:
            try:
                item = queued.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                client.res.append({"t": item["t"], "raw": item["raw"]})
                trailing += 1
    reader = getattr(client, "_reader", None)
    stopped = reader is not None and not reader.is_alive()
    noise = []
    for number, item in enumerate(client.res, 1):
        try:
            envelope = json.loads(item["raw"])
            if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0" or not ("id" in envelope or "method" in envelope):
                raise ValueError("not a JSON-RPC envelope")
        except ValueError:
            noise.append({"line": number, "sha256": sha256_text(item["raw"])})
    return {"scope": "captured stdout through owned Job teardown and joined reader",
            "reader_stopped": stopped, "post_close_lines": trailing,
            "noise": noise, "wire_protocol_clean": stopped and not noise}


class ProviderRun:
    """One real wrapper process, its cases and its cleanup receipt."""

    def __init__(self, name: str, wrapper: Path, outdir: Path, env_extra: dict,
                 startup_timeout: float = 90.0):
        self.name = name
        self.wrapper = wrapper
        self.outdir = outdir
        self.env_extra = env_extra
        self.startup_timeout = startup_timeout
        self.dir = outdir
        self.client: RawMcp | None = None
        self.cases: list[dict] = []
        self.session: dict = {}
        self.cleanup: dict | None = None
        self.error: str | None = None
        self._owns_output = False

    def start(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=False)
        self._owns_output = True
        env = no_mcp_env()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.update(self.env_extra)
        cmd = [COMSPEC, "/d", "/v:off", "/c", "call", str(self.wrapper)]
        self.session["command"] = cmd
        self.session["wrapper"] = str(self.wrapper)
        self.session["wrapper_sha256"] = sha256_file(self.wrapper)
        self.session["cwd"] = str(self.dir)
        self.client = RawMcp(cmd, cwd=str(self.dir), env=env,
                             timeout=self.startup_timeout)
        self.client.start()
        self.session["provider_pid"] = self.client.proc.pid
        self.session["start_observation"] = self.client.start_observation
        self.session["tree_after_start"] = snap_tree(self.client.proc.pid, snap_all())
        init = self.client.initialize()
        self.session["initialize"] = init
        self.session["protocol_version"] = (init.get("result") or {}).get("protocolVersion")
        self.session["server_info"] = (init.get("result") or {}).get("serverInfo")
        listing = self.client.send("tools/list", {}, timeout=self.startup_timeout)
        self.session["tools_list_rpc_id"] = listing.get("id")
        tools = (listing.get("result") or {}).get("tools") or []
        names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
        if not tools or len(names) != len(tools) or not all(names) or len(set(names)) != len(names):
            raise RuntimeError("empty, malformed or duplicate-name tool catalog")
        self.session["tool_count"] = len(tools)
        self.session["tools"] = tools
        (self.dir / "catalog.json").write_text(
            json.dumps({"provider": self.name, "tool_count": len(tools),
                        "tools": tools}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    def call(self, case_id: str, tool: str, args: dict, check_fn,
             classification: str = "positive", timeout: float = 30.0,
             note: str = "") -> dict:
        if self.client is None:
            raise RuntimeError("provider not started")
        started = time.monotonic()
        rec: dict = {
            "case_id": case_id,
            "tool": tool,
            "arguments": args,
            "classification": classification,
            "timeout_cap_seconds": timeout,
            "note": note,
        }
        try:
            resp = self.client.send("tools/call", {"name": tool, "arguments": args},
                                    timeout=timeout)
        except Exception as exc:  # timeout / EOF / protocol failure
            rec.update({
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "error": repr(exc),
                "checks": {"call_completed": {"pass": False, "detail": repr(exc)}},
                "all_pass": False,
                "failed_checks": ["call_completed"],
            })
            self.cases.append(rec)
            return rec
        elapsed = round(time.monotonic() - started, 3)
        text = content_text(resp)
        parsed = try_json(text)
        checks = Checks()
        checks.add("rpc_result_present", isinstance(resp.get("result"), dict))
        checks.add("rpc_error_absent", "error" not in resp)
        if classification in ("positive", "partial"):
            checks.add("success_error_flag", (resp.get("result") or {}).get("isError") in (None, False))
        ctx = {"case_id": case_id, "resp": resp, "text": text,
               "parsed": parsed, "result": resp.get("result") or {}}
        try:
            check_fn(ctx, checks)
        except Exception as exc:  # oracle bug is a failed check, not a call failure
            checks.add("oracle_exception", False, repr(exc))
        rec.update({
            "rpc_id": resp.get("id"),
            "elapsed_seconds": elapsed,
            "within_timeout": elapsed < timeout,
            "is_error": ctx["result"].get("isError"),
            "checks": checks.items,
            "all_pass": checks.ok and elapsed < timeout,
        })
        if not rec["all_pass"]:
            rec["failed_checks"] = checks.failed + (
                [] if elapsed < timeout else ["within_timeout"])
        if self.name == "wireshark":
            rec["content_text"] = text
        else:
            rec["content_json"] = parsed if parsed is not None else text
        self.cases.append(rec)
        return rec

    def execute(self, exercise):
        """Keep the owner object and finish even when start or oracle setup raises."""
        try:
            self.start()
            exercise()
        except Exception as exc:
            self.error = repr(exc)
        finally:
            self.finish()

    def finish(self) -> None:
        if self.client is not None:
            try:
                self.cleanup = self.client.close()
            except Exception as exc:
                self.cleanup = {"observed_cleanup_ok": False, "close_error": repr(exc)}
            self.session["stdout_audit"] = audit_stdout(self.client)
            if self._owns_output:
                (self.dir / "raw.jsonl").write_text(
                    "\n".join(json.dumps(item, ensure_ascii=False)
                              for item in self.client.req + self.client.res),
                    encoding="utf-8")
                (self.dir / "stderr.txt").write_bytes(b"".join(self.client.stderr_chunks))
                (self.dir / "cleanup.json").write_text(
                    json.dumps(self.cleanup, ensure_ascii=False, indent=2), encoding="utf-8")
        if not self._owns_output:
            return
        self.session["error"] = self.error
        (self.dir / "cases.json").write_text(
            json.dumps(self.cases, ensure_ascii=False, indent=2), encoding="utf-8")
        (self.dir / "session.json").write_text(
            json.dumps(self.session, ensure_ascii=False, indent=2), encoding="utf-8")

    @property
    def cleanup_ok(self) -> bool:
        return bool(self.cleanup and self.cleanup.get("observed_cleanup_ok"))

    @property
    def cases_ok(self) -> bool:
        return bool(self.cases) and all(c.get("all_pass") for c in self.cases)


# ---------------------------------------------------------------------------
# Wireshark checks


def ws_checks(pcap: Path, corrupt: Path, exports: Path):
    def check_installation(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False),
              ctx["result"].get("isError"))
        c.regex("tshark_version", text, r"^tshark: TShark \(Wireshark\) \d+\.\d+\.\d+")
        c.contains("tshark_path", text, "Path: ")
        c.contains("tshark_exe", text, "tshark.EXE")
        c.contains("dumpcap_found", text, "dumpcap: found at ")
        c.contains("dumpcap_exe", text, "dumpcap.EXE")

    def list_interfaces(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        match = re.search(r"^Found (\d+) network interface\(s\):", text)
        c.add("count_header", match is not None, trunc(text))
        if match:
            declared = int(match.group(1))
            lines = [line for line in text.splitlines() if re.match(r"^\d+\. ", line)]
            c.eq("declared_count", declared, len(lines))
            c.add("count_positive", declared >= 1, declared)
            c.add("npf_present", any("\\Device\\NPF_" in line for line in lines),
                  lines[0] if lines else None)

    def read_pcap_two(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("count_line", text, f"Read 2 packet(s) from {pcap}")
        parsed = None
        if "Preview:\n" in text:
            parsed = try_json(text.split("Preview:\n", 1)[1])
        c.add("preview_parsed", isinstance(parsed, list), type(parsed).__name__)
        if isinstance(parsed, list):
            c.eq("preview_len", len(parsed), 2)
            layers = [p.get("_source", {}).get("layers", {}) for p in parsed]
            c.eq("frames", [l.get("frame", {}).get("frame.number") for l in layers], ["1", "2"])
            c.eq("pkt1_ip_src", layers[0].get("ip", {}).get("ip.src"), "192.0.2.10")
            c.eq("pkt1_ip_dst", layers[0].get("ip", {}).get("ip.dst"), "198.51.100.53")
            c.eq("pkt1_dns_name", find_field(layers[0], "dns.qry.name"),
                 "fixture.ws-test.test")
            c.eq("pkt2_dns_response", find_field(layers[1], "dns.flags.response"), "1")
            c.eq("pkt2_dns_a", find_field(layers[1], "dns.a"), "192.0.2.53")

    def display_filter_http(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("count_line", text, "Found 2 packet(s) matching filter 'http'")
        parsed = None
        if "Preview:\n" in text:
            parsed = try_json(text.split("Preview:\n", 1)[1])
        c.add("preview_parsed", isinstance(parsed, list), type(parsed).__name__)
        if isinstance(parsed, list):
            c.eq("preview_len", len(parsed), 2)
            layers = [p.get("_source", {}).get("layers", {}) for p in parsed]
            c.eq("frames", [l.get("frame", {}).get("frame.number") for l in layers], ["6", "7"])
            c.eq("request_method", find_field(layers[0], "http.request.method"), "GET")
            c.eq("request_uri", find_field(layers[0], "http.request.uri"), "/fixture")
            c.eq("request_host", find_field(layers[0], "http.host"),
                 "fixture.ws-test.test")
            c.eq("response_code", find_field(layers[1], "http.response.code"), "200")
            c.eq("response_phrase", find_field(layers[1], "http.response.phrase"), "OK")

    def summarize(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("header", text, f"=== Summary: {pcap} ===")
        c.contains("io_section", text, "--- I/O Statistics ---")
        c.regex("io_row", text, r"\|\s*0\.000 <> 6\.006\s*\|\s*7\s*\|\s*641\s*\|")
        c.contains("hierarchy_section", text, "--- Protocol Hierarchy ---")
        c.regex("frame_row", text, r"frame\s+frames:7 bytes:641")
        c.regex("dns_row", text, r"dns\s+frames:2 bytes:176")
        c.regex("tcp_row", text, r"tcp\s+frames:5 bytes:465")
        c.regex("http_row", text, r"http\s+frames:2 bytes:285")
        c.contains("conversation_section", text, "--- Top IP Conversations ---")
        c.regex("http_conversation", text,
                r"192\.0\.2\.10\s+<-> 198\.51\.100\.20\s+2 204 bytes\s+3 261 bytes\s+5 465 bytes")
        c.regex("dns_conversation", text,
                r"192\.0\.2\.10\s+<-> 198\.51\.100\.53\s+1 96 bytes\s+1 80 bytes\s+2 176 bytes")

    def stats_by_proto(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("prefix", text, f"Protocol Statistics for {pcap}:")
        c.contains("heading", text, "Protocol Hierarchy Statistics")
        c.regex("frame_row", text, r"frame\s+frames:7 bytes:641")
        c.regex("udp_dns_row", text, r"udp\s+frames:2 bytes:176")
        c.regex("dns_row", text, r"dns\s+frames:2 bytes:176")
        c.regex("tcp_row", text, r"tcp\s+frames:5 bytes:465")
        c.regex("http_row", text, r"http\s+frames:2 bytes:285")

    def follow_tcp(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("prefix", text, f"TCP Stream 0 from {pcap}:")
        c.contains("filter", text, "Filter: tcp.stream eq 0")
        c.contains("node0", text, "Node 0: 192.0.2.10:49152")
        c.contains("node1", text, "Node 1: 198.51.100.20:8080")
        c.contains("request_line", text, "GET /fixture HTTP/1.1")
        c.contains("request_host", text, "Host: fixture.ws-test.test")
        c.contains("response_line", text, "HTTP/1.1 200 OK")
        c.contains("content_length", text, "Content-Length: 25")
        c.contains("body", text, "hello-from-authored-http")

    def follow_udp(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("prefix", text, f"UDP Stream 0 from {pcap}:")
        c.contains("filter", text, "Filter: udp.stream eq 0")
        c.contains("node0", text, "Node 0: 192.0.2.10:53000")
        c.contains("node1", text, "Node 1: 198.51.100.53:53")
        c.eq("query_name_twice", text.count("fixture.ws-test.test"), 2)
        c.regex("query_length", text, r"\r?\n38\r?\n")
        c.regex("response_length", text, r"\r?\n\t54\r?\n")

    def expert_info_warn(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("exact_text", text, "No expert info entries found.")

    def protocol_stats(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.contains("prefix", text, f"Stats 'conv,ip' for {pcap}:")
        c.contains("heading", text, "IPv4 Conversations")
        c.regex("http_row", text,
                r"192\.0\.2\.10\s+<-> 198\.51\.100\.20\s+2 204 bytes\s+3 261 bytes\s+5 465 bytes")
        c.regex("dns_row", text,
                r"192\.0\.2\.10\s+<-> 198\.51\.100\.53\s+1 96 bytes\s+1 80 bytes\s+2 176 bytes")

    def export_all(ctx, c: Checks):
        text = ctx["text"]
        target = exports / "all.json"
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("message", text, f"Exported 7 packet(s) from {pcap} to {target}")
        c.add("file_exists", target.is_file())
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            c.eq("packet_count", len(data), 7)
            layers = [p.get("_source", {}).get("layers", {}) for p in data]
            c.eq("frames", [l.get("frame", {}).get("frame.number") for l in layers],
                 [str(i) for i in range(1, 8)])
            c.eq("request_host", find_field(layers[5], "http.host"),
                 "fixture.ws-test.test")
            c.eq("response_code", find_field(layers[6], "http.response.code"), "200")
            c.eq("dns_name", find_field(layers[0], "dns.qry.name"),
                 "fixture.ws-test.test")

    def export_http_one(ctx, c: Checks):
        text = ctx["text"]
        target = exports / "http-one.json"
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("message", text, f"Exported 1 packet(s) from {pcap} to {target}")
        c.add("file_exists", target.is_file())
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            c.eq("packet_count", len(data), 1)
            layers = data[0]["_source"]["layers"]
            c.eq("frame", find_field(layers, "frame.number"), "6")
            c.eq("request_uri", find_field(layers, "http.request.uri"), "/fixture")

    def iec61850_no_match(ctx, c: Checks):
        text = ctx["text"]
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("exact_text", text, f"No GOOSE packets found in {pcap}")

    def read_corrupt(ctx, c: Checks):
        text = ctx["text"]
        c.contains("prefix", text, "Error reading pcap file: tshark failed:")
        c.contains("semantic", text,
                   "isn't a capture file in a format TShark understands")
        c.add("no_success_text", not text.startswith("Read "), trunc(text))
        c.add("isError_true", ctx["result"].get("isError") is True,
              ctx["result"].get("isError"))

    def filter_invalid(ctx, c: Checks):
        text = ctx["text"]
        c.contains("prefix", text, "Error applying display filter:")
        c.contains("semantic", text, "Unexpected end of filter expression")
        c.add("no_success_text", not text.startswith("Found "), trunc(text))
        c.add("isError_true", ctx["result"].get("isError") is True,
              ctx["result"].get("isError"))

    def export_missing(ctx, c: Checks):
        text = ctx["text"]
        missing = pcap.parent / "missing.pcap"
        c.eq("exact_text", text, f"Error: File not found: {missing}")
        c.add("isError_true", ctx["result"].get("isError") is True,
              ctx["result"].get("isError"))

    return {
        "ws-check-installation": check_installation,
        "ws-list-interfaces": list_interfaces,
        "ws-read-pcap-two": read_pcap_two,
        "ws-display-filter-http": display_filter_http,
        "ws-summarize-pcap": summarize,
        "ws-stats-by-proto": stats_by_proto,
        "ws-follow-tcp-0": follow_tcp,
        "ws-follow-udp-0": follow_udp,
        "ws-expert-info-warn": expert_info_warn,
        "ws-protocol-stats-conv-ip": protocol_stats,
        "ws-export-json-all": export_all,
        "ws-export-json-http-one": export_http_one,
        "ws-analyze-iec61850-no-match": iec61850_no_match,
        "ws-read-pcap-corrupt": read_corrupt,
        "ws-display-filter-invalid": filter_invalid,
        "ws-export-json-missing": export_missing,
    }


def run_wireshark(station: Path, out: Path, fixtures: dict, identities: dict) -> ProviderRun:
    fix = Path(fixtures["root"])
    pcap = fix / "dns-tcp-http.pcap"
    corrupt = fix / "corrupt.pcap"
    exports = out / "exports"
    config = out / "wireshark-config"
    run = ProviderRun("wireshark", station / "MCP/bin/wireshark-mcp.cmd", out,
                      {"WIRESHARK_CONFIG_DIR": str(config)})
    def exercise():
        exports.mkdir()
        config.mkdir()
        checks = ws_checks(pcap, corrupt, exports)
        plan = [
            ("ws-check-installation", "check_installation", {}),
            ("ws-list-interfaces", "list_interfaces", {}),
            ("ws-read-pcap-two", "read_pcap", {"file_path": str(pcap), "packet_count": 2}),
            ("ws-display-filter-http", "display_filter",
             {"file_path": str(pcap), "filter": "http"}),
            ("ws-summarize-pcap", "summarize_pcap", {"file_path": str(pcap)}),
            ("ws-stats-by-proto", "stats_by_proto", {"file_path": str(pcap)}),
            ("ws-follow-tcp-0", "follow_tcp", {"file_path": str(pcap), "stream_id": 0}),
            ("ws-follow-udp-0", "follow_udp", {"file_path": str(pcap), "stream_id": 0}),
            ("ws-expert-info-warn", "expert_info", {"file_path": str(pcap), "severity": "warn"}),
            ("ws-protocol-stats-conv-ip", "protocol_stats",
             {"file_path": str(pcap), "protocol": "conv", "variant": "ip"}),
            ("ws-export-json-all", "export_json",
             {"file_path": str(pcap), "output_path": str(exports / "all.json")}),
            ("ws-export-json-http-one", "export_json",
             {"file_path": str(pcap), "output_path": str(exports / "http-one.json"),
              "display_filter": "http", "packet_count": 1}),
            ("ws-analyze-iec61850-no-match", "analyze_iec61850",
             {"file_path": str(pcap), "protocol": "goose"}),
            ("ws-read-pcap-corrupt", "read_pcap", {"file_path": str(corrupt)}),
            ("ws-display-filter-invalid", "display_filter",
             {"file_path": str(pcap), "filter": "http and"}),
            ("ws-export-json-missing", "export_json",
             {"file_path": str(fix / "missing.pcap"), "output_path": str(exports / "x.json")}),
        ]
        for case_id, tool, args in plan:
            classification = "negative" if case_id.startswith(("ws-read-pcap-corrupt",
                                                              "ws-display-filter-invalid",
                                                              "ws-export-json-missing")) else ("partial" if case_id == "ws-analyze-iec61850-no-match" else "positive")
            run.call(case_id, tool, args, checks[case_id], classification=classification)
    run.execute(exercise)
    for case in run.cases:
        if case["case_id"] == "ws-check-installation":
            match = re.search(r"TShark \(Wireshark\) (\d+\.\d+\.\d+)",
                              case.get("content_text", ""))
            identities["tshark_version"] = match.group(1) if match else None
    return run


# ---------------------------------------------------------------------------
# 7-Zip checks


def z_checks(fix: Path, made: Path):
    data = fix / "sevenzip-input"
    alpha, beta, gamma = data / "alpha.txt", data / "beta.txt", data / "gamma.txt"
    alpha_bytes = (data / "alpha.txt").read_bytes()
    beta_bytes = (data / "beta.txt").read_bytes()
    gamma_bytes = (data / "gamma.txt").read_bytes()

    def crc(data_bytes: bytes) -> str:
        return "%08X" % (zlib.crc32(data_bytes) & 0xFFFFFFFF)

    def list_items(ctx) -> list[dict]:
        parsed = ctx["parsed"]
        return parsed if isinstance(parsed, list) else []

    def path_exists_true(ctx, c: Checks):
        c.eq("text", ctx["text"], "true")
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))

    def path_exists_false(ctx, c: Checks):
        c.eq("text", ctx["text"], "false")
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))

    def dir_list(ctx, c: Checks):
        items = list_items(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("entry_count", len(items), 3)
        by_name = {item.get("name"): item for item in items}
        c.eq("names", sorted(by_name), ["alpha.txt", "beta.txt", "gamma.txt"])
        for name, raw in (("alpha.txt", alpha_bytes), ("beta.txt", beta_bytes),
                          ("gamma.txt", gamma_bytes)):
            item = by_name.get(name, {})
            c.eq(name + "_type", item.get("type"), "file")
            c.eq(name + "_size", item.get("size"), str(len(raw)))
            c.eq(name + "_path", item.get("path"), str(data / name))
            c.add(name + "_keys", set(item) == {"type", "name", "size", "mtime", "path"},
                  sorted(item))

    def path_info(ctx, c: Checks):
        item = ctx["parsed"] if isinstance(ctx["parsed"], dict) else {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("keys", sorted(item), ["mtime", "name", "path", "size", "type"])
        c.eq("type", item.get("type"), "file")
        c.eq("name", item.get("name"), "alpha.txt")
        c.eq("size", item.get("size"), str(len(alpha_bytes)))
        c.eq("path", item.get("path"), str(alpha))

    def make(ctx, c: Checks):
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("returned_path", ctx["text"], str(made.resolve()))
        c.add("file_exists", made.is_file())
        if made.is_file():
            c.eq("7z_magic", made.read_bytes()[:6], b"7z\xbc\xaf\x27\x1c")

    def list_after_make(ctx, c: Checks):
        items = list_items(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("entry_count", len(items), 2)
        by_path = {item.get("Path"): item for item in items}
        c.eq("paths", sorted(by_path), ["alpha.txt", "beta.txt"])
        c.eq("alpha_size", by_path.get("alpha.txt", {}).get("Size"), str(len(alpha_bytes)))
        c.eq("alpha_crc", by_path.get("alpha.txt", {}).get("CRC"), crc(alpha_bytes))
        c.eq("beta_size", by_path.get("beta.txt", {}).get("Size"), str(len(beta_bytes)))
        c.eq("beta_crc", by_path.get("beta.txt", {}).get("CRC"), crc(beta_bytes))

    def replace(ctx, c: Checks):
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("returned_path", ctx["text"], str(made.resolve()))

    def list_after_replace(ctx, c: Checks):
        items = list_items(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("entry_count", len(items), 3)
        by_path = {item.get("Path"): item for item in items}
        c.eq("paths", sorted(by_path), ["alpha.txt", "beta.txt", "gamma.txt"])
        c.eq("gamma_size", by_path.get("gamma.txt", {}).get("Size"), str(len(gamma_bytes)))
        c.eq("gamma_crc", by_path.get("gamma.txt", {}).get("CRC"), crc(gamma_bytes))
        c.eq("alpha_crc", by_path.get("alpha.txt", {}).get("CRC"), crc(alpha_bytes))

    def remove(ctx, c: Checks):
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("returned_path", ctx["text"], str(made.resolve()))

    def list_after_remove(ctx, c: Checks):
        items = list_items(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("entry_count", len(items), 2)
        by_path = {item.get("Path"): item for item in items}
        c.eq("paths", sorted(by_path), ["alpha.txt", "gamma.txt"])
        c.add("beta_gone", "beta.txt" not in by_path)

    def make_bad_extension(ctx, c: Checks):
        c.add("isError_true", ctx["result"].get("isError") is True,
              ctx["result"].get("isError"))
        c.contains("message", ctx["text"],
                   "Unsupported archive format: .rar. Supported formats are .7z and .zip.")
        c.add("no_rar_created", not (fix / "bad.rar").exists())

    def list_missing(ctx, c: Checks):
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.contains("message", ctx["text"],
                   f"Archive file not found: {fix / 'missing.7z'}")

    def replace_missing(ctx, c: Checks):
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.contains("message", ctx["text"],
                   f"Archive file does not exist: {fix / 'missing.7z'}")

    def dir_list_file(ctx, c: Checks):
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.contains("message", ctx["text"],
                   f"Specified path is not a directory: {alpha.resolve()}")

    return {
        "z-path-exists-true": path_exists_true,
        "z-path-exists-false": path_exists_false,
        "z-dir-item-list": dir_list,
        "z-path-item-info": path_info,
        "z-make-archive": make,
        "z-list-after-make": list_after_make,
        "z-replace-items": replace,
        "z-list-after-replace": list_after_replace,
        "z-remove-items": remove,
        "z-list-after-remove": list_after_remove,
        "z-make-bad-extension": make_bad_extension,
        "z-list-missing": list_missing,
        "z-replace-missing": replace_missing,
        "z-dir-list-file": dir_list_file,
    }


def run_sevenzip(station: Path, out: Path, fixtures: dict) -> ProviderRun:
    fix = Path(fixtures["root"])
    data = fix / "sevenzip-input"
    made = out / "artifacts" / "made.7z"
    run = ProviderRun("sevenzip", station / "MCP/bin/7zip-mcp.cmd", out, {})
    def exercise():
        (out / "artifacts").mkdir()
        checks = z_checks(fix, made)
        plan = [
            ("z-path-exists-true", "mcp7zop_path_is_exist",
             {"item_path": str(data / "alpha.txt")}, "positive"),
            ("z-path-exists-false", "mcp7zop_path_is_exist",
             {"item_path": str(data / "missing.txt")}, "negative"),
            ("z-dir-item-list", "mcp7zop_get_dir_item_list", {"dir_path": str(data)}, "positive"),
            ("z-path-item-info", "mcp7zop_get_path_item_info",
             {"item_path": str(data / "alpha.txt")}, "positive"),
            ("z-make-archive", "mcp7zop_make_archive",
             {"archive_path": str(made),
              "input_pathes": [str(data / "alpha.txt"), str(data / "beta.txt")]}, "positive"),
            ("z-list-after-make", "mcp7zop_get_archive_item_list",
             {"archive_path": str(made)}, "positive"),
            ("z-replace-items", "mcp7zop_replace_archive_items",
             {"archive_path": str(made), "replace_pathes": [str(data / "gamma.txt")]},
             "positive"),
            ("z-list-after-replace", "mcp7zop_get_archive_item_list",
             {"archive_path": str(made)}, "positive"),
            ("z-remove-items", "mcp7zop_remove_archive_items",
             {"archive_path": str(made), "remove_item_paths": ["beta.txt"]}, "positive"),
            ("z-list-after-remove", "mcp7zop_get_archive_item_list",
             {"archive_path": str(made)}, "positive"),
            ("z-make-bad-extension", "mcp7zop_make_archive",
             {"archive_path": str(fix / "bad.rar"), "input_pathes": [str(data / "alpha.txt")]},
             "negative"),
            ("z-list-missing", "mcp7zop_get_archive_item_list",
             {"archive_path": str(fix / "missing.7z")}, "negative"),
            ("z-replace-missing", "mcp7zop_replace_archive_items",
             {"archive_path": str(fix / "missing.7z"),
              "replace_pathes": [str(data / "alpha.txt")]}, "negative"),
            ("z-dir-list-file", "mcp7zop_get_dir_item_list",
             {"dir_path": str(data / "alpha.txt")}, "negative"),
        ]
        for case_id, tool, args, classification in plan:
            run.call(case_id, tool, args, checks[case_id], classification=classification)
    run.execute(exercise)
    return run


# ---------------------------------------------------------------------------
# REA checks


def zip_member_hashes(path: Path) -> dict[str, str]:
    result = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            result[info.filename] = sha256_bytes(archive.read(info))
    return result


def rea_checks(fix: Path, manifest: dict, bundle_path: Path):
    files = manifest["files"]
    app = fix / "js-app"
    bad_app = fix / "js-app-bad"
    esm_a = fix / "js-app-esm-a"
    esm_b = fix / "js-app-esm-b"
    zip1 = fix / "archive-v1.zip"
    zip2 = fix / "archive-v2.zip"
    corrupt_zip = fix / "corrupt.zip"
    pe = fix / "fixture.pe"
    missing = fix / "missing-app"
    evidence: dict[str, dict] = {}

    def result_body(ctx) -> dict:
        parsed = ctx["parsed"]
        return parsed if isinstance(parsed, dict) else {}

    def err(ctx) -> dict:
        body = result_body(ctx)
        return body.get("error") or {}

    def ok_evidence(ctx, c: Checks, key: str) -> dict:
        body = result_body(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False),
              ctx["result"].get("isError"))
        c.add("evidence_id_shape", bool(re.match(r"^ev_[a-f0-9]{64}$",
                                                 body.get("evidence_id", ""))),
              body.get("evidence_id"))
        evidence[key] = body
        return body

    def session_initial(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("open", result.get("open"), False)
        capabilities = result.get("capabilities") or []
        c.eq("capability_count", len(capabilities), 18)
        ops = {item.get("operation"): item for item in capabilities}
        required = ["inspect_artifact", "extract_artifact", "inspect_managed_artifact",
                    "inspect_managed_members", "inspect_managed_native_boundaries",
                    "decode_interface_builder", "inspect_keyed_archive",
                    "trace_dylib_resolution"]
        c.eq("required_available",
             sorted(op for op in required if ops.get(op, {}).get("available")), sorted(required))
        unavailable = [item for item in capabilities if not item.get("available")]
        c.add("unavailable_have_reasons",
              all(item.get("availability_code") and item.get("reason")
                  for item in unavailable),
              [item.get("operation") for item in unavailable])
        identity = result.get("server_identity") or {}
        c.eq("rea_version", (identity.get("package") or {}).get("version"), "6.4.0")
        c.eq("rea_server", (identity.get("server") or {}).get("name"), "rea")
        c.eq("negotiated_protocol", identity.get("negotiated_protocol_version"),
             "2025-11-25")
        c.eq("catalog_tool_count", (identity.get("catalog") or {}).get("counts", {})
             .get("mcp_tools"), 170)
        evidence["session_identity"] = identity

    def unknowns_empty(ctx, c: Checks):
        result = (result_body(ctx).get("result") or {})
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("items", result.get("items"), [])
        c.eq("total", result.get("total"), 0)

    def bundle_empty(ctx, c: Checks):
        result = (result_body(ctx).get("result") or {})
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        for key in ("records", "unknowns", "artifacts", "providers"):
            c.eq(key + "_empty", result.get(key), [])

    def analyze_app(ctx, c: Checks):
        body = ok_evidence(ctx, c, "js_app")
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "analyze_javascript_application")
        c.eq("provider", (body.get("provider") or {}).get("id"),
             "rea-javascript-application")
        c.eq("format", nr.get("format"), "directory")
        c.eq("input_path", nr.get("input_path"), str(app))
        stats = nr.get("statistics") or {}
        c.eq("relevant_files", stats.get("relevant_files"), 3)
        c.eq("parsed_javascript_files", stats.get("parsed_javascript_files"), 2)
        c.eq("parse_failures", stats.get("parse_failures"), 0)
        c.eq("invalid_utf8_files", stats.get("invalid_utf8_files"), 0)
        c.eq("nested_asar", stats.get("nested_asar_containers"), 0)
        c.eq("modules", stats.get("modules"), 0)
        c.eq("integrity_contradictions", nr.get("integrity_contradictions"), [])
        c.eq("root_digest", nr.get("root_artifact_sha256"),
             (body.get("subject") or {}).get("digest", {}).get("sha256"))
        graph = nr.get("graph") or {}
        c.eq("graph_schema", graph.get("schema"), "JavaScriptApplicationGraph")
        nodes = graph.get("nodes") or []
        path_hashes = {}
        package_obs = None
        for node in nodes:
            observations = node.get("observations") or []
            props = (observations[0].get("properties") if observations else {}) or {}
            path = props.get("path")
            digest = (node.get("identity") or {}).get("sha256")
            if path and digest:
                path_hashes[path] = digest
            if node.get("kind") == "package":
                package_obs = props
        expected_hashes = {
            "package.json": files["js_app_package"]["sha256"],
            "src/main.js": files["js_app_main"]["sha256"],
            "src/util.js": files["js_app_util"]["sha256"],
        }
        c.eq("file_hashes", path_hashes, expected_hashes)
        c.eq("package_name", (package_obs or {}).get("name"), "ws-fixture-app")
        c.eq("package_version", (package_obs or {}).get("version"), "1.2.3")
        c.eq("package_main", (package_obs or {}).get("main"), "src/main.js")
        c.eq("package_parse_status", (package_obs or {}).get("parse_status"), "included")

    def analyze_bad(ctx, c: Checks):
        body = ok_evidence(ctx, c, "js_bad")
        nr = body.get("normalized_result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("operation", body.get("operation"), "analyze_javascript_application")
        stats = nr.get("statistics") or {}
        c.eq("relevant_files", stats.get("relevant_files"), 2)
        c.eq("parsed_javascript_files", stats.get("parsed_javascript_files"), 1)
        c.eq("integrity_contradictions", nr.get("integrity_contradictions"), [])
        package_obs = None
        for node in (nr.get("graph") or {}).get("nodes") or []:
            if node.get("kind") == "package":
                observations = node.get("observations") or []
                package_obs = (observations[0].get("properties") if observations else {}) or {}
        c.eq("package_parse_status", (package_obs or {}).get("parse_status"), "invalid")
        c.eq("package_name_null", (package_obs or {}).get("name"), None)
        c.eq("package_version_null", (package_obs or {}).get("version"), None)

    def analyze_missing(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "invalid_request")
        issues = (error.get("details") or {}).get("issues") or []
        c.eq("issue_path", (issues[0] or {}).get("path") if issues else None, ["input_path"])
        c.eq("issue_reason", (issues[0] or {}).get("reason") if issues else None,
             "invalid_value")
        c.contains("enoent", (issues[0] or {}).get("message", "") if issues else "", "ENOENT")

    def analyze_esm(ctx, c: Checks):
        key = "esm_a" if "esm-a" in ctx.get("case_id", "") else "esm_b"
        body = ok_evidence(ctx, c, key)
        nr = body.get("normalized_result") or {}
        c.eq("format", nr.get("format"), "directory")
        c.eq("parsed_javascript_files",
             (nr.get("statistics") or {}).get("parsed_javascript_files"), 2)
        exports = []
        for edge in (nr.get("graph") or {}).get("edges") or []:
            if edge.get("relation") == "exposes":
                exports.append((edge.get("properties") or {}).get("exported_name"))
        c.eq("exports", sorted(exports), ["GREETING", "greet", "normalize"])

    def trace(ctx, c: Checks):
        body = ok_evidence(ctx, c, "trace")
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "trace_javascript_semantics")
        c.eq("provider", (body.get("provider") or {}).get("id"),
             "rea-javascript-application-workflows")
        c.eq("status", nr.get("status"), "ambiguous")
        c.eq("summary", nr.get("summary"), {
            "total_seed_matches": 1, "traversed_nodes": 5,
            "traversed_relations": 4, "traversed_functions": 1,
            "traversed_modules": 1, "relevant_unknowns": 1})
        c.eq("seed", nr.get("seed"),
             {"kind": "literal", "value": "hello-from-authored-fixture"})
        c.eq("coverage_status", (nr.get("coverage") or {}).get("status"), "partial")
        unknowns = nr.get("unknowns") or []
        c.eq("unknown_count", len(unknowns), 1)
        if unknowns:
            c.eq("unknown_family", unknowns[0].get("family"), "call-flow")
            c.eq("unknown_reason", unknowns[0].get("reason"), "dynamic-call")
        c.eq("application_evidence_id",
             (body.get("parameters") or {}).get("application_evidence_id"),
             (evidence.get("js_app") or {}).get("evidence_id"))

    def analysis_view(ctx, c: Checks):
        body = ok_evidence(ctx, c, "view")
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "inspect_analysis_view")
        c.eq("provider", (body.get("provider") or {}).get("id"), "rea-analysis-view")
        c.eq("kind", nr.get("kind"), "summary")
        c.eq("view_kind", (nr.get("view") or {}).get("kind"), "summary")
        parent = evidence.get("js_app") or {}
        c.eq("parent_evidence_id", (body.get("parameters") or {}).get("parent_evidence_id"),
             parent.get("evidence_id"))
        summary = nr.get("summary") or {}
        c.eq("input_path", summary.get("input_path"), str(app))
        c.eq("statistics_match",
             summary.get("statistics"),
             (parent.get("normalized_result") or {}).get("statistics"))
        c.eq("root_digest", summary.get("root_artifact_sha256"),
             (parent.get("normalized_result") or {}).get("root_artifact_sha256"))
        c.eq("evidence_links", body.get("evidence_links"), [parent.get("evidence_id")])

    def compare_shapes(ctx, c: Checks):
        body = ok_evidence(ctx, c, "shapes")
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "compare_javascript_export_shapes")
        left = nr.get("left") or {}
        right = nr.get("right") or {}
        c.eq("left_status", left.get("status"), "selected")
        c.eq("right_status", right.get("status"), "selected")
        c.add("left_selected_node", bool(left.get("selected_node_id")),
              left.get("selected_node_id"))
        c.add("right_selected_node", bool(right.get("selected_node_id")),
              right.get("selected_node_id"))
        c.eq("summary", nr.get("summary"),
             {"added": 0, "removed": 0, "changed": 0, "unknown": 2})
        c.eq("coverage_status", (nr.get("coverage") or {}).get("status"), "partial")
        changes = nr.get("changes") or []
        c.eq("change_count", len(changes), 2)
        c.add("all_unknown", all(change.get("status") == "unknown" for change in changes),
              [change.get("status") for change in changes])
        reasons = [((change.get("left") or {}).get("reason") or "") +
                   ((change.get("right") or {}).get("reason") or "") for change in changes]
        c.add("pairing_reasons",
              all("unique exact cross-version pairing" in reason for reason in reasons),
              reasons)
        c.eq("evidence_links", body.get("evidence_links"),
             [(evidence.get("esm_a") or {}).get("evidence_id"),
              (evidence.get("esm_b") or {}).get("evidence_id")])

    def open_zip1(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("path", result.get("path"), str(zip1))
        c.eq("format", result.get("format"), "zip")
        c.eq("kind", result.get("kind"), "archive")
        c.eq("sha256", result.get("sha256"), files["archive_v1"]["sha256"])
        c.eq("architecture", result.get("architecture"), None)

    def inspect_zip(ctx, c: Checks, key: str, zip_path: Path, expected_sha: str,
                    expected_paths: set[str]):
        body = ok_evidence(ctx, c, key)
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "inspect_artifact")
        c.eq("provider", (body.get("provider") or {}).get("id"), "rea-artifact-graph")
        substeps = nr.get("substeps") or []
        c.eq("substep_count", len(substeps), 1)
        if not substeps:
            return
        substep = substeps[0]
        c.eq("substep_operation", substep.get("operation"), "inventory_artifact")
        inventory = (substep.get("evidence") or {})
        inv = inventory.get("normalized_result") or {}
        c.add("inventory_evidence_shape",
              bool(re.match(r"^ev_[a-f0-9]{64}$", inventory.get("evidence_id", ""))),
              inventory.get("evidence_id"))
        manifest_data = inv.get("manifest") or {}
        c.eq("node_count", manifest_data.get("node_count"), len(expected_paths) + 1)
        c.eq("occurrence_count", manifest_data.get("occurrence_count"),
             len(expected_paths) + 1)
        c.eq("edge_count", manifest_data.get("edge_count"), len(expected_paths))
        c.eq("root_sha256", manifest_data.get("root_sha256"), expected_sha)
        c.eq("root_format", manifest_data.get("root_format"), "zip")
        nodes = {node.get("artifact_id"): node.get("sha256")
                 for node in inv.get("nodes") or []}
        occurrences = inv.get("occurrences") or []
        paths = sorted(item.get("logical_path") for item in occurrences)
        c.eq("logical_paths", paths, sorted({".", *expected_paths}))
        expected_hashes = zip_member_hashes(zip_path)
        actual_hashes = {}
        for item in occurrences:
            path = item.get("logical_path")
            if path in expected_hashes:
                actual_hashes[path] = nodes.get(item.get("artifact_id"))
        c.eq("member_hashes", actual_hashes, expected_hashes)
        c.eq("evidence_links", body.get("evidence_links"),
             [inventory.get("evidence_id")])
        evidence["inv_" + key] = inventory

    def compare_artifacts(ctx, c: Checks):
        body = ok_evidence(ctx, c, "compare")
        nr = body.get("normalized_result") or {}
        c.eq("operation", body.get("operation"), "compare_artifacts")
        c.eq("provider", (body.get("provider") or {}).get("id"),
             "rea-artifact-comparison")
        c.eq("status", nr.get("status"), "changed")
        c.eq("summary", nr.get("summary"), {
            "unchanged": 2, "added": 1, "removed": 0,
            "changed": 2, "unknown": 0, "contradiction": 0})
        changes = nr.get("changes") or []
        by_path = {change.get("logical_path"): change for change in changes}
        c.eq("change_paths", sorted(by_path), [".", "data/added.txt", "pkg/package.json"])
        c.eq("added_classification",
             (by_path.get("data/added.txt") or {}).get("classification"), "added")
        c.eq("package_classification",
             (by_path.get("pkg/package.json") or {}).get("classification"), "changed")
        c.eq("root_classification", (by_path.get(".") or {}).get("classification"),
             "changed")
        c.eq("evidence_links", body.get("evidence_links"),
             [(evidence.get("inv_zip1") or {}).get("evidence_id"),
              (evidence.get("inv_zip2") or {}).get("evidence_id")])

    def export_bundle(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        target = Path(result.get("path") or "")
        c.eq("path", str(target), str(bundle_path))
        c.add("file_exists", target.is_file(), str(target))
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            c.eq("bytes", result.get("bytes"), target.stat().st_size)
            c.eq("records", result.get("records"), len(data.get("records") or []))
            c.eq("unknowns", result.get("unknowns"), len(data.get("unknowns") or []))
            ids = {record.get("evidence_id") for record in data.get("records") or []}
            expected_ids = [ev.get("evidence_id") for key, ev in evidence.items()
                            if key not in ("session_identity", "export", "bundle")]
            missing_ids = [ev_id for ev_id in expected_ids if ev_id and ev_id not in ids]
            c.eq("retained_evidence_ids", missing_ids, [])
            evidence["bundle"] = data
            evidence["bundle_sha256"] = sha256_file(target)

    def export_exists(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "invalid_request")
        c.eq("reason", (error.get("details") or {}).get("reason"), "exists")
        c.contains("message", error.get("message", ""), "Evidence file already exists")

    def export_overwrite(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        target = Path(result.get("path") or "")
        c.add("file_exists", target.is_file(), str(target))
        if target.is_file():
            c.eq("deterministic_sha256", sha256_file(target),
                 evidence.get("bundle_sha256"))

    def close_target(ctx, c: Checks):
        body = result_body(ctx)
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.add("parsed_object", isinstance(ctx["parsed"], dict))
        c.add("explicit_result", "result" in body)
        c.add("no_structured_error", not body.get("error"))
        c.eq("result_null", body.get("result"), None)

    def session_after_close(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.add("parsed_object", isinstance(ctx["parsed"], dict))
        c.add("explicit_result", isinstance(body.get("result"), dict))
        c.add("no_structured_error", not body.get("error"))
        c.eq("open", result.get("open"), False)

    def open_pe_auto(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "capability_unavailable")
        details = error.get("details") or {}
        c.eq("selection_reason", details.get("selection_reason"), "ambiguous")
        c.eq("candidates", sorted(details.get("candidate_ids") or []),
             ["ghidra", "hopper", "ida"])

    def open_pe(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("path", result.get("path"), str(pe))
        c.eq("format", result.get("format"), "pe")
        c.eq("kind", result.get("kind"), "executable")
        c.eq("architecture", result.get("architecture"), "x86")
        c.eq("sha256", result.get("sha256"), files["pe"]["sha256"])

    def overview(ctx, c: Checks):
        body = ok_evidence(ctx, c, "overview")
        nr = body.get("normalized_result") or {}
        c.regex("document", nr.get("document") or "", r"^target-[0-9a-f]{12}\.pe$")
        c.eq("segment_count", nr.get("segment_count"), 2)
        c.eq("segments", nr.get("segments"), [
            {"name": "Headers", "start": "0x0", "end": "0x200", "length": 512},
            {"name": ".text", "start": "0x1000", "end": "0x1200", "length": 512}])
        c.eq("procedure_count", nr.get("procedure_count"), 1)
        c.eq("string_count", nr.get("string_count"), 2)

    def strings(ctx, c: Checks):
        body = ok_evidence(ctx, c, "strings")
        nr = body.get("normalized_result")
        expected = [
            {"address": "0x1010", "value": "WS-FIXTURE-STRING",
             "string": {"encoding": "US-ASCII",
                        "termination": "present_or_not_required",
                        "byte_length": 18}},
            {"address": "0x1022", "value": "authored-pe-fixture",
             "string": {"encoding": "US-ASCII",
                        "termination": "present_or_not_required",
                        "byte_length": 22}},
        ]
        c.eq("strings", nr, expected)

    def search(ctx, c: Checks):
        body = ok_evidence(ctx, c, "search")
        c.eq("matches", body.get("normalized_result"),
             [{"address": "0x1010", "value": "WS-FIXTURE-STRING"}])

    def open_corrupt_zip(ctx, c: Checks):
        body = result_body(ctx)
        result = body.get("result") or {}
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        c.eq("format", result.get("format"), "zip")
        c.eq("kind", result.get("kind"), "archive")
        c.eq("sha256", result.get("sha256"), files["corrupt_zip"]["sha256"])

    def inspect_corrupt_zip(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "artifact_operation_failed")
        c.eq("reason", (error.get("details") or {}).get("reason"), "io")
        c.contains("message", error.get("message", ""),
                   "Artifact could not be read or written")

    def open_missing(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "target_unavailable")
        c.contains("enoent", error.get("message", ""), "ENOENT")
        c.eq("path", (error.get("details") or {}).get("path"), str(missing))

    def inspect_binary_layout_blocked(ctx, c: Checks):
        error = err(ctx)
        c.add("isError_true", ctx["result"].get("isError") is True)
        c.eq("code", error.get("code"), "capability_unavailable")
        c.eq("provider", (error.get("details") or {}).get("provider_id"),
             "pwntools-elf")
        c.contains("message", error.get("message", ""),
                   "supports Linux x64 only")

    def unknowns_final(ctx, c: Checks):
        result = (result_body(ctx).get("result") or {})
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        total = result.get("total")
        items = result.get("items") or []
        c.eq("items_match_total", len(items), total)
        bundle = evidence.get("bundle") or {}
        c.eq("matches_bundle", total, len(bundle.get("unknowns") or []))
        c.add("domains", any(item.get("domain") == "artifact-comparison"
                             for item in items),
              [item.get("domain") for item in items])
        c.add("required_fields",
              all(item.get("unknown_id") and item.get("question") and
                  item.get("severity") and item.get("domain") and item.get("status")
                  for item in items), len(items))

    def bundle_final(ctx, c: Checks):
        result = (result_body(ctx).get("result") or {})
        c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
        bundle = evidence.get("bundle") or {}
        c.eq("kind", result.get("kind"), "evidence-bundle-summary")
        c.eq("total_retained_records", result.get("total_retained_records"),
             len(bundle.get("records") or []))
        c.eq("matching_records", result.get("matching_records"),
             len(bundle.get("records") or []))
        c.eq("record_count", len(result.get("records") or []),
             len(bundle.get("records") or []))
        c.add("records_have_operation",
              all(record.get("operation") and record.get("evidence_id")
                  for record in result.get("records") or []),
              len(result.get("records") or []))

    checks = {
        "rea-session-initial": session_initial,
        "rea-list-unknowns-empty": unknowns_empty,
        "rea-evidence-bundle-empty": bundle_empty,
        "rea-analyze-js-app": analyze_app,
        "rea-analyze-js-bad-package": analyze_bad,
        "rea-analyze-js-missing": analyze_missing,
        "rea-analyze-esm-a": analyze_esm,
        "rea-analyze-esm-b": analyze_esm,
        "rea-trace-js-literal": trace,
        "rea-analysis-view-summary": analysis_view,
        "rea-compare-export-shapes": compare_shapes,
        "rea-open-zip1": open_zip1,
        "rea-inspect-zip1": lambda ctx, c: inspect_zip(
            ctx, c, "zip1", zip1, files["archive_v1"]["sha256"],
            set(zip_member_hashes(zip1))),
        "rea-open-zip2": lambda ctx, c: None,  # replaced below
        "rea-inspect-zip2": lambda ctx, c: inspect_zip(
            ctx, c, "zip2", zip2, files["archive_v2"]["sha256"],
            set(zip_member_hashes(zip2))),
        "rea-compare-artifacts": compare_artifacts,
        "rea-export-bundle": export_bundle,
        "rea-export-bundle-exists": export_exists,
        "rea-export-bundle-overwrite": export_overwrite,
        "rea-list-unknowns-final": unknowns_final,
        "rea-evidence-bundle-final": bundle_final,
        "rea-close-archive": close_target,
        "rea-session-after-close": session_after_close,
        "rea-open-pe-auto-ambiguous": open_pe_auto,
        "rea-open-pe-ghidra": open_pe,
        "rea-binary-overview": overview,
        "rea-list-strings": strings,
        "rea-search-strings": search,
        "rea-close-pe": close_target,
        "rea-open-corrupt-zip": open_corrupt_zip,
        "rea-inspect-corrupt-zip": inspect_corrupt_zip,
        "rea-open-missing": open_missing,
        "rea-inspect-binary-layout-blocked": inspect_binary_layout_blocked,
    }
    return checks, evidence


def run_rea(station: Path, out: Path, fixtures: dict) -> ProviderRun:
    fix = Path(fixtures["root"])
    app = fix / "js-app"
    bad_app = fix / "js-app-bad"
    esm_a = fix / "js-app-esm-a"
    esm_b = fix / "js-app-esm-b"
    zip1 = fix / "archive-v1.zip"
    zip2 = fix / "archive-v2.zip"
    corrupt_zip = fix / "corrupt.zip"
    pe = fix / "fixture.pe"
    missing = fix / "missing-app"
    run = ProviderRun("rea", station / "MCP/bin/rea-mcp.cmd", out, {})
    def exercise():
        checks, evidence = rea_checks(fix, fixtures, out / "bundle.json")

        def open_zip2(ctx, c: Checks):
            body = ctx["parsed"] if isinstance(ctx["parsed"], dict) else {}
            result = body.get("result") or {}
            c.add("isError_not_true", ctx["result"].get("isError") in (None, False))
            c.eq("path", result.get("path"), str(zip2))
            c.eq("format", result.get("format"), "zip")
            c.eq("kind", result.get("kind"), "archive")
            c.eq("sha256", result.get("sha256"),
                 fixtures["files"]["archive_v2"]["sha256"])

        checks["rea-open-zip2"] = open_zip2
        plan = [
            ("rea-session-initial", "binary_session", {}, "positive"),
            ("rea-list-unknowns-empty", "list_unknowns", {}, "positive"),
            ("rea-evidence-bundle-empty", "get_evidence_bundle", {}, "positive"),
            ("rea-analyze-js-app", "analyze_javascript_application",
             {"input_path": str(app), "format": "directory"}, "positive"),
            ("rea-analyze-js-bad-package", "analyze_javascript_application",
             {"input_path": str(bad_app), "format": "directory"}, "negative"),
            ("rea-analyze-js-missing", "analyze_javascript_application",
             {"input_path": str(missing), "format": "directory"}, "negative"),
            ("rea-analyze-esm-a", "analyze_javascript_application",
             {"input_path": str(esm_a), "format": "directory"}, "positive"),
            ("rea-analyze-esm-b", "analyze_javascript_application",
             {"input_path": str(esm_b), "format": "directory"}, "positive"),
            ("rea-trace-js-literal", "trace_javascript_semantics",
             {"application": None, "query": {
                 "seed": {"kind": "literal", "value": "hello-from-authored-fixture"},
                 "direction": "forward-influence"}}, "partial"),
            ("rea-analysis-view-summary", "inspect_analysis_view",
             {"source": None, "view": {"kind": "summary"}}, "positive"),
            ("rea-compare-export-shapes", "compare_javascript_export_shapes",
             {"left": None, "left_module_path": "src/main.js", "left_export_name": "greet",
              "right": None, "right_module_path": "src/main.js",
              "right_export_name": "greet"}, "partial"),
            ("rea-open-zip1", "open_binary", {"path": str(zip1)}, "positive"),
            ("rea-inspect-zip1", "inspect_artifact", {}, "positive"),
            ("rea-open-zip2", "open_binary", {"path": str(zip2)}, "positive"),
            ("rea-inspect-zip2", "inspect_artifact", {}, "positive"),
            ("rea-compare-artifacts", "compare_artifacts",
             {"left": None, "right": None}, "positive"),
            ("rea-export-bundle", "export_evidence_bundle",
             {"path": str(out / "bundle.json")}, "positive"),
            ("rea-export-bundle-exists", "export_evidence_bundle",
             {"path": str(out / "bundle.json")}, "negative"),
            ("rea-export-bundle-overwrite", "export_evidence_bundle",
             {"path": str(out / "bundle.json"), "overwrite": True}, "positive"),
            ("rea-list-unknowns-final", "list_unknowns", {}, "positive"),
            ("rea-evidence-bundle-final", "get_evidence_bundle",
             {"detail": "summary"}, "positive"),
            ("rea-close-archive", "close_binary", {}, "positive"),
            ("rea-session-after-close", "binary_session", {}, "positive"),
            ("rea-open-pe-auto-ambiguous", "open_binary", {"path": str(pe)}, "negative"),
            ("rea-open-pe-ghidra", "open_binary",
             {"path": str(pe), "provider_id": "ghidra"}, "positive"),
            ("rea-binary-overview", "binary_overview", {}, "positive"),
            ("rea-list-strings", "list_strings", {}, "positive"),
            ("rea-search-strings", "search_strings", {"pattern": "WS-FIXTURE"}, "positive"),
            ("rea-close-pe", "close_binary", {}, "positive"),
            ("rea-open-corrupt-zip", "open_binary", {"path": str(corrupt_zip)}, "positive"),
            ("rea-inspect-corrupt-zip", "inspect_artifact", {}, "negative"),
            ("rea-open-missing", "open_binary", {"path": str(missing)}, "negative"),
            ("rea-inspect-binary-layout-blocked", "inspect_binary_layout",
             {"path": str(pe)}, "blocked"),
        ]
        for case_id, tool, args, classification in plan:
            if case_id == "rea-trace-js-literal":
                args["application"] = evidence["js_app"]
            elif case_id == "rea-analysis-view-summary":
                args["source"] = {"kind": "inline", "evidence": evidence["js_app"]}
            elif case_id == "rea-compare-export-shapes":
                args["left"] = evidence["esm_a"]
                args["right"] = evidence["esm_b"]
            elif case_id == "rea-compare-artifacts":
                args["left"] = evidence["inv_zip1"]
                args["right"] = evidence["inv_zip2"]
            if case_id in ("rea-binary-overview", "rea-list-strings",
                           "rea-search-strings", "rea-open-pe-ghidra") or \
                    tool == "analyze_javascript_application":
                timeout = 90.0
            else:
                timeout = 30.0
            run.call(case_id, tool, args, checks[case_id],
                     classification=classification, timeout=timeout)
    run.execute(exercise)
    return run


# ---------------------------------------------------------------------------
# Coverage / report


def build_coverage(catalog: dict, runs: dict[str, ProviderRun]) -> dict:
    """Derive acceptance from executed cases; a catalog/name is never a PASS."""
    statuses = ("PASS", "PARTIAL", "NEGATIVE_ONLY", "BLOCKED", "FAILED",
                "UNTESTED", "OUT_OF_SCOPE")
    providers = {}
    totals = dict.fromkeys(("catalog_methods", "methods_called", "calls",
                           "negative_cases", "prior_methods_called", "new_methods_vs_prior",
                           *(status.lower() for status in statuses)), 0)
    for name, provider in catalog["providers"].items():
        run = runs.get(name)
        cases = run.cases if run else []
        by_tool = {}
        for case in cases:
            by_tool.setdefault(case["tool"], []).append(case)
        methods = {}
        for tool in provider.get("tools") or []:
            tool_name = tool["name"]
            observed = by_tool.get(tool_name, [])
            kinds = {c.get("classification") for c in observed}
            failed = [c["case_id"] for c in observed if not c.get("all_pass")]
            reason = ""
            if failed:
                status, reason = "FAILED", "failed cases: " + ", ".join(failed)
            elif observed:
                if kinds <= {"blocked"}:
                    status, reason = "BLOCKED", "provider explicitly refused the fixture capability"
                elif "partial" in kinds:
                    status, reason = "PARTIAL", "only partial/no-match semantics established"
                elif "positive" in kinds:
                    status = "PASS"
                else:
                    status, reason = "NEGATIVE_ONLY", "only rejection/absence paths exercised"
            elif name == "wireshark" and tool_name == "live_capture":
                status, reason = "OUT_OF_SCOPE", "live capture not selected by this offline lab"
            else:
                status, reason = "UNTESTED", "no call in this run"
            methods[tool_name] = {
                "status": status,
                "cases": [c["case_id"] for c in observed],
                "called": bool(observed),
                "previously_exercised": tool_name in PRIOR_METHODS.get(name, set()),
                "preconditions": "authored fixtures; see exact request arguments" if observed else reason,
                "evidence": f"runs/{name}/cases.json" if observed else f"runs/{name}/catalog.json",
                "reason": reason,
            }
        counts = {status: sum(m["status"] == status for m in methods.values()) for status in statuses}
        unknown = sorted(set(by_tool) - set(methods))
        providers[name] = {
            "catalog_count": len(provider.get("tools") or []),
            "case_count": len(cases), "methods": methods, "counts": counts,
            "called_but_not_cataloged": unknown,
            "run_error": run.error if run else "no provider run",
            "cleanup_observed": run.cleanup_ok if run else False,
        }
        totals["catalog_methods"] += len(provider.get("tools") or [])
        totals["methods_called"] += len(by_tool)
        totals["calls"] += len(cases)
        totals["negative_cases"] += sum(c.get("classification") == "negative" for c in cases)
        totals["prior_methods_called"] += len(set(by_tool) & PRIOR_METHODS.get(name, set()))
        for status, count in counts.items():
            totals[status.lower()] += count
    totals["new_methods_vs_prior"] = totals["methods_called"] - totals["prior_methods_called"]
    return {"schema": "tool-lab-coverage/2", "generated_utc": utc_now(),
            "scope": "executed fixture cases only; not whole-method or whole-tool certification",
            "prior_methods_not_counted_as_new": {k: sorted(v) for k, v in PRIOR_METHODS.items()},
            "providers": providers, "totals": totals}


def collect_failures(coverage: dict, runs: dict, input_integrity=None) -> list[str]:
    failures = []
    for name, run in runs.items():
        if run.error:
            failures.append(f"{name}: {run.error}")
        if not run.cases:
            failures.append(f"{name}: no cases executed")
        if coverage["providers"][name]["called_but_not_cataloged"]:
            failures.append(f"{name}: called method absent from catalog")
        if not run.cleanup_ok:
            failures.append(f"{name}: cleanup not observed")
        if run.session.get("stdout_audit", {}).get("wire_protocol_clean") is not True:
            failures.append(f"{name}: clean stdout through reader shutdown not observed")
        for case in run.cases:
            if not case.get("all_pass"):
                failures.append(f"{name}/{case['case_id']}: "
                                f"{', '.join(case.get('failed_checks') or ['failed'])}")
    if input_integrity is not None and not input_integrity.get("unchanged"):
        failures.append("authored fixture files changed during the run")
    return failures


def fixture_snapshot(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha256_file(p)
            for p in sorted(root.rglob("*")) if p.is_file()}


def build_report(output: Path, coverage: dict, runs: dict[str, ProviderRun],
                 identities: dict) -> str:
    lines = [
        "# Bounded offline MCP tool-lab — Wireshark / 7-Zip / REA",
        "",
        f"Run: `{output.name}`  ",
        f"Generated: {utc_now()}  ",
        f"Station: `{identities['station']}`  ",
        "Worker slice: authored fixtures only; no live capture, browser, ADB, "
        "network service, process target or sample execution.",
        "",
        "## Command",
        "",
        "```",
        f"\"{identities.get('client_python_executable', sys.executable)}\" -X utf8 scripts/tool_lab/offline_acceptance.py "
        f"--station \"{identities['station']}\" --output \"{output}\"",
        "```",
        "",
        "## Source and runtime identity",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Station git HEAD | `{identities.get('station_git_head')}` |",
        f"| Wireshark wrapper SHA-256 | `{identities['wrappers']['wireshark']}` |",
        f"| 7-Zip wrapper SHA-256 | `{identities['wrappers']['sevenzip']}` |",
        f"| REA wrapper SHA-256 | `{identities['wrappers']['rea']}` |",
        f"| tshark version | `{identities.get('tshark_version')}` |",
        f"| Client Python | `{identities['client_python']}` |",
        f"| RawMcp client SHA-256 | `{identities['raw_mcp_sha256']}` |",
        f"| Fixture manifest | `fixtures/fixtures.json` |",
        "",
        "Provider source hashes and the REA server identity are in "
        "`identities.json`; full schemas are in `catalog.json`.",
        "",
        "## Catalog",
        "",
        "| Provider | Advertised tools | Cases |",
        "|---|---:|---:|",
    ]
    for name, provider in coverage["providers"].items():
        lines.append(f"| {name} | {provider['catalog_count']} | {provider['case_count']} |")
    totals = coverage["totals"]
    lines += [
        "",
        f"Cataloged methods: {totals['catalog_methods']}; "
        f"distinct methods called: {totals['methods_called']}; "
        f"calls: {totals['calls']}; negative controls: {totals['negative_cases']}.",
        "",
        "## Method status",
        "",
        "| Provider | Method | Status | Cases | Reason / note |",
        "|---|---|---|---|---|",
    ]
    for name, provider in coverage["providers"].items():
        for method, info in sorted(provider["methods"].items()):
            cases = ", ".join(info["cases"]) if info["cases"] else "—"
            reason = info["reason"].replace("|", "\\|")
            lines.append(f"| {name} | `{method}` | {info['status']} | {cases} | {reason} |")
    failures = collect_failures(coverage, runs, identities.get("input_integrity"))
    lines += ["", "## Explicit failures", ""]
    lines += [f"- {item}" for item in failures] if failures else ["- None."]
    lines += [
        "",
        "## Acceptance requirements",
        "",
        "- The selected 7-Zip negatives must return MCP `isError: true` with exact refusal text "
        "(unsupported extension, missing archive, directory/file confusion).",
        "- The selected REA negatives must return structured error objects (`invalid_request`, "
        "`target_unavailable`, `artifact_operation_failed`, `capability_unavailable`).",
        "- Wireshark malformed capture/filter/missing-file controls require MCP `isError: true`; false flags fail the run.",
        "",
        "## Boundaries",
        "",
        "- `live_capture` was not called: live network capture is prohibited by the brief.",
        "- No browser/CDP, ADB/Android, JEB, firmware, EVM, managed/.NET, process-capture "
        "or third-party network target was used.",
        "- The plan includes a PE32 capability-refusal control for `inspect_binary_layout`; check its case before concluding it ran.",
        "- The planned Ghidra static operations use an authored PE and explicit close/session checks. Catalog presence is not execution.",
        "- Fixture before/after hashes, provider cleanup and actual case outcomes are recorded separately in identities.json/result.json.",
        "- Prior revision-002 coverage (`decode_protocol`, `extract_archive`, "
        "`get_archive_item_list`, `inspect_pe_resources`) is metadata only; a current PASS requires this run's cases. It is not "
        "counted as new coverage.",
        "",
        "## Evidence layout",
        "",
        "- `catalog.json` — full tool schemas returned by each real `tools/list`.",
        "- `coverage.json` — every advertised method, status, cases and reason.",
        "- `runs/<provider>/raw.jsonl` — exact request/response lines.",
        "- `runs/<provider>/cases.json` — parsed responses, RPC ids, args, checks.",
        "- `runs/<provider>/cleanup.json` — Job Object cleanup receipt.",
        "- `runs/<provider>/stderr.txt`, `session.json`, `catalog.json`.",
        "- `fixtures/` — authored bytes regenerated by `offline_fixtures.py`.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main


def station_identity(station: Path) -> dict:
    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(["git", "-C", str(station), *args],
                                  capture_output=True, text=True, timeout=10)
            return proc.stdout.strip() if proc.returncode == 0 else None
        except Exception:
            return None

    def hash_relative(rel: str) -> dict | None:
        path = station / rel
        if not path.is_file():
            return None
        return {"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size}

    source_files = {
        "wireshark": [
            "MCP/mcp-wireshark/src/mcp_wireshark/server.py",
            "MCP/mcp-wireshark/src/mcp_wireshark/read_tools.py",
            "MCP/mcp-wireshark/src/mcp_wireshark/write_tools.py",
            "MCP/mcp-wireshark/pyproject.toml",
        ],
        "sevenzip": [
            "MCP/mcp7zop/src/mcp7zop/server.py",
            "MCP/mcp7zop/src/mcp7zop/impl_7z.py",
            "MCP/mcp7zop/src/mcp7zop/impl_fs.py",
            "MCP/mcp7zop/pyproject.toml",
        ],
    }
    sources = {}
    for provider, rels in source_files.items():
        sources[provider] = [item for item in (hash_relative(rel) for rel in rels) if item]
    return {
        "station": str(station),
        "station_git_head": git("rev-parse", "HEAD"),
        "station_git_status_sha256": sha256_text(git("status", "--porcelain") or ""),
        "entry_documents": {
            name: hash_relative(name)
            for name in ("AGENTS.md", "OWNER.md", "docs/CURRENT-CLOSEOUT.md")
        },
        "wrappers": {
            "wireshark": sha256_file(station / "MCP/bin/wireshark-mcp.cmd"),
            "sevenzip": sha256_file(station / "MCP/bin/7zip-mcp.cmd"),
            "rea": sha256_file(station / "MCP/bin/rea-mcp.cmd"),
        },
        "provider_sources": sources,
        "client_python": sys.version.split()[0],
        "client_python_executable": sys.executable,
        "raw_mcp_sha256": sha256_file(HERE / "raw_mcp.py"),
        "common_sha256": sha256_file(HERE / "common.py"),
        "build_fixtures_sha256": sha256_file(HERE / "offline_fixtures.py"),
        "runner_sha256": sha256_file(Path(__file__)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--station", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new directory for this run; must not exist")
    args = parser.parse_args(argv)
    station = args.station.resolve()
    output = args.output.resolve()
    if output == station or output.is_relative_to(station):
        raise SystemExit("output must be a new directory outside the station tree")
    if not station.is_dir():
        raise SystemExit(f"station root not found: {station}")
    for name in ("wireshark", "7zip", "rea"):
        wrapper = station / f"MCP/bin/{name}-mcp.cmd"
        if not wrapper.is_file():
            raise SystemExit(f"wrapper not found: {wrapper}")
    output.mkdir(parents=True, exist_ok=False)

    fixtures = build_fixtures.build_all(output / "fixtures")
    fixture_before = fixture_snapshot(output / "fixtures")
    identities = station_identity(station)
    identities["fixtures"] = fixtures

    runs: dict[str, ProviderRun] = {}
    runs["wireshark"] = run_wireshark(station, output / "runs" / "wireshark",
                                      fixtures, identities)
    runs["sevenzip"] = run_sevenzip(station, output / "runs" / "sevenzip", fixtures)
    runs["rea"] = run_rea(station, output / "runs" / "rea", fixtures)

    catalog = {
        "schema": "tool-lab-catalog/1",
        "generated_utc": utc_now(),
        "providers": {
            name: {
                "wrapper": run.session.get("wrapper"),
                "wrapper_sha256": run.session.get("wrapper_sha256"),
                "protocol_version": run.session.get("protocol_version"),
                "server_info": run.session.get("server_info"),
                "tool_count": run.session.get("tool_count"),
                "tools": run.session.get("tools") or [],
            }
            for name, run in runs.items()
        },
    }
    (output / "catalog.json").write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")

    rea_identity = None
    for case in runs["rea"].cases:
        if case["case_id"] == "rea-session-initial":
            body = case.get("content_json") or {}
            rea_identity = (body.get("result") or {}).get("server_identity")
    identities["rea_server_identity"] = rea_identity
    fixture_after = fixture_snapshot(output / "fixtures")
    identities["input_integrity"] = {
        "before": fixture_before, "after": fixture_after,
        "unchanged": fixture_before == fixture_after,
    }
    (output / "identities.json").write_text(
        json.dumps(identities, ensure_ascii=False, indent=2), encoding="utf-8")

    coverage = build_coverage(catalog, runs)
    (output / "coverage.json").write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2), encoding="utf-8")

    report = build_report(output, coverage, runs, identities)
    (output / "REPORT.md").write_text(report, encoding="utf-8")

    failures = collect_failures(coverage, runs, identities["input_integrity"])
    result = {
        "schema": SCHEMA,
        "run": output.name,
        "finished_utc": utc_now(),
        "providers": {
            name: {
                "tool_count": run.session.get("tool_count"),
                "case_count": len(run.cases),
                "cases_ok": run.cases_ok,
                "cleanup_ok": run.cleanup_ok,
                "cleanup_observed": run.cleanup.get("observed_cleanup_ok")
                if run.cleanup else None,
                "stdout_audit": run.session.get("stdout_audit"),
                "protocol_version": run.session.get("protocol_version"),
            }
            for name, run in runs.items()
        },
        "totals": coverage["totals"],
        "failures": failures,
        "input_integrity": identities["input_integrity"]["unchanged"],
        "all_pass": not failures,
    }
    (output / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not failures else 2


if __name__ == "__main__":
    sys.exit(main())
