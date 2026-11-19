"""Raw calls and authored semantic assertions remain separate observations."""
import hashlib
import json
from pathlib import Path
import queue
import time

from catalog import write_json, digest
from raw_mcp import RawMcp, now_utc


def payload(response):
    result = response.get("result") or {}
    content = result.get("content") or []
    text = "\n".join(x.get("text", "") for x in content if x.get("type") == "text")
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text


class LabSession:
    def __init__(self, backend, argv, cwd, env, output, route, timeout=30):
        self.output = Path(output)
        self.output.mkdir(exist_ok=False)
        self.client = RawMcp(argv, str(cwd), env, timeout=timeout, tag=backend)
        self.record = {"backend": backend, "route": route, "argv": argv, "cwd": str(cwd),
                       "started_utc": now_utc(), "cases": [], "tools": [], "cleanup": None}

    def __enter__(self):
        try:
            self.client.start()
            self.record["initialize"] = self.client.initialize(client_name="debugger-tool-lab")
            self.record["catalog_response"] = self.client.send("tools/list", {})
            result = self.record["catalog_response"].get("result", {})
            if result.get("nextCursor") is not None:
                raise ValueError("call runner requires a complete single-page catalog; use catalog.py for paginated discovery")
            self.record["tools"] = result.get("tools", [])
            if not self.record["tools"]:
                raise ValueError("empty or failed tools/list")
        except BaseException:
            self.__exit__(*__import__("sys").exc_info())
            raise
        return self

    def call(self, name, arguments, case_id, kind="positive", timeout=None):
        if name not in {t.get("name") for t in self.record["tools"]}:
            raise ValueError("method absent from actual runtime catalog: " + name)
        started = time.monotonic()
        case = {"case_id": case_id, "method": name, "arguments": arguments, "kind": kind, "checks": {}}
        self.record["cases"].append(case)
        try:
            response = self.client.send("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
            case.update(response=response, response_id=response.get("id"), payload=payload(response))
        except Exception as error:
            case["error"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            case["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return case

    @staticmethod
    def check(case, name, actual, expected):
        case["checks"][name] = {"pass": actual == expected, "actual": actual, "expected": expected}

    def __exit__(self, kind, error, traceback):
        try:
            self.record["cleanup"] = self.client.close()
        except BaseException as cleanup_error:
            # Preserve raw observations even when cleanup itself fails. Unknown
            # process state cannot become a green result or erase an earlier error.
            self.record["cleanup"] = {"observed_cleanup_ok": False,
                                      "error": {"type": type(cleanup_error).__name__, "message": str(cleanup_error)}}
        # RawMcp.read_id consumes only through the requested response. Its
        # close joins the reader; drain the remaining captured lines now so
        # shutdown output cannot evade the independent stdout audit.
        queued = getattr(self.client, "_q", None)
        trailing_lines = 0
        if queued is not None:
            while True:
                try:
                    item = queued.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    self.client.res.append({"t": item["t"], "raw": item["raw"]})
                    trailing_lines += 1
        reader = getattr(self.client, "_reader", None)
        reader_stopped = reader is not None and not reader.is_alive()
        self.record["stdout_audit"] = {"scope": "captured stdout through owned Job teardown and joined reader",
                                       "reader_stopped": reader_stopped, "post_close_lines": trailing_lines}
        for filename, entries in (("requests.jsonl", self.client.req), ("responses.jsonl", self.client.res)):
            raw = "\n".join(x["raw"] for x in entries)
            (self.output / filename).write_text(raw + ("\n" if raw else ""), encoding="utf-8")
        (self.output / "stderr.txt").write_bytes(b"".join(self.client.stderr_chunks))
        self.record["raw_sha256"] = {n: digest(self.output / n) for n in ("requests.jsonl", "responses.jsonl", "stderr.txt")}
        noise = []
        for number, item in enumerate(self.client.res, 1):
            try:
                envelope = json.loads(item["raw"])
                if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0" or not ("id" in envelope or "method" in envelope):
                    raise ValueError("not a JSON-RPC envelope")
            except ValueError:
                noise.append({"line": number, "sha256": hashlib.sha256(item["raw"].encode()).hexdigest()})
        self.record["stdout_noise"] = noise
        self.record["wire_protocol_clean"] = not noise
        if error:
            self.record["runner_error"] = {"type": type(error).__name__, "message": str(error)}
        for case in self.record["cases"]:
            response = case.get("response", {})
            case["semantic_pass"] = bool(case["checks"]) and all(x["pass"] for x in case["checks"].values()) and "error" not in case
            result = response.get("result")
            valid_result = isinstance(result, dict) and "error" not in response
            is_error = result.get("isError", False) if isinstance(result, dict) else None
            case["mcp_error_flag"] = is_error
            case["protocol_flag_consistent"] = valid_result and ((is_error is True) if case["kind"] == "negative" else (is_error is False))
            case["status"] = ("positive_pass" if case["kind"] == "positive" else "expected_rejection") if case["semantic_pass"] and case["protocol_flag_consistent"] else ("semantic_rejection_flag_gap" if case["kind"] == "negative" and case["semantic_pass"] else "failed")
        self.record["unique_methods_called"] = len({c["method"] for c in self.record["cases"] if "response" in c})
        self.record["unique_positive_methods"] = len({c["method"] for c in self.record["cases"] if c["status"] == "positive_pass"})
        self.record["all_checks_pass"] = bool(self.record["cases"]) and all(c["semantic_pass"] and c["protocol_flag_consistent"] for c in self.record["cases"]) and self.record["cleanup"]["observed_cleanup_ok"] and error is None and not noise and reader_stopped
        self.record["finished_utc"] = now_utc()
        write_json(self.output / "RESULTS.json", self.record)
        return False
