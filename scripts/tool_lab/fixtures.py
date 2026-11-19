#!/usr/bin/env python3
"""Author deterministic public fixtures; no target program is executed."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

HTTP_MARKER = "TOOLLAB_HTTP_MARKER"
PE_MARKER = b"TOOLLAB_OWNED_MARKER\x00"


def build_pe():
    image = bytearray(1536)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 2, 0, 0, 0, 224, 0x0102)
    opt = 0x98
    struct.pack_into("<HBBIIIIII", image, opt, 0x10B, 14, 0, 512, 512, 0, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<III", image, opt + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", image, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", image, opt + 52, 0, 0x3000, 0x200)
    struct.pack_into("<HH", image, opt + 68, 3, 0)
    struct.pack_into("<IIIIII", image, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    section = opt + 224
    struct.pack_into("<8sIIIIIIHHI", image, section, b".text", 6, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", image, section + 40, b".rdata", len(PE_MARKER), 0x2000, 512, 1024, 0, 0, 0, 0, 0x40000040)
    image[512:518] = bytes.fromhex("b82a000000c3")  # mov eax,42; ret, inspected statically only
    image[1024:1024 + len(PE_MARKER)] = PE_MARKER
    return bytes(image)


def build_har(timestamp="2026-11-19T00:00:00.000Z"):
    def entry(url, status, mime, text):
        return {"startedDateTime": timestamp, "time": 1,
                "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
                "response": {"status": status, "statusText": "OK" if status == 200 else "Switching Protocols", "httpVersion": "HTTP/1.1", "headers": [{"name": "Content-Type", "value": mime}], "cookies": [], "content": {"size": len(text.encode()), "mimeType": mime, "text": text}, "redirectURL": "", "headersSize": -1, "bodySize": len(text.encode())},
                "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}}
    http = entry("https://fixture.test/api/items/7", 200, "application/json", json.dumps({"marker": HTTP_MARKER, "answer": 42}, separators=(",", ":")))
    ws = entry("wss://fixture.test/events", 101, "application/octet-stream", "")
    ws["request"]["headers"] = [{"name": "Upgrade", "value": "websocket"}, {"name": "Connection", "value": "Upgrade"}]
    ws["response"]["headers"] = [{"name": "Upgrade", "value": "websocket"}, {"name": "Connection", "value": "Upgrade"}]
    epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    ws["_webSocketMessages"] = [
        {"type": "send", "time": epoch, "opcode": 1, "data": '{"event":"TOOLLAB_HELLO","answer":42}'},
        {"type": "receive", "time": epoch + 0.1, "opcode": 1, "data": '{"event":"TOOLLAB_ACK","answer":42}'},
        {"type": "receive", "time": epoch + 0.2, "opcode": 8, "data": '{"code":1000,"reason":"owned fixture done"}'},
    ]
    return {"log": {"version": "1.2", "creator": {"name": "debugger-tool-lab", "version": "1"}, "entries": [http, ws]}}


def build_all(out: Path, timestamp="2026-11-19T00:00:00.000Z"):
    out.mkdir(parents=True, exist_ok=False)
    (out / "owned-static.exe").write_bytes(build_pe())
    (out / "owned.har").write_text(json.dumps(build_har(timestamp), indent=2) + "\n", encoding="utf-8")
    (out / "malformed.har").write_text("not HAR or JSON\n", encoding="utf-8")
    (out / "OwnedSleeper.cs").write_text(
        'using System; using System.Threading; public class OwnedSleeper { public static void Main(string[] args) { Console.WriteLine("TOOLLAB_OWNED_PROCESS"); Thread.Sleep(60000); } }\n', encoding="utf-8")
    manifest = {"origin": "authored, no captured traffic or downloaded sample", "timestamp": timestamp,
                "pe": {"entry_va": "0x401000", "text_hex": "b82a000000c3", "marker_va": "0x402000", "marker": PE_MARKER[:-1].decode()},
                "har": {"entries": 2, "http_url": "https://fixture.test/api/items/7", "ws_url": "wss://fixture.test/events", "ws_messages": 3, "http_marker": HTTP_MARKER},
                "files": {p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(out.iterdir())}}
    (out / "FIXTURES.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timestamp", default="2026-11-19T00:00:00.000Z")
    args = ap.parse_args()
    print(json.dumps(build_all(args.output, args.timestamp), indent=2))
