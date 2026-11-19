#!/usr/bin/env python3
"""Build deterministic, authored fixtures for the Wireshark / 7-Zip / REA lab.

Every byte is generated here: DNS/TCP/HTTP packets use documentation IP ranges
(192.0.2.0/24, 198.51.100.0/24) and reserved .test names; archive contents are
literal strings; the PE is a hand-assembled PE32 with one .text section.

CLI:
    python scripts/tool_lab/offline_fixtures.py --output NEW_DIR

Writes NEW_DIR/fixtures.json (paths, sizes, SHA-256) and prints the manifest.
No network capture, no third-party binaries, no execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# pcap

ETH_DST = bytes.fromhex("020000000002")
ETH_SRC = bytes.fromhex("020000000001")
IP_CLIENT = bytes([192, 0, 2, 10])
IP_DNS = bytes([198, 51, 100, 53])
IP_HTTP = bytes([198, 51, 100, 20])
TCP_SPORT = 49152
TCP_DPORT = 8080
HTTP_BODY = b"hello-from-authored-http\n"
HTTP_REQUEST = (
    b"GET /fixture HTTP/1.1\r\n"
    b"Host: fixture.ws-test.test\r\n"
    b"User-Agent: authored-fixture/1.0\r\n"
    b"\r\n"
)
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: " + str(len(HTTP_BODY)).encode() + b"\r\n"
    b"\r\n" + HTTP_BODY
)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return ETH_DST + ETH_SRC + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, proto: int, src: bytes, dst: bytes, ident: int) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, proto, 0, src, dst)
    csum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, proto, csum, src, dst)
    return header + payload


def _udp(payload: bytes, sport: int, dport: int, src: bytes, dst: bytes) -> bytes:
    length = 8 + len(payload)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, length)
    csum = _checksum(pseudo + struct.pack("!HHHH", sport, dport, length, 0) + payload)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def _tcp(payload: bytes, sport: int, dport: int, seq: int, ack: int,
         flags: int, src: bytes, dst: bytes) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = _checksum(pseudo + header + payload)
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, csum, 0)
    return header + payload


def _frame(payload: bytes) -> bytes:
    if len(payload) < 60:
        payload += b"\x00" * (60 - len(payload))
    return payload


def _dns_query() -> bytes:
    name = b"".join(bytes([len(label)]) + label
                    for label in b"fixture.ws-test.test".split(b".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def _dns_response() -> bytes:
    name = b"".join(bytes([len(label)]) + label
                    for label in b"fixture.ws-test.test".split(b".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 53])
    return header + name + struct.pack("!HH", 1, 1) + answer


def build_pcap() -> bytes:
    packets = []

    def add(payload: bytes, proto: int, src: bytes, dst: bytes, ident: int) -> None:
        packets.append(_frame(_ethernet(_ipv4(payload, proto, src, dst, ident))))

    add(_udp(_dns_query(), 53000, 53, IP_CLIENT, IP_DNS),
        17, IP_CLIENT, IP_DNS, 1)
    add(_udp(_dns_response(), 53, 53000, IP_DNS, IP_CLIENT),
        17, IP_DNS, IP_CLIENT, 2)
    add(_tcp(b"", TCP_SPORT, TCP_DPORT, 1000, 0, 0x02, IP_CLIENT, IP_HTTP),
        6, IP_CLIENT, IP_HTTP, 3)                                     # SYN
    add(_tcp(b"", TCP_DPORT, TCP_SPORT, 5000, 1001, 0x12, IP_HTTP, IP_CLIENT),
        6, IP_HTTP, IP_CLIENT, 4)                                     # SYN-ACK
    add(_tcp(b"", TCP_SPORT, TCP_DPORT, 1001, 5001, 0x10, IP_CLIENT, IP_HTTP),
        6, IP_CLIENT, IP_HTTP, 5)                                     # ACK
    add(_tcp(HTTP_REQUEST, TCP_SPORT, TCP_DPORT, 1001, 5001, 0x18,
             IP_CLIENT, IP_HTTP),
        6, IP_CLIENT, IP_HTTP, 6)                                     # GET
    add(_tcp(HTTP_RESPONSE, TCP_DPORT, TCP_SPORT, 5001,
             1001 + len(HTTP_REQUEST), 0x18, IP_HTTP, IP_CLIENT),
        6, IP_HTTP, IP_CLIENT, 7)                                     # 200 OK

    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, frame in enumerate(packets):
        seconds = 1700000000 + index
        usec = index * 1000
        out += struct.pack("<IIII", seconds, usec, len(frame), len(frame))
        out += frame
    return bytes(out)


# ---------------------------------------------------------------------------
# PE32

PE_TEXT_OFFSET = 0x200
PE_STRINGS = b"WS-FIXTURE-STRING\x00authored-pe-fixture\x00"


def build_pe() -> bytes:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x014C)   # i386
    struct.pack_into("<H", buf, 0x86, 1)        # one section
    struct.pack_into("<H", buf, 0x94, 0xE0)     # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 0x96, 0x0102)   # executable image
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x010B)    # PE32
    struct.pack_into("<I", buf, opt + 16, 0x1000)   # AddressOfEntryPoint
    struct.pack_into("<I", buf, opt + 20, 0x1000)   # BaseOfCode
    struct.pack_into("<I", buf, opt + 32, 0x1000)   # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)    # FileAlignment
    struct.pack_into("<I", buf, opt + 56, 0x2000)   # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)    # SizeOfHeaders
    struct.pack_into("<I", buf, opt + 92, 16)       # NumberOfRvaAndSizes
    sec = 0x178
    buf[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sec + 8, 0x200)     # VirtualSize
    struct.pack_into("<I", buf, sec + 12, 0x1000)   # VirtualAddress
    struct.pack_into("<I", buf, sec + 16, 0x200)    # SizeOfRawData
    struct.pack_into("<I", buf, sec + 20, 0x200)    # PointerToRawData
    struct.pack_into("<I", buf, sec + 36, 0x60000020)  # code | execute | read
    buf[PE_TEXT_OFFSET:PE_TEXT_OFFSET + 6] = bytes.fromhex("b82a000000c3")  # mov eax,42; ret
    buf[0x210:0x210 + len(PE_STRINGS)] = PE_STRINGS
    return bytes(buf)


# ---------------------------------------------------------------------------
# JavaScript applications

APP_PACKAGE = {
    "name": "ws-fixture-app",
    "version": "1.2.3",
    "main": "src/main.js",
    "description": "authored fixture",
}
APP_UTIL = (
    "function normalize(value) {\n"
    "  return String(value).trim().toLowerCase();\n"
    "}\n"
    "module.exports = { normalize };\n"
)
APP_MAIN = (
    '"use strict";\n'
    'const util = require("./util");\n'
    'const GREETING = "hello-from-authored-fixture";\n'
    "function greet(name) {\n"
    '  return GREETING + ":" + util.normalize(name);\n'
    "}\n"
    "module.exports = { greet, GREETING };\n"
)
ESM_UTIL = (
    "export function normalize(value) {\n"
    "  return String(value).trim().toLowerCase();\n"
    "}\n"
)
ESM_MAIN_A = (
    'import { normalize } from "./util.js";\n'
    'export const GREETING = "hello-from-authored-fixture";\n'
    "export function greet(name) {\n"
    '  return GREETING + ":" + normalize(name);\n'
    "}\n"
)
ESM_MAIN_B = (
    'import { normalize } from "./util.js";\n'
    'export const GREETING = "hello-from-authored-fixture";\n'
    "export function greet(name) {\n"
    "  return { message: GREETING, name: normalize(name) };\n"
    "}\n"
)
ESM_PACKAGE = {
    "name": "ws-fixture-esm",
    "version": "1.0.0",
    "type": "module",
    "main": "src/main.js",
    "description": "authored fixture",
}


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict) -> None:
    write_text(path, json.dumps(value, indent=2) + "\n")


# ---------------------------------------------------------------------------
# archive

ZIP_MEMBERS_V1 = {
    "pkg/package.json": '{"name":"fixture-archive","version":"1.0.0"}\n',
    "pkg/index.js": 'module.exports = "fixture-entry";\n',
    "data/hello.txt": "hello-authored-archive\n",
}
ZIP_MEMBERS_V2 = {
    "pkg/package.json": '{"name":"fixture-archive","version":"2.0.0"}\n',
    "pkg/index.js": 'module.exports = "fixture-entry";\n',
    "data/hello.txt": "hello-authored-archive\n",
    "data/added.txt": "added-in-v2\n",
}
ZIP_DATE = (2026, 1, 2, 3, 4, 6)
SEVENZIP_FILES = {
    "alpha.txt": b"alpha-authored-bytes\n",
    "beta.txt": b"beta-authored-bytes\n",
    "gamma.txt": b"gamma-authored-bytes-v2\n",
}


def build_zip(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        for name, text in members.items():
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            archive.writestr(info, text.encode("utf-8"))


# ---------------------------------------------------------------------------


def build_all(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, dict] = {}

    def record(name: str, path: Path) -> None:
        data = path.read_bytes()
        manifest[name] = {
            "path": str(path),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    pcap = out / "dns-tcp-http.pcap"
    pcap.write_bytes(build_pcap())
    record("pcap", pcap)

    corrupt_pcap = out / "corrupt.pcap"
    corrupt_pcap.write_bytes(b"not a pcap at all\n")
    record("corrupt_pcap", corrupt_pcap)

    zip1 = out / "archive-v1.zip"
    build_zip(zip1, ZIP_MEMBERS_V1)
    record("archive_v1", zip1)
    zip2 = out / "archive-v2.zip"
    build_zip(zip2, ZIP_MEMBERS_V2)
    record("archive_v2", zip2)
    corrupt_zip = out / "corrupt.zip"
    corrupt_zip.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    record("corrupt_zip", corrupt_zip)

    data_dir = out / "sevenzip-input"
    data_dir.mkdir()
    for name, data in SEVENZIP_FILES.items():
        (data_dir / name).write_bytes(data)
    for name in SEVENZIP_FILES:
        record("sevenzip_" + name.split(".")[0], data_dir / name)

    app = out / "js-app"
    write_json(app / "package.json", APP_PACKAGE)
    write_text(app / "src" / "main.js", APP_MAIN)
    write_text(app / "src" / "util.js", APP_UTIL)
    for name, rel in [("js_app_package", "package.json"),
                      ("js_app_main", "src/main.js"),
                      ("js_app_util", "src/util.js")]:
        record(name, app / rel)

    bad_app = out / "js-app-bad"
    write_text(bad_app / "package.json", "{not json\n")
    write_text(bad_app / "src" / "main.js", "module.exports = 1;\n")
    record("js_bad_package", bad_app / "package.json")
    record("js_bad_main", bad_app / "src" / "main.js")

    for tag, main in (("a", ESM_MAIN_A), ("b", ESM_MAIN_B)):
        esm = out / ("js-app-esm-" + tag)
        write_json(esm / "package.json", ESM_PACKAGE)
        write_text(esm / "src" / "main.js", main)
        write_text(esm / "src" / "util.js", ESM_UTIL)
        for name, rel in [(f"esm_{tag}_package", "package.json"),
                          (f"esm_{tag}_main", "src/main.js"),
                          (f"esm_{tag}_util", "src/util.js")]:
            record(name, esm / rel)

    pe = out / "fixture.pe"
    pe.write_bytes(build_pe())
    record("pe", pe)

    corrupt_pe = out / "corrupt.pe"
    corrupt_pe.write_bytes(b"MZ" + b"\x00" * 30)
    record("corrupt_pe", corrupt_pe)

    (out / "fixtures.json").write_text(
        json.dumps({"root": str(out), "files": manifest}, indent=2) + "\n",
        encoding="utf-8")
    return {"root": str(out), "files": manifest}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new directory that will receive the fixtures")
    args = parser.parse_args(argv)
    manifest = build_all(args.output)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
