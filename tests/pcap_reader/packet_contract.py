#!/usr/bin/env python3
"""Black-box PCAP boundaries, encoded from wire formats, without importing the parser.

Run the SAME frozen driver against old and new source trees. Outputs are external
and per case; no network, packet replay, external capture, or parser dependency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ethernet(payload, kind=0x0800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", kind) + payload


def ipv4(payload, *, ihl=5, version=4, total=None, fragment=0, proto=17):
    header = struct.pack("!BBHHHBBH4s4s", (version << 4) | ihl, 0,
                         20 + len(payload) if total is None else total,
                         1, fragment, 64, proto, 0, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02")
    return ethernet(header + payload)


def ipv6(payload, *, nxt=17, length=None, version=6):
    header = struct.pack("!IHBB16s16s", version << 28,
                         len(payload) if length is None else length, nxt, 64,
                         bytes.fromhex("20010db8000000000000000000000001"),
                         bytes.fromhex("20010db8000000000000000000000002"))
    return ethernet(header + payload, 0x86DD)


def udp(payload, *, length=None):
    return struct.pack("!HHHH", 53000, 53, 8 + len(payload) if length is None else length, 0) + payload


def fragment(payload, *, offset=0, more=False, reserved=0, nxt=17):
    return struct.pack("!BBHI", nxt, reserved, (offset << 3) | int(more), 0x12345678) + payload


def pcap(frames, *, endian="<", nano=False, tail=b"", incl_delta=0):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        result += struct.pack(endian + "IIII", 1700000000, 123, len(frame), len(frame) + incl_delta) + frame
    return result + tail


def cases():
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
    valid = ipv4(udp(dns))
    rows = []
    def add(name, data, fields, code=0):
        rows.append((name, data, fields, code))
    positive = {"packets": 1, "ipv4": 1, "udp": 1, "dns_queries": 1, "dns_responses": 0,
                "top_ports": [[1, 53000], [1, 53]]}
    for endian, suffix in [("<", "le"), (">", "be")]:
        for nano in (False, True):
            add("magic_" + suffix + ("_ns" if nano else "_us"), pcap([valid], endian=endian, nano=nano), positive)
    add("empty_capture", pcap([]), {"packets": 0, "udp": 0, "dns_queries": 0})
    for n in (1, 8, 15):
        add("truncated_record_header_" + str(n), pcap([valid], tail=b"\0" * n), {"ok": False}, 2)
    add("incl_exceeds_original_control", pcap([valid], incl_delta=-1), {"ok": False}, 2)
    add("body_truncated_control", pcap([valid])[:-1], {"ok": False}, 2)
    for version, ip in [(4, ipv4), (6, ipv6)]:
        add(f"ipv{version}_short_dns", pcap([ip(udp(dns[:4]))]), {"udp": 1, "dns_queries": 0, "dns_responses": 0})
        add(f"ipv{version}_udp_padding", pcap([ip(udp(dns, length=8))]), {"udp": 1, "dns_queries": 0})
        add(f"ipv{version}_invalid_udp_length", pcap([ip(udp(dns, length=7))]), {"udp": 0, "dns_queries": 0, "top_ports": []})
    add("ipv4_padding_after_total_length", pcap([ipv4(udp(dns), total=28)]), {"udp": 1, "dns_queries": 0})
    add("ipv6_padding_after_payload_length", pcap([ipv6(udp(dns), length=8)]), {"udp": 1, "dns_queries": 0})
    add("ipv4_invalid_ihl", pcap([ipv4(udp(dns), ihl=4)]), {"udp": 0, "top_ports": []})
    add("ipv4_invalid_version", pcap([ipv4(udp(dns), version=6)]), {"udp": 0, "top_ports": []})
    add("ipv4_total_less_than_header", pcap([ipv4(udp(dns), total=19)]), {"udp": 0, "top_ports": []})
    add("ipv4_continuation_control", pcap([ipv4(udp(dns), fragment=1)]),
        {"fragments_continuation": 1, "udp": 0, "dns_queries": 0, "top_ports": []})
    add("ipv6_continuation", pcap([ipv6(fragment(udp(dns), offset=1), nxt=44)]),
        {"fragments_continuation": 1, "ipv6_ext_headers": 1, "udp": 0, "dns_queries": 0, "top_ports": []})
    # First fragments carry an upper-layer header; the 24-byte fragment is a multiple of eight.
    add("ipv6_first_fragment", pcap([ipv6(fragment(udp(dns + b"data"), more=True), nxt=44)]),
        {"fragments_first": 1, "fragments_continuation": 0, "udp": 1, "dns_queries": 1})
    for reserved in (0, 1):
        add("ipv6_atomic_fragment_reserved_" + str(reserved),
            pcap([ipv6(fragment(udp(dns), reserved=reserved), nxt=44)]),
            {"fragments_first": 0, "fragments_continuation": 0, "ipv6_ext_headers": 1, "udp": 1,
             "dns_queries": 1, "top_ports": [[1, 53000], [1, 53]]})
    add("ipv6_fragment_header_truncated", pcap([ipv6(fragment(b"")[:4], nxt=44)]),
        {"udp": 0, "top_ports": []})
    add("ipv6_invalid_version", pcap([ipv6(udp(dns), version=4)]), {"udp": 0, "top_ports": []})
    add("ipv6_zero_payload_with_padding", pcap([ipv6(udp(dns), length=0)]), {"udp": 0, "dns_queries": 0})
    for version, ip in [(4, ipv4), (6, ipv6)]:
        kw = {"proto": 6} if version == 4 else {"nxt": 6}
        add(f"ipv{version}_short_tcp", pcap([ip(struct.pack("!HH", 53000, 443), **kw)]), {"tcp": 0, "top_ports": []})
        tcp = struct.pack("!HHIIBBHHH", 53000, 443, 1, 0, 5 << 4, 2, 4096, 0, 0)
        add(f"ipv{version}_tcp_control", pcap([ip(tcp, **kw)]), {"tcp": 1, "top_ports": [[1, 53000], [1, 443]]})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True, help="pcap_reader.py under a source tree with scripts/probe_artifact.py")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    source = args.source.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    manifest = []
    for name, data, fields, code in cases():
        folder = out / name
        folder.mkdir()
        target = folder / "input.pcap"
        target.write_bytes(data)
        env = dict(os.environ, DEBUGGER_PROBE_ARTIFACT_ROOT=str(folder / "artifacts"), PYTHONIOENCODING="utf-8")
        run = subprocess.run([sys.executable, "-X", "utf8", "-B", str(source), str(target)],
                             cwd=folder, env=env, capture_output=True, timeout=15)
        (folder / "stdout.bin").write_bytes(run.stdout)
        (folder / "stderr.bin").write_bytes(run.stderr)
        try:
            got = json.loads(run.stdout.decode("utf-8"))
            checks = {"exit_code": run.returncode == code, **{k: got.get(k) == v for k, v in fields.items()}}
        except (ValueError, UnicodeError) as exc:
            got = {"driver_parse_error": str(exc)}
            checks = {"json": False}
        results.append({"id": name, "pass": all(checks.values()), "checks": checks,
                        "exit_code": run.returncode, "observed": got, "expected_fields": fields})
        manifest.append({"id": name, "target_sha256": sha(data), "expected_exit": code, "expected_fields": fields})
    (out / "fixtures.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    result = {"contract": "pcap-wire-boundaries.1", "source_sha256": sha(source.read_bytes()),
              "driver_sha256": sha(Path(__file__).read_bytes()), "platform": sys.platform,
              "count": len(results), "passed": sum(r["pass"] for r in results), "results": results}
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("contract", "source_sha256", "driver_sha256", "platform", "count", "passed")}))
    return 0 if result["count"] == result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
