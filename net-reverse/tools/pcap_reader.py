#!/usr/bin/env python
"""Read a pcap file with no library and no tshark, and say what is in it.

WHY THIS EXISTS. `net.pcap.analyse` answers capture questions by shelling out to TShark 4.6.8.
It is the arsenal's only capture-analysis instrument, so Q4.data measured one instrument in one
family and the independence gate could never pass there. Independence here is meant to mean *two
implementations*, and a second front-end over the same C library would be one implementation held
twice.

So this parses the file itself: the 24-byte pcap global header, the 16-byte per-packet headers,
then Ethernet / IPv4 / IPv6 / TCP / UDP far enough to count packets, directions, ports and DNS
traffic. That is the smallest honest implementation that can disagree with TShark, and the point
is not that it agrees -- it is that agreement between a from-scratch reader and a decade-old C
parser is evidence, and disagreement is a finding.

Two things it will not do, both deliberately. It does not reassemble, so it cannot read a DNS name
that spans multiple packets, and it does not decode TLS. Where it cannot answer, it says it cannot
answer rather than returning a smaller number that looks like a count of everything.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import sys

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN = 0x0800, 0x86DD, 0x8100
IPPROTO_TCP, IPPROTO_UDP = 6, 17


def die(code: int, error: str, **extra):
    out = {"ok": False, "exit": code, "error": error}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def parse(path: str) -> dict:
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            die(2, f"file is {len(gh)} bytes; a pcap global header is 24, so this is not a pcap",
                first_bytes=fh.read(4).hex() if False else None)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = "<"
        elif magic in (PCAP_MAGIC_BE,):
            endian = ">"
        else:
            die(2, f"not a pcap: magic 0x{magic:08x} is neither 0xa1b2c3d4 nor its byte-swapped twin",
                first_bytes=gh[:4].hex())
        vmaj, vmin, _tz, _sig, snaplen, link = struct.unpack(endian + "HHiIII", gh[4:24])
        if link != LINKTYPE_ETHERNET:
            die(2, f"link type {link} is not Ethernet (1); this reader only decodes Ethernet frames "
                   f"and will not pretend otherwise", linktype=link)

        packets = 0
        bytes_on_wire = 0
        truncated = 0
        ipv4 = ipv6 = 0
        tcp = udp = other_proto = 0
        dns_queries = dns_responses = 0
        flows: dict[tuple, int] = {}
        ports: dict[int, int] = {}
        payload_bytes = 0
        data = fh.read()

    off = 0
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > snaplen and snaplen:
            truncated += 1
        if off + incl > n:
            die(2, f"packet {packets} claims {incl} bytes but only {n - off} remain: the capture is "
                   f"truncated mid-packet", packets=packets)
        frame = data[off:off + incl]
        off += incl
        packets += 1
        bytes_on_wire += orig
        payload_bytes += incl

        if len(frame) < 14:
            continue
        etype = struct.unpack(">H", frame[12:14])[0]
        l3 = 14
        # Unwrap any number of stacked VLAN tags; a truncated tag is a real defect, not padding.
        while etype == ETHERTYPE_VLAN:
            if len(frame) < l3 + 4:
                break
            etype = struct.unpack(">H", frame[l3 + 2:l3 + 4])[0]
            l3 += 4

        src = dst = None
        proto = None
        sport = dport = None
        if etype == ETHERTYPE_IPV4 and len(frame) >= l3 + 20:
            ihl = (frame[l3] & 0x0F) * 4
            if len(frame) < l3 + ihl:
                continue
            ipv4 += 1
            proto = frame[l3 + 9]
            src = str(ipaddress.IPv4Address(frame[l3 + 12:l3 + 16]))
            dst = str(ipaddress.IPv4Address(frame[l3 + 16:l3 + 20]))
            l4 = l3 + ihl
            if proto == IPPROTO_UDP and len(frame) >= l4 + 8:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                udp += 1
                if (sport == 53 or dport == 53) and len(frame) >= l4 + 10:
                    # A DNS message is at least 12 bytes; bit 15 of the flags field marks a reply.
                    dns_off = l4 + 8
                    if len(frame) >= dns_off + 4:
                        if struct.unpack(">H", frame[dns_off + 2:dns_off + 4])[0] & 0x8000:
                            dns_responses += 1
                        else:
                            dns_queries += 1
            elif proto == IPPROTO_TCP and len(frame) >= l4 + 4:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                tcp += 1
            else:
                other_proto += 1
        elif etype == ETHERTYPE_IPV6 and len(frame) >= l3 + 40:
            ipv6 += 1
            proto = frame[l3 + 6]
            src = str(ipaddress.IPv6Address(frame[l3 + 8:l3 + 24]))
            dst = str(ipaddress.IPv6Address(frame[l3 + 24:l3 + 40]))
            l4 = l3 + 40
            if proto == IPPROTO_UDP and len(frame) >= l4 + 8:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                udp += 1
                if (sport == 53 or dport == 53) and len(frame) >= l4 + 10:
                    dns_off = l4 + 8
                    if len(frame) >= dns_off + 4:
                        if struct.unpack(">H", frame[dns_off + 2:dns_off + 4])[0] & 0x8000:
                            dns_responses += 1
                        else:
                            dns_queries += 1
            elif proto == IPPROTO_TCP and len(frame) >= l4 + 4:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                tcp += 1
            else:
                other_proto += 1
        else:
            continue

        if src is not None:
            flows[(src, dst, proto)] = flows.get((src, dst, proto), 0) + 1
        for pt in (sport, dport):
            if pt:
                ports[pt] = ports.get(pt, 0) + 1

    return {
        "ok": True, "exit": 0, "file": path,
        "pcap": {"version": f"{vmaj}.{vmin}", "snaplen": snaplen, "linktype": link,
                 "endian": "little" if endian == "<" else "big"},
        "packets": packets, "bytes_on_wire": bytes_on_wire, "captured_bytes": payload_bytes,
        "frames_over_snaplen": truncated,
        "ipv4": ipv4, "ipv6": ipv6, "tcp": tcp, "udp": udp, "other_proto": other_proto,
        "dns_queries": dns_queries, "dns_responses": dns_responses,
        "distinct_flows": len(flows),
        "top_ports": sorted(((c, p) for p, c in ports.items()), reverse=True)[:6],
        "limits": ("NO REASSEMBLY AND NO TLS. A DNS name split across packets, or any encrypted "
                   "payload, is not decoded here -- this reader counts what it can see and reports "
                   "the rest as a limit rather than as an absence. Agreement with TShark on the "
                   "counts is corroboration of the COUNTS only; it says nothing about names, and "
                   "neither instrument here can say anything about content."),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    args = ap.parse_args()
    try:
        print(json.dumps(parse(args.pcap)))
    except IsADirectoryError:
        die(2, f"{args.pcap} is a directory")
    except FileNotFoundError:
        die(2, f"no such file: {args.pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())