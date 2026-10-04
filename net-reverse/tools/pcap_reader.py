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
import pathlib

# Added 2026-10-04 so this reader stops being a string match. `assert-probes.py`
# matches substrings in stdout and says so itself: "NOT a claim that the instrument
# ran: a stub which prints them satisfies it." Writing the parse to disk moves the
# verdict onto the filesystem. See scripts/probe_artifact.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from probe_artifact import write_artifact  # noqa: E402

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN = 0x0800, 0x86DD, 0x8100
# 802.1ad QinQ and legacy QinQ use DIFFERENT outer TPIDs, and a stack may legally carry either.
# Added 2026-10-04: unwrapping only 0x8100 made three of twenty hostile captures parse as
# all-zero with exit 0, while the code's own comment claimed to unwrap any number of tags.
VLAN_TPIDS = frozenset({0x8100, 0x88A8, 0x9100})
IPPROTO_TCP, IPPROTO_UDP = 6, 17
IPPROTO_AH = 51
# IPv6 extension headers that must be walked to reach the transport header. AH is separate
# because its length field has a different unit.
IPV6_EXT_HEADERS = frozenset({0, 43, 44, 60, 51})      # hop-by-hop, routing, fragment, dest-opts, AH


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
        # Fragment and extension-header accounting, added 2026-10-04. These exist so a
        # non-first fragment or an IPv6 frame with extension headers is REPORTED as such
        # rather than landing silently in `other_proto` -- which is what made two wrong
        # readings look like deliberate classifications.
        fragments_first = fragments_continuation = ipv6_ext_headers = 0
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
        # 802.1ad QinQ (TPID 0x88a8) and legacy QinQ 0x9100 unwrap like 0x8100. Added 2026-10-04
        # after an independent experiment built 20 hostile captures: three stacked a non-0x8100
        # outer tag, and this loop -- whose own comment claimed "any number of stacked VLAN tags"
        # -- declined to unwrap them, returning all-zero counts with exit 0. A comment claiming a
        # capability the code lacks is the same defect as a constant where a reading belongs:
        # the docstring had become part of the instrument's output.
        while etype in VLAN_TPIDS:
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
            # FRAGMENTS. `frag_off` was never read, so a non-first fragment's payload was parsed
            # as a transport header. Measured 2026-10-04 on a two-fragment IPv4 capture: the
            # continuation fragment's payload began with ASCII "SECO" (0x53 0x45 0x43 0x4F), and
            # the reader reported that as source port 21317 / destination port 17231. Both ports
            # were fabricated from payload bytes -- and `distinct_flows` stayed correct, because
            # the flow key excludes ports, so the corruption did not even surface as inflation.
            #
            # Correct behaviour: count the packet, say it is a fragment, and do NOT read ports.
            # A continuation fragment has no transport header at all.
            frag_word = struct.unpack(">H", frame[l3 + 6:l3 + 8])[0]
            more_frags = bool(frag_word & 0x2000)
            frag_offset = frag_word & 0x1FFF
            if frag_offset:
                fragments_continuation += 1
                other_proto += 1
                continue
            if more_frags:
                fragments_first += 1
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
            # EXTENSION HEADERS. `l4 = l3 + 40` was hardcoded, which is correct only when the
            # Next Header field is already the transport protocol. Measured 2026-10-04: a Hop-by-Hop
            # (nxt=0) and a Routing (nxt=43) header each shifted L4 by 8 and 16 bytes, and the
            # reader reported `tcp=0, other_proto=1, top_ports empty` for frames that plainly
            # carried a TCP header at 443. Silent, exit 0, and the "other_proto" bucket made it
            # look like a deliberate classification rather than a missed walk.
            #
            # Walked here, bounded, and the two length conventions are respected: the extension
            # headers that carry an explicit length use (Hdr Ext Len + 1) * 8 bytes, while AH uses
            # (Payload Len + 2) * 4. An unrecognised or truncated header stops the walk and the
            # frame is counted as `other_proto` -- never guessed at.
            l4, nxt, walked = l3 + 40, frame[l3 + 6], 0
            while nxt in IPV6_EXT_HEADERS and walked < 8:
                if nxt == IPPROTO_AH:
                    if len(frame) < l4 + 2:
                        break
                    step = (frame[l4 + 1] + 2) * 4
                else:
                    if len(frame) < l4 + 2:
                        break
                    step = (frame[l4 + 1] + 1) * 8
                if step <= 0 or len(frame) < l4 + step:
                    break
                nxt, l4, walked = frame[l4], l4 + step, walked + 1
                ipv6_ext_headers += 1
            if nxt != frame[l3 + 6]:
                proto = nxt
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
        # Surfaced, not folded into other_proto. A reader that cannot tell "this frame carried a
        # protocol I do not decode" from "this frame carried a fragment I deliberately did not
        # parse" is exactly the reader that reported fabricated ports with a straight face.
        "fragments_first": fragments_first,
        "fragments_continuation": fragments_continuation,
        "ipv6_ext_headers": ipv6_ext_headers,
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
        result = parse(args.pcap)
        print(json.dumps(result))
        # out_dir is EXPLICIT. The helper defaults to native-lab/out, which put this reader's
        # evidence inside a different lab -- and net.pcap.selfparse's registry entry binds a
        # sha256 to that path. Cross-lab evidence is the "a probe that cannot localise a fault
        # is not much of a probe" hazard that native-lab's own --only split exists to avoid.
        write_artifact("pcap_reader", result, out_dir="net-reverse/out")
    except IsADirectoryError:
        die(2, f"{args.pcap} is a directory")
    except FileNotFoundError:
        die(2, f"no such file: {args.pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())