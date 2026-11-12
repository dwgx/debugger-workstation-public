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
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
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
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            endian = ">"
        else:
            die(2, f"not a pcap: unsupported magic 0x{magic:08x}; expected microsecond or nanosecond pcap in either byte order",
                first_bytes=gh[:4].hex())
        vmaj, vmin, _tz, _sig, snaplen, link_word = struct.unpack(endian + "HHiIII", gh[4:24])
        if (vmaj, vmin) != (2, 4):
            die(2, f"unsupported pcap version {vmaj}.{vmin}; this reader implements version 2.4")
        # pcap-savefile(5): only the low 16 bits are LINKTYPE. P plus the
        # top nibble optionally describe the captured frame check sequence.
        if link_word & 0x0BFF0000:
            die(2, "pcap link-layer additional information has nonzero reserved bits",
                linktype_word=link_word)
        link = link_word & 0xFFFF
        fcs_bytes = ((link_word >> 28) & 15) * 2 if link_word & 0x04000000 else None
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
        unparsed_network_headers = 0
        flows: dict[tuple, int] = {}
        ports: dict[int, int] = {}
        payload_bytes = 0
        data = fh.read()

    off = 0
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        # `incl_len` (captured) EXCEEDING `orig_len` (on the wire) is a header that
        # contradicts itself, and it is checked BEFORE the truncation guard on purpose.
        # Measured 2026-10-05 on a generated one-record capture with incl_len=100,
        # orig_len=40 and all 100 body bytes present: the reader reported
        #   {ok: true, bytes_on_wire: 40, captured_bytes: 100}
        # -- captured MORE bytes than were ever on the wire, reported as a success.
        # The neighbouring case (truncated mid-packet) already refused, so this reader
        # did know that a record header can lie; it just checked one lie and not the other.
        #
        # REFUSE rather than accept-and-flag, which is the debatable half of this change:
        #   * `orig_len` is defined by pcap-savefile(5) as the bytes that WOULD have been
        #     present had the packet not been snaplen-truncated, so `incl > orig` cannot
        #     happen in a file any conforming writer produced. Either field is a lie and
        #     the reader cannot tell which.
        #   * `bytes_on_wire` is a SUM of `orig`. If `orig` is the lie, that aggregate is
        #     already wrong, and flagging it does not un-poison a number whose whole job is
        #     to be compared against TShark.
        #   * The reader advances `off += incl`. An inflated `incl` therefore moves the
        #     record boundary and every later packet is read from the wrong offset, so
        #     "accept but flag" is not "keep the counts" -- it is "keep publishing counts
        #     from a framing that is no longer established".
        #   * This reader's own docstring: "Where it cannot answer, it says it cannot answer
        #     rather than returning a smaller number that looks like a count of everything."
        #     A caveat attached to a poisoned aggregate is exactly that failure.
        # Bounded by the SAME rule as the truncation guard below -- a record header that
        # cannot be true is a refusal -- so the two defects get one policy, not two.
        if incl > orig:
            die(2, f"packet {packets} declares incl_len {incl} > orig_len {orig}: a record cannot capture "
                   f"more bytes than were on the wire, so this header is malformed and no later record "
                   f"boundary can be trusted either",
                packets=packets, incl_len=incl, orig_len=orig)
        if incl > snaplen and snaplen:
            truncated += 1
        if off + incl > n:
            die(2, f"packet {packets} claims {incl} bytes but only {n - off} remain: the capture is "
                   f"truncated mid-packet", packets=packets)
        if fcs_bytes is not None and orig < fcs_bytes:
            die(2, f"packet {packets} is shorter than its declared FCS", packets=packets)
        # In a snaplen-truncated record the FCS can be absent or only partly
        # captured. Bound by the original frame's data extent, not incl - FCS.
        data_length = min(incl, orig - fcs_bytes) if fcs_bytes is not None else incl
        frame = data[off:off + data_length]
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
            total_length = struct.unpack(">H", frame[l3 + 2:l3 + 4])[0]
            if frame[l3] >> 4 != 4 or ihl < 20 or total_length < ihl or len(frame) < l3 + ihl:
                unparsed_network_headers += 1
                continue
            # Ethernet padding is outside the IP datagram. A snaplen-short capture
            # may still expose complete headers, but bytes beyond total_length cannot.
            packet_end = min(len(frame), l3 + total_length)
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
        elif etype == ETHERTYPE_IPV6 and len(frame) >= l3 + 40:
            if frame[l3] >> 4 != 6:
                unparsed_network_headers += 1
                continue
            ipv6 += 1
            payload_length = struct.unpack(">H", frame[l3 + 4:l3 + 6])[0]
            packet_end = min(len(frame), l3 + 40 + payload_length)
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
            continuation = False
            while nxt in IPV6_EXT_HEADERS and walked < 8:
                if nxt == 44:
                    # RFC 8200 section 4.5: fixed eight bytes, not Hdr Ext Len.
                    # The second octet is reserved and must be ignored on reception.
                    step = 8
                    if packet_end < l4 + step:
                        break
                    fragment_word = struct.unpack(">H", frame[l4 + 2:l4 + 4])[0]
                    if fragment_word >> 3:
                        fragments_continuation += 1
                        continuation = True
                    elif fragment_word & 1:
                        fragments_first += 1
                elif nxt == IPPROTO_AH:
                    if packet_end < l4 + 2:
                        break
                    step = (frame[l4 + 1] + 2) * 4
                else:
                    if packet_end < l4 + 2:
                        break
                    step = (frame[l4 + 1] + 1) * 8
                if step <= 0 or packet_end < l4 + step:
                    break
                nxt, l4, walked = frame[l4], l4 + step, walked + 1
                ipv6_ext_headers += 1
                if continuation:
                    break
            if continuation:
                other_proto += 1
                continue
            proto = nxt
        else:
            if etype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
                unparsed_network_headers += 1
            continue

        # Transport parsing uses the tighter of capture, IP and UDP boundaries.
        # DNS counters identify a complete 12-byte header on port 53; they do not
        # validate questions, records, checksums, names, or a reassembled message.
        if proto == IPPROTO_UDP and packet_end >= l4 + 8:
            udp_length = struct.unpack(">H", frame[l4 + 4:l4 + 6])[0]
            if udp_length >= 8:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                udp += 1
                udp_end = min(packet_end, l4 + udp_length)
                if (sport == 53 or dport == 53) and udp_end >= l4 + 8 + 12:
                    dns_off = l4 + 8
                    if struct.unpack(">H", frame[dns_off + 2:dns_off + 4])[0] & 0x8000:
                        dns_responses += 1
                    else:
                        dns_queries += 1
            else:
                unparsed_network_headers += 1
                other_proto += 1
        elif proto == IPPROTO_TCP and packet_end >= l4 + 20:
            tcp_header_length = (frame[l4 + 12] >> 4) * 4
            if tcp_header_length >= 20 and packet_end >= l4 + tcp_header_length:
                sport, dport = struct.unpack(">HH", frame[l4:l4 + 4])
                tcp += 1
            else:
                unparsed_network_headers += 1
                other_proto += 1
        else:
            other_proto += 1
            if proto in (IPPROTO_TCP, IPPROTO_UDP) or proto in IPV6_EXT_HEADERS:
                unparsed_network_headers += 1

        if src is not None:
            flows[(src, dst, proto)] = flows.get((src, dst, proto), 0) + 1
        for pt in (sport, dport):
            if pt is not None:
                ports[pt] = ports.get(pt, 0) + 1

    if off != n:
        die(2, f"{n - off} trailing bytes form an incomplete 16-byte packet record header",
            packets=packets, trailing_bytes=n - off)

    return {
        "ok": True, "exit": 0, "file": path,
        "pcap": {"version": f"{vmaj}.{vmin}", "snaplen": snaplen, "linktype": link,
                 "linktype_word": link_word, "fcs_bytes": fcs_bytes,
                 "timestamp_resolution": "nanoseconds" if magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE) else "microseconds",
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
        "unparsed_network_headers": unparsed_network_headers,
        "distinct_flows": len(flows),
        "top_ports": sorted(((c, p) for p, c in ports.items()), reverse=True)[:6],
        "limits": ("NO REASSEMBLY, TLS, CHECKSUM VALIDATION, OR IPV6 JUMBOGRAMS. DNS counters require "
                   "a complete header on UDP port 53 but do not validate the question or record sections. "
                   "A DNS name split across packets, or any encrypted "
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
