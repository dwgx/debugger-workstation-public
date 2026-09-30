/* pcap-writer.mjs — a libpcap file writer (Ethernet/IPv4/TCP/UDP/DNS), zero dependencies.
 *
 * Why hand-rolled: the station owns tshark but owns no pcap corpus and no packet
 * crafting library, and installing one (scapy, gopacket) would add a third-party
 * dependency for something the pcap format makes easy — a 24-byte file header, a
 * 16-byte record header per packet, and a frame. ~250 lines, no install, and the
 * corpus stays self-authored and inspectable.
 *
 * Everything here is SYNTHETIC. No byte in any generated file came from a real
 * network. Addresses use the RFC 5737 documentation ranges (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24), names use the RFC 2606 `.test` TLD, and MACs
 * use the locally-administered prefix 02:00:5e:... so a generated file can never
 * be mistaken for a capture of somebody's traffic.
 */
import fs from 'node:fs';

/* ---------------------------------------------------------------- primitives */

/** Internet checksum (RFC 1071) over a buffer, with an optional pseudo-header. */
export function checksum16(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += (buf[i] << 8) | buf[i + 1];
  if (buf.length & 1) sum += buf[buf.length - 1] << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

export const ipToBytes = ip => ip.split('.').map(n => parseInt(n, 10));
export const macToBytes = mac => mac.split(':').map(h => parseInt(h, 16));

function u16(n) { return Buffer.from([(n >>> 8) & 0xff, n & 0xff]); }
function u32(n) { return Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]); }

/** Pseudo-header for TCP/UDP checksums (IPv4). */
function pseudoHeader(srcIp, dstIp, proto, length) {
  return Buffer.concat([Buffer.from(ipToBytes(srcIp)), Buffer.from(ipToBytes(dstIp)),
    Buffer.from([0, proto]), u16(length)]);
}

/* ---------------------------------------------------------------- layer 4 */

export function udp({ srcIp, dstIp, srcPort, dstPort, payload = Buffer.alloc(0) }) {
  const len = 8 + payload.length;
  const body = Buffer.concat([u16(srcPort), u16(dstPort), u16(len), Buffer.from([0, 0]), payload]);
  const sum = checksum16(Buffer.concat([pseudoHeader(srcIp, dstIp, 17, len), body]));
  body.writeUInt16BE(sum === 0 ? 0xffff : sum, 6);
  return body;
}

const TCP_FLAG = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32 };
export const tcpFlags = names => names.reduce((acc, n) => acc | TCP_FLAG[n], 0);

/** Options: MSS + SACK-permitted + window scale + two NOPs = 12 bytes (data offset 8). */
export function synOptions(mss = 1460, wscale = 8) {
  return Buffer.from([
    0x02, 0x04, (mss >> 8) & 0xff, mss & 0xff,   // MSS
    0x04, 0x02,                                   // SACK permitted
    0x01,                                         // NOP
    0x03, 0x03, wscale,                           // window scale
    0x01, 0x01                                    // NOP, NOP  -> 12 bytes total
  ]);
}

export function tcp({ srcIp, dstIp, srcPort, dstPort, seq, ack = 0, flags, window = 64240, payload = Buffer.alloc(0), options = Buffer.alloc(0) }) {
  const offset = 5 + options.length / 4;
  const header = Buffer.alloc(20);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt32BE(seq >>> 0, 4);
  header.writeUInt32BE(ack >>> 0, 8);
  header.writeUInt8((offset << 4) | 0, 12);
  header.writeUInt8(flags, 13);
  header.writeUInt16BE(window, 14);
  header.writeUInt16BE(0, 16);          // checksum placeholder
  header.writeUInt16BE(0, 18);          // urgent pointer
  const body = Buffer.concat([header, options, payload]);
  const sum = checksum16(Buffer.concat([pseudoHeader(srcIp, dstIp, 6, body.length), body]));
  body.writeUInt16BE(sum === 0 ? 0xffff : sum, 16);
  return body;
}

/* ---------------------------------------------------------------- layer 3/2 */

export function ipv4({ srcIp, dstIp, proto, payload, id = 0, ttl = 64, dscp = 0 }) {
  const total = 20 + payload.length;
  const header = Buffer.alloc(20);
  header.writeUInt8(0x45, 0);
  header.writeUInt8(dscp << 2, 1);
  header.writeUInt16BE(total, 2);
  header.writeUInt16BE(id & 0xffff, 4);
  header.writeUInt16BE(0x4000, 6);       // don't fragment — these are tiny synthetic frames
  header.writeUInt8(ttl, 8);
  header.writeUInt8(proto, 9);
  header.writeUInt16BE(0, 10);           // checksum placeholder
  Buffer.from(ipToBytes(srcIp)).copy(header, 12);
  Buffer.from(ipToBytes(dstIp)).copy(header, 16);
  header.writeUInt16BE(checksum16(header), 10);
  return Buffer.concat([header, payload]);
}

export function ethernet({ srcMac, dstMac, ethertype = 0x0800, payload }) {
  return Buffer.concat([Buffer.from(macToBytes(dstMac)), Buffer.from(macToBytes(srcMac)), u16(ethertype), payload]);
}

/* ---------------------------------------------------------------- pcap file */

export const PCAP_MAGIC_USEC = 0xa1b2c3d4;

/** packets: [{ ts: seconds(float), data: Buffer(frame) }] -> pcap file buffer. */
export function writePcap(packets, { snaplen = 262144 } = {}) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(PCAP_MAGIC_USEC, 0);
  head.writeUInt16LE(2, 4);              // version major
  head.writeUInt16LE(4, 6);              // version minor
  head.writeUInt32LE(0, 8);              // thiszone
  head.writeUInt32LE(0, 12);             // sigfigs
  head.writeUInt32LE(snaplen, 16);
  head.writeUInt32LE(1, 20);             // LINKTYPE_ETHERNET
  const chunks = [head];
  for (const p of packets) {
    const tsSec = Math.floor(p.ts);
    const tsUsec = Math.round((p.ts - tsSec) * 1e6);
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(tsSec, 0);
    rec.writeUInt32LE(tsUsec, 4);
    rec.writeUInt32LE(p.data.length, 8);
    rec.writeUInt32LE(p.data.length, 12);
    chunks.push(rec, p.data);
  }
  return Buffer.concat(chunks);
}

export function writePcapFile(file, packets, opts) {
  fs.writeFileSync(file, writePcap(packets, opts));
  return fs.statSync(file).size;
}

/* ---------------------------------------------------------------- DNS */

const DNS_TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28 };
export const DNS_TYPE_NAME = Object.fromEntries(Object.entries(DNS_TYPE).map(([k, v]) => [v, k]));

function qname(name) {
  const parts = name.replace(/\.$/, '').split('.');
  const bufs = parts.map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function rdataFor(type, value) {
  if (type === DNS_TYPE.A) return Buffer.from(ipToBytes(value));
  if (type === DNS_TYPE.AAAA) {
    const groups = value.split(':');
    const full = groups.length === 8 ? groups : [...groups.slice(0, groups.length - 1), ...Array(8 - groups.length).fill('0'), groups[groups.length - 1]];
    return Buffer.concat(full.map(g => u16(parseInt(g === '' ? '0' : g, 16))));
  }
  if (type === DNS_TYPE.CNAME) return qname(value);
  if (type === DNS_TYPE.TXT) {
    const text = Buffer.from(value, 'ascii');
    const out = [];
    for (let i = 0; i < text.length; i += 64) {
      const slice = text.subarray(i, i + 64);
      out.push(Buffer.from([slice.length]), slice);
    }
    return Buffer.concat(out);
  }
  throw new Error(`rdataFor: unsupported type ${type}`);
}

export function dnsQuery({ id, name, type = 'A', rd = true, opcode = 0 }) {
  const flags = (opcode << 11) | (rd ? 0x0100 : 0);
  return Buffer.concat([
    u16(id), u16(flags), u16(1), u16(0), u16(0), u16(0),
    qname(name), u16(DNS_TYPE[type]), u16(1)
  ]);
}

/**
 * Response. answers: [{ name, type, value, ttl, compressed:true }] — `compressed`
 * uses a 0xC00C pointer, the shape every real resolver sends, which is also why
 * an analyst sees `dns.qry.name` in the answer rows instead of a mangled label.
 */
export function dnsResponse({ id, name, type = 'A', answers = [], rcode = 0, aa = false, rd = true, ra = true, questionRepeat = true }) {
  const flags = 0x8000 | (aa ? 0x0400 : 0) | (rd ? 0x0100 : 0) | (ra ? 0x0080 : 0) | (rcode & 0xf);
  const q = questionRepeat ? Buffer.concat([qname(name), u16(DNS_TYPE[type]), u16(1)]) : Buffer.alloc(0);
  const ans = answers.map(a => {
    const rdata = rdataFor(DNS_TYPE[a.type], a.value);
    return Buffer.concat([
      Buffer.from([0xc0, 0x0c]), u16(DNS_TYPE[a.type]), u16(1), u32(a.ttl ?? 300), u16(rdata.length), rdata
    ]);
  });
  return Buffer.concat([u16(id), u16(flags), u16(questionRepeat ? 1 : 0), u16(ans.length), u16(0), u16(0), q, ...ans]);
}

/* ---------------------------------------------------------------- conversations */

/**
 * A TCP conversation that owns sequence numbers, so callers only push bytes.
 * Emits the frames in order: handshake -> data -> FIN teardown, with plausible
 * inter-packet timing (0.2 ms inside the box at these rtts).
 */
export class TcpFlow {
  constructor({ t, clientIp, serverIp, clientPort, serverPort, clientMac, serverMac, id = 1 }) {
    this.t = t;
    this.clientIp = clientIp; this.serverIp = serverIp;
    this.clientPort = clientPort; this.serverPort = serverPort;
    this.clientMac = clientMac; this.serverMac = serverMac;
    this.packets = [];
    this.idBase = id;
    this.cseq = 1000; this.sseq = 500000;
    this.mss = 1460;
  }

  #emit({ from, flags, payload = Buffer.alloc(0) }) {
    const clientToServer = from === 'client';
    const srcIp = clientToServer ? this.clientIp : this.serverIp;
    const dstIp = clientToServer ? this.serverIp : this.clientIp;
    const srcPort = clientToServer ? this.clientPort : this.serverPort;
    const dstPort = clientToServer ? this.serverPort : this.clientPort;
    const seq = clientToServer ? this.cseq : this.sseq;
    const ack = clientToServer ? this.sseq : this.cseq;
    const options = (flags & TCP_FLAG.SYN) ? synOptions(this.mss) : Buffer.alloc(0);
    const seg = tcp({ srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, options });
    const frame = ethernet({
      srcMac: clientToServer ? this.clientMac : this.serverMac,
      dstMac: clientToServer ? this.serverMac : this.clientMac,
      payload: ipv4({ srcIp, dstIp, proto: 6, payload: seg, id: (this.idBase + this.packets.length) & 0xffff })
    });
    this.packets.push({ ts: this.t, data: frame });
    this.t += 0.0002;
    if (clientToServer) this.cseq = (this.cseq + payload.length + (flags & TCP_FLAG.SYN ? 1 : 0) + (flags & TCP_FLAG.FIN ? 1 : 0)) >>> 0;
    else this.sseq = (this.sseq + payload.length + (flags & TCP_FLAG.SYN ? 1 : 0) + (flags & TCP_FLAG.FIN ? 1 : 0)) >>> 0;
  }

  handshake() {
    this.#emit({ from: 'client', flags: tcpFlags(['SYN']) });
    this.sseq += 0; // server stays as-is; seq already advanced by #emit
    this.#emit({ from: 'server', flags: tcpFlags(['SYN', 'ACK']) });
    this.#emit({ from: 'client', flags: tcpFlags(['ACK']) });
    this.t += 0.0004;
    return this;
  }

  /** Client -> server bytes. */
  clientData(buf) { this.#emit({ from: 'client', flags: tcpFlags(['PSH', 'ACK']), payload: buf }); return this; }
  /** Server -> client bytes. */
  serverData(buf) { this.#emit({ from: 'server', flags: tcpFlags(['PSH', 'ACK']), payload: buf }); return this; }

  close() {
    this.t += 0.001;
    this.#emit({ from: 'server', flags: tcpFlags(['FIN', 'ACK']) });
    this.#emit({ from: 'client', flags: tcpFlags(['FIN', 'ACK']) });
    this.#emit({ from: 'server', flags: tcpFlags(['ACK']) });
    this.t += 0.002;
    return this;
  }
}

/** One UDP datagram as an Ethernet frame. */
export function udpFrame({ t, srcIp, dstIp, srcPort, dstPort, payload, srcMac, dstMac, id = 1 }) {
  return {
    ts: t,
    data: ethernet({
      srcMac, dstMac,
      payload: ipv4({ srcIp, dstIp, proto: 17, payload: udp({ srcIp, dstIp, srcPort, dstPort, payload }), id })
    })
  };
}

/** The house constants: documentation address space + locally administered MACs. */
export const NET = {
  clientIp: '192.0.2.10',
  serverIp: '203.0.113.10',
  resolverIp: '198.51.100.53',
  clientMac: '02:00:5e:10:00:01',
  serverMac: '02:00:5e:10:00:02',
  resolverMac: '02:00:5e:10:00:03',
  echoMac: '02:00:5e:10:00:04'
};

/** Deterministic clock: every generated corpus starts at 2026-09-30T12:00:00Z. */
export const T0 = Date.UTC(2026, 8, 30, 12, 0, 0) / 1000;
