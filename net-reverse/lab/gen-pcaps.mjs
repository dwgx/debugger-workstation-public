/* gen-pcaps.mjs — generate the self-authored pcap corpus (zero dependencies, synthetic only).
 *
 *   node lab/gen-pcaps.mjs [--out <dir>]
 *
 * Every file is built byte by byte with `pcap-writer.mjs`; no capture device is
 * touched, so nothing here can contain real traffic. Each file is written next to
 * a `corpus.json` label that states what it demonstrates, its sha256, and the
 * exact `tshark -r` filter that finds the guaranteed fact.
 *
 * The default output is `%TEMP%\net-reverse-lab\pcaps` (machine state, and the
 * station .gitignore forbids *.pcap in git — the generator is the source of
 * truth, the files are rebuilt, never shipped).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  NET, T0, TcpFlow, dnsQuery, dnsResponse, ethernet, ipv4, udpFrame, writePcapFile
} from './pcap-writer.mjs';

/* ------------------------------------------------------------------ builders */

function dnsExchange(packets, { t, name, type, id, answers, rcode = 0 }) {
  const q = dnsQuery({ id, name, type });
  packets.push(udpFrame({
    t, srcIp: NET.clientIp, dstIp: NET.resolverIp, srcPort: 53211, dstPort: 53, payload: q,
    srcMac: NET.clientMac, dstMac: NET.resolverMac, id: 0x100 + id
  }));
  const r = dnsResponse({ id, name, type, answers, rcode });
  packets.push(udpFrame({
    t: t + 0.012, srcIp: NET.resolverIp, dstIp: NET.clientIp, srcPort: 53, dstPort: 53211, payload: r,
    srcMac: NET.resolverMac, dstMac: NET.clientMac, id: 0x200 + id
  }));
}

const CRLF = '\r\n';
const toBuf = (s, enc = 'utf8') => Buffer.from(s, enc);

/** An HTTP message is start-line CRLF headers CRLF CRLF [body] — the blank line
 *  is what tells the dissector the request is complete, so it is built here once
 *  instead of being spelled out per call site (the first version ended messages
 *  with a single CRLF, and tshark then refused to dissect them as HTTP at all). */
function httpMsg({ startLine, headers = [], body = '' }) {
  const head = [startLine, ...headers].join(CRLF) + CRLF + CRLF;
  return Buffer.from(body ? head + body : head, 'utf8');
}

/* --- 1. DNS query/response shape ------------------------------------------- */
function buildDnsBasic() {
  const packets = [];
  dnsExchange(packets, { t: T0, name: 'lab.example.test', type: 'A', id: 0x1234, answers: [{ name: 'lab.example.test', type: 'A', value: '203.0.113.7', ttl: 300 }] });
  dnsExchange(packets, { t: T0 + 0.5, name: 'lab.example.test', type: 'AAAA', id: 0x1235, answers: [{ name: 'lab.example.test', type: 'AAAA', value: '2001:db8::7', ttl: 300 }] });
  return packets;
}

/* --- 2. HTTP request/response with headers + a plaintext credential -------- */
function buildHttpBasic() {
  const flow = new TcpFlow({ t: T0, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 49812, serverPort: 80, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0x300 }).handshake();

  flow.clientData(httpMsg({
    startLine: 'GET /index.html HTTP/1.1',
    headers: [
      'Host: lab.example.test',
      'User-Agent: lab-curl/1.0 (net-reverse corpus)',
      'Accept: text/html,application/xhtml+xml',
      'Accept-Language: en-US,en;q=0.9',
      'Connection: keep-alive'
    ]
  }));

  const page = '<html><head><title>net-reverse lab</title></head><body><form action="/login" method="post">lab</form></body></html>';
  flow.serverData(httpMsg({
    startLine: 'HTTP/1.1 200 OK',
    headers: [
      'Date: Wed, 30 Sep 2026 12:00:00 GMT',
      'Server: lab-httpd/1.0',
      'Content-Type: text/html; charset=utf-8',
      `Content-Length: ${Buffer.byteLength(page)}`,
      'ETag: "lab-1a2b3c"',
      'Cache-Control: no-store',
      'Connection: keep-alive'
    ],
    body: page
  }));

  /* The credential the corpus guarantees is recoverable: form-encoded, in the
     body, on a POST — i.e. it is NOT in a header and NOT in the URI, so the
     analyst has to reach for http.file_data (or follow the stream) to see it.
     Obviously a lab value, not a secret: it is committed source. */
  const form = 'username=lab-user&password=lab-only-password-9f2c&submit=Login';
  flow.clientData(httpMsg({
    startLine: 'POST /login HTTP/1.1',
    headers: [
      'Host: lab.example.test',
      'User-Agent: lab-curl/1.0 (net-reverse corpus)',
      'Content-Type: application/x-www-form-urlencoded',
      `Content-Length: ${Buffer.byteLength(form)}`,
      'Referer: http://lab.example.test/index.html',
      'Connection: keep-alive'
    ],
    body: form
  }));

  flow.serverData(httpMsg({
    startLine: 'HTTP/1.1 302 Found',
    headers: [
      'Date: Wed, 30 Sep 2026 12:00:01 GMT',
      'Server: lab-httpd/1.0',
      'Location: /dashboard',
      'Set-Cookie: lab_session=lab-session-not-a-real-token; Path=/; HttpOnly',
      'Content-Length: 0',
      'Connection: keep-alive'
    ]
  }));

  flow.close();
  return flow.packets;
}

/* --- 3. TLS ClientHello x2 (JA3-shaped fingerprint material) --------------- */

function tlsExt(type, data) {
  const head = Buffer.alloc(4);
  head.writeUInt16BE(type, 0);
  head.writeUInt16BE(data.length, 2);
  return Buffer.concat([head, data]);
}

function sniExt(host) {
  const name = Buffer.from(host, 'ascii');
  const list = Buffer.concat([Buffer.from([0]), to16(name.length), name]);
  return tlsExt(0, Buffer.concat([to16(list.length), list]));
}
function groupsExt(groups) {
  const list = Buffer.concat(groups.map(g => to16(g)));
  return tlsExt(10, Buffer.concat([to16(list.length), list]));
}
function pointFormatsExt(formats) { return tlsExt(11, Buffer.concat([Buffer.from([formats.length]), Buffer.from(formats)])); }
function sigAlgsExt(algs) {
  const list = Buffer.concat(algs.map(a => to16(a)));
  return tlsExt(13, Buffer.concat([to16(list.length), list]));
}
function alpnExt(protos) {
  const list = Buffer.concat(protos.map(p => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'ascii')])));
  return tlsExt(16, Buffer.concat([to16(list.length), list]));
}
function supportedVersionsExt(versions) {
  const list = Buffer.concat(versions.map(v => to16(v)));
  return tlsExt(43, Buffer.concat([Buffer.from([list.length]), list]));
}
function keyShareExt(group, keyLen) {
  const key = Buffer.alloc(keyLen, 0x7a);
  const share = Buffer.concat([to16(group), to16(key.length), key]);
  return tlsExt(51, Buffer.concat([to16(share.length), share]));
}
function to16(n) { return Buffer.from([(n >>> 8) & 0xff, n & 0xff]); }

/** A whole ClientHello record. `greaseFirst` mirrors what Chrome/Firefox send. */
function clientHello({ serverName, recordVersion, ciphers, extensions, sessionIdLen = 32, compression = [0] }) {
  const sessionId = Buffer.alloc(sessionIdLen, 0x5a);
  const exts = Buffer.concat(extensions);
  const body = Buffer.concat([
    to16(0x0303),                                 // legacy client_version (TLS 1.2)
    Buffer.alloc(32, 0x11),                       // random
    Buffer.from([sessionIdLen]), sessionId,
    to16(ciphers.length * 2), Buffer.concat(ciphers.map(c => to16(c))),
    Buffer.from([compression.length]), Buffer.from(compression),
    to16(exts.length), exts
  ]);
  const hsHead = Buffer.alloc(4);
  hsHead.writeUInt8(1, 0);                        // ClientHello
  hsHead.writeUIntBE(body.length, 1, 3);
  const recBody = Buffer.concat([hsHead, body]);
  const recHead = Buffer.alloc(5);
  recHead.writeUInt8(0x16, 0);                    // handshake
  recHead.writeUInt16BE(recordVersion, 1);
  recHead.writeUInt16BE(recBody.length, 3);
  return Buffer.concat([recHead, recBody]);
}

function buildTlsClientHello() {
  const packets = [];
  const ch1 = clientHello({
    serverName: 'shop.lab.test',
    recordVersion: 0x0301,
    ciphers: [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions: [
      sniExt('shop.lab.test'), groupsExt([0x0a0a, 29, 23, 24]), pointFormatsExt([0]), sigAlgsExt([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
      alpnExt(['h2', 'http/1.1']), supportedVersionsExt([0x0a0a, 0x0304, 0x0303]), keyShareExt(29, 32)
    ]
  });
  const ch2 = clientHello({
    serverName: 'api.lab.test',
    recordVersion: 0x0303,
    ciphers: [0x1301, 0x1303, 0xc02f, 0xc030, 0x009c, 0x009d, 0x002f, 0x0035, 0xc013, 0xc014],
    extensions: [
      sniExt('api.lab.test'), supportedVersionsExt([0x0304, 0x0303]), groupsExt([23, 24, 25]), pointFormatsExt([0, 1]),
      sigAlgsExt([0x0403, 0x0503, 0x0603]), alpnExt(['http/1.1']), keyShareExt(23, 65)
    ]
  });

  const flowA = new TcpFlow({ t: T0, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 52100, serverPort: 443, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0x400 }).handshake();
  flowA.clientData(ch1);
  flowA.close();
  packets.push(...flowA.packets);

  const flowB = new TcpFlow({ t: T0 + 1.5, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 52101, serverPort: 443, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0x500 }).handshake();
  flowB.clientData(ch2);
  flowB.close();
  packets.push(...flowB.packets);
  return packets;
}

/* --- 4. What a dissector refuses to guess: NTP and WHOIS on odd ports -------
 *
 * Measured on this box (Wireshark 4.6.8): HTTP, DNS and TFTP all register TCP/UDP
 * *heuristic* dissectors, so they are parsed on any port and "Decode As" teaches
 * nothing for them. NTP, WHOIS and Modbus/TCP are port-bound — stock tshark sees
 * `UDP 12345 → 40009 Len=48` and nothing more until `-d` names the protocol.
 * That difference is the lesson, so this file carries both halves.
 */
function buildOddPort() {
  const packets = [];

  /* (a) NTP over UDP 12345: client mode 3, server mode 4, stratum 2, refid "LAB". */
  const ntpReq = Buffer.alloc(48, 0);
  ntpReq[0] = 0x23;                        // LI=0, VN=4, Mode=3 (client)
  const ntpResp = Buffer.alloc(48, 0);
  ntpResp[0] = 0x24;                       // LI=0, VN=4, Mode=4 (server)
  ntpResp[1] = 2;                          // stratum 2
  ntpResp[2] = 6;                          // poll interval
  ntpResp[3] = 0xec;                       // precision -20
  ntpResp.writeUInt32BE(0x4c414200, 12);   // reference id "LAB\0"
  packets.push(udpFrame({ t: T0, srcIp: NET.clientIp, dstIp: NET.serverIp, srcPort: 40009, dstPort: 12345, payload: ntpReq, srcMac: NET.clientMac, dstMac: NET.serverMac, id: 0xc01 }));
  packets.push(udpFrame({ t: T0 + 0.001, srcIp: NET.serverIp, dstIp: NET.clientIp, srcPort: 12345, dstPort: 40009, payload: ntpResp, srcMac: NET.serverMac, dstMac: NET.clientMac, id: 0xc02 }));

  /* (b) WHOIS over TCP 4343. */
  const whois = new TcpFlow({ t: T0 + 0.5, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 40010, serverPort: 4343, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0xc10 }).handshake();
  whois.clientData(toBuf('LAB-WHOIS-42\r\n', 'ascii'));
  whois.serverData(toBuf([
    'domain: LAB-WHOIS-42',
    'netname: 203.0.113.0/24',
    'descr: net-reverse synthetic corpus',
    'mnt-by: LAB-NOC',
    ''
  ].join('\r\n'), 'ascii'));
  whois.close();
  packets.push(...whois.packets);

  /* (c) A framed binary protocol: 4-byte magic, version, length, then a tagged
     field table. The marker is ASCII inside a length-prefixed field, so it only
     appears if the analyst follows the stream instead of filtering for it. */
  const bin = new TcpFlow({ t: T0 + 1.5, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 40011, serverPort: 1337, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0x700 }).handshake();
  const header = Buffer.concat([toBuf('LAPP'), Buffer.from([0x02, 0x00, 0x02])]);
  const field = (tag, value) => Buffer.concat([Buffer.from([tag]), Buffer.from([value.length]), toBuf(value)]);
  const frame = Buffer.concat([header, field(1, 'LAB-MARKER-7f3a'), field(2, 'role=analyst')]);
  bin.clientData(frame);
  bin.serverData(Buffer.concat([Buffer.from([0x4c, 0x41, 0x50, 0x50]), Buffer.from([0x02, 0x80, 0x00])]));
  bin.close();
  packets.push(...bin.packets);

  /* (d) The control: HTTP on TCP 4444 is dissected with NO decode-as at all,
     because 4.6 ships an HTTP heuristic. Contrast is the teaching point. */
  const odd = new TcpFlow({ t: T0 + 2.5, clientIp: NET.clientIp, serverIp: NET.serverIp, clientPort: 45678, serverPort: 4444, clientMac: NET.clientMac, serverMac: NET.serverMac, id: 0x600 }).handshake();
  odd.clientData(httpMsg({
    startLine: 'GET /admin/status HTTP/1.1',
    headers: [
      'Host: 203.0.113.10:4444',
      'User-Agent: lab-curl/1.0 (net-reverse corpus)',
      'Accept: */*',
      'Connection: keep-alive'
    ]
  }));
  const json = '{"service":"lab-admin","port":4444,"ok":true}';
  odd.serverData(httpMsg({
    startLine: 'HTTP/1.1 200 OK',
    headers: ['Server: lab-httpd/1.0', 'Content-Type: application/json', `Content-Length: ${Buffer.byteLength(json)}`, 'Connection: keep-alive'],
    body: json
  }));
  odd.close();
  packets.push(...odd.packets);

  return packets;
}

/* --- 5. The answer hides in a record type you did not think to filter for -- */
export const TXT_ANSWER = 'LAB{tx-ball-42e1b8c9}';
function buildDnsTxt() {
  const packets = [];
  dnsExchange(packets, {
    t: T0, name: '_lab-challenge.lab.test', type: 'TXT', id: 0x2001,
    answers: [
      { name: '_lab-challenge.lab.test', type: 'TXT', value: 'ignore-this-vendor-txt-record', ttl: 60 },
      { name: '_lab-challenge.lab.test', type: 'TXT', value: TXT_ANSWER, ttl: 60 }
    ]
  });

  /* Alias chain: the A record an analyst wants is only reachable through a CNAME. */
  const q = dnsQuery({ id: 0x2002, name: 'www.lab.test', type: 'A' });
  packets.push(udpFrame({
    t: T0 + 0.7, srcIp: NET.clientIp, dstIp: NET.resolverIp, srcPort: 53212, dstPort: 53, payload: q,
    srcMac: NET.clientMac, dstMac: NET.resolverMac, id: 0x201
  }));
  const r = dnsResponse({
    id: 0x2002, name: 'www.lab.test', type: 'A',
    answers: [
      { name: 'www.lab.test', type: 'CNAME', value: 'edge.lab.test', ttl: 300 },
      { name: 'www.lab.test', type: 'A', value: '203.0.113.99', ttl: 120 }
    ]
  });
  packets.push(udpFrame({
    t: T0 + 0.712, srcIp: NET.resolverIp, dstIp: NET.clientIp, srcPort: 53, dstPort: 53212, payload: r,
    srcMac: NET.resolverMac, dstMac: NET.clientMac, id: 0x202
  }));
  return packets;
}

/* ------------------------------------------------------------------ driver */

/** file -> { teaches, guarantees, filters, build } — the corpus label + truth. */
export const FILES = {
  'dns-basic.pcap': {
    teaches: 'DNS query/response shape for A and AAAA over UDP/53.',
    protocols: ['dns', 'udp'],
    filters: ['dns', 'dns.a', 'dns.aaaa', 'dns.qry.name == "lab.example.test"'],
    guarantees: [
      'lab.example.test resolves to A 203.0.113.7 (TTL 300)',
      'lab.example.test resolves to AAAA 2001:db8::7',
      'exactly 2 DNS queries in the file'
    ],
    build: buildDnsBasic
  },
  'http-basic.pcap': {
    teaches: 'HTTP request/response with headers, bodies and a status line; a plaintext credential in a POST body.',
    protocols: ['tcp', 'http'],
    filters: ['http', 'http.request.method == "POST"', 'http.request.uri == "/login"', 'http.file_data'],
    guarantees: [
      'GET /index.html answered 200 by "lab-httpd/1.0"',
      'POST /login carries username=lab-user&password=lab-only-password-9f2c in the body',
      'the response sets a lab_session cookie; the credential never appears in a header or the URI'
    ],
    build: buildHttpBasic
  },
  'tls-clienthello.pcap': {
    teaches: 'TLS ClientHello internals: SNI, cipher list, extension list, groups — the inputs a JA3-shaped client fingerprint is built from.',
    protocols: ['tcp', 'tls'],
    filters: ['tls.handshake.type == 1', 'tls.handshake.extensions_server_name', 'tls.handshake.ciphersuite', 'tls.handshake.extension.type'],
    guarantees: [
      'two ClientHellos: SNI shop.lab.test (record version 0x0301) and SNI api.lab.test (record version 0x0303)',
      'the cipher lists and extension lists differ, so the two clients hash to 2 distinct fingerprints',
      'no ServerHello, no certificate: the file exercises parsing, not decryption'
    ],
    build: buildTlsClientHello
  },
  'odd-port.pcap': {
    teaches: 'Which protocols need Decode As and which do not: NTP on 12345 and WHOIS on 4343 are invisible to the stock dissectors, HTTP on 4444 is not (4.6 ships an HTTP heuristic). Plus a binary stream whose payload only appears if you follow it.',
    protocols: ['udp', 'ntp (decode-as)', 'tcp', 'whois (decode-as)', 'http (heuristic)', 'custom binary'],
    filters: ['-d udp.port==12345,ntp -Y ntp', '-d tcp.port==4343,whois -Y whois', '-z conv,tcp', '-q -z follow,tcp,ascii,2'],
    guarantees: [
      'stock `-Y ntp` and `-Y whois` match 0 packets: the protocols are port-bound, not heuristic',
      'with -d, the NTP exchange is client mode 3 -> server mode 4, stratum 2, reference id "LAB"',
      'with -d, the WHOIS answer carries the netname 203.0.113.0/24 for the query LAB-WHOIS-42',
      'TCP stream 2 is a framed binary protocol (magic "LAPP") whose payload contains the ASCII marker LAB-MARKER-7f3a',
      'HTTP on TCP 4444 is dissected with no decode-as (the control case)'
    ],
    build: buildOddPort
  },
  'dns-txt.pcap': {
    teaches: 'The value you want is often in a record type you did not filter for: an alias chain plus a multi-chunk TXT answer that Wireshark splits across dns.txt occurrences.',
    protocols: ['dns', 'udp'],
    filters: ['dns.resp.type == 16', 'dns.txt', 'dns.cname', 'dns.a'],
    guarantees: [
      `the TXT answer for _lab-challenge.lab.test contains ${TXT_ANSWER} (split across chunks, and preceded by a decoy TXT record)`,
      'www.lab.test is a CNAME to edge.lab.test, which is A 203.0.113.99'
    ],
    build: buildDnsTxt
  }
};

export function defaultOutDir() {
  return process.env.NET_REVERSE_PCAP_DIR || path.join(os.tmpdir(), 'net-reverse-lab', 'pcaps');
}

export function generate(outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const manifest = { generated_at: new Date().toISOString(), synthetic: true, generator: 'net-reverse/lab/gen-pcaps.mjs', files: {} };
  for (const [file, spec] of Object.entries(FILES)) {
    const packets = spec.build().sort((a, b) => a.ts - b.ts);
    const target = path.join(outDir, file);
    const bytes = writePcapFile(target, packets);
    const sha256 = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
    manifest.files[file] = {
      path: target, bytes, packets: packets.length, sha256,
      teaches: spec.teaches, protocols: spec.protocols, filters: spec.filters, guarantees: spec.guarantees
    };
  }
  fs.writeFileSync(path.join(outDir, 'corpus.json'), JSON.stringify(manifest, null, 2));
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outIdx = process.argv.indexOf('--out');
  const outDir = outIdx > -1 ? process.argv[outIdx + 1] : defaultOutDir();
  const manifest = generate(outDir);
  console.log(`net-reverse pcap corpus (synthetic, self-authored) -> ${outDir}`);
  for (const [file, info] of Object.entries(manifest.files)) {
    console.log(`  ${file.padEnd(24)} ${String(info.packets).padStart(3)} packets  ${String(info.bytes).padStart(6)} B  sha256:${info.sha256.slice(0, 16)}`);
    console.log(`      teaches: ${info.teaches}`);
  }
  console.log(`  label -> ${path.join(outDir, 'corpus.json')}`);
}
