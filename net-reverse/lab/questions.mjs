/* questions.mjs — the analyst questions the corpus is built to answer.
 *
 * Each entry is one question an analyst would actually ask of a capture, the
 * tshark command that answers it, and the assertion that decides PASS. The
 * question is judged against the guarantee in `corpus.json` — if tshark stops
 * finding the thing the file is built to contain, the driver exits non-zero.
 *
 * `negative` is the falsifiability half: the same command, run against a file
 * that must NOT satisfy it. A question that passes on every file proves nothing.
 */
import crypto from 'node:crypto';
import { hexFieldToText, lines } from './tshark.mjs';

const uniq = a => [...new Set(a)];
const has = (haystack, needle) => haystack.includes(needle);

export const QUESTIONS = [
  /* ---------------------------------------------------------------- DNS shape */
  {
    id: 'dns-a-record',
    pcap: 'dns-basic.pcap',
    question: 'What IPv4 address does lab.example.test resolve to?',
    method: 'field extraction (-e dns.a under the dns display filter)',
    args: ['-Y', 'dns.a', '-T', 'fields', '-e', 'dns.a'],
    guarantee: 'lab.example.test resolves to A 203.0.113.7 (TTL 300)',
    test: out => {
      const got = uniq(lines(out));
      return { ok: got.length > 0 && got.every(v => v === '203.0.113.7'), detail: got.join(',') || '(no dns.a)' };
    },
    negative: { pcap: 'dns-txt.pcap', why: 'dns-txt.pcap resolves other names; the same filter must not return 203.0.113.7' }
  },
  {
    id: 'dns-aaaa-record',
    pcap: 'dns-basic.pcap',
    question: 'What IPv6 address does the same name answer with?',
    method: 'field extraction (-e dns.aaaa) — the same name, a different record type',
    args: ['-Y', 'dns.aaaa', '-T', 'fields', '-e', 'dns.aaaa'],
    guarantee: 'lab.example.test resolves to AAAA 2001:db8::7',
    test: out => {
      const got = uniq(lines(out));
      return { ok: got.length === 1 && got[0] === '2001:db8::7', detail: got.join(',') || '(no dns.aaaa)' };
    },
    negative: { pcap: 'dns-txt.pcap', why: 'no AAAA record exists in dns-txt.pcap' }
  },
  {
    id: 'dns-query-count',
    pcap: 'dns-basic.pcap',
    question: 'How many DNS queries (not responses) are in the capture?',
    method: 'counting rows: filter on dns.flags.response == 0, count the ids',
    args: ['-Y', 'dns.flags.response == 0', '-T', 'fields', '-e', 'dns.id'],
    guarantee: 'exactly 2 DNS queries in the file',
    test: out => {
      const got = lines(out);
      return { ok: got.length === 2, detail: `${got.length} query id(s)` };
    },
    negative: { pcap: 'http-basic.pcap', why: 'http-basic.pcap has no DNS query at all, so the count must not read 2' }
  },

  /* ------------------------------------------------------- HTTP with a secret */
  {
    id: 'http-plaintext-credential',
    pcap: 'http-basic.pcap',
    question: 'Find the plaintext credential field in this capture. Where does it live?',
    method: 'the credential is in the BODY, not a header or the URI: filter http.request.method == POST and read http.file_data (hex bytes)',
    args: ['-Y', 'http.request.method == POST', '-T', 'fields', '-e', 'http.request.uri', '-e', 'http.file_data'],
    guarantee: 'POST /login carries username=lab-user&password=lab-only-password-9f2c in the body',
    test: out => {
      const decoded = lines(out).map(l => hexFieldToText(l.split('\t').pop())).join('\n');
      const ok = has(decoded, 'password=lab-only-password-9f2c') && has(decoded, 'username=lab-user');
      return { ok, detail: ok ? 'POST body decodes to username=lab-user&password=lab-only-password-9f2c' : `body did not contain the credential (${decoded.length} bytes decoded)` };
    },
    negative: { pcap: 'dns-basic.pcap', why: 'no HTTP POST exists in a DNS-only capture' }
  },
  {
    id: 'http-credential-is-not-in-headers',
    pcap: 'http-basic.pcap',
    question: 'Is the credential visible in a request header or in the URI?',
    method: 'the inverse check — proving where a secret is NOT is part of finding where it is',
    args: ['-Y', 'http.request', '-T', 'fields', '-e', 'http.request.uri', '-e', 'http.cookie', '-e', 'http.authorization'],
    guarantee: 'the credential never appears in a header or the URI',
    test: out => {
      const ok = !has(out, 'lab-only-password-9f2c');
      return { ok, detail: ok ? 'no credential in URI/cookie/authorization' : 'credential leaked into a header or URI' };
    },
    negative: {
      pcap: 'http-basic.pcap',
      args: ['-q', '-z', 'follow,tcp,ascii,0'],
      why: 'the same credential IS in the POST body — following the stream as text must surface it, otherwise "not in headers" would be vacuous'
    }
  },
  {
    id: 'http-server-banner',
    pcap: 'http-basic.pcap',
    question: 'What server software answered, and with which status codes?',
    method: 'field extraction across responses (-e http.response.code -e http.server)',
    args: ['-Y', 'http.response', '-T', 'fields', '-e', 'http.response.code', '-e', 'http.server'],
    guarantee: 'GET /index.html answered 200 by "lab-httpd/1.0"',
    test: out => {
      const got = lines(out);
      const ok = got.length === 2 && has(out, 'lab-httpd/1.0') && has(out, '200') && has(out, '302');
      return { ok, detail: got.join(' | ') || '(no responses)' };
    },
    negative: { pcap: 'tls-clienthello.pcap', why: 'the TLS capture carries no HTTP response' }
  },

  /* ------------------------------------------------------------------- TLS */
  {
    id: 'tls-sni',
    pcap: 'tls-clienthello.pcap',
    question: 'Which hostnames are the clients asking for?',
    method: 'filter tls.handshake.type == 1 (ClientHello), extract extensions_server_name',
    args: ['-Y', 'tls.handshake.type == 1', '-T', 'fields', '-e', 'tls.handshake.extensions_server_name'],
    guarantee: 'two ClientHellos: SNI shop.lab.test and SNI api.lab.test',
    test: out => {
      const got = uniq(lines(out));
      const ok = got.length === 2 && has(got.join(','), 'shop.lab.test') && has(got.join(','), 'api.lab.test');
      return { ok, detail: got.join(',') || '(no SNI)' };
    },
    negative: { pcap: 'http-basic.pcap', why: 'plaintext HTTP has no ClientHello' }
  },
  {
    id: 'tls-distinct-client-fingerprints',
    pcap: 'tls-clienthello.pcap',
    question: 'How many distinct client fingerprints are in the capture?',
    method: 'JA3-shaped fingerprint: md5(record_version, cipher list, extension list, groups, point formats) per ClientHello, then count distinct',
    args: [
      '-Y', 'tls.handshake.type == 1', '-T', 'fields',
      '-e', 'tls.record.version', '-e', 'tls.handshake.ciphersuite', '-e', 'tls.handshake.extension.type',
      '-e', 'tls.handshake.extensions_supported_group', '-e', 'tls.handshake.extensions_ec_point_format'
    ],
    guarantee: 'the cipher lists and extension lists differ, so the two clients hash to 2 distinct fingerprints',
    /* JA3 removes GREASE (0x?a?a) values before hashing; same here, so the number
       is stable across real Chrome/Firefox captures as well as this corpus. */
    test: out => {
      const isGrease = v => { const n = parseInt(v, 16); return !Number.isNaN(n) && (n & 0x0f0f) === 0x0a0a; };
      const strip = field => (field ? field.split(',').map(s => s.trim()).filter(s => s && !isGrease(s)).join('-') : '');
      const fingerprints = lines(out).map(line => {
        const [version, ciphers, exts, groups, points] = line.split('\t');
        const ja3String = [version, ciphers, exts, groups, points].map(strip).join(',');
        return { ja3String, md5: crypto.createHash('md5').update(ja3String).digest('hex') };
      });
      const distinct = uniq(fingerprints.map(f => f.md5));
      return {
        ok: fingerprints.length === 2 && distinct.length === 2,
        detail: `${fingerprints.length} ClientHello(s) -> ${distinct.length} distinct fingerprint(s): ${distinct.map(d => d.slice(0, 12)).join(', ')}`
      };
    },
    negative: { pcap: 'dns-basic.pcap', why: 'a DNS-only capture has no ClientHello to fingerprint' }
  },
  {
    id: 'tls-no-server-secrets',
    pcap: 'tls-clienthello.pcap',
    question: 'Can this capture be decrypted — is there a ServerHello or a certificate in it?',
    method: 'asking about ABSENCE: -Y "tls.handshake.type == 2 or tls.handshake.type == 11" must match nothing',
    args: ['-Y', 'tls.handshake.type == 2 or tls.handshake.type == 11', '-T', 'fields', '-e', 'tls.handshake.type'],
    guarantee: 'no ServerHello, no certificate: the file exercises parsing, not decryption',
    test: out => {
      const got = lines(out);
      return { ok: got.length === 0, detail: got.length === 0 ? 'absent as guaranteed (no ServerHello/certificate)' : `unexpected: ${got.join(',')}` };
    },
    negative: { pcap: 'tls-clienthello.pcap', args: ['-Y', 'tls.handshake.type == 1', '-T', 'fields', '-e', 'tls.handshake.type'], why: 'the ClientHellos ARE there — the absence check above is not vacuous' }
  },

  /* --------------------------------------- the port-bound dissectors (decode-as) */
  {
    id: 'odd-ntp-decode-as',
    pcap: 'odd-port.pcap',
    question: 'Something is talking UDP 12345. What is it, and what stratum does the server claim?',
    method: 'Decode As: -d udp.port==12345,ntp, then filter ntp.flags.mode == 4 and read ntp.stratum / ntp.refid',
    args: ['-d', 'udp.port==12345,ntp', '-Y', 'ntp.flags.mode == 4', '-T', 'fields', '-e', 'ntp.stratum', '-e', 'ntp.refid'],
    guarantee: 'with -d, the NTP exchange is client mode 3 -> server mode 4, stratum 2, reference id "LAB"',
    test: out => {
      const ok = /^2\t4c414200$/m.test(out.trim());
      return { ok, detail: out.trim() || '(no NTP server packet)' };
    },
    negative: { pcap: 'odd-port.pcap', args: ['-Y', 'ntp.flags.mode == 4', '-T', 'fields', '-e', 'ntp.stratum'], why: 'without -d the dissector never runs, so the stock filter must return nothing' }
  },
  {
    id: 'odd-whois-decode-as',
    pcap: 'odd-port.pcap',
    question: 'What does the WHOIS answer on TCP 4343 say?',
    method: 'Decode As: -d tcp.port==4343,whois, then read whois.answer',
    args: ['-d', 'tcp.port==4343,whois', '-Y', 'whois.answer', '-T', 'fields', '-e', 'whois.query', '-e', 'whois.answer'],
    guarantee: 'with -d, the WHOIS answer carries the netname 203.0.113.0/24 for the query LAB-WHOIS-42',
    test: out => {
      const ok = has(out, 'netname: 203.0.113.0/24') && has(out, 'LAB-WHOIS-42');
      return { ok, detail: ok ? 'query LAB-WHOIS-42 -> netname 203.0.113.0/24' : 'answer text not found' };
    },
    negative: { pcap: 'odd-port.pcap', args: ['-Y', 'whois.answer', '-T', 'fields', '-e', 'whois.answer'], why: 'without -d, tshark dissects TCP 4343 as opaque bytes' }
  },
  {
    id: 'odd-follow-stream-marker',
    pcap: 'odd-port.pcap',
    question: 'A non-HTTP stream carries a marker. Recover it.',
    method: "follow the stream: -q -z follow,tcp,ascii,1 (the marker is inside a length-prefixed field, so no display filter reaches it)",
    args: ['-q', '-z', 'follow,tcp,ascii,1'],
    guarantee: 'TCP stream 1 is a framed binary protocol (magic "LAPP") whose payload contains the ASCII marker LAB-MARKER-7f3a',
    test: out => {
      const ok = has(out, 'LAB-MARKER-7f3a') && has(out, 'LAPP');
      return { ok, detail: ok ? 'stream 1 payload decoded: LAPP frame with LAB-MARKER-7f3a' : 'marker not present in the followed stream' };
    },
    negative: { pcap: 'odd-port.pcap', args: ['-q', '-z', 'follow,tcp,ascii,0'], why: 'stream 0 is the WHOIS conversation; the marker must not appear there' }
  },
  {
    id: 'odd-http-needs-no-decode-as',
    pcap: 'odd-port.pcap',
    question: 'Is HTTP on TCP 4444 also hidden without Decode As?',
    method: 'the control: filter http.request with NO -d at all',
    args: ['-Y', 'http.request and tcp.port == 4444', '-T', 'fields', '-e', 'http.request.uri'],
    guarantee: 'HTTP on TCP 4444 is dissected with no decode-as (the control case)',
    test: out => {
      const got = lines(out);
      return { ok: got.length === 1 && got[0] === '/admin/status', detail: got.join(',') || '(not dissected)' };
    },
    negative: { pcap: 'odd-port.pcap', args: ['-Y', 'http.request and tcp.port == 4343', '-T', 'fields', '-e', 'http.request.uri'], why: 'the WHOIS port carries no HTTP, so the control is not a blanket "http always fires"' }
  },
  {
    id: 'odd-tcp-conversations',
    pcap: 'odd-port.pcap',
    question: 'How many TCP conversations are in the file?',
    method: 'statistics: -q -z conv,tcp, count the conversation rows',
    args: ['-q', '-z', 'conv,tcp'],
    guarantee: 'three TCP conversations (4343, 1337, 4444)',
    test: out => {
      const rows = lines(out).filter(l => /<\s*->/.test(l));
      return { ok: rows.length === 3, detail: `${rows.length} conversation(s): ${rows.map(r => r.trim().split(/\s+/).slice(0, 3).join(' ')).join(' ; ')}` };
    },
    negative: { pcap: 'http-basic.pcap', why: 'http-basic.pcap has exactly one TCP conversation, not three' }
  },

  /* -------------------------------------------- the non-obvious record type */
  {
    id: 'dns-txt-record',
    pcap: 'dns-txt.pcap',
    question: 'A name carries a challenge value. Which record type holds it, and what is the value?',
    method: 'the answer is not an A record: filter dns.resp.type == 16 and read dns.txt (Wireshark splits a chunked TXT answer into several occurrences)',
    args: ['-Y', 'dns.resp.type == 16', '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.txt'],
    guarantee: 'the TXT answer for _lab-challenge.lab.test contains LAB{tx-ball-42e1b8c9} (preceded by a decoy TXT record)',
    test: out => {
      const ok = has(out, 'LAB{tx-ball-42e1b8c9}') && has(out, 'ignore-this-vendor-txt-record') && has(out, '_lab-challenge.lab.test');
      return { ok, detail: ok ? 'TXT answer set: decoy + LAB{tx-ball-42e1b8c9}' : 'challenge value not in the TXT answer' };
    },
    negative: { pcap: 'dns-basic.pcap', why: 'dns-basic.pcap has A/AAAA answers only — no TXT record to find' }
  },
  {
    id: 'dns-cname-chain',
    pcap: 'dns-txt.pcap',
    question: 'Follow the alias chain for www.lab.test to its address.',
    method: 'field extraction across record types: -e dns.cname -e dns.a on the same name',
    args: ['-Y', 'dns.cname or dns.a', '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.cname', '-e', 'dns.a'],
    guarantee: 'www.lab.test is a CNAME to edge.lab.test, which is A 203.0.113.99',
    test: out => {
      const ok = has(out, 'edge.lab.test') && has(out, '203.0.113.99');
      return { ok, detail: ok ? 'www.lab.test -> edge.lab.test -> 203.0.113.99' : 'alias chain incomplete' };
    },
    negative: { pcap: 'dns-basic.pcap', why: 'no CNAME exists in dns-basic.pcap' }
  }
];

export const questionById = id => QUESTIONS.find(q => q.id === id);
