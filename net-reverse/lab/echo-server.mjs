/* echo-server.mjs — a loopback recorder: the "server side" of the replay and
 * interception proofs (zero dependencies).
 *
 * It is deliberately a RAW TCP reader rather than a polished HTTP server, because
 * the claim it has to support is byte-level: "what the server received is exactly /
 * is not exactly what was captured". So it records the raw bytes of every request,
 * hashes them, parses just enough HTTP to know where the body ends, and answers
 * with a JSON body that echoes the fields it saw — including anything an
 * interceptor rewrote on the way in.
 *
 * Isolation: binds 127.0.0.1 only and refuses anything else. Loopback is the whole
 * authorised surface of this lab.
 *
 *   node lab/echo-server.mjs --port 8080
 */
import crypto from 'node:crypto';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

/** Split the first complete HTTP message out of a byte stream (headers + Content-Length body). */
export function splitFirstMessage(buf) {
  const end = buf.indexOf('\r\n\r\n');
  if (end < 0) return null;
  const head = buf.subarray(0, end).toString('latin1');
  const m = /content-length:\s*(\d+)/i.exec(head);
  const bodyLen = m ? parseInt(m[1], 10) : 0;
  const total = end + 4 + bodyLen;
  if (buf.length < total) return null;
  return { head, body: buf.subarray(end + 4, total), total };
}

/** Split every complete HTTP message out of a byte stream (headers + Content-Length body). */
export function splitMessages(buf) {
  const out = [];
  let offset = 0;
  while (offset < buf.length) {
    const rest = buf.subarray(offset);
    const message = splitFirstMessage(rest);
    if (!message) break;
    out.push(rest.subarray(0, message.total));
    offset += message.total;
  }
  return out;
}

function parseRequest(head, body) {
  const [requestLine, ...headerLines] = head.split('\r\n');
  const [method, url, version] = requestLine.split(' ');
  const headers = {};
  for (const line of headerLines) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return { method, url, version, headers, body: body.toString('utf8') };
}

/**
 * @returns {{server: net.Server, records: object[], port: () => number, close: () => Promise<void>}}
 */
export function createRecorder({ port = 0, host = '127.0.0.1', log = () => {}, name = 'echo-server' } = {}) {
  if (!LOOPBACK.has(host)) throw new Error(`echo-server refuses to bind ${host}: loopback only`);
  const records = [];

  const server = net.createServer(socket => {
    const chunks = [];
    socket.on('data', chunk => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      const message = splitFirstMessage(buf);
      if (!message) return;
      const raw = buf.subarray(0, message.total);
      const parsed = parseRequest(message.head, message.body);
      const record = {
        at: new Date().toISOString(),
        remote: `${socket.remoteAddress}:${socket.remotePort}`,
        bytes: raw.length,
        sha256: crypto.createHash('sha256').update(raw).digest('hex'),
        bodySha256: crypto.createHash('sha256').update(message.body).digest('hex'),
        ...parsed
      };
      records.push(record);
      const marker = parsed.headers['x-lab-marker'] ?? null;
      log(`[${name}] ${record.at} ${record.method} ${record.url} bytes=${record.bytes} sha256=${record.sha256.slice(0, 16)} x-lab-marker=${marker} body=${JSON.stringify(parsed.body.slice(0, 120))}`);

      const payload = JSON.stringify({
        ok: true,
        received: {
          method: parsed.method,
          url: parsed.url,
          marker: marker,
          body: parsed.body,
          host: parsed.headers.host ?? null,
          raw_sha256: record.sha256,
          body_sha256: record.bodySha256
        }
      }, null, 2);
      socket.end(
        'HTTP/1.1 200 OK\r\n' +
        'Server: net-reverse-recorder/1.0\r\n' +
        'Content-Type: application/json\r\n' +
        `Content-Length: ${Buffer.byteLength(payload)}\r\n` +
        'x-lab-server: net-reverse-recorder\r\n' +
        'Connection: close\r\n\r\n' + payload
      );
    });
    socket.on('error', () => {});
  });

  return {
    server,
    records,
    listen: () => new Promise(resolve => server.listen(port, host, () => resolve(server.address()))),
    port: () => server.address()?.port,
    close: () => new Promise(resolve => server.close(() => resolve()))
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const portIdx = process.argv.indexOf('--port');
  const port = portIdx > -1 ? parseInt(process.argv[portIdx + 1], 10) : 8080;
  const recorder = createRecorder({ port, log: m => console.log(m) });
  const addr = await recorder.listen();
  console.log(`net-reverse recorder listening on http://127.0.0.1:${addr.port} (loopback only)`);
  const shutdown = async () => { await recorder.close(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
