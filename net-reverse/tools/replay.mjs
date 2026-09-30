/* replay.mjs — re-inject a captured request into a loopback listener (zero deps).
 *
 *   node tools/replay.mjs --pcap http-basic.pcap [--stream 0] [--messages first|all] [--json]
 *
 * Why not tcpreplay: tcpreplay writes frames to a NIC, needs a capture driver and
 * Npcap-admin, and cannot target a loopback endpoint. The claim this lane has to
 * prove is narrower and stronger — "the bytes in the capture arrive at a listener
 * we control, unchanged" — so the replayer extracts the client payload with tshark
 * (the same field-extraction method the analysis questions use), sends it to
 * 127.0.0.1, and compares hashes.
 *
 * The verdict is hash equality between what the capture holds and what the listener
 * recorded. Mismatch exits 5. Non-loopback destinations are refused outright.
 */
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { runTshark, lines, hexFieldToText } from '../lab/tshark.mjs';
import { createRecorder, splitMessages } from '../lab/echo-server.mjs';
import { defaultOutDir, generate } from '../lab/gen-pcaps.mjs';
import fs from 'node:fs';

const args = process.argv.slice(2);
const flag = name => { const i = args.indexOf(`--${name}`); return i > -1 ? args[i + 1] : undefined; };
const JSON_OUT = args.includes('--json');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

function corpusDir() {
  const dir = flag('dir') || defaultOutDir();
  if (!fs.existsSync(path.join(dir, 'corpus.json'))) generate(dir);
  return dir;
}

/* ---------------------------------------------------------------- extraction */

/** The client-to-server byte stream of one TCP conversation, straight from tshark. */
function extractStream(pcap, stream) {
  const res = runTshark([
    '-r', pcap, '-Y', `tcp.stream == ${stream} and tcp.len > 0`, '-T', 'fields',
    '-e', 'ip.src', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'tcp.payload', '-e', 'frame.number'
  ]);
  const rows = lines(res.stdout).map(l => l.split('\t'));
  if (rows.length === 0) return null;
  const [clientIp, clientPort, serverPort] = rows[0];
  const fromClient = rows.filter(r => r[0] === clientIp && r[1] === clientPort);
  const payload = Buffer.concat(fromClient.map(r => Buffer.from(r[3].replace(/[^0-9a-fA-F]/g, ''), 'hex')));
  return { clientIp, clientPort, serverPort, frames: fromClient.map(r => r[4]), payload, command: res.display };
}

function firstTcpStream(pcap) {
  const res = runTshark(['-r', pcap, '-Y', 'tcp.len > 0', '-T', 'fields', '-e', 'tcp.stream']);
  const found = lines(res.stdout)[0];
  return found === undefined ? null : parseInt(found, 10);
}

/* -------------------------------------------------------------------- replay */

/** Send bytes to a loopback listener and collect its answer. */
function exchange(host, port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port }, () => socket.write(payload, () => socket.end()));
    const chunks = [];
    socket.on('data', d => chunks.push(d));
    socket.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', reject);
    socket.setTimeout(10_000, () => { socket.destroy(); reject(new Error('replay timed out')); });
  });
}

async function main() {
  const dir = corpusDir();
  const pcapArg = flag('pcap');
  if (!pcapArg) { console.error('usage: node tools/replay.mjs --pcap <name.pcap> [--stream N] [--messages first|all] [--json]'); process.exit(1); }
  const pcap = path.isAbsolute(pcapArg) ? pcapArg : path.join(dir, pcapArg.endsWith('.pcap') ? pcapArg : `${pcapArg}.pcap`);
  if (!fs.existsSync(pcap)) { console.error(`no such capture: ${pcap}`); process.exit(1); }

  const stream = flag('stream') !== undefined ? parseInt(flag('stream'), 10) : firstTcpStream(pcap);
  if (stream === null || stream === undefined || Number.isNaN(stream)) { console.error('no TCP stream with payload in this capture'); process.exit(1); }

  const extracted = extractStream(pcap, stream);
  if (!extracted || extracted.payload.length === 0) { console.error(`stream ${stream} carries no client payload`); process.exit(1); }

  const messages = flag('messages') || 'first';
  const all = messages === 'all';
  const nth = flag('message') !== undefined ? parseInt(flag('message'), 10) : 1;

  const complete = splitMessages(extracted.payload);
  const raw = args.includes('--raw');
  const selected = raw ? [extracted.payload] : (all ? complete : [complete[nth - 1]].filter(Boolean));
  if (!raw && complete.length === 0) {
    console.error('this stream does not begin with a complete HTTP message; use --raw to re-inject the whole client stream');
    process.exit(1);
  }
  if (selected.length === 0) { console.error(`stream ${stream} has ${complete.length} message(s); --message ${nth} is out of range`); process.exit(1); }

  const host = flag('host') || '127.0.0.1';
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    console.error(`refusing to replay to ${host}: this lab replays to loopback only`);
    process.exit(2);
  }

  /* A recorder in this process unless the caller names an already-running one. */
  const useExternal = flag('port') !== undefined;
  const targetPort = useExternal ? parseInt(flag('port'), 10) : 0;
  const perMessage = [];

  for (const payload of selected) {
    const sentSha = sha(payload);
    const recorder = useExternal ? null : createRecorder({ log: () => {} });
    const addr = recorder ? await recorder.listen() : { port: targetPort };
    const response = await exchange(host, addr.port, payload);
    const record = recorder ? recorder.records[0] : null;
    if (recorder) await recorder.close();
    const requestLine = payload.subarray(0, payload.indexOf('\r\n')).toString('latin1');
    perMessage.push({
      requestLine,
      bytes: payload.length,
      capturedSha256: sentSha,
      serverObserved: record ? { bytes: record.bytes, sha256: record.sha256, method: record.method, url: record.url, remote: record.remote, marker: record.headers['x-lab-marker'] ?? null } : null,
      credentialInPayload: /password=([^&\s]+)/.exec(payload.toString('latin1'))?.[1] ?? null,
      byteIdentical: record ? record.sha256 === sentSha : null,
      responseHead: response.split('\r\n\r\n')[0].split('\r\n').slice(0, 4).join(' | '),
      target: `http://${host}:${addr.port}`
    });
  }

  const mismatched = perMessage.filter(m => m.byteIdentical === false);
  const out = {
    ok: mismatched.length === 0,
    pcap: path.basename(pcap),
    stream,
    frames: extracted.frames,
    conversation: `${extracted.clientIp}:${extracted.clientPort} -> ${extracted.serverPort}`,
    selection: all ? 'all messages' : `message ${nth} of ${complete.length}`,
    extractionCommand: extracted.command,
    messages: perMessage
  };

  if (JSON_OUT) {
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log(`replay — captured request re-injected into a loopback listener`);
    console.log(`  capture    ${pcap}`);
    console.log(`  extract    $ ${extracted.command}`);
    console.log(`  captured   TCP stream ${stream}, frames ${extracted.frames.join(',')} (${out.conversation}), ${extracted.payload.length} bytes, ${complete.length} complete message(s)`);
    console.log(`  selection  ${out.selection}`);
    for (const [i, m] of perMessage.entries()) {
      console.log(`\n  [${i + 1}] ${m.requestLine}`);
      console.log(`      captured ${m.bytes} bytes, sha256:${m.capturedSha256.slice(0, 32)}`);
      if (m.credentialInPayload) console.log(`      carries the captured credential: password=${m.credentialInPayload}`);
      console.log(`      replayed -> ${m.target}`);
      if (m.serverObserved) {
        console.log(`      server   ${m.serverObserved.method} ${m.serverObserved.url} from ${m.serverObserved.remote}`);
        console.log(`               ${m.serverObserved.bytes} bytes received, sha256:${m.serverObserved.sha256.slice(0, 32)}`);
        console.log(`      verdict  ${m.byteIdentical ? 'IDENTICAL — every captured byte arrived at the listener' : 'MISMATCH — the replayed bytes differ from the capture'}`);
      } else {
        console.log(`      server   (external listener on port ${targetPort}: compare with its own log)`);
      }
      console.log(`      response ${m.responseHead}`);
    }
  }
  process.exit(mismatched.length ? 5 : 0);
}

main().catch(err => { console.error(`replay failed: ${err.message}`); process.exit(1); });
