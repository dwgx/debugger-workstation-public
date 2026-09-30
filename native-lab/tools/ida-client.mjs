// native-lab/tools/ida-client.mjs — one MCP client for the whole native lab.
//
// Every tool in this lab talks to the same server the same way, and the ways are
// easy to get wrong in ways that fail silently:
//
//   * MCP is POST /mcp. A GET returns 405, which is the protocol, not a fault.
//   * Responses arrive as SSE frames, so the JSON is inside a `data:` line.
//   * Every tool call needs database=<session_id>; without it the server answers
//     with a well-formed error about a missing parameter, which reads like the
//     tool is broken rather than the call being incomplete.
//   * IDA does not list a session until its initial analysis finishes. Asking early
//     returns an empty list, indistinguishable from a failure to open.
//   * A FAILED analysis comes back with isError:false, code:null and an error
//     string. Trusting isError alone records the failure as a success.
//
// That last one is why `ok()` exists and why callers are expected to use it.

import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

export const IDALIB = 'D:/Software/Developer/Python314/Scripts/idalib-mcp.exe';
export const HOST = '127.0.0.1';
export const PORT = 8745;
export const MCP = `http://${HOST}:${PORT}/mcp`;

const HDRS = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };

let rpcId = 0;
async function raw(method, params) {
  rpcId += 1;
  const r = await fetch(MCP, {
    method: 'POST', headers: HDRS, signal: AbortSignal.timeout(180_000),
    body: JSON.stringify({ jsonrpc: '2.0', id: rpcId, method, params: params || {} }),
  });
  const text = await r.text();
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (t.startsWith('data:')) return JSON.parse(t.slice(5).trim());
  }
  return JSON.parse(text);
}

export async function portFree() {
  try {
    const r = await fetch(MCP, { method: 'POST', headers: HDRS,
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} }),
      signal: AbortSignal.timeout(4000) });
    return !r.ok;
  } catch { return true; }
}

export async function waitForPort(proc, budgetMs = 120_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < budgetMs) {
    if (proc.exitCode !== null) return false;
    try {
      const r = await fetch(MCP, { method: 'POST', headers: HDRS,
        body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} }),
        signal: AbortSignal.timeout(5000) });
      if (r.ok) return true;
    } catch { /* not listening yet */ }
    await sleep(1000);
  }
  return false;
}

export async function handshake() {
  await raw('initialize', { protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'native-lab', version: '1' } });
  await fetch(MCP, { method: 'POST', headers: HDRS,
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) }).catch(() => {});
}

export async function toolNames() {
  const t = await raw('tools/list');
  return (t?.result?.tools || []).map((x) => x.name);
}

/** Call a tool. Returns { isError, body } — isError is kept separate on purpose,
 *  because on this server it is NOT the failure signal for an analysis. */
export async function call(tool, args) {
  const res = await raw('tools/call', { name: tool, arguments: args });
  const text = (res?.result?.content || []).map((c) => c.text || '').join('');
  let body;
  try { body = JSON.parse(text); } catch { body = { _raw: text }; }
  return { isError: res?.result?.isError === true, body };
}

/** The honest success test for an analysis result: no error AND non-null payload.
 *  isError alone is not enough — see the header. */
export function ok(res) {
  return !res.isError && body_(res);
}
function body_(res) {
  const b = res?.body;
  if (!b || typeof b !== 'object') return false;
  if (typeof b.error === 'string' && b.error) return false;
  return true;
}

export async function waitForSession(budgetMs = 420_000) {
  const t0 = Date.now();
  let seen = 'no response';
  while (Date.now() - t0 < budgetMs) {
    const r = await call('idb_list', {}).catch((e) => ({ body: { err: e.message } }));
    const s = (r?.body?.sessions || [])[0];
    if (s) {
      if (!s.is_analyzing && !s.busy) return s;
      seen = `session ${s.session_id} still ${s.is_analyzing ? 'analyzing' : 'busy'}`;
    } else {
      seen = `no session yet (count=${r?.body?.count ?? '?'})`;
    }
    await sleep(2500);
  }
  throw new Error(`session never became ready: ${seen}`);
}

export async function withServer(target, fn) {
  if (!(await portFree())) {
    throw new Error(
      `something is already serving ${MCP}. Refusing to inherit another run's server — ` +
      `taskkill /PID <pid> /T /F it, then re-run.`);
  }
  const proc = spawn(IDALIB, ['--host', HOST, '--port', String(PORT), target],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d.toString(); });
  proc.stdout.on('data', () => {});
  try {
    if (!(await waitForPort(proc))) throw new Error(`no port; stderr: ${stderr.slice(-300)}`);
    await handshake();
    return await fn();
  } finally {
    // proc.kill() trips a libuv assertion on Windows; taskkill /T is quieter and
    // also takes the spawned idalib worker, which otherwise keeps holding the port.
    try { execFileSync('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore' }); } catch { /* gone */ }
  }
}

export function flattenFuncs(body) {
  const flat = Array.isArray(body) ? body : body?.data || body?.result || [];
  return flat.flatMap((g) => (Array.isArray(g) ? g : g?.data || []));
}
