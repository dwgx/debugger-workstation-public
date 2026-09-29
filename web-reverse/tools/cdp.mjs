/* cdp.mjs — minimal Chrome DevTools Protocol client (zero dependencies).
 *
 * Why hand-rolled: Node 24 ships a global `WebSocket` (verified on this box:
 * `node -e "typeof WebSocket"` -> function), so raw CDP needs no npm package at
 * all. The station keeps third-party code out of git; this is ~90 lines instead.
 *
 * Scope: JSON-RPC over one browser websocket with flat session ids
 * (`Target.attachToTarget {flatten:true}`), plus event waiting. That is the whole
 * surface this lab needs: Page, Runtime, Network, Target.
 */
export class CDP {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    ws.addEventListener('message', ev => this.#onMessage(ev.data));
    ws.addEventListener('close', () => {
      for (const { reject } of this.pending.values()) reject(new Error('CDP socket closed'));
      this.pending.clear();
    });
  }

  static connect(wsUrl, { timeoutMs = 10_000 } = {}) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      const timer = setTimeout(() => reject(new Error(`timeout connecting to ${wsUrl}`)), timeoutMs);
      ws.addEventListener('open', () => { clearTimeout(timer); resolve(new CDP(ws)); }, { once: true });
      ws.addEventListener('error', () => { clearTimeout(timer); reject(new Error(`websocket error: ${wsUrl}`)); }, { once: true });
    });
  }

  #onMessage(raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (msg.id !== undefined) {
      const slot = this.pending.get(msg.id);
      if (!slot) return;
      this.pending.delete(msg.id);
      if (msg.error) slot.reject(new Error(`${slot.method}: ${msg.error.message}`));
      else slot.resolve(msg.result);
      return;
    }
    for (const fn of [...this.listeners]) fn(msg);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.ws.send(JSON.stringify(payload));
    });
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

  /** Resolve with the first event matching `method` (+ optional predicate). */
  waitFor(method, { sessionId, predicate, timeoutMs = 15_000 } = {}) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { off(); reject(new Error(`timeout waiting for ${method}`)); }, timeoutMs);
      const off = this.on(msg => {
        if (msg.method !== method) return;
        if (sessionId && msg.sessionId !== sessionId) return;
        if (predicate && !predicate(msg.params)) return;
        clearTimeout(timer);
        off();
        resolve(msg.params);
      });
    });
  }

  close() { try { this.ws.close(); } catch { /* already gone */ } }
}

/** Collect events without blocking; returns {events, stop}. */
export function record(cdp, method, { sessionId } = {}) {
  const events = [];
  const off = cdp.on(msg => {
    if (msg.method !== method) return;
    if (sessionId && msg.sessionId !== sessionId) return;
    events.push(msg.params);
  });
  return { events, stop: off };
}

export async function evalInPage(cdp, sessionId, expression, { awaitPromise = false } = {}) {
  const res = await cdp.send('Runtime.evaluate', {
    expression, awaitPromise, returnByValue: true
  }, sessionId);
  if (res.exceptionDetails) {
    throw new Error(`page exception: ${res.exceptionDetails.exception?.description || res.exceptionDetails.text}`);
  }
  return res.result?.value;
}
