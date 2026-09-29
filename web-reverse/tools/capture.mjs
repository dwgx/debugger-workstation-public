/* capture.mjs — drive a lab page in a disposable Chrome and capture the signed request.
 *
 * The technique is the general one, not a lab affordance: the page is left entirely
 * alone, and observation happens from the outside through CDP.
 *
 *   Network.enable + Network.requestWillBeSent  -> URL, method, headers, body
 *   Runtime.addBinding('__labTap') + an XHR tap injected with
 *       Page.addScriptToEvaluateOnNewDocument  -> headers/body as the page saw them
 *   Runtime.evaluate                            -> trigger the page's own submit path
 *
 * Usage:
 *   node tools/capture.mjs --url http://127.0.0.1:8787/plain --out capture-plain.json
 *   node tools/capture.mjs --url http://127.0.0.1:8787/obf   --clicks 2 --headed
 *   node tools/capture.mjs --url ... --cdp-http http://127.0.0.1:9222
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CDP } from './cdp.mjs';
import { launchChrome, browserWsFromHttp } from './chrome.mjs';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const targetUrl = get('--url', 'http://127.0.0.1:8787/plain');
const clicks = Number(get('--clicks', 1));
const headed = has('--headed');
const keepOpen = has('--keep-open');
const dumpHeaders = has('--dump-headers');
const cdpHttp = get('--cdp-http', null);
const label = (get('--label', null) || targetUrl.replace(/^https?:\/\/[^/]+/, '').replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'page') + (has('--obf') ? '-obf' : '');
const outPath = get('--out', path.join(os.tmpdir(), 'web-reverse-captures', `${label}.json`));

/* Injected before any page script runs: record what the page hands to fetch()/XHR.
   Reports through the CDP runtime binding so the shape is identical to what an
   analyst sees with a Debugger breakpoint, without needing one. */
const TAP_SOURCE = `
(() => {
  if (window.__labTapInstalled) return;
  window.__labTapInstalled = true;
  const O = XMLHttpRequest.prototype.open,
        S = XMLHttpRequest.prototype.setRequestHeader,
        D = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) {
    this.__lab = { method: String(m), url: String(u), headers: {} };
    return O.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
    try { if (this.__lab) this.__lab.headers[String(n).toLowerCase()] = String(v); } catch (e) {}
    return S.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    try {
      if (this.__lab) {
        this.__lab.body = (body === undefined || body === null) ? null : String(body);
        if (typeof __labTap === 'function') __labTap(JSON.stringify(this.__lab));
      }
    } catch (e) {}
    return D.apply(this, arguments);
  };
})();`;

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitUntil(pred, timeoutMs, what) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await sleep(50);
  }
  throw new Error(`timeout after ${timeoutMs}ms waiting for ${what}`);
}

const cdpCalls = [];
let chrome = null;
let browser = null;

try {
  if (cdpHttp) {
    browser = await CDP.connect(await browserWsFromHttp(cdpHttp));
  } else {
    chrome = await launchChrome({ headless: !headed, tag: 'capture', url: 'about:blank' });
    browser = await CDP.connect(chrome.wsUrl);
  }
  const rawSend = browser.send.bind(browser);
  browser.send = (method, params = {}, sessionId) => { cdpCalls.push(method); return rawSend(method, params, sessionId); };

  const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });

  await browser.send('Page.enable', {}, sessionId);
  await browser.send('Network.enable', {}, sessionId);
  await browser.send('Runtime.enable', {}, sessionId);
  await browser.send('Runtime.addBinding', { name: '__labTap' }, sessionId);
  await browser.send('Page.addScriptToEvaluateOnNewDocument', { source: TAP_SOURCE }, sessionId);

  const submits = [];
  const taps = [];
  const consoleLines = [];
  browser.on(msg => {
    if (msg.sessionId !== sessionId) return;
    if (msg.method === 'Network.requestWillBeSent') {
      const r = msg.params.request;
      if (!/\/api\//.test(new URL(r.url, 'http://x').pathname)) return;
      submits.push({
        requestId: msg.params.requestId,
        method: r.method,
        url: r.url,
        headers: r.headers,
        body: r.postData ?? null,
        status: null,
        responseBody: null,
        tap: null
      });
    } else if (msg.method === 'Network.responseReceived') {
      const rec = submits.find(s => s.requestId === msg.params.requestId);
      if (rec) rec.status = msg.params.response.status;
    } else if (msg.method === 'Runtime.bindingCalled' && msg.params.name === '__labTap') {
      let payload = null;
      try { payload = JSON.parse(msg.params.payload); } catch { payload = { raw: msg.params.payload }; }
      taps.push(payload);
      const h = payload.headers || {};
      const match = submits.find(s => !s.tap &&
        (h['x-lab-sign'] ? s.headers['x-lab-sign'] === h['x-lab-sign'] : s.body === payload.body));
      if (match) match.tap = payload;
    } else if (msg.method === 'Runtime.consoleAPICalled') {
      consoleLines.push({ type: msg.params.type, text: (msg.params.args || []).map(a => a.value ?? a.description ?? '').join(' ') });
    }
  });

  const loaded = browser.waitFor('Page.loadEventFired', { sessionId, timeoutMs: 15_000 });
  await browser.send('Page.navigate', { url: targetUrl }, sessionId);
  await loaded;

  for (let i = 0; i < clicks; i++) {
    await browser.send('Runtime.evaluate', {
      expression: `document.getElementById('go').click()`,
      awaitPromise: false
    }, sessionId);
    await waitUntil(() => submits.filter(s => s.status !== null).length >= i + 1, 10_000,
      `response #${i + 1} for ${targetUrl}`);
  }

  for (const rec of submits) {
    if (rec.requestId && rec.status !== null) {
      try {
        const bodyRes = await browser.send('Network.getResponseBody', { requestId: rec.requestId }, sessionId);
        rec.responseBody = bodyRes.base64Encoded ? Buffer.from(bodyRes.body, 'base64').toString('utf8') : bodyRes.body;
      } catch { /* body may already be evicted; the status still stands */ }
    }
  }

  const capture = {
    capturedAt: new Date().toISOString(),
    targetUrl,
    label,
    browser: chrome ? { path: chrome.browserPath, headless: !headed, profile: chrome.profileDir } : { attached: cdpHttp },
    cdpCalls: [...new Set(cdpCalls)],
    requests: submits.map(({ requestId, ...rest }) => rest),
    taps,
    console: consoleLines
  };
  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(capture, null, 2));

  console.log(`capture: ${submits.length} /api request(s) from ${targetUrl}`);
  for (const r of submits) {
    const sign = (r.headers['x-lab-sign'] || (r.tap && r.tap.headers && r.tap.headers['x-lab-sign']) || '');
    console.log(`  ${r.method} ${r.url} -> HTTP ${r.status}`);
    console.log(`    x-lab-ts   ${r.headers['x-lab-ts'] ?? '-'}`);
    console.log(`    x-lab-sign ${sign}`);
    console.log(`    body       ${r.body ?? '-'}`);
    if (r.tap) console.log(`    tap        ${Object.keys(r.tap.headers).join(', ')}`);
    if (dumpHeaders) for (const [k, v] of Object.entries(r.headers)) console.log(`      ${k}: ${v}`);
  }
  console.log(`written ${path.resolve(outPath)}`);
  console.log(`CDP calls: ${capture.cdpCalls.join(', ')}`);

  const ok = submits.length === clicks && submits.every(s => s.status === 200);
  if (!ok) {
    console.error(`NOT all captures were accepted (expected ${clicks} x HTTP 200)`);
    process.exitCode = 3;
  }
} finally {
  if (browser && !keepOpen) {
    try { browser.close(); } catch { /* ignore */ }
  }
  if (chrome) {
    if (keepOpen) console.log(`browser kept open: ${chrome.httpBase} (profile ${chrome.profileDir})`);
    else await chrome.close();
  }
  if (!keepOpen) setTimeout(() => process.exit(process.exitCode ?? 0), 300);
}
