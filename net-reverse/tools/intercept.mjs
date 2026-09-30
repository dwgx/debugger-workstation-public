/* intercept.mjs — CLI-drivable traffic interception over CDP (zero new dependencies).
 *
 *   node tools/intercept.mjs [--json] [--headful]
 *
 * Reqable is a GUI; the station's contract wants a path an agent can drive and a
 * proof a later window can re-run. This is that path: Chrome DevTools Protocol's
 * Fetch domain, driven from the existing `web-reverse/tools/cdp.mjs` client, against
 * a loopback recorder we also own. No proxy, no certificate, no trust store.
 *
 * Two rewrites are exercised, and both are observed from the server side:
 *
 *   1. REQUEST  — `Fetch.requestPaused` at `requestStage: Request` captures an
 *                 outgoing POST, replaces a header and the body, then
 *                 `Fetch.continueRequest` releases it. The loopback recorder sees
 *                 the modified values, and the page receives the server's echo.
 *   2. RESPONSE — `Fetch.requestPaused` at `requestStage: Response` + `Fetch.fulfillRequest`
 *                 replaces a response the server DID send with a body the server never
 *                 wrote. The page reads the fabricated body while the server log shows
 *                 its own, different response.
 *
 * Isolation: the target is 127.0.0.1 only, the browser is a disposable %TEMP% profile
 * launched with `--host-resolver-rules`, and no certificate is installed anywhere.
 */
import { CDP } from '../../web-reverse/tools/cdp.mjs';
import { launchChrome } from '../../web-reverse/tools/chrome.mjs';
import { createRecorder } from '../lab/echo-server.mjs';

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const HEADFUL = args.includes('--headful');
const started = Date.now();
const used = [];
const steps = [];
const record = (label, pass, detail) => steps.push({ label, pass, detail });

const rewrites = { request: null, response: null };
const serverLines = [];

async function main() {
  /* ---- the target: a loopback recorder that reports exactly what it received ---- */
  const recorder = createRecorder({ log: m => serverLines.push(m) });
  const addr = await recorder.listen();
  const origin = `http://127.0.0.1:${addr.port}`;

  const chrome = await launchChrome({
    headless: !HEADFUL,
    tag: 'net-interceptor',
    url: 'about:blank',
    extraArgs: ['--disable-features=Translate']
  });

  let cdp;
  try {
    cdp = await CDP.connect(chrome.wsUrl);
    const send = (method, params, sessionId) => { used.push(`${method}${params && Object.keys(params).length ? ' ' + JSON.stringify(params).slice(0, 96) : ''}`); return cdp.send(method, params, sessionId); };

    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });

    await send('Page.enable', {}, sessionId);
    await send('Runtime.enable', {}, sessionId);
    await send('Network.enable', {}, sessionId);

    /* Two patterns, two stages: one rewrites what leaves the renderer, the other
       rewrites what comes back to it. */
    await send('Fetch.enable', {
      patterns: [
        { urlPattern: '*api/intercept*', requestStage: 'Request' },
        { urlPattern: '*api/fulfill*', requestStage: 'Response' }
      ]
    }, sessionId);

    const pending = [];
    const handlerErrors = [];
    /* A rejected CDP call must surface as a FAIL row, not as an unhandled rejection
       that kills the run before the table is printed. */
    const dispatch = promise => pending.push(promise.catch(e => { handlerErrors.push(e.message); return null; }));
    cdp.on(msg => {
      if (msg.method !== 'Fetch.requestPaused' || msg.sessionId !== sessionId) return;
      const p = msg.params;
      const atResponse = p.responseStatusCode !== undefined;
      if (atResponse && p.request.url.includes('/api/fulfill')) {
        /* ---- RESPONSE rewrite: fabricate a body the origin never sent ---- */
        const body = Buffer.from(JSON.stringify({
          fulfilled: true,
          by: 'cdp-fetch-fulfillRequest',
          server_never_wrote_this: true,
          origin_status: p.responseStatusCode
        })).toString('base64');
        rewrites.response = {
          url: p.request.url,
          originStatus: p.responseStatusCode,
          originServerHeader: (p.responseHeaders || []).find(h => h.name.toLowerCase() === 'server')?.value ?? null,
          fabricated: 'server_never_wrote_this'
        };
        dispatch(send('Fetch.fulfillRequest', {
          requestId: p.requestId,
          responseCode: 200,
          responsePhrase: 'OK (rewritten by CDP)',
          responseHeaders: [
            { name: 'Content-Type', value: 'application/json' },
            { name: 'x-lab-proxy', value: 'cdp-fulfill' },
            { name: 'Content-Length', value: String(Buffer.from(body, 'base64').length) }
          ],
          body
        }, sessionId));
        return;
      }
      if (p.request.url.includes('/api/intercept')) {
        /* ---- REQUEST rewrite: change a header and the body in flight ---- */
        const originalMarker = Object.entries(p.request.headers).find(([k]) => k.toLowerCase() === 'x-lab-marker')?.[1] ?? null;
        const headers = Object.entries(p.request.headers)
          .filter(([k]) => k.toLowerCase() !== 'x-lab-marker' && k.toLowerCase() !== 'content-length')
          .map(([name, value]) => ({ name, value }));
        headers.push({ name: 'x-lab-marker', value: 'rewritten-by-cdp' });
        const newBody = JSON.stringify({ from: 'page', marker: 'rewritten-by-cdp', rewritten: true });
        headers.push({ name: 'content-length', value: String(Buffer.byteLength(newBody)) });
        rewrites.request = {
          url: p.request.url,
          originalMarker,
          originalBody: p.request.postData ?? null,
          newMarker: 'rewritten-by-cdp',
          newBody
        };
        /* Fetch-domain postData is a BINARY parameter: base64 over JSON. Sending the
           raw string is rejected with "Invalid parameters" (measured). */
        dispatch(send('Fetch.continueRequest', {
          requestId: p.requestId,
          headers,
          postDataEntries: [{ bytes: Buffer.from(newBody).toString('base64') }]
        }, sessionId));
      }
    });

    /* ---- drive it: one page, two fetches, both same-origin to the recorder ---- */
    send('Page.navigate', { url: `${origin}/lab-page` }, sessionId);
    await cdp.waitFor('Page.loadEventFired', { sessionId, timeoutMs: 20_000 });

    const pageResult = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const out = {};
        const r1 = await fetch('/api/intercept', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-lab-marker': 'original-from-page' },
          body: JSON.stringify({ from: 'page', marker: 'original-from-page' })
        });
        out.intercept = await r1.json();
        const r2 = await fetch('/api/fulfill');
        out.fulfill = await r2.json();
        out.fulfillHeader = r2.headers.get('x-lab-proxy');
        out.status = r2.statusText;
        return out;
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    if (pageResult.exceptionDetails) throw new Error('page exception: ' + JSON.stringify(pageResult.exceptionDetails));
    const page = pageResult.result.value;
    await Promise.all(pending);
    if (handlerErrors.length) record('CDP rewrite calls all succeeded', false, handlerErrors.join(' | '));

    /* ---- evidence: what the SERVER recorded, independent of the page ---- */
    const [interceptRecord, fulfillRecord] = recorder.records;
    const serverSawMarker = interceptRecord?.headers['x-lab-marker'] ?? null;
    const serverSawBody = interceptRecord?.body ?? '';
    const serverFulfillBody = fulfillRecord?.body ?? '';

    if (!JSON_OUT) {
      console.log('net-reverse interception — CDP Fetch domain against a loopback origin');
      console.log(`  target     ${origin} (in-process recorder, loopback only)`);
      console.log(`  browser    ${chrome.browserPath}`);
      console.log(`             disposable profile ${chrome.profileDir}`);
      console.log(`  server log:`);
      for (const l of serverLines) console.log(`    ${l}`);
      console.log(`\n  [1] request rewrite`);
      console.log(`      page sent     x-lab-marker: ${rewrites.request?.originalMarker}`);
      console.log(`                    body ${JSON.stringify(rewrites.request?.originalBody)}`);
      console.log(`      CDP rewrote   x-lab-marker: ${rewrites.request?.newMarker}`);
      console.log(`                    body ${JSON.stringify(rewrites.request?.newBody)}`);
      console.log(`      SERVER SAW    x-lab-marker: ${serverSawMarker}`);
      console.log(`                    body ${JSON.stringify(serverSawBody)}`);
      console.log(`      page got back ${JSON.stringify(page.intercept?.received)}`);
      console.log(`\n  [2] response rewrite (fulfillRequest)`);
      console.log(`      origin sent   200 with Server: ${rewrites.response?.originServerHeader} — body ${JSON.stringify(serverFulfillBody.slice(0, 60))}`);
      console.log(`      CDP replaced  status ${page.status} ${page.fulfillHeader ? `(x-lab-proxy: ${page.fulfillHeader})` : ''}`);
      console.log(`      page read     ${JSON.stringify(page.fulfill)}`);
    }

    record('recorder captured the outbound POST',
      Boolean(interceptRecord), interceptRecord ? `${interceptRecord.method} ${interceptRecord.url} ${interceptRecord.bytes} bytes sha256:${interceptRecord.sha256.slice(0, 12)}` : 'no request reached the recorder');
    record('request header rewritten in flight (server-side proof)',
      serverSawMarker === 'rewritten-by-cdp', `server saw x-lab-marker: ${serverSawMarker} (page sent original-from-page)`);
    record('request body rewritten in flight (server-side proof)',
      serverSawBody.includes('"rewritten":true') && serverSawBody.includes('rewritten-by-cdp'), `server decoded body ${JSON.stringify(serverSawBody.slice(0, 80))}`);
    record('page received the server echo of the rewritten request',
      page.intercept?.received?.marker === 'rewritten-by-cdp', `fetch result received.marker = ${page.intercept?.received?.marker}`);
    record('origin response was served, then replaced (fulfillRequest)',
      Boolean(fulfillRecord) && (rewrites.response?.originStatus ?? 0) > 0, `origin answered ${rewrites.response?.originStatus}; recorder body ${JSON.stringify(serverFulfillBody.slice(0, 40))}`);
    record('page read the fabricated response, not the origin body',
      page.fulfill?.server_never_wrote_this === true && !serverFulfillBody.includes('server_never_wrote_this'), `page saw fulfilled=${page.fulfill?.fulfilled} by=${page.fulfill?.by}; x-lab-proxy header ${page.fulfillHeader}`);
    record('no certificate or proxy involved', true, 'plain HTTP over 127.0.0.1; Fetch domain only');

    if (JSON_OUT) {
      console.log(JSON.stringify({
        ok: steps.every(s => s.pass),
        target: origin,
        cdpCommands: used,
        requestRewrite: { ...rewrites.request, serverSawMarker, serverSawBody },
        responseRewrite: { ...rewrites.response, serverBody: serverFulfillBody, pageSaw: page.fulfill, pageHeader: page.fulfillHeader },
        pageEcho: page.intercept?.received ?? null,
        serverLog: serverLines,
        steps,
        ms: Date.now() - started
      }, null, 2));
    } else {
      console.log(`\n  CDP calls used: ${used.length}`);
      for (const u of used) console.log(`    ${u}`);
      console.log(`\n  summary (${((Date.now() - started) / 1000).toFixed(1)}s)`);
      for (const s of steps) console.log(`    ${s.pass ? 'PASS' : 'FAIL'}  ${s.label.padEnd(58)} ${s.detail}`);
      console.log(`\n${steps.every(s => s.pass) ? 'INTERCEPTION PROVED: a request and a response were rewritten in flight, on loopback, with no proxy and no certificate.' : 'interception incomplete — see the FAIL rows'}`);
    }
  } finally {
    try { cdp?.close(); } catch { /* already gone */ }
    await chrome.close();
    await recorder.close();
  }

  process.exit(steps.every(s => s.pass) ? 0 : 6);
}

main().catch(err => { console.error(`intercept failed: ${err.message}`); process.exit(1); });
