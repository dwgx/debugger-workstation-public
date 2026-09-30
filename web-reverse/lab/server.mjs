/* server.mjs — web-reverse lab target (self-authored, zero dependencies).
 *
 * Local-only lab server. Loopback bind, no outbound reach, nothing leaves the machine.
 * It serves a page that signs each request in JavaScript and VALIDATES that signature
 * server-side, so the capture -> recover -> replay loop has a real accept/reject gate.
 *
 * Signature scheme (the thing an analyst has to reverse):
 *     x-lab-ts   : epoch milliseconds, string
 *     x-lab-sign : hex( HMAC-SHA256( LAB_KEY, "<ts>.<raw-body>" ) )
 *
 * Validation is not decorative: wrong signature -> 401, stale timestamp -> 401,
 * exact reuse of a seen signature inside the window -> 409. Copying a captured
 * request is therefore worthless; only a recovered algorithm+key reproduces it.
 *
 * LAB_KEY below is a public lab constant, not a credential. Stop line: no real
 * secrets in git, ever.
 *
 *   node server.mjs [--port 8787] [--host 127.0.0.1]
 */
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const LabCrypto = require('./pages/sha256-pure.js');

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const LAB_KEY = 'lab-demo-signing-key-9f2c1a7e-not-a-real-secret-v1';
export const SIGN_WINDOW_MS = 300_000;

export function keyId(key = LAB_KEY) {
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}

export function signBody(body, ts, key = LAB_KEY) {
  return LabCrypto.hmacSha256Hex(key, `${ts}.${body}`);
}

function timingSafeEqHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'hex'), bb = Buffer.from(b, 'hex');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/* ---------------------------------------------------------------- fingerprinting
 * A miniature "looks like a bot?" checker of the kind real sites run. It is a
 * DETECTOR: it scores the client and explains itself. Nothing here spoofs or
 * evades anything, and the tooling that drives it reports the verdict rather
 * than defeating it. Header-side signals are scored here; the page posts the
 * client-side ones, and the two halves are merged.
 */
const HEADER_SIGNALS = [
  { id: 'ua-headless', cost: 35, why: 'User-Agent advertises HeadlessChrome', test: v => /HeadlessChrome/i.test(v.ua) },
  { id: 'ua-empty', cost: 30, why: 'no User-Agent header at all', test: v => !v.ua },
  { id: 'no-accept-language', cost: 10, why: 'no Accept-Language header (browsers always send one)', test: v => !v.acceptLanguage },
  { id: 'no-client-hints', cost: 10, why: 'no Sec-CH-UA client hints (Chromium >= 90 always sends them)', test: v => !v.secChUa },
  { id: 'no-sec-fetch-site', cost: 10, why: 'no Sec-Fetch-Site (Chromium >= 76 sends it on scripted requests)', test: v => !v.secFetchSite },
  { id: 'accept-star-no-fetch-metadata', cost: 5, why: "Accept: */* with no Sec-Fetch-Site: a scripted client that dropped its fetch metadata", test: v => v.accept === '*/*' && !v.secFetchSite }
];

const CLIENT_SIGNALS = [
  { id: 'navigator.webdriver', cost: 40, why: 'navigator.webdriver === true, the WebDriver marker', test: v => v.webdriver === true },
  { id: 'cdp-error-stack-hook', cost: 25, why: 'DevTools/CDP attached: Error.prepareStackTrace was read without the page reading .stack itself', test: v => v.prepareStackTraceReadWithoutTouch === true },
  { id: 'no-window.chrome', cost: 20, why: 'window.chrome missing (Chromium ships it outside some automation builds)', test: v => v.hasWindowChrome === false },
  { id: 'webgl-software-renderer', cost: 20, why: 'WebGL UNMASKED_RENDERER names a software rasterizer (SwiftShader/llvmpipe)', test: v => /SwiftShader|llvmpipe|Subzero|Software Rasterizer|Mesa/i.test(String(v.webglRenderer || '')) },
  { id: 'no-plugins', cost: 15, why: 'navigator.plugins is empty', test: v => v.plugins === 0 },
  { id: 'no-mime-types', cost: 10, why: 'navigator.mimeTypes is empty', test: v => v.mimeTypes === 0 },
  { id: 'no-languages', cost: 10, why: 'navigator.languages is empty', test: v => v.languages === 0 },
  { id: 'no-notification-api', cost: 10, why: 'Notification API absent', test: v => v.hasNotification === false },
  { id: 'no-hardware-concurrency', cost: 5, why: 'navigator.hardwareConcurrency undefined', test: v => typeof v.hardwareConcurrency !== 'number' }
];

export function verdictFor(score) {
  if (score >= 60) return 'bot';
  if (score >= 25) return 'suspect';
  return 'human';
}

function scoreHeaders(headers) {
  const v = {
    ua: headers['user-agent'] || '',
    acceptLanguage: headers['accept-language'],
    secChUa: headers['sec-ch-ua'],
    secFetchSite: headers['sec-fetch-site'],
    accept: headers['accept']
  };
  return HEADER_SIGNALS.filter(s => {
    try { return s.test(v); } catch { return false; }
  }).map(s => ({ id: s.id, cost: s.cost, side: 'header', why: s.why }));
}

export function scoreClient(reported = {}) {
  const hit = [];
  for (const s of CLIENT_SIGNALS) {
    let fired = false;
    try { fired = !!s.test(reported); } catch { fired = false; }
    if (fired) hit.push({ id: s.id, cost: s.cost, side: 'client', why: s.why });
  }
  return hit;
}

/* ------------------------------------------------------------------- pages/routes */
const PAGES = {
  '/': ['pages/index.html', 'text/html; charset=utf-8'],
  '/plain': ['pages/plain.html', 'text/html; charset=utf-8'],
  '/obf': ['pages/obf.html', 'text/html; charset=utf-8'],
  '/fingerprint': ['pages/fingerprint.html', 'text/html; charset=utf-8'],
  '/js/sha256-pure.js': ['pages/sha256-pure.js', 'application/javascript; charset=utf-8']
};

/* /obf-gen — the generated obfuscator.io variant from web-reverse/static/gen-obf.mjs.
   It lives outside the repo on purpose: obfuscator output is regenerated machine
   state, not source. Same client, same key, same gate as /plain, so the toolchain
   can be graded against a known answer on the same target the runtime loop uses. */
export const GEN_PAGE = process.env.WEB_REVERSE_GEN_PAGE
  || path.join(os.tmpdir(), 'web-reverse-captures', 'static', 'obf-gen.html');

/* Read at request time so a caller that generates into its own directory can point
   the server there after it has started (tools/loop2.mjs does exactly that). */
const genPagePath = () => process.env.WEB_REVERSE_GEN_PAGE || GEN_PAGE;

function send(res, code, body, type = 'application/json; charset=utf-8') {
  res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(body);
}

function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', c => {
      n += c.length;
      if (n > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const seen = new Map(); // signature -> expiry, the replay guard
let lastFingerprint = null; // newest verdict, readable over HTTP so a client without
                            // CDP (baseline browser) can still be measured

function stamp() { return new Date().toISOString().slice(11, 23); }

export function createServer({ log = () => {} } = {}) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const line = `${req.method} ${url.pathname}`;

    if (req.method === 'GET' && PAGES[url.pathname]) {
      const [rel, type] = PAGES[url.pathname];
      try {
        send(res, 200, fs.readFileSync(path.join(HERE, rel)), type);
        log(`${stamp()} ${line} 200 page`);
      } catch (e) {
        send(res, 500, JSON.stringify({ ok: false, error: String(e.message) }));
        log(`${stamp()} ${line} 500 missing-page`);
      }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/obf-gen') {
      const file = genPagePath();
      try {
        send(res, 200, fs.readFileSync(file), 'text/html; charset=utf-8');
        log(`${stamp()} ${line} 200 generated page`);
      } catch {
        send(res, 404, JSON.stringify({
          ok: false,
          error: 'generated-page-missing',
          hint: 'node web-reverse/static/gen-obf.mjs  (or set WEB_REVERSE_GEN_PAGE)',
          path: file
        }));
        log(`${stamp()} ${line} 404 generated-page-missing`);
      }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/health') {
      send(res, 200, JSON.stringify({
        ok: true,
        scheme: 'hmac-sha256(key, ts + "." + rawBody) hex',
        headerNames: ['x-lab-ts', 'x-lab-sign'],
        windowMs: SIGN_WINDOW_MS,
        keyId: keyId(),
        endpoints: ['POST /api/submit', 'POST /api/fingerprint']
      }));
      log(`${stamp()} ${line} 200 health`);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/submit') {
      const body = await readBody(req);
      const ts = req.headers['x-lab-ts'];
      const sig = req.headers['x-lab-sign'];
      if (!ts || !sig) {
        send(res, 401, JSON.stringify({ ok: false, error: 'missing-signature-headers' }));
        log(`${stamp()} ${line} 401 missing-signature-headers`);
        return;
      }
      if (!timingSafeEqHex(sig, signBody(body, ts))) {
        send(res, 401, JSON.stringify({ ok: false, error: 'bad-signature', bit: 'signature does not match' }));
        log(`${stamp()} ${line} 401 bad-signature`);
        return;
      }
      if (Math.abs(Date.now() - Number(ts)) > SIGN_WINDOW_MS) {
        send(res, 401, JSON.stringify({ ok: false, error: 'stale-timestamp', bit: 'ts outside window' }));
        log(`${stamp()} ${line} 401 stale-timestamp`);
        return;
      }
      const nonce = `${ts}:${sig}`;
      const now = Date.now();
      for (const [k, exp] of seen) if (exp < now) seen.delete(k);
      if (seen.has(nonce)) {
        send(res, 409, JSON.stringify({ ok: false, error: 'replayed-signature', bit: 'that exact signature was already accepted' }));
        log(`${stamp()} ${line} 409 replayed-signature`);
        return;
      }
      seen.set(nonce, now + SIGN_WINDOW_MS);
      let parsed = null;
      try { parsed = JSON.parse(body); } catch { parsed = null; }
      send(res, 200, JSON.stringify({
        ok: true,
        accepted: true,
        keyId: keyId(),
        ts: Number(ts),
        sign: sig,
        bodyBytes: Buffer.byteLength(body),
        received: parsed
      }));
      log(`${stamp()} ${line} 200 accepted sign=${String(sig).slice(0, 16)}…`);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/fingerprint') {
      const body = await readBody(req);
      let reported = {};
      try { reported = JSON.parse(body) || {}; } catch { reported = {}; }
      const hits = [...scoreHeaders(req.headers), ...scoreClient(reported)];
      const score = hits.reduce((a, h) => a + h.cost, 0);
      const capped = Math.min(100, score);
      const payload = {
        ok: true,
        at: new Date().toISOString(),
        score: capped,
        verdict: verdictFor(capped),
        reasons: hits,
        observed: { client: reported, headers: {
          'user-agent': req.headers['user-agent'] || null,
          'accept-language': req.headers['accept-language'] || null,
          'sec-ch-ua': req.headers['sec-ch-ua'] || null
        } }
      };
      lastFingerprint = payload;
      send(res, 200, JSON.stringify(payload, null, 2));
      log(`${stamp()} ${line} 200 verdict=${payload.verdict} score=${capped} reasons=${hits.map(h => h.id).join(',') || '-'}`);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/fingerprint/last') {
      send(res, lastFingerprint ? 200 : 404, JSON.stringify(
        lastFingerprint || { ok: false, error: 'no fingerprint recorded yet' }, null, 2));
      return;
    }

    send(res, 404, JSON.stringify({ ok: false, error: 'not-found', path: url.pathname }));
    log(`${stamp()} ${line} 404`);
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const get = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
  const port = Number(get('--port', 8787));
  const host = get('--host', '127.0.0.1');
  if (host !== '127.0.0.1' && host !== '::1') {
    console.error('refusing to bind off-loopback: lab target is loopback-only');
    process.exit(2);
  }
  const server = createServer({ log: m => console.log(m) });
  server.listen(port, host, () => {
    console.log(`web-reverse lab target  http://${host}:${port}`);
    console.log(`  keyId(sha256(key)[0:16]) = ${keyId()}   (assert this after recovering the key)`);
    console.log(`  pages: / , /plain , /obf , /fingerprint , /obf-gen (generated, ${fs.existsSync(genPagePath()) ? 'present' : 'missing — run static/gen-obf.mjs'})`);
    console.log(`  api:   POST /api/submit (signed) , POST /api/fingerprint , GET /api/health`);
    console.log('  loopback-only. Nothing leaves this machine.');
  });
}
