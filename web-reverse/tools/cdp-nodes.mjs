/* cdp-nodes.mjs — ONE URL in, the page's DOM nodes out, as typed JSON.
 *
 * WHY THIS EXISTS. `web.js.cdp` was `observed` with a probe and no `invoke`, because
 * chrome.mjs is a MODULE and the only driver that spoke to it was loop.mjs, which runs the
 * lab's own fixed six checks against a lab-served page rather than a caller-supplied URL.
 * The entry's own not_callable.reason said exactly that, and named the fix: "if a URL-taking
 * wrapper is added later, this entry gains an invoke". This is that wrapper.
 *
 * It is a thin driver, not a second instrument: launchChrome (disposable profile under
 * %TEMP%, host-resolver-rules mapping every host to NOTFOUND) and the hand-rolled CDP client
 * are the SAME ones capture.mjs and loop.mjs use. Nothing about containment is re-invented
 * here, which is the point -- a wrapper that re-implemented the browser launch would be a
 * second place for the stop line to rot.
 *
 * LOOPBACK ONLY, ENFORCED. The entry consumes a `url` and its reach says net:false, so the
 * scheme+host is checked BEFORE a browser is spawned. chrome.mjs would already map a remote
 * host to NOTFOUND, but "the resolver happens to block it" is a weaker claim than "the
 * wrapper refuses it", and the refusal is the one a reader can audit.
 *
 * STDOUT IS ONE JSON OBJECT. mission.ps1 merges the child's stdout and stderr into one string
 * before parsing, so every diagnostic goes to stderr. This is the rule native.disasm.capstone
 * paid for with a whole mission round.
 *
 *   node web-reverse/tools/cdp-nodes.mjs --url http://127.0.0.1:8787/plain
 *   node web-reverse/tools/cdp-nodes.mjs --url http://127.0.0.1:8787/plain --max 50 --headed
 *
 * Exit: 0 observed, 1 refused (not loopback / bad argv), 2 could not run (no browser, no load).
 */
import { CDP, evalInPage } from './cdp.mjs';
import { launchChrome } from './chrome.mjs';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const KNOWN = new Set(['--url', '--max', '--headed', '--keep-profile', '--timeout-ms']);
for (let i = 0; i < args.length; i++) {
  if (KNOWN.has(args[i])) { if (args[i] !== '--headed' && args[i] !== '--keep-profile') i += 1; continue; }
  emit({ ok: false, exit: 2, error: `unrecognised argument: ${args[i]}`,
         note: 'An argument this wrapper ignores would report an observation nobody made.' }, 2);
}

const url = get('--url', null);
const max = Number(get('--max', 500));
const timeoutMs = Number(get('--timeout-ms', 20_000));

if (!url) {
  emit({ ok: false, exit: 2, error: 'usage: cdp-nodes.mjs --url <loopback-url> [--max N]' }, 2);
}

/* --- loopback gate, before anything is spawned ------------------------------- */
let parsed;
try { parsed = new URL(url); } catch (e) {
  emit({ ok: false, exit: 1, error: `not a URL: ${url}` }, 1);
}
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
if (!/^https?:$/.test(parsed.protocol) || !LOOPBACK.has(parsed.hostname)) {
  emit({
    ok: false, exit: 1, error: `refusing non-loopback origin: ${parsed.protocol}//${parsed.hostname}`,
    note: 'This capability declares net:false and consumes a loopback URL. A host with no ' +
          'verdict is not a runtime self-decision: get a gate verdict before pointing this anywhere else.'
  }, 1);
}

/* --- the observation -------------------------------------------------------- */
/* A short CSS path per element, built from what is actually on the page. Positional
 * `:nth-of-type` is used only where a tag/class cannot identify the node, so the selector is
 * stable across a re-run of the same page and readable when it is not. */
const NODES_EXPR = `(() => {
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'META', 'LINK']);
  const seg = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) return s + '#' + el.id;
    const cls = (el.className && typeof el.className === 'string')
      ? el.className.trim().split(/\\s+/).filter(Boolean).slice(0, 2) : [];
    if (cls.length) return s + '.' + cls.join('.');
    const parent = el.parentElement;
    if (!parent) return s;
    const same = Array.from(parent.children).filter(c => c.tagName === el.tagName);
    return same.length > 1 ? s + ':nth-of-type(' + (same.indexOf(el) + 1) + ')' : s;
  };
  const path = (el) => {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) parts.unshift(seg(n));
    return parts.join(' > ') || seg(el);
  };
  const out = [];
  const walk = (el, depth) => {
    if (depth > 24) return;
    for (const child of el.children) {
      if (SKIP.has(child.tagName)) continue;
      const text = Array.from(child.childNodes)
        .filter(n => n.nodeType === 3).map(n => n.textContent.trim()).filter(Boolean).join(' ');
      if (text) out.push({ selector: path(child), text });
      walk(child, depth + 1);
    }
  };
  walk(document.body, 0);
  return { title: document.title, href: location.href, nodes: out };
})()`;

let chrome = null;
let browser = null;
try {
  chrome = await launchChrome({ headless: !has('--headed'), tag: 'cdp-nodes', url: 'about:blank', keepProfile: has('--keep-profile') });
  browser = await CDP.connect(chrome.wsUrl);
  const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
  await browser.send('Page.enable', {}, sessionId);
  await browser.send('Runtime.enable', {}, sessionId);

  const loaded = browser.waitFor('Page.loadEventFired', { sessionId, timeoutMs });
  await browser.send('Page.navigate', { url }, sessionId);
  await loaded;

  const seen = await evalInPage(browser, sessionId, NODES_EXPR);
  const nodes = (seen.nodes || []).slice(0, max);
  emit({
    ok: true,
    exit: 0,
    url,
    final_url: seen.href,
    title: seen.title,
    count: nodes.length,
    truncated: (seen.nodes || []).length > nodes.length,
    nodes,
    caveat: 'ONE observation of a LIVE page at one moment. `invalidates_on` says a navigation ' +
            'voids it, and nothing here says the page is stable or that the same bytes would be ' +
            'served to another client.'
  }, 0);
} catch (e) {
  emit({ ok: false, exit: 2, error: String(e && e.message ? e.message : e), url }, 2);
} finally {
  try { if (browser) browser.close(); } catch { /* already gone */ }
  try { if (chrome) await chrome.close(); } catch { /* already gone */ }
}

function emit(obj, code) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
  process.exit(code);
}
