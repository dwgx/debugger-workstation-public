/* fingerprint.mjs — run the lab's bot-detection surface and report what it saw.
 *
 * This is a DETECTOR and a REPORTER, deliberately. It answers two questions an
 * operator actually needs on an authorized target:
 *   "is this client being classified as automation, and on what evidence?"
 *   "how much of that evidence is MY OWN instrumentation?"
 * It does not spoof, patch, or hide any signal. Building evasion for someone
 * else's production site is out of scope for this station, permanently.
 *
 *   node tools/fingerprint.mjs [--url http://127.0.0.1:8787/fingerprint]
 *                              [--headed] [--compare] [--out report.json]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CDP } from './cdp.mjs';
import { launchChrome } from './chrome.mjs';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const pageUrl = get('--url', 'http://127.0.0.1:8787/fingerprint');
const outPath = get('--out', path.join(os.tmpdir(), 'web-reverse-captures', 'fingerprint.json'));
const keepOpen = has('--keep-open');

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function probe({ headless, withCdp }) {
  const chrome = await launchChrome({ headless, tag: headless ? 'fp-headless' : 'fp-headed', url: 'about:blank' });
  try {
    const browser = await CDP.connect(chrome.wsUrl);
    const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
    await browser.send('Page.enable', {}, sessionId);
    if (withCdp) await browser.send('Runtime.enable', {}, sessionId);
    const loaded = browser.waitFor('Page.loadEventFired', { sessionId, timeoutMs: 15_000 });
    await browser.send('Page.navigate', { url: pageUrl }, sessionId);
    await loaded;
    let verdict = null;
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline && !verdict) {
      const res = await browser.send('Runtime.evaluate', { expression: 'window.__labVerdict || null', returnByValue: true }, sessionId);
      verdict = res.result?.value ?? null;
      if (!verdict) await sleep(100);
    }
    browser.close();
    if (!verdict) throw new Error('page never produced a verdict (is the lab server up?)');
    return { headless, withCdp, ...verdict, browserPath: chrome.browserPath };
  } finally {
    if (!keepOpen) await chrome.close();
  }
}

function show(label, r) {
  console.log(`\n=== ${label} ===`);
  console.log(`verdict  ${r.verdict}   score ${r.score}   (headless=${r.headless}, cdp-runtime=${r.withCdp})`);
  console.log('reasons');
  if (!r.reasons.length) console.log('  (none — the checker found nothing suspicious)');
  for (const x of r.reasons) console.log(`  ${x.id.padEnd(26)} +${String(x.cost).padStart(3)}  ${x.side.padEnd(6)} ${x.why}`);
  console.log('observed (client-side)');
  console.log(JSON.stringify(r.raw, null, 2));
}

/* Baseline: a browser with NO debugging port at all. The page reports itself over
   plain HTTP, and we read the verdict back from the server. This is the control
   that says which signals are the browser's and which are OUR instrumentation. */
async function baselineProbe({ headless }) {
  const lastUrl = new URL('/api/fingerprint/last', pageUrl).toString();
  const readLast = async () => { try { const r = await fetch(lastUrl); return r.ok ? await r.json() : null; } catch { return null; } };
  const before = await readLast();
  const chrome = await launchChrome({ headless, tag: 'fp-baseline', url: pageUrl, remoteDebugging: false });
  try {
    const deadline = Date.now() + 25_000;
    while (Date.now() < deadline) {
      const rec = await readLast();
      if (rec && rec.at && (!before || rec.at !== before.at)) {
        return { headless, withCdp: false, ...rec, raw: (rec.observed && rec.observed.client) || null, browserPath: chrome.browserPath };
      }
      await sleep(150);
    }
    throw new Error('baseline browser never reported a fingerprint (is the lab server up?)');
  } finally {
    await chrome.close();
  }
}

const reports = [];
if (has('--compare')) {
  const runs = [
    ['headless Chrome, CDP attached', await probe({ headless: true, withCdp: true })],
    ['headless Chrome, no CDP (baseline)', await baselineProbe({ headless: true })],
    ['windowed Chrome, CDP attached', await probe({ headless: false, withCdp: true })],
    ['windowed Chrome, no CDP (baseline)', await baselineProbe({ headless: false })]
  ];
  for (const [label, r] of runs) { show(label, r); reports.push(r); }

  const [hCdp, hBase, wCdp, wBase] = runs.map(([, r]) => r);
  console.log('\n                      score  verdict  cdp-error-stack-hook  navigator.webdriver');
  const row = (name, r) => {
    const hook = r.reasons.some(x => x.id === 'cdp-error-stack-hook');
    console.log(`  ${name.padEnd(20)} ${String(r.score).padStart(5)}  ${r.verdict.padEnd(8)} ${String(hook).padEnd(21)} ${r.raw ? String(r.raw.webdriver) : '-'}`);
  };
  row('headless+cdp', hCdp); row('headless baseline', hBase); row('windowed+cdp', wCdp); row('windowed baseline', wBase);
  console.log(`\nmeasured CDP footprint: +${hCdp.score - hBase.score} point(s) for the headless browser, +${wCdp.score - wBase.score} for the windowed one.`);
  const hookFired = hCdp.reasons.some(x => x.id === 'cdp-error-stack-hook') || wCdp.reasons.some(x => x.id === 'cdp-error-stack-hook');
  console.log(`Error.prepareStackTrace inspector probe: ${hookFired ? 'FIRED — a CDP client with Runtime.enable was detected without the page touching .stack' : 'did not fire in this configuration (recorded as a negative result, not assumed to work)'}`);
  const driverFlag = (hCdp.raw && hCdp.raw.webdriver === true) && (hBase.raw && hBase.raw.webdriver !== true);
  console.log(`navigator.webdriver attribution: ${driverFlag ? 'true only when --remote-debugging-port is set — the same browser without it reports false' : 'not attributed in this run'}`);
  console.log(`windowed browser, no instrumentation: ${wBase.score} (${wBase.verdict}) — the floor the detector puts a plain human client on`);

  if (!(wBase.score < hCdp.score)) {
    console.error('the windowed baseline did not score lower than instrumented headless Chrome — the detector is not discriminating');
    process.exitCode = 8;
  }
  if (wBase.verdict !== 'human') {
    console.error(`a plain windowed browser scored ${wBase.verdict} (${wBase.score}) — the detector over-flags humans`);
    process.exitCode = 8;
  }
} else {
  const r = await probe({ headless: !has('--headed'), withCdp: !has('--no-cdp') });
  show('single probe', r);
  reports.push(r);
  if (!has('--headed') && r.verdict === 'human') {
    console.error('headless Chrome scored as human — unexpected');
    process.exitCode = 8;
  }
}

fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify({ probedAt: new Date().toISOString(), page: pageUrl, reports }, null, 2));
console.log(`\nwritten ${path.resolve(outPath)}`);
if (!keepOpen) setTimeout(() => process.exit(process.exitCode ?? 0), 300);
