/* chrome.mjs — launch / attach a DISPOSABLE lab Chrome for CDP work (zero deps).
 *
 * Stop line this respects: the daily Chrome and the other agent browser are
 * protected surfaces. This helper never attaches to a running browser; it spawns
 * its own instance with its own throwaway profile under %TEMP%, and refuses to
 * bind remote debugging to anything but loopback.
 *
 * Network containment: `--host-resolver-rules` maps every host to NOTFOUND except
 * loopback, so a lab page physically cannot reach the internet while we drive it.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CANDIDATES = [
  process.env.LAB_CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  path.join(os.homedir(), 'AppData/Local/Google/Chrome/Application/chrome.exe'),
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
].filter(Boolean);

export function findBrowser() {
  for (const c of CANDIDATES) if (fs.existsSync(c)) return c;
  throw new Error('no Chrome/Edge found; set LAB_CHROME to a browser executable');
}

export function labProfileDir(tag = 'lab') {
  const dir = path.join(os.tmpdir(), `web-reverse-${tag}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/* Windows keeps handles on a just-killed browser's profile for a moment, so a single
   rm() races and silently leaves the directory behind (observed: 3 strays after a few
   runs). Retry briefly, and report it instead of pretending the profile is gone. */
async function removeProfile(dir, attempts = 8) {
  for (let i = 1; i <= attempts; i++) {
    try {
      await fs.promises.rm(dir, { recursive: true, force: true });
      return true;
    } catch (e) {
      if (i === attempts) {
        console.error(`note: could not remove disposable profile ${dir} (${e.code || e.message}) — it is in %TEMP%`);
        return false;
      }
      await new Promise(r => setTimeout(r, 150 * i));
    }
  }
  return false;
}

/**
 * Spawn a disposable browser and wait for its DevTools endpoint.
 * @returns {Promise<{proc, wsUrl, httpBase, profileDir, browserPath, close}>}
 */
export async function launchChrome({
  headless = true,
  port = 0,
  tag = 'lab',
  url = 'about:blank',
  remoteDebugging = true,
  extraArgs = [],
  keepProfile = false,
  timeoutMs = 30_000
} = {}) {
  const browserPath = findBrowser();
  const profileDir = labProfileDir(tag);
  const args = [
    ...(remoteDebugging ? [`--remote-debugging-port=${port}`, '--remote-debugging-address=127.0.0.1'] : []),
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--no-service-autorun',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-sync',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-features=Translate,MediaRouter,OptimizationHints',
    '--metrics-recording-only',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
    ...(headless ? ['--headless=new'] : []),
    ...extraArgs,
    url
  ];

  const proc = spawn(browserPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  if (!remoteDebugging) {
    return {
      proc, wsUrl: null, httpBase: null, profileDir, browserPath,
      close: async () => {
        try { proc.kill(); } catch { /* already dead */ }
        if (!keepProfile) {
          await removeProfile(profileDir);
        }
      }
    };
  }
  let stderr = '';
  const wsUrl = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`browser did not open a DevTools endpoint in ${timeoutMs}ms\n${stderr}`)), timeoutMs);
    const scan = chunk => {
      stderr += chunk.toString();
      const m = /DevTools listening on (ws:\/\/[^\s]+)/.exec(stderr);
      if (m) { clearTimeout(timer); resolve(m[1]); }
    };
    proc.stderr.on('data', scan);
    proc.stdout.on('data', scan);
    proc.on('exit', code => { clearTimeout(timer); reject(new Error(`browser exited early (code ${code})\n${stderr}`)); });
  });

  const httpBase = wsUrl.replace(/^ws:\/\//, 'http://').replace(/\/devtools\/browser\/.*$/, '');
  const close = async () => {
    try { proc.kill(); } catch { /* already dead */ }
    if (!keepProfile) {
      await removeProfile(profileDir);
    }
  };
  return { proc, wsUrl, httpBase, profileDir, browserPath, close };
}

/** Browser-level websocket URL from an already-running lab browser. */
export async function browserWsFromHttp(httpBase) {
  const res = await fetch(`${httpBase}/json/version`);
  if (!res.ok) throw new Error(`GET ${httpBase}/json/version -> HTTP ${res.status}`);
  const json = await res.json();
  return json.webSocketDebuggerUrl;
}
