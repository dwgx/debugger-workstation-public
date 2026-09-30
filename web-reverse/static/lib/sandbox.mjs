/* sandbox.mjs — run recovered client code with no browser.
 *
 * The recovered signing logic is executed in a fresh V8 context. Per the method
 * (wiki/methods/web-reverse-method.md, Layer 4):
 *
 *   - ECMAScript builtins come from the context itself, never from the host
 *   - only host/BOM/DOM stubs are injected
 *   - the crypto primitive is node:crypto, an implementation independent of the
 *     page's own, so an accepted signature proves the *recovered algorithm*, not
 *     that we copied a value
 *
 * Deliberately NOT done here (see README honest limits): no native-masked
 * Function.prototype.toString, no `document.all` Proxy, no timing masking. This
 * sandbox is for code we own; it is not an anti-detection runtime.
 */
import vm from 'node:vm';
import crypto from 'node:crypto';

export function hmacSha256Hex(key, message) {
  return crypto.createHmac('sha256', key).update(message).digest('hex');
}

export function sha256Hex(string) {
  return crypto.createHash('sha256').update(string).digest('hex');
}

function elementStub(selector) {
  const el = {
    tagName: 'DIV',
    id: String(selector || ''),
    textContent: '',
    innerText: '',
    value: '',
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, contains: () => false },
    getAttribute: () => null,
    setAttribute() {},
    removeAttribute() {},
    appendChild: (c) => c,
    addEventListener() {},
    removeEventListener() {},
    click() {},
    focus() {},
    querySelector: () => elementStub('querySelector'),
    querySelectorAll: () => []
  };
  return el;
}

export function createSandbox({ log = () => {} } = {}) {
  const sandbox = {
    LabCrypto: { hmacSha256Hex, sha256Hex },
    console: { log, info: log, warn: log, error: log, debug: log },
    document: {
      getElementById: (id) => elementStub(id),
      querySelector: (s) => elementStub(s),
      querySelectorAll: () => [],
      createElement: (t) => elementStub(t),
      addEventListener() {},
      body: elementStub('body'),
      head: elementStub('head'),
      cookie: '',
      readyState: 'complete'
    },
    XMLHttpRequest: class {
      constructor() { this.readyState = 0; this.status = 0; this.responseText = ''; }
      open() { this.readyState = 1; }
      setRequestHeader() {}
      addEventListener() {}
      send() { this.readyState = 4; }
      getAllResponseHeaders() { return ''; }
    },
    fetch: async () => ({ ok: true, status: 200, text: async () => '', json: async () => ({}) }),
    navigator: { userAgent: 'web-reverse-sandbox', languages: ['en-US'], webdriver: false },
    location: { href: 'http://127.0.0.1/', origin: 'http://127.0.0.1', search: '' },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: () => 0,
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {}
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  return sandbox;
}

/* wakaru emits ESM (`export { f };`). Inside a vm.Script that is a SyntaxError, so
   when that is the only problem we strip the top-level export statements, keep the
   declarations (which are what we want to call), and say so in the result. */
function stripTopLevelEsm(code) {
  const stripped = code
    .replace(/^\s*export\s*\{[^}]*\}\s*;?\s*$/gm, '')
    .replace(/^\s*export\s+default\s+/gm, 'var __default_export = ')
    .replace(/^\s*export\s+(?=(async\s+function|function|class|const|let|var)\b)/gm, '');
  return { code: stripped, changed: stripped !== code };
}

/**
 * Execute recovered code and return the sandbox plus a small report.
 * @param {string} code recovered client source
 * @param {{filename?: string, log?: Function}} [opts]
 */
export function loadRecovered(code, { filename = 'recovered.js', log = () => {} } = {}) {
  const started = Date.now();
  const strip = stripTopLevelEsm(code);
  const sandbox = createSandbox({ log });
  const script = new vm.Script(strip.code, { filename });
  script.runInContext(sandbox, { timeout: 10_000 });
  return { sandbox, strippedEsm: strip.changed, ms: Date.now() - started };
}

/** Call `name` on the sandbox (window.*), with the exception surfaced verbatim. */
export function callGlobal(sandbox, name, args = [], { timeout = 10_000 } = {}) {
  const fn = sandbox[name];
  if (typeof fn !== 'function') {
    const seen = Object.keys(sandbox).filter(k => typeof sandbox[k] === 'function').slice(0, 20);
    throw new Error(`${name} is not a function in the recovered context (functions present: ${seen.join(', ') || 'none'})`);
  }
  const vmFn = vm.runInContext(name, sandbox, { timeout });
  return vmFn.apply(null, args);
}
