/* triage.mjs — Layer-0 triage for the static JS toolchain.
 *
 * Answers, from the bytes alone:
 *   1. is there a source map?              (if yes: read the source, do not deobfuscate)
 *   2. which bundler produced this?        (chooses the unpacker)
 *   3. which obfuscator family is this?    (chooses the deobfuscation strategy)
 *   4. which transpiler artifacts remain?  (decides whether wakaru has work to do)
 *
 * Pure string analysis, no dependencies, no execution of the input. Every signal
 * here is a shape an analyst can verify by eye — the point is a reviewable verdict,
 * not a clever classifier.
 */

const SOURCE_MAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/;
const SOURCE_URL_COMMENT = /\/\/[#@]\s*sourceURL=([^\s'"]*)/;

const BUNDLERS = [
  {
    id: 'webpack',
    unpacker: 'webcrack --unpack / wakaru --unpack',
    signals: [
      /__webpack_require__/,
      /__webpack_modules__/,
      /webpackChunk[A-Za-z0-9_$]*\s*(\[|=\s*\[)/,
      /__webpack_exports__/
    ]
  },
  {
    id: 'browserify',
    unpacker: 'webcrack --unpack / wakaru --unpack',
    signals: [
      /\{\s*\d+\s*:\s*\[\s*function\s*\(\s*require\s*,\s*module\s*,\s*exports\s*\)/,
      /\(function\s*\(\s*\)\s*\{\s*function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/,
      /\.exports\s*=\s*\w+\s*\}\s*,\s*\{\s*\}\s*\]\s*,\s*\{/,
      /MODULE_NOT_FOUND/,
      /\brequire\s*=\s*function/
    ]
  },
  {
    id: 'esbuild',
    unpacker: 'webcrack --unpack / wakaru --unpack',
    signals: [
      /__commonJS\s*\(/,
      /__toESM\s*\(/,
      /__toCommonJS\s*\(/,
      /__require\s*\(/,
      /\/\/\s*\S+\.(js|ts)\b\s*\n\s*var\s+\w+\s*=\s*\{\}/
    ]
  },
  {
    id: 'metro',
    unpacker: 'wakaru --unpack',
    signals: [
      /__d\s*\(\s*function\s*\(/,
      /_?\$\$_REQUIRE\s*\(/,
      /__METRO_GLOBAL_PREFIX__/,
      /global\.__r\s*=/
    ]
  },
  {
    id: 'bun',
    unpacker: 'wakaru (bun container)',
    signals: [/\/\/\s*bun\s+build/i, /Bun\.(version|inspect)\b/]
  },
  {
    id: 'rollup-vite',
    unpacker: 'webcrack --unpack (module graph)',
    signals: [/\/\/\s*vite\b/i, /__vitePreload\b/, /^\s*\/\/\s*rollup/m]
  },
  {
    id: 'amd',
    unpacker: 'webcrack --unpack',
    signals: [/\bdefine\s*\(\s*\[/, /define\.amd\s*=/]
  }
];

const FAMILIES = [
  {
    id: 'string-array',
    why: 'hex-named identifiers plus an indexed accessor over one large array — the dominant obfuscator.io family',
    strategy: 'webcrack --deobfuscate (decode table, inline literals, drop the accessor)',
    test: s => /_0x[0-9a-fA-F]{4,6}/.test(s) && /\[(_0x[0-9a-fA-F]{4,6})(\(|,)/.test(s)
  },
  {
    id: 'control-flow-flattening',
    why: 'a `while (!![]) { switch (order[i++]) { case \'0\': … } }` dispatcher over a shuffled block order',
    strategy: 'webcrack --deobfuscate (order the blocks, delete the dispatcher)',
    /* obfuscator.io v5 shape: the order is a pipe-delimited string in an object
       literal, the subject is that string split into an array, and the cases are
       the indices. Both halves are required — a bare `while (!![])` switch is
       also what some non-obfuscator code looks like. */
    test: s => /while\s*\(\s*!!\[\]\s*\)\s*\{\s*switch\s*\(/.test(s)
      || /\{\s*['"][A-Za-z0-9_$]{2,8}['"]\s*:\s*['"][0-9]+(?:\|[0-9]+)+['"]\s*,/.test(s)
  },
  {
    id: 'dead-code-injection',
    why: 'injected `if (!![]) { … }` blocks and predicate arithmetic that exist only to be removed',
    strategy: 'webcrack --deobfuscate (fold predicates, drop unreachable blocks)',
    test: s => /if\s*\(\s*!!\[\]\s*\)\s*\{/.test(s)
      || /parseInt\(\s*_0x[0-9a-fA-F]{4,6}\s*\(\s*0x[0-9a-fA-F]+\s*\)\s*\)\s*\/\s*0x[0-9a-fA-F]+/.test(s)
  },
  {
    id: 'eval-packer',
    why: 'Dean-Edwards style `eval(function(p,a,c,k,e,d))` self-decoding packer',
    strategy: 'static unpack of the payload array (webcrack), then re-run this triage on the result',
    test: s => /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/.test(s)
  },
  {
    id: 'self-defending',
    why: 'integrity checks on `Function.prototype.toString` / `constructor("return this")`',
    strategy: 'webcrack may partially fold it; otherwise patch the check out by hand (ast-grep)',
    test: s => /Function\.prototype\.toString\b/.test(s)
      || /constructor\s*\(\s*['"`]return this['"`]\s*\)/.test(s)
      || /debugger\b/.test(s) && /setInterval\s*\(/.test(s)
  },
  {
    id: 'jsvmp',
    why: 'an opcode interpreter (`while(true) switch(op)` over a big number array) — a VM, not an obfuscator',
    strategy: 'NOT static-deobfuscatable: instrument the interpreter boundary instead (tools/capture.mjs + hooks)',
    test: s => /switch\s*\(\s*_?[a-z]{1,3}\[\s*\w+\+\+\s*\]\s*\)/.test(s) || /while\s*\(\s*!!\[\]\s*\)[\s\S]{0,400}?case\s+0x[0-9a-f]{2,4}\s*:/.test(s)
  }
];

const TRANSPILER_HINTS = [
  { id: 'async-to-generator', test: /_asyncToGenerator|asyncGeneratorStep|_awaiter|__awaiter/ },
  { id: 'optional-chaining-lowering', test: /=== null \|\| \w+ === void 0 \? void 0|!== null && \w+ !== void 0/ },
  /* `nullish-lowering` used to be `/\w+ !== null && \w+ !== void 0 \? \w+ :/`. Three
     unbounded `\w+` runs with literals between them: on a long run of identifier
     characters the engine retries every start position and every split of the first
     run, which is quadratic. Measured: a 200 KB run took `triage()` 8.7 SECONDS.
     Found by fuzz-lab as a HANG, not a crash -- which is the whole reason a hang is a
     finding here and not a skip: nothing threw, nothing looked wrong, and the tool just
     stopped answering on the file it was handed.

     Bounded to 64 characters (longer than any identifier Babel emits for this
     construct) and it is O(n) again: 200 KB is now 18 ms, 1.6 MB is 145 ms. The matched
     set is unchanged, verified against real lowered output in both directions. The
     neighbouring `optional-chaining-lowering` hint has the same shape and is left
     alone: its first branch is anchored on a literal `===`, so it never enters the
     quadratic path (measured 0 ms on the same 200 KB input). */
  { id: 'nullish-lowering', test: /\w{1,64} !== null && \w{1,64} !== void 0 \? \w{1,64} :/ },
  { id: 'interop-require', test: /_interopRequireDefault|_interopRequireWildcard/ },
  { id: 'class-lowering', test: /_createClass\(|_classCallCheck\(|_inherits\(/ },
  { id: 'spread-lowering', test: /_toConsumableArray\(|_objectSpread\(/ },
  { id: 'cjs-wrapper', test: /Object\.defineProperty\(exports,\s*"__esModule"/ }
];

function hits(list, source) {
  return list.filter(entry => entry.signals.some(re => re.test(source))).map(entry => entry.id);
}

export function findSourceMap(source) {
  const comment = SOURCE_MAP_COMMENT.exec(source);
  const sourceUrl = SOURCE_URL_COMMENT.exec(source);
  const out = {
    sourceMappingURL: comment ? comment[1] : null,
    sourceURL: sourceUrl ? sourceUrl[1] : null,
    inline: false,
    mapBytes: 0,
    map: null,
    parseError: null
  };
  if (out.sourceMappingURL && out.sourceMappingURL.startsWith('data:')) {
    out.inline = true;
    const m = /^data:([^;,]*)[^,]*,(.*)$/s.exec(out.sourceMappingURL);
    if (m) {
      const isB64 = /;base64/i.test(m[1]);
      try {
        const json = isB64 ? Buffer.from(m[2], 'base64').toString('utf8') : decodeURIComponent(m[2]);
        out.map = JSON.parse(json);
        out.mapBytes = json.length;
      } catch (e) {
        out.parseError = String(e.message);
      }
    }
  }
  return out;
}

export function originalsFromMap(map) {
  if (!map || !Array.isArray(map.sources)) return [];
  const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
  const out = [];
  for (let i = 0; i < map.sources.length; i++) {
    const text = contents[i];
    if (typeof text === 'string' && text.length > 0) out.push({ name: map.sources[i] || `source-${i}.js`, text });
  }
  return out;
}

export function triage(source, { headers = {} } = {}) {
  const bytes = Buffer.byteLength(source);
  const lines = source.split('\n').length;
  const sourceMap = findSourceMap(source);
  const xSourceMap = headers['x-sourcemap'] || headers['sourcemap'] || null;

  const bundlers = hits(BUNDLERS, source);
  const families = FAMILIES.filter(f => {
    try { return f.test(source); } catch { return false; }
  }).map(f => ({ id: f.id, why: f.why, strategy: f.strategy }));
  const transpilers = TRANSPILER_HINTS.filter(h => h.test.test(source)).map(h => h.id);

  const minified = !sourceMap.sourceMappingURL && lines <= Math.max(3, bytes / 4000) && bytes > 500;
  const obfuscated = families.some(f => f.id !== 'jsvmp') || /_0x[0-9a-fA-F]{4,6}/.test(source);

  const originals = originalsFromMap(sourceMap.map);
  let verdict;
  if (originals.length > 0) verdict = 'sourcemap-with-originals';
  else if (sourceMap.sourceMappingURL || xSourceMap) verdict = 'sourcemap-reference';
  else if (obfuscated) verdict = 'obfuscated';
  else if (bundlers.length > 0) verdict = 'bundle';
  else if (minified) verdict = 'minified';
  else verdict = 'plain';

  const strategy =
    originals.length > 0 ? 'read the recovered original sources; deobfuscation would be wasted work'
      : verdict === 'obfuscated' ? 'webcrack --deobfuscate' + (transpilers.length ? ' then wakaru (transpiler artifacts present)' : '')
        : verdict === 'bundle' || verdict === 'minified' ? 'webcrack --unpack --unminify' + (transpilers.length ? ' then wakaru' : '')
          : transpilers.length ? 'wakaru (only transpiler artifacts to recover)' : 'nothing to do — already source';

  return {
    bytes,
    lines,
    verdict,
    strategy,
    sourceMap,
    xSourceMap,
    bundlers,
    bundlerUnpackers: bundlers.map(id => (BUNDLERS.find(b => b.id === id) || {}).unpacker).filter(Boolean),
    obfuscatorFamilies: families,
    transpilerArtifacts: transpilers,
    minified
  };
}

/* Residual-obfuscation metrics on the *output*, so "deobfuscated" is a measurable
   claim rather than a vibe. Each count maps to a family above. */
export function residuals(source) {
  const count = (re) => (source.match(re) || []).length;
  return {
    hexIdentifiers: new Set(source.match(/_0x[0-9a-fA-F]{4,6}/g) || []).size,
    /* `tableAccessorCalls` used to be `/[_$\w]+\s*\(\s*0x[0-9a-fA-F]+\s*\)/g`, which is
     * quadratic: `[_$\w]+` and the `\w` reachable after the group are ambiguous, so the
     * backtracker explores the overlap. A 300 KB run of identifier characters took this
     * function 22 SECONDS (measured, and unchanged at 25s for 300 KB). The input is
     * untrusted JS text -- it is the thing being triaged -- so this is the same defect
     * class as the ReDoS in crypto-lab's analyzer: a triage tool that hangs on the file
     * it was handed.
     *
     * Fixed by anchoring the identifier start to a non-identifier character and bounding
     * both quantified runs. 300 KB is now under 1 ms; 1.6 MB is under 1 ms. Found by
     * fuzz-lab (crash `web-triage-reference-*`). */
    tableAccessorCalls: count(/(?:^|[^\w$])[A-Za-z_$][\w$]{0,63}\s*\(\s*0x[0-9a-fA-F]{1,16}\s*\)/g),
    dispatcherLoops: count(/while\s*\(\s*(!!\[\]|true)\s*\)\s*\{[\s\S]{0,80}?switch\s*\(/g),
    evalCalls: count(/\beval\s*\(/g),
    functionConstructor: count(/new\s+Function\s*\(/g),
    longChunks: count(/const\s+[_$\w]+\s*=\s*['"][^'"]{80,}/g)
  };
}
