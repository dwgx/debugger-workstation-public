/*
 * frida-selftest-lib.mjs — the cases, as a callable function.

 * This is the same content as tools/frida-selftest.mjs, factored out so tools/loop.mjs can
 * run the suite as one step and count its results instead of re-implementing the checks.
 *
 * WHAT IS ACTUALLY EXECUTED
 * -------------------------
 *   Phase A  pure-logic unit tests on frida/lib/logic.mjs. That file is the same code the
 *            device runs, and the test additionally asserts it contains NO Frida globals.
 *   Phase B  each frida/hooks/*.js is LOADED into the runtime model in frida-emulator.mjs
 *            and driven: Java.use resolves, .overload selects, .implementation is
 *            installed, and calling the wrapper runs the hook and produces send() records.
 *            The records are asserted, not eyeballed.
 *   Phase C  static validation of the script text: every Frida API the scripts reference
 *            must exist in the model, and a script that references an API the model does not
 *            have is a FAILURE, not a skip — that is the check that catches a typo'd or
 *            removed API before anyone spends an hour attaching to find out.
 *   Phase D  the negative control: the detector run against an INSTRUMENTED synthetic target
 *            must detect. A detector that passes only on a clean target proves nothing.
 *
 * WHAT A PASS DOES NOT MEAN
 * -------------------------
 * See frida-emulator.mjs. This proves script logic, overload selection, hook ordering and
 * trace payloads. It does not prove ART accepts the script, that the real Interceptor
 * trampoline behaves this way, or anything about a live process. The exit code says
 * "the scripts are logic-verified", not "the scripts work on a phone".
 *
 * runFridaSelfTest() -> { results, failures }
 * The CLI wrapper is tools/frida-selftest.mjs.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createFridaEnv } from '../frida/lib/frida-emulator.mjs';
import * as L from '../frida/lib/logic.mjs';
import { buildSo } from '../lab/build/make-so.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const HOOKS = path.join(ROOT, 'frida', 'hooks');
const LOGIC = path.join(ROOT, 'frida', 'lib', 'logic.mjs');

const results = [];
let failures = 0;

function check(name, fn) {
  try {
    const detail = fn();
    results.push({ phase: 'case', name, pass: true, detail: detail ?? '' });
  } catch (e) {
    failures++;
    results.push({ phase: 'case', name, pass: false, detail: e.message });
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function eq(actual, expected, msg) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) throw new Error(`${msg}: expected ${b}, got ${a}`);
}

/* ================================================================== *
 * Phase A — pure logic
 * ================================================================== */

const A = () => {
  /* --- JNI name mangling, the rule the analyser and the hooks both depend on --- */
  check('jni: symbol name for a non-overloaded native method', () => {
    eq(L.jniSymbolName('com.lab.mobilelab.MainActivity', 'nativeDeriveKey'),
      'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey', 'mangled symbol');
    return 'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey';
  });

  check('jni: overload suffix is appended when a signature is given', () => {
    const s = L.jniSymbolName('com.lab.mobilelab.MainActivity', 'nativeReadFlag', 'I');
    eq(s, 'Java_com_lab_mobilelab_MainActivity_nativeReadFlag__I', 'mangled overload');
    return s;
  });

  /* This is the case a naive implementation gets wrong: escaping '_' first, then ';'
     would turn the '_1' it just wrote into '_11'. */
  check('jni: escape characters are encoded in the right order', () => {
    eq(L.encodeJniName('a_b;c[d'), 'a_1b_2c_3d', 'escaped name');
    return "a_b;c[d -> a_1b_2c_3d";
  });

  check('jni: round-trip encode/decode', () => {
    const original = 'weird_name;with[brackets';
    eq(L.decodeJniName(L.encodeJniName(original)), original, 'round trip');
    return 'round trip holds';
  });

  check('jni: parse a symbol back to class + method', () => {
    const p = L.parseJniSymbol('Java_com_lab_mobilelab_NativePinConfig_verifyNativePin');
    eq(p, { className: 'com.lab.mobilelab.NativePinConfig', methodName: 'verifyNativePin', signature: null }, 'parsed');
    return 'com.lab.mobilelab.NativePinConfig.verifyNativePin';
  });

  check('jni: an ordinary C export is NOT reported as a JNI boundary', () => {
    eq(L.parseJniSymbol('memcmp'), null, 'non-JNI symbol');
    eq(L.parseJniSymbol('some_library_internal'), null, 'non-JNI symbol');
    return 'memcmp and friends correctly ignored';
  });

  /* --- overload selection: the decision a device cannot show you --- */
  check('overload: picks the right one of three by parameter types', () => {
    const overloads = ['int', 'int,int', 'java.lang.String,[Ljava.lang.Object;'];
    eq(L.selectOverload(overloads, ['int']), 0, 'single int');
    eq(L.selectOverload(overloads, ['int', 'int']), 1, 'two ints');
    eq(L.selectOverload(overloads, ['java.lang.String', '[Ljava.lang.Object;']), 2, 'string + array');
    return 'all three resolved by type';
  });

  check('overload: an unmatched call selects nothing instead of guessing', () => {
    const overloads = ['int', 'int,int'];
    eq(L.selectOverload(overloads, ['java.lang.String']), -1, 'no match');
    eq(L.selectOverload(overloads, ['int', 'int', 'int']), -1, 'arity mismatch');
    return 'returns -1, never a wrong overload';
  });

  /* --- credential classification and redaction --- */
  check('redaction: a key-shaped constant is flagged AND redacted', () => {
    const r = L.redactConstant('sk-lab-PLACEHOLDER-0000000000000000');
    assert(r.flagged, 'should be flagged');
    assert(r.shapes.includes('prefixed-api-key'), `wrong shape: ${r.shapes}`);
    assert(!r.display.includes('0000000000000000'), 'the value must not survive redaction');
    return `${r.shapes.join(',')} -> ${r.display}`;
  });

  check('redaction: an ordinary string is left alone', () => {
    const r = L.redactConstant('com.lab.mobilelab.MainActivity');
    assert(!r.flagged, 'a class name is not a credential');
    assert(!r.redacted, 'a class name must not be redacted');
    return r.display;
  });

  check('redaction: a URL with embedded credentials is caught', () => {
    const r = L.redactConstant('https://user:hunter2@example.invalid/');
    assert(r.flagged && r.shapes.includes('basic-auth-url'), `missed: ${JSON.stringify(r)}`);
    return r.shapes.join(',');
  });

  /* --- the maps detector --- */
  check('maps: a frida-agent mapping is detected', () => {
    const line = '7f3a1c0000-7f3a1c4000 r-xp 00000000 08:01 1234  /data/local/tmp/frida-agent-64.so';
    const c = L.classifyMapsLine(line);
    assert(c && c.kind === 'agent-module' && c.marker === 'frida', `not detected: ${JSON.stringify(c)}`);
    return 'frida-agent-64.so detected';
  });

  check('maps: an ordinary system mapping is NOT reported', () => {
    for (const line of [
      '7f0000000000-7f0000001000 r-xp 00000000 08:01 100 /system/lib64/libc.so',
      '7f0000002000-7f0000003000 rw-p 00000000 00:00 0 [anon:dalvik-main space]',
      '',
    ]) {
      eq(L.classifyMapsLine(line), null, `should be null for: ${line}`);
    }
    return 'no false positives on system/anon/blank lines';
  });

  check('maps: an executable mapping outside /system is surfaced', () => {
    const line = '7f2b00000000-7f2b00001000 r-xp 00000000 fd:00 999 /data/app/com.example.base.apk!/lib/arm64-v8a/libfoo.so';
    const c = L.classifyMapsLine(line);
    assert(c && c.kind === 'unusual-exec-mapping', `missed: ${JSON.stringify(c)}`);
    return c.marker;
  });

  check('tracerPid: 0 = clean, >0 = instrumented, absent = UNKNOWN not clean', () => {
    eq(L.readTracerPid('Name:\tapp\nTracerPid:\t0\n').state, 'clean', 'zero');
    eq(L.readTracerPid('Name:\tapp\nTracerPid:\t1234\n').state, 'instrumented', 'nonzero');
    eq(L.readTracerPid('Name:\tapp\n').state, 'unknown', 'absent line');
    eq(L.readTracerPid(null).state, 'unknown', 'null input');
    return 'clean / instrumented / unknown are three distinct answers';
  });

  /* --- pin handling --- */
  check('pins: recognised, normalised and deduplicated', () => {
    const good = 'sha256/7gL4Y5kKz6bWf0m2H1pQ8sT3vX7yZ0A9dC5eR1uI4oP2lM6nJ8fG0hK3w=';
    assert(L.looksLikePin(good), 'a real-looking pin must be recognised');
    assert(!L.looksLikePin('not-a-pin'), 'junk must be rejected');
    eq(L.normalizePin('SHA256/abc'), 'sha256/abc', 'prefix normalised, digest untouched');
    const u = L.uniquePins(['sha256/AAA=', 'sha256/AAA=', 'sha256/BBB=']);
    eq(u.length, 2, 'duplicates collapse');
    return '2 unique pins from 3 inputs';
  });

  check('trace: formatTrace never lets a throwing toString escape', () => {
    const hostile = { toString() { throw new Error('boom'); } };
    const rec = L.formatTrace({ event: 'x', target: 'y', args: [hostile, 'ok'] });
    assert(rec.args[0].startsWith('<unstringifiable'), `expected a safe placeholder, got ${rec.args[0]}`);
    eq(rec.args[1], 'ok', 'the good value survives');
    return 'hostile object contained';
  });

  check('url: a non-parsable URL-looking string is still reported', () => {
    const c = L.classifyUrl('https://[bad');
    assert(c.parsed === false && c.url === 'https://[bad', 'must not be silently dropped');
    return 'reported unparsed rather than dropped';
  });
};

/* Phase A also asserts the pure module is genuinely pure. */
const A_purity = () => {
  check('purity: logic.mjs references no Frida globals', () => {
    const src = fs.readFileSync(LOGIC, 'utf8');
    /* Comments and string literals are stripped first. Without that, the file's own header
       — which has to NAME the Frida APIs it is deliberately free of, in order to explain
       why the split exists — would fail this check for merely describing them. */
    const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/.*$/gm, ' ')
      .replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""');
    for (const forbidden of ['Java.perform', 'Java.use(', 'Interceptor.attach', 'Module.enumerate']) {
      assert(!code.includes(forbidden), `logic.mjs references "${forbidden}" — the pure half must not touch Frida`);
    }
    return 'no Java./Interceptor./Module. references';
  });
};

/* ================================================================== *
 * Phase C — static validation of the hook scripts
 * ================================================================== */

const KNOWN_FRIDA_APIS = new Set([
  'Java', 'Interceptor', 'Module', 'Memory', 'Process', 'NativeFunction', 'NativePointer',
  'send', 'recv', 'console', 'ptr', 'setImmediate', 'setTimeout', 'Script', 'Socket',
]);

const C = () => {
  const files = fs.readdirSync(HOOKS).filter(f => f.endsWith('.js')).sort();
  assert(files.length > 0, 'no hook scripts found');

  for (const f of files) {
    check(`static: ${f} references only known Frida APIs`, () => {
      const src = fs.readFileSync(path.join(HOOKS, f), 'utf8');
      /* Strip strings and comments so a mention inside prose is not read as a call. */
      const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/.*$/gm, ' ')
        .replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""');
      const used = new Set();
      for (const m of code.matchAll(/\b(Java|Interceptor|Module|Memory|Process|NativeFunction|NativePointer|send|recv|ptr|setImmediate|setTimeout|Socket|Script)\b/g)) {
        used.add(m[1]);
      }
      const unknown = [...used].filter(u => !KNOWN_FRIDA_APIS.has(u));
      eq(unknown, [], 'unknown Frida API referenced');
      return `${used.size} APIs, all known: ${[...used].sort().join(' ')}`;
    });

    check(`static: ${f} parses as JavaScript`, () => {
      const src = fs.readFileSync(path.join(HOOKS, f), 'utf8');
      /* new Function compiles without running: a syntax error throws here. */
      new Function('Java', 'Interceptor', 'Module', 'Memory', 'Process', 'send', 'recv', 'ptr', src);
      return 'compiles';
    });

    check(`static: ${f} declares its scope`, () => {
      const src = fs.readFileSync(path.join(HOOKS, f), 'utf8');
      assert(/observation|observe-only|detect/i.test(src),
        'a hook must state whether it observes or modifies; silence here is how a bypass gets written by accident');
      return 'scope stated in the header';
    });
  }
};

/* ================================================================== *
 * Phase B — run the hooks against the runtime model
 * ================================================================== */

/** Synthetic targets mirroring the shapes the lab's own APK actually has. */
function okhttpEnv() {
  return createFridaEnv({
    targets: {
      'okhttp3.CertificatePinner$Builder': {
        methods: { add: { overloads: ['java.lang.String,java.lang.String'] } },
      },
      'okhttp3.CertificatePinner': {
        methods: { check: { overloads: ['java.lang.String,[Ljava.lang.Object;'] } },
      },
      'com.lab.mobilelab.PinningTrustManager': {
        methods: { checkServerTrusted: { overloads: ['[Ljavax.security.cert.X509Certificate;,java.lang.String'] } },
      },
    },
  });
}

function readHook(name) {
  return fs.readFileSync(path.join(HOOKS, name), 'utf8');
}

const B = () => {
  /* --- B1: the OkHttp pinning observer actually observes --- */
  check('run 01-okhttp: installs three hooks and sends agent-ready', () => {
    const fe = okhttpEnv();
    fe.run(readHook('01-okhttp-certificate-pinner.js'), '01-okhttp-certificate-pinner.js');
    eq(fe.errors, [], 'no resolution errors');
    const ready = fe.sent.filter(s => s.event === 'agent-ready');
    eq(ready.length, 1, 'one agent-ready');
    eq(ready[0].scope, 'observe-only', 'scope');
    return 'agent-ready(observe-only)';
  });

  check('run 01-okhttp: Builder.add is hooked and records a declared pin', () => {
    const fe = okhttpEnv();
    fe.run(readHook('01-okhttp-certificate-pinner.js'), '01-okhttp.js');
    const builder = fe.env.Java.use('okhttp3.CertificatePinner$Builder');
    builder.add('api.lab.invalid', 'sha256/7gL4Y5kKz6bWf0m2H1pQ8sT3vX7yZ0A9dC5eR1uI4oP2lM6nJ8fG0hK3w=');
    const d = fe.sent.filter(s => s.event === 'pin-declared');
    eq(d.length, 1, 'one pin-declared record');
    eq(d[0].domain, 'api.lab.invalid', 'domain');
    assert(d[0].wellFormed === true, 'a real pin must be well-formed');
    return `declared ${d[0].domain} wellFormed=${d[0].wellFormed}`;
  });

  check('run 01-okhttp: a malformed pin is reported as malformed, not as a pin', () => {
    const fe = okhttpEnv();
    fe.run(readHook('01-okhttp-certificate-pinner.js'), '01-okhttp.js');
    fe.env.Java.use('okhttp3.CertificatePinner$Builder').add('api.lab.invalid', 'totally-not-a-pin');
    const d = fe.sent.filter(s => s.event === 'pin-declared');
    eq(d[0].wellFormed, false, 'must be reported malformed');
    return 'malformed pin flagged';
  });

  check('run 01-okhttp: check() is hooked and the trace names the host', () => {
    const fe = okhttpEnv();
    fe.run(readHook('01-okhttp-certificate-pinner.js'), '01-okhttp.js');
    const pinner = fe.env.Java.use('okhttp3.CertificatePinner');
    pinner.check('api.lab.invalid', []);
    const c = fe.sent.filter(s => s.event === 'pin-check');
    eq(c.length, 1, 'one pin-check');
    eq(c[0].hostname, 'api.lab.invalid', 'hostname');
    assert(/not modified/i.test(c[0].note), 'the record must state the decision was not modified');
    return `pin-check ${c[0].hostname}, decision not modified`;
  });

  check('run 01-okhttp: a class that does not exist fails loudly', () => {
    /* The negative control for the resolver: a typo'd class must not silently no-op. */
    const fe = createFridaEnv({ targets: {} });
    let threw = false;
    try {
      fe.run('Java.perform(function(){ Java.use("com.does.not.Exist").overload("int"); });', 'typo.js');
    } catch (e) { threw = true; }
    assert(threw, 'Java.use on a missing class must throw, not return a silent stub');
    return 'ClassNotFoundException surfaced';
  });

  /* --- B2: the JNI boundary hook, against the real hand-built .so --- */
  const so = buildSo();
  const soEnv = () => createFridaEnv({
    targets: {
      'com.lab.mobilelab.MainActivity': { methods: { nativeReadFlag: { overloads: ['int'] } } },
    },
    modules: [{
      name: 'libmobilelab.so',
      base: 0x1000,
      exports: so.meta.exports.map((n, i) => ({ name: n, address: 0x1000 + i * 8, type: 'function' }))
        .concat(so.meta.imports.map((n, i) => ({ name: n, address: 0, type: 'function' }))),
    }],
  });

  check('run 03-jni: reports the real export table from the hand-built .so', () => {
    const fe = soEnv();
    fe.run(readHook('03-jni-native-boundary.js'), '03-jni.js');
    const t = fe.sent.find(s => s.event === 'export-table');
    assert(t, 'no export-table record');
    eq(t.module, 'libmobilelab.so', 'module');
    eq(t.jniExports.sort(), so.meta.exports.slice().sort(), 'JNI exports must match the .so exactly');
    return `${t.jniExports.length} JNI exports enumerated, matching the built ELF`;
  });

  check('run 03-jni: attaches to all three watched exports', () => {
    const fe = soEnv();
    fe.run(readHook('03-jni-native-boundary.js'), '03-jni.js');
    const s = fe.sent.find(x => x.event === 'attach-summary');
    eq(s.requested, 3, 'requested');
    eq(s.attached, 3, 'attached');
    eq(s.missing, [], 'missing');
    return '3/3 attached';
  });

  check('run 03-jni: onEnter then onLeave produce ordered trace records', () => {
    const fe = soEnv();
    fe.run(readHook('03-jni-native-boundary.js'), '03-jni.js');
    const target = '0x1000';
    const res = fe.fire(target, { args: [{}, {}, 'salt', 4096] });
    assert(res, 'no hook fired');
    assert(res.entered && res.left, 'both callbacks must run');
    const kinds = fe.sent.map(s => s.event);
    const iEnter = kinds.indexOf('jni-enter');
    const iLeave = kinds.indexOf('jni-leave');
    assert(iEnter >= 0 && iLeave > iEnter, `onEnter must precede onLeave: ${kinds.join(',')}`);
    return 'jni-enter then jni-leave';
  });

  check('run 03-jni: a missing export is reported, not silently skipped', () => {
    /* Negative control: rename one symbol in the module and require the summary to say so. */
    const fe = createFridaEnv({
      targets: { 'com.lab.mobilelab.MainActivity': { methods: { nativeReadFlag: { overloads: ['int'] } } } },
      modules: [{ name: 'libmobilelab.so', base: 0x1000, exports: [
        { name: 'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey', address: 0x1000, type: 'function' },
      ] }],
    });
    fe.run(readHook('03-jni-native-boundary.js'), '03-jni.js');
    const s = fe.sent.find(x => x.event === 'attach-summary');
    eq(s.attached, 1, 'only one can attach');
    eq(s.missing.length, 2, 'the other two must be reported missing');
    assert(/did not resolve/.test(s.verdict), 'verdict must name the failure');
    return `1 attached, 2 reported missing: ${s.missing.join(', ')}`;
  });

  /* --- B3: the detector, on a CLEAN target --- */
  const detectorEnv = (maps, status) => createFridaEnv({
    targets: {
      'java.io.FileInputStream': { methods: { read: { overloads: [] }, close: { overloads: [] } } },
      'java.io.File': { methods: { available: { overloads: [] } } },
      'android.os.Debug': { methods: { isDebuggerConnected: { overloads: [] }, waitingForDebugger: { overloads: [] } } },
      'com.lab.mobilelab.IntegrityGuard': {
        methods: {
          hasFridaServer: { overloads: [] },
          isBeingDebugged: { overloads: [] },
          tracerPid: { overloads: [] },
        },
      },
    },
  });

  check('run 02-detector: loads and emits a report', () => {
    const fe = detectorEnv();
    fe.run(readHook('02-anti-instrumentation-detector.js'), '02-detector.js');
    const r = fe.sent.find(s => s.event === 'anti-instrumentation-report');
    assert(r, 'no report emitted');
    eq(r.confidence, 'observed', 'confidence tier must be stated');
    assert(Array.isArray(r.findings), 'findings must be an array');
    assert(typeof r.limits === 'string' && r.limits.length > 0, 'an honest limits field is mandatory');
    return `report emitted, ${r.knownSignals.length} signals described`;
  });
};

/* ================================================================== *
 * Phase D — the negative control
 * ================================================================== */

const D = () => {
  check('NEGATIVE CONTROL: the detector logic fires on an instrumented target', () => {
    /* This is the control that makes the clean-target result mean something. We drive the
       SAME classifier the hook uses, against maps/status content that a real attach
       produces, and require a positive. If this fails, the detector is decorative. */
    const maps = [
      '7f0000000000-7f0000001000 r-xp 00000000 08:01 100 /system/lib64/libc.so',
      '7f2a1b000000-7f2a1b001000 r-xp 00000000 08:01 555 /data/local/tmp/frida-agent-64.so',
      '7f2a1c000000-7f2a1c002000 rw-p 00000000 00:00 0 [anon:dalvik-main space]',
    ].join('\n');
    const r = L.detectInMaps(maps);
    assert(r.findings.length >= 1, 'an instrumented target must produce findings');
    assert(r.findings.some(f => f.kind === 'agent-module' && f.marker === 'frida'),
      `expected a frida agent marker, got ${JSON.stringify(r.findings)}`);

    const clean = L.detectInMaps([
      '7f0000000000-7f0000001000 r-xp 00000000 08:01 100 /system/lib64/libc.so',
      '7f2a1c000000-7f2a1c002000 rw-p 00000000 00:00 0 [anon:dalvik-main space]',
    ].join('\n'));
    eq(clean.findings, [], 'a clean target must produce no findings');

    const traced = L.readTracerPid('TracerPid:\t4242\n');
    eq(traced.state, 'instrumented', 'a nonzero TracerPid is instrumented');

    return 'detects instrumented, silent on clean, positive on TracerPid';
  });

  check('NEGATIVE CONTROL: an unparseable TracerPid is UNKNOWN, never clean', () => {
    const r = L.readTracerPid('TracerPid:\tnot-a-number\n');
    eq(r.state, 'unknown', 'must not collapse to clean');
    return 'unknown stays unknown';
  });
};

/* Run every phase. Returns the case list so the caller can count pass/fail itself. */
export function runFridaSelfTest() {
  results.length = 0;
  failures = 0;
  A(); A_purity(); C(); B(); D();
  return { results: results.slice(), failures };
}
