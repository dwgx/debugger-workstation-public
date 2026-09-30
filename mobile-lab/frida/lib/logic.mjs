/*
 * logic.mjs — the PURE part of every Frida script in this lab.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * A Frida script is only testable with a device if all of its interesting behaviour lives
 * in callbacks that run inside the target process. That is the wrong place for logic:
 * JNI name mangling, overload selection, /proc/self/maps classification and credential
 * redaction are all decidable from plain strings and arrays.
 *
 * So every script here is split in two:
 *
 *     frida/hooks/*.js      thin binding — Java.perform / Interceptor.attach / send()
 *     frida/lib/logic.mjs   this file — every decision, as a pure function
 *
 * The pure half is what the offline validator exercises. It is not a mock: it is the same
 * code the device runs, called with the same inputs. What the validator cannot prove is
 * that Frida's runtime behaves as the emulator models it, and the README says so.
 *
 * No Frida globals appear in this file. That is enforced by tools/frida-selftest.mjs, which
 * runs it in a bare context and fails if anything reaches for Java, Interceptor or Module.
 */

/* ------------------------------------------------------------------ *
 * JNI name mangling (JNI spec, "Resolving Native Method Names")
 * ------------------------------------------------------------------ */

/**
 * Encode a Java method name the way the JNI mangler does.
 *   '_' -> '_1', ';' -> '_2', '[' -> '_3', '/' -> '_' (package separator)
 * The order matters: the escape characters must themselves be encoded first, or every
 * later replacement would re-encode the underscores it just introduced.
 */
export function encodeJniName(name) {
  return String(name).replace(/_/g, '_1').replace(/;/g, '_2').replace(/\[/g, '_3');
}

/** Decode a mangled component back to its original (used to explain a symbol to a human). */
export function decodeJniName(encoded) {
  return String(encoded).replace(/_1/g, '_').replace(/_2/g, ';').replace(/_3/g, '[');
}

/**
 * Build the full exported symbol name for a Java native method.
 *
 *   jniSymbolName('com.lab.mobilelab.MainActivity', 'nativeDeriveKey')
 *     -> 'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey'
 *
 * Overloaded native methods carry a `__<jni-signature>` suffix. Passing `signature`
 * appends it; omitting it produces the short form, which is what you want for the
 * (common) non-overloaded case.
 */
export function jniSymbolName(className, methodName, signature) {
  const cls = String(className).replace(/\./g, '/');
  const encodedClass = cls.split('/').map(encodeJniName).join('_');
  const encodedMethod = encodeJniName(methodName);
  const base = `Java_${encodedClass}_${encodedMethod}`;
  return signature ? `${base}__${signature}` : base;
}

/**
 * Parse an exported .so symbol back into { className, methodName, signature }.
 * Returns null for anything that is not a JNI export — an ordinary C function is not a
 * finding, and reporting it as one is how a static pass becomes noise.
 */
export function parseJniSymbol(symbol) {
  const s = String(symbol);
  if (!s.startsWith('Java_')) return null;

  let rest = s.slice(5);
  let signature = null;
  const sigAt = rest.indexOf('__');
  if (sigAt >= 0) {
    signature = rest.slice(sigAt + 2);
    rest = rest.slice(0, sigAt);
  }

  const parts = rest.split('_');
  if (parts.length < 2) return null;

  /* The class is everything up to the last component, which is the method. Greedy on the
     class is what makes package names containing underscores survive. */
  const classParts = parts.slice(0, -1).map(decodeJniName);
  const methodName = decodeJniName(parts[parts.length - 1]);
  return { className: classParts.join('.'), methodName, signature };
}

/* ------------------------------------------------------------------ *
 * Overload resolution
 * ------------------------------------------------------------------ */

/** JNI type descriptors for the Java types this lab's scripts name. */
export const JAVA_SIGNATURES = {
  'void': 'V', 'boolean': 'Z', 'byte': 'B', 'char': 'C', 'short': 'S',
  'int': 'I', 'long': 'J', 'float': 'F', 'double': 'D',
  'java.lang.String': 'Ljava/lang/String;',
  '[Ljava.lang.Object;': '[Ljava/lang/Object;',
  'int[]': '[I', 'byte[]': '[B',
};

/**
 * Pick the overload whose parameter list matches the given runtime argument type names.
 *
 * Returns the index of the match, or -1. Pure and total: an unknown type never throws, it
 * just fails to match, because a hook that throws while resolving its own overload takes
 * down the very method it was installed to observe.
 *
 * This is the decision the "which overload did we hook" question actually turns on, and it
 * is exactly the thing that cannot be checked by eye on a real device.
 */
export function selectOverload(overloads, argTypes) {
  if (!Array.isArray(overloads) || overloads.length === 0) return -1;
  if (!Array.isArray(argTypes)) return -1;

  /* BOTH sides go through the same normalisation. Mapping only the caller's types and
     comparing them against raw declared names searches for "I" in a list containing
     "int", never matches, and returns -1 — which reads as "no such overload" and silently
     installs no hook at all. */
  const norm = t => JAVA_SIGNATURES[t] ?? t;
  const wanted = argTypes.map(norm);

  for (let i = 0; i < overloads.length; i++) {
    const params = String(overloads[i]).replace(/^\[|\]$/g, '').split(',').map(s => norm(s.trim()));
    if (params.length !== wanted.length) continue;
    if (params.every((p, k) => p === wanted[k])) return i;
  }
  return -1;
}

/* ------------------------------------------------------------------ *
 * Endpoint / credential extraction
 * ------------------------------------------------------------------ */

const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)\]]+/gi;

/** Classify a URL string: which parts are worth reporting. */
export function classifyUrl(raw) {
  const url = String(raw).trim();
  let host = null, path = null, scheme = null;
  try {
    const u = new URL(url);
    scheme = u.protocol.replace(':', '');
    host = u.hostname;
    path = u.pathname + u.search;
  } catch {
    /* A string that starts like a URL but does not parse is still reported, unparsed —
       silently dropping it is how a real endpoint goes missing. */
    return { url, scheme: null, host: null, path: null, parsed: false };
  }
  return { url, scheme, host, path, parsed: true };
}

/**
 * Decide whether a constant looks like a credential, and produce a safe rendering of it.
 *
 * Two separate questions, deliberately kept separate:
 *   - should this be FLAGGED (it has the shape of a secret)
 *   - what is SAFE TO PRINT (a redaction, never the value)
 *
 * Anything that is flagged is also redacted in the report, so a report can be pasted into a
 * ticket without leaking the thing it found.
 */
const CREDENTIAL_SHAPES = [
  /* The body allows hyphens because every real prefixed key is hyphen-separated
     (sk-lab-..., sk-proj-...). [A-Za-z0-9]{8,} alone stops at the second hyphen and misses
     the most common shape there is. */
  { id: 'prefixed-api-key', re: /\b(?:sk|pk|rk|ak)[-_][A-Za-z0-9][A-Za-z0-9_-]{7,}/ },
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { id: 'pem-private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: 'basic-auth-url', re: /\bhttps?:\/\/[^/\s:@]+:[^/\s:@]+@/i },
  { id: 'bearer-literal', re: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/ },
];

export function redactConstant(value) {
  const s = String(value);
  const hits = CREDENTIAL_SHAPES.filter(c => c.re.test(s));
  if (hits.length === 0) return { flagged: false, shapes: [], display: s, redacted: false };
  /* Keep only a short prefix so two different values remain distinguishable in a report
     without either being reconstructible. */
  const head = s.slice(0, 4);
  return {
    flagged: true,
    shapes: hits.map(h => h.id),
    display: `${head}<redacted ${s.length} chars>`,
    redacted: true,
  };
}

/* ------------------------------------------------------------------ *
 * /proc/self/maps classification — the anti-instrumentation DETECTOR
 * ------------------------------------------------------------------ */

/**
 * Agent module markers. This is a DETECTION list, matching what a process's own maps would
 * reveal about instrumentation loaded into it. It is the answer to "is this app looking at
 * me?", which is a question about our own instrumentation.
 *
 * It is deliberately NOT a bypass list: nothing in this lab hides Frida, unhooks a
 * detection, or makes an app's checks fail to fire.
 */
export const AGENT_MARKERS = ['frida', 'gadget', 'xposed', 'substrate', 'riru', 'zygisk', 'sandhook', 'whale'];

/** Debugger/ptracer markers that are not agent modules but indicate instrumentation. */
export const TRACER_MARKERS = ['TracerPid', '/proc/self/status'];

/**
 * Classify one line of /proc/self/maps.
 * Returns null for an ordinary mapping, which is the overwhelming majority and must not be
 * reported — a detector that lists 400 anonymous mappings has told the analyst nothing.
 */
export function classifyMapsLine(line) {
  const s = String(line);
  if (!s.trim()) return null;
  const lower = s.toLowerCase();
  for (const m of AGENT_MARKERS) {
    if (lower.includes(m)) return { kind: 'agent-module', marker: m, line: s.trim() };
  }
  /* Parsed by shape, not by column index. The kernel format is
       <start>-<end> <perms> <offset> <dev> <inode> <pathname>
     but the inode field is right-aligned to the width of the largest pid on the system, so
     the pathname's byte offset moves from machine to machine. A hardcoded slice(73) lands
     inside the pathname on one host and inside the inode on another, and the check then
     passes on junk while being unable to fire on the thing it exists for. Splitting on
     whitespace runs gets perms and pathname right regardless of inode width. */
  const m = /^\S+\s+(\S{4})\s+\S+\s+\S+\s+\S+\s+(.*)$/.exec(s);
  if (m) {
    const perms = m[1];
    const p = m[2].trim();
    /* perms is [r-][w-][x-][ps]. A plain "r-xp" is an ORDINARY code mapping and must not
       be reported; what is worth surfacing is an executable file mapping outside /system
       and /apex, and especially one that is also WRITABLE. Testing perms[0] === '-' (as an
       earlier version did) rejects every real mapping, because that field is 'r', not '-'. */
    const writable = perms[1] === 'w';
    const executable = perms[2] === 'x';
    if (executable && p && !p.startsWith('[')
        && !p.startsWith('/system/') && !p.startsWith('/apex/')) {
      return {
        kind: writable ? 'writable-exec-mapping' : 'unusual-exec-mapping',
        marker: p.split('/').pop(), line: s.trim(), writable,
      };
    }
  }
  return null;
}

/** Run the detector over a whole maps file. Returns only the interesting lines, sorted. */
export function detectInMaps(mapsText) {
  if (typeof mapsText !== 'string') return { findings: [], scanned: 0, status: 'unavailable' };
  const lines = mapsText.split('\n');
  const findings = [];
  for (const l of lines) {
    const c = classifyMapsLine(l);
    if (c) findings.push(c);
  }
  return { findings, scanned: lines.length, status: 'ok' };
}

/**
 * Interpret /proc/self/status TracerPid.
 * 0  = nothing has ptrace attached  -> clean
 * >0 = a ptracer is attached        -> instrumented
 * -1 = the file could not be read   -> UNKNOWN, never reported as clean
 *
 * Collapsing the unknown case into "clean" is the single most common way an anti-debug
 * check reports a false negative, so it is a distinct return value here.
 */
export function readTracerPid(statusText) {
  if (typeof statusText !== 'string') return { value: -1, state: 'unknown', reason: 'no input' };
  for (const line of statusText.split('\n')) {
    if (!line.startsWith('TracerPid:')) continue;
    const raw = line.slice('TracerPid:'.length).trim();
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n)) return { value: -1, state: 'unknown', reason: `unparseable "${raw}"` };
    if (n === 0) return { value: 0, state: 'clean' };
    return { value: n, state: 'instrumented', reason: `ptracer pid ${n}` };
  }
  return { value: -1, state: 'unknown', reason: 'TracerPid line absent' };
}

/* ------------------------------------------------------------------ *
 * Hook trace formatting
 * ------------------------------------------------------------------ */

/**
 * Format one onEnter/onLeave trace record. Kept pure and kept small: this is the payload a
 * `send()` call carries, so its shape is part of the tool's contract with whatever consumes
 * the trace, and a formatter that needs a live process to be correct is untestable.
 */
export function formatTrace({ event, target, args = [], retval = null, extra = null } = {}) {
  const rec = { event, target };
  if (Array.isArray(args) && args.length) rec.args = args.map(safeString);
  if (retval !== null) rec.retval = safeString(retval);
  if (extra && typeof extra === 'object') rec.extra = extra;
  return rec;
}

/** Never let a Java object's toString() throw inside a hook and kill the hook. */
export function safeString(v) {
  if (v === null || v === undefined) return String(v);
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    return String(v);
  } catch (e) {
    /* A Proxy or a broken Java wrapper can throw here. The hook must survive it. */
    return `<unstringifiable: ${e && e.name ? e.name : 'Error'}>`;
  }
}

/* ------------------------------------------------------------------ *
 * Certificate-pinning pin recognition (used by the hook templates)
 * ------------------------------------------------------------------ */

/** The JCA SPKI pin format. Also the exact shape a pin must have to be worth reporting. */
const PIN_RE = /^sha(?:1|256|384|512)\/[A-Za-z0-9+/]{20,}={0,2}$/;

export function looksLikePin(value) {
  return PIN_RE.test(String(value).trim());
}

/**
 * Normalise a pin for comparison: JCA pins are case-sensitive in their base64 but the
 * algorithm prefix is conventionally lower case, and a real app mixes both. Normalising the
 * prefix only — never the digest — keeps the comparison correct.
 */
export function normalizePin(value) {
  const s = String(value).trim();
  const at = s.indexOf('/');
  if (at < 0) return s;
  return `${s.slice(0, at).toLowerCase()}/${s.slice(at + 1)}`;
}

/** Every pin in a set, deduplicated by normalised form, sorted for stable output. */
export function uniquePins(pins) {
  const seen = new Map();
  for (const p of pins ?? []) {
    const n = normalizePin(p);
    if (!seen.has(n)) seen.set(n, { pin: String(p).trim(), normalized: n, wellFormed: looksLikePin(p) });
  }
  return [...seen.values()].sort((a, b) => a.normalized.localeCompare(b.normalized));
}
