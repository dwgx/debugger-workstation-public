/*
 * frida-emulator.mjs — a small, honest Frida runtime model.
 *
 * WHAT THIS IS
 * ------------
 * A stand-in for the globals a Frida script sees inside a target process: Java.use /
 * .overload / .implementation, Interceptor.attach with onEnter/onLeave, Module.enumerate
 * Exports, Memory.readByteArray, NativePointer, and send(). It lets a hook script be
 * EXECUTED and its trace output asserted, on a machine with no device.
 *
 * WHAT THIS IS NOT — read this before trusting a pass
 * ----------------------------------------------------
 * It is a model, not Frida. A green result here proves:
 *     - the script parses and runs
 *     - it selects the overload it intended to select
 *     - its onEnter/onLeave ordering, argument marshalling and send() payloads are correct
 *     - its pure decision logic is correct on the given inputs
 * It does NOT prove:
 *     - that the real ART accepts the script (obfuscated/renamed members, hidden API limits)
 *     - that the real Interceptor trampoline behaves like the model's
 *     - anything about timing, threads, or a live TLS stack
 * Every report this lab emits says so in its `limits` field. The emulator is how a script
 * gets to "reviewed and logic-verified" without a phone; it is not a substitute for one.
 *
 * The model is deliberately thin. It emulates dispatch and data flow, not ART.
 */

import vm from 'node:vm';

/** A NativePointer-alike: an address plus a readable backing buffer. */
class FakePointer {
  constructor(address, buffer, offset = 0) {
    this.address = address >>> 0;
    this._buf = buffer;
    this._off = offset;
  }
  toString() { return `0x${this.address.toString(16)}`; }
  add(n) { return new FakePointer(this.address + n, this._buf, this._off + n); }
  readU8() { return this._buf[this._off]; }
  readU16() { return this._buf.readUInt16LE(this._off); }
  readU32() { return this._buf.readUInt32LE(this._off); }
  readByteArray(n) { return this._buf.subarray(this._off, this._off + n); }
  readUtf8String(n) { return this._buf.toString('utf8', this._off, this._off + (n ?? this._buf.length - this._off)); }
  isNull() { return this.address === 0; }
}

/**
 * Build the Frida global environment.
 *
 * @param spec.targets  { 'com.example.Class': { methods: { name: { overloads: [...],
 *                              static?: bool } } } }
 * @param spec.modules  [ { name, base, exports: [{name, address, type}] } ]
 * @param spec.memory   Buffer backing FakePointer reads
 */
export function createFridaEnv(spec = {}) {
  const targets = spec.targets ?? {};
  const modules = spec.modules ?? [];
  const memory = spec.memory ?? Buffer.alloc(0x1000);
  const sent = [];
  const installed = [];
  const errors = [];

  /* ---- Java ---- */
  const makeClass = (className) => {
    const def = targets[className];
    if (!def) {
      errors.push({ kind: 'class-not-found', className });
      /* Frida returns a wrapper whose every access throws ClassNotFoundException. Modelling
         it as a hard throw is what makes a typo'd class name fail loudly instead of
         silently producing an empty hook list. */
      const missing = new Proxy({}, {
        get(_t, prop) {
          if (prop === 'overload') {
            return () => { throw new Error(`ClassNotFoundException: ${className}`); };
          }
          throw new Error(`ClassNotFoundException: ${className}.${String(prop)}`);
        },
      });
      return missing;
    }

    const wrapper = { $className: className };

    for (const [name, m] of Object.entries(def.methods ?? {})) {
      /* Each METHOD carries its own overload registry, because that is the shape scripts
         actually use: `Klass.method.overload(...).implementation = fn`. Putting .overload on
         the class wrapper alone leaves `method.overload` undefined, the assignment throws,
         the script's try/catch swallows it, and the hook silently never installs — the
         worst possible failure, because the script still reports that it loaded. */
      const overloads = {};
      const declared = m.overloads ?? [];

      const fn = function (...args) {
        /* Dispatch by arity to the overload whose implementation the script installed. */
        const hit = Object.values(overloads)
          .find(o => o.implementation && o.types.length === args.length);
        if (!hit) return { $unhooked: true, method: name, argc: args.length };
        const rv = hit.implementation.apply(Object.assign({}, this, args), args);
        return { $hooked: true, method: name, signature: hit.types.join(','), retval: rv };
      };

      fn.$className = className;
      fn.$methodName = name;
      fn.$overloads = overloads;
      fn.overload = (...types) => {
        const key = types.join(',');
        if (declared.length && !declared.includes(key)) {
          errors.push({ kind: 'overload-not-found', className, method: name, signature: key, known: declared });
          throw new Error(`NoSuchMethodError: ${className}.${name}.overload(${key}); declared: ${declared.join(' | ')}`);
        }
        /* `original` is what was in place before the script replaced the implementation.
           `.call()` invokes it, which is how a Frida hook reaches the original method. */
        const rec = { types, implementation: null, original: overloads[key]?.original ?? null };
        rec.call = function (thisArg, ...args) {
          return typeof rec.original === 'function' ? rec.original.apply(thisArg, args) : undefined;
        };
        overloads[key] = rec;
        return rec;
      };

      wrapper[name] = fn;
    }
    return wrapper;
  };

  const javaUseCache = new Map();

  const Java = {
    available: true,
    use(className) {
      if (!javaUseCache.has(className)) javaUseCache.set(className, makeClass(className));
      return javaUseCache.get(className);
    },
    perform(fn) { fn(); },
    performNow(fn) { fn(); },
    /* Some scripts probe these; modelling them keeps the branch honest. */
    get classFactory() { return { use: c => Java.use(c) }; },
  };

  /* ---- Interceptor ---- */
  const Interceptor = {
    attach(target, callbacks = {}) {
      const addr = typeof target === 'string' ? target : String(target);
      const record = { kind: 'attach', target: addr, callbacks, onEnter: !!callbacks.onEnter, onLeave: !!callbacks.onLeave };
      installed.push(record);
      return {
        detach() { record.detached = true; },
        /* Models one invocation crossing the trampoline: onEnter, then onLeave. */
        _fire(invocation = {}) {
          const state = { context: { pc: addr, retval: null, sp: 0x7ff000 }, args: invocation.args ?? [] };
          if (callbacks.onEnter) callbacks.onEnter.call(state, state.args, state.context);
          const rv = callbacks.onLeave ? callbacks.onLeave.call(state, state.retval, state.context) : undefined;
          return { entered: !!callbacks.onEnter, left: !!callbacks.onLeave, retval: rv };
        },
      };
    },
    replace() { throw new Error('Interceptor.replace is not modelled'); },
    flush() { },
  };

  /* ---- Module / Process / Memory ---- */
  const Module = {
    enumerateExports(spec) {
      if (spec && spec.name) {
        const m = modules.find(x => x.name === spec.name);
        return (m?.exports ?? []).map(e => ({ name: e.name, address: `0x${(e.address ?? 0).toString(16)}`, type: e.type ?? 'function' }));
      }
      return modules.flatMap(m => m.exports.map(e => ({
        name: e.name,
        address: `0x${(e.address ?? 0).toString(16)}`,
        type: e.type ?? 'function',
        module: m.name,
      })));
    },
    findExportByName(name, sym) {
      const all = Module.enumerateExports(name);
      return all.find(e => e.name === sym) ?? null;
    },
    findBaseAddress(name) {
      const m = modules.find(x => x.name === name);
      return m ? `0x${(m.base ?? 0).toString(16)}` : null;
    },
    getExportByName: null,
  };

  const Memory = {
    readByteArray(p, n) { return p instanceof FakePointer ? p.readByteArray(n) : null; },
    readUtf8String(p, n) { return p instanceof FakePointer ? p.readUtf8String(n) : null; },
    readU32(p) { return p instanceof FakePointer ? p.readU32() : 0; },
    readU8(p) { return p instanceof FakePointer ? p.readU8() : 0; },
    scan() { return []; },
  };

  const env = {
    Java, Interceptor, Module, Memory,
    Process: { id: 4242, arch: 'arm64', platform: 'android' },
    send(payload) { sent.push(payload); },
    recv() { },
    console,
    ptr(address, backing) { return new FakePointer(address, backing ?? memory); },
    NativePointer: FakePointer,
    setImmediate(fn) { fn(); },
    setTimeout(fn) { fn(); },
  };

  return {
    env,
    sent,
    installed,
    errors,
    FakePointer,
    /** Run a script body as if it were `frida -l script.js`. */
    run(source, filename = 'hook.js') {
      const ctx = vm.createContext(env);
      const wrapped = `"use strict";\n${source}\n//# sourceURL=${filename}`;
      return vm.runInContext(wrapped, ctx, { filename, timeout: 10000 });
    },
    /**
     * Fire an installed Interceptor hook the way the real trampoline would: onEnter, then
     * onLeave, on the same `this` context. Returns the record so a test can assert on the
     * trace the script produced.
     */
    fire(target, invocation = {}) {
      const rec = installed.find(i => i.target === target || i.target.endsWith(target));
      if (!rec) return null;
      const cb = rec.callbacks ?? {};
      const state = { context: { pc: rec.target, retval: null, sp: 0x7ff000 }, args: invocation.args ?? [] };
      if (cb.onEnter) cb.onEnter.call(state, state.args, state.context);
      const rv = cb.onLeave ? cb.onLeave.call(state, state.retval, state.context) : undefined;
      return { record: rec, retval: rv, entered: !!cb.onEnter, left: !!cb.onLeave };
    },
  };
}

export { FakePointer };
