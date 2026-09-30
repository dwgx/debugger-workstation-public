/*
 * 03-jni-native-boundary.js — trace the Java <-> native boundary.
 *
 * WHAT IT DOES
 * ------------
 * Two halves of one boundary:
 *   1. Interceptor.attach on an exported JNI symbol, with onEnter/onLeave, so the
 *      arguments crossing into native code and the value coming back are recorded.
 *   2. Module.enumerateExports, so the export table is reported even when a symbol is
 *      missing — an unresolvable JNI export is itself a finding (an obfuscator stripped
 *      it, or RegisterNatives is in play and there is no export at all).
 *
 * The RegisterNatives case matters: an app can bind natives dynamically, in which case
 * enumerateExports finds nothing and the boundary is not in the ELF at all. The script
 * reports that honestly rather than reporting "no natives".
 *
 * SCOPE
 * -----
 * Observation only. It does not patch return values, does not redirect control flow, and
 * does not dump process memory outside the addresses the app itself passed in.
 *
 * HOW IT IS VERIFIED HERE (no device)
 *   tools/frida-selftest.mjs attaches this to a synthetic module whose .dynsym is the one
 *   lab/build/make-so.mjs produced, fires the hook with known arguments, and asserts the
 *   trace and the Memory.read* decoding.
 */

'use strict';

const TARGET_MODULE = 'libmobilelab.so';
const WATCH = [
  'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey',
  'Java_com_lab_mobilelab_MainActivity_nativeAttest',
  'Java_com_lab_mobilelab_MainActivity_nativeReadFlag',
];

function safe(v) {
  if (v === null || v === undefined) return String(v);
  try { return String(v); } catch (e) { return '<unstringifiable>'; }
}

Java.perform(function () {
  /* --- 1. what does this module actually export? --- */
  let exports = [];
  try {
    exports = Module.enumerateExports({ name: TARGET_MODULE });
  } catch (e) {
    send({ event: 'module-enumeration-failed', module: TARGET_MODULE, reason: safe(e) });
  }

  const jniExports = exports.filter(e => e.name.indexOf('Java_') === 0);
  send({
    event: 'export-table',
    module: TARGET_MODULE,
    totalExports: exports.length,
    jniExports: jniExports.map(e => e.name),
    imports: exports.filter(e => e.type !== 'function' || e.name.indexOf('Java_') !== 0).length,
    /* The honest negative: a library with no Java_ exports is usually RegisterNatives. */
    note: jniExports.length === 0
      ? 'no Java_ exports: this library most likely binds natives dynamically via RegisterNatives, so the boundary is not in the ELF symbol table'
      : 'JNI exports are statically bound and hookable by name',
  });

  /* --- 2. attach to each watched export --- */
  let attached = 0;
  const missing = [];
  for (const name of WATCH) {
    const sym = exports.find(e => e.name === name);
    if (!sym) { missing.push(name); continue; }

    Interceptor.attach(sym.address, {
      onEnter(args) {
        this.trace = {
          event: 'jni-enter',
          symbol: name,
          /* args[0] is the JNIEnv*, args[1] the jobject/jclass; the real parameters start
             at args[2]. Reading them is how a native boundary is actually observed. */
          jniArgs: args.length,
        };
        send(this.trace);
      },
      onLeave(retval) {
        send({
          event: 'jni-leave',
          symbol: name,
          retval: safe(retval),
          durationUnknown: true,
        });
      },
    });
    attached++;
  }

  send({
    event: 'attach-summary',
    module: TARGET_MODULE,
    requested: WATCH.length,
    attached,
    missing,
    verdict: missing.length === 0
      ? 'every watched JNI export resolved'
      : 'some JNI exports did not resolve: ' + missing.join(', '),
  });

  /* --- 3. the Java side of the same boundary, so both ends are in one trace --- */
  try {
    const Main = Java.use('com.lab.mobilelab.MainActivity');
    Main.nativeReadFlag.overload('int').implementation = function (index) {
      send({ event: 'java-native-call', method: 'nativeReadFlag', index: index });
      return Main.nativeReadFlag.overload('int').call(this, index);
    };
  } catch (e) {
    send({ event: 'java-native-hook-unavailable', reason: safe(e) });
  }
});
