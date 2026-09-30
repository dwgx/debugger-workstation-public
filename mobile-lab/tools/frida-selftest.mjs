#!/usr/bin/env node
/*
 * frida-selftest.mjs — run the Frida offline suite and print its table.
 *
 * The cases live in tools/frida-selftest-lib.mjs so tools/loop.mjs can count them as one
 * step of the bigger loop. This file is only the CLI around them.
 *
 * Exit: 0 = all cases passed, 9 = at least one failed.
 */
import { runFridaSelfTest } from './frida-selftest-lib.mjs';

console.log('mobile-lab — Frida script library, offline validation');
console.log('  emulator: a model of the Frida runtime, NOT Frida. See frida/lib/frida-emulator.mjs');
console.log('');

const { results, failures } = runFridaSelfTest();

for (const r of results) {
  console.log(`  ${r.pass ? 'PASS' : 'FAIL'}  ${r.name}`);
  if (r.detail) console.log(`        ${r.detail}`);
}

console.log('');
if (failures === 0) {
  console.log(`FRIDA LOGIC VERIFIED: ${results.length} case(s) passed with no device attached.`);
  console.log('  Proven:    script logic, overload selection, hook ordering, trace payloads,');
  console.log('             static API validation, and a detector that fails when it must.');
  console.log('  NOT proven: that ART accepts these scripts, that the real Interceptor trampoline');
  console.log('             behaves like the model, or anything requiring a live process.');
} else {
  console.log(`${failures} case(s) FAILED.`);
}
process.exit(failures === 0 ? 0 : 9);
