#!/usr/bin/env node
/* decompile-assembly.mjs -- ONE assembly in, its decompiled method bodies out, as typed JSON.
 *
 * WHY THIS EXISTS. `managed.il.decompile` consumes an `assembly` path_ref and produces
 * `managed.method.code`, but its only entry points were the five per-sample solvers
 * (solve-m01.mjs .. solve-m05.mjs) and loop.mjs, which is a regression suite over its own
 * corpus. loop.mjs says so itself: "it is a regression suite, not a general decompiler
 * driver ... To measure your own assembly, run the solver directly". The solvers, in turn,
 * each know ONE sample's scheme -- solve-m01 looks for `Reveal` and `KeyStream`, which no
 * other assembly has. So a caller with an arbitrary assembly had no argv to run.
 *
 * This wrapper is that argv. It decompiles with the SAME ilspycmd resolution and the SAME
 * spawn helper the solvers use (clrlib.mjs), so there is no second convention for finding
 * the tool or for reading its exit code. It does NOT try to recover a scheme: reading a
 * specific obfuscation is what the per-sample solvers are for, and pretending otherwise
 * would be the "confident answer" the entry's own does_not_prove warns about.
 *
 *   node managed-lab/tools/decompile-assembly.mjs --asm out/m01/m01_stringobf.dll
 *   node managed-lab/tools/decompile-assembly.mjs --asm <any.dll> --method Reveal
 *   node managed-lab/tools/decompile-assembly.mjs --asm <any.dll> --list
 *
 * STDOUT IS ONE JSON OBJECT. Diagnostics go to stderr; mission.ps1 merges the streams.
 *
 * Exit: 0 decompiled, 1 refused (bad argv, no such assembly, method not found), 2 could not run.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ILSPYCMD, decompile, method } from './clrlib.mjs';

const args = process.argv.slice(2);
const get = (flag, dflt) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : dflt; };
const has = flag => args.includes(flag);

const KNOWN = new Set(['--asm', '--method', '--max-chars', '--list']);
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--list') continue;
  if (KNOWN.has(a)) { i += 1; continue; }
  emit({ ok: false, exit: 2, error: `unrecognised argument: ${a}`,
         note: 'An argument this wrapper ignores would report a decompilation nobody did.' }, 2);
}

const asmArg = get('--asm', null);
if (!asmArg) emit({ ok: false, exit: 2, error: 'usage: decompile-assembly.mjs --asm <assembly> [--method NAME] [--list]' }, 2);
/* ABSOLUTE, before anything else. clrlib's run() sets cwd to LAB_ROOT (managed-lab/), so a
 * caller's relative path would be resolved from the wrong directory -- measured:
 * "managed-lab/managed-lab/out/m01/m01_stringobf.dll does not exist". The registry passes
 * repo-relative paths, which are relative to the CALLER's cwd. */
const asm = path.resolve(asmArg);
if (!fs.existsSync(asm)) emit({ ok: false, exit: 1, error: `no such assembly: ${asm}` }, 1);
if (!fs.existsSync(ILSPYCMD)) {
  emit({ ok: false, exit: 2, error: `ilspycmd not found at ${ILSPYCMD}`,
         note: 'Set MANAGED_LAB_ILSPY or install ilspycmd under Static-Reversing/ilspycmd/.' }, 2);
}

/* ILSpy writes a C# source file. Method bodies are extracted from THAT text -- the same
 * brace-matched `method()` the solvers use -- so a name is only ever reported when the
 * decompiler actually emitted it. */
let src;
try {
  src = await decompile(asm);
} catch (e) {
  emit({ ok: false, exit: 2, error: `ilspycmd failed: ${e && e.message ? e.message : e}`, assembly: asm }, 2);
}
if (!src || !src.trim()) {
  emit({ ok: false, exit: 2, error: 'ilspycmd produced no source', assembly: asm }, 2);
}

/* Declaration scan. Modifier-anchored on purpose: a bare `Foo(` also matches a CALL, and a
 * call site is not a declaration. */
const DECL = /(?:^|\n)\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\b[^;=\n{]*?\b([A-Za-z_]\w*)\s*\(/g;
const names = [...new Set([...src.matchAll(DECL)].map((m) => m[1]))].filter((n) => method(src, n));

if (names.length === 0) {
  emit({ ok: false, exit: 2, error: 'no method declarations recovered from the decompilation', assembly: asm }, 2);
}

if (has('--list')) {
  emit({ ok: true, exit: 0, assembly: asm, count: names.length, methods: names }, 0);
}

const wanted = get('--method', null);
let chosen;
if (wanted) {
  if (!method(src, wanted)) {
    emit({ ok: false, exit: 1, error: `method not found in the decompilation: ${wanted}`,
           assembly: asm, methods_available: names }, 1);
  }
  chosen = wanted;
} else {
  /* No name given: take the LONGEST body, and say that this is the rule. A first-declared
   * rule would pick a constructor or a property getter on most assemblies, which is a
   * "confident answer" about the wrong method. */
  chosen = names.map((n) => ({ n, len: method(src, n).length })).sort((a, b) => b.len - a.len)[0].n;
}

const body = method(src, chosen);
const maxChars = Number(get('--max-chars', 0)) || 0;
const code = maxChars > 0 && body.length > maxChars ? body.slice(0, maxChars) : body;

emit({
  ok: true,
  exit: 0,
  assembly: path.resolve(asm),
  method: chosen,
  technique: 'ilspycmd decompilation of the assembly; method body brace-matched out of the emitted C#. The target is READ, never executed.',
  selection: wanted ? 'named by --method' : 'longest recovered method body (no --method given)',
  method_count: names.length,
  methods: names,
  code,
  truncated: code.length !== body.length,
  caveat: 'This is the DECOMPILER output, not a recovered scheme. A body that looks like a ' +
          'decryption routine has not been shown to decrypt anything -- the entry\'s ' +
          'does_not_prove says so, and the per-sample solvers are what close that gap by ' +
          'feeding the answer back to the binary.'
}, 0);

function emit(obj, code_) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
  process.exit(code_);
}
