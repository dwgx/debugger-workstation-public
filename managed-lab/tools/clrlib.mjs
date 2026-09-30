/* clrlib.mjs -- shared plumbing for the managed-lab solvers.
 *
 * Three things live here and nowhere else:
 *
 *   1. where the tools are (so no solver hard-codes a path), and `run()`;
 *   2. `method()` / `braces()` -- pull a method body out of decompiled C# by
 *      brace matching, so a solver can work on one function instead of the file;
 *   3. `evalCsharp()` -- turn a C# integer expression out of that body into a
 *      value, with an allow-list that rejects anything that is not arithmetic.
 *
 * The point of (3) is that no solver in this lab hard-codes a constant that
 * lives in a sample. Every key, seed, length, offset multiplier and checksum
 * prime is read out of the decompilation and evaluated. If a sample changes, the
 * solver follows; if a solver is wrong, the runner's comparison against the
 * sample's own output catches it.
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LAB_ROOT = path.resolve(HERE, '..');
export const OUT = path.join(LAB_ROOT, 'out');

const STATION = process.env.DEBUGGER_STATION || path.resolve(LAB_ROOT, '..');

/** Locate a file inside the station tree, preferring an explicit env override. */
export function tool(envName, segments) {
  if (process.env[envName] && fs.existsSync(process.env[envName])) return process.env[envName];
  const p = path.join(STATION, ...segments);
  if (!fs.existsSync(p)) throw new Error(`clrlib: tool not found (${envName}): ${p}`);
  return p;
}

export const ILSPYCMD = tool('MANAGED_LAB_ILSPY', ['Static-Reversing', 'ilspycmd', 'ilspycmd.exe']);
export const RADARE2 = tool('MANAGED_LAB_R2', ['Static-Reversing', 'radare2', 'radare2-6.2.2-w64', 'bin', 'radare2.exe']);
export const RABIN2 = tool('MANAGED_LAB_RABIN2', ['Static-Reversing', 'radare2', 'radare2-6.2.2-w64', 'bin', 'rabin2.exe']);

/** Spawn and collect. Never throws on a non-zero exit; the caller decides. */
export function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: opts.cwd || LAB_ROOT, windowsHide: true, env: process.env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => resolve({ code: -1, stdout, stderr, error: e.message }));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/* ------------------------------------------------------------------ ilspycmd */

/** `ilspycmd <args...> <assembly>` -- decompile, list resources, extract, whatever. */
export async function ilspy(args, asm) {
  const r = await run(ILSPYCMD, ['--disable-updatecheck', ...args, asm]);
  if (r.code !== 0) {
    const tail = (r.stderr || r.error || '').trim().split('\n').slice(-4).join('\n');
    throw new Error(`ilspycmd exited ${r.code} for ${asm}\n${tail}`);
  }
  return r.stdout;
}

/** Decompile a whole assembly to C# text. */
export async function decompile(asm) {
  return ilspy([], asm);
}

/* ---------------------------------------------------------- C# source poking */

/** Index of the `}` that closes the `{` at or after `open` (-1 if unbalanced). */
export function braces(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Body of `name(...)` in `src`, brace matched. Returns '' when not found --
 * a missing method is a normal outcome for a solver that probes.
 */
export function method(src, name) {
  const m = new RegExp(`\\b${name}\\s*\\(([^)]*)\\)\\s*(?:where[^{]*)?\\{`).exec(src);
  if (!m) return '';
  const open = src.indexOf('{', m.index + m[0].length - 1);
  const close = braces(src, open);
  return close < 0 ? '' : src.slice(open + 1, close);
}

/** Parameter names of the first `name(...)` declaration in `src`. */
export function params(src, name) {
  const m = new RegExp(`\\b${name}\\s*\\(([^)]*)\\)`).exec(src);
  if (!m) return [];
  return m[1].split(',').map((s) => s.trim().split(/\s+/).pop()).filter(Boolean);
}

/** The single `return <expr>;` of a method body, with the trailing `;` removed. */
export function returnExpr(body) {
  const m = /\breturn\b([^;]*);/.exec(body);
  return m ? m[1].trim() : '';
}

const CSHARP_OK = /^[0-9a-fA-FxXuUlL+\-*/%()<>&|^!~.=\[\]'"\s]*$/;

/**
 * Evaluate a C# integer/boolean expression with `env` supplying identifiers.
 *
 * Deliberately narrow. The character allow-list has no letters in it other than
 * the `x`/`u`/`l` literal suffixes, so identifiers, `constructor`, `Math`,
 * template literals and property access all fail closed. `&&`, `||`, `!` and
 * `^` mean the same thing in JS; only `==`/`!=` are rewritten so that a single
 * `=` cannot smuggle an assignment into the generated function.
 */
export function evalCsharp(expr, env = {}) {
  let js = expr;
  for (const [name, value] of Object.entries(env)) {
    js = js.split(name).join(`(${value})`);
  }
  js = js
    .replace(/uint\.MaxValue/g, '4294967295')
    .replace(/int\.MaxValue/g, '2147483647')
    .replace(/!=(?!=)/g, '!==')
    .replace(/(?<![=!])==(?!=)/g, '===')
    .replace(/<>/g, '!==');
  if (!CSHARP_OK.test(js)) throw new Error(`evalCsharp: refusing to evaluate \`${expr}\` (as \`${js}\`)`);
  if (/[^=!<>]=(?!=)/.test(js)) throw new Error(`evalCsharp: assignment in \`${expr}\``);
  // eslint-disable-next-line no-new-func
  return Function('"use strict";return (' + js + ')')();
}

/** A C# numeric literal (decimal or 0x, any u/l suffix) as a JS number. */
export function num(text) {
  const t = String(text).trim().replace(/[uUlL]+$/, '');
  if (/^0[xX]/.test(t)) return parseInt(t.slice(2), 16);
  return parseInt(t, 10);
}

/* ------------------------------------------------------------------- r2 I/O */

/** `rabin2 -Ej <file>` -- the export table, as `{name, vaddr, ...}` records. */
export async function exportsOf(dll) {
  const r = await run(RABIN2, ['-Ej', dll]);
  if (r.code !== 0) throw new Error(`rabin2 -Ej failed: ${r.stderr.trim()}`);
  const doc = JSON.parse(r.stdout);
  return Array.isArray(doc) ? doc : doc.exports || [];
}

/** Read `n` raw bytes at a virtual address through r2's loader. */
export async function readVa(dll, va, n) {
  const r = await run(RADARE2, ['-q', '-c', `pxj ${n} @ ${va}`, dll]);
  if (r.code !== 0) throw new Error(`r2 pxj failed: ${r.stderr.trim()}`);
  const line = r.stdout.split('\n').find((l) => l.trim().startsWith('['));
  if (!line) throw new Error(`r2 pxj produced no array: ${r.stdout.slice(0, 200)}`);
  return Buffer.from(JSON.parse(line).map((b) => b & 0xff));
}

/* ---------------------------------------------------------------- arg parsing */

export function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

export function flag(name) {
  return process.argv.includes(`--${name}`);
}

/**
 * Shared exit protocol.
 *
 *   --expect <v>   the known answer; a mismatch exits 4 and says so
 *   --json         machine-readable result on stdout
 *
 * Three exit codes, and the third one is the point:
 *
 *   0  the analysis ran and the answer is the expected one
 *   4  the analysis ran and the answer is wrong (wrong --expect, or the
 *      solver's own validity check failed, e.g. the "plaintext" is not text)
 *   1  the analysis could not run -- a required piece was missing
 *
 * Splitting 4 from 1 is what makes a negative control meaningful. The control
 * asserts 4, so a solver that returned garbage without complaining, or one that
 * gave up before looking, both fail the control instead of passing quietly.
 */
export function finish(result, { expect, expectName = 'answer' } = {}) {
  const answer = result.answer;
  const ran = result.ran !== false;
  const valid = result.valid !== false;
  let matched = true;
  let why = '';
  if (expect !== undefined) {
    matched = answer === expect;
    why = matched ? '' : `${expectName}: got \`${answer}\`, expected \`${expect}\``;
  }
  const ok = ran && valid && matched;
  if (flag('json')) {
    process.stdout.write(`${JSON.stringify({ ...result, ran, valid, ok, expect: expect ?? null, why })}\n`);
  } else {
    for (const [k, v] of Object.entries(result)) {
      if (k === 'answer' || v === undefined || v === null) continue;
      process.stdout.write(`${k.padEnd(11)} ${Array.isArray(v) ? v.join('  |  ') : v}\n`);
    }
    process.stdout.write(`${'answer'.padEnd(11)} ${answer}\n`);
    if (why) process.stderr.write(`MISMATCH ${why}\n`);
  }
  process.exit(ok ? 0 : (ran ? 4 : 1));
}
