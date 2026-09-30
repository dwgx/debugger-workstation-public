#!/usr/bin/env node
/* rename.mjs — apply a rename map with real scope information.
 *
 * The method's rule for identifier recovery (wiki/methods/web-reverse-method.md,
 * Layer 1): let a model *propose* names, let a deterministic tool *apply* them —
 * never let a model rewrite code. This is that applier.
 *
 *   --list  enumerate renameable bindings with reference counts (the model's input)
 *   --map   apply {"_0x3d92cb": "signingKey", …} through `path.scope.rename`,
 *           which fixes every reference in every scope it is visible from
 *
 * Printing goes through recast, so bytes this tool did not touch come back out
 * unchanged: the diff of a patch is the patch.
 *
 * Usage:
 *   node static/rename.mjs --in recovered.js --list
 *   node static/rename.mjs --in recovered.js --map names.json [--out file] [--dry-run] [--json]
 */
import fs from 'node:fs';
import path from 'node:path';
import * as babelParser from '@babel/parser';
import * as traverseModule from '@babel/traverse';
import * as recast from 'recast';

/* @babel/traverse is CJS; under Node's ESM interop the callable sits at
   namespace.default.default (measured: namespace.default is the module object
   and its own `.default` is the function). */
const TRAVERSE = typeof traverseModule === 'function' ? traverseModule
  : typeof traverseModule.traverse === 'function' ? traverseModule.traverse
    : typeof traverseModule.default === 'function' ? traverseModule.default
      : traverseModule.default?.default;
if (typeof TRAVERSE !== 'function') {
  console.error('rename: could not resolve @babel/traverse — run `npm install` inside web-reverse/static');
  process.exit(2);
}

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const has = (name) => args.includes(name);
if (has('--help') || has('-h') || !flag('--in')) {
  console.log('rename.mjs --in <file> [--list] [--map names.json] [--out file] [--dry-run] [--print] [--json]');
  process.exit(flag('--in') ? 0 : 2);
}
const json = has('--json');
const inFile = path.resolve(flag('--in'));
const source = fs.readFileSync(inFile, 'utf8');

const MINIFIED = /^(_0x[0-9a-fA-F]{2,8}|_$|[a-zA-Z]{1,2}\d?)$/;

function parse(code) {
  return recast.parse(code, {
    parser: {
      parse: (s) => babelParser.parse(s, { sourceType: 'unambiguous', allowReturnOutsideFunction: true, plugins: ['jsx'] })
    }
  });
}

/* --------------------------------------------------------------- --list mode */
if (has('--list') || !flag('--map')) {
  const ast = parse(source);
  const seen = new Map();
  const collect = (scope) => {
    for (const [name, binding] of Object.entries(scope.bindings || {})) {
      if (!binding || binding.kind === 'module') continue;
      const key = `${name}#${binding.scope?.uid ?? '?'}`;
      if (seen.has(key)) continue;
      const refs = (binding.referencePaths || []).length
        + (binding.constantViolations || []).length;
      seen.set(key, {
        name,
        kind: binding.kind,
        constant: !!binding.constant,
        references: refs,
        renameable: MINIFIED.test(name)
      });
    }
  };
  TRAVERSE(ast, {
    Program(p) { collect(p.scope); },
    Function(p) { collect(p.scope); }
  });
  const bindings = [...seen.values()].sort((a, b) => b.references - a.references);
  const renameable = bindings.filter(b => b.renameable);
  const out = {
    file: inFile,
    bytes: Buffer.byteLength(source),
    bindings: bindings.length,
    renameable: renameable.length,
    candidates: renameable.slice(0, 40)
  };
  if (json) console.log(JSON.stringify(out, null, 2));
  else {
    console.log(`rename --list  ${inFile}  (${out.bindings} binding(s), ${out.renameable} still mangled)`);
    for (const c of out.candidates) console.log(`  ${String(c.references).padStart(4)} refs  ${c.name.padEnd(14)} ${c.kind}${c.constant ? ' const' : ''}`);
    console.log(`\nA model proposes { "${out.candidates[0]?.name ?? '_0x…'}": "readableName", … }; this tool applies it with scope-aware renaming.`);
  }
  process.exit(0);
}

/* ---------------------------------------------------------------- --map mode */
const mapFile = path.resolve(flag('--map'));
const rawMap = JSON.parse(fs.readFileSync(mapFile, 'utf8'));
const map = rawMap.renames && typeof rawMap.renames === 'object' ? rawMap.renames : rawMap;
if (typeof map !== 'object' || Array.isArray(map)) {
  console.error('rename: the map must be an object ({"old": "new"}) or {"renames": {...}}');
  process.exit(2);
}

const ast = parse(source);
const applied = [];
const wanted = new Map(Object.entries(map));
TRAVERSE(ast, {
  Scope(p) {
    for (const name of Object.keys(p.scope.bindings || {})) {
      if (!wanted.has(name)) continue;
      const next = wanted.get(name);
      try {
        p.scope.rename(name, next);
        applied.push({ from: name, to: next, scope: p.scope.uid });
      } catch (e) {
        applied.push({ from: name, to: next, error: String(e.message).slice(0, 120) });
      }
      wanted.delete(name);
    }
  }
});

const code = recast.print(ast).code;
const outFile = flag('--out', path.join(path.dirname(inFile), `${path.basename(inFile, path.extname(inFile))}.renamed${path.extname(inFile)}`));
const dryRun = has('--dry-run');
if (!dryRun) fs.writeFileSync(outFile, code);

const report = {
  ok: applied.length > 0,
  file: inFile,
  map: mapFile,
  applied: applied.length,
  unmatchedNames: [...wanted.keys()],
  bytesBefore: Buffer.byteLength(source),
  bytesAfter: Buffer.byteLength(code),
  output: dryRun ? null : outFile
};
if (json) console.log(JSON.stringify(report, null, 2));
else {
  console.log(`rename  ${inFile}  (${report.bytesBefore} -> ${report.bytesAfter} B)`);
  for (const a of applied) console.log(`  ${a.error ? 'FAIL' : 'ok  '}  ${a.from.padEnd(16)} -> ${a.to}${a.error ? `  ${a.error}` : ''}`);
  if (report.unmatchedNames.length) console.log(`  unmatched (no such binding): ${report.unmatchedNames.join(', ')}`);
  console.log(dryRun ? '  dry run: nothing written' : `  written: ${outFile}`);
}
if (has('--print')) process.stdout.write(code.endsWith('\n') ? code : code + '\n');
process.exit(applied.some(a => a.error) ? 3 : 0);
