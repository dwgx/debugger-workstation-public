#!/usr/bin/env node
/* sg.mjs — surgical one-pattern rewrites over the @ast-grep/cli binary.
 *
 * Broad tools (webcrack, wakaru) are non-surgical: they hand back a whole new
 * file. ast-grep is the one to reach for when the finding is "replace this exact
 * shape" — one pattern, one reviewable diff. Default is a dry run that shows the
 * matches; `--apply` is opt-in, because rewriting a file is the thing you want to
 * look at first.
 *
 * Usage:
 *   node static/sg.mjs --pattern 'foo($X)' [--rewrite 'bar($X)'] [--lang js] <file...>
 *   node static/sg.mjs --pattern 'foo($X)' --rewrite 'bar($X)' --apply <file...>
 *   node static/sg.mjs -- raw-ast-grep-args...
 */
import { runAstGrep } from './lib/astgrep.mjs';

const argv = process.argv.slice(2);
if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
  console.log(`sg.mjs — one pattern, one reviewable diff (wraps @ast-grep/cli)

  node static/sg.mjs --pattern 'foo($X)' [--rewrite 'bar($X)'] [--lang js] [--apply] <file...>
  node static/sg.mjs -- <raw ast-grep args>        # escape hatch for anything else

  --pattern   ast-grep pattern ($X = one node, $$$ARGS = variadic)
  --rewrite   replacement pattern; without it this is a search
  --lang      js (default), ts, html, json, …      --apply  write the rewrite in place`);
  process.exit(0);
}

/* Reject binary/oversized inputs before ast-grep sees them: the lab rewrites JS,
   and the flag exists so a mistyped path cannot hand the tool a sample. */
if (argv[0] === '--') {
  const args = argv.slice(1);
  const r = await runAstGrep(args);
  process.stdout.write(r.out);
  process.stderr.write(r.err);
  console.error(`sg: raw ast-grep ${args.join(' ')} -> exit ${r.code}`);
  process.exit(r.code);
}

const get = (name, fallback) => {
  const i = argv.indexOf(name);
  if (i < 0) return fallback;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith('--')) {
    console.error(`sg: ${name} needs a value`);
    process.exit(2);
  }
  return v;
};

const pattern = get('--pattern', null);
const rewrite = get('--rewrite', null);
const lang = get('--lang', 'js');
const apply = argv.includes('--apply');
const files = argv.filter(a => !a.startsWith('--') && a !== pattern && a !== rewrite && a !== lang);

if (!pattern || files.length === 0) {
  console.error('sg: need --pattern <pattern> and at least one file (see --help)');
  process.exit(2);
}

const base = ['run', '--pattern', pattern, '--lang', lang];
if (rewrite) base.push('--rewrite', rewrite);
if (apply) {
  if (!rewrite) { console.error('sg: --apply needs --rewrite'); process.exit(2); }
  base.push('--update-all');
}
const r = await runAstGrep([...base, ...files]);
process.stdout.write(r.out);
process.stderr.write(r.err);
if (!apply) console.log(`sg: dry run (${r.code === 0 ? 'matches found' : `exit ${r.code}`}) — re-run with --apply to write the rewrite`);
process.exit(r.code);
