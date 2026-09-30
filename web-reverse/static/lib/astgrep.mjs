/* astgrep.mjs — locate and drive the @ast-grep/cli binary.
 *
 * The npm package ships a per-platform binary in an optional dependency and a
 * JS `bin` shim that the postinstall step links. Under an install policy that
 * skips install scripts (npm 11's `allowScripts` gate — measured on this box:
 * `@ast-grep/cli` postinstall not run) the shim is missing while the real
 * executable is installed, so resolve the executable itself instead of the shim.
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export function astGrepBin() {
  const pkgDir = path.dirname(require.resolve('@ast-grep/cli/package.json'));
  const candidates = process.platform === 'win32'
    ? ['ast-grep.exe', 'sg.exe']
    : ['ast-grep', 'sg'];
  for (const name of candidates) {
    const file = path.join(pkgDir, name);
    if (fs.existsSync(file)) return file;
  }
  const shim = path.join(pkgDir, '..', '..', '.bin', process.platform === 'win32' ? 'ast-grep.cmd' : 'ast-grep');
  if (fs.existsSync(shim)) return shim;
  throw new Error('@ast-grep/cli binary not found; run `npm install` inside web-reverse/static');
}

export function runAstGrep(args, { input = null, cwd = process.cwd() } = {}) {
  const bin = astGrepBin();
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('error', reject);
    child.on('close', code => resolve({ code, out, err, bin }));
    if (input !== null) child.stdin.end(input); else child.stdin.end();
  });
}
