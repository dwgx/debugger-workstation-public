#!/usr/bin/env node
/* loop.mjs -- the whole managed-RE proof in one command, self-judging.
 *
 *   node tools/loop.mjs
 *
 * Four sections, in the order an analyst would actually work:
 *
 *   1. TOOLS + BUILD      the inventory, and a build if any sample is missing
 *   2. SOLVE + CROSSCHECK each solver runs against the known answer, and then its
 *                         result is compared against the SAMPLE'S OWN OUTPUT.
 *                         Two sources, one of which never saw the decompilation.
 *   3. IL                 the headless IL path, asserted rather than described:
 *                         the strings, the opaque predicates, the integrity
 *                         constants and the pinvoke are each found in raw IL
 *   4. CONTROLS           every solver is re-run in the mode that breaks it, and
 *                         the runner requires a non-zero exit each time
 *
 * Exit 0 means all of that held on this machine, in this run.
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ILSPYCMD, LAB_ROOT, OUT, run } from './clrlib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATION = path.resolve(LAB_ROOT, '..');
const wantJson = process.argv.includes('--json');

/* ------------------------------------------------------------------ the corpus */

const CORPUS = [
  {
    id: 'm01', dir: 'm01', asm: 'm01_stringobf.dll', exe: 'm01_stringobf.exe',
    technique: 'string encryption -- per-index keystream XOR + odd-index byte swap',
    solver: 'solve-m01.mjs', args: ['--asm', '@asm'],
    expect: 'the quick brown fox jumps over the lazy dog',
    controls: [{ name: 'layers applied in the wrong order', args: ['--wrong-order'] }],
  },
  {
    id: 'm02', dir: 'm02', asm: 'm02_flatten.dll', exe: 'm02_flatten.exe',
    technique: 'control-flow flattening + opaque predicates + a decoy block',
    solver: 'solve-m02.mjs', args: ['--asm', '@asm'],
    expect: 'dbb9c662',
    controls: [
      { name: 'dead edges trusted (naive case-body parse)', args: ['--ignore-opaque'] },
      { name: 'wrong entry state (a complete, confident, wrong answer)', args: ['--entry', '43'] },
    ],
  },
  {
    id: 'm03', dir: 'm03', asm: 'm03_resource.dll', exe: 'm03_resource.exe',
    technique: 'base64 payload in an embedded resource, seed derived from the resource name',
    solver: 'solve-m03.mjs', args: ['--asm', '@asm'],
    expect: 'ae5ee44b7f198f47106fd52f1d17f72e804144598480c90ebe302d53d1300f24',
    controls: [{ name: 'resource extracted but left masked', args: ['--skip-mask'] }],
  },
  {
    id: 'm04', dir: 'm04', asm: 'm04_struct.dll', exe: 'm04_struct.exe',
    technique: 'hand-rolled 16-byte header + length-prefixed records, FNV-1a/32, 4-byte aligned',
    solver: 'solve-m04.mjs', args: ['--dat', '@dat'],
    expect: [
      'MSTR v3 records=5 total=0x00000080 hdrcheck=0x59a863b9',
      '[0] @0x0010 kind=1 flags=0x01 id=0x0001 len=27 check=0x3761b960 ascii="license-check: fails closed"',
      '[1] @0x0038 kind=2 flags=0x00 id=0x0002 len=4 check=0x06ff67ff u32=0x000004d2',
      '[2] @0x0048 kind=3 flags=0x02 id=0x0003 len=8 check=0x842f3f33 hex=0011223344556677',
      '[3] @0x005c kind=1 flags=0x00 id=0x0100 len=7 check=0x50971b81 ascii="stage=2"',
      '[4] @0x0070 kind=2 flags=0x03 id=0x0200 len=4 check=0xd7252efe u32=0xdeadbeef',
    ].join('\n'),
    controls: [
      { name: 'CRC32 substituted for the recovered FNV-1a/32', args: ['--crc32'] },
      { name: 'alignment padding ignored', args: ['--no-align'] },
    ],
  },
  {
    id: 'm05', dir: 'm05', asm: 'm05_bridge.dll', exe: 'm05_bridge.exe',
    technique: 'P/Invoke boundary: the answer is in the DLL, not in the managed code',
    solver: 'solve-m05.mjs', args: ['--asm', '@asm', '--ghidra-dir', '@ghidra'],
    expect: 'M05-BRIDGE-KEY',
    controls: [
      { name: 'forward transform used instead of its inverse', args: ['--forward'] },
      { name: 'masked table left masked', args: ['--no-mask'] },
    ],
  },
];

/* -------------------------------------------------------------------- helpers */

const checks = [];
const add = (ok, name, detail) => checks.push({ ok, name, detail });

async function solve(spec, extra = [], expectOverride = undefined) {
  const asm = path.join(OUT, spec.dir, spec.asm);
  const dat = path.join(OUT, spec.dir, 'm04_records.dat');
  const ghidra = path.join(OUT, spec.dir, 'ghidra');
  const args = spec.args.flatMap((a) => a
    .replace('@asm', asm)
    .replace('@dat', dat)
    .replace('@ghidra', ghidra));
  const expect = expectOverride ?? spec.expect;
  const argv = [...args, ...extra, '--expect', expect, '--json'];
  return run(process.execPath, [path.join(HERE, spec.solver), ...argv], { timeout: 900000 });
}

function parseJson(out) {
  try { return JSON.parse(out.trim().split('\n').pop()); } catch { return null; }
}

/** Ghidra is 20s of work; cache it against the DLL's own fingerprint. */
async function ensureGhidra(spec) {
  const dll = path.join(OUT, spec.dir, 'labnative.dll');
  const cache = path.join(OUT, spec.dir, 'ghidra');
  const stamp = path.join(cache, '.stamp');
  const want = crypto.createHash('sha256').update(fs.readFileSync(dll)).digest('hex').slice(0, 16);
  if (fs.existsSync(path.join(cache, 'decompiled')) && fs.existsSync(stamp) && fs.readFileSync(stamp, 'utf8') === want) {
    return { ok: true, cached: true, dir: cache };
  }
  fs.rmSync(cache, { recursive: true, force: true });
  const wrapper = path.join(STATION, 'scripts', 'ghidra-headless.ps1');
  const r = await run('powershell',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', wrapper, '-Sample', dll, '-OutDir', cache],
    { timeout: 900000 });
  if (r.code !== 0 || !fs.existsSync(path.join(cache, 'decompiled'))) {
    return { ok: false, cached: false, dir: cache, error: `ghidra-headless.ps1 exited ${r.code}` };
  }
  fs.writeFileSync(stamp, want);
  return { ok: true, cached: false, dir: cache };
}

/* ------------------------------------------------------------------ main */

async function main() {
  const lines = [];
  const say = (s = '') => { lines.push(s); if (!wantJson) process.stdout.write(`${s}\n`); };

  say('managed-lab loop -- .NET / managed reverse engineering, known-answer corpus');
  say('='.repeat(100));
  say('');

  /* ---- 1. tools + build ------------------------------------------------- */
  const ilspyVersion = await run(ILSPYCMD, ['--version']);
  const dotnet = await run('dotnet', ['--version']);
  add(ilspyVersion.code === 0, 'ilspycmd on PATH via the station tree', ilspyVersion.stdout.trim().split('\n').join(' '));
  add(dotnet.code === 0, 'dotnet SDK available', `dotnet ${dotnet.stdout.trim()}`);

  const missing = CORPUS.filter((c) => !fs.existsSync(path.join(OUT, c.dir, c.asm)));
  if (missing.length > 0) {
    say(`  ${missing.length} sample(s) not built -- running tools/build.ps1`);
    const b = await run('powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(HERE, 'build.ps1')],
      { timeout: 900000 });
    if (b.code !== 0) {
      add(false, 'build all samples', `build.ps1 exited ${b.code}`);
      say('');
      report();
      return finish();
    }
  }
  for (const c of CORPUS) {
    const asm = path.join(OUT, c.dir, c.asm);
    const exe = path.join(OUT, c.dir, c.exe);
    add(fs.existsSync(asm) && fs.existsSync(exe), `built ${c.id}`, `${path.basename(asm)} + ${path.basename(exe)}`);
  }
  const dat = path.join(OUT, 'm04', 'm04_records.dat');
  add(fs.existsSync(dat), 'm04 artifact on disk', fs.existsSync(dat) ? `${fs.statSync(dat).size} bytes` : 'missing');

  /* ---- 2. solve, then cross-check against the sample itself -------------- */
  say('');
  say('  solve + independent cross-check');
  say(`  ${'sample'.padEnd(6)}${''.padEnd(2)}${'solver'.padEnd(8)}${'answer'.padEnd(46)}cross-check against the sample's own output`);
  say(`  ${'-'.repeat(96)}`);

  const rows = [];
  for (const c of CORPUS) {
    const asm = path.join(OUT, c.dir, c.asm);
    const exe = path.join(OUT, c.dir, c.exe);
    const row = { id: c.id, technique: c.technique, ok: true, notes: [] };

    if (c.id === 'm05') {
      const g = await ensureGhidra(c);
      if (!g.ok) {
        row.ok = false;
        row.notes.push(g.error);
        rows.push(row);
        add(false, `${c.id} solve`, g.error);
        continue;
      }
      row.ghidra = g.cached ? 'reused cached headless decompile' : 'headless Ghidra decompile (fresh)';
    }

    const r = await solve(c);
    const parsed = r.code === 0 ? parseJson(r.stdout) : null;
    if (!parsed || !parsed.ok) {
      row.ok = false;
      row.notes.push(parsed ? parsed.why || JSON.stringify(parsed) : `solver exited ${r.code}: ${(r.stderr || '').trim().split('\n').pop()}`);
      rows.push(row);
      add(false, `${c.id} solve`, row.notes.join(' | '));
      continue;
    }
    row.answer = parsed.answer;
    row.detail = parsed;

    /* the independent source: what the sample prints about itself */
    let truth = null;
    if (c.id === 'm01') {
      truth = (await run(exe, [])).stdout.trim().split(/\r?\n/);
      if (JSON.stringify(truth) !== JSON.stringify(parsed.recovered)) {
        row.ok = false;
        row.notes.push(`decompiled recovery ${JSON.stringify(parsed.recovered)} != sample output ${JSON.stringify(truth)}`);
      }
    } else if (c.id === 'm02') {
      const t = (await run(exe, ['--trace'])).stdout.trim().split(/\r?\n/);
      if (t[0] !== parsed.order || t[1] !== parsed.answer) {
        row.ok = false;
        row.notes.push(`order/acc ${parsed.order} / ${parsed.answer} != sample trace ${t[0]} / ${t[1]}`);
      }
    } else if (c.id === 'm03') {
      const kv = Object.fromEntries((await run(exe, [])).stdout.trim().split(/\r?\n/)
        .map((l) => l.trim().split(/\s{2,}/)));
      const resName = (/--resource (\S+)/.exec(parsed.tool2) || [])[1];
      for (const [label, got] of [['resource', resName], ['length', String(parsed.length)],
        ['magic', parsed.magic], ['sha256', parsed.sha256], ['version', parsed.version], ['body', parsed.body]]) {
        if (kv[label] !== got) { row.ok = false; row.notes.push(`${label}: decompiled ${got} != sample ${kv[label]}`); }
      }
    } else if (c.id === 'm04') {
      const t = (await run(exe, [dat, '--no-write'])).stdout.trim();
      if (t !== parsed.answer) {
        row.ok = false;
        row.notes.push(`listing differs from the artifact's own reader\n--- decompiled ---\n${parsed.answer}\n--- sample ---\n${t}`);
      }
    } else if (c.id === 'm05') {
      const good = await run(exe, [parsed.answer]);
      const bad = await run(exe, ['AAAAAAAAAAAAAA']);   // 14 bytes, so LabCheck itself does the rejecting
      if (!/verdict ACCEPT/.test(good.stdout) || good.code !== 0) {
        row.ok = false;
        row.notes.push(`sample rejected the recovered key: ${good.stdout.trim().split(/\r?\n/).pop()}`);
      }
      if (!/verdict REJECT/.test(bad.stdout) || bad.code === 0) {
        row.ok = false;
        row.notes.push('sample accepted a wrong key -- the gate is not discriminating');
      }
      row.verdict = `${good.stdout.trim().split(/\r?\n/).pop()} / wrong key -> ${bad.stdout.trim().split(/\r?\n/).pop()}`;
    }

    if (!row.ok) row.notes.push('see above');
    add(row.ok, `${c.id} solve + cross-check`,
      `${row.ok ? 'recovered and confirmed by the sample' : row.notes.join(' | ')}  [${c.technique}]`);
    rows.push(row);

    say(`  ${row.ok ? 'PASS' : 'FAIL'}  ${c.id.padEnd(6)}${''} ${'exit 0'.padEnd(8)}${String(parsed.answer).slice(0, 44).padEnd(46)}`
      + `${c.id === 'm05' ? (row.verdict || '') : 'matches the sample output exactly'}`);
    for (const n of row.notes) say(`        !! ${n}`);
  }

  /* ---- 3. the headless IL path, asserted -------------------------------- */
  say('');
  say('  raw IL, headless (ilspycmd -il) -- the same facts, one layer lower');
  const IL_FACTS = [
    { id: 'm01', asm: path.join(OUT, 'm01', 'm01_stringobf.dll'), label: 'ciphertext is an ldstr, the key stream is a call', want: [/ldstr "NwYAEBHiG/, /call int32 M01\.Program::KeyStream\(int32, uint8\)/] },
    { id: 'm02', asm: path.join(OUT, 'm02', 'm02_flatten.dll'), label: 'the dispatcher is a brfalse chain, not a switch opcode; the dead state 43 is a plain literal', want: [/call bool M02\.Program::Opaque1\(int32, int32\)/, /ldc\.i4\.s 43/, /brfalse\.s/] },
    { id: 'm03', asm: path.join(OUT, 'm03', 'm03_resource.dll'), label: 'the payload is not in the IL at all -- only the suffix and the seed are', want: [/ldstr "\.b64"/, /ldc\.i4\.s 90/] },
    { id: 'm04', asm: path.join(OUT, 'm04', 'm04_struct.dll'), label: 'the integrity constants are IL immediates -- 0x811C9DC5 prints signed, as -2128831035', want: [/ldc\.i4 -2128831035/, /ldc\.i4 16777619/] },
    { id: 'm05', asm: path.join(OUT, 'm05', 'm05_bridge.dll'), label: 'the managed/native boundary is one pinvokeimpl line', want: [/pinvokeimpl\("labnative" nomangle cdecl\)/] },
  ];
  for (const f of IL_FACTS) {
    const r = await run(ILSPYCMD, ['--disable-updatecheck', '-il', f.asm]);
    const missing = f.want.filter((re) => !re.test(r.stdout)).map((re) => String(re));
    add(r.code === 0 && missing.length === 0, `${f.id} IL facts readable headlessly`,
      missing.length === 0 ? f.label : `not found in IL: ${missing.join(' ')}`);
    say(`  ${missing.length === 0 && r.code === 0 ? 'PASS' : 'FAIL'}  ${f.id.padEnd(6)} ${'ilspycmd -il'.padEnd(14)}${f.label}`);
  }

  /* ---- 4. negative controls ---------------------------------------------- */
  say('');
  say('  negative controls -- each solver in the mode that breaks it');
  for (const c of CORPUS) {
    for (const ctl of c.controls) {
      const r = await solve(c, ctl.args);
      const parsed = r.code === 0 ? parseJson(r.stdout) : null;
      const failed = r.code !== 0;
      add(failed, `${c.id} control: ${ctl.name}`,
        failed ? `exit ${r.code} (non-zero, as required)${parsed ? ` -- answer \`${parsed.answer}\`` : ''}` : 'EXITED 0 -- the control did not fail, so the checks above prove nothing');
      say(`  ${failed ? 'PASS' : 'FAIL'}  ${c.id.padEnd(6)}${''} ${`exit ${r.code}`.padEnd(8)}${ctl.name}`
        + `${failed ? '' : '   <<< CONTROL DID NOT FAIL'}`);
    }
  }

  /* ---- 5. the tooling itself can fail ------------------------------------ */
  {
    // m01's solver pointed at m02's assembly must refuse, not invent an answer.
    const r = await run(process.execPath, [path.join(HERE, 'solve-m01.mjs'),
      '--asm', path.join(OUT, 'm02', 'm02_flatten.dll'), '--expect', CORPUS[0].expect, '--json']);
    add(r.code !== 0, 'control: a solver given the wrong sample refuses',
      r.code !== 0 ? `exit ${r.code} -- ${(r.stderr || '').trim().split('\n').pop()}` : 'EXITED 0 -- it produced an answer for an assembly that has none of its facts');
    say('');
    say(`  ${r.code !== 0 ? 'PASS' : 'FAIL'}  tool   ${`exit ${r.code}`.padEnd(8)}m01's solver pointed at m02's assembly refuses instead of guessing`);
  }

  say('');
  report();
  return finish();

  function report() {
    say('  checks');
    for (const c of checks) say(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.name.padEnd(48)} ${c.detail}`);
    say('');
  }

  function finish() {
    const failed = checks.filter((c) => !c.ok);
    const summary = {
      ok: failed.length === 0,
      schema: 'managed-lab/loop@1',
      samples: rows.map((r) => ({ id: r.id, ok: r.ok, technique: r.technique, answer: r.answer ?? null, ghidra: r.ghidra ?? null, notes: r.notes })),
      checks: checks.map(({ ok, name }) => ({ ok, name })),
      failed: failed.map((f) => f.name),
      counts: { total: checks.length, pass: checks.length - failed.length, fail: failed.length },
    };
    say('='.repeat(100));
    if (failed.length === 0) {
      say('LOOP CLOSED: every sample was recovered from its decompilation alone, every recovery was confirmed');
      say('             against the sample\'s own output, and every negative control failed as it must.');
    } else {
      say(`LOOP OPEN: ${failed.length} check(s) failed -- ${failed.map((f) => f.name).join('; ')}`);
    }
    say('JSON-SUMMARY ' + JSON.stringify(summary.counts));
    if (wantJson) process.stdout.write(`${JSON.stringify(summary)}\n`);
    process.exit(failed.length === 0 ? 0 : 1);
  }
}

main().catch((e) => {
  process.stderr.write(`loop: ${e.stack || e.message}\n`);
  process.exit(2);
});
