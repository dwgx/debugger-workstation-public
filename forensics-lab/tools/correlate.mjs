/* correlate.mjs — hand the carved evidence to tools that are not this lab.
 *
 * Invariant 2 of the analysis loop: exhaust the cheap static passes, then instrument
 * the SLICE. The whole image is 150 KB and nothing needs instrumenting; the one thing
 * worth a second opinion is the 100 KB carved out of the injected region, so that is
 * what gets carved and shipped to three independent implementations.
 *
 * Three kinds of check, and they are NOT the same kind of evidence:
 *
 *   1. TOOL AGREEMENT (independent implementations). `diec` and `yr` are separate
 *      codebases from `tools/triage.mjs`. If all three say the carved bytes are a PE
 *      carrying the lab marker, the claim survives an implementation that is not ours.
 *      This raises confidence in the OBSERVATION.
 *
 *   2. CAPABILITY PROBE (a recorded negative result). Real Volatility 3 is installed on
 *      this station and is invoked for real against the image. It refuses, for a
 *      documented reason, and that refusal is captured verbatim and asserted. Recording
 *      the boundary is the honest thing to do; pretending the station can run pslist
 *      here would be the dishonest thing.
 *
 *   3. NOT A SOURCE. None of this changes a claim's source-group count. An extra tool
 *      reading the same bytes is not a second artifact, and treating it as one is exactly
 *      the mistake that makes triangulation decorative. That is stated in the output.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyze } from './analyze.mjs';
import { LabImage } from './triage.mjs';

/* The station root is two levels up from this file (forensics-lab/tools -> repo).
 * `fileURLToPath` rather than `URL.pathname`: on Windows the latter yields `/D:/...`,
 * which every path.join downstream then mangles. */
export function stationRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

/* Tool discovery. Relative to the repo, so nothing here is hard-coded to a user
 * profile and the lab still runs on a clone in a different directory. */
export function findTools(root) {
  const candidates = {
    vol: ['System-Forensics/volatility3/vol.exe'],
    diec: ['Static-Reversing/die_win64_portable_3.21_x64/die/diec.exe'],
    yr: ['Static-Reversing/YARA-X/yr.exe'],
    capa: ['Static-Reversing/capa/capa.exe'],
  };
  const out = {};
  for (const [key, rel] of Object.entries(candidates)) {
    for (const r of rel) {
      const p = path.join(root, r);
      if (fs.existsSync(p)) { out[key] = p; break; }
    }
  }
  return out;
}

function run(cmd, args, { timeout = 120_000 } = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
  return {
    cmd: `${path.basename(cmd)} ${args.join(' ')}`,
    exit: r.status,
    stdout: (r.stdout || '').trim(),
    stderr: (r.stderr || '').trim(),
    error: r.error ? String(r.error.message) : null,
    timedOut: r.error?.code === 'ETIMEDOUT' ?? false,
  };
}

/* ------------------------------------------------------------------ carve */

/* Carving is the narrow the loop calls for: the region bytes are written to a real file
 * so a file-oriented tool can be pointed at them. The carve is bounded by the VAD's own
 * recorded size, and the file's hash is recorded so the tool output can be tied back to
 * the exact bytes. */
export function carve(targetDir, outDir, analysis) {
  const manifest = JSON.parse(fs.readFileSync(path.join(targetDir, 'manifest.json'), 'utf8'));
  const img = new LabImage(path.join(targetDir, manifest.image.file));
  img.banners();
  fs.mkdirSync(outDir, { recursive: true });
  const carved = [];
  for (const f of analysis.findings) {
    if (f.id !== 'INJECTED_PRIVATE_RWX_REGION' || !f.subject) continue;
    const s = f.subject;
    const bytes = img.slice(Number(s.contentOffset), Number(s.contentSize));
    if (!bytes) { carved.push({ error: `region at ${s.contentOffset} is outside the image` }); continue; }
    const file = path.join(outDir, `carved-pid${s.pid}-0x${Number(s.start).toString(16)}.bin`);
    fs.writeFileSync(file, bytes);
    carved.push({
      pid: s.pid, start: s.start, file, bytes: bytes.length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      /* the lab's own read of the bytes, for comparison against what the tools say */
      labRead: { claim: 'structurally valid PE carrying the lab marker', verifiedBy: 'tools/triage.mjs:looksLikePe' },
    });
  }
  return carved;
}

/* ------------------------------------------------------------------ the probe */

export function correlate(targetDir, outDir) {
  const root = stationRoot();
  const tools = findTools(root);
  const analysis = analyze(targetDir);
  if (!analysis.ok) return { ok: false, error: analysis.error };

  const carved = carve(targetDir, outDir, analysis);
  const checks = [];

  /* --- 1. independent implementations on the carved bytes ------------------- */
  for (const c of carved) {
    if (c.error) { checks.push({ carve: c, tools: [], error: c.error }); continue; }
    const toolRuns = [];

    if (tools.diec) {
      const r = run(tools.diec, ['-j', c.file]);
      let filetype = null;
      try { filetype = JSON.parse(r.stdout)?.detects?.[0]?.filetype ?? null; } catch { /* leave null */ }
      toolRuns.push({ tool: 'diec', version: 'Detect It Easy (portable)', exit: r.exit, result: filetype, agrees: filetype === 'PE64', raw: r.exit === 0 ? undefined : (r.stderr || r.stdout).slice(0, 400) });
    }
    if (tools.yr) {
      const ruleFile = path.join(outDir, 'd12-payload.yar');
      fs.writeFileSync(ruleFile, [
        '// D12 lab rule. Written by tools/correlate.mjs; matches the marker the payload',
        '// PE carries. Its job is to be an INDEPENDENT implementation agreeing with the',
        '// lab parser about what is in the carved region.',
        'rule D12_LabPayload {',
        '  meta:',
        '    author = "d12-forensics-lab"',
        '    description = "self-authored lab payload marker"',
        '  strings:',
        '    $m = "D12LAB-PAYLOAD" ascii',
        '  condition:',
        '    uint16(0) == 0x5A4D and $m',
        '}',
        '',
      ].join('\n'), 'utf8');
      /* yr's argument order is RULES first, then TARGET. Verified on yara-x 1.20.0. */
      const r = run(tools.yr, ['scan', ruleFile, c.file]);
      const hit = r.stdout.includes('D12_LabPayload');
      toolRuns.push({ tool: 'yr', version: 'YARA-X', exit: r.exit, result: r.stdout.split(/\r?\n/)[0] || '(no match)', agrees: hit, raw: r.stdout.slice(0, 400) });
    }
    checks.push({ carve: c, tools: toolRuns });
  }

  /* --- 2. capability probe: real Volatility 3, invoked for real --------------- */
  /* This is a recorded NEGATIVE result and it is the honest limit of the whole lane.
   * Volatility 3 is installed (frozen exe, no Python required) and it is run against
   * the image here. Every plugin that needs a kernel needs KDBG + a matching PDB, which
   * only a real acquisition produces, so it refuses. The refusal is captured verbatim
   * and asserted by loop.mjs, because "it can't" is a claim and this is the evidence. */
  const volProbe = { tool: 'Volatility 3', installed: Boolean(tools.vol), runs: [], conclusion: null };
  if (tools.vol) {
    const imageFile = path.join(targetDir, JSON.parse(fs.readFileSync(path.join(targetDir, 'manifest.json'), 'utf8')).image.file);
    /* `--offline` on every probe. Volatility's automagic otherwise reaches for ISF/PDB
     * data and maintains a symbol cache under %APPDATA%\volatility3; this lab makes no
     * network calls and writes no user-global state, and the refusal it is measuring is
     * byte-identical with the flag (verified). */
    const OFF = ['-q', '--offline'];
    for (const [label, pluginArgs] of [
      ['frameworkinfo.FrameworkInfo', ['-q', '--offline', 'frameworkinfo.FrameworkInfo']],
      ['banners', [...OFF, '-f', imageFile, 'banners']],
      ['windows.pslist', [...OFF, '-f', imageFile, 'windows.pslist']],
      ['yarascan.YaraScan', [...OFF, '-f', imageFile, 'yarascan.YaraScan', '--yara-file', path.join(outDir, 'd12-payload.yar')]],
    ]) {
      const r = run(tools.vol, pluginArgs);
      const text = `${r.stdout}\n${r.stderr}`;
      volProbe.runs.push({
        plugin: label,
        exit: r.exit,
        ok: r.exit === 0,
        /* the requirement Volatility prints when it refuses, verbatim */
        refusal: /Unsatisfied requirement ([^\n]+)/.exec(text)?.[1] ?? null,
        output: text.split(/\r?\n/).filter((l) => l.trim() && !/^Progress:/.test(l)).slice(0, 6),
      });
    }
    volProbe.conclusion = volProbe.runs.find((r) => r.plugin === 'windows.pslist' && !r.ok)
      ? 'Volatility 3 runs, and refuses every kernel-level plugin on this image because a synthetic fixture carries no KDBG and no matching PDB. That is the boundary of this lab, recorded rather than asserted.'
      : 'Volatility 3 accepted a kernel plugin on a synthetic image. That is unexpected and is reported as-is.';
  } else {
    volProbe.conclusion = 'Volatility 3 is not installed at the expected path; the capability probe was skipped.';
  }

  return {
    schema: 'forensics-lab/correlate@1',
    ok: true,
    tools,
    /* The statement that keeps this honest: a second implementation is not a second
       source, and this lab does not let one masquerade as the other. */
    independenceNote: 'Tool agreement raises confidence in an OBSERVED value. It does not add a source group: all three implementations are reading the same bytes of the same file, so no claim\'s independent-source count changes because of anything in this section.',
    carved,
    checks,
    volatility: volProbe,
  };
}

/* ------------------------------------------------------------------ cli */

function main(argv) {
  const i = argv.indexOf('--target');
  const target = (i >= 0 ? argv[i + 1] : null) || path.join(process.env.TEMP || process.cwd(), 'd12-forensics-lab', 'target');
  const j = argv.indexOf('--out');
  const out = (j >= 0 ? argv[j + 1] : null) || path.join(path.dirname(target), 'carved');
  const r = correlate(target, out);
  if (!r.ok) { console.error(`correlate: ${r.error}`); return 3; }
  console.log(`D12 forensics lab — correlation with tools that are not this lab\n`);
  console.log(`  ${r.independenceNote}\n`);
  console.log(`CARVED`);
  for (const c of r.carved) {
    if (c.error) { console.log(`  ERROR ${c.error}`); continue; }
    console.log(`  pid ${c.pid}  ${c.start}  ${c.bytes} bytes  sha256 ${c.sha256}`);
    console.log(`         -> ${c.file}`);
  }
  console.log(`\nINDEPENDENT IMPLEMENTATIONS ON THE CARVED BYTES`);
  for (const c of r.checks) {
    if (c.error) { console.log(`  ${c.error}`); continue; }
    for (const t of c.tools) {
      console.log(`  ${(t.agrees ? 'AGREE ' : 'DISAGREE')}  ${t.tool.padEnd(5)} exit ${String(t.exit).padEnd(3)} ${t.result}`);
    }
  }
  console.log(`\nVOLATILITY 3 CAPABILITY PROBE  (installed: ${r.volatility.installed})`);
  for (const p of r.volatility.runs) {
    console.log(`  ${p.ok ? 'ran ' : 'refused'}  ${p.plugin.padEnd(28)} exit ${p.exit}${p.refusal ? `   ${p.refusal}` : ''}`);
  }
  console.log(`  -> ${r.volatility.conclusion}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]).endsWith('correlate.mjs')) {
  process.exit(main(process.argv.slice(2)));
}
