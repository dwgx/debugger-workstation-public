/* pcap-lab.mjs — the self-judging protocol-analysis driver.
 *
 *   node tools/pcap-lab.mjs status
 *   node tools/pcap-lab.mjs list
 *   node tools/pcap-lab.mjs ask  --pcap <file|name> --question <id> [--json]
 *   node tools/pcap-lab.mjs ask  --pcap <file> --filter '<display filter>'      (free-form; no verdict)
 *   node tools/pcap-lab.mjs verify [--pcap <name>] [--json]
 *
 * `verify` is the point of the tool. For every question it runs the tshark command
 * twice: once against the capture that is built to answer it (must PASS) and once
 * against a capture that must NOT answer it (must not pass). A question that only
 * ever passes proves nothing — that is the negative control, and it is enforced,
 * not suggested.
 *
 * Exit codes: 0 all good, 1 usage/IO, 3 a question failed to find what the capture
 * guarantees, 4 a negative control unexpectedly passed.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate, defaultOutDir } from '../lab/gen-pcaps.mjs';
import { findTshark, runTshark, lines } from '../lab/tshark.mjs';
import { QUESTIONS, questionById } from '../lab/questions.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = name => { const i = args.indexOf(`--${name}`); return i > -1 ? args[i + 1] : undefined; };
const hasFlag = name => args.includes(`--${name}`);
const JSON_OUT = hasFlag('json');
const action = (args[0] && !args[0].startsWith('--')) ? args[0] : 'verify';

/* ------------------------------------------------------------------ corpus */

function resolveCorpus() {
  const dir = flag('dir') || defaultOutDir();
  const label = path.join(dir, 'corpus.json');
  if (!fs.existsSync(label)) {
    if (!fs.existsSync(dir) || fs.readdirSync(dir).filter(f => f.endsWith('.pcap')).length === 0) {
      generate(dir);
    }
  }
  const manifest = JSON.parse(fs.readFileSync(label, 'utf8'));
  return { dir, manifest };
}

function pcapPath(dir, name) {
  const file = name.endsWith('.pcap') ? name : `${name}.pcap`;
  const full = path.isAbsolute(name) ? name : path.join(dir, file);
  if (!fs.existsSync(full)) throw new Error(`no such capture: ${full}`);
  return full;
}

/* ------------------------------------------------------------------ running */

function runQuestion(q, { pcap, extraArgs = [] }) {
  const res = runTshark(['-r', pcap, ...q.args, ...extraArgs]);
  const verdict = q.test(res.stdout);
  return { ...verdict, argv: res.argv, display: res.display, stderr: res.stderr.trim(), stdout: res.stdout };
}

function describe(q) {
  const negative = q.negative ? `negative control: ${q.negative.pcap} — ${q.negative.why}` : 'no negative control';
  return `${q.id}  [${q.pcap}]  ${q.question}\n    method:   ${q.method}\n    tshark:   tshark -r <corpus>/${q.pcap} ${q.args.join(' ')}\n    ${negative}`;
}

/* ------------------------------------------------------------------ actions */

const tshark = (() => { try { return findTshark(); } catch (e) { return { error: e.message }; } })();

if (action === 'status') {
  const { dir, manifest } = resolveCorpus();
  const files = Object.entries(manifest.files).map(([name, info]) => ({
    file: name, packets: info.packets, bytes: info.bytes, sha256: info.sha256.slice(0, 16), path: info.path
  }));
  const out = {
    ok: !tshark.error,
    tshark: tshark.error ? null : { path: tshark.path, version: tshark.version, source: tshark.source },
    corpusDir: dir,
    corpus: files,
    questions: QUESTIONS.length,
    error: tshark.error
  };
  console.log(JSON_OUT ? JSON.stringify(out, null, 2) : [
    `net-reverse pcap lab`,
    `  tshark      ${tshark.error ? 'NOT FOUND: ' + tshark.error : `${tshark.version} (${tshark.source})`}`,
    `  tshark path ${tshark.error ? '-' : tshark.path}`,
    `  corpus      ${dir} (${files.length} synthetic captures, ${QUESTIONS.length} questions)`,
    ...files.map(f => `    ${f.file.padEnd(22)} ${String(f.packets).padStart(3)} pkts  sha256:${f.sha256}`)
  ].join('\n'));
  process.exit(tshark.error ? 1 : 0);
}

if (action === 'list') {
  const { dir, manifest } = resolveCorpus();
  if (JSON_OUT) {
    console.log(JSON.stringify({ corpusDir: dir, questions: QUESTIONS.map(q => ({ ...q, test: undefined, negative: q.negative })) }, null, 2));
  } else {
    console.log(`corpus: ${dir}\n`);
    for (const [name, info] of Object.entries(manifest.files)) {
      console.log(`${name}\n  teaches: ${info.teaches}\n  filters: ${info.filters.join(' ; ')}`);
      for (const g of info.guarantees) console.log(`    - ${g}`);
      console.log('');
    }
    console.log(`${QUESTIONS.length} questions (node tools/pcap-lab.mjs list --json for the machine form):`);
    for (const q of QUESTIONS) console.log(describe(q));
  }
  process.exit(0);
}

if (action === 'ask') {
  const { dir, manifest } = resolveCorpus();
  const pcapArg = flag('pcap');
  const filter = flag('filter');
  const qid = flag('question');

  if (filter && !qid) {
    if (!pcapArg) { console.error('ask --filter needs --pcap <file>'); process.exit(1); }
    const pcap = pcapPath(dir, pcapArg);
    const res = runTshark(['-r', pcap, '-Y', filter, '-T', 'fields', ...(flag('fields') ? flag('fields').split(',').flatMap(f => ['-e', f]) : [])]);
    console.log(`$ ${res.display}\n${res.stdout.trimEnd() || '(no packets matched)'}`);
    if (res.stderr.trim()) console.error(res.stderr.trim());
    process.exit(res.code === 0 ? 0 : 3);
  }

  if (!pcapArg || !qid) {
    console.error('usage: ask --pcap <file> --question <id>   (or --filter "<display filter>" [--fields a,b])');
    console.error('questions: ' + QUESTIONS.map(q => q.id).join(', '));
    process.exit(1);
  }

  const q = questionById(qid);
  if (!q) { console.error(`unknown question ${qid}. Known: ${QUESTIONS.map(x => x.id).join(', ')}`); process.exit(1); }
  const pcap = pcapPath(dir, pcapArg);
  const result = runQuestion(q, { pcap });
  const guarantee = manifest.files[q.pcap]?.guarantees.find(g => g === q.guarantee) || q.guarantee;

  if (JSON_OUT) {
    console.log(JSON.stringify({
      ok: result.ok, question: q.id, asked: q.question, pcap: path.basename(pcap), method: q.method,
      command: result.display, stdout: result.stdout.trimEnd(), detail: result.detail, guarantee
    }, null, 2));
  } else {
    console.log(`Q: ${q.question}`);
    console.log(`   capture  ${path.basename(pcap)}`);
    console.log(`   method   ${q.method}`);
    console.log(`   command  ${result.display}`);
    console.log(`   observed ${result.detail}`);
    console.log(`   guarantee  ${guarantee}`);
    console.log(`   verdict  ${result.ok ? 'ANSWERED' : 'NOT FOUND'}`);
    if (result.stderr) console.log(`   stderr   ${result.stderr}`);
  }
  process.exit(result.ok ? 0 : 3);
}

if (action === 'verify') {
  if (tshark.error) { console.error(tshark.error); process.exit(1); }
  const { dir, manifest } = resolveCorpus();
  const only = flag('pcap');
  const selected = only ? QUESTIONS.filter(q => q.pcap === only || q.id === only) : QUESTIONS;
  if (selected.length === 0) { console.error(`no questions match ${only}`); process.exit(1); }

  const results = [];
  for (const q of selected) {
    /* the capture's own label must still contain the claim we are testing */
    const declared = manifest.files[q.pcap]?.guarantees.includes(q.guarantee) ? 'declared' : 'NOT-DECLARED';
    const positive = runQuestion(q, { pcap: pcapPath(dir, q.pcap) });
    const negative = q.negative
      ? runQuestion({ ...q, args: q.negative.args || q.args }, { pcap: pcapPath(dir, q.negative.pcap) })
      : null;
    results.push({ q, declared, positive, negative });
  }

  const failed = results.filter(r => !r.positive.ok);
  const badNegatives = results.filter(r => r.negative && r.negative.ok);

  if (JSON_OUT) {
    console.log(JSON.stringify({
      ok: failed.length === 0 && badNegatives.length === 0,
      tshark: tshark.version,
      corpusDir: dir,
      results: results.map(r => ({
        id: r.q.id, pcap: r.q.pcap, question: r.q.question, guarantee: r.declared,
        command: r.positive.display, verdict: r.positive.ok ? 'PASS' : 'FAIL', observed: r.positive.detail,
        negative: r.negative ? { pcap: r.q.negative.pcap, control: r.negative.ok ? 'CONTROL FAILED (also passed)' : 'control held', observed: r.negative.detail } : null
      }))
    }, null, 2));
  } else {
    console.log(`pcap-lab verify — ${QUESTIONS.length ? selected.length : 0} question(s) against ${dir}`);
    console.log(`tshark: ${tshark.version}\n`);
    console.log('  idx  question                                     capture               verdict  observed');
    for (const [i, r] of results.entries()) {
      const label = r.q.id.padEnd(34).slice(0, 34);
      const cap = r.q.pcap.padEnd(20).slice(0, 20);
      console.log(`  ${String(i + 1).padStart(3)}  ${label} ${cap}  ${r.positive.ok ? 'PASS  ' : 'FAIL  '}   ${r.positive.detail}`);
      console.log(`       $ ${r.positive.display}`);
      if (r.negative) {
        console.log(`       negative control on ${r.q.negative.pcap}: ${r.negative.ok ? 'FAILED — it also answered' : 'held (did not answer)'} — ${r.negative.detail}`);
      }
    }
    console.log(`\n  ${results.length} question(s), ${failed.length} failed, ${badNegatives.length} negative control(s) leaked`);
  }
  process.exit(failed.length || badNegatives.length ? (failed.length ? 3 : 4) : 0);
}

console.error(`unknown action ${action}. Use: status | list | ask | verify`);
process.exit(1);
