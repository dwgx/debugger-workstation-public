/* analyze.mjs — the triangulator. THIS is the deliverable.
 *
 * `triage.mjs` produces observations. This file decides what they MEAN, and it is
 * built around one rule:
 *
 *   A single artifact lies. A conclusion needs two or more INDEPENDENT sources.
 *
 * "Independent" is not a vibe. Every claim in this file carries the set of source
 * groups that support it, and a claim is only CONFIRMED when at least two DIFFERENT
 * groups support it. Groups, not files: five prefetch files are one source, and a
 * single memory image examined by six plugins is still one source. That is the whole
 * lesson, and the reason `psscan` alone does not convict a hidden process even though
 * it is a completely different code path from `pslist`.
 *
 * Confidence tiers, borrowed verbatim from the analysis loop:
 *   OBSERVED   read directly out of a byte, no interpretation
 *   INFERRED   derived from >= 2 independent sources
 *   POSSIBLE   consistent with one source, uncorroborated
 *   REJECTED   a source claimed it and the triangulation did not hold up
 *
 * The decoy is not a special case in the code. It falls out of the same rule as
 * everything else: one source supports it, so it lands in POSSIBLE, and a POSSIBLE
 * claim is not a finding. There is no `if (decoy)` anywhere in this file.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { triage, crossView, LabImage, SOURCE_GROUPS } from './triage.mjs';

/* The gate. One number, stated in one place, so the rule can be argued with rather
 * than inferred from behaviour. */
export const MIN_INDEPENDENT_SOURCES = 2;

export const TIER = { OBSERVED: 'OBSERVED', INFERRED: 'INFERRED', POSSIBLE: 'POSSIBLE', REJECTED: 'REJECTED' };

/* Claims are accumulated as evidence and only then judged. Keeping them apart is what
 * stops the analyser from inventing a claim and then "confirming" it. */
class Ledger {
  constructor() { this.claims = new Map(); }
  claim(id, { title, kind, severity, subject, detail, support, tier, method, why, rejectReason }) {
    const prev = this.claims.get(id);
    if (prev) {
      prev.support = [...new Set([...prev.support, ...support])].sort();
      prev.detail.push(...detail);
      return prev;
    }
    const c = { id, title, kind, severity, subject, support: [...new Set(support)].sort(), detail, tier, method, why, rejectReason };
    this.claims.set(id, c);
    return c;
  }
  all() { return [...this.claims.values()]; }
}

/* The judgement. A claim is INFERRED when the supporting set, collapsed into source
 * GROUPS, has at least MIN_INDEPENDENT_SOURCES members. `support` entries are
 * `<GROUP>:<artifact>` so the evidence is traceable back to a file, while the count is
 * taken over distinct groups. */
function tierFor(support) {
  const groups = new Set(support.map((s) => s.split(':')[0]));
  return {
    groups: [...groups].sort(),
    independentSources: groups.size,
    tier: groups.size >= MIN_INDEPENDENT_SOURCES ? TIER.INFERRED : TIER.POSSIBLE,
  };
}

const norm = (p) => (p || '').replace(/\\/g, '/').toLowerCase();
const baseName = (p) => norm(p).split('/').pop();

/* ------------------------------------------------------------------ the pass */

export function analyze(targetDir) {
  const t = crossView(triage(targetDir));
  if (t.ok === false) return { ok: false, error: t.error, banner: t.banner };
  const manifest = JSON.parse(fs.readFileSync(path.join(targetDir, 'manifest.json'), 'utf8'));
  const led = new Ledger();
  const img = new LabImage(path.join(targetDir, manifest.image.file));
  img.banners();

  /* ---------------- cross-view: the list walk and the pool scan disagree --------- */
  for (const rec of t.crossChecks.inPoolNotInList) {
    const pf = t.artifacts.prefetch.find((p) => p.exe && norm(p.exe) === norm(rec.name));
    const am = t.artifacts.amcache.rows.find((r) => norm(r.path) === norm(rec.path));
    const srum = t.artifacts.srum.rows.find((r) => norm(r.app) === norm(rec.path));
    const support = [`MEM:psscan(pid ${rec.pid})`, `MEM:pslist(absent)`];
    if (pf) support.push(`PF:${pf.file}`);
    if (am) support.push(`AM:${am.path}`);
    if (srum) support.push(`SRUM:${srum.app}`);
    led.claim('UNLINKED_PROCESS', {
      title: `PID ${rec.pid} (${rec.name}) is resident in the pool but not reachable from the EPROCESS list`,
      kind: 'rootkit-dkom',
      severity: 'high',
      subject: { pid: rec.pid, name: rec.name, path: rec.path, createTime: rec.createTime },
      detail: [
        `psscan found EPROCESS at image offset 0x${(t.plugins.psscan.processes.find((p) => p.pid === rec.pid)?.offset ?? 0).toString(16)}`,
        'pslist, following ActiveProcessLinks from the list head, does not reach it',
        pf ? `prefetch ${pf.file} records ${pf.runs} run(s), last ${pf.runTimes[pf.runTimes.length - 1]}` : 'no prefetch record',
        am ? `Amcache records an execution of ${am.path} at ${am.execTime}` : 'no Amcache record',
      ],
      support,
      method: 'two independent walks of the same image (list traversal vs pool signature scan), each corroborated or not by an artefact outside the image',
      why: 'a process that a list walk cannot reach but a pool scan can see is the classic DKOM signature; the outside artefacts say the program really was running',
    });
  }
  for (const pid of t.crossChecks.inListNotInPool) {
    led.claim(`LISTED_NOT_SCANNED:${pid}`, {
      title: `PID ${pid} is on the list but no pool block was scanned for it`,
      kind: 'anomaly',
      severity: 'medium',
      subject: { pid },
      detail: ['the two views disagree in the opposite direction: a live pointer with no scanned allocation'],
      support: ['MEM:pslist', 'MEM:psscan'],
      method: 'cross-view',
      why: 'reported because a disagreement is information; it is not evidence of an attack on its own',
    });
  }

  /* ---------------- malfind: a private executable PE, cross-checked ------------ */
  for (const c of t.plugins.malfind.candidates) {
    const net = t.plugins.netscan.connections.filter((n) => n.pid === c.pid && n.state === 'ESTABLISHED' && !n.remoteAddr.startsWith('0.'));
    const srum = t.artifacts.srum.rows.find((r) => net.length && norm(r.app) === norm(t.plugins.psscan.processes.find((p) => p.pid === c.pid)?.path));
    const handles = t.plugins.handlescan.handles.filter((h) => h.pid === c.pid && h.type === 'Section');

    if (c.suspicious) {
      const support = [`MEM:malfind(pid ${c.pid} 0x${c.start.toString(16)})`];
      if (net.length) support.push(`MEM:netscan(${net[0].local} -> ${net[0].remote})`);
      if (srum) support.push(`SRUM:${srum.app}`);
      led.claim('INJECTED_PRIVATE_RWX_REGION', {
        title: `PID ${c.pid} has a private ${c.prot} region holding a ${c.pe.kind} that no load-list module explains`,
        kind: 'code-injection',
        severity: 'high',
        subject: {
          pid: c.pid, start: `0x${c.start.toString(16)}`, end: `0x${c.end.toString(16)}`,
          prot: c.prot, mem: c.mem, pe: c.pe.kind, contentOffset: `0x${c.contentOffset.toString(16)}`,
          contentSize: c.contentSize, sha256: shaOf(img, c.contentOffset, c.contentSize),
        },
        detail: [
          c.reason,
          `PE check: ${c.pe.kind}, machine ${c.pe.machine}, e_lfanew 0x${c.pe.lfanew.toString(16)}`,
          `process load list: ${c.loadList.length ? c.loadList.join(', ') : '(empty)'}`,
          handles.length ? `handle ${handles[0].value} of type ${handles[0].type} named ${handles[0].name}` : 'no section handle',
          net.length ? `socket ${net[0].state} ${net[0].local} -> ${net[0].remote}, opened ${net[0].createTime}` : 'no external socket',
          srum ? `SRUM attributes ${srum.netSent} bytes sent by ${srum.app} at ${srum.time}` : 'no SRUM network attribution',
        ],
        support,
        method: 'malfind: private + executable + structurally valid PE, minus regions a load-list module backs; then network attribution from a source outside the image',
        why: 'an executable private region that no loaded module explains is code the process did not get from its image on disk',
      });
    } else {
      /* A PE header that is NOT an injection. Two different reasons land here and they
       * are kept apart, because conflating them is how a report ends up asserting
       * "not executable" about a region that is: */
      /*   (a) the region holds a PE but is not executable  -> a data buffer
       *   (b) the region is executable but a load-list module backs it -> normal code
       * Both are candidates the predicate kept and then rejected, and both are reported
       * so the reader can see the signal was considered rather than dropped. */
      const notExecutable = !c.executable;
      led.claim(`NOT_AN_INJECTION:pid-${c.pid}-0x${c.start.toString(16)}`, {
        title: notExecutable
          ? `PID ${c.pid}: a ${c.pe.kind} sits in a ${c.prot} private region at 0x${c.start.toString(16)} — a data buffer, not an injection`
          : `PID ${c.pid}: the ${c.prot} region at 0x${c.start.toString(16)} holds a ${c.pe.kind} and is explained by ${c.backing}`,
        kind: 'rejected-signal',
        severity: 'info',
        subject: { pid: c.pid, start: `0x${c.start.toString(16)}`, prot: c.prot, mem: c.mem, backing: c.backing },
        detail: [
          `holds a structurally valid ${c.pe.kind} (machine ${c.pe.machine}, e_lfanew 0x${c.pe.lfanew.toString(16)})`,
          notExecutable
            ? `region protection is ${c.prot}: not executable, so nothing here can be injected code`
            : `region protection is ${c.prot}: executable, but ${c.backing} is on the process load list`,
          `process load list: ${c.loadList.length ? c.loadList.join(', ') : '(empty)'}`,
        ],
        support: [`MEM:malfind(candidate only)`],
        tier: TIER.REJECTED,
        method: 'the malfind predicate, with the failing half named',
        why: notExecutable
          ? 'a private region holding a PE-shaped buffer is a data buffer until the region is executable'
          : 'an executable region a loaded module accounts for is ordinary code, not an injection',
        rejectReason: notExecutable ? 'region is not executable' : 'region is explained by a load-list module',
      });
    }
  }

  /* ---------------- netscan: connections, and the ones nobody corroborates -------- */
  const procPath = new Map(t.plugins.psscan.processes.map((p) => [p.pid, p.path]));
  for (const n of t.plugins.netscan.connections) {
    if (n.state !== 'ESTABLISHED' || n.remoteAddr.startsWith('0.')) continue;
    const path = procPath.get(n.pid);
    const srum = t.artifacts.srum.rows.find((r) => norm(r.app) === norm(path) && r.netSent > 0);
    const support = [`MEM:netscan(${n.local} -> ${n.remote})`];
    if (srum) support.push(`SRUM:${srum.app}`);
    led.claim(`OUTBOUND_CONNECTION:pid-${n.pid}`, {
      title: `PID ${n.pid} holds an established connection ${n.local} -> ${n.remote}`,
      kind: 'network',
      severity: 'medium',
      subject: { pid: n.pid, local: n.local, remote: n.remote, state: n.state, createTime: n.createTime, imagePath: path },
      detail: [
        `opened ${n.createTime}`,
        srum ? `SRUM: ${srum.netSent} bytes sent / ${srum.netRecv} received by ${srum.app} at ${srum.time}` : 'no SRUM attribution for this image path',
      ],
      support,
      method: 'netscan, corroborated by per-app resource accounting outside the image',
      why: 'a connection is only notable once something other than the socket table explains it',
    });
  }

  /* ---------------- SRUM: paths that no other source has ever heard of ----------- */
  /* THE DECOY lives here and nowhere else. This loop is not told about the decoy: it
     reports every SRUM row whose image path is unknown to every other source, and the
     decoy falls out of that rule alongside any future one. */
  for (const r of t.artifacts.srum.rows) {
    const knownToMem = t.plugins.psscan.processes.some((p) => norm(p.path) === norm(r.app));
    const knownToAm = t.artifacts.amcache.rows.some((a) => norm(a.path) === norm(r.app));
    const knownToPf = t.artifacts.prefetch.some((p) => p.exe && norm(p.exe) === norm(baseName(r.app)));
    if (knownToMem || knownToAm || knownToPf) continue;
    const contradictory = [
      !knownToMem ? 'no process in the image runs this path' : null,
      !knownToAm ? 'no Amcache execution record' : null,
      !knownToPf ? 'no prefetch run history' : null,
    ].filter(Boolean);
    led.claim(`UNCORROBORATED_PATH:${r.app}`, {
      title: `${r.app} transferred ${r.netSent} bytes at ${r.time}, and one source says so`,
      kind: 'exfiltration-candidate',
      severity: 'medium',
      subject: { app: r.app, time: r.time, netSent: r.netSent, netRecv: r.netRecv, cpuMs: r.cpuMs },
      detail: [
        `SRUM: ${r.netSent} sent / ${r.netRecv} received, ${r.cpuMs} ms CPU at ${r.time}`,
        ...contradictory.map((c) => c),
        'MEM/AM/PF were each searched for this path and none has it',
      ],
      support: [`SRUM:${r.app}`],
      method: 'source-differential: an artefact names a path that no other artefact knows',
      why: 'a resource-usage row is a claim about a path, not proof the path ever ran; SRUM retains rows for programs that no longer exist',
    });
  }

  /* ---------------- judge every claim ------------------------------------------ */
  const claims = led.all().map((c) => {
    if (c.tier === TIER.REJECTED) {
      return { ...c, groups: supportGroups(c.support), independentSources: supportGroups(c.support).length, verdict: 'REJECTED', verdictReason: c.rejectReason ?? 'the signal did not survive the predicate' };
    }
    const { groups, independentSources, tier } = tierFor(c.support);
    return {
      ...c,
      groups,
      independentSources,
      tier,
      verdict: tier === TIER.INFERRED ? 'FINDING' : 'UNCONFIRMED',
      verdictReason: tier === TIER.INFERRED
        ? `${independentSources} independent sources agree: ${groups.join(', ')}`
        : `only ${independentSources} independent source (${groups.join(', ')}); ${MIN_INDEPENDENT_SOURCES} are required for a finding`,
    };
  });

  const findings = claims.filter((c) => c.verdict === 'FINDING');
  const unconfirmed = claims.filter((c) => c.verdict === 'UNCONFIRMED');
  const rejected = claims.filter((c) => c.verdict === 'REJECTED');

  return {
    schema: 'forensics-lab/analysis@1',
    ok: true,
    target: t.target,
    rule: {
      statement: 'a single artifact lies; a conclusion needs two or more independent sources',
      minIndependentSources: MIN_INDEPENDENT_SOURCES,
      sourceGroups: SOURCE_GROUPS,
      counting: 'distinct source GROUPS, not files: five prefetch files are one source, and one image read by six plugins is still one source',
      tiers: TIER,
    },
    triage: {
      pslist: { count: t.plugins.pslist.count, processes: t.plugins.pslist.processes.map((p) => ({ pid: p.pid, name: p.name, path: p.path, createTime: p.createTime })), method: t.plugins.pslist.method },
      psscan: { count: t.plugins.psscan.count, method: t.plugins.psscan.method },
      netscan: { count: t.plugins.netscan.count, chainIntact: t.plugins.netscan.chainIntact, method: t.plugins.netscan.method },
      malfind: { candidates: t.plugins.malfind.candidates.length, suspicious: t.plugins.malfind.suspicious.length, method: t.plugins.malfind.method },
      handlescan: { count: t.plugins.handlescan.count, method: t.plugins.handlescan.method },
    },
    counts: { findings: findings.length, unconfirmed: unconfirmed.length, rejected: rejected.length, claims: claims.length },
    findings: findings.sort((a, b) => a.id.localeCompare(b.id)),
    unconfirmed: unconfirmed.sort((a, b) => a.id.localeCompare(b.id)),
    rejected: rejected.sort((a, b) => a.id.localeCompare(b.id)),
  };
}

const supportGroups = (support) => [...new Set(support.map((s) => s.split(':')[0]))].sort();

function shaOf(img, off, len) {
  const b = img.slice(off, len);
  return b ? crypto.createHash('sha256').update(b).digest('hex') : null;
}

/* ------------------------------------------------------------------ cli */

function main(argv) {
  const i = argv.indexOf('--target');
  const target = (i >= 0 ? argv[i + 1] : null) || path.join(process.env.TEMP || process.cwd(), 'd12-forensics-lab', 'target');
  if (argv.includes('--print-header')) {
    const r = analyze(target);
    if (!r.ok) { console.error(`analyze: ${r.error}`); return 3; }
    console.log(JSON.stringify(r.triage, null, 2));
    return 0;
  }
  const r = analyze(target);
  if (!r.ok) { console.error(`analyze: ${r.error}`); return 3; }
  const ei = argv.indexOf('--expect');
  if (ei >= 0) {
    const want = new Set(argv[ei + 1].split(',').map((s) => s.trim()).filter(Boolean));
    const got = new Set(r.findings.map((f) => f.id));
    const missing = [...want].filter((x) => !got.has(x));
    const extra = [...got].filter((x) => !want.has(x));
    if (missing.length || extra.length) {
      console.error(`analyze: --expect mismatch  missing=[${missing}] unexpected=[${extra}]`);
      return 4;
    }
    return 0;
  }
  const line = (c) => `  [${c.verdict.padEnd(11)}] ${c.tier.padEnd(9)} ${c.id}\n      ${c.verdictReason}\n      ${c.title}`;
  console.log(`D12 forensics lab — analysis of ${path.basename(r.target.image)}  sha256 ${r.target.sha256.slice(0, 16)}...`);
  console.log(`  ${r.target.warning}\n`);
  console.log(`TRIAGE`);
  console.log(`  pslist      ${r.triage.pslist.count} processes   ${r.triage.pslist.processes.map((p) => p.pid).join(' ')}`);
  console.log(`  psscan      ${r.triage.psscan.count} processes`);
  console.log(`  netscan     ${r.triage.netscan.count} connections (chain intact: ${r.triage.netscan.chainIntact})`);
  console.log(`  malfind     ${r.triage.malfind.suspicious} suspicious of ${r.triage.malfind.candidates} candidates`);
  console.log(`  handlescan  ${r.triage.handlescan.count} handles`);
  console.log(`\nRULE  ${r.rule.statement}  (>= ${r.rule.minIndependentSources} independent source groups)\n`);
  console.log(`FINDINGS (${r.counts.findings})`);
  for (const c of r.findings) console.log(line(c));
  console.log(`\nUNCONFIRMED — single-source, deliberately NOT promoted (${r.counts.unconfirmed})`);
  for (const c of r.unconfirmed) console.log(line(c));
  console.log(`\nREJECTED — a signal that did not survive the predicate (${r.counts.rejected})`);
  for (const c of r.rejected) console.log(line(c));
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]).endsWith('analyze.mjs')) {
  process.exit(main(process.argv.slice(2)));
}
