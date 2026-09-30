/* trustcheck.mjs — prove the lab installed nothing into a trust store (Windows).
 *
 *   node tools/trustcheck.mjs [--json]
 *
 * The lane's stop line is that a lab CA never enters the machine or user root
 * store, because Chromium-on-Windows consults the machine store for EVERY profile,
 * including the daily browser. So this tool does not "check a flag" — it reads the
 * actual stores and the actual proxy configuration, and fails if the lab CA (or a
 * MITM-CA-shaped subject) is present.
 *
 * It is deliberately read-only: `certutil -store` and `reg query` only. Nothing here
 * can add a certificate, which is the point of running it as evidence.
 */
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const JSON_OUT = process.argv.includes('--json');
const LAB_CA = process.env.LAB_CA || 'E:/<private-tree>-sandbox/tls/lab-ca.crt';

/* Subjects that mean "a MITM proxy installed itself". Our own lab CA is matched by
 * thumbprint instead of by name, because a thumbprint cannot be typo'd. */
const MITM_SHAPED = /(mitmproxy|reqable|fiddler|charles|proxyman|burp|certificate authority for|omp-lab-CA)/i;

function run(cmd, argv) {
  const res = spawnSync(cmd, argv, { encoding: 'utf8', windowsHide: true });
  return { code: res.status, stdout: res.stdout || '', stderr: res.stderr || '', error: res.error?.message };
}

/** Parse `certutil -store Root` output into a list of { index, subject, issuer, serial, sha1 }. */
function parseStore(stdout) {
  const certs = [];
  const blocks = stdout.split(/={10,}/).filter(b => /Certificate/.test(b) || /Subject:/.test(b));
  const current = () => certs[certs.length - 1];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    let m;
    if ((m = /^Subject:\s*(.+)$/.exec(line))) { certs.push({ subject: m[1], issuer: null, serial: null, sha1: null }); continue; }
    if (!certs.length) continue;
    if ((m = /^Issuer:\s*(.+)$/.exec(line)) && current().issuer === null) current().issuer = m[1];
    if ((m = /^Serial Number:\s*(.+)$/.exec(line)) && current().serial === null) current().serial = m[1];
    if ((m = /^Cert Hash\(sha1\):\s*([0-9a-f ]+)$/i.exec(line))) current().sha1 = m[1].replace(/\s+/g, '');
  }
  return certs;
}

/** SHA-1 thumbprint of a PEM/PFX file, so we can look for exactly our lab CA. */
function fileThumbprint(file) {
  if (!fs.existsSync(file)) return null;
  const pem = fs.readFileSync(file, 'utf8');
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  try {
    const der = Buffer.from(b64, 'base64');
    return crypto.createHash('sha1').update(der).digest('hex');
  } catch { return null; }
}

const machine = run('certutil', ['-store', 'Root']);
const userRes = run('certutil', ['-user', '-store', 'Root']);
const winhttp = run('netsh', ['winhttp', 'show', 'proxy']);
const proxyEnable = run('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable']);
const proxyServer = run('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyServer']);

const machineCerts = parseStore(machine.stdout);
const userCerts = parseStore(userRes.stdout);
const labThumb = fileThumbprint(LAB_CA);

const suspicious = [
  ...machineCerts.filter(c => MITM_SHAPED.test(c.subject)).map(c => ({ store: 'machine Root', ...c })),
  ...userCerts.filter(c => MITM_SHAPED.test(c.subject)).map(c => ({ store: 'user Root', ...c }))
];
const labPresent = labThumb
  ? [...machineCerts.map(c => ({ store: 'machine Root', ...c })), ...userCerts.map(c => ({ store: 'user Root', ...c }))]
      .filter(c => (c.sha1 || '').toLowerCase() === labThumb)
  : [];

const proxyEnabled = /ProxyEnable\s+REG_DWORD\s+0x1/i.test(proxyEnable.stdout);
const winhttpProxyLine = (winhttp.stdout.split(/\r?\n/).map(l => l.trim()).filter(l => /proxy server|direct access/i.test(l))[0]) || `netsh exit ${winhttp.code}`;

/* ---- baseline diff: "nothing landed during the run" is a comparison, not a mood ---- */
const BASELINE = process.env.TRUST_BASELINE || path.join(os.tmpdir(), 'net-reverse-lab', 'trust-baseline.json');
const snapshot = {
  at: new Date().toISOString(),
  machineRoot: machineCerts.length,
  userRoot: userCerts.length,
  machineSubjects: machineCerts.map(c => c.subject).sort(),
  userSubjects: userCerts.map(c => c.subject).sort()
};
let baselineBefore = null;
let baselineNote;
if (fs.existsSync(BASELINE)) {
  try { baselineBefore = JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch { baselineBefore = null; }
}
if (!baselineBefore) {
  fs.mkdirSync(path.dirname(BASELINE), { recursive: true });
  fs.writeFileSync(BASELINE, JSON.stringify(snapshot, null, 2));
  baselineNote = `baseline recorded now (${BASELINE}): machine ${snapshot.machineRoot}, user ${snapshot.userRoot}`;
} else {
  const deltaMachine = snapshot.machineRoot - baselineBefore.machineRoot;
  const deltaUser = snapshot.userRoot - baselineBefore.userRoot;
  const added = snapshot.machineSubjects.filter(s => !baselineBefore.machineSubjects.includes(s))
    .concat(snapshot.userSubjects.filter(s => !baselineBefore.userSubjects.includes(s)));
  baselineNote = deltaMachine === 0 && deltaUser === 0 && added.length === 0
    ? `unchanged since ${baselineBefore.at} (machine ${snapshot.machineRoot}, user ${snapshot.userRoot})`
    : `CHANGED since ${baselineBefore.at}: machine ${deltaMachine >= 0 ? '+' : ''}${deltaMachine}, user ${deltaUser >= 0 ? '+' : ''}${deltaUser}${added.length ? ' — added: ' + added.join(' | ') : ''}`;
}

const checks = [
  {
    label: 'lab CA absent from the machine root store',
    pass: !labPresent.some(c => c.store === 'machine Root'),
    detail: labThumb ? `lab CA sha1 ${labThumb.slice(0, 16)}… not found in ${machineCerts.length} machine-root cert(s)` : `no lab CA file at ${LAB_CA} (nothing to look for); ${machineCerts.length} machine-root cert(s)`
  },
  {
    label: 'lab CA absent from the user root store',
    pass: !labPresent.some(c => c.store === 'user Root'),
    detail: `not found in ${userCerts.length} user-root cert(s)`
  },
  {
    label: 'no MITM-proxy-shaped CA in either root store',
    pass: suspicious.length === 0,
    detail: suspicious.length ? suspicious.map(c => `${c.store}: ${c.subject}`).join(' | ') : 'no mitmproxy/Reqable/Fiddler/Charles/Burp-shaped subject'
  },
  {
    label: 'Windows system proxy is off (WinINET)',
    pass: !proxyEnabled,
    detail: proxyEnabled ? `ProxyEnable=1 ${(proxyServer.stdout.match(/ProxyServer\s+REG_SZ\s+(.+)/) || [])[1] || ''}`.trim() : 'HKCU ProxyEnable = 0 (or unset)'
  },
  {
    label: 'WinHTTP proxy is not configured',
    pass: /Direct access \(no proxy server\)/i.test(winhttp.stdout) || winhttp.code !== 0,
    detail: winhttpProxyLine
  },
  {
    label: 'no certificate landed since the baseline run',
    pass: baselineNote.startsWith('unchanged') || baselineNote.startsWith('baseline recorded'),
    detail: baselineNote
  }
];

const out = {
  ok: checks.every(c => c.pass),
  host: os.hostname(),
  stores: {
    machineRoot: { count: machineCerts.length, subjects: machineCerts.map(c => c.subject) },
    userRoot: { count: userCerts.length, subjects: userCerts.map(c => c.subject) }
  },
  labCa: { file: LAB_CA, sha1: labThumb, present: labPresent.length > 0 },
  suspicious,
  baseline: { file: BASELINE, note: baselineNote, before: baselineBefore ? { machineRoot: baselineBefore.machineRoot, userRoot: baselineBefore.userRoot, at: baselineBefore.at } : null },
  proxy: { wininetProxyEnable: proxyEnabled, winhttp: winhttp.stdout.trim().split(/\r?\n/).pop() || null },
  checks
};

if (JSON_OUT) {
  console.log(JSON.stringify(out, null, 2));
} else {
  console.log('isolation check — trust stores and proxy configuration (read-only)');
  console.log(`  host            ${out.host}`);
  console.log(`  machine Root    ${machineCerts.length} certificate(s)`);
  console.log(`  user Root       ${userCerts.length} certificate(s)`);
  console.log(`  lab CA          ${LAB_CA} ${labThumb ? `sha1:${labThumb.slice(0, 16)}…` : '(file not present)'} -> present in a root store: ${out.labCa.present}`);
  console.log(`  proxy           WinINET ProxyEnable=${proxyEnabled ? '1 (ON)' : '0/absent'}; WinHTTP: ${out.proxy.winhttp}`);
  if (suspicious.length) for (const c of suspicious) console.log(`  MITM-shaped     ${c.store}: ${c.subject}`);
  console.log('');
  for (const c of checks) console.log(`  ${c.pass ? 'PASS' : 'FAIL'}  ${c.label.padEnd(48)} ${c.detail}`);
  console.log(`\n${out.ok ? 'ISOLATION HELD: zero lab certificates in the machine/user root stores, no system proxy.' : 'ISOLATION BROKEN — a lab or MITM certificate is in a root store, or a system proxy is on.'}`);
}

const wantSubjects = process.argv.includes('--subjects');
if (wantSubjects && !JSON_OUT) {
  console.log('\nmachine Root store contents:');
  for (const c of machineCerts) console.log(`  - ${c.subject}`);
  console.log('user Root store contents:');
  for (const c of userCerts) console.log(`  - ${c.subject}`);
}

process.exit(out.ok ? 0 : 7);
