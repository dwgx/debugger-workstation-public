/* spec.mjs — THE SCENARIO. One source of truth for the target and its ground truth.
 *
 * Everything the lab analyses is generated from this file. Nothing is a real host,
 * a real user, or a real image. The process names below are Windows system binaries
 * because that is what a triage table has to look like; the *paths* and the *facts*
 * are invented and are labelled as such in the image header.
 *
 * The three independent evidence sources are declared here too, because source
 * independence is the thing the lab teaches and it has to be a decision, not a hope:
 *
 *   MEM      the synthetic memory image      (one artifact: D12IMG)
 *   AM       Amcache-shaped execution log    (registry-derived)
 *   PF       Prefetch-shaped .pf files       (per-execution timing)
 *   SRUM     SRUM-shaped resource usage log  (per-app network bytes)
 *
 * `independenceGroups` says which of those are genuinely different acquisition
 * paths. Two artefacts in the same group count once.
 */

/* Frozen clock. Nothing in this lab reads the wall clock: the image must be
 * byte-identical across runs or "deterministic" is a claim instead of a fact. */
export const FROZEN_EPOCH = Date.UTC(2026, 2, 14, 2, 17, 33); // 2026-03-14T02:17:33Z
export const LAB_ID = 'D12';
export const IMAGE_MAGIC = 'D12IMG';
export const IMAGE_VERSION = 1;
export const PAGE_SIZE = 4096;

/* Image container geometry. ONE definition, imported by both the writer and the reader,
 * because two hand-maintained copies of a header layout is exactly how a parser ends up
 * reading a stride of 0 and sweeping the whole image. */
export const REGION_ORDER = ['HEADER', 'STRINGS', 'CONTENT', 'POOL', 'VADS', 'OBJECTS'];

export const HEADER = { magic: 0, version: 8, pageSize: 12, label: 16, warning: 144, clock: 272, frozenEpoch: 336, regionNames: 344 };
HEADER.regionTable = HEADER.regionNames + REGION_ORDER.length * 16;
HEADER.regionCount = HEADER.regionTable + REGION_ORDER.length * 8;
/* four u32 counts sit at regionCount: regionCount, processes, vads, tcp */
HEADER.counts = HEADER.regionCount;
HEADER.strides = HEADER.counts + 16;
HEADER.procListHead = HEADER.strides + 16;
HEADER.total = HEADER.procListHead + 8;
if (HEADER.total > PAGE_SIZE) throw new Error(`header needs ${HEADER.total} bytes, page is ${PAGE_SIZE}`);

/* Structure signatures. The parser hunts for these the way psscan hunts for
 * pool-tagged EPROCESS blocks: by signature, not by a table of offsets. */
export const SIG = {
  eprocess: 0x4450_5245, // 'D12E' little-endian read
  vad: 0x4441_5644,      // 'DVAD'
  tcp: 0x5043_5444,      // 'DTCP'
  handle: 0x444e_4844,   // 'DHND'
  object: 0x444a_424f,   // 'DOBJ'
  prefetch: 0x4650_4431, // 'D12PF' -> 'D1PF' as u32
  string: 0x0053_3144,   // 'D1S\0'
};

/* VAD protection bits, same shape Volatility reports (PAGE_* folded to 2 bits). */
export const PROT = { NOACCESS: 0, READONLY: 1, READWRITE: 2, WRITECOPY: 3, EXECUTE: 4, EXECUTE_READ: 5, EXECUTE_READWRITE: 6, EXECUTE_WRITECOPY: 7 };
export const MEM = { NONE: 0, PRIVATE: 1, MAPPED: 2, IMAGE: 3 };

/* The external endpoint the injected region is talking to. RFC 5737 TEST-NET-3:
 * reserved for documentation, so this string is not a real victim and not routable. */
export const EXTERNAL_IP = 0xCB00_7117; // 203.0.113.23
export const EXTERNAL_IP_TEXT = '203.0.113.23';
export const EXTERNAL_PORT = 8443;
export const EXTERNAL_HOST = 'lab-c2.invalid'; // .invalid is reserved by RFC 2606

/* ------------------------------------------------------------------ processes */

export const PROCESSES = [
  { pid: 4, ppid: 0, name: 'System', path: '', createOffset: -900_000, unlinked: false, note: 'kernel idle' },
  { pid: 620, ppid: 4, name: 'smss.exe', path: 'C:\\Windows\\System32\\smss.exe', createOffset: -880_000, unlinked: false },
  { pid: 744, ppid: 620, name: 'csrss.exe', path: 'C:\\Windows\\System32\\csrss.exe', createOffset: -879_500, unlinked: false, note: 'hosts the PE-shaped data decoy' },
  { pid: 1204, ppid: 744, name: 'winlogon.exe', path: 'C:\\Windows\\System32\\winlogon.exe', createOffset: -879_000, unlinked: false },
  { pid: 1880, ppid: 1204, name: 'lsass.exe', path: 'C:\\Windows\\System32\\lsass.exe', createOffset: -878_800, unlinked: false },
  {
    pid: 4120, ppid: 1880, name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe',
    createOffset: -870_000, unlinked: false,
    note: 'carries the injected private RWX region and the outbound socket',
  },
  {
    pid: 6692, ppid: 1880, name: 'lsass-helper.exe', path: 'C:\\ProgramData\\D12Lab\\lsass-helper.exe',
    createOffset: -640_000, unlinked: true,
    note: 'DKOM: physically resident in the pool, spliced out of the EPROCESS list',
  },
  {
    pid: 5500, ppid: 1204, name: 'spoolsv.exe', path: 'C:\\Windows\\System32\\spoolsv.exe',
    createOffset: -860_000, unlinked: false, note: 'benign; exists so the decoy has a plausible neighbour',
  },
];

/* ------------------------------------------------------------------ VADs */

/* Each VAD names the region content to stamp into the image. `content` is one of
 * the PAYLOAD / DATA / ZERO kinds below — the generator turns it into bytes. */
export const VADS = [
  // svchost.exe: the finding. Private, RWX, PE header at the region start, and the
  // module is NOT in the process's load list, so nothing on disk can account for it.
  {
    proc: 4120, start: 0x0000_0000_7ff6_0000, end: 0x0000_0000_7ff6_4000, prot: PROT.EXECUTE_READWRITE,
    mem: MEM.PRIVATE, backing: null, content: { kind: 'payload' }, poolTag: 'D12A',
  },
  // svchost.exe: an ordinary mapped image region, executable but not private, and
  // present in the load list. This is what "normal" looks like and the parser must
  // not flag it.
  {
    proc: 4120, start: 0x0000_0000_7ff7_0000, end: 0x0000_0000_7ff7_8000, prot: PROT.EXECUTE_READ,
    mem: MEM.IMAGE, backing: 'C:\\Windows\\System32\\svchost.exe', content: { kind: 'peheader', prot: PROT.IMAGE },
    poolTag: 'D12I',
  },
  // csrss.exe: THE DETECTOR-LEVEL DECOY. Private and starts with a structurally valid
  // MZ/PE, but PAGE_READONLY and not executable. A scanner that greps for "MZ in a
  // private region" calls this an injection. It is a data buffer. Ground truth: not
  // an injection. `exec: false` is the whole point of the region.
  {
    proc: 744, start: 0x0000_0000_0021_0000, end: 0x0000_0000_0021_2000, prot: PROT.READONLY,
    mem: MEM.PRIVATE, backing: null, content: { kind: 'peheader', prot: PROT.IMAGE }, poolTag: 'D12A',
  },
  // lsass-helper.exe: private RW data, no PE. Ordinary private memory.
  {
    proc: 6692, start: 0x0000_0000_0180_0000, end: 0x0000_0000_0181_0000, prot: PROT.READWRITE,
    mem: MEM.PRIVATE, backing: null, content: { kind: 'zeros' }, poolTag: 'D12A',
  },
  // smss.exe: tiny mapped data region, the parser must survive it without noise.
  {
    proc: 620, start: 0x0000_0000_0010_0000, end: 0x0000_0000_0010_0800, prot: PROT.READWRITE,
    mem: MEM.MAPPED, backing: 'C:\\Windows\\System32\\smss.exe', content: { kind: 'zeros' }, poolTag: 'D12I',
  },
];

/* ------------------------------------------------------------------ network */

/* The canonical TCP state enum. Writer and reader both take it from here: a fixture
 * whose writer and reader disagree about an enum is a fixture that reports a plausible
 * wrong state, which is the failure this lab exists to make visible. */
export const TCP_STATES = [
  'CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RCVD', 'ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2',
  'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT', 'DELETE_TCB',
];
export const tcpStateIndex = (s) => {
  const i = TCP_STATES.indexOf(s);
  if (i < 0) throw new Error(`unknown TCP state ${s}`);
  return i;
};

export const TCP = [
  { pid: 4120, state: 'ESTABLISHED', local: '10.0.0.42', localPort: 49812, remote: EXTERNAL_IP_TEXT, remotePort: EXTERNAL_PORT, createOffset: -120_000, ownsRegion: true },
  { pid: 744, state: 'LISTEN', local: '0.0.0.0', localPort: 135, remote: '0.0.0.0', remotePort: 0, createOffset: -879_400, ownsRegion: false },
  { pid: 1880, state: 'LISTEN', local: '0.0.0.0', localPort: 445, remote: '0.0.0.0', remotePort: 0, createOffset: -878_700, ownsRegion: false },
  { pid: 4120, state: 'TIME_WAIT', local: '10.0.0.42', localPort: 49820, remote: '93.184.216.34', remotePort: 80, createOffset: -90_000, ownsRegion: false },
];

/* ------------------------------------------------------------------ handles */

export const HANDLES = [
  { proc: 4120, value: 0x18, access: 0x0010_0000, type: 'Section', name: '\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe' },
  { proc: 4120, value: 0x2c, access: 0x0010_0000, type: 'Section', name: '\\BaseNamedObjects\\D12LabRegion7A', note: 'a named section handle onto the injected region' },

  { proc: 4120, value: 0x40, access: 0x0000_0001, type: 'Key', name: 'REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\D12Lab' },
  { proc: 1880, value: 0x10, access: 0x001f_0003, type: 'Token', name: 'NT AUTHORITY\\SYSTEM' },
  { proc: 6692, value: 0x04, access: 0x0010_0000, type: 'Section', name: '\\Device\\HarddiskVolume3\\ProgramData\\D12Lab\\lsass-helper.exe' },
];

/* ------------------------------------------------------------------ artifacts */

/* AM (Amcache-shaped): file executions. Deliberately does NOT contain the payload —
 * it was never written to disk through any path Amcache would have seen. */
export const AMCACHE_ROWS = [
  { path: 'C:\\Windows\\System32\\smss.exe', size: 12_288, execOffset: -880_000 },
  { path: 'C:\\Windows\\System32\\csrss.exe', size: 24_064, execOffset: -879_500 },
  { path: 'C:\\Windows\\System32\\winlogon.exe', size: 51_200, execOffset: -879_000 },
  { path: 'C:\\Windows\\System32\\lsass.exe', size: 61_440, execOffset: -878_800 },
  { path: 'C:\\Windows\\System32\\svchost.exe', size: 57_344, execOffset: -870_000 },
  { path: 'C:\\Windows\\System32\\spoolsv.exe', size: 98_304, execOffset: -860_000 },
  { path: 'C:\\ProgramData\\D12Lab\\lsass-helper.exe', size: 43_008, execOffset: -640_000 },
];

/* PF (Prefetch-shaped): per-image run history. */
export const PREFETCH = [
  { exe: 'SYSTEM.EXE', runs: 1, firstOffset: -900_000, lastOffset: -899_000 },
  { exe: 'SMSS.EXE', runs: 1, firstOffset: -880_000, lastOffset: -880_000 },
  { exe: 'WINLOGON.EXE', runs: 1, firstOffset: -879_000, lastOffset: -700_000 },
  { exe: 'LSASS.EXE', runs: 1, firstOffset: -878_800, lastOffset: -878_800 },
  { exe: 'SVCHOST.EXE', runs: 3, firstOffset: -870_000, lastOffset: -120_000 },
  { exe: 'SPOOLSV.EXE', runs: 1, firstOffset: -860_000, lastOffset: -860_000 },
  { exe: 'LSASS-HELPER.EXE', runs: 1, firstOffset: -640_000, lastOffset: -300_000 },
  // CSRSS.EXE is absent on purpose: the csrss decoy region must not acquire a
  // prefetch trail that would accidentally corroborate it.
];

/* SRUM (SRUM-shaped): per-app resource usage. The DECOY lives here and nowhere else. */
export const SRUM_ROWS = [
  { app: 'C:\\Windows\\System32\\svchost.exe', offset: -125_000, netSent: 4_194_304, netRecv: 65_536, cpuMs: 8_210 },
  { app: 'C:\\Windows\\System32\\lsass.exe', offset: -600_000, netSent: 0, netRecv: 0, cpuMs: 1_004 },
  { app: 'C:\\ProgramData\\D12Lab\\lsass-helper.exe', offset: -300_000, netSent: 1_048_576, netRecv: 32_768, cpuMs: 5_500 },
  // THE DECOY. One artefact, one row, and it points somewhere that looks bad.
  { app: 'C:\\Users\\Public\\D12LabStage\\stage-updater.exe', offset: -180_000, netSent: 44_040_192, netRecv: 131_072, cpuMs: 900, decoy: true },
  { app: 'C:\\Windows\\System32\\spoolsv.exe', offset: -400_000, netSent: 262_144, netRecv: 262_144, cpuMs: 2_400 },
];

/* ------------------------------------------------------------------ ground truth */

export const GROUND_TRUTH = {
  /* Two independent walks of the same image must disagree by exactly this much. */
  processesInList: [4, 620, 744, 1204, 1880, 4120, 5500],
  processesInPool: [4, 620, 744, 1204, 1880, 4120, 5500, 6692],

  /* Claims that MUST be reported as findings, with the source groups each requires.
     `id` is the claim id `tools/analyze.mjs` emits, so the comparison is exact rather
     than approximate: an extra finding fails the loop just as a missing one does. */
  confirmed: [
    {
      id: 'INJECTED_PRIVATE_RWX_REGION',
      pid: 4120,
      kind: 'code-injection',
      severity: 'high',
      requiresSources: ['MEM', 'SRUM'],
      why: 'a private RWX VAD holding a PE that no load-list module explains, plus network attribution for the same PID from a source outside the image',
    },
    {
      id: 'OUTBOUND_CONNECTION:pid-4120',
      pid: 4120,
      kind: 'network',
      severity: 'medium',
      requiresSources: ['MEM', 'SRUM'],
      why: 'the socket table and per-app resource accounting agree on who sent bytes and when',
    },
    {
      id: 'UNLINKED_PROCESS',
      pid: 6692,
      kind: 'rootkit-dkom',
      severity: 'high',
      requiresSources: ['MEM', 'PF', 'AM'],
      why: 'pslist and psscan disagree (list walk omits it, pool scan finds it) and three sources outside the list walk place it on the host',
    },
  ],

  /* THE DECOY. Exactly one artefact mentions this path. It must be REPORTED — silently
     dropping it would be a hole in the report — and it must be reported as UNCONFIRMED,
     never as a finding. `claimId` is what the analyser's source-differential rule emits. */
  rejected: [
    {
      app: 'C:\\Users\\Public\\D12LabStage\\stage-updater.exe',
      claimId: 'UNCORROBORATED_PATH:C:\\Users\\Public\\D12LabStage\\stage-updater.exe',
      singleSource: 'SRUM',
      kind: 'exfiltration-candidate',
      severity: 'medium',
      why: 'exactly one artefact mentions this path; no process, no prefetch trail, no file record corroborates it',
    },
  ],

  /* Present in the image, must be reported as NOT an injection. */
  silent: [
    { pid: 744, start: 0x0021_0000, kind: 'pe-shaped-private-readonly-region', why: 'a private region holding a PE header is a data buffer unless the region is executable' },
    { pid: 4120, start: 0x0000_0000_7ff7_0000, kind: 'load-list-backed-image-region', why: 'an executable region a loaded module accounts for is ordinary code' },
  ],
};
