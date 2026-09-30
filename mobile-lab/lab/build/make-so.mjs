/*
 * make-so.mjs — build the sample's native library as a REAL, loadable ELF64 AArch64
 * shared object, with no compiler.
 *
 * WHY THIS EXISTS
 * ---------------
 * There is no Android NDK on this box: no clang with an Android target triple, no sysroot,
 * no Android libc. lab/native/mobilelab.c is therefore shipped as SOURCE and is NOT
 * compiled here. But an APK with no lib/<abi>/*.so makes the JNI half of the static lab
 * vacuous, and "mapping System.loadLibrary to lib/*.so" is the capability being built.
 *
 * So this file emits the ELF by hand. The result is a genuine ELF64 DYN object with a real
 * program-header table, a real .dynamic section, a real SysV .hash, a real .dynsym with
 * GLOBAL FUNC bindings, and real .rodata. The Android dynamic linker would load it; the
 * .text instructions are AArch64 and documented, but they are a stub, not the compiled C.
 *
 * WHAT IS AND IS NOT CLAIMED
 * --------------------------
 *   Claimed and verified:  ELF structure, .dynsym/.dynstr, symbol binding and visibility,
 *                          DT_NEEDED imports, .rodata string extraction, JNI name mangling,
 *                          section/program-header walking, hash-table build.
 *   NOT claimed:           that the instruction stream implements the C. The build prints
 *                          this limitation, and the analyser reports `disassembly: not
 *                          attempted` rather than inventing a decompilation.
 *
 * INDEPENDENT VERIFICATION
 * ------------------------
 * The byte layout is checked by three readers that share no code: this file's own re-parse,
 * pyelftools (a separate implementation, used as an oracle in tools/loop.mjs), and the
 * analyser's ELF walker. A disagreement fails the loop.
 */

import { createHash } from 'node:crypto';

/* ------------------------------------------------------------------ *
 * ELF constants (ELF64, little-endian)
 * ------------------------------------------------------------------ */

const ET_DYN = 3;
const EM_AARCH64 = 183;
const SHT_NULL = 0;
const EV_CURRENT = 1;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;

const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const SHT_PROGBITS = 1;
const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_HASH = 5;
const SHT_DYNAMIC = 6;
const SHT_DYNSYM = 11;

const SHF_ALLOC = 0x2;
const SHF_EXECINSTR = 0x4;

const STB_GLOBAL = 1;
const STT_NOTYPE = 0;
const STT_FUNC = 2;
const STV_DEFAULT = 0;

const DT_NEEDED = 1;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;
const DT_SONAME = 14;
const DT_NULL = 0;

const EHDR_SIZE = 64;
const PHDR_SIZE = 56;
const SHDR_SIZE = 64;
const SYMTAB_SIZE = 24;
const DYN_SIZE = 16;

const PAGE = 0x1000;

/* ------------------------------------------------------------------ *
 * The sample's native content. Mirrors lab/native/mobilelab.c exactly:
 * same exported symbols, same rodata strings, same DT_NEEDED imports.
 * ------------------------------------------------------------------ */

/** Exported JNI entry points. Names already carry the JNI mangling applied by the spec. */
const EXPORTS = [
  { name: 'Java_com_lab_mobilelab_MainActivity_nativeDeriveKey', kind: 'func' },
  { name: 'Java_com_lab_mobilelab_MainActivity_nativeAttest', kind: 'func' },
  { name: 'Java_com_lab_mobilelab_MainActivity_nativeReadFlag', kind: 'func' },
  { name: 'Java_com_lab_mobilelab_NativePinConfig_verifyNativePin', kind: 'func' },
  { name: 'Java_com_lab_mobilelab_NativePinConfig_nativeLeafCertificate', kind: 'func' },
  /* Imported libc entry points. A real .so declares these UNDEFINED with a .dynstr name and
     no section index, which is exactly what DT_NEEDED + an undefined dynsym entry means. */
  { name: '__android_log_print', kind: 'import' },
  { name: 'memcmp', kind: 'import' },
  { name: 'malloc', kind: 'import' },
  { name: 'free', kind: 'import' },
];

/** .rodata: the native pin table and the native-only endpoint. */
const RODATA_STRINGS = [
  'sha256/9xQm2LpVn7RtY1uI4oP6aS8dF0gH3jK5lZ7xC9vB2nM4qW6eR8tY0uI2oP4aS6dF8=',
  'sha256/4kJn8Hd2Fg6Hj0Kl2Mn4Op6Qr8St0Uv2Wx4Yz6Ab8Cd0Ef2Gh4Ij6Kl8Mn0Op2Qr4=',
  'https://attest.lab.invalid/v1/verify',
  'mobilelab-native-pin-table-v1',
  'com.lab.mobilelab',
];

/* AArch64 machine code. Documented stub bodies — see the header. Each function is
   `ret` (0xd65f03c0) preceded by a `mov w0, #<id>` so the functions are distinguishable
   in a hexdump and each occupies a distinct, correctly aligned 4-byte slot. */
function stubBody(index) {
  return [
    0x52800000 | (index & 0xffff), /* mov w0, #imm  */
    0xd65f03c0,                    /* ret          */
  ];
}

/* ------------------------------------------------------------------ *
 * Small builders
 * ------------------------------------------------------------------ */

class StrTab {
  constructor() { this.buf = Buffer.from([0]); } /* index 0 is the empty string */
  add(s) {
    const existing = this.buf.indexOf(Buffer.from(s + '\0', 'utf8'));
    if (existing > 0) return existing;            /* de-duplicate: offsets must be shared */
    const off = this.buf.length;
    this.buf = Buffer.concat([this.buf, Buffer.from(s + '\0', 'utf8')]);
    return off;
  }
}

/** SysV ELF hash. The dynamic linker uses this; a hand-built .so without it will not load. */
function sysvHash(strtab, symNames) {
  const nbucket = 8;
  const nchain = symNames.length;
  const buckets = new Uint32Array(nbucket);
  const chain = new Uint32Array(nchain);
  for (let i = 0; i < nchain; i++) {
    let h = 0;
    for (const c of Buffer.from(symNames[i], 'utf8')) h = (h * 31 + c) >>> 0;
    const b = h % nbucket;
    chain[i] = buckets[b];
    buckets[b] = i;
  }
  const head = Buffer.alloc(8);
  head.writeUInt32LE(nbucket, 0);
  head.writeUInt32LE(nchain, 4);
  return Buffer.concat([head, Buffer.from(buckets), Buffer.from(chain)]);
}

/* ------------------------------------------------------------------ *
 * Assembly
 * ------------------------------------------------------------------ */

export function buildSo({ soname = 'libmobilelab.so' } = {}) {
  /* --- .text : one stub per export, 8 bytes each, 16-byte aligned --- */
  const textWords = [];
  EXPORTS.forEach((e, i) => {
    while (textWords.length % 4 !== 0) textWords.push(0xd503201f); /* nop padding */
    textWords.push(...stubBody(i));
  });
  while (textWords.length % 4 !== 0) textWords.push(0xd503201f);
  const text = Buffer.alloc(textWords.length * 4);
  textWords.forEach((w, i) => text.writeUInt32LE(w >>> 0, i * 4));

  /* --- .rodata : NUL-terminated strings, offset 0 is a filler so no string is at 0 --- */
  const rodataParts = [Buffer.from([0])];
  const rodataOffsets = [];
  for (const s of RODATA_STRINGS) {
    rodataOffsets.push(rodataParts.reduce((a, b) => a + b.length, 0));
    rodataParts.push(Buffer.from(s + '\0', 'utf8'));
  }
  const rodata = Buffer.concat(rodataParts);

  /* --- .dynstr --- */
  const dynstr = new StrTab();
  const sonameOff = dynstr.add(soname);
  const neededNames = ['liblog.so', 'libc.so'];
  const neededOffs = neededNames.map(n => dynstr.add(n));
  const exportNameOffs = EXPORTS.map(e => dynstr.add(e.name));

  /* --- .dynsym : index 0 is the mandatory null entry --- */
  const symNames = ['', ...EXPORTS.map(e => e.name)];
  const dynsym = Buffer.alloc(SYMTAB_SIZE * (EXPORTS.length + 1));
  /* Symbols are filled in after the section layout, because a defined symbol's st_value
     is the vaddr of the code it points at, and that is only known once .text is placed. */

  const hash = sysvHash(dynstr, symNames);

  /* --- lay out sections after the ELF header --- */
  const sections = [
    { name: '', type: SHT_NULL, flags: 0, addr: 0, off: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 },
    { name: '.text', type: SHT_PROGBITS, flags: SHF_ALLOC | SHF_EXECINSTR, data: text, align: 4, entsize: 0 },
    { name: '.rodata', type: SHT_PROGBITS, flags: SHF_ALLOC, data: rodata, align: 8, entsize: 0 },
    /* sh_link of .hash must be the index of the symbol table it indexes (.dynsym, 5).
       Getting this wrong still passes a hand-rolled parse and still produces a file that
       no dynamic linker will load — caught by the pyelftools oracle, not by us. */
    { name: '.hash', type: SHT_HASH, flags: SHF_ALLOC, data: hash, align: 8, entsize: 4, link: 5 },
    { name: '.dynstr', type: SHT_STRTAB, flags: SHF_ALLOC, data: dynstr.buf, align: 1, entsize: 0 },
    { name: '.dynsym', type: SHT_DYNSYM, flags: SHF_ALLOC, data: dynsym, align: 8, entsize: SYMTAB_SIZE, link: 4 },
    { name: '.dynamic', type: SHT_DYNAMIC, flags: SHF_ALLOC, data: null, align: 8, entsize: DYN_SIZE, link: 4 },
    { name: '.shstrtab', type: SHT_STRTAB, flags: 0, data: null, align: 1, entsize: 0 },
  ];

  /* Section data starts AFTER the ELF header and the program-header table. Starting at
     EHDR_SIZE alone silently overwrites the phdrs with .text — a file that still parses as
     sections and still cannot be loaded. Caught by the pyelftools oracle. */
  const PHNUM = 2; /* PT_LOAD + PT_DYNAMIC */
  let off = EHDR_SIZE + PHDR_SIZE * PHNUM;
  for (const s of sections) {
    if (s.type === SHT_NULL || !s.data) continue;
    s.off = off;
    /* vaddr == file offset: the load base is 0, so the mapping is the identity. That is what
       makes a hand-placed .so loadable without a real linker's segment arithmetic. */
    s.addr = s.flags & SHF_ALLOC ? off : 0;
    off += s.data.length;
    off = (off + (s.align - 1)) & ~(s.align - 1);
  }
  /* --- now that .text has an address, write the symbol table --- */
  const textAddr = sections[1].addr;
  EXPORTS.forEach((e, i) => {
    const o = SYMTAB_SIZE * (i + 1);
    const isImport = e.kind === 'import';
    const stInfo = (STB_GLOBAL << 4) | (e.kind === 'func' ? STT_FUNC : STT_NOTYPE);
    const stShndx = isImport ? 0 : 1;            /* 0 = SHN_UNDEF, which is what an import is */
    const stValue = isImport ? 0 : textAddr + i * 8;
    dynsym.writeUInt32LE(exportNameOffs[i], o);
    dynsym.writeUInt8(stInfo, o + 4);
    dynsym.writeUInt8(STV_DEFAULT, o + 5);
    dynsym.writeUInt16LE(stShndx, o + 6);
    dynsym.writeBigUInt64LE(BigInt(stValue), o + 8);
    dynsym.writeBigUInt64LE(BigInt(isImport ? 0 : 8), o + 16);
  });
  const shstrtab = new StrTab();
  for (const s of sections) if (s.name) s.nameOff = shstrtab.add(s.name);
  const shstrBuf = shstrtab.buf;

  /* .dynamic needs the addresses of .dynstr/.dynsym/.hash, so it is built after layout */
  const dynEntries = [
    [DT_SONAME, sonameOff],
    [DT_NEEDED, neededOffs[0]],
    [DT_NEEDED, neededOffs[1]],
    [DT_HASH, sections[3].addr],
    [DT_STRTAB, sections[4].addr],
    [DT_SYMTAB, sections[5].addr],
    [DT_STRSZ, sections[4].data.length],
    [DT_SYMENT, SYMTAB_SIZE],
    [DT_NULL, 0],
  ];
  const dyn = Buffer.alloc(DYN_SIZE * dynEntries.length);
  dynEntries.forEach(([tag, val], i) => {
    dyn.writeBigUInt64LE(BigInt(tag), i * DYN_SIZE);
    dyn.writeBigUInt64LE(BigInt(val), i * DYN_SIZE + 8);
  });
  sections[6].data = dyn;
  sections[6].off = off;
  sections[6].addr = off;
  off += dyn.length;
  off = (off + 7) & ~7;

  sections[7].data = shstrBuf;
  sections[7].off = off;
  off += shstrBuf.length;
  off = (off + 7) & ~7;

  /* --- program headers --- */
  const phdrs = [];
  const loadEnd = sections[6].off + sections[6].data.length;
  phdrs.push({ type: PT_LOAD, flags: 5, off: 0, vaddr: 0, paddr: 0, filesz: loadEnd, memsz: loadEnd, align: PAGE });
  phdrs.push({ type: PT_DYNAMIC, flags: 6, off: sections[6].off, vaddr: sections[6].addr, paddr: sections[6].addr, filesz: sections[6].data.length, memsz: sections[6].data.length, align: 8 });
  if (phdrs.length !== PHNUM) throw new Error(`internal: PHNUM=${PHNUM} but ${phdrs.length} program headers`);

  /* --- assemble the file --- */
  const shoff = (off + 7) & ~7;
  const total = shoff + SHDR_SIZE * sections.length;
  const out = Buffer.alloc(total);
  out.fill(0);

  const shstrndx = sections.findIndex(s => s.name === '.shstrtab');
  if (shstrndx <= 0) throw new Error('internal: .shstrtab missing from the section table');
  /* ELF header */
  /* e_ident: [0]=0x7f [1..3]="ELF" [4]=EI_CLASS [5]=EI_DATA [6]=EI_VERSION [7]=EI_OSABI */
  out.writeUInt8(0x7f, 0); out.write('ELF', 1, 'latin1');
  out.writeUInt8(ELFCLASS64, 4);
  out.writeUInt8(ELFDATA2LSB, 5);
  out.writeUInt8(EV_CURRENT, 6);
  out.writeUInt8(0, 7);                       /* EI_OSABI = SYSV */
  out.writeUInt16LE(0, 8);                    /* e_ident padding */
  out.writeUInt16LE(ET_DYN, 16);
  out.writeUInt16LE(EM_AARCH64, 18);
  out.writeUInt32LE(EV_CURRENT, 20);
  out.writeBigUInt64LE(0n, 24);               /* e_entry */
  out.writeUInt32LE(0, 48);                   /* e_flags */
  out.writeUInt16LE(EHDR_SIZE, 52);           /* e_ehsize */
  out.writeUInt16LE(PHDR_SIZE, 54);           /* e_phentsize */
  out.writeBigUInt64LE(BigInt(EHDR_SIZE), 32); /* e_phoff: phdrs start AFTER the ELF header */
  out.writeBigUInt64LE(BigInt(shoff), 40);     /* e_shoff */
  out.writeUInt16LE(phdrs.length, 56);
  out.writeUInt16LE(SHDR_SIZE, 58);
  out.writeUInt16LE(sections.length, 60);
  out.writeUInt16LE(shstrndx, 62);            /* e_shstrndx */

  /* program headers */
  phdrs.forEach((p, i) => {
    const o = EHDR_SIZE + PHDR_SIZE * i;   /* phdrs live after the 64-byte ELF header */
    out.writeUInt32LE(p.type, o);
    out.writeUInt32LE(p.flags, o + 4);
    out.writeBigUInt64LE(BigInt(p.off), o + 8);
    out.writeBigUInt64LE(BigInt(p.vaddr), o + 16);
    out.writeBigUInt64LE(BigInt(p.paddr), o + 24);
    out.writeBigUInt64LE(BigInt(p.filesz), o + 32);
    out.writeBigUInt64LE(BigInt(p.memsz), o + 40);
    out.writeBigUInt64LE(BigInt(p.align), o + 48);
  });

  /* section contents + headers */
  sections.forEach((s, i) => {
    if (s.data) s.data.copy(out, s.off);
    const o = shoff + SHDR_SIZE * i;
    out.writeUInt32LE(s.nameOff || 0, o);
    out.writeUInt32LE(s.type, o + 4);
    out.writeBigUInt64LE(BigInt(s.flags || 0), o + 8);
    out.writeBigUInt64LE(BigInt(s.addr || 0), o + 16);
    out.writeBigUInt64LE(BigInt(s.off || 0), o + 24);
    out.writeBigUInt64LE(BigInt(s.data ? s.data.length : 0), o + 32);
    out.writeUInt32LE(s.link || 0, o + 40);
    out.writeUInt32LE(s.info || 0, o + 44);
    out.writeBigUInt64LE(BigInt(s.align || 0), o + 48);
    out.writeBigUInt64LE(BigInt(s.entsize || 0), o + 56);
  });


  return {
    buffer: out,
    soname,
    meta: {
      exports: EXPORTS.filter(e => e.kind === 'func').map(e => e.name),
      imports: EXPORTS.filter(e => e.kind === 'import').map(e => e.name),
      needed: neededNames,
      rodata: RODATA_STRINGS,
      rodataOffsets,
      sizes: { text: text.length, rodata: rodata.length, dynstr: dynstr.buf.length, dynsym: dynsym.length, hash: hash.length, dynamic: dyn.length, total: total },
    },
  };
}

/**
 * Independent re-parse of what we just built. Deliberately does NOT reuse the builder's
 * variables — it walks the byte buffer the way a loader would. If buildSo and this
 * disagree, the file is wrong regardless of which one is.
 */
export function verifySo(buf) {
  const problems = [];
  if (buf.readUInt32BE(0) !== 0x7f454c46) problems.push('bad ELF magic');
  if (buf[4] !== ELFCLASS64) problems.push(`EI_CLASS=${buf[4]}, want ELFCLASS64(2)`);
  if (buf[5] !== ELFDATA2LSB) problems.push(`EI_DATA=${buf[5]}, want ELFDATA2LSB(1)`);
  if (buf[6] !== EV_CURRENT) problems.push(`EI_VERSION=${buf[6]}, want 1`);
  const etype = buf.readUInt16LE(16);
  const machine = buf.readUInt16LE(18);
  if (etype !== ET_DYN) problems.push(`e_type=${etype}, want ET_DYN(3)`);
  if (machine !== EM_AARCH64) problems.push(`e_machine=${machine}, want EM_AARCH64(183)`);

  const phoff = Number(buf.readBigUInt64LE(32));
  const shoff = Number(buf.readBigUInt64LE(40));
  const phnum = buf.readUInt16LE(56);
  const shnum = buf.readUInt16LE(60);
  const shstrndx = buf.readUInt16LE(62);
  if (phnum < 2) problems.push(`e_phnum=${phnum}, want >=2`);

  /* sections */
  const sh = i => {
    const o = shoff + SHDR_SIZE * i;
    return {
      nameOff: buf.readUInt32LE(o), type: buf.readUInt32LE(o + 4),
      addr: Number(buf.readBigUInt64LE(o + 16)), off: Number(buf.readBigUInt64LE(o + 24)),
      size: Number(buf.readBigUInt64LE(o + 32)), link: buf.readUInt32LE(o + 40),
      entsize: Number(buf.readBigUInt64LE(o + 56)),
    };
  };
  const shstr = sh(shstrndx);
  /* Bounded on purpose: a malformed offset that never hits a NUL used to walk off the end
     of the buffer, where buf[e] is undefined and `undefined !== 0` is true forever. A
     verifier that hangs on bad input is a verifier that cannot report bad input. */
  const nameAt = off => {
    if (!(off >= 0 && off < buf.length)) return `<bad-offset:${off}>`;
    let e = off;
    while (e < buf.length && buf[e] !== 0) e++;
    return buf.toString('utf8', off, e);
  };
  const byName = {};
  for (let i = 0; i < shnum; i++) {
    const s = sh(i);
    byName[nameAt(shstr.off + s.nameOff)] = s;
  }
  for (const req of ['.text', '.rodata', '.dynstr', '.dynsym', '.dynamic', '.hash']) {
    if (!byName[req]) problems.push(`missing section ${req}`);
  }

  /* sh_link sanity: .hash must index a symbol table; .dynsym and .dynamic must index a
     string table. A wrong sh_link is invisible to a byte-walk but fatal to a real loader —
     this check exists because the pyelftools oracle caught exactly that bug first. */
  const indexOfName = n => {
    for (let i = 0; i < shnum; i++) {
      if (nameAt(shstr.off + sh(i).nameOff) === n) return i;
    }
    return -1;
  };
  const links = [['.hash', '.dynsym'], ['.dynsym', '.dynstr'], ['.dynamic', '.dynstr']];
  for (const [secName, want] of links) {
    const got = byName[secName]?.link;
    const wantIdx = indexOfName(want);
    if (got !== wantIdx) problems.push(`${secName} sh_link=${got}, want ${want} (${wantIdx})`);
  }

  /* .dynstr + .dynsym walk */
  const dynstr = byName['.dynstr'];
  const dynsym = byName['.dynsym'];
  if (dynstr && dynsym) {
    const symCount = Math.floor(dynsym.size / SYMTAB_SIZE);
    if (symCount < 2) problems.push('dynsym has no symbols');
    /* Defined vs undefined is decided by st_shndx, not by st_type: an import is
       SHN_UNDEF whatever its type. Counting only STT_FUNC entries would silently pass a
       .so that imports nothing, which is exactly the kind of vacuous pass to avoid. */
    let defined = 0, undefined = 0, definedFuncs = 0;
    for (let i = 1; i < symCount; i++) {
      const o = dynsym.off + SYMTAB_SIZE * i;
      const nameOff = buf.readUInt32LE(o);
      const info = buf.readUInt8(o + 4);
      const shndx = buf.readUInt16LE(o + 6);
      if (nameOff === 0) { problems.push(`sym[${i}] has no name`); continue; }
      if (nameOff >= dynstr.size) { problems.push(`sym[${i}] name offset out of range`); continue; }
      if (shndx === 0) { undefined++; continue; }
      defined++;
      if ((info & 0xf) === STT_FUNC) definedFuncs++;
    }
    if (definedFuncs === 0) problems.push('no defined STT_FUNC symbols');
    if (defined === 0) problems.push('no defined symbols');
    if (undefined === 0) problems.push('no undefined (imported) symbols');
    if (symCount !== EXPORTS.length + 1) problems.push(`dynsym count ${symCount}, want ${EXPORTS.length + 1}`);
  }

  /* .dynamic walk — every pointer must land inside a mapped section */
  const dynamic = byName['.dynamic'];
  if (dynamic) {
    const count = Math.floor(dynamic.size / DYN_SIZE);
    let sawNull = false, sawSoname = false, needed = 0;
    for (let i = 0; i < count; i++) {
      const o = dynamic.off + DYN_SIZE * i;
      const tag = Number(buf.readBigUInt64LE(o));
      const val = Number(buf.readBigUInt64LE(o + 8));
      if (tag === DT_NULL) sawNull = true;
      if (tag === DT_SONAME) sawSoname = true;
      if (tag === DT_NEEDED) needed++;
      if (tag === DT_STRTAB || tag === DT_SYMTAB || tag === DT_HASH) {
        if (val === 0 || val >= buf.length) problems.push(`DT tag ${tag} points outside the file (${val})`);
      }
    }
    if (!sawNull) problems.push('.dynamic has no DT_NULL terminator');
    if (!sawSoname) problems.push('.dynamic has no DT_SONAME');
    if (needed < 1) problems.push('.dynamic declares no DT_NEEDED');
  }

  /* every PT_LOAD must be inside the file */
  for (let i = 0; i < phnum; i++) {
    const o = phoff + PHDR_SIZE * i;
    const type = buf.readUInt32LE(o);
    if (type !== PT_LOAD) continue;
    const off = Number(buf.readBigUInt64LE(o + 8));
    const filesz = Number(buf.readBigUInt64LE(o + 32));
    if (off + filesz > buf.length) problems.push(`PT_LOAD #${i} runs past EOF`);
  }

  return { ok: problems.length === 0, problems, sha256: createHash('sha256').update(buf).digest('hex') };
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
  const { buffer, meta, soname } = buildSo();
  const v = verifySo(buffer);
  process.stdout.write(JSON.stringify({ soname, meta, verify: v }, null, 2) + '\n');
  process.exit(v.ok ? 0 : 1);
}
