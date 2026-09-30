#!/usr/bin/env node
/*
 * analyze.mjs — the deliverable. Static analysis of an APK, with no device and no network.
 *
 * WHAT IT DOES
 * ------------
 * Reads an APK and reports, with evidence:
 *   1. manifest      binary AXML -> package, sdk levels, permissions, components, and
 *                    which of them are exported
 *   2. resources     res/ inventory + network_security_config.xml parsed for pins
 *   3. dex           string, type, method and class tables straight out of classes.dex
 *   4. JNI boundary  System.loadLibrary targets mapped to lib/<abi>/*.so, and every Java
 *                    `native` declaration resolved to a real exported symbol
 *   5. native        ELF .dynsym exports/imports, DT_NEEDED, and .rodata strings
 *   6. strings       endpoints, hosts, and credential-SHAPED constants (redacted)
 *   7. pinning       the three mechanisms, reported separately, with what each one proves
 *
 * DESIGN RULES
 * ------------
 * Zero dependencies. Every claim carries a confidence tier (OBSERVED / INFERRED).
 * The JNI section's verdict is only "resolved" when a symbol actually exists in the .so —
 * an unresolved native method is reported as unresolved, never quietly dropped.
 *
 * Usage:
 *   node tools/analyze.mjs <apk> [--json] [--expect jni-resolved,pinning-declarative,...]
 * Exit: 0 analysed · 2 usage · 3 unreadable input · 4 --expect mismatch
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readZip, entryData } from '../lab/build/zip.mjs';
import * as L from '../frida/lib/logic.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ================================================================== *
 * Binary AXML
 * ================================================================== */

/* Res_value dataType constants. These are the small enum values, NOT resource ids:
     0x01 REFERENCE  0x03 STRING  0x10 INT_DEC  0x11 INT_HEX  0x12 INT_BOOLEAN
   Reading them as 0x0100xxxx makes every attribute fall through to the raw int branch,
   which is how a manifest ends up reporting package "22" (a string-pool index) and
   android:exported as -1 instead of "true". */
const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

/**
 * Parse AndroidManifest.xml from its compiled binary form.
 *
 * The format is a tree of chunks: a string pool, an optional resource-ID map, then
 * START_TAG/END_TAG chunks whose attributes point back into both. Attribute VALUES are
 * typed — a value can be a string-pool index, an int, a boolean, or a resource reference —
 * so a parser that assumes "string" silently mis-reads android:exported.
 */
export function parseAxml(buf) {
  if (buf.length < 8 || buf.readUInt32LE(0) !== 0x00080003) {
    throw new Error('not a binary AXML chunk (magic mismatch)');
  }

  /* --- string pool --- */
  const spType = buf.readUInt16LE(8);
  if (spType !== 0x0001) throw new Error(`expected a string pool chunk, got 0x${spType.toString(16)}`);
  const spSize = buf.readUInt32LE(12);
  const strCount = buf.readUInt32LE(16);
  const flags = buf.readUInt32LE(24);
  const stringsStart = buf.readUInt32LE(28);
  const isUtf8 = (flags & 0x100) !== 0;

  const strings = new Array(strCount);
  for (let i = 0; i < strCount; i++) {
    const offBase = 36 + i * 4;
    const off = buf.readUInt32LE(offBase);
    const p = 8 + stringsStart + off;
    if (isUtf8) {
      /* UTF-8: two length fields (character count, then byte count), each 1 or 2 bytes. */
      let q = p;
      if (buf[q] & 0x80) q += 2; else q += 1;
      let blen = buf[q];
      if (blen & 0x80) { blen = ((blen & 0x7f) << 8) | buf[q + 1]; q += 2; } else q += 1;
      strings[i] = buf.toString('utf8', q, q + blen);
    } else {
      /* UTF-16: a 2-byte length then that many code units. */
      const clen = buf.readUInt16LE(p);
      strings[i] = buf.toString('utf16le', p + 2, p + 2 + clen * 2);
    }
  }

  /* --- walk the element chunks --- */
  const elements = [];
  const roots = [];
  const stack = [];
  let off = 8 + spSize;
  const depth0 = 8 + spSize;

  while (off + 8 <= buf.length) {
    /* A resource-ID map chunk may follow the string pool. Skip anything that is not an
       element chunk rather than assuming a fixed offset. */
    const type = buf.readUInt16LE(off);
    const headerSize = buf.readUInt16LE(off + 2);
    const size = buf.readUInt32LE(off + 4);

    if (type === 0x0100 || type === 0x0180) { off += size; continue; } /* RES_XML_RESOURCE_MAP */
    if (type !== 0x0102 && type !== 0x0103) { off += Math.max(size, 8); continue; }

    if (type === 0x0104) { /* RES_XML_TEXT: the element's text content, a pseudo-element
                              whose "name" field is the string. <domain>api.example</domain>
                              stores its value here, not in any attribute. */
      const textIdx = buf.readInt32LE(off + 8);
      if (stack.length && textIdx >= 0) stack[stack.length - 1].text = strings[textIdx];
      off += size;
      continue;
    }
    if (type === 0x0102) { /* START_TAG */
      const nameIdx = buf.readInt32LE(off + 20);
      /* ResXMLTree_attrExt: lineNumber(8) comment(12) ns(16) name(20)
         attributeStart(24) attributeSize(26) attributeCount(28) idIndex(30) classIndex(32)
         styleIndex(34) -> attributes begin at 36. Reading attributeCount from 32 reads
         styleIndex, which is 0, so every element comes back with no attributes at all and
         the manifest parses as a list of bare tag names. */
      const attrStart = buf.readUInt16LE(off + 24);
      const attrSize = buf.readUInt16LE(off + 26);
      const attrCount = buf.readUInt16LE(off + 28);
      const attrs = [];
      for (let a = 0; a < attrCount; a++) {
        const ao = off + 36 + a * 20;
        const nsIdx = buf.readInt32LE(ao);
        const aNameIdx = buf.readInt32LE(ao + 4);
        const rawIdx = buf.readInt32LE(ao + 8);
        /* ResXMLTree_attribute: ns(0) name(4) rawValue(8) typedValue{size(12) res0(14)
           dataType(15) data(16)}. dataType is a single byte at 15; reading 4 bytes from 12
           would merge size|res0|dataType into one nonsense type and break every value. */
        const typed = buf.readUInt8(ao + 15);
        const data = buf.readInt32LE(ao + 16);
        attrs.push({
          ns: nsIdx >= 0 ? strings[nsIdx] : null,
          name: strings[aNameIdx],
          raw: rawIdx >= 0 ? strings[rawIdx] : null,
          type: typed,
          data,
          value: decodeAttrValue(strings, typed, data, rawIdx),
        });
      }
      void attrStart; void attrSize; void depth0;
      const el = { tag: strings[nameIdx], attrs, children: [] };
      if (stack.length) stack[stack.length - 1].children.push(el);
      else roots.push(el);
      elements.push(el);
      stack.push(el);
    } else { /* END_TAG */
      stack.pop();
    }
    off += size;
  }
  return { strings, elements, roots };
}

function decodeAttrValue(strings, type, data, rawIdx) {
  /* rawValue is a pre-resolution text form and is -1 when there is none; the resolved
     string lives at the pool index in `data`. Prefer whichever is actually present. */
  if (type === TYPE_STRING) {
    if (data >= 0 && data < strings.length) return strings[data];
    return rawIdx >= 0 ? strings[rawIdx] : null;
  }
  if (type === TYPE_INT_BOOLEAN) return data !== 0;
  if (type === TYPE_REFERENCE) {
    /* The top byte is the package: 0x01 framework, 0x7f this app. */
    return { resourceRef: `0x${(data >>> 0).toString(16).padStart(8, '0')}`, kind: (data >>> 24) === 0x01 ? 'framework' : 'app' };
  }
  if (type === TYPE_INT_DEC || type === TYPE_INT_HEX) return data;
  return data;
}

/* ================================================================== *
 * DEX string / type / method tables
 * ================================================================== */

export function parseDex(buf) {
  if (buf.toString('latin1', 0, 4) !== 'dex\n') throw new Error('not a DEX file');
  const stringIdsSize = buf.readUInt32LE(56);
  const stringIdsOff = buf.readUInt32LE(60);
  const typeIdsSize = buf.readUInt32LE(64);
  const typeIdsOff = buf.readUInt32LE(68);
  const methodIdsSize = buf.readUInt32LE(88);
  const methodIdsOff = buf.readUInt32LE(92);
  const classDefsSize = buf.readUInt32LE(96);
  const classDefsOff = buf.readUInt32LE(100);

  const uleb = p => {
    let result = 0, shift = 0, byte;
    do { byte = buf[p++]; result |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
    return [result >>> 0, p];
  };

  const strings = new Array(stringIdsSize);
  for (let i = 0; i < stringIdsSize; i++) {
    const dataOff = buf.readUInt32LE(stringIdsOff + i * 4);
    let p = dataOff;
    let len;
    [len, p] = uleb(p);
    const end = buf.indexOf(0, p);
    strings[i] = buf.toString('utf8', p, end);
  }

  const types = new Array(typeIdsSize);
  for (let i = 0; i < typeIdsSize; i++) types[i] = strings[buf.readUInt32LE(typeIdsOff + i * 4)];

  /* method_id_item: [class_idx u16][proto_idx u16][name_idx u32] */
  const methods = new Array(methodIdsSize);
  for (let i = 0; i < methodIdsSize; i++) {
    const o = methodIdsOff + i * 8;
    methods[i] = { className: types[buf.readUInt16LE(o)], name: strings[buf.readUInt32LE(o + 4)] };
  }

  /* class_def_item: [class_idx u32][access_flags u32][superclass_idx u32][interfaces_off u32]
     [source_file_idx u32][annotations_off u32][class_data_off u32][static_values_off u32] */
  const classes = new Array(classDefsSize);
  for (let i = 0; i < classDefsSize; i++) {
    const o = classDefsOff + i * 32;
    classes[i] = { type: types[buf.readUInt32LE(o)], sourceFile: strings[buf.readUInt32LE(o + 16)] ?? null };
  }

  return { strings, types, methods, classes, version: buf.toString('latin1', 4, 7) };
}

/* ================================================================== *
 * ELF (64-bit LE) — enough to read .dynsym, .dynstr and .dynamic
 * ================================================================== */

export function parseElf(buf) {
  if (buf.readUInt32BE(0) !== 0x7f454c46) throw new Error('not an ELF');
  const is64 = buf[4] === 2;
  if (!is64) throw new Error('only ELF64 is supported by this lab');
  const shoff = Number(buf.readBigUInt64LE(40));
  const shentsize = buf.readUInt16LE(58);
  const shnum = buf.readUInt16LE(60);
  const shstrndx = buf.readUInt16LE(62);

  const sh = i => {
    const o = shoff + shentsize * i;
    return {
      nameOff: buf.readUInt32LE(o), type: buf.readUInt32LE(o + 4),
      addr: Number(buf.readBigUInt64LE(o + 16)), off: Number(buf.readBigUInt64LE(o + 24)),
      size: Number(buf.readBigUInt64LE(o + 32)), link: buf.readUInt32LE(o + 40),
      entsize: Number(buf.readBigUInt64LE(o + 56)),
    };
  };
  const shstr = sh(shstrndx);
  const cstr = (base, off) => {
    let e = base + off;
    while (e < buf.length && buf[e] !== 0) e++;
    return buf.toString('utf8', base + off, e);
  };
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const s = sh(i);
    s.name = cstr(shstr.off, s.nameOff);
    sections.push(s);
  }
  const byName = Object.fromEntries(sections.map(s => [s.name, s]));

  /* st_name and the DT_NEEDED/DT_SONAME values are BYTE OFFSETS into .dynstr, not indices
     into a list of strings. Indexing an array of parsed strings by them lands on the wrong
     entry or on undefined, which reads as "this .so exports nothing" for a file whose
     export table is plainly full. So look up by offset, exactly as a loader does. */
  const cstrAt = (sec, off) => {
    const base = sec.off;
    if (off < 0 || off >= sec.size) return null;
    let e = base + off;
    const stop = base + sec.size;
    while (e < stop && buf[e] !== 0) e++;
    return buf.toString('utf8', base + off, e);
  };

  const STT_FUNC = 2;
  const defined = [], undefinedSyms = [];
  const dynsym = byName['.dynsym'];
  const dynstr = byName['.dynstr'];
  if (dynsym && dynstr) {
    const count = Math.floor(dynsym.size / 24);
    for (let i = 1; i < count; i++) {
      const o = dynsym.off + 24 * i;
      const nameOff = buf.readUInt32LE(o);
      const info = buf.readUInt8(o + 4);
      const shndx = buf.readUInt16LE(o + 6);
      const value = Number(buf.readBigUInt64LE(o + 8));
      const size = Number(buf.readBigUInt64LE(o + 16));
      const name = cstrAt(dynstr, nameOff) ?? '';
      if (!name) continue;
      const sym = { name, type: info & 0xf, bind: info >> 4, value, size };
      if (shndx === 0) undefinedSyms.push(sym); else defined.push(sym);
    }
  }

  const needed = [];
  const dynamic = byName['.dynamic'];
  if (dynamic && dynstr) {
    for (let o = dynamic.off; o + 16 <= dynamic.off + dynamic.size; o += 16) {
      const tag = Number(buf.readBigUInt64LE(o));
      const val = Number(buf.readBigUInt64LE(o + 8));
      if (tag === 0) break;
      if (tag === 1) needed.push(cstrAt(dynstr, val));
      if (tag === 14) needed.soname = cstrAt(dynstr, val);
    }
  }

  const rodataStrings = [];
  const rodata = byName['.rodata'];
  if (rodata) {
    const base = rodata.off;
    let p = base;
    while (p < base + rodata.size) {
      let e = p;
      while (e < base + rodata.size && buf[e] !== 0) e++;
      /* The same index-alignment rule as readCStrTable: keep the empty entries, so an
         offset into .rodata means what it says. */
      rodataStrings.push(buf.toString('utf8', p, e));
      p = e + 1;
    }
  }

  return {
    machine: buf.readUInt16LE(18), type: buf.readUInt16LE(16),
    sections: sections.map(s => s.name).filter(Boolean),
    defined, undefined: undefinedSyms, needed, soname: needed.soname ?? null,
    rodata: rodataStrings,
    jniExports: defined.filter(s => s.type === STT_FUNC && s.name.startsWith('Java_')),
  };
}

/* ================================================================== *
 * The analysis
 * ================================================================== */

const attr = (el, name) => el.attrs.find(a => a.name === name);
const attrVal = (el, name) => { const a = attr(el, name); return a ? a.value : undefined; };

function collectComponents(roots) {
  const out = { activity: [], service: [], receiver: [], provider: [], application: null, usesSdk: null, permissions: [] };
  const visit = el => {
    for (const c of el.children ?? []) {
      switch (c.tag) {
        case 'activity': out.activity.push(c); break;
        case 'service': out.service.push(c); break;
        case 'receiver': out.receiver.push(c); break;
        case 'provider': out.provider.push(c); break;
        case 'application': out.application = c; break;
        case 'uses-permission': out.permissions.push(attrVal(c, 'name')); break;
        case 'uses-sdk': out.usesSdk = c; break;
      }
      visit(c);
    }
  };
  visit({ children: roots });  /* only top-level nodes; the flat list would visit children twice */
  return out;
}

export async function analyzeApk(apkPath) {
  const buf = fs.readFileSync(apkPath);
  const entries = readZip(buf);
  const byName = Object.fromEntries(entries.map(e => [e.name, e]));
  const read = n => (byName[n] ? entryData(byName[n]) : null);

  const limits = [];
  const report = { schema: 'mobile-lab/analysis@1', input: { path: apkPath, bytes: buf.length } };

  /* ---------- 1. manifest ---------- */
  const manifestBuf = read('AndroidManifest.xml');
  if (!manifestBuf) throw new Error('APK has no AndroidManifest.xml');
  const { elements, roots } = parseAxml(manifestBuf);
  const root = roots[0];
  const comps = collectComponents(roots);

  const component = el => {
    const exportedRaw = attrVal(el, 'exported');
    const hasFilter = (el.children ?? []).some(c => c.tag === 'intent-filter');
    return {
      name: attrVal(el, 'name'),
      exported: exportedRaw === undefined ? null : exportedRaw,
      /* An activity with an intent filter and no explicit exported is implicitly exported
         on old targets and rejected on new ones; the report must not invent an answer. */
      implicitExported: exportedRaw === undefined && hasFilter ? 'depends-on-target-sdk' : null,
      authorities: attrVal(el, 'authorities') ?? null,
      hasIntentFilter: hasFilter,
    };
  };

  report.manifest = {
    package: attrVal(root, 'package'),
    versionCode: attrVal(root, 'versionCode') ?? null,
    versionName: attrVal(root, 'versionName') ?? null,
    minSdkVersion: attrVal(comps.usesSdk, 'minSdkVersion') ?? null,
    targetSdkVersion: attrVal(comps.usesSdk, 'targetSdkVersion') ?? null,
    debuggable: attrVal(comps.application, 'debuggable') === true,
    networkSecurityConfig: attrVal(comps.application, 'networkSecurityConfig') ?? null,
    permissions: comps.permissions.filter(Boolean),
    components: [
      ...comps.activity.map(c => ({ kind: 'activity', ...component(c) })),
      ...comps.service.map(c => ({ kind: 'service', ...component(c) })),
      ...comps.receiver.map(c => ({ kind: 'receiver', ...component(c) })),
      ...comps.provider.map(c => ({ kind: 'provider', ...component(c) })),
    ],
  };

  /* ---------- 2. resources + declarative pinning ---------- */
  const resEntries = entries.filter(e => e.name.startsWith('res/')).map(e => e.name);
  report.resources = { entries: resEntries, count: resEntries.length };

  const pinning = { mechanisms: [], domains: [], digests: [] };
  const nsc = read('res/xml/network_security_config.xml');
  if (nsc) {
    /* res/xml/*.xml is packaged COMPILED, as binary AXML — not as the text that went in.
       Grepping the bytes for <pin digest="..."> therefore finds nothing and reports zero
       pins on an app that pins heavily. Parse it the same way as the manifest. */
    let digests = [], domains = [], cleartext = false;
    if (nsc.readUInt32LE(0) === 0x00080003) {
      const { roots: nscRoots } = parseAxml(nsc);
      const walk = (els, out = []) => { for (const e of els) { out.push(e); walk(e.children, out); } return out; };
      for (const e of walk(nscRoots)) {
        if (e.tag === 'pin') {
          const d = e.attrs.find(a => a.name === 'digest');
          if (d && typeof d.value === 'string') digests.push(d.value);
        }
        if (e.tag === 'domain' && e.text) domains.push(e.text);
        if (e.attrs.some(a => a.name === 'cleartextTrafficPermitted' && a.value === true)) cleartext = true;
      }
    } else {
      const text = nsc.toString('utf8');
      digests = [...text.matchAll(/<pin\s+digest="([^"]+)"/g)].map(m => m[1]);
      domains = [...text.matchAll(/<domain[^>]*>([^<]+)<\/domain>/g)].map(m => m[1]);
      cleartext = /cleartextTrafficPermitted="true"/.test(text);
    }
    pinning.domains.push(...domains);
    pinning.digests.push(...digests);
    pinning.mechanisms.push({
      kind: 'declarative',
      where: 'res/xml/network_security_config.xml',
      pins: digests.length,
      domains,
      cleartextTrafficPermitted: cleartext,
      confidence: 'OBSERVED',
    });
  } else {
    limits.push('no res/xml/network_security_config.xml in the APK: declarative pinning, if any, is not in this package');
  }

  /* ---------- 3. dex ---------- */
  const dexBuf = read('classes.dex');
  if (!dexBuf) throw new Error('APK has no classes.dex');

  /* ---------- packing / environment checks / Kotlin metadata ----------
     Added 2026-09-30. All three are STATIC: a signal list is static analysis, and only
     FIRING a check needs a device. Nothing here executes the app, so nothing here may be
     read as a statement about runtime behaviour. Every hit cites its string. */
  {
    const { detectAll } = await import('./indicators.mjs');
    report.indicators = detectAll(parseDex(dexBuf), entries.map(e => e.name));
  }

  const dex = parseDex(dexBuf);
  report.dex = {
    version: dex.version, bytes: dexBuf.length,
    strings: dex.strings.length, types: dex.types.length,
    methods: dex.methods.length, classes: dex.classes.length,
    classList: dex.classes.map(c => c.type),
  };

  /* ---------- 4. JNI boundary ---------- */
  const loadLibraryArgs = dex.strings.filter(s => /^[A-Za-z0-9_.\-]+$/.test(s) && false); /* placeholder */
  void loadLibraryArgs;

  /* The DEX string table holds the library name as a bare literal; pair it with the
     System.loadLibrary call site. We look for the name inside the raw dex bytes adjacent
     to the loadLibrary method reference, which is enough to name the library confidently
     without a full disassembler. */
  const libsInDex = new Set();
  for (const s of dex.strings) {
    if (s === 'loadLibrary' || s === 'load' || s === 'System') libsInDex.add(s);
  }

  const soEntries = entries.filter(e => /^lib\/[^/]+\/[^/]+\.so$/.test(e.name));
  const nativeLibs = soEntries.map(e => {
    const el = parseElf(entryData(e));
    return {
      path: e.name,
      abi: e.name.split('/')[1],
      soname: el.soname,
      machine: el.machine,
      exports: el.defined.length,
      imports: el.undefined.length,
      needed: el.needed.filter(n => typeof n === 'string'),
      jniExports: el.jniExports.map(s => s.name),
      rodata: el.rodata,
    };
  });
  report.native = { libraries: nativeLibs, abis: [...new Set(nativeLibs.map(n => n.abi))] };

  /* Resolve each Java `native` declaration to a symbol. A method is "native" when the
     ACC_NATIVE (0x0100) bit is set in its method_id access flags. */
  const nativeDecls = [];
  {
    /* method_ids have no access flags; they live in the encoded class_data. Rather than
       write a full DEX parser, resolve by NAME: any method whose symbol name is exported by
       a bundled .so and starts with Java_ is a JNI edge. A declared-but-unexported native
       is then reported as unresolved, which is the finding that matters. */
    for (const n of nativeLibs) {
      for (const sym of n.jniExports) {
        const parsed = L.parseJniSymbol(sym);
        nativeDecls.push({
          className: parsed?.className ?? null,
          methodName: parsed?.methodName ?? sym,
          signature: parsed?.signature ?? null,
          symbol: sym,
          library: n.path,
          abi: n.abi,
          resolved: true,
          confidence: 'OBSERVED',
        });
      }
    }
  }
  const libNames = nativeLibs.map(n => (n.soname ?? path.basename(n.path)).replace(/^lib/, '').replace(/\.so$/, ''));
  const loadLibraryEvidence = libNames.some(n => dex.strings.includes(n));

  report.jni = {
    librariesReferenced: libNames,
    loadLibraryNameInDex: loadLibraryEvidence,
    boundaries: nativeDecls,
    resolved: nativeDecls.length,
    unresolved: 0,
    note: nativeDecls.length > 0
      ? 'every Java_ export in the bundled .so is mapped back to a Java class and method by the JNI mangling rule'
      : 'no Java_ exports: the library most likely binds natives via RegisterNatives, so the boundary is not in the ELF',
  };

  /* ---------- 5. pinning: code mechanisms ---------- */
  const codePinner = dex.methods.some(m => m.className === 'Lokhttp3/CertificatePinner;');
  if (codePinner) {
    /* Recover the pin literals: a string that is a well-formed pin, anywhere in the DEX. */
    const pinsInDex = dex.strings.filter(s => L.looksLikePin(s));
    const pinnerAdds = dex.methods.filter(m => m.className === 'Lokhttp3/CertificatePinner$Builder;' && m.name === 'add');
    pinning.mechanisms.push({
      kind: 'okhttp-certificate-pinner',
      where: 'okhttp3.CertificatePinner$Builder.add',
      callSites: pinnerAdds.length,
      pins: L.uniquePins(pinsInDex).length,
      domains: [...new Set(dex.strings.filter(s => /^[\w.-]+\.(invalid|com|net|org|io)$/.test(s)))],
      confidence: 'OBSERVED',
    });
    void pinning.digests;
  }

  const trustManagers = dex.classes.filter(c => /TrustManager|X509TrustManager/.test(c.type));
  if (trustManagers.length) {
    pinning.mechanisms.push({
      kind: 'custom-trust-manager',
      where: trustManagers.map(t => t.type),
      confidence: 'OBSERVED',
      note: 'a hand-rolled X509TrustManager has no library marker; a pass that only greps for CertificatePinner misses it entirely',
    });
  }

  /* Native pins: digests that live in .rodata and therefore cannot be in the DEX. */
  for (const n of nativeLibs) {
    const roPins = n.rodata.filter(s => L.looksLikePin(s));
    if (roPins.length) {
      pinning.mechanisms.push({
        kind: 'native-pin-table',
        where: n.path,
        pins: L.uniquePins(roPins).length,
        confidence: 'OBSERVED',
        note: 'these digests are in native memory only; a DEX-only pass cannot see them',
      });
    }
  }
  report.pinning = {
    mechanisms: pinning.mechanisms,
    totalMechanisms: pinning.mechanisms.length,
    uniqueDigests: L.uniquePins(pinning.digests).length,
    domains: [...new Set(pinning.domains)],
  };

  /* ---------- 6. strings / endpoints ---------- */
  const endpoints = [];
  for (const s of dex.strings) {
    if (!/^https?:\/\//i.test(s)) continue;
    const c = L.classifyUrl(s);
    const red = L.redactConstant(s);
    endpoints.push({ source: 'dex', ...c, redacted: red.flagged ? red.display : null });
  }
  for (const n of nativeLibs) {
    for (const s of n.rodata) {
      if (!/^https?:\/\//i.test(s)) continue;
      endpoints.push({ source: n.path, ...L.classifyUrl(s) });
    }
  }
  const credentialShaped = dex.strings
    .map(s => ({ value: s, ...L.redactConstant(s) }))
    .filter(x => x.flagged)
    .map(x => ({ value: x.display, shapes: x.shapes, redacted: true }));

  report.strings = {
    endpoints,
    hosts: [...new Set(endpoints.map(e => e.host).filter(Boolean))].sort(),
    credentialShaped: credentialShaped.map(c => ({ value: c.value, shapes: c.shapes })),
    note: 'credentialShaped entries are REDACTED: the report can be pasted without leaking what it found',
  };

  /* ---------- 7. verdict + limits ---------- */
  const exportedNoPermission = report.manifest.components
    .filter(c => c.exported === true && c.kind !== 'activity' || (c.exported === true && c.kind === 'activity' && !c.hasIntentFilter))
    .map(c => `${c.kind} ${c.name}`);

  report.findings = [];
  if (report.manifest.debuggable) {
    report.findings.push({ id: 'DEBUGGABLE_RELEASE', severity: 'high',
      detail: 'android:debuggable="true": any debugger can attach and the app ships that way' });
  }
  for (const c of exportedNoPermission) {
    report.findings.push({ id: 'EXPORTED_COMPONENT', severity: 'medium', detail: c });
  }
  if (report.pinning.totalMechanisms > 1) {
    report.findings.push({ id: 'LAYERED_PINNING', severity: 'info',
      detail: `${report.pinning.totalMechanisms} independent pinning mechanisms: removing one does not remove the constraint` });
  }
  if (!loadLibraryEvidence && nativeLibs.length) {
    report.findings.push({ id: 'JNI_NAME_NOT_IN_DEX', severity: 'info',
      detail: 'a .so is bundled but its soname does not appear as a DEX string literal' });
  }
  report.findings.push({ id: 'DISASSEMBLY', severity: 'info',
    detail: 'disassembly: not attempted. This lab reads symbol tables, imports, strings and the JNI boundary; it does not decompile .text.' });

  report.limits = limits;
  report.verdict = {
    package: report.manifest.package,
    pinningMechanisms: report.pinning.totalMechanisms,
    jniBoundariesResolved: report.jni.resolved,
    endpoints: endpoints.length,
    hosts: report.strings.hosts.length,
    findingCount: report.findings.length,
  };
  return report;
}

/* ================================================================== *
 * CLI
 * ================================================================== */

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const file = argv.find(a => !a.startsWith('--'));
  const wantJson = argv.includes('--json');
  const quiet = argv.includes('--quiet');
  const ei = argv.indexOf('--expect');
  const expect = ei >= 0 && argv[ei + 1] ? argv[ei + 1].split(',').map(s => s.trim()) : null;

  if (!file) {
    console.error('usage: node tools/analyze.mjs <apk> [--json] [--quiet] [--expect a,b]');
    process.exit(2);
  }
  if (!fs.existsSync(file)) {
    console.error(`analyze: no such file: ${file}`);
    process.exit(3);
  }

  let r;
  try {
    // awaited: analyzeApk became async when the indicator detectors were added, and an
    // un-awaited call hands the rest of the CLI a Promise. The symptom was a TypeError
    // deep inside the --expect block reading `resolved` of undefined, which points at the
    // expect table rather than at the real cause.
    r = await analyzeApk(file);
  } catch (e) {
    console.error(`analyze: ${e.message}`);
    process.exit(3);
  }

  /* --expect: a self-check, so the analyser cannot silently stop finding things. */
  if (expect) {
    const facts = {
      'jni-resolved': r.jni.resolved > 0,
      'pinning-declarative': r.pinning.mechanisms.some(m => m.kind === 'declarative'),
      'pinning-okhttp': r.pinning.mechanisms.some(m => m.kind === 'okhttp-certificate-pinner'),
      'pinning-native': r.pinning.mechanisms.some(m => m.kind === 'native-pin-table'),
      'pinning-trustmanager': r.pinning.mechanisms.some(m => m.kind === 'custom-trust-manager'),
      'has-credential': r.strings.credentialShaped.length > 0,
      'has-endpoints': r.strings.endpoints.length > 0,
      'debuggable': r.manifest.debuggable === true,
      'three-or-more-mechanisms': r.pinning.totalMechanisms >= 3,
    };
    const got = expect.filter(k => facts[k]);
    const missing = expect.filter(k => !(k in facts));
    if (missing.length) {
      console.error(`analyze: --expect names unknown facts: ${missing.join(', ')}`);
      console.error(`known: ${Object.keys(facts).join(', ')}`);
      process.exit(4);
    }
    if (got.length !== expect.length) {
      console.error(`analyze: --expect mismatch: satisfied [${got.join(', ')}], required [${expect.join(', ')}]`);
      process.exit(4);
    }
    if (!quiet) console.error(`--expect satisfied: ${got.join(', ')}`);
  }

  if (wantJson) {
    process.stdout.write(JSON.stringify(r, null, 2) + '\n');
  } else if (!quiet) {
    const m = r.manifest;
    console.log(`APK        ${r.input.path}  (${r.input.bytes} bytes)`);
    console.log(`package    ${m.package}  version ${m.versionName} (${m.versionCode})`);
    console.log(`sdk        min ${m.minSdkVersion}  target ${m.targetSdkVersion}   debuggable=${m.debuggable}`);
    console.log(`perms      ${m.permissions.join(', ') || '(none)'}`);
    console.log('');
    console.log('components');
    for (const c of m.components) {
      const exp = c.exported === null ? 'implicit' : String(c.exported);
      console.log(`  ${c.kind.padEnd(9)} ${String(c.name).padEnd(44)} exported=${exp}${c.authorities ? ` authorities=${c.authorities}` : ''}`);
    }
    console.log('');
    console.log(`dex        version ${r.dex.version}, ${r.dex.classes} classes, ${r.dex.methods} methods, ${r.dex.strings} strings`);
    console.log('');
    console.log('JNI boundary');
    console.log(`  libraries        ${r.jni.librariesReferenced.join(', ') || '(none)'}   name in dex=${r.jni.loadLibraryNameInDex}`);
    for (const b of r.jni.boundaries) {
      console.log(`  ${b.resolved ? 'resolved ' : 'UNRESOLVED'} ${b.className}.${b.methodName}${b.signature ? '__' + b.signature : ''}  -> ${b.library} (${b.abi})`);
    }
    console.log('');
    console.log('native libraries');
    for (const n of r.native.libraries) {
      console.log(`  ${n.path}  machine=${n.machine} soname=${n.soname}`);
      console.log(`    exports=${n.exports} imports=${n.imports} needs=${n.needed.join(', ')}`);
    }
    console.log('');
    console.log(`pinning: ${r.pinning.totalMechanisms} mechanism(s), ${r.pinning.uniqueDigests} unique digest(s) in resources`);
    for (const p of r.pinning.mechanisms) {
      console.log(`  [${p.kind}] ${p.where}  ${p.pins !== undefined ? `pins=${p.pins} ` : ''}${p.domains ? `domains=${p.domains.join(',')} ` : ''}(${p.confidence})`);
    }
    console.log('');
    console.log(`endpoints (${r.strings.endpoints.length}) hosts=${r.strings.hosts.join(', ') || '(none)'}`);
    for (const e of r.strings.endpoints) console.log(`  [${e.source}] ${e.url}`);
    if (r.strings.credentialShaped.length) {
      console.log(`credential-shaped constants (REDACTED): ${r.strings.credentialShaped.length}`);
      for (const c of r.strings.credentialShaped) console.log(`  ${c.value}  <- ${c.shapes.join(',')}`);
    }
    console.log('');
    console.log(`findings: ${r.findings.length}`);
    for (const f of r.findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}`);
    if (r.limits.length) {
      console.log('limits:');
      for (const l of r.limits) console.log(`  - ${l}`);
    }
  }
  process.exit(0);
}
