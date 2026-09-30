#!/usr/bin/env node
/*
 * indicators.mjs — static detection of packing, emulator/root checks, and Kotlin name
 * metadata. Device-free, network-free, zero dependencies.
 *
 * THE DISTINCTION THIS FILE EXISTS TO KEEP SHARP
 * ------------------------------------------------
 * A signal LIST is static analysis. Only FIRING the check needs a device.
 *
 * So what this reports is "the binary contains code shaped like an emulator check",
 * never "the emulator check fired" and never "the app evaded anything". That
 * difference is the whole point: reading a list of strings out of a DEX is static
 * analysis, and claiming the runtime behaviour from it would be the exact move this
 * station refuses to make everywhere else.
 *
 * Each hit CITES the string and where it was found. A detector that cannot show its
 * evidence is a vibe, not a detector — so nothing is reported without a citation.
 *
 * WHAT THIS DELIBERATELY DOES NOT SHIP
 * ------------------------------------
 * No bypass. Not a hook, not a patch, not a way to defeat any of these checks. The
 * output is an inventory of what an APK carries, for analysis of APKs we own. The
 * research dossier's survey found high-star "skills" shipping one-click unpacking and
 * anti-detection bypass for third-party apps; that is out of scope here and none of it
 * is implemented.
 */

/* ================================================================== *
 * Packers and shells
 * ================================================================== */

const PACKER_SIGS = [
  { id: 'qihoo-360',      vendor: 'Qihoo 360',        sigs: ['com/qihoo/util/StubApplication', 'com.stub.StubApp'] },
  { id: 'bangcle',        vendor: 'Bangcle / SecNeo', sigs: ['com/secneo/apkwrapper', 'com/SecShell.SecApp'] },
  { id: 'ijiami',         vendor: 'Ijiami',           sigs: ['com/shell/SuperApplication', 'ijiami'] },
  { id: 'tencent-legu',   vendor: 'Tencent Legu',     sigs: ['com/tencent/stub/StubApplication', 'com/tencent/StubApplication'] },
  { id: 'baidu',          vendor: 'Baidu',            sigs: ['com/baidu/protect/StubApplication'] },
  { id: 'ali',            vendor: 'Alibaba',          sigs: ['com/ali/mobisecenhance/StubApplication'] },
  { id: 'apkprotect',     vendor: 'APKProtect',       sigs: ['com/apkprotect/WalkApplication'] },
  { id: 'kiwi',           vendor: 'Kiwi / SecShell',  sigs: ['com/kiwisign/ShellApplication'] },
  { id: 'generic-assets', vendor: 'generic',          sigs: [] },
];

// Generic packing tells. Each is a claim about SHAPE, never proof, and the caller is
// expected to report them as inferences rather than observations.
const PACKER_SHAPE = [
  { id: 'assets-dynamic',  why: 'an assets/ directory with no media in it is a decrypted-payload drop point' },
  { id: 'assets-empty',    why: 'assets/ contains no drawable or raw resource, which an unpacked app would' },
  { id: 'native-lib-only', why: 'a single native library doing all the work is a loader shape' },
  { id: 'dex-name-mismatch', why: 'classes.dex is present alongside another .dex with a loader-like name' },
];

/* ================================================================== *
 * Emulator and root checks
 * ================================================================== */

/* STRONG emulator signals are the DISTINCTIVE ones. An emulator check leaves a trace
   only a check would look for. */
const EMULATOR_SIGS_STRONG = [
  'goldfish', 'ranchu', '/dev/socket/qemud', '/dev/qemu_pipe', 'qemu.hw.mainkeys',
  'ro.kernel.qemu', 'vbox86', 'genymotion', 'ttVM_Hdragon', 'google_sdk',
  'Andy', 'Nox', 'BLUESTACKS', 'vbox', 'ttVM', 'goldfish_x86',
];

/* WEAK emulator signals are what nearly EVERY app reads. `android.os.Build`,
   `ro.build.fingerprint` and `FINGERPRINT` appear in ordinary crash reporting. And
   `sdk` is three characters: on this lab's own clean APK it matched the string "sdk="
   and produced a confident "emulator check present" out of nothing.

   These are kept, because a build-fingerprint CHECK is real, but they are counted
   separately and never set `emulator_checks_present` on their own. */
const EMULATOR_SIGS_WEAK = [
  'android.os.Build', 'ro.build.fingerprint', 'ro.hardware', 'ro.product.model',
  'FINGERPRINT', 'sdk', 'generic', 'ro.kernel.qemu.arm',
];

/* STRONG root signals: absolute paths and package names. These are load-bearing. */
const ROOT_SIGS_STRONG = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/data/local/su', '/data/local/xbin/su',
  '/system/app/Superuser.apk', '/system/sd/xbin/su', '/system/bin/.ext/.su',
  'eu.chainfire.supersu', 'com.topjohnwu.magisk', 'com.noshufou.android.su',
  'com.thirdparty.superuser', 'test-keys',
];

/* WEAK root signals: bare words that occur in ordinary text. Measured on this lab's own
   clean APK, the substring "su" fired repeatedly on innocent strings -- including XML
   element names. Reporting that as "root check present" is crying wolf, and a detector
   that cries wolf gets ignored, which is worse than having none. */
const ROOT_SIGS_WEAK = ['su', 'Superuser', 'SuperSU', 'magisk', 'Magisk', 'busybox', 'ro.debuggable', 'ro.secure'];

/* ================================================================== *
 * Detection
 * ================================================================== */

/** Case-sensitive substring scan over the DEX string table, citing the index. */
function scanStrings(dex, sigs) {
  const hits = [];
  const seen = new Set();
  for (let i = 0; i < dex.strings.length; i++) {
    const s = dex.strings[i];
    if (!s || s.length < 3) continue;
    for (const sig of sigs) {
      if (!s.includes(sig)) continue;
      const k = `${sig}|${i}`;
      if (seen.has(k)) continue;
      seen.add(k);
      hits.push({ signal: sig, dex_string_index: i, value: s.length > 120 ? `${s.slice(0, 120)}…` : s });
    }
  }
  return hits;
}

/**
 * Packing. Two independent halves, because either alone is weak:
 *   vendor signature  -- a named packer's own classes are present (OBSERVED)
 *   shape heuristic   -- the layout a packer produces (INFERRED, never proof)
 */
export function detectPacking(dex, entries = []) {
  const observed = [];
  const inferred = [];

  for (const p of PACKER_SIGS) {
    const hits = [];
    for (const sig of p.sigs) {
      for (let i = 0; i < dex.strings.length; i++) {
        if (dex.strings[i] && dex.strings[i].includes(sig)) hits.push({ signature: sig, dex_string_index: i });
      }
    }
    if (hits.length) observed.push({ packer: p.id, vendor: p.vendor, hits });
  }

  const assetEntries = entries.filter((e) => /^assets\//.test(e));
  if (assetEntries.length && !assetEntries.some((e) => /\.(png|jpg|jpeg|webp|mp3|mp4|json|xml|bin|so)$/i.test(e))) {
    inferred.push({ shape: 'assets-dynamic', why: PACKER_SHAPE[0].why, entries: assetEntries.slice(0, 6) });
  }
  const dexEntries = entries.filter((e) => /\.dex$/i.test(e));
  if (dexEntries.length > 1) {
    inferred.push({ shape: 'dex-name-mismatch', why: PACKER_SHAPE[3].why, entries: dexEntries });
  }

  return {
    verdict: observed.length ? 'packed' : inferred.length ? 'suspicious' : 'no_indicator',
    confidence: observed.length ? 'OBSERVED' : inferred.length ? 'INFERRED' : 'OBSERVED',
    observed,
    inferred,
    does_not_prove: [
      'that the packer is active, or that its payload decrypts',
      'that a packer was used because a heuristic shape matched -- shape is a hint, not a verdict',
      'anything at all about runtime, since nothing here executes the app'
    ],
  };
}

/**
 * Emulator and root checks. Reports the PRESENCE of check-shaped strings.
 *
 * The word matters: `root_checks_present` is a statement about the binary. It is not a
 * statement that a check fired, and not a statement that any check can be defeated --
 * this file ships no way to defeat one.
 */
export function detectEnvironmentChecks(dex) {
  const emuStrong = scanStrings(dex, EMULATOR_SIGS_STRONG);
  const emuWeak = scanStrings(dex, EMULATOR_SIGS_WEAK);
  const rootStrong = scanStrings(dex, ROOT_SIGS_STRONG);
  const rootWeak = scanStrings(dex, ROOT_SIGS_WEAK);

  return {
    /* Counted from the STRONG buckets only. The first version counted weak substrings,
       so this lab's own clean APK reported root_checks_present: true on the strength of
       "su" appearing in XML. */
    emulator_checks_present: emuStrong.length > 0,
    root_checks_present: rootStrong.length > 0,

    emulator_hits: emuStrong,
    root_hits: rootStrong,
    emulator_hits_weak: emuWeak,
    root_hits_weak: rootWeak,

    weak_note: 'weak signals are ordinary text: the substring "su" fires on XML element names, and "sdk" fired on the literal string "sdk=" in this lab own clean APK. They are reported so a reader can judge, and they never set the *_present flags on their own. A build-fingerprint or /system/xbin/su check is real; a bare "su" is a rumour.',
    does_not_prove: [
      'that any check FIRES, or what it would return -- that needs a device, and nothing here runs the app',
      'that the developer intended evasion rather than diagnostics or QA',
      'that any check can be bypassed -- this file ships no bypass, by design'
    ],
  };
}

/**
 * Kotlin @DebugMetadata recovery.
 *
 * The highest-yield transform for an obfuscated Android app, because R8 cannot strip
 * it: kotlin.Metadata carries `k` (the Kotlin class name) and `d1` (JVM signatures)
 * alongside `d2`. This recovers the RAW MATERIAL -- the metadata annotation payloads
 * present in the string table -- rather than claiming a full rename, because a full
 * rename needs the encoded_array parser and a type resolver, and a partial claim that
 * overstates itself is worse than no claim.
 *
 * What it DOES give is the census: how many classes carry metadata, and whether the
 * Kotlin names are present at all. That answers the question an analyst actually asks
 * first -- is there anything here to recover?
 */
export function recoverKotlinMetadata(dex) {
  const META = 'Lkotlin/Metadata;';
  const carriers = [];
  for (let i = 0; i < dex.strings.length; i++) {
    const s = dex.strings[i];
    if (s && s.includes(META)) carriers.push({ dex_string_index: i, value: s.length > 160 ? `${s.slice(0, 160)}…` : s });
  }

  // d1 entries look like JVM descriptors; the encoded_array payload is bracketed.
  const encodedArrays = [];
  for (let i = 0; i < dex.strings.length; i++) {
    const s = dex.strings[i];
    if (!s || s.length < 8) continue;
    if (/^\{.*\}$/s.test(s) && /Lkotlin\/Metadata|@Lkotlin\/Metadata/.test(s)) {
      encodedArrays.push({ dex_string_index: i, value: s.length > 200 ? `${s.slice(0, 200)}…` : s });
    }
  }

  const present = carriers.length > 0;
  return {
    kotlin_metadata_present: present,
    metadata_carriers: carriers.length,
    encoded_arrays: encodedArrays.length,
    samples: encodedArrays.slice(0, 3),
    recovery_possible: present && encodedArrays.length > 0,
    does_not_prove: [
      'a renamed class -- this recovers the raw metadata payloads, NOT decoded names',
      'that the metadata is complete: R8 can drop d1/d2 for private members',
      'anything about a particular obfuscated symbol without decoding the array first'
    ],
    next_step: present && encodedArrays.length
      ? 'decode the encoded_array (a protobuf message with a 1/3/5/7/9 prefix-length scheme) and map k to the class_def; that is the actual rename'
      : 'no Kotlin metadata in this DEX; either the app is not Kotlin, or the metadata was stripped',
  };
}

/**
 * Run all three and return one object, so the caller has a single surface.
 *
 * Takes an ALREADY-PARSED dex. It used to parse the buffer itself via a static import
 * of parseDex from analyze.mjs, and that is a circular dependency: analyze.mjs
 * dynamically imports this module, so the two waited on each other's module evaluation
 * and the process exited 13 with "unsettled top-level await". The caller already has the
 * parsed table, so passing it in removes the cycle entirely.
 */
export function detectAll(dex, entries = []) {
  return {
    packing: detectPacking(dex, entries),
    environment_checks: detectEnvironmentChecks(dex),
    kotlin: recoverKotlinMetadata(dex),
    _reading_guide: 'OBSERVED means the bytes are present. INFERRED means a shape matched. Neither means anything about runtime.',
  };
}
