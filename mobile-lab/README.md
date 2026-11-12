# mobile-lab — Android static analysis + Frida authoring lane

Self-authored sample APK, a static APK analyser, and a Frida script library that is
**logic-verified without a device**. Zero npm dependencies. No network at run time.

This is the station's answer to the one domain it had tools for but no *practice* in: Frida
was installed and inert. This lane turns it into an authored, tested capability, and it
proves the static half end-to-end by **building a real APK from source** with no Android SDK.

| Path | What it is |
|---|---|
| `lab/app/` | The self-authored sample app (Java). Deliberately contains every artefact the analyser must find. |
| `lab/stubs/` | Compile-time `android.*` / `okhttp3.*` stubs. **Not packaged** into the APK. |
| `lab/native/mobilelab.c` | The native source. **Not compiled here** — no NDK. Read the limits section. |
| `lab/build/build-apk.mjs` | javac → d8 → aapt2 → zipalign → apksigner. Builds a real signed APK. |
| `lab/build/make-so.mjs` | Hand-assembles a real ELF64 AArch64 `.so`. No compiler. |
| `lab/build/zip.mjs` | ~200-line ZIP reader/writer. Replays each entry's compression method verbatim. |
| `tools/analyze.mjs` | **The deliverable.** APK in, structured analysis out. AXML, DEX, ELF, JNI, pinning, strings. |
| `tools/loop.mjs` | One self-judging command. Exit 0 = the loop closed. |
| `tools/oracle-elf.py` | pyelftools cross-check. An **independent** ELF implementation. |
| `tools/frida-selftest.mjs` | Runs the Frida suite; `frida-selftest-lib.mjs` is the callable form. |
| `frida/lib/logic.mjs` | The **pure** half of every hook: all decisions, no Frida globals. |
| `frida/lib/frida-emulator.mjs` | A model of the Frida runtime, so hooks can be executed offline. |
| `frida/hooks/*.js` | Three real hook templates, observation-only. |
| `pinning.md` | The certificate-pinning analysis method, written out. |

## The one command

```powershell
node tools\loop.mjs
```

It builds the APK, cross-checks the hand-built `.so` against pyelftools, runs the analyser,
runs the 40-case Frida suite, cross-checks against **JADX and Apktool**, and runs five
negative controls. Exit `0` means all of that held on this machine, in that run.

| exit | meaning in `tools/loop.mjs` |
|---|---|
| 0 | every required check ran and held; the loop closed |
| 2 | a stray argument was refused |
| 6 | the APK build prerequisite failed; no downstream claim could be judged |
| 8 | no check failed, but at least one required cross-check was skipped |
| 9 | one or more executed checks were refuted |

A skipped decoder is not independent corroboration, and a failed build is not a verdict
about the APK analysis claims.

```
  PASS  build a real signed APK from source (javac + d8 + aapt2 + zipalign + apksigner)  25135 bytes
  PASS  AndroidManifest.xml is binary AXML, not text               magic 0x00080003, 3136 bytes
  PASS  hand-built ELF .so passes its own re-parse                 1888 bytes, 5 exports
  PASS  INDEPENDENT oracle: pyelftools agrees on the .so            VERDICT: AGREES with the hand-built layout
  PASS  manifest: package, sdk, debuggable parsed from binary AXML  package=com.lab.mobilelab min=24 target=34
  PASS  JNI: every Java_ export resolved to a Java class and method 5 boundaries, library name in DEX=true
  PASS  native: .dynsym exports, imports and DT_NEEDED read        exports=5 imports=4 needs=liblog.so,libc.so
  PASS  pinning: all four mechanisms distinguished, not just OkHttp declarative, okhttp-…, custom-trust-manager, native-pin-table
  PASS  strings: endpoints found in BOTH the DEX and native memory api.lab.invalid, attest.lab.invalid, telemetry.lab.invalid
  PASS  Frida script library logic-verified offline (40 cases)     40/40 passed, no device attached
  PASS  cross-check: JADX recovers the same classes the DEX table lists  10/10 class names agree
  PASS  cross-check: Apktool decodes the manifest independently     package, debuggable, components, authorities agree
  PASS  NEGATIVE: ELF self-verifier rejects a corrupted .so        rejected: bad ELF magic
  PASS  NEGATIVE: detector fires on an instrumented target …       instrumented=1 finding(s), clean=0
  ...
LOOP CLOSED
```

Other entry points:

```powershell
node lab\build\build-apk.mjs                 # rebuild the APK only
node tools\analyze.mjs artifacts\mobilelab.apk --json
node tools\analyze.mjs <apk> --expect jni-resolved,pinning-native,has-credential
node tools\frida-selftest.mjs                 # the 40 Frida cases alone
```

## The ceiling, established rather than assumed

Everything below was measured on this box, not inferred. What surprised us is included.

**A real APK build IS possible here, and that is the headline.** `D:\Software\Android\Sdk`
contains **build-tools 35.0.0** (not in the brief — it was found by searching). That gives
`aapt2`, `d8`, `dexdump`, `zipalign`, `apksigner`. Combined with JDK 21's `javac` and
`keytool`, the full chain works. The lab builds a genuinely signed APK with real binary AXML,
a real `resources.arsc`, a real DEX 037, and a real `.so`.

| Question | Answer | Evidence |
|---|---|---|
| Can a real APK be built? | **Yes** | 25,135 bytes, signed v1+v2, decoded by JADX 1.5.6 and Apktool 3.0.3 |
| `adb` / platform-tools? | **Absent** | no `adb.exe` anywhere on `C:` or `D:`; no `platform-tools` in the SDK |
| An AVD / emulator? | **Not attempted, and it would not help** | see below |
| Frida usable against a device? | **No device to attach to** | `frida-ls-devices` **hangs indefinitely** (killed at 300 s, then 25 s) — device enumeration never terminates here |
| Android NDK? | **Absent** | no clang target triple, no sysroot, no Android libc. Hence the hand-built `.so` |
| MobSF? | Source only, no venv | not part of this lane |

### Why the emulator was not installed

The brief says to report size and feasibility before attempting it. Measured from Google's
own repository manifests:

| Package | Download | Notes |
|---|---|---|
| `platform-tools` | ~8.6 MB | would give us `adb` |
| `emulator` | ~338–470 MB | |
| `system-images;android-30;google_apis;x86_64` | ~1,372 MB | ~2.9 GB installed |
| **Total** | **~1.7 GB** | fits comfortably: `D:` has 288 GB free |

**Disk is not the blocker.** Three things are:

1. **No elevation.** This shell is not an Administrator (`IsInRole(Administrator)` →
   `False`), so `Get-WindowsOptionalFeature` and any feature install fail with *"The
   requested operation requires elevation"*.
2. **WSL is disabled** (`wsl --status` → `Wsl/0x80070422`, "service is disabled"), so the
   emulator's WSL2 backend is unavailable and enabling it needs elevation plus a reboot.
3. **Hyper-V is already running** (`HypervisorPresent: True`, `vmcompute` and `vmms`
   both `Running`). The emulator's WHPX backend would need the *Windows Hypervisor
   Platform* optional feature, whose state cannot even be queried without elevation.

So the honest position: *feasible on a sufficiently elevated machine, and roughly 1.7 GB*,
but it requires installing a Windows optional feature and rebooting — an owner decision
under `AGENTS.md` §5 ("Do not silent-install drivers"), not something an agent should do
unilaterally mid-task. **Nothing in this lane needs it.** Every claim below is proved without
a device, which is why none of them is conditional on one.

## What the Frida emulator does and does not prove

This is the part most worth reading carefully, because it is where an offline harness is
most likely to be oversold.

`frida/lib/frida-emulator.mjs` models `Java.use`/`.overload`/`.implementation`,
`Interceptor.attach` with `onEnter`/`onLeave`, `Module.enumerateExports`, `Memory.read*`,
`NativePointer` and `send()`. The hooks in `frida/hooks/` are **executed** against it, and
their trace records are asserted — not eyeballed.

**Proved, with no device:**
- the script parses, runs, and its `send()` payloads are what the tests claim
- it selects the **intended overload** (a three-way `int` / `int,int` / `String,Object[]` case)
- `onEnter` precedes `onLeave`; a missing export is reported, not silently skipped
- JNI name mangling round-trips, including the escape-order case (`a_b;c[d` → `a_1b_2c_3d`)
- `/proc/self/maps` and `TracerPid` classification, with a **negative control** that must fire
- every Frida API referenced is one the model knows — a typo'd or removed API is a *failure*
- `TracerPid` unreadable is `unknown`, never `clean` (the classic false negative)
- credential-shaped constants are flagged **and redacted**; the report cannot leak what it found

**Not proved, and not claimed:**
- that ART accepts these scripts (obfuscated members, hidden-API limits, class loaders)
- that the real `Interceptor` trampoline behaves like the model
- anything about threads, timing, a live TLS stack, or a real `Certificate` object

`frida/lib/logic.mjs` is split out precisely so the decisions are testable without a
runtime; the selftest asserts that file contains no Frida globals at all, so the split
cannot quietly rot.

## The `.so` substitution, stated plainly

`lab/native/mobilelab.c` is **not compiled** — there is no NDK. Instead `make-so.mjs`
emits a real ELF64 AArch64 `ET_DYN` object byte by byte: program headers, a SysV `.hash`,
`.dynstr`, a `.dynsym` with GLOBAL FUNC bindings, `.dynamic` with `DT_SONAME`/`DT_NEEDED`,
and `.rodata`.

- **Real:** ELF structure, symbol table, imports, `DT_NEEDED`, `.rodata` strings, JNI name
  mangling, and the native pin table — all of which the static lane depends on.
- **Not real:** the instruction stream. `.text` holds documented AArch64 stub bodies, not the
  compiled C. **This lab does not disassemble.** `analyze.mjs` emits an explicit
  `DISASSEMBLY: not attempted` finding rather than inventing a decompilation.

The independent oracle earned its place immediately: it caught a `sh_link` bug in `.hash`
that our own re-parse passed, and it caught `.text` being laid out **over the program
header table** — a file that still parsed as sections and still could not be loaded.

## Honest limits

- **No disassembly, no decompilation of native code.** The analyser reads symbol tables,
  imports, strings and the JNI boundary. Pointing it at a real arm64 `.so` with stripped
  symbols will produce little, and that is the correct answer, not a failure.
- **`native` declarations are resolved by symbol, not by `ACC_NATIVE`.** The DEX method
  table carries no access flags — they live in the encoded `class_data`, which this lab does
  not parse. A `native` method whose symbol was stripped is therefore **absent** from the
  report rather than listed as unresolved. `resolved: 5` means "five `Java_` exports, all
  mapped", not "five natives, all confirmed".
- **DEX coverage is the four index tables** (string, type, proto, method) plus `class_def`.
  No bytecode, no control flow, no `try`/`catch` structure, no `RegisterNatives` payloads.
- **`Module.enumerateExports` is modelled, not implemented.** On a real device a
  `RegisterNatives` app has no `Java_` exports at all; the hook reports that honestly, but
  the dynamic-binding path is untested.
- **The maps detector covers documented signals only** — `TracerPid`, agent module names,
  unusual exec mappings, the app's own public checks. Not timing side channels, not custom
  syscall probes, not a detector taught about this specific agent.
- **Credential shapes are heuristics.** A field called `salt` holding a UUID will flag; a
  secret called `x9` will not. `sk-l…` matching is a shape test, not a validity test.
- **One ABI, one architecture.** The sample is `arm64-v8a` only, and the ELF is AArch64.
  There is no x86_64 or armeabi-v7a variant, and no split-ABI analysis.
- **The framework stub is a stub.** `aapt2 link` needs `android.jar`, which is not
  installed, so the lab declares the ~20 framework attributes the manifest uses and links
  them into a tiny `framework.apk`. The IDs are the **real** Android IDs — verified by
  Apktool decoding the result against its own framework table, not ours.
- **`zipalign -p` and `apksigner` are the real Google tools, not reimplementations.** The
  ZIP container around them is ours, and it replays each entry's compression method verbatim
  so `resources.arsc` and `lib/**.so` stay STORED, which is the invariant that matters.

## Stop lines

- **Authorized work only.** Instrumenting a sample you own, or an asset you are authorized
  in writing to test. Never a third-party production app.
- **Anti-frida / anti-debug DETECTION is in scope; BYPASSING is not.** This lab ships a
  *detector* — it enumerates the signals an app could use to notice us and reports which
  fire. There is no Frida hiding, no root concealment, no unhooking, no anti-dump trick, and
  nothing that makes an app's checks fail. `02-anti-instrumentation-detector.js` exists to
  answer "if I attach, will this app know?" — a question about *our* instrumentation.
- **No pinning bypass.** `01-okhttp-certificate-pinner.js` observes which digest the app
  checked and falls through to the original via `.call(this, …)`. It does not modify the
  pin set, does not return a fabricated result, and does not install a user CA.
- **No repackaging-and-resigning flow aimed at someone else's app.** The APK built here is
  signed with a **throwaway debug key generated at build time into gitignored `work/keys/`**.
  It exists so our own fixture is a well-formed APK.
- **No third-party binaries in git.** The APK is a build product in gitignored `artifacts/`;
  `pyelftools` lives in a gitignored `.venv` and is an **oracle, not a dependency** — the
  analyser never imports it.
- **No secrets.** Every endpoint uses the reserved `.invalid` TLD (RFC 2606) and cannot
  resolve. The one credential-shaped constant is a published placeholder, and the analyser
  redacts it in its own output.
- **Loopback only, no network at run time.** Nothing here reaches the internet.

## Reproduce from scratch

```powershell
cd mobile-lab
node tools\loop.mjs

# the pyelftools oracle is optional but the loop asks for it:
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install pyelftools==0.33
```

Verified present at build time: Node **v24.19.0**, Python **3.14.7**, JDK **21.0.12**,
Android build-tools **35.0.0**, JADX **1.5.6**, Apktool **3.0.3**, `pyelftools` **0.33**.
Frida **17.17.0** is installed in the station's objection venv but is **not** exercised by
this lane — there is no device, and `frida-ls-devices` hangs here rather than returning an
empty device list.

`.venv/`, `out/`, `work/`, `artifacts/` and `lab/build/framework-res/` are gitignored.
