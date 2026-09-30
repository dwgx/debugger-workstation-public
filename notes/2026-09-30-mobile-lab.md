# mobile-lab (D5) — Android static + Frida authoring lane

Built 2026-09-30. Entry: `mobile-lab/`, wrapper `scripts\mobile-lab.ps1 loop`.

## The finding that changed the plan

The brief said "no Android SDK". That is **out of date**: `D:\Software\Android\Sdk`
contains **build-tools 35.0.0** (aapt2, d8, dexdump, zipalign, apksigner). Combined with
JDK 21 `javac`/`keytool`, a **real signed APK is buildable on this box** — no Gradle, no
platform SDK, no network. The lab builds one: binary AXML manifest, real `resources.arsc`,
DEX 037, and a real `.so`.

`aapt2 link` needs `android.jar` for `android:*` attributes, which is still absent. Solved by
emitting a small framework stub (`lab/build/build-apk.mjs`) that declares the ~20 attributes
the manifest uses **at their real Android resource IDs**. Verified: Apktool decodes the
result against *its own* framework table and agrees, which is the evidence the IDs are real.

## Ceiling (measured, not assumed)

- **adb / platform-tools:** absent everywhere.
- **Emulator:** ~1.7 GB download (emulator 338–470 MB + android-30 x86_64 image 1.37 GB).
  Disk is NOT the blocker (`D:` 288 GB free). Blocked by (1) shell is not Administrator, so
  optional-feature install/query fails; (2) WSL disabled, `Wsl/0x80070422`; (3) Hyper-V is
  already running (`vmcompute`/`vmms` Running) so the emulator needs the Windows Hypervisor
  Platform feature. Not attempted — that is an owner decision under AGENTS.md §5.
- **Frida:** 17.17.0 installed, but `frida-ls-devices` **hangs indefinitely** on this box
  (killed at 300 s, again at 25 s) rather than returning an empty list. Device enumeration
  never terminates.
- **NDK:** absent. Hence the hand-assembled ELF in `lab/build/make-so.mjs`.

## What the independent oracles caught

Both caught real bugs that the lab's own verifier passed:

- **pyelftools**: `.hash` had `sh_link=0`; and `.text` was laid out at offset 64, **over the
  program-header table** — a file that still parsed as sections and still could not be loaded.
- **JADX/Apktool**: confirmed manifest parsing against implementations that share no code.

Also worth remembering, because each was a silent-wrong-answer bug: `st_name` is a **byte
offset** into `.dynstr`, not an array index; `res/xml/*.xml` in an APK is **compiled AXML**,
so grepping it for `<pin digest="` silently reports zero pins; and `windowsVerbatimArguments`
must apply to the `cmd.exe` path **only**, or `keytool -dname` splits into tokens.

## Proved

`node tools/loop.mjs` → 24/24 PASS, exit 0. Real APK built; pyelftools agrees; analyser
resolves 5/5 JNI boundaries and all 4 pinning mechanisms; 40/40 Frida cases pass with no
device; 5 negative controls fail as designed.

**Not proved:** attaching, live TLS interception, ART accepting the scripts, and
disassembly of the sample `.so` (no NDK — `analyze.mjs` reports this rather than faking it).
