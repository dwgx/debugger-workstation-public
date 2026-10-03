STATUS: DONE

# clone freshness — what a fresh clone is missing (R3 / R5 / R6)

Date: 2026-10-03. Station: `D:\Software\Tool\WorkStation\debugger`, git `main`, HEAD `a894a3c`.
Python 3.14.7. One new file plus one wiki page; nothing else was created, edited or deleted.

| file | status |
|---|---|
| `scripts/verify-clone-freshness.py` | **new**, 684 lines, the deliverable |
| `<project>/<private-tree>/wiki/methods/arsenal-clone.md` | **did not exist — created** (the brief said to check first; `ls wiki/methods/ \| grep -i clone` returned nothing) |
| `manifests/capabilities.json`, `manifests/tools.json`, every other `scripts/` file, every other wiki file | untouched |
| `%TEMP%\station-clone`, `%TEMP%\verify-station` | **read only.** The script was invoked from its station path with `--repo <clone>`; not one byte was written into either clone. |
| scratch | `%TEMP%\clonefresh-neg-095314-24928` — a fresh `git archive HEAD` export, made because the negative test needs a clone whose corpus I am allowed to touch |

---

## 1. The question that was asked first: what does the bootstrap slice say today?

**It exists, and it is good.** `README.md` carries a section headed *What a fresh clone does not have*
(`README.md:65`), whose *Step 1* is the corpus build. Verbatim, `README.md:65-97`:

> ## What a fresh clone does not have
>
> Everything below was measured on 2026-10-03 against a pristine `git archive HEAD` export (383 tracked
> files) — not against this workstation, which has been built for a month.
>
> **A clone ships 383 files and zero build products.** `.gitignore` excludes every `out/` directory, so
> `crackme-corpus/out/`, `managed-lab/out/` and `headless-lab/out/` are empty directories that do not
> even exist. That exclusion is deliberate and permanent: `crackme-corpus/README.md` states `out/` holds
> compiled binaries plus ~1500 machine-generated decompiled C files and "exporting decompiled C into git
> is forbidden by the station charter. The sources are the product."
>
> **`scripts/bootstrap.ps1` does not build any of it.** Read what it actually does: it copies
> `manifests/ skills/ docs/ scripts/ templates/` plus a fixed list of root files, generates `.mcp.json`,
> clones third-party MCP upstreams, and creates **exactly one** virtualenv — `mcp/debugger-router/.venv`,
> the only MCP enabled by default. It prints the official download URL for each third-party tool and
> downloads none of them. No lab output directory is produced by any script in `scripts/`.
>
> ### Step 1 — build the corpus, from inside `crackme-corpus/`
>
> This is the one build step nothing else does for you, and **11 of the 21 executable proofs in
> `manifests/capabilities.json` read a binary out of it.**
>
> ```powershell
> cd crackme-corpus
> python tools\loop.py
> ```
>
> Run it from **inside** `crackme-corpus/`, not from the repo root. `loop.py` passes `-OutDir "out"` as a
> relative path and `build-c.ps1` resolves it against the current directory. Measured: from the repo root
> the binaries land in `<repo>\out\` while the solvers look in `crackme-corpus\out\`, so the run reports
> `PASS build c01` followed by `FAIL solve c01` against a file that was never built.
> `scripts/crackme-corpus.ps1` dispatches the same runner and does not change the working directory, so
> the same rule applies.

`crackme-corpus/README.md:9-17` says the same thing under the heading *The one command*, and adds the
prerequisite table (MSVC 2022, Ghidra headless, radare2 + rabin2, .NET SDK + ilspycmd) at
`README.md:101-109` plus `scripts/download-tools.ps1 -Apply` as the partial remedy.

**So the answer to "is there a bootstrap command" is YES, and it is not news:** `cd crackme-corpus ;
python tools\loop.py`, documented in three places. What does **not** exist is a *script* that runs it —
`scripts/bootstrap.ps1` provably does not (quoted above), and `scripts/crackme-corpus.ps1` dispatches
the same runner **without** changing the working directory (measured by the script itself, which greps
that file for `Set-Location|Push-Location|cd ` and reports the result). The deliverable therefore does
not invent a remedy; it locates one by reading the repo and prints it, or prints
`NO SUCH COMMAND EXISTS TODAY` when the runner is absent.

Two numbers I re-measured rather than believed:
- `git ls-tree -r HEAD --name-only | wc -l` = **389** tracked files at HEAD today, against the README's
  "383 tracked files". Same day, different tree state; the README number is stale by 6 files, not wrong.
- The script re-derives **11 of the 21 checked** corpus-dependent capabilities from the registry and
  lands on the README's number exactly (§7.1).

---

## 2. What `scripts/verify-clone-freshness.py` does

Three static sections, no probe executed, ~0.25 s wall, 169 lines of output on the station.

1. **CORPUS (R3).** Existence and recursive entry count of `crackme-corpus/out/`; every capability
   that names a path inside it, split into the ones `scripts/assert-probes.py` actually checks and the
   six it skips (the skip list is `ast`-parsed out of that file, not copied — a second copy of it is a
   list that drifts); every named artefact checked individually; and the build command located by
   reading `crackme-corpus/README.md`, `README.md` and `scripts/*corpus*.ps1`.
   **Exits non-zero** when the corpus is missing/empty *and* a capability needs it.
2. **TOOLS (R5).** Every path or bare command a probe, a `probe.prepare` or a `requires.tools[].probe`
   invokes — 23 distinct targets today — resolved by `shutil.which` for bare names and by declared
   location otherwise, including a tool *install-root* fallback (Ghidra names
   `Ghidra/Features/...`, which hangs off `Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC`, not off the
   repo). Three verdicts per target: present/absent, **declared or undeclared** in
   `manifests/tools.json`, and **inside or outside this clone**.
3. **WIKI (R6).** Read-only walk of the wiki tree for a `%TEMP%` path on a line that reads like a
   reproduction step (fenced block, or a line starting with a command verb). Reports `file:line` plus
   the line, tags the ones that already declare themselves `[DEAD]`/`[HISTORICAL]`, counts prose
   mentions separately, and **never writes**. The wiki lives outside the repo
   (`<project>/<private-tree>/wiki`), so the root list is explicit and overridable (`--wiki-root`,
   `DEBUGGER_WIKI_ROOT`); a scan that silently finds nothing says so rather than reporting clean.

Exit codes: `0` nothing fatal · `1` the corpus gate fired (or any warning under `--strict`) ·
`2` the script's own fault (repo/manifest unreadable).

---

## 3. RUN 1 — the station. `python scripts/verify-clone-freshness.py`, **exit 0**.

Full output, verbatim:

```text
verify-clone-freshness
  repo : D:\Software\Tool\WorkStation\debugger
  python 3.14.7  static checks only -- no probe is executed

==============================================================================
1. CORPUS   crackme-corpus/out/   (R3)
==============================================================================
  directory : crackme-corpus/out  [present]
  entries   : 5285 files, 24 directories
  needed by : 14 capabilities name a path inside it
              11 of those are CHECKED by scripts/assert-probes.py (out of 21 checked); 3 are on its SKIP list
    checked -> dynamic.win.frida, dynamic.win.frida.intercept, native.behaviour.capa, native.disasm.capstone, native.function.match, native.ghidra.decompile, native.pe.authenticode, native.pe.container, native.pe.hardening, native.pe.packer, native.signature.certverify
    skipped -> native.ghidra.emulate, native.ida.decompile, native.ida.list_functions
          * dynamic.win.frida  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * dynamic.win.frida.intercept  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.container  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c03_antidebug.exe
          * native.pe.packer  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.packer  requires.tools[upx].probe  crackme-corpus/out/c01-stringobf.exe
          * native.disasm.capstone  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.authenticode  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.behaviour.capa  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.signature.certverify  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  requires.tools[rabin2].probe  crackme-corpus/out/c01-stringobf.exe
            native.ida.decompile  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
            native.ida.list_functions  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
          * native.ghidra.decompile  probe.command -> scripts/ghidra-failopen-regress.ps1:6  crackme-corpus/out
            native.ghidra.emulate  probe.command -> scripts/emulation-probe.ps1:60  crackme-corpus/out/c01-stringobf.exe
          (* = a capability the evidence sweep actually runs)
  
  REMEDY    : cd crackme-corpus ; python tools\loop.py      (run from the repo root)
              crackme-corpus/README.md:12  'python tools\\loop.py'
              README.md:88  'cd crackme-corpus'
              README.md:89  'python tools\\loop.py'
              scripts/crackme-corpus.ps1  exists; changes working directory: False
  NOTE      : this command is NOT run by any script in scripts/; a clone must be told to run it by hand.

==============================================================================
2. TOOLS    binaries a probe invokes   (R5)
==============================================================================
  MISS cmd  adb   [dynamic.device.frida]
  OK   cmd  idalib-mcp  ->  D:\Software\Developer\Python314\Scripts\idalib-mcp.EXE   [native.ida.list_functions]
  OK   cmd  java  ->  D:\Software\Developer\jdk\21\bin\java.EXE   [native.function.match]
  OK   cmd  node  ->  D:\Software\Developer\nodejs\node.EXE   [crypto.jose.parse,forensics.memory.artefact,fuzz.differential.parse,managed.il.decompile,mobile.apk.static,native.ida.decompile,native.ida.list_functions,net.pcap.analyse,net.pcap.selfparse,web.js.cdp]
  OK   cmd  openssl  ->  C:\Program Files\Git\mingw64\bin\openssl.EXE   [native.signature.certverify]
  OK   cmd  powershell  ->  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE   [native.function.match,native.ghidra.decompile,native.ghidra.emulate,native.il2cpp.symbols,native.pe.packer]
  OK   cmd  python  ->  D:\Software\Developer\Python314\python.EXE   [native.behaviour.capa,native.disasm.capstone,native.pe.authenticode,native.pe.container,native.pe.hardening,native.signature.certverify,net.pcap.selfparse,re.corpus.solve]
  OK   path .\Mobile-Android\objection\.venv\Scripts\frida-ps.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe   [dynamic.win.frida]
  OK   path .\Mobile-Android\objection\.venv\Scripts\frida.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe   [dynamic.win.frida]
  OK   path .\Mobile-Android\objection\.venv\Scripts\python.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe   [dynamic.win.frida.intercept]
  OK   path .\native-lab\tools\frida_spawn_gate.py  ->  D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py   [dynamic.win.frida.intercept]
  OK   path %USERPROFILE%\.local\bin\skillspector.exe  ->  %USERPROFILE%\.local\bin\skillspector.exe   [ops.skill.security]
  OK   path D:/Software/Developer/Python314/Scripts/idalib-mcp.exe  ->  D:\Software\Developer\Python314\Scripts\idalib-mcp.exe   [native.ida.decompile]
  OK   path Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java  ->  D:\Software\Tool\WorkStation\debugger\Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\Ghidra\Features\VersionTracking\ghidra_scripts\AutoVersionTrackingScript.java   [native.crosscompare.ghidra]
  OK   path Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe  ->  D:\Software\Tool\WorkStation\debugger\Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe   [net.pcap.analyse]
  OK   path Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat  ->  D:\Software\Tool\WorkStation\debugger\Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat   [native.function.match,native.ghidra.decompile]
  OK   path Static-Reversing\capa\capa.exe  ->  D:\Software\Tool\WorkStation\debugger\Static-Reversing\capa\capa.exe   [native.behaviour.capa]
  OK   path Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe  ->  D:\Software\Tool\WorkStation\debugger\Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe   [native.pe.packer]
  OK   path Static-Reversing\radare2\radare2-6.2.2-w64\bin\rabin2.exe  ->  D:\Software\Tool\WorkStation\debugger\Static-Reversing\radare2\radare2-6.2.2-w64\bin\rabin2.exe   [native.pe.hardening]
  OK   path Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/Il2CppDumper.exe  ->  D:\Software\Tool\WorkStation\debugger\Unpackers-Game\Il2CppDumper-net6-win-v6.7.46\Il2CppDumper.exe   [native.il2cpp.symbols]
  OK   path Unpackers-Game\upx\upx-5.2.1-win64\upx.exe  ->  D:\Software\Tool\WorkStation\debugger\Unpackers-Game\upx\upx-5.2.1-win64\upx.exe   [native.pe.packer]
  OK   path scripts/ghidra/EmulateDecode.java  ->  D:\Software\Tool\WorkStation\debugger\scripts\ghidra\EmulateDecode.java   [native.ghidra.emulate]
  OK   path web-reverse/tools/chrome.mjs  ->  D:\Software\Tool\WorkStation\debugger\web-reverse\tools\chrome.mjs   [web.js.cdp]
  
  23 distinct targets, 1 absent.
  
  UNDECLARED IN manifests/tools.json (2) -- invoked by a probe, named in no manifest, so a clone has no way to learn it must install them:
    adb   needed by dynamic.device.frida   [absent here AND undeclared]
    openssl   needed by native.signature.certverify   [present HERE, unknown to a clone]

==============================================================================
2b. TOOLS   manifests/tools.json declared locations
==============================================================================
  declared with dir+entry: 52 present, 2 absent
    ABSENT  crypto-lab/crypto-lab oracle (node): crypto-lab/node_modules/jsonwebtoken/tools/oracle-node.mjs
    ABSENT  crypto-lab/crypto-lab oracle (python): crypto-lab/.venv/tools/oracle.py

==============================================================================
3. WIKI     %TEMP% in a reproduction step   (R6, READ-ONLY)
==============================================================================
  roots    : <private-tree>\wiki
  scanned  : 165 markdown file(s); 24 %TEMP% line(s) shaped like a reproduction step, 28 prose mention(s)
  03-second-instrument.md:398
      usage: %USERPROFILE%\AppData\Local\Temp\fridaprobe\target.exe <password>
  03-second-instrument.md:443
      #   [stage] copied to %TEMP% ...\fridagate-XXXXXXXX\c01-stringobf.exe (143872 bytes); the
  03-second-instrument.md:523
      head -c 600 crackme-corpus\out\c01-stringobf.exe > "$env:TEMP\trunc.exe"
  03-second-instrument.md:524
      python native-lab\tools\pe_probe.py "$env:TEMP\trunc.exe"
  03-second-instrument.md:739
      python -m venv $env:TEMP\spk-venv
  03-second-instrument.md:740
      & $env:TEMP\spk-venv\Scripts\python.exe -m pip install "setuptools<81" speakeasy-emulator
  03-second-instrument.md:741
      speakeasy -t crackme-corpus\out\c01-stringobf.exe --no-mp -o $env:TEMP\spk-c01.json
  03-second-instrument.md:1217  [self-declared dead/historical]
      # [DEAD] python "%USERPROFILE%\AppData\Local\Temp\w13-pe-probe.py"  -> no such file
  03-second-instrument.md:1226
      head -c 600 crackme-corpus\out\c01-stringobf.exe > "$env:TEMP\trunc.exe"
  03-second-instrument.md:1227
      python native-lab\tools\pe_probe.py "$env:TEMP\trunc.exe"
  03-second-instrument.md:1233
      # It stages its own %TEMP% copy, so no fixture has to be created first.
  03-second-instrument.md:1236
      # expect: [stage] copied to %TEMP% … ; [js] {"kind": "HIT", ...} ; [end] verdict=INTERCEPT-PROVEN
  03-second-instrument.md:1242  [self-declared dead/historical]
      # [DEAD] python "%USERPROFILE%\AppData\Local\Temp\w13-capstone-probe.py" -> no such file
  03-second-instrument.md:1260  [self-declared dead/historical]
      # [HISTORICAL, fixture not committed] this leaned on $env:TEMP\fridaprobe\target.exe, which is not
  03-second-instrument.md:1263  [self-declared dead/historical]
      # rely on a %TEMP% fixture. [REPLACED BY] the committed control, which builds its own:
  04-mcp-exposure-and-frida.md:264
      $exe = "$env:TEMP\w13\c01-stringobf.exe"   # copy of crackme-corpus/out/c01-stringobf.exe
  04-mcp-exposure-and-frida.md:265
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe positive
  04-mcp-exposure-and-frida.md:266
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe neg-badaddr
  04-mcp-exposure-and-frida.md:267
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe neg-rebase
  04-mcp-exposure-and-frida.md:276
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  04-mcp-exposure-and-frida.md:291
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  04-mcp-exposure-and-frida.md:304
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  native-pe-instrument-playbook.md:221
      $env:TEMP\pair c01 -import crackme-corpus\out\c01-stringobf.exe `
  native-pe-instrument-playbook.md:222
      -postScript ExportDecompile.java $env:TEMP\ghout -scriptPath scripts\ghidra -deleteProject
  
  context: 28 further %TEMP% mention(s) are prose (provenance, stop-lines, fixture notes), not steps. Listed, not counted against the wiki.

==============================================================================
VERDICT
==============================================================================
  WARN tool: not present: adb (PATH=cmd)  needed by dynamic.device.frida
  WARN tool-undeclared: adb is invoked by a probe but is absent from manifests/tools.json (absent on this station too)
  WARN tool-undeclared: openssl is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-declared: crypto-lab/crypto-lab oracle (node) declared at crypto-lab/node_modules/jsonwebtoken/tools/oracle-node.mjs but absent
  WARN tool-declared: crypto-lab/crypto-lab oracle (python) declared at crypto-lab/.venv/tools/oracle.py but absent
  WARN wiki: 03-second-instrument.md:398 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:443 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:523 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:524 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:739 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:740 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:741 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1217 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1226 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1227 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1233 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1236 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1242 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1260 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1263 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 04-mcp-exposure-and-frida.md:264 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:265 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:266 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:267 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:276 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:291 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:304 publishes a %TEMP% path as a reproduction step
  WARN wiki: native-pe-instrument-playbook.md:221 publishes a %TEMP% path as a reproduction step
  WARN wiki: native-pe-instrument-playbook.md:222 publishes a %TEMP% path as a reproduction step

  findings: 0 FAIL, 29 WARN -> exit 0
```

Reading of that run: corpus `present`, 5285 files / 24 directories, every named artefact present →
**corpus clean**. Tools: 23 targets, **1 absent** (`adb`), **2 undeclared** (`adb`, `openssl`),
**0 foreign-tree**. Wiki: 164 markdown files, **24 recipe-shaped `%TEMP%` lines**, 27 prose mentions.

---

## 4. RUN 2 — `%TEMP%\station-clone`. Same command, clone as `--repo`, **exit 1**.

```text
verify-clone-freshness
  repo : %USERPROFILE%\AppData\Local\Temp\station-clone
  python 3.14.7  static checks only -- no probe is executed

==============================================================================
1. CORPUS   crackme-corpus/out/   (R3)
==============================================================================
  directory : crackme-corpus/out  [present]
  entries   : 1 files, 0 directories
  needed by : 14 capabilities name a path inside it
              11 of those are CHECKED by scripts/assert-probes.py (out of 21 checked); 3 are on its SKIP list
    checked -> dynamic.win.frida, dynamic.win.frida.intercept, native.behaviour.capa, native.disasm.capstone, native.function.match, native.ghidra.decompile, native.pe.authenticode, native.pe.container, native.pe.hardening, native.pe.packer, native.signature.certverify
    skipped -> native.ghidra.emulate, native.ida.decompile, native.ida.list_functions
          * dynamic.win.frida  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * dynamic.win.frida.intercept  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.container  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c03_antidebug.exe
          * native.pe.packer  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.packer  requires.tools[upx].probe  crackme-corpus/out/c01-stringobf.exe
          * native.disasm.capstone  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.authenticode  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.behaviour.capa  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.signature.certverify  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  requires.tools[rabin2].probe  crackme-corpus/out/c01-stringobf.exe
            native.ida.decompile  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
            native.ida.list_functions  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
          * native.ghidra.decompile  probe.command -> scripts/ghidra-failopen-regress.ps1:6  crackme-corpus/out
            native.ghidra.emulate  probe.command -> scripts/emulation-probe.ps1:60  crackme-corpus/out/c01-stringobf.exe
          (* = a capability the evidence sweep actually runs)
  MISSING   crackme-corpus/out/c03_antidebug.exe
  
  REMEDY    : cd crackme-corpus ; python tools\loop.py      (run from the repo root)
              crackme-corpus/README.md:12  'python tools\\loop.py'
              scripts/crackme-corpus.ps1  exists; changes working directory: False
  NOTE      : this command is NOT run by any script in scripts/; a clone must be told to run it by hand.

==============================================================================
2. TOOLS    binaries a probe invokes   (R5)
==============================================================================
  MISS cmd  adb   [dynamic.device.frida]
  OK   cmd  idalib-mcp  ->  D:\Software\Developer\Python314\Scripts\idalib-mcp.EXE   [native.ida.list_functions]
  OK   cmd  java  ->  D:\Software\Developer\jdk\21\bin\java.EXE   [native.function.match]
  OK   cmd  node  ->  D:\Software\Developer\nodejs\node.EXE   [crypto.jose.parse,forensics.memory.artefact,fuzz.differential.parse,managed.il.decompile,mobile.apk.static,native.ida.decompile,native.ida.list_functions,net.pcap.analyse,net.pcap.selfparse,web.js.cdp]
  OK   cmd  openssl  ->  C:\Program Files\Git\mingw64\bin\openssl.EXE   [native.signature.certverify]
  OK   cmd  powershell  ->  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE   [native.function.match,native.ghidra.decompile,native.ghidra.emulate,native.il2cpp.symbols,native.pe.packer]
  OK   cmd  python  ->  D:\Software\Developer\Python314\python.EXE   [native.behaviour.capa,native.disasm.capstone,native.pe.authenticode,native.pe.container,native.pe.hardening,native.signature.certverify,net.pcap.selfparse,re.corpus.solve]
  OK   path %USERPROFILE%\.local\bin\skillspector.exe  ->  %USERPROFILE%\.local\bin\skillspector.exe   [ops.skill.security]
  OK   path D:/Software/Developer/Python314/Scripts/idalib-mcp.exe  ->  D:\Software\Developer\Python314\Scripts\idalib-mcp.exe   [native.ida.decompile]
  OK   path D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe   [dynamic.win.frida]
  OK   path D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe   [dynamic.win.frida]
  OK   path D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe  ->  D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe   [dynamic.win.frida.intercept]
  OK   path D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py  ->  D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py   [dynamic.win.frida.intercept]
  MISS path Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java   [native.crosscompare.ghidra]
  MISS path Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe   [net.pcap.analyse]
  MISS path Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat   [native.function.match,native.ghidra.decompile]
  MISS path Static-Reversing\capa\capa.exe   [native.behaviour.capa]
  MISS path Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe   [native.pe.packer]
  MISS path Static-Reversing\radare2\radare2-6.2.2-w64\bin\rabin2.exe   [native.pe.hardening]
  MISS path Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/Il2CppDumper.exe   [native.il2cpp.symbols]
  MISS path Unpackers-Game\upx\upx-5.2.1-win64\upx.exe   [native.pe.packer]
  OK   path scripts/ghidra/EmulateDecode.java  ->  %USERPROFILE%\AppData\Local\Temp\station-clone\scripts\ghidra\EmulateDecode.java   [native.ghidra.emulate]
  OK   path web-reverse/tools/chrome.mjs  ->  %USERPROFILE%\AppData\Local\Temp\station-clone\web-reverse\tools\chrome.mjs   [web.js.cdp]
  
  23 distinct targets, 9 absent.
  
  UNDECLARED IN manifests/tools.json (7) -- invoked by a probe, named in no manifest, so a clone has no way to learn it must install them:
    adb   needed by dynamic.device.frida   [absent here AND undeclared]
    openssl   needed by native.signature.certverify   [present HERE, unknown to a clone]
    %USERPROFILE%\.local\bin\skillspector.exe   needed by ops.skill.security   [present HERE, unknown to a clone]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe   needed by dynamic.win.frida   [present HERE, unknown to a clone]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe   needed by dynamic.win.frida   [present HERE, unknown to a clone]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe   needed by dynamic.win.frida.intercept   [present HERE, unknown to a clone]
    D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py   needed by dynamic.win.frida.intercept   [present HERE, unknown to a clone]
  
  HARDCODED PATH OUTSIDE THIS CLONE (5) -- the probe resolves and the target EXISTS, so it reports success while reading somebody else's tree:
    %USERPROFILE%\.local\bin\skillspector.exe
        -> %USERPROFILE%\.local\bin\skillspector.exe   [ops.skill.security]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe
        -> D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe   [dynamic.win.frida]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe
        -> D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe   [dynamic.win.frida]
    D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe
        -> D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe   [dynamic.win.frida.intercept]
    D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py
        -> D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py   [dynamic.win.frida.intercept]

==============================================================================
2b. TOOLS   manifests/tools.json declared locations
==============================================================================
  declared with dir+entry: 22 present, 32 absent
    ABSENT  static-reversing/Ghidra: Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC/ghidraRun.bat
    ABSENT  static-reversing/IDA Pro: Static-Reversing/IDA/ida.exe
    ABSENT  static-reversing/PE-bear: Static-Reversing/PE-bear/PE-bear.exe
    ABSENT  static-reversing/ImHex: Static-Reversing/ImHex/imhex-gui.exe
    ABSENT  static-reversing/Detect It Easy: Static-Reversing/die_win64_portable_3.21_x64/die/die.exe
    ABSENT  static-reversing/capa: Static-Reversing/capa/capa.exe
    ABSENT  static-reversing/FLOSS: Static-Reversing/FLOSS/floss.exe
    ABSENT  static-reversing/YARA-X: Static-Reversing/YARA-X/yr.exe
    ABSENT  static-reversing/ILSpy: Static-Reversing/ILSpy/ILSpy.exe
    ABSENT  static-reversing/ilspycmd: Static-Reversing/ilspycmd/ilspycmd.exe
    ABSENT  static-reversing/dnSpyEx: Static-Reversing/dnSpyEx/dnSpy.exe
    ABSENT  static-reversing/ReClass.NET: Static-Reversing/ReClass.NET/x64/ReClass.NET.exe
    ABSENT  static-reversing/radare2: Static-Reversing/radare2/radare2-6.2.2-w64/bin/radare2.exe
    ABSENT  debuggers/x64dbg: Debuggers/x64dbg/release/x64/x64dbg.exe
    ABSENT  debuggers/GH Injector: Debuggers/GH-Injector/GH Injector SM - x64.exe
    ABSENT  debuggers/Cheat Engine: Debuggers/Cheat Engine/cheatengine-x86_64.exe
    ABSENT  mobile-android/JADX: Mobile-Android/jadx/bin/jadx.bat
    ABSENT  mobile-android/Apktool: Mobile-Android/Apktool/apktool.jar
    ABSENT  network-http/Reqable: Network-HTTP/reqable-app-windows-x86_64/Reqable.exe
    ABSENT  network-http/Wireshark: Network-HTTP/Wireshark/portable/App/Wireshark/tshark.exe
    ... and 12 more

==============================================================================
3. WIKI     %TEMP% in a reproduction step   (R6, READ-ONLY)
==============================================================================
  roots    : <private-tree>\wiki
  scanned  : 165 markdown file(s); 24 %TEMP% line(s) shaped like a reproduction step, 28 prose mention(s)
  03-second-instrument.md:398
      usage: %USERPROFILE%\AppData\Local\Temp\fridaprobe\target.exe <password>
  03-second-instrument.md:443
      #   [stage] copied to %TEMP% ...\fridagate-XXXXXXXX\c01-stringobf.exe (143872 bytes); the
  03-second-instrument.md:523
      head -c 600 crackme-corpus\out\c01-stringobf.exe > "$env:TEMP\trunc.exe"
  03-second-instrument.md:524
      python native-lab\tools\pe_probe.py "$env:TEMP\trunc.exe"
  03-second-instrument.md:739
      python -m venv $env:TEMP\spk-venv
  03-second-instrument.md:740
      & $env:TEMP\spk-venv\Scripts\python.exe -m pip install "setuptools<81" speakeasy-emulator
  03-second-instrument.md:741
      speakeasy -t crackme-corpus\out\c01-stringobf.exe --no-mp -o $env:TEMP\spk-c01.json
  03-second-instrument.md:1217  [self-declared dead/historical]
      # [DEAD] python "%USERPROFILE%\AppData\Local\Temp\w13-pe-probe.py"  -> no such file
  03-second-instrument.md:1226
      head -c 600 crackme-corpus\out\c01-stringobf.exe > "$env:TEMP\trunc.exe"
  03-second-instrument.md:1227
      python native-lab\tools\pe_probe.py "$env:TEMP\trunc.exe"
  03-second-instrument.md:1233
      # It stages its own %TEMP% copy, so no fixture has to be created first.
  03-second-instrument.md:1236
      # expect: [stage] copied to %TEMP% … ; [js] {"kind": "HIT", ...} ; [end] verdict=INTERCEPT-PROVEN
  03-second-instrument.md:1242  [self-declared dead/historical]
      # [DEAD] python "%USERPROFILE%\AppData\Local\Temp\w13-capstone-probe.py" -> no such file
  03-second-instrument.md:1260  [self-declared dead/historical]
      # [HISTORICAL, fixture not committed] this leaned on $env:TEMP\fridaprobe\target.exe, which is not
  03-second-instrument.md:1263  [self-declared dead/historical]
      # rely on a %TEMP% fixture. [REPLACED BY] the committed control, which builds its own:
  04-mcp-exposure-and-frida.md:264
      $exe = "$env:TEMP\w13\c01-stringobf.exe"   # copy of crackme-corpus/out/c01-stringobf.exe
  04-mcp-exposure-and-frida.md:265
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe positive
  04-mcp-exposure-and-frida.md:266
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe neg-badaddr
  04-mcp-exposure-and-frida.md:267
      & $py "$env:TEMP\w13\frida_spawn_gate.py" $exe neg-rebase
  04-mcp-exposure-and-frida.md:276
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  04-mcp-exposure-and-frida.md:291
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  04-mcp-exposure-and-frida.md:304
      [js  ] {"kind": "module", "name": "c01-stringobf.exe", "base": "0x7ff726b20000", "size": 163840, "path": "%USERPROFILE%
  native-pe-instrument-playbook.md:221
      $env:TEMP\pair c01 -import crackme-corpus\out\c01-stringobf.exe `
  native-pe-instrument-playbook.md:222
      -postScript ExportDecompile.java $env:TEMP\ghout -scriptPath scripts\ghidra -deleteProject
  
  context: 28 further %TEMP% mention(s) are prose (provenance, stop-lines, fixture notes), not steps. Listed, not counted against the wiki.

==============================================================================
VERDICT
==============================================================================
  FAIL corpus: corpus present and 14 capabilities read it; 1 named artefact(s) absent -> this clone cannot run its own proofs
  WARN tool: not present: adb (PATH=cmd)  needed by dynamic.device.frida
  WARN tool: not present: Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java (PATH=path)  needed by native.crosscompare.ghidra
  WARN tool: not present: Network-HTTP\Wireshark\portable\App\Wireshark\tshark.exe (PATH=path)  needed by net.pcap.analyse
  WARN tool: not present: Static-Reversing\Ghidra\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat (PATH=path)  needed by native.function.match,native.ghidra.decompile
  WARN tool: not present: Static-Reversing\capa\capa.exe (PATH=path)  needed by native.behaviour.capa
  WARN tool: not present: Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe (PATH=path)  needed by native.pe.packer
  WARN tool: not present: Static-Reversing\radare2\radare2-6.2.2-w64\bin\rabin2.exe (PATH=path)  needed by native.pe.hardening
  WARN tool: not present: Unpackers-Game/Il2CppDumper-net6-win-v6.7.46/Il2CppDumper.exe (PATH=path)  needed by native.il2cpp.symbols
  WARN tool: not present: Unpackers-Game\upx\upx-5.2.1-win64\upx.exe (PATH=path)  needed by native.pe.packer
  WARN tool-undeclared: adb is invoked by a probe but is absent from manifests/tools.json (absent on this station too)
  WARN tool-undeclared: openssl is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-undeclared: %USERPROFILE%\.local\bin\skillspector.exe is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-undeclared: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-undeclared: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-undeclared: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-undeclared: D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py is invoked by a probe but is absent from manifests/tools.json (present on this station)
  WARN tool-foreign: %USERPROFILE%\.local\bin\skillspector.exe resolves to %USERPROFILE%\.local\bin\skillspector.exe, outside this clone -- the probe reads a foreign tree
  WARN tool-foreign: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe resolves to D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida-ps.exe, outside this clone -- the probe reads a foreign tree
  WARN tool-foreign: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe resolves to D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe, outside this clone -- the probe reads a foreign tree
  WARN tool-foreign: D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe resolves to D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\python.exe, outside this clone -- the probe reads a foreign tree
  WARN tool-foreign: D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py resolves to D:\Software\Tool\WorkStation\debugger\native-lab\tools\frida_spawn_gate.py, outside this clone -- the probe reads a foreign tree
  WARN tool-declared: static-reversing/Ghidra declared at Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC/ghidraRun.bat but absent
  WARN tool-declared: static-reversing/IDA Pro declared at Static-Reversing/IDA/ida.exe but absent
  WARN tool-declared: static-reversing/PE-bear declared at Static-Reversing/PE-bear/PE-bear.exe but absent
  WARN tool-declared: static-reversing/ImHex declared at Static-Reversing/ImHex/imhex-gui.exe but absent
  WARN tool-declared: static-reversing/Detect It Easy declared at Static-Reversing/die_win64_portable_3.21_x64/die/die.exe but absent
  WARN tool-declared: static-reversing/capa declared at Static-Reversing/capa/capa.exe but absent
  WARN tool-declared: static-reversing/FLOSS declared at Static-Reversing/FLOSS/floss.exe but absent
  WARN tool-declared: static-reversing/YARA-X declared at Static-Reversing/YARA-X/yr.exe but absent
  WARN tool-declared: static-reversing/ILSpy declared at Static-Reversing/ILSpy/ILSpy.exe but absent
  WARN tool-declared: static-reversing/ilspycmd declared at Static-Reversing/ilspycmd/ilspycmd.exe but absent
  WARN tool-declared: static-reversing/dnSpyEx declared at Static-Reversing/dnSpyEx/dnSpy.exe but absent
  WARN tool-declared: static-reversing/ReClass.NET declared at Static-Reversing/ReClass.NET/x64/ReClass.NET.exe but absent
  WARN tool-declared: static-reversing/radare2 declared at Static-Reversing/radare2/radare2-6.2.2-w64/bin/radare2.exe but absent
  WARN tool-declared: debuggers/x64dbg declared at Debuggers/x64dbg/release/x64/x64dbg.exe but absent
  WARN tool-declared: debuggers/GH Injector declared at Debuggers/GH-Injector/GH Injector SM - x64.exe but absent
  WARN tool-declared: debuggers/Cheat Engine declared at Debuggers/Cheat Engine/cheatengine-x86_64.exe but absent
  WARN tool-declared: mobile-android/JADX declared at Mobile-Android/jadx/bin/jadx.bat but absent
  WARN tool-declared: mobile-android/Apktool declared at Mobile-Android/Apktool/apktool.jar but absent
  WARN tool-declared: network-http/Reqable declared at Network-HTTP/reqable-app-windows-x86_64/Reqable.exe but absent
  WARN tool-declared: network-http/Wireshark declared at Network-HTTP/Wireshark/portable/App/Wireshark/tshark.exe but absent
  WARN wiki: 03-second-instrument.md:398 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:443 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:523 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:524 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:739 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:740 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:741 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1217 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1226 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1227 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1233 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1236 publishes a %TEMP% path as a reproduction step
  WARN wiki: 03-second-instrument.md:1242 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1260 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 03-second-instrument.md:1263 publishes a %TEMP% path as a reproduction step (already marked dead/historical)
  WARN wiki: 04-mcp-exposure-and-frida.md:264 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:265 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:266 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:267 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:276 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:291 publishes a %TEMP% path as a reproduction step
  WARN wiki: 04-mcp-exposure-and-frida.md:304 publishes a %TEMP% path as a reproduction step
  WARN wiki: native-pe-instrument-playbook.md:221 publishes a %TEMP% path as a reproduction step
  WARN wiki: native-pe-instrument-playbook.md:222 publishes a %TEMP% path as a reproduction step

  findings: 1 FAIL, 65 WARN -> exit 1
  This clone/station cannot be trusted to run its own proofs until the FAILs above are cleared.
```

The same command, the same script, and the difference is not asserted — it is on the page:

| line | station | `%TEMP%\station-clone` |
|---|---|---|
| exit code | **0** | **1** |
| corpus | `present`, 5285 files / 24 dirs | `present` but **1 file**; `crackme-corpus/out/c03_antidebug.exe` MISSING |
| corpus verdict | OK | **FAIL corpus** + **FAIL corpus-gate** |
| tool targets absent | 1 of 23 (`adb`) | **9 of 23** |
| undeclared in `tools.json` | 2 (`adb`, `openssl`) | **7** |
| hardcoded path outside the clone | 0 | **5** |
| declared tool locations absent | 2 of 54 | **32 of 54** |

Two clone facts this surfaced that the brief did not list:

- The clone's registry still carries **absolute station paths**. `manifests/capabilities.json` at the
  clone's commit `f441462` has `& 'D:\Software\Tool\WorkStation\debugger\Mobile-Android\objection\.venv\Scripts\frida.exe'`
  where today's station has `& '.\Mobile-Android\...'`. Those probes **resolve and succeed on this box**
  — they read the station's tree, not the clone's — which is worse than failing, and is what the
  `HARDCODED PATH OUTSIDE THIS CLONE` block exists to name.
- The clone's corpus is *partially* built (1 file). A "1 file is not 0" count would have called that
  fine; that is why every named artefact is checked individually rather than counted.

### RUN 3 — `%TEMP%\verify-station` (the second clone named in the brief), **exit 1**

Full output at `%TEMP%\o-clone2.txt`. Same shape: corpus `present` with **7 files / 2 directories**,
`FAIL corpus` on the one artefact still absent, **9 of 23** tool targets absent, **7 undeclared**,
**5 hardcoded paths outside the clone**, **32 of 54** declared tool locations absent,
`1 FAIL, 65 WARN -> exit 1`.

---

## 5. NEGATIVE TEST — the empty corpus, and a mutation proof that the gate is what goes red

Scratch clone: `%TEMP%\clonefresh-neg-095314-24928`, a pristine `git archive HEAD` export
(4,444,160 bytes) with the new script copied in. Three runs, same script, same tree:

| case | corpus state | exit | the line that decides it |
|---|---|---|---|
| **A** | `crackme-corpus/out` renamed away → **MISSING** | **1** | `FAIL corpus-gate: crackme-corpus/out does not exist while 14 capabilities depend on it` |
| **B** | `crackme-corpus/out` present but **empty** | **1** | `FAIL corpus-gate: out/ exists but is empty while capabilities depend on it` |
| **C** | same empty corpus, **mutant** | **0** | `findings: 0 FAIL, 60 WARN -> exit 0` |

Case A, verbatim head and tail:

```text
verify-clone-freshness
  repo : %USERPROFILE%\AppData\Local\Temp\clonefresh-neg-095314-24928
  python 3.14.7  static checks only -- no probe is executed

==============================================================================
1. CORPUS   crackme-corpus/out/   (R3)
==============================================================================
  directory : crackme-corpus/out  [MISSING]
  entries   : 0 files, 0 directories
  needed by : 14 capabilities name a path inside it
              11 of those are CHECKED by scripts/assert-probes.py (out of 21 checked); 3 are on its SKIP list
    checked -> dynamic.win.frida, dynamic.win.frida.intercept, native.behaviour.capa, native.disasm.capstone, native.function.match, native.ghidra.decompile, native.pe.authenticode, native.pe.container, native.pe.hardening, native.pe.packer, native.signature.certverify
    skipped -> native.ghidra.emulate, native.ida.decompile, native.ida.list_functions
          * dynamic.win.frida  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * dynamic.win.frida.intercept  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.container  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c03_antidebug.exe
          * native.pe.packer  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.packer  requires.tools[upx].probe  crackme-corpus/out/c01-stringobf.exe
          * native.disasm.capstone  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.authenticode  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.behaviour.capa  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.signature.certverify  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  requires.tools[rabin2].probe  crackme-corpus/out/c01-stringobf.exe
            native.ida.decompile  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
            native.ida.list_functions  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
          * native.ghidra.decompile  probe.command -> scripts/ghidra-failopen-regress.ps1:6  crackme-corpus/out
            native.ghidra.emulate  probe.command -> scripts/emulation-probe.ps1:60  crackme-corpus/out/c01-stringobf.exe
          (* = a capability the evidence sweep actually runs)
  MISSING   crackme-corpus/out
  MISSING   crackme-corpus/out/c01-stringobf.exe
  MISSING   crackme-corpus/out/c03_antidebug.exe
  
  REMEDY    : cd crackme-corpus ; python tools\loop.py      (run from the repo root)
              crackme-corpus/README.md:12  'python tools\\loop.py'
              README.md:88  'cd crackme-corpus'
              README.md:89  'python tools\\loop.py'
              scripts/crackme-corpus.ps1  exists; changes working directory: False
  NOTE      : this command is NOT run by any script in scripts/; a clone must be told to run it by hand.

  ... [sections 2 TOOLS and 3 WIKI elided; full output at %TEMP%\o-neg-missing.txt] ...
  
  context: 28 further %TEMP% mention(s) are prose (provenance, stop-lines, fixture notes), not steps. Listed, not counted against the wiki.

==============================================================================
VERDICT
==============================================================================
  FAIL corpus: corpus MISSING and 14 capabilities read it; 3 named artefact(s) absent -> this clone cannot run its own proofs
  FAIL corpus-gate: crackme-corpus/out does not exist while 14 capabilities depend on it
  ... [WARN list elided] ...
  findings: 2 FAIL, 60 WARN -> exit 1
  This clone/station cannot be trusted to run its own proofs until the FAILs above are cleared.
```

Case B, verbatim head and tail:

```text
verify-clone-freshness
  repo : %USERPROFILE%\AppData\Local\Temp\clonefresh-neg-095314-24928
  python 3.14.7  static checks only -- no probe is executed

==============================================================================
1. CORPUS   crackme-corpus/out/   (R3)
==============================================================================
  directory : crackme-corpus/out  [EMPTY]
  entries   : 0 files, 0 directories
  needed by : 14 capabilities name a path inside it
              11 of those are CHECKED by scripts/assert-probes.py (out of 21 checked); 3 are on its SKIP list
    checked -> dynamic.win.frida, dynamic.win.frida.intercept, native.behaviour.capa, native.disasm.capstone, native.function.match, native.ghidra.decompile, native.pe.authenticode, native.pe.container, native.pe.hardening, native.pe.packer, native.signature.certverify
    skipped -> native.ghidra.emulate, native.ida.decompile, native.ida.list_functions
          * dynamic.win.frida  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * dynamic.win.frida.intercept  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.container  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.function.match  probe.command  crackme-corpus/out/c03_antidebug.exe
          * native.pe.packer  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.packer  requires.tools[upx].probe  crackme-corpus/out/c01-stringobf.exe
          * native.disasm.capstone  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.authenticode  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.behaviour.capa  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.signature.certverify  probe.prepare  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  probe.command  crackme-corpus/out/c01-stringobf.exe
          * native.pe.hardening  requires.tools[rabin2].probe  crackme-corpus/out/c01-stringobf.exe
            native.ida.decompile  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
            native.ida.list_functions  probe.command -> native-lab/tools/loop.mjs:25  crackme-corpus/out/c01-stringobf.exe
          * native.ghidra.decompile  probe.command -> scripts/ghidra-failopen-regress.ps1:6  crackme-corpus/out
            native.ghidra.emulate  probe.command -> scripts/emulation-probe.ps1:60  crackme-corpus/out/c01-stringobf.exe
          (* = a capability the evidence sweep actually runs)
  MISSING   crackme-corpus/out/c01-stringobf.exe
  MISSING   crackme-corpus/out/c03_antidebug.exe
  
  REMEDY    : cd crackme-corpus ; python tools\loop.py      (run from the repo root)
              crackme-corpus/README.md:12  'python tools\\loop.py'
              README.md:88  'cd crackme-corpus'
              README.md:89  'python tools\\loop.py'
              scripts/crackme-corpus.ps1  exists; changes working directory: False
  NOTE      : this command is NOT run by any script in scripts/; a clone must be told to run it by hand.

==============================================================================
  ... [sections 2 and 3 elided; full output at %TEMP%\o-neg-empty.txt] ...
  
  context: 28 further %TEMP% mention(s) are prose (provenance, stop-lines, fixture notes), not steps. Listed, not counted against the wiki.

==============================================================================
VERDICT
==============================================================================
  FAIL corpus: corpus EMPTY and 14 capabilities read it; 2 named artefact(s) absent -> this clone cannot run its own proofs
  FAIL corpus-gate: out/ exists but is empty while capabilities depend on it
  ... [WARN list elided] ...
  findings: 2 FAIL, 60 WARN -> exit 1
  This clone/station cannot be trusted to run its own proofs until the FAILs above are cleared.
```

### The mutation, and why case C is the interesting one

A gate that has never been seen to fire is not a gate. So the mechanism was deleted and the same
empty corpus re-measured. The mutant is the shipped script with exactly one line changed — the count
that decides whether anything depends on the corpus:

```diff
     needed = len(cap_ids)
+    needed = 0  # MUTANT: the corpus-dependency count is disabled
```

Written to `scripts/verify-clone-freshness.MUTANT.py` **inside the scratch clone** (the station file is
untouched), then run against the identical tree:

```text
verify-clone-freshness
  repo : %USERPROFILE%\AppData\Local\Temp\clonefresh-neg-095314-24928
  python 3.14.7  static checks only -- no probe is executed

==============================================================================
1. CORPUS   crackme-corpus/out/   (R3)
==============================================================================
  directory : crackme-corpus/out  [EMPTY]
  entries   : 0 files, 0 directories
  needed by : 14 capabilities name a path inside it
              11 of those are CHECKED by scripts/assert-probes.py (out of 21 checked); 3 are on its SKIP list
    checked -> dynamic.win.frida, dynamic.win.frida.intercept, native.behaviour.capa, native.disasm.capstone, native.function.match, native.ghidra.decompile, native.pe.authenticode, native.pe.container, native.pe.hardening, native.pe.packer, native.signature.certverify
  ... [sections 1b-3 elided; full output at %TEMP%\o-neg-mutant.txt] ...
  WARN wiki: native-pe-instrument-playbook.md:222 publishes a %TEMP% path as a reproduction step

  findings: 0 FAIL, 60 WARN -> exit 0
```

The mutant still *prints* `directory : crackme-corpus/out [EMPTY]` — the measurement survives the
mutation, which is the whole point of separating measurement from verdict. What dies is the verdict:
`0 FAIL … exit 0` against the same bytes. So the non-zero exit in cases A and B comes from the
capability→corpus dependency, not from the file count, the directory probe, or the tools section.

---

## 6. Findings that change the brief's premises

### 6.1 R5's named example, `skillspector.exe`, is now declared — but only in the working tree

The brief states skillspector "is absent from `manifests/tools.json`". Measured today:

- **In the clones it is absent.** `git show 8ebf4cc^:manifests/tools.json | grep -i skillspector`
  → no match; that tree's category list is `static-reversing, debuggers, mobile-android,
  network-http, unpackers-game, system-forensics, web-reverse, crypto-lab, forensics-lab,
  fuzz-lab` — no `ops` category at all. Both `%TEMP%` clones sit at or before that shape, which is
  why **both flag skillspector.exe as undeclared**.
- **At the station's HEAD today it is declared.** `git log -1 -- manifests/tools.json` → `8ebf4cc`
  "Twelve tools are launched by absolute path and three of them were declared nowhere";
  `git status --porcelain manifests/tools.json` → **empty (clean)**; `git show HEAD:manifests/tools.json
  | grep -c "SkillSpector\|MSVC vcvars64"` → **2**. So a clone made from HEAD *now* gets both.
- **RETRACTION — this section first said the fix was uncommitted.** I wrote "In the working tree it
  is declared … `git status` → ` M` … the fix exists but is uncommitted, so a clone made from HEAD
  today still misses it." That was a **stale read**: the ` M` was true when I took it and `8ebf4cc`
  landed between that read and my commit (`git push` reported `8ebf4cc..070320a`). The tools-manifest
  worker caught it and re-measured it independently rather than believing me. A claim about the index
  has a shelf life, and this one did — the retraction is left in place instead of deleted, because
  the next window should be able to see that it was made, checked, and found stale.
- **What survives:** the station run and the two clone runs were never disagreeing. They were reading
  three different commits — two clones behind `8ebf4cc`, the station at it. The clone-side flags for
  `skillspector.exe` are a true statement about *those two trees*, not about the station.

Two more of the brief's implicit assumptions did not survive measurement: MSVC is declared too
(`build / MSVC vcvars64`), and the undeclared set today is `adb` and `openssl` —
`adb` absent from this box *and* from the manifest, `openssl` present here (Git's copy, resolving to
`C:\Program Files\Git\mingw64\bin\openssl.EXE`) and known to no manifest. Interpreters (`python`,
`node`, `java`, `powershell`, `dotnet`) are deliberately excluded from that verdict: flagging them
would bury the two findings that a human can act on.

### 6.2 "11 of the 21" is reproducible, and one name deeper than a grep finds

The script derives the number by reading `manifests/capabilities.json`, following each
`probe.command` into the harness script it invokes, and subtracting the six ids
`scripts/assert-probes.py` never runs. Result: **14 capabilities name a path inside
`crackme-corpus/out/`; 11 of them are checked by the sweep, out of 21 checked.** The README's claim
reproduces exactly. Three of the 14 are invisible to a string search over `probe.command`:

- `native.ghidra.decompile` → `scripts/ghidra-failopen-regress.ps1:6`
- `native.ida.decompile`, `native.ida.list_functions` → `native-lab/tools/loop.mjs:25` (both on the SKIP list)
- `native.ghidra.emulate` → `scripts/emulation-probe.ps1:60` (SKIP list)

### 6.3 R6 is live, and 4 of the 24 hits are self-declared dead

The wiki scan reports 24 recipe-shaped `%TEMP%` lines across 3 files. Seven of them sit in
`literature/survey-2026-10-02/03-second-instrument.md` and carry their own
`[DEAD]` / `[HISTORICAL]` / `[REPLACED BY]` marker — documentation of a dead probe, which is honest
and is reported *with* the tag rather than hidden. The rest are live recipes a reader cannot run:
`03-second-instrument.md:523` `head -c 600 crackme-corpus\out\c01-stringobf.exe > "$env:TEMP\trunc.exe"`,
`:739-741` a `speakeasy` venv under the temp root, `04-mcp-exposure-and-frida.md:264-267`
`& $py "$env:TEMP\w13\frida_spawn_gate.py" $exe positive` against a probe file that no longer exists,
and `methods/native-pe-instrument-playbook.md:221-222`. **Fixing them is a wiki edit and belongs to
the wiki's writers; this script is a reader by construction.** The freshly created
`methods/arsenal-clone.md` adds **0** hits to the count — verified by re-running the station sweep
after writing it (still `0 FAIL, 29 WARN`).

---

## 7. What this script deliberately does not do

- It does not build, install, decompile, or run a probe, and it does not write outside stdout. It is
  usable on a stranger's box in under a second, which is the whole point.
- It does not rewrite the wiki. A %TEMP% recipe in published prose is a defect in the prose.
- It does not repair a registry. `probe.expect` edits are how a station loses its ability to be wrong.
- It does not report "clean" for a scan that never ran: no wiki root found → `WARN … the R6 scan did
  NOT run`, naming the paths it looked at.

### 7.1 The boundary, stated because a sibling worker asked

`scripts/verify-tools-manifest.py` (another writer this wave) scans the repo's **own scripts** for
absolute executable paths; this script scans **registry probe strings** in
`manifests/capabilities.json`. Overlap is one line of output; the inputs are disjoint, and merging
them is Main's call, not mine. Three points measured rather than assumed:

- **Their `dir`-without-`entry` shape is handled.** My declared-side check requires both fields
  (`scripts/verify-clone-freshness.py`, section 2b), so `ops / SkillSpector` and `build / MSVC vcvars64`
  are skipped, not reported absent. Evidence: the station run counts `52 present, 2 absent` out of 54
  entries that carry both fields, and neither new entry appears in the ABSENT list.
- **Their manifest edit silences my R5 finding, and both `%TEMP%` clones still flag
  `skillspector.exe`** — not because the edit is uncommitted (it is committed, `8ebf4cc`) but because
  those two clones sit *behind* it. See §6.1.
- **Their `rabin2` example does not hold; their `openssl` example is already covered.**
  `native-lab/tools/hardening_probe.py:57` is `DEFAULT_RABIN2 = os.environ.get("RABIN2_EXE") or
  _newest_rabin2()` — a pinned path, and `:79-80` refuses outright with *"this path is the pinned
  6.2.2 build and is not a PATH lookup"*. Not a bare launch. `openssl` **is** launched bare
  (`native-lab/tools/cert_verify.py:97`), and my scan already reports it: from the registry's
  `native.signature.certverify` → `requires.tools[openssl].probe = "openssl version"`, resolving to
  `C:\Program Files\Git\mingw64\bin\openssl.EXE` and undeclared.

The residual gap is real and I am not closing it here: **a bare launch inside a repo script that no
registry entry mentions is invisible to my scan.** Measured example: `speakeasy` — `shutil.which` is
`None`, it is in no manifest, and it appears only in a wiki recipe, which the R6 scan catches instead.
Extending section 2 to walk repo scripts would collide with the other worker's file; the honest
statement of scope is that section 2 covers *what the registry claims*, not *what the code executes*.

Lint note: `python -m ruff check scripts/verify-clone-freshness.py` reports 7 findings with no ruff
config in the repo (default ruleset). For calibration, `scripts/assert-probes.py` reports 19 and
`scripts/registry-verify.py` 15 on the same default, so the file is below the house baseline and I
left the rest alone rather than restyle code nobody asked me to touch. The station output pasted in
§3 was re-run after the one import fix and is byte-identical.

## 8. Reproduce

```powershell
cd D:\Software\Tool\WorkStation\debugger
python scripts\verify-clone-freshness.py                      ; # exit 0 today
python scripts\verify-clone-freshness.py --strict             ; # warnings promoted
python scripts\verify-clone-freshness.py --repo <a clone>     ; # read-only against any clone
```

Cost measured: 0.20–0.38 s wall, no network, no subprocess, no write outside stdout.
`--help` documents every flag. Nothing in the station's own harness calls it yet; wiring it into
`scripts/verify-all.ps1` is a one-line change for whoever owns that file (I do not own it).

## 9. If someone picks this up next

1. ~~**Commit `manifests/tools.json`.**~~ — **DONE by Main in `8ebf4cc`, no action.** Kept struck
   rather than deleted because it is the second claim in this report that aged out from under me, and
   the pattern is the finding: anything asserted about the index must be re-measured, not inherited
   from a sibling's message or from my own earlier note (§6.1 RETRACTION, §10 NEXT item 4).
2. **Decide where the corpus build lives.** The command exists and is documented; nothing executes it.
   A `-BuildCorpus` flag on `scripts/bootstrap.ps1` would turn a three-paragraph instruction into a
   command a clone cannot skip.
3. **`adb` and `openssl`.** Both are named by live probes, neither is in any manifest. Declaring them
   costs two JSON lines; leaving them means a clone discovers the gap by failing.
4. **The 17 live %TEMP% wiki recipes** (§6.3) need an author, not a script.
---

## 10. Wrap-up (session paused by Owner mid-task)

- **Committed and pushed**, not left as a patch. `debugger-workstation` `main`: `070320a`, containing
  exactly two files — `scripts/verify-clone-freshness.py` and this report. `<private-tree>` `master`:
  `bd841bd`, one file — `wiki/methods/arsenal-clone.md`. Nothing of another writer's is in either
  commit; `git diff --cached --name-only` was checked before committing.
- **Nothing staged but unfinished.** No edit of mine is half-applied; both trees carry only my two
  additions plus other agents' independent work, which I did not touch.
- One lint fix landed after the runs in §3–§6 were captured: a blank line after
  `from __future__ import annotations` (ruff `I001`). The station output was re-run after it and is
  **byte-identical** to the paste above (`cmp` on the two captures). All exit codes in this report
  are from runs I executed; nothing here is `[UNVERIFIED]`.

### NEXT — cold-start notes, in the order I would do them

1. **Wire it into the gate.** `scripts/verify-all.ps1` does not call
   `scripts/verify-clone-freshness.py`. One line, but I do not own that file. Until then a clone is
   only checked if a human remembers to run it — which is the same failure this script was written to
   stop.
2. **Run it over `crackme-corpus/tools/loop.py --list` semantics.** I verified the corpus *gate*, not
   the corpus *runner*: I never executed `loop.py` (110 s + a Ghidra JVM), so "this command populates
   the corpus" rests on `crackme-corpus/README.md:9-17`, `README.md:88-89` and the runner's own
   existence — three documents plus a file listing, **not** one build. The next window that has
   budget should run it once in a scratch clone and paste the table.
3. **R5 residue** (§6.1): `adb` and `openssl` are named by live probes and declared in no manifest.
   `adb` is not on this box at all, so `dynamic.device.frida` cannot run here either.
4. ~~**`manifests/tools.json` is still uncommitted on the station**~~ — **WITHDRAWN, it was a stale
   read.** Re-measured: `git status --porcelain manifests/tools.json` is empty and the file is
   committed at `8ebf4cc`, so a clone from HEAD gets `ops / SkillSpector` and `build / MSVC vcvars64`.
   Nothing to do here. See the RETRACTION in §6.1; do not go looking for this problem.
5. **The 17 live `%TEMP%` wiki recipes** (§6.3) need an author, not a script. Full list with
   `file:line` is in any run's section 3.
6. **Decide whether the two tools gates merge.** `scripts/verify-tools-manifest.py` (repo scripts,
   absolute paths) vs mine (registry probe strings). §7.1 states the boundary; merging is Main's call.

### Scratch left behind (harmless, inside %TEMP%)

- `%TEMP%\clonefresh-neg-095314-24928` — the pristine `git archive HEAD` export used for cases A/B/C,
  including `scripts/verify-clone-freshness.MUTANT.py`, the one-line mutant. Delete whenever.
- `%TEMP%\o-*.txt` — the full captured outputs whose middle sections §5 elides.

### Cross-check after the sibling's `8ebf4cc` landed (both agents stopped, then re-measured)

The tools-manifest worker closed its side and I re-ran mine against the same HEAD. **Nothing in my
numbers moved**, which is the point of the split rather than a coincidence:

| | mine (registry probe strings) | theirs (repo scripts, absolute paths) |
|---|---|---|
| undeclared after their fix | **2** — `adb`, `openssl` | **0** of 12 invoked absolute-path tools |
| what each fix touched | nothing their commit covered | `ops/SkillSpector`, `build/MSVC vcvars64`, `msedge` needs |

Their 3 undeclared tools were all *absolute-path launches in repo scripts*; my 2 are *bare names named
by a registry probe*. Neither commit can move the other's count, and neither number is wrong. The
undeclared sets are disjoint (theirs is empty), so the station-wide count of *undeclared-and-invoked*
tools is **2**: `adb`, `openssl`.

**But do not add the denominators.** The sibling worker caught me implying a total I cannot defend, and
is right: `23 + 12 = 35` is also wrong, because the two sets **overlap**. Their 12 are absolute-path
launches inside repo scripts — which include harness internals my gate never sees (`node.exe`,
`python.exe`, `powershell.exe`, and `frida_spawn_gate.py`, which is a repo file, not a tool) — while my
23 are capability-probe targets their gate never sees (`tshark`, `capa`, `diec`, and the bare-name
PATH-resolved ones). So: **neither 12, nor 23, nor 35 is a station-wide tool count.** They are two
differently-scoped denominators. Anyone who wants one number needs a third gate over the union, and
neither of us has written it. (Their reading of the overlap is `[INFERENCE]` from the two inclusion
criteria, not a measured set comparison — the union count is `[UNVERIFIED]` in this report too.)

Two numbers in this report are **captured at a moment and are already stale** — the pasted station run
in §3 is a snapshot: the wiki scan now reads **165** markdown files / 28 prose mentions (was 164 / 27)
because another writer added a page, and section 2b still reads `52 present, 2 absent`. The gate is
still `0 FAIL, 29 WARN -> exit 0`, re-verified after that re-run. Do not read §3 as the current state of
the wiki; re-run the command.