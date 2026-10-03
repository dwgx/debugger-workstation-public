STATUS: DONE

# tools.json vs. what the station actually launches

Target: `manifests/tools.json` + ONE new file `scripts/verify-tools-manifest.py`. Nothing else.

## 1. What I changed

| file | change |
|---|---|
| `scripts/verify-tools-manifest.py` | NEW, 711 lines. The inventory + gate. `--selftest` proves its own rules. |
| `manifests/tools.json` | +6 lines (2 new categories, 2 new entries), 3 lines edited. 60 → 62 entries. |

The manifest diff is 9 added / 3 removed: the 3 removals are the three `web-reverse` entries I
edited in place (their `needs`), and the 6 additions are the `ops` and `build` blocks. File is
still 100% CRLF (96 CRLF, 0 bare LF), no BOM, valid JSON, no duplicate keys, no duplicate tool
names.

## 2. ACCEPTANCE 1 — gate exits 0 on the station as left

```
$ python scripts/verify-tools-manifest.py
verify-tools-manifest: scanned 141 files under scripts/, */tools/, */lab/ -> 12 distinct absolute executable names
...
INVOKED BUT UNDECLARED  (this is what fails the run)
  none
...
EXCLUSION RULES APPLIED (audit the inventory, do not trust it)
  E1-url                   dropped 16 candidate(s)
  E2-escaped-spelling      dropped 15 candidate(s)
  E4-comment               dropped 0 candidate(s)
  E3-no-launch-in-file     dropped 1 candidate(s)

tools: 62 declared, 12 invoked, 0 undeclared, 2 dead
>>> EXIT=0
```

## 3. ACCEPTANCE 2 — NEGATIVE CONTROL, actually run

Deleted the `ops` / SkillSpector entry — the one the brief named — and re-ran:

```
$ python -c "...drop the line containing '\"name\": \"SkillSpector\"'..."   # deleted 1 line
deleted the ops/SkillSpector entry ( 1 line )

############ ACCEPTANCE 2: NEGATIVE CONTROL ############
INVOKED BUT UNDECLARED  (this is what fails the run)
  UNDECLARED skillspector.exe     headless-lab/tools/skill_security_control.ps1:24
             $env:USERPROFILE\.local\bin\skillspector.exe
             launched by absolute path, absent from manifests/tools.json; 1 spawn / 0 reference
>>> EXIT=1
```

Restored and re-verified:

```
>>> RESTORED EXIT=0
CRLF 96 bareLF 0 | SkillSpector present: True
>>> SELFTEST EXIT=0
```

## 4. Counts

| | before my manifest edit | after |
|---|---|---|
| declared entries | 60 | 62 |
| invoked (distinct absolute executable names) | 12 | 12 |
| **undeclared and invoked** | **3** | **0** |
| dead declarations | 2 | 2 |

Undeclared before, all three now declared:

| bare name | site that proved it | declared as |
|---|---|---|
| `skillspector.exe` | `headless-lab/tools/skill_security_control.ps1:24` | new `ops` / SkillSpector (`dir` basename) |
| `vcvars64.bat` | `crackme-corpus/tools/build-c.ps1:26`, `forensics-lab/lab/payload/build.bat:5`, +12 more | new `build` / MSVC vcvars64 (`dir` basename) |
| `msedge.exe` | `web-reverse/tools/chrome.mjs:21-22` | extended `needs` on the three web-reverse entries |

## 5. The classified inventory — 12 invoked names, with the file:line that justified each

Condition column: **U** = invoked unconditionally on the path taken, **C** = conditional
(candidate list / `Test-Path` probe / env override).

| bare name | cond | sites (file:line) | classification + justification |
|---|---|---|---|
| `skillspector.exe` | U | `headless-lab/tools/skill_security_control.ps1:24` | `& "$env:USERPROFILE\.local\bin\skillspector.exe" scan $p --no-llm --fail-on-findings`, then `exit $LASTEXITCODE`. Unconditional, and the script's whole purpose. **Was the gap.** |
| `vcvars64.bat` | C | `crackme-corpus/tools/build-c.ps1:26-30`, `headless-lab/tools/build.ps1:32-35`, `managed-lab/tools/build.ps1:40-43`, `forensics-lab/lab/payload/build.bat:5` | Probed with `Test-Path`, first hit wins; `build-c.ps1:33-37` and `build.ps1:37-38` hard-fail (exit 3 / `Write-Error`). `build.bat:5` calls one path unconditionally. 14 sites. |
| `chrome.exe` | C | `web-reverse/tools/chrome.mjs:18,19,21`, `scripts/web-reverse-lab.ps1:49,50` | `CANDIDATES` list, first `fs.existsSync` wins (`chrome.mjs:26`). `web-reverse-lab.ps1:47-52` is a presence check that only reports `chromeFound` at `:102`. |
| `msedge.exe` | C | `web-reverse/tools/chrome.mjs:21,22` | Same candidate list, reached only when no Chrome exists. **Was the gap.** |
| `idalib-mcp.exe` | U | `native-lab/tools/ida-client.mjs:21`, `native-lab/tools/loop.mjs:24`, `scripts/native-lab.ps1:61` | `spawn(IDALIB, ...)` at `ida-client.mjs:124` and `loop.mjs:137`. Unconditional once the loop runs. |
| `idat.exe` | C | `scripts/ida-cli.ps1:20` | Fallback after `Join-Path $InstallRoot 'Static-Reversing\IDA\idat.exe'` misses (`:18-21`). Declared only via the IDA Pro `note` — flagged WEAKEST FIELD in the output. |
| `tshark.exe` | C | `net-reverse/lab/tshark.mjs:19,20` | Candidate list; `spawnSync(candidate, ['--version'])` at `:31` and the result must match `/^TShark/i` (`:32`). Also a repo-relative candidate at `:18`. |
| `7z.exe` | C | `scripts/restore-from-cache.ps1:31` | Second candidate after the station copy; `& $z7 x ...` at `:38`, and `:34` throws if neither exists. |
| `node.exe` | U | `scripts/smoke-all.ps1:43` | `$Node`; `:47-52` exits 2 if any of the three interpreters is missing, so the run cannot proceed without it. |
| `python.exe` | C | `scripts/crackme-corpus.ps1:36,37`, `scripts/smoke-all.ps1:44` | Two candidates then `Get-Command python` fallback (`:41`); `& $python $runner` at `:53`. |
| `powershell.exe` | U | `scripts/smoke-all.ps1:45` | `C:\Windows\...` — classified `os`, not a manifest concern. |
| `frida_spawn_gate.py` | U | `headless-lab/tools/frida_gate_control.ps1:10,12` | An in-tree repo file, not a tool — classified `in-tree`. |

`in-tree` and `os` are classifications, not passes: a name is only `in-tree` when **every**
absolute path to it resolves inside the repo, and only `os` when every one is under
`C:\Windows\`. `python.exe` appears at both an in-repo venv (`frida_gate_control.ps1:8`) and
outside it, so it is judged external — judging on the first site alone called a host
interpreter a repo file and hid the dependency.

## 6. Manifest additions (existing shape, no new fields)

```json
    "ops": [
      { "name": "SkillSpector",  "version": "2.12.0", "dir": "%USERPROFILE%\\.local\\bin\\skillspector.exe", "official_source": "https://github.com/NVIDIA/skillspector", "auto_update": false, "verify": true, "note": "..." }
    ],
    "build": [
      { "name": "MSVC vcvars64", "version": "2022",   "dir": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat", "official_source": "https://visualstudio.microsoft.com/downloads/", "auto_update": false, "verify": true, "note": "..." }
    ]
```

Every version and path in those two entries was measured on this station, not recalled:

- `skillspector.exe --version` → `SkillSpector v2.12.0` (run; matches the probe expectation already in `capabilities.json`).
- MSVC probed on disk: **present** at `...\2022\Community\...` and `...\18\Community\...`;
  **absent** at `2022\Professional`, `2022\Enterprise`, and the x86 BuildTools path.

Three deliberate choices, stated because a reviewer should be able to reject them:

1. **Two new category keys (`ops`, `build`).** The *entry* shape is unchanged — same
   `name`/`version`/`dir`/`official_source`/`auto_update`/`verify`/`note` as every existing
   third-party entry. A category is a key under `tools`, not a field on an entry. I did not
   want to hide a C-toolchain requirement inside an unrelated entry's `needs` string, which is
   how MSVC was recorded before (`needs: "MSVC 2022 (optional)"` on the forensics-lab payload
   entry, while three other labs depended on it just as hard and named it nowhere).
2. **`dir` holds the whole path and there is deliberately no `entry`.** This follows the
   existing `ida-pro-mcp (idalib)` record. It also avoids planting a false "declared location
   is absent" warning in `verify-clone-freshness.py:496-500`, which resolves `repo/dir/entry`
   and would compute a nonsense path from a host-absolute one.
3. **`needs` extended, not a new Edge entry.** `web-reverse/tools/chrome.mjs` really does
   launch `msedge.exe`, so the three entries that list `Chrome` now say
   `Chrome; msedge.exe accepted as fallback`. That names the executable, so the dependency is
   checkable, without adding a tool record for a fallback browser.

Verified `bootstrap.ps1:303-311` still renders the manifest (`ConvertFrom-Json` + iterate all
categories) — both new categories appear:

```
[ops] 1 entries
    - SkillSpector           2.12.0     https://github.com/NVIDIA/skillspector
[build] 1 entries
    - MSVC vcvars64          2022       https://visualstudio.microsoft.com/downloads/
```

## 7. Dead declarations — reported, does not fail, and why neither is a defect

```
tools: 62 declared, 12 invoked, 0 undeclared, 2 dead
  dead      ScyllaHide                   [debuggers]
  dead      PE-bear                      [static-reversing]
```

- **ScyllaHide** — no `entry`, `dir` is `Debuggers/ScyllaHide`, and no scanned script names
  that directory. It is a plugin the human injects into a running x64dbg; there is no script
  that could launch it. Deleting the record would remove the only place a clone learns it
  ships with x64dbg.
- **PE-bear** — `dir` `Static-Reversing/PE-bear`, `entry` `PE-bear.exe`, and neither string
  appears anywhere in the 141 scanned files. It is a GUI started by a human from a menu. Same
  argument: the record is the information, not the defect.

The exit code stays 0 for these by design (docstring says why): failing a build on a
correctly-described lab entry point would push the obvious "fix", which is deleting the entry
and destroying exactly what a fresh clone needs.

### A third bucket the tool reports, which is a real defect but not mine to fix

9 declared entries have an `entry` filename that **no script names**, while their directory is
named. The sharpest is **Detect It Easy**: `tools.json` declares `entry: "die/die.exe"`, but
`scripts/intel-agent.ps1:20` and `scripts/forensics-lab.ps1:140-147` both launch **`diec.exe`**.
Same shape for GH Injector, Reqable, ImHex, ReClass.NET, System Informer, Universal Extractor,
pyinstxtractor-ng, and `forensics-lab payload` (declares `d12payload.c`, built via
`lab/payload/build.bat`). `tools.json` is mine to edit but those entries are not what this
brief is about, and changing 9 entry filenames is a separate claim I have not verified tool by
tool. Flagged, not silently changed.

## 8. The gate is mutation-proven — four controls, each run

| # | what I removed | result |
|---|---|---|
| 1 | the `ops`/SkillSpector manifest entry | **exit 1**, `UNDECLARED skillspector.exe ... skill_security_control.ps1:24` |
| 2 | the `idat.exe` mention from the IDA Pro `note` | **exit 1**, `UNDECLARED idat.exe ... scripts/ida-cli.ps1:20` |
| 3 | rule E2 (escaped-spelling) from the script | **exit 0** — no verdict changed |
| 4 | the quote-exclusion from the token regex | `--selftest` **exit 1**, 24/26 |

Control 3 is a **negative result and I am reporting it rather than hiding it**: E2 and E3 overlap
completely on today's tree. Attribution of every dropped candidate to the first rule that
dropped it shows E2 fires only on `forensics-lab/lab/spec.mjs` (15 candidates) and E3 only on
`native-lab/tools/frida_spawn_gate.py:36` (1 candidate) — and `spec.mjs` also fails the
launcher test, so removing E2 loses nothing *today*. I kept E2 because it covers a shape E3
cannot: `registry-verify.py:1881`'s foreign fixture sits inside a longer command string, so it
never begins a token and no extractor rule sees it. Rewrite it as
`"command", "D:\\Some\\Other\\Machine\\tool.exe"` and only E2 catches it. The docstring says
this plainly instead of implying E2 is carrying weight it is not.

Control 2 exists because `idat.exe` is satisfied by the *weakest* field (`note`). A gate whose
loosest path is untested is a gate that might not be a gate; it is tested.

Control 4 proves the self-test is load-bearing: reintroducing the token bug (a bare token
swallowing the opening quote of `r"C:\..."`) turns `--selftest` red and the run exits 1.

`--selftest` = **26/26**, exit 0. It asserts the rules, including the two extractor bugs I
actually made and fixed:

```
selftest: 26/26 passed
```

## 9. Completeness check — is the inventory missing anything?

An independent broad sweep (regex for any drive/env/UNC-rooted `.exe|.bat|.cmd|.com|.jar|.ps1|.py|.mjs|.js`
anywhere in scope) finds **58 occurrences across 18 files**. 11 are in the accepted inventory;
the other 47 fall into buckets I can name:

| bucket | where | why it is not a tool |
|---|---|---|
| lab ground-truth table | `forensics-lab/lab/spec.mjs` (15) | fabricated process-image paths the lab *describes*; E2 |
| URL | `download-tools.ps1:169,194,198`, `intel-agent.ps1:55` | `://` scheme tail; E1 |
| XML namespace | `mobile-lab/lab/build/build-apk.mjs:232` | `http://schemas.android.com` |
| target binary, not a dependency | `native-lab/tools/frida_spawn_gate.py:36` | a default `argv`; E3 |
| docstring / comment | `assert-probes.py:186`, `check_backend_consistency.py:39`, `gate.ps1:37`, `smoke-all.ps1:13`, `registry-verify.py:1881` | not code |
| self-test fixture | `verify-tools-manifest.py:27` | my own docstring; excluded from scan entirely |

**No real tool was missed.** That is the check that matters: an extractor that quietly drops
space-bearing paths is worse than no extractor, and I found exactly that bug (it hid
`chrome.exe`, `msedge.exe`, `tshark.exe` and `7z.exe` on the first run).

## 10. Near-miss class — measured, deliberately NOT in the gate

The gate sees absolute **executable** paths. It cannot see a tool reached by joining a bare
name onto an absolute **directory** root, because resolving that needs cross-file variable
analysis, and a wrong resolution fails closed on a real tool. So, stated rather than hidden:

**Android SDK build-tools, via an absolute directory root.**
`scripts/mobile-lab.ps1:58` → `$bt = ... else { 'D:\Software\Android\Sdk\build-tools\35.0.0' }`,
`:59` → `Join-Path $bt 'aapt2.exe'`; `mobile-lab/lab/build/build-apk.mjs:75-76` has the same two
roots. Launched at `build-apk.mjs:210,228,233,239` (`aapt2.exe`), `:268` (`d8.bat`),
`:303,304` (`zipalign.exe`), `:322` (`apksigner.bat`), and `mobile-lab.ps1:67-68` calls them
"aapt2 + d8 + zipalign + apksigner ... what makes a real APK buildable with no full SDK".
**None of the four is in `tools.json`, and mobile-lab has no entry at all.** That is a real gap
in the same family as the one I was asked to close; it needs a decision about whether
`mobile-lab` gets its own category, which is beyond this brief.

**Tools launched by bare name, resolved from PATH or an argument.**

| tool | site | declared? |
|---|---|---|
| `rabin2` | `native-lab/tools/hardening_probe.py:83` (`args.rabin2`) | **CORRECTED — I was wrong here.** Not a bare launch: `:57` is `DEFAULT_RABIN2 = os.environ.get("RABIN2_EXE") or _newest_rabin2()`, and `_newest_rabin2()` globs `radare2-*-w64/bin/rabin2.exe` under the declared `Static-Reversing/radare2` dir. `:79-81` even refuses with "this path is the pinned 6.2.2 build and is not a PATH lookup". Declared by directory. |
| `openssl` | `native-lab/tools/cert_verify.py:97` | **no** |
| `certutil` | `net-reverse/tools/trustcheck.mjs:60,61` | no, OS-provided |
| `curl.exe` | `scripts/web-reverse-lab.ps1:56`, `crypto-lab.ps1:80`, `mobsf-agent.ps1:47,53,54` | no, OS-provided |
| `taskkill` | `native-lab/tools/ida-client.mjs:136`, `loop.mjs:217` | no, OS-provided |
| `cmd.exe` | `ghidra-headless.ps1:71,96`, `mcp-probe.py:239`, `mobile-lab/tools/loop.mjs:252` | no, OS-provided |

`openssl` is the only one of these that is neither declared nor OS-provided. `CloneBootstrapProbe`
independently reached the same conclusion from the registry side: `native.signature.certverify` →
`requires.tools[openssl].probe` = `"openssl version"`, resolving to
`C:\Program Files\Git\mingw64\bin\openssl.EXE`, undeclared. First reported here 2026-10-03.

## 11. Coordination — a sibling already covers part of this ground

`scripts/verify-clone-freshness.py` is **untracked in this wave** and implements rule R5
("at least one tool is absent from `manifests/tools.json`, so a clone cannot know it must
install it"). It reaches the same conclusion by a different route: it reads probe commands out
of **`manifests/capabilities.json`**, whereas mine searches the **repo's own scripts**. Different
inputs, same question, so both are defensible — but two scripts reporting "undeclared tool" is
the second-convention failure, so:

- I did not touch their file.
- Their declared-side check (`:496-500`) skips entries lacking `dir` **or** `entry`, and I gave
  both new entries a `dir` with no `entry` precisely so they are skipped rather than reported
  absent.
- My manifest fix benefits both: their check tests the stem (`Path(val).stem`), so declaring
  `skillspector` and `vcvars64` silences the same finding on their side.

## 12. [UNVERIFIED] — stated, not claimed

- **`scripts/verify-all.ps1` was not run.** It is not in my acceptance criteria, it runs
  `assert-probes --budget 150` (real tools, ~15 min) and two mission selftests, and four
  sibling workers are running concurrently — that is a load-sensitive collision I chose not to
  cause. What I did instead, measured rather than assumed: `grep` for `tools.json` across the
  whole repo shows the only *code* readers are `bootstrap.ps1` (display only, replayed above
  and rendering both new categories), `verify-clone-freshness.py` (sibling), and my own script.
  `scripts/doc-facts.py` contains no reference to `tools.json` at all, so no hardcoded tool
  count can have drifted. If you want the full harness run, it is one command.
- **`E4-comment` drops 0 candidates** and is therefore not exercised by the live run. It is
  covered by four `--selftest` cases (PS block comment, PS line comment, Python docstring, JS
  `//`). Its purpose is a guarantee that comment text can never become a dependency, not a
  filter doing work today; the docstring says so rather than implying otherwise.
- **`E1`/`E2` counts move with the tree.** They read 16/15 in my captures; a sibling editing a
  file under `scripts/` moves them. That is why the report prints the counts instead of
  asserting a fixed inventory.
- The 9 `entry`-mismatch entries in §7 are reported from a mechanical comparison. I did **not**
  run each tool to confirm which filename it really starts from, so I am not claiming each
  `entry` value is wrong — only that no scanned script names it.

## 13. ANSWER to Main's question: which of my exclusion rules does `verify-clone-freshness.py`'s input shape make UNREACHABLE?

The answer is **a specific rule — three of them, headed by E2.** It is not "none", so the
subset checker survives on the input shape rather than on symmetry.

Their input is strings taken from `manifests/capabilities.json` **after JSON decoding**
(`probe.command`, `probe.prepare`, `requires.tools[].probe`), fed through `probe_targets()`
(`verify-clone-freshness.py:384`). Mine is **raw source text** — `Source.__init__` opens each
file as text with escapes intact. That single difference decides all three.

| rule | reachable for them? | why |
|---|---|---|
| **E2** escaped-spelling | **NO — structurally unreachable** | This is the sharp one. `capabilities.json:2381` stores the probe as `"& \"$env:USERPROFILE\\.local\\bin\\skillspector.exe\" scan ..."` — the path written with **doubled** backslashes. `json.load` resolves those escapes, so `probe_targets()` receives `$env:USERPROFILE\.local\bin\skillspector.exe` with **single** backslashes. The spelling E2 exists to reject exists only BEFORE decoding. It is not a rule they could add; it is a rule about a layer their input never occupies. Measured: E2 fires 15× on `spec.mjs` (raw text) and is unreachable from parsed JSON. |
| **E3** no-launch-in-file | **NO** | E3 asks "can this file spawn a process?". Their input is a list of command strings with no file attached, and every token is a declared launch **by construction** — it came out of a probe field. The question has no referent. |
| **E4** comment | **NO** | JSON has no comment syntax, and they read only `command`/`prepare`, never `note`. There is nothing to strip. |
| **E1** URL | **YES in principle, not exercised** | A probe command could contain a URL. `[UNVERIFIED]` — I did not run their `probe_targets`/`classify` over `capabilities.json` to see whether a URL would be misread. |

So: the subset checker's justification is that it **cannot perform the source-text checks at
all**, not that it is a convenient second opinion. Its distinct question — "what is missing IN
A CLONE" — is genuinely different from "what is undeclared in the source", and it survives on
that basis. Main stated he is handling the merge himself (their file, my file, their call);
I did not touch it and will not.

## 14. NEXT — for the next window, which starts cold

**Landed and committed.** `manifests/tools.json` (+2 categories, 3 lines edited) and
`scripts/verify-tools-manifest.py` are committed by Main as `8ebf4cc`. This report file was
written after that commit and is committed separately. Nothing of mine is left staged,
partial, or half-applied in the shared worktree.

**Open finding 1 — the named blind spot (KEPT DELIBERATELY, do not "fix" by widening the gate).**
Android SDK build-tools are reached by joining a bare name onto an absolute **directory** root:
`scripts/mobile-lab.ps1:58-59` and `mobile-lab/lab/build/build-apk.mjs:75-76` hold
`D:\Software\Android\Sdk\build-tools\35.0.0`, and `aapt2.exe` / `d8.bat` / `zipalign.exe` /
`apksigner.bat` are launched at `build-apk.mjs:210,268,303,304,322`. An absolute-**executable**-path
extractor cannot see this. None is declared and **mobile-lab has no `tools.json` entry at all**.
Closing it needs a decision about whether mobile-lab gets its own category. Resolving variables
across files to catch it automatically would fail *closed* on a real tool, so the blind spot is
named in the tool's own docstring instead.

**Open finding 2 — needs an Owner decision, explicitly NOT mine to make.**
Nine declared entries have an `entry` filename no scanned script names. Sharpest:
`tools.json` declares Detect It Easy as `die/die.exe`, while `scripts/intel-agent.ps1:20` and
`scripts/forensics-lab.ps1:140-147` both launch **`diec.exe`**. This is a manifest that is
confidently *wrong*, which is a different failure from one that is merely incomplete — the fix
needs someone to say which filename is canonical. Report stands; no entry was edited.
Also in that bucket: GH Injector, Reqable, ImHex, ReClass.NET, System Informer,
Universal Extractor, pyinstxtractor-ng, `forensics-lab payload` (`d12payload.c`).

**Open finding 3 — ONE bare-name tool that is neither declared nor OS-provided.**
`openssl` (`native-lab/tools/cert_verify.py:97`, `subprocess.run(["openssl", ...])`). Found
independently by both checkers from opposite directions.

**RETRACTED from this report:** I previously listed `rabin2` here as an undeclared bare-name
tool. That was wrong, and `CloneBootstrapProbe` measured it rather than argued it —
`hardening_probe.py:57` resolves it from `RABIN2_EXE` or a glob under the declared
`Static-Reversing/radare2` directory, and `:79-81` explicitly refuses a PATH lookup. It is
covered by the radare2 `dir`. Kept here as a retraction rather than deleted, because a
plausible-but-unverified claim is exactly what this project keeps paying for, and the next
window should be able to see that the claim was made, checked, and found false.

**Next command I would have run**, had the session not been paused — to close the one
`[UNVERIFIED]` in §13. `verify-clone-freshness.py` has an `if __name__ == "__main__":` guard at
line 707, so it is importable without side effects:

```python
import importlib.util, json, pathlib
spec = importlib.util.spec_from_file_location("vcf", "scripts/verify-clone-freshness.py")
vcf = importlib.util.module_from_spec(spec); spec.loader.exec_module(vcf)
mine = importlib.util.spec_from_file_location("vtm", "scripts/verify-tools-manifest.py")
vtm = importlib.util.module_from_spec(mine); mine.loader.exec_module(vtm)
caps = json.loads(pathlib.Path("manifests/capabilities.json").read_text(encoding="utf-8"))
# for every probe.command / probe.prepare / requires.tools[].probe:
#   toks = vcf.probe_targets(text)
#   for t in toks: print(t, "->", vtm.candidate_paths(t)[0], "E2?" , "\\\\" in t)
```
That records, per probe token, exactly which of my rules fire or cannot fire on their input,
turning §13's E1 row from inference into measurement.

**Deliberately not done, and why.** `scripts/verify-all.ps1` was never run (four siblings live,
`assert-probes` is ~15 min of real tools); the substitute basis is in §12. No manifest entry
was edited to silence a mismatch. No exclusion rule was relaxed to make a metric improve — the
one mutation that came back clean (E2, §8 control 3) is reported as a negative result rather
than quietly kept or quietly deleted.