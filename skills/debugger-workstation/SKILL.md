---
name: debugger-workstation
description: >-
  Reverse-engineering workstation (反编译, 逆向, decompile, unpack, Ghidra, IDA, x64dbg,
  JADX, Apktool, Il2CppDumper, AssetRipper, Frida, YARA, capa, FLOSS, PE, .NET, pcap,
  内存取证, memory forensics). Auto-apply when the user wants to reverse a binary, analyse a
  pcap or a memory image, unpack a game/APK/Unity IL2CPP, or the task is clearly RE — do
  not wait to be named. Carries the traps that make an otherwise-correct agent answer wrong:
  the PASS-line counting error, the IDA isError=false failure shape, the Start-Process
  stdin trap, and the per-tool-directory path rule. Client MCP is debugger-router only.
  Drive CLI tools via SmartCLI. Never dump 19 backends into user-global MCP.
---

# debugger-workstation

Root: `D:\Software\Tool\WorkStation\debugger`. All commands below run from there.

Read `../../../AGENTS.md` first, then the gitignored `../../../OWNER.md`. High-risk (Npcap,
drivers, Defender, running an untrusted sample on the host): brief the Owner, then follow
intent. Do not silent-install drivers, and do not run an untrusted sample on the host instead
of a VM.

<!-- PATH RULE. Markdown links below are written relative to THIS FILE, because that is the
     CWD a reader is in when it opens a skill. Only references/*.md resolve directly; anything
     else needs ../../../. An independent verifier caught exactly this: SKILL.md pointed at
     AGENTS.md and docs/EXPERT_PLAYBOOK.md station-root-relative while references/triage.md
     correctly used ../../../, so several links were dead from the only place the document is
     read. COMMANDS are the exception and stay station-root-relative -- they are run, not
     clicked, and the station root is the CWD for running them. Fix, do not repeat. -->

---

## 1. First move: is the station healthy?

```
powershell -File scripts\verify-all.ps1
```

23 steps, **both** trees (the station's gates and the wiki tree's own structure), prints its
own wall clock. **It does not strictly mean "everything passed":** a *skipped* proof forces
exit 0, and the script's own comment says "a skipped proof is not a passing proof". Read the
step list, not just the exit code. `[UNVERIFIED]` the 10:28 wall clock — that figure was never
written to `evidence/`, so it is chat, not memory (§9).

If you only want the labs exercised:

```
powershell -File scripts\smoke-all.ps1
```

**pass=19 fail=0**, measured twice on 2026-10-04 at **237 s** and **312 s** — budget 4–6
minutes, not 3. Two of those nineteen report *blocked* and still pass: that is the doctrine
working, not a gap.

---

## 2. The traps — read this before you quote any number

These are not style notes. Each one has already produced a wrong answer in this project, and
each cost real time. Full list: `<private-tree>\wiki\methods\arsenal-workflow-rules.md`.

### 2.1 Count the lab's own summary line, never the `PASS` lines

A check prints a verdict *and* its evidence, and some labs print a row per case inside one
check. Measured:

| lab | `PASS` lines printed | actual checks |
|---|---|---|
| forensics | 74 | **37** |
| crypto | 29 | **17** |
| managed | 46 | **27** |

Use the lab's own summary line — `JSON-SUMMARY`, or `CORPUS CLOSED` / `LANE CLOSED`. **The
exception is `forensics-lab`, which prints `LOOP CLOSED:` with no number and no
`JSON-SUMMARY` at all.** For that lab the only correct ruler is **the count of distinct check
names**: its 74 rows are 37 checks printed exactly twice.
**A bad ruler does not merely miss — it corrects correct numbers, and the correction looks
authoritative because it came from a script.**

### 2.2 IDA failures come back with `isError: false`

A bogus address answers:

```json
{"addr":"0xdeadbeef","code": null, "error": "Decompilation failed at 0xdeadbeef"}
```

**The envelope's `isError` flag is present, and its value is `false`.** (A *missing required
field* is different — that one does set `isError:true` from the schema layer.) A wrapper that
checks only `isError` therefore records **a failed decompile as a successful null** — the
"complete, confident, wrong" shape this whole station exists to reject. **Any wrapper must test
the `error` field and require a non-null `code`.** The native lab asserts this rather than
assuming it (`CONTROL: isError is FALSE on that failure`), and an independent verifier
reproduced it at the wire level with its own client.

### 2.3 `Start-Process` cannot redirect stdin

A tool blocked on its prompt and a tool that failed to launch look identical if you only check
"did it exit, and did the stdout file grow". That mistake invented a **fake blocker** which
then sat in the registry as a measured fact: `il2cpp-probe.ps1` reported the tool "could not
start for lack of .NET 6" when it starts fine with `DOTNET_ROLL_FORWARD` and simply waits for
a target.

**Use `System.Diagnostics.ProcessStartInfo` with `RedirectStandardInput = $true` when you need
to know whether something started.** And check what your measurement could not see before
believing a blocker.

### 2.4 `tools.json` paths need the per-tool directory

Every `entry` in `manifests/tools.json` is relative to that tool's own **`dir` field, which the
schema does record**. `capa` declares `entry: "capa.exe"` and `dir: "Static-Reversing/capa"`;
the file is at `Static-Reversing\capa\capa.exe`.

Measured: **0 of 54 `entry` values resolve from the repo root; 52 of 54 resolve via `dir`**.
The other two are inside `node_modules/` and `.venv/` — installed dependencies a fresh
checkout does not have, which is not a broken pin. `verify-tools-manifest.py` now checks this
and reports each unresolvable pin.

`capa` is also the reason not to trust `install_root_default` (`D:\Tool\debugger`), which does
not exist on this machine.
Two more traps in the same family:

- **Basename search across the whole tree is not safe.** Basenames collide across labs —
  `crypto-lab/loop.mjs` matches `web-reverse/tools/loop.mjs`. Searching by name alone reported
  "54 of 54 found" and was wrong about six of them.
- **A shell glob over a directory that holds two versions reads the first.** That produced
  "Ghidra 12.1.3 declared, 12.1.2 on disk" — **both exist**, so the wiki was right and the
  glob was wrong.

⇒ The pin table in `references\arsenal.md`: **29 of 30 pin paths resolve as written.** One does
not — `ghidraRun.bat` is a bare basename matching **two** files (`ghidra_12.1.2_PUBLIC\` and
`ghidra_12.1.3_PUBLIC\`), which is the basename-collision trap below, sitting inside the file the
trap warns about. Use the pins, not `tools.json`, and pin that one to its version directory.

---

## 3. Verified commands — I hold one of these, what do I run?

Every command below was run on this machine and its output read. Full guide with the rest of
the situations: `<private-tree>\wiki\methods\arsenal-how-to-use.md`.

| I hold | run this | you get |
|---|---|---|
| a Windows PE | `powershell -File headless-lab\tools\triage-packer.ps1 -Target FILE.exe` | `packed` verdict **derived from DiE's own verdict** |
| a PE, want behaviour | `python native-lab\tools\capa_probe.py FILE.exe` | capa features as JSON |
| a PE, want mitigations | `python native-lab\tools\hardening_probe.py FILE.exe` | per-flag mitigations: `nx`, `pic`, `relocs`, `crypto`, … — **there is no `CFG` key**; do not report one |
| a PE, want the real C | `node native-lab/tools/loop.mjs --only=decompile` | **15/15** incl. 5 failure-shape controls (`NEGATIVE:` ×4 + `CONTROL:` ×1) |
| a PE, want functions | `node native-lab/tools/loop.mjs --only=list_funcs` | **6/6** |
| a .NET assembly | `node managed-lab/tools/loop.mjs` | **27/27** |
| an APK | `node mobile-lab/tools/loop.mjs` | builds a real APK from source and cross-checks it |
| a pcap | `node net-reverse/tools/loop.mjs` | `LANE CLOSED` + `ISOLATION HELD` — **read the isolation line every run** |
| a memory image / dump | `node forensics-lab/tools/loop.mjs` | planted injection found; 4 negative controls |
| a .NET assembly, obfuscated | `ilspycmd FILE.exe`, or `powershell -File scripts\dnspy-console.ps1` | dnSpy/ILSpy. **`de4dot` is NOT installed here** (exit 127) — do not tell an agent to run it |
| training on your own binary | `python crackme-corpus/tools/loop.py` | `CORPUS CLOSED`, 20 checks, 5 negative controls |

**Start with the cheapest recognition pass.** It decides whether the rest is worth running.

---

## 4. What is actually available — check before you promise

```
python scripts\assert-probes.py --list
```

Prints a `SKIP` with a reason for each. That reason is a claim about the world, not about the
script — verify it before you relay it (§2.3 is what happens when you don't).

**23 of 27 are `state: observed`. That is NOT the same as "falsifiable".** Only **11 of 27**
declare `probe.produces` — a path-bound artifact whose bytes must land on disk during the run.
The rest are verified by **string matching**, and `assert-probes.py` says so itself on every OK:
*"this entry declares no probe.produces, so this checker matched STRINGS only, and a stub which
prints them satisfies it."*

**So do not tell anyone 23 capabilities are cryptographically bound.** Say: 23 observed,
**11 artifact-bound**. The gap is the honest measure of what a stub could still fake here.
Closing it is mechanical — `scripts/probe_artifact.py` does it in one call per probe — and it is
the next thing to close.

The four that are genuinely unavailable — saying so is the correct answer:

| capability | state | why |
|---|---|---|
| `dynamic.device.frida` | absent | no Android device attached |
| `native.il2cpp.symbols` | absent | **no authorized IL2CPP artifact** — see §6 |
| `native.ghidra.emulate` | blocked | the Ghidra emulator API; successor identified, buildable |
| `native.crosscompare.ghidra` | planned | no runnable command yet |

**Not in the registry at all**, so do not plan around them: kernel/driver RE, symbolic
execution, DAP (debug adapter protocol). All three are in
`<private-tree>\wiki\methods\arsenal-skill-index.md`, but **not all in §3E–§3F** —
kernel/driver is §3E and memory forensics §3F, while symbolic execution is entries #8 and #15
and DAP is entry #7, both in §2.

---

## 5. Fire

| Job | Read |
|---|---|
| Unknown sample | `references\triage.md` |
| Need a binary path | [references/arsenal.md](references/arsenal.md) — 30 pins, **29 resolve as written** |
| MCP tool call | `references\mcp-router.md` |
| Agent CLI (no GUI) | `references\agent-cli.md` |
| Deep combo | [../../docs/EXPERT_PLAYBOOK.md](../../docs/EXPERT_PLAYBOOK.md) |
| Knowledge: techniques, tools, papers | `<private-tree>\wiki\methods\arsenal-skill-index.md` — **155 entries, 194 URLs**, each with what it solves and an adopt verdict |
| Knowledge: the web research behind it | `<private-tree>\wiki\methods\arsenal-research-dossier.md` |

---

## 6. The authorization line — not negotiable, and it is currently load-bearing

`il2cpp-probe.ps1` prints this every run and it is right:

> `global-metadata.dat` files DO exist here, in third-party commercial software (the VIVE Hub
> installer). They are deliberately NOT used: the arsenal gate requires an Owner-named object
> with checkable provenance, and an installed third-party binary is not that.

**"It was on the disk" is not authorization.** If a capability needs a target you do not have,
the unblock is a sentence from the Owner naming one — not a technique. Same for anything on a
HackerOne submission button, anything that installs a driver, and any untrusted sample.

---

## 7. Lazy MCP (required)

This station ships **one** client MCP: `debugger-router`. It starts a backend, runs the tool,
exits.

- Catalog (not for the client): `MCP\.mcp.json`
- Client attach file: `D:\Software\Tool\WorkStation\mcp-clients\debugger-router.json`
- **Never** merge the 19 backends into `~\.cursor\mcp.json` / Claude user MCP / Codex user
  toml / Grok toml.
- IDA **idalib** is already on all four runtimes. Do not add a **second** IDA MCP. Router `ida`
  is `idalib-mcp --stdio`, not GUI `:13337`.
- Agent CLI first (no GUI stall): `scripts\agent-cli.ps1`, table in `references\agent-cli.md`.
- **`mcp-virustotal` reaches the public internet.** It posts hashes and IOCs to a third party.
  An RE agent already holds untrusted content and private data at once, which is this project's
  own named "lethal trifecta". Confirm the call site is opt-in before using it.

## 8. IDA on this PC

`Static-Reversing\IDA` → `D:\Software\Tool\Debugger\IDA Professional 9.2`. Do not download IDA.
Agent default is `idalib` or `idat -A`, **not** the GUI on 13337.

## 9. After a job

1. **Finish on disk before reporting status.** A result that exists only in your reply was
   never delivered — that is how eight worker reports went missing and 232 citations across the
   estate became un-re-runnable.
2. Run `debugger-review`. Dual-axis score, then `notes/` / `Reports/`. **Chat is not memory.**
3. Save evidence so the next window can check it rather than believe it:
   `python scripts\assert-probes.py <id> --save-evidence evidence/probes`