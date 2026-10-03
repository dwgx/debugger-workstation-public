#!/usr/bin/env python
"""Re-run each capability's recorded probe and control, and check the recorded strings.

WHY THIS EXISTS. The registry's honesty was, until now, checked by whoever remembered to
check it. A recorded `probe.expect` is a CLAIM about what a tool prints, and nothing static
can test it -- R2 can tell a command is runnable and can never tell that its output still
matches the string beside it. Independent verification on 2026-10-02 found exactly this:

  native.pe.packer    probe.expect read '"packed": false' with a space. The tool emits
                      PowerShell's compact ConvertTo-Json, '"packed":false'. A literal
                      substring check FAILS on a perfectly healthy probe.
  native.function.match  expect read '"match_rate": 37.6'; the tool emits '"match_rate":37.6'.
                      The SAME defect, in a second entry, which is what makes it a class.
  native.pe.authenticode  its control was three statements joined by ';'. That separates
                      commands in PowerShell and is an ARGUMENT DELIMITER in cmd.exe, so run
                      verbatim under cmd it reached authenticode.py as one invocation and died
                      with "unrecognized arguments: python -c import sys;d=open(...)". Under
                      PowerShell it produces exactly what was always claimed -- so the string
                      was never false, it was simply in a shell that could not run it.
  native.pe.container  control.measured said "the wrapper prints REFUSED and exits 2" while
                      quoting the BARE pefile command, which exits 1 and prints a traceback.
                      grep -c REFUSED native-lab/tools/pe_probe.py returns 0.

None of those is visible to a static rule, and all four survived a registry that reported
REGISTRY CLEAN. They were found only because somebody ran the strings.

    python scripts/assert-probes.py                 # every capability whose probe is safe here
    python scripts/assert-probes.py native.pe.packer native.pe.container

    python scripts/assert-probes.py --require-produces   # sweep mode: every entry that runs
                                                          # must name the bytes its probe leaves

WHAT probe.produces IS, AND WHY IT HAD TO BE ADDED. Everything below compares STRINGS, and a
two-line stub that prints the recorded `probe.expect` and exits 0 satisfies every comparison
this script makes -- which is exactly what the OK verdict used to admit in its own last
sentence. No better string fixes that; a stub can be handed any string. The fix is a check that
does not read the output at all: a check on the FILE SYSTEM. `probe.produces` names a path or
glob the probe RUN must leave behind -- repo-relative or absolute, `%VAR%` and `$env:VAR`
expanded, `**` honoured. After the run the pattern is resolved:

  matches nothing                       -> DRIFT, naming the glob and the command
  matches, but every file BYTE-IDENTICAL before and after this run -> DRIFT
  matches and at least one file CHANGED during this run -> every matched file's sha256 goes
                                                    into the evidence log beside the command, so
                                                    the artifact is hashable by the next window

Freshness is what makes this a check rather than a formality, and it is measured in BYTES, not
seconds. The checker hashes every declared path before launching the probe and again after, and
counts a file as produced only if its size, mtime or content changed. Existence alone would be
worthless: one honest green run leaves a file behind and every stub run afterwards inherits it.
A time window was implemented first and MEASURED WRONG -- with 4 seconds of slack, the real
capability's own artifact, written 0.4 s earlier in the same sweep, satisfied the stub's check and
both capabilities came back OK. Comparing identities has no window to tune and no race to lose.

An entry that declares nothing is UNAFFECTED, so the default sweep stays backward compatible and
such an entry simply receives the weaker OK verdict, which says in its own words that only
strings were matched. `--require-produces` makes the declaration itself the requirement for every
entry that runs, which is how a NEW entry is held to the stronger standard without retro-fitting
every old one in the same commit.

WHAT IS STILL NOT PROVEN WHEN PRODUCES PASSES. That a file appeared and that its bytes changed
during this run. NOT that the bytes are correct, NOT that the number inside them is right, and
NOT that the instrument a caller reaches in anger is the one that ran here. An instrument that
writes the right bytes for the wrong reason would still pass, and a hash buys tamper-evidence
after the fact, not correctness at the moment of writing.

    python scripts/assert-probes.py --list          # ids only, run nothing

WHAT IT DELIBERATELY DOES NOT DO. It does not fix anything, and it does not rewrite a string
that no longer matches: a probe whose output legitimately changed has two possible causes --
the instrument regressed, or the claim was never true -- and those have OPPOSITE fixes, so the
tool reports and leaves it to a human. It does not run smoke-all.ps1, any lab loop, or any
fuzz run; those are parent-owned.

THE VERDICT THAT MATTERS MOST: TOOL-FAULT. This script's own first run reported 21 DRIFT out
of 24, and nearly all were its own fault -- the registry's commands are PowerShell and were
being handed to cmd.exe, which dies in 0.0 s with exit 255. A shell failure is not evidence
about the registry, so a command that dies fast with no output is named as THIS SCRIPT's
fault and never counted as DRIFT. A broken harness is not a finding, the same way an error is
not a zero.
"""
from __future__ import annotations

import argparse
import glob as globmod
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"

# Never run here: long, parent-owned, or prose only an MCP session can execute. Always shown.
SKIP = {
    "native.ida.decompile": "driven through the idalib-mcp MCP device, not a CLI command",
    "native.ida.list_functions": "driven through the idalib-mcp MCP device, not a CLI command",
    "native.crosscompare.ghidra": "state=planned; no runnable command exists to check",
    "native.ghidra.emulate": "state=blocked; needs a runtime the registry does not have",
    "dynamic.device.frida": "state=absent; needs an attached device",
    "native.il2cpp.symbols": "state=absent; needs an extracted IL2CPP metadata dump",
}

FAULT_MARKERS = ("is not recognized", "not recognized as an", "the term",
                 "commandnotfound", "is not installed", "no such file", "parsererror",
                 "stringnotexpanded", "was unexpected at this time", "syntaxerror")

TOOL_FAULT_SECS = 0.5
TIMEOUT_RC = -1          # what run() returns when subprocess.TimeoutExpired fires

# `--save-evidence DIR` writes what each probe ACTUALLY printed, per capability, so a run can be
# retained on disk instead of remembered. Added 2026-10-03 for a measured reason: every one of
# the eleven `probe.run_log` values in the registry turned out to be PROSE ("measured 2026-10-02
# in this session, ..."), and R17 accepted any non-empty string as proof that `state: observed`
# is bound to a run -- which is the field gate.ps1 filters on when it decides what a grant may
# contain. A retained file is the smallest thing that makes that binding real.
EVIDENCE_DIR: "pathlib.Path | None" = None

# `--require-produces` makes the sweep DEMAND `probe.produces` from every entry that runs. It is
# the whole-sweep form of the same check: a capability that declares nothing has told this
# script which strings to look for and nothing about which bytes it must leave, so with the flag
# on, silence about produces is itself the finding. Off by default, because turning it on against
# today's registry would report 21 DRIFT for a missing annotation rather than for a broken claim.
REQUIRE_PRODUCES = False

# Freshness is decided by IDENTITY, not by a clock. The checker records (size, mtime_ns, sha256)
# for every matched file BEFORE launching the probe and compares after it returns; a file counts
# as produced only if one of those three changed. A time window was tried first and measured
# wrong: with a 4-second slack the real capability's own artifact -- written 0.4 s earlier in the
# same sweep -- satisfied the STUB's check, and both capabilities came back OK. Two green
# verdicts from one real run and one stub is precisely the defect this file exists to close, so
# the window had to go rather than be narrowed. A hash is more expensive than an mtime and buys
# the thing that matters: a file rewritten with identical bytes is still not a fresh observation
# of an instrument, while a file rewritten with different bytes is, whatever the clock says.


def save_evidence(cid: str, kind: str, cmd: str, rc: int, secs: float, blob: str,
                 artifacts: "list[tuple[Path, bool]] | None" = None) -> None:
    """Write one run's output verbatim, with enough header to re-run it.

    `artifacts` are the (path, written-by-this-run) pairs the produces check resolved. They are
    hashed HERE, in the evidence log, next to the command that made them -- so the log is a
    complete record on its own: what ran, what it printed, and what bytes it left behind with
    their sha256. A log that names a command and its stdout but not its artifact still cannot be
    re-verified by a later window, which is the entire point of retaining it.
    """
    if EVIDENCE_DIR is None:
        return
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    head = (f"# assert-probes evidence: {cid} {kind}\n"
            f"# command: {cmd}\n"
            f"# exit: {rc}\n"
            f"# seconds: {secs:.2f}\n"
            f"# captured by: python scripts/assert-probes.py --save-evidence <dir>\n"
            f"# re-run the command above; this file is OUTPUT, not a claim about it.\n")
    for path, fresh in (artifacts or []):
        try:
            digest = sha256_of(path)
        except OSError as e:
            head += f"# produces: {path} UNREADABLE ({e})\n"
            continue
        head += (f"# produces: {path}\n"
                 f"#   sha256: {digest}\n"
                 f"#   bytes: {path.stat().st_size}\n"
                 f"#   written-by-this-run: {'yes' if fresh else 'NO -- pre-existing'}\n")
    head += f"{'-' * 72}\n"
    (EVIDENCE_DIR / f"{cid}.{kind}.log").write_text(head + blob, encoding="utf-8")


def sha256_of(path: Path) -> str:
    """Hash a file in chunks. A probe artifact can be hundreds of MB and must not be slurped."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def expand_produces(pat: str) -> str:
    """Resolve one `probe.produces` value to a glob this machine can actually match.

    A registry that names `%TEMP%\\signed-fixture.exe` is naming a real place, not a template --
    the commands beside it already use `$env:TEMP`, so the same spelling has to work here or the
    declaration is unmatchable on the only platform it was written for.
    """
    p = os.path.expandvars(pat.strip().strip('"'))
    p = re.sub(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}",
               lambda m: os.environ.get(m.group(1), m.group(0)), p)
    p = re.sub(r"\$env:([A-Za-z_][A-Za-z0-9_]*)",
               lambda m: os.environ.get(m.group(1), m.group(0)), p)
    return p


def produces_specs(probe: dict) -> list[str]:
    """`probe.produces` as a list, whether the registry wrote one string or several."""
    spec = probe.get("produces")
    if spec is None:
        return []
    return [str(s) for s in ([spec] if isinstance(spec, str) else spec) if str(s).strip()]


def resolve_produces(spec: str) -> list[Path]:
    """Every existing file the `probe.produces` glob names, repo-relative or absolute.

    Directories are excluded on purpose: a glob like `fuzz-lab/out/**` matching the directory
    `fuzz-lab/out` itself is not evidence that anything was produced inside it, and a checker that
    counted it would pass on an empty output directory.
    """
    pat = expand_produces(spec)
    # A bare path with no magic must not be globbed away: glob() returns [] for a literal
    # path that does not exist, which is the answer we want, but it also returns [] for one that
    # does -- so the literal branch is only about reporting a clearer "no such file" downstream.
    if not globmod.has_magic(pat):
        cand = Path(pat)
        if not cand.is_absolute():
            cand = REPO / cand
        return [cand] if cand.is_file() else []
    base = pat if Path(pat).is_absolute() else str(REPO / pat)
    # recursive=True is what makes `**` cross directory levels; without it `**` behaves as `*`.
    hits = [Path(m) for m in globmod.glob(base, recursive=True)]
    return sorted({p for p in hits if p.is_file()})


def snapshot_produces(specs: list[str]) -> dict[Path, tuple[int, int, str]]:
    """The identity of every file `specs` names RIGHT NOW: (size, mtime_ns, sha256).

    Taken before the probe is launched so the comparison afterwards can distinguish "this run wrote
    it" from "it was already there", which is the entire difference between an instrument and a
    stub that prints the recorded strings.
    """
    snap: dict[Path, tuple[int, int, str]] = {}
    for spec in specs:
        for p in resolve_produces(spec):
            if p in snap:
                continue
            try:
                st = p.stat()
                snap[p] = (st.st_size, st.st_mtime_ns, sha256_of(p))
            except OSError:
                continue
    return snap


def check_produces(cid: str, specs: list[str], cmd: str,
                   before: dict[Path, tuple[int, int, str]]
                   ) -> tuple[str, list[tuple[str, str]], dict[Path, tuple[int, int, str]]]:
    """Did this run leave the bytes it declared? Returns (state, verdicts-to-add, after-map).

    `state` is "unclaimed" (the entry declares nothing), "fresh" (at least one declared file's
    identity CHANGED across the run) or "stale" (the paths exist but none of them was touched).
    The fresh/stale split is the whole mechanism: a stub printing the recorded strings satisfies
    every comparison in check() and still leaves the filesystem exactly as it found it, so
    "stale" is the verdict that finally separates an instrument from a two-line `echo`.

    The after-map comes back so the caller can write the evidence log from it instead of hashing
    the same artifact a third time. A probe artifact can be hundreds of megabytes; reading it
    three times to answer one question is a cost the mechanism does not need to pay.
    """
    if not specs:
        return "unclaimed", [], {}
    after = snapshot_produces(specs)

    out: list[tuple[str, str]] = []
    fresh: list[Path] = []
    stale: list[Path] = []
    for one in specs:
        hits = resolve_produces(one)
        if not hits:
            out.append(("DRIFT",
                        f"{cid} PRODUCES: {one!r} matched NO FILE after the run, so the command "
                        f"above either never ran or ran without writing what it declared. This "
                        f"is the check a string matcher cannot do: a stub which prints the "
                        f"recorded expect strings passes every comparison above and still leaves "
                        f"the filesystem untouched, because nothing that only reads stdout can "
                        f"account for bytes. Check the glob against the instrument's real output "
                        f"path. :: {cmd[:60]}"))
            continue
        for p in hits:
            (fresh if before.get(p) != after.get(p) else stale).append(p)
    if not out and fresh and not stale:
        return "fresh", [], after
    if not out and fresh:
        # A mixed result is still a finding: something was written, but part of the declaration
        # was already on disk, so the glob is too wide to be evidence of this run alone.
        names = ", ".join(str(p) for p in stale[:4])
        out.append(("DRIFT",
                    f"{cid} PRODUCES: {len(fresh)} of the declared file(s) changed during this "
                    f"run, but {len(stale)} were byte-identical before and after: {names}. Either "
                    f"the glob is too wide or the instrument stopped producing part of what it "
                    f"declares."))
        return "fresh", out, after
    if not out and stale:
        names = ", ".join(str(p) for p in stale[:4])
        out.append(("DRIFT",
                    f"{cid} PRODUCES: {specs!r} matched {len(stale)} existing file(s) -- "
                    f"{names} -- and every one of them is BYTE-IDENTICAL before and after this "
                    f"run. This is the verdict a string matcher cannot reach: a stub which prints "
                    f"the recorded expect strings satisfies every comparison above and leaves the "
                    f"filesystem exactly as it found it, so the path existing proves nothing. "
                    f"Compare the bytes, not the presence."))
        return "stale", out, after
    return ("fresh" if fresh else "stale"), out, after


def load() -> list[dict]:
    return json.load(open(REG, encoding="utf-8"))["capabilities"]


def run(cmd: str, timeout: int, env: dict | None = None) -> tuple[int, str, float]:
    """Execute `cmd` byte-for-byte, with no re-quoting of any kind.

    The command goes into a .ps1 file which PowerShell runs with -File. Two earlier designs
    were wrong: sniffing for PowerShell markers and wrapping in `powershell -Command "..."`
    missed 8 commands AND destroyed every command containing a double quote. Re-quoting a
    command you did not write is how a harness quietly breaks a probe and then reports the
    breakage as the registry's. The only arrangement in which 'verbatim' is true is no
    transformation at all.

    stderr is merged into stdout on purpose: a tool may decorate stderr and write its contract
    on stdout, and the recorded expect strings were written against combined output. This is
    the OPPOSITE of mission.ps1, which separates the two because a capability under a mission
    must not corrupt its JSON. Two contracts, two behaviours.
    """
    # The RUNTIME half of R26. R26 refuses an unquoted brace at validation time; this refuses one
    # at execution time, because the failure is SILENT rather than loud: measured 2026-10-03, a
    # probe carrying `FLAG{abc}` unquoted produces stderr EMPTY and exit 0, with PowerShell handing
    # the child `-encodedCommand <base64 of a mangled token>`. Unless a recorded expect string
    # happens to contain that mangled token, nothing looks wrong and the sweep reports OK. rc 127
    # is distinct on purpose, so tool_fault() names it as TOOL-FAULT instead of DRIFT -- blaming
    # the registry for a command the shell rewrote is the third instance of that mistake today.
    _brace = UNQUOTED_BRACE.search(cmd)
    if _brace:
        return 127, (f"<refused before running: unquoted brace {_brace.group(0)} in argument "
                     f"position. PowerShell reads it as the start of a script block, re-enters "
                     f"itself, and hands the child -encodedCommand <base64 of a mangled token> "
                     f"instead of the recorded value -- measured with stderr empty and exit 0, so "
                     f"the damage is invisible unless you know to look for it.>"), 0.0
    script = REPO / "_assert_probe_cmd.ps1"
    t0 = time.time()
    try:
        # The wrapper MUST propagate the exit code. `powershell -File` returns 0 unless the
        # script says `exit`, so without this line assert-probes reports EVERY control as
        # exiting 0 and every refusal looks like a pass. That is not hypothetical: it is what
        # this script did on its previous run, and it is the same defect it was written to
        # find. The failure mode of a checking tool is to check nothing and look green.
        script.write_text(cmd + "\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
        merged = dict(os.environ)
        merged.update(env or {})
        p = subprocess.run(
            f'powershell -NoProfile -ExecutionPolicy Bypass -File "{script}"',
            shell=True, cwd=REPO, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace", env=merged)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return -1, f"<timeout after {timeout}s>", time.time() - t0
    except Exception as e:  # noqa: BLE001 - a broken shell is a finding, not a crash
        return -2, f"<could not run: {e}>", time.time() - t0
    finally:
        try:
            script.unlink()
        except OSError:
            pass


def tool_fault(rc: int, blob: str, secs: float) -> str | None:
    """Did this command fail to RUN, rather than run and fail? Never report that as DRIFT."""
    # A TIMEOUT is this script's budget, not the registry's claim. fuzz-lab's loop needs ~634 s
    # and was being cut off at 180 s, so its closing marker "LOOP CLOSED" was never captured and
    # the missing string was reported as DRIFT -- naming the registry for this tool's impatience.
    # That is the third time this script has blamed the registry for its own limit, which is
    # enough to make it a named verdict rather than an occasional correction.
    if rc == TIMEOUT_RC:
        return (f"timed out after {secs:.0f}s, so no output was captured and NOTHING can be "
                f"concluded about the expect string. THIS TOOL'S LIMIT: rerun with a larger "
                f"--timeout. A truncated run is not evidence.")
    # THE MARKER DECIDES, NOT THE EXIT CODE. Measured 2026-10-03 by a sibling's harness: PowerShell
    # leaves `$LASTEXITCODE` UNSET when a command is not found, so the `exit $LASTEXITCODE` wrapper
    # propagates 0 -- and this function short-circuited on `rc == 0` BEFORE scanning the markers.
    # "is not recognized" was in FAULT_MARKERS the whole time, unreachable on that path, so a probe
    # naming a binary that does not exist came back as a clean pass.
    #
    # The control that proves the other half is still reachable: a quoted exe with no call operator
    # gives rc=1 in ~0.27 s with a ParserError, under TOOL_FAULT_SECS, so the marker branch fires.
    if secs >= TOOL_FAULT_SECS:
        return None
    low = blob.lower()
    hit = next((m for m in FAULT_MARKERS if m in low), None)
    if hit:
        return (f"never ran: the shell rejected it ({hit!r}) after {secs:.2f}s, exit {rc}. "
                f"THIS TOOL'S FAULT -- the registry is not implicated.")
    if not blob.strip():
        return (f"never ran: no output at all after {secs:.2f}s, exit {rc}. THIS TOOL'S "
                f"FAULT, most likely the shell -- the registry is not implicated.")
    return None


UNQUOTED_BRACE = re.compile(r"\{[A-Za-z0-9_.:]+\}")


def prose(cmd: str) -> bool:
    head = cmd.strip().split()[0] if cmd.strip() else ""
    return head in {"see", "list_funcs", "run", "use", "the"} or not cmd.strip()


def _missing_paths(cmd: str) -> list[str]:
    """Path-looking tokens in a command that do not exist, repo-relative to the runner's cwd.

    Deliberately conservative: a token qualifies only if it carries a path separator or a known
    file extension, and only if NOTHING matching it exists. A bare word like `any` is not a path,
    and a glob is not required to resolve. Returning an empty list means "no evidence", and the
    caller then says nothing -- silence is the correct answer when the evidence is thin.
    """
    # An environment-referenced path is removed WHOLE before anything is scanned, not filtered after
    # the fact: the token class has no `$` and no `%`, so `$env:TEMP\x.exe` was captured as
    # `env:TEMP\x.exe` and `%TEMP%\x.exe` as `\x.exe`, and a file the shell would have expanded was
    # reported MISSING. Measured on net.pcap.selfparse and native.signature.certverify, both of
    # which name their fixture through the environment.
    cmd = re.sub(r"(?i)(?:%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\})"
                 r"[\\/][^\s'\"]+", "ENVVAR_PATH", cmd)
    cands: list[str] = []
    for tok in re.findall(r"[A-Za-z0-9_.:\\/\\-]+\.(?:exe|py|js|mjs|ps1|json|pcap|apk|md|txt|log|raw)\b", cmd):
        t = tok.strip("'\"")
        # MUST carry a path separator. Measured 2026-10-03 against the real registry: requiring only
        # a file extension matched `console.log` five times inside the frida JavaScript payload and
        # a bare `dns-txt.pcap` fragment, so a healthy probe would have been reported as missing its
        # prerequisite. A bare filename tells us nothing about where the runner would look, so the
        # honest answer is silence.
        if "/" not in t and "\\" not in t:
            continue
        if "$" in t or "%" in t:
            continue
        if t.upper().startswith("ENVVAR_PATH"):
            continue
        cands.append(t)
    if not cands:
        return []
    missing = []
    for t in cands:
        p = Path(t)
        if "*" in t or "?" in t:
            ok = bool(list(REPO.glob(t)))          # a glob may legitimately match
        elif p.is_absolute():
            ok = p.exists()
        else:
            ok = (REPO / t).exists()
        # A drive letter is part of the path. The first version's character class excluded `:`, so
        # `D:/.../python.exe` was captured as `/.../python.exe`, found to be neither absolute nor
        # repo-relative, and reported MISSING on a probe that had just run successfully -- caught
        # by a sibling's harness on its first plant, which is the right way to find this.
        if re.match(r"^[A-Za-z]:", t) or t.startswith(("\\\\", "//")):
            ok = Path(t).exists()
            # The first version also accepted the token if ANY sibling existed in the same
            # directory, which made every missing file "present" on a machine that had built its
            # corpus once -- i.e. it reported missing exactly when it was missing, which is the
            # opposite of useful. Measured: a planted NOT-BUILT-ANYWHERE.exe came back as DRIFT,
            # not PREREQ, because c01-stringobf.exe sat next to it.
        if not ok:
            missing.append(t)
    return missing


def check(cap: dict, timeout: int) -> list[tuple[str, str]]:
    cid = cap["id"]
    if cid in SKIP:
        return [("SKIP", f"{cid}: {SKIP[cid]}")]

    out: list[tuple[str, str]] = []
    probe = cap.get("probe") or {}
    cmd = (probe.get("command") or "").strip()
    if not cmd or prose(cmd):
        return [("SKIP", f"{cid}: probe.command is not executable ({cmd[:50]!r})")]

    # `probe.prepare` NOW RUNS, on the evidence of 2026-10-03: eleven entries declared it and
    # NOTHING read it. The clearest case is net.pcap.selfparse, whose probe reads a capture its
    # own prepare command generates -- so on a clean machine the probe cannot run at all, and
    # the recorded run could only have happened after something else made the file appear. A
    # declared dependency nobody executes is the same defect as a declared expectation nobody
    # checks. A prepare that fails is a TOOL-FAULT, not a DRIFT: the probe never got its input.
    prep = str(probe.get("prepare") or "").strip()
    if prep:
        prc, pblob, psecs = run(prep, timeout, (probe.get("env") or None))
        if prc != 0:
            out.append(("TOOL-FAULT", f"{cid} PREPARE failed (exit {prc}) after {psecs:.1f}s :: "
                                       f"{prep[:60]} :: {(pblob or '').strip()[:120]}"))
    # probe.env exists because crypto.jose.parse needs CRYPTO_LAB_PORT: its lab's default
    # port 8791 is held by ANOTHER of the Owner's projects, so without this the checker
    # reports a DRIFT on every run for a reason that is not the registry's. A checker that
    # cries wolf gets switched off, so teaching it to set the variable is the fix.
    # Snapshot the declared artifacts BEFORE launching the probe. What the probe writes is then
    # whatever differs between these two maps, which is a question about bytes rather than about
    # the clock -- see the note above on freshness for why the clock version was measured wrong.
    specs = produces_specs(probe)
    before = snapshot_produces(specs)
    rc, blob, secs = run(cmd, timeout, (probe.get("env") or None))
    pstate, pverdicts, after = check_produces(cid, specs, cmd, before)
    artifacts = [(p, before.get(p) != after.get(p)) for p in sorted(after)]
    save_evidence(cid, "probe", cmd, rc, secs, blob, artifacts)
    fault = tool_fault(rc, blob, secs)
    if fault:
        out.append(("TOOL-FAULT", f"{cid} PROBE {fault} :: {cmd[:60]}"))
    else:
        # The produces verdicts land BEFORE the string ones on purpose. The strings are exactly
        # what a stub can fake, so when both fail the reader meets the filesystem evidence first
        # and forms the more serious hypothesis first.
        out.extend(pverdicts)
        want_exit = probe.get("expect_exit")
        if want_exit is not None and rc != want_exit:
            out.append(("DRIFT", f"{cid} PROBE exit: recorded expect_exit={want_exit}, real={rc} "
                                  f"after {secs:.1f}s :: {cmd[:60]}"))
        want = probe.get("expect")
        if want and want not in blob:
            # PREREQ-MISSING, tried before DRIFT and only on the combination that is almost
            # never anything else. Measured 2026-10-03 by an audit of re-runnability: in a fresh
            # clone `crackme-corpus/out/` is EMPTY -- it is gitignored by design and nothing in the
            # repository builds it -- so 11 of the 21 bound proofs read a file that does not exist.
            # Every one of those reported `expect is not a substring of the real output`, which
            # reads as "the instrument regressed" and invites the exact wrong repair: editing the
            # recorded expect string. `.agent/HANDOFF.md` records that repair being made before.
            #
            # The three conditions together are what keep this from crying wolf:
            #   (1) the command names at least one path-looking token,
            #   (2) NONE of those tokens exists on disk, and
            #   (3) the recorded expect is absent from the output.
            # One alone is common; all three mean the run had nothing to read.
            missing = _missing_paths(cmd)
            if missing:
                out.append(("PREREQ", f"{cid} PROBE: nothing to read. The command names "
                                       f"{len(missing)} path(s) and none exists: "
                                       f"{missing[:3]}. This is a MISSING PREREQUISITE, not a "
                                       f"regression -- build or install what the path names, then "
                                       f"re-run. Do NOT edit probe.expect in response to this; a "
                                       f"string that was true stays true."))
                want = None
        if want and want not in blob:
            near = ""
            for pat in (r'"packed"\s*:\s*\S+', r'"match_rate"\s*:\s*\S+', r'verdict=\S+',
                        r'width=\S+'):
                m = re.search(pat, blob)
                if m:
                    near = f" (output has {m.group(0)!r})"
                    break
            out.append(("DRIFT", f"{cid} PROBE expect: {want!r} is not a substring of the real "
                                  f"output{near}. Either the instrument regressed or the string "
                                  f"was never true; those have opposite fixes, so read it."))

    # An isolation_check is not a negative control: it asserts the MACHINE is uncontaminated and
    # its success is exit 0. Checking it under control polarity would record a clean station as a
    # broken capability, which is the exact inversion that got it misfiled in the first place.
    iso = cap.get("negative_control", {}).get("isolation_check")
    if isinstance(iso, dict) and (iso.get("command") or "").strip():
        irc, iblob, _ = run(iso["command"].strip(), timeout)
        if irc != iso.get("expect_exit", 0):
            out.append(("DRIFT", f"{cid} ISOLATION exit: expected "
                                  f"{iso.get('expect_exit')}, real={irc}. The station may be "
                                  f"contaminated; treat this as an emergency, not a finding."))
        want_i = iso.get("expect_output")
        if want_i and want_i not in iblob:
            out.append(("DRIFT", f"{cid} ISOLATION output: {want_i!r} absent"))

    nc = cap.get("negative_control") or {}
    ccmd = (nc.get("command") or "").strip()
    if not ccmd or prose(ccmd):
        # NOT a bare `return out`. This early exit meant a capability whose negative control is a
        # plan -- an empty command -- produced NO verdict at all, so the run printed
        # "1 checked, ." with the SKIP as its only line. That is the same "checked nothing and
        # looked fine" shape the floor exists to prevent, wearing a SKIP instead of a dot.
        # Found by fuzz.differential.parse, the one entry with an empty negative_control.command.
        probe_said_something = bool(out)
        out.append(("SKIP", f"{cid} CONTROL: not executable ({ccmd[:50]!r})"))
        if not probe_said_something:
            out.append(("OK", f"{cid}: every comparison this entry declares matched, and it "
                              f"declares no EXECUTABLE negative control, so nothing about its "
                              f"control was compared at all -- the SKIP above is the whole of it. "
                              f"PROVEN: the probe's own comparisons held. NOT PROVEN: that the "
                              f"instrument ran, or that the capability refuses anything."))
        return out

    crc, cblob, csecs = run(ccmd, timeout, (nc.get("env") or None))
    save_evidence(cid, "control", ccmd, crc, csecs, cblob)
    cfault = tool_fault(crc, cblob, csecs)
    if cfault:
        out.append(("TOOL-FAULT", f"{cid} CONTROL {cfault} :: {ccmd[:60]}"))
        return out

    want_ce = nc.get("expect_exit")
    if want_ce is None:
        out.append(("DRIFT", f"{cid} CONTROL: declares no expect_exit, so nothing states what "
                              f"the refusal looks like."))
    elif crc != want_ce:
        out.append(("DRIFT", f"{cid} CONTROL exit: recorded expect_exit={want_ce}, real={crc} "
                              f"after {csecs:.1f}s :: {ccmd[:60]}"))
    want_co = nc.get("expect_output")
    if want_co and want_co not in cblob:
        out.append(("DRIFT", f"{cid} CONTROL expect_output: {want_co!r} absent from real output"))
    # THE FLOOR. A capability whose probe and control both matched used to return NOTHING, so
    # `results` stayed empty for it, the summary printed `1 checked, .`, and main() returned 0.
    # That is how a two-line stub printing the recorded strings passes as proof: the instrument is
    # never asked whether it ran. Measured 2026-10-02 (.agent/audit/a2/report.md against
    # native.pe.packer) and re-confirmed by the 2026-10-03 red team a day later.
    #
    # There is deliberately NO second copy of this floor in main(). One was written there and
    # independent verification proved it cannot fire: check() guarantees one verdict per
    # capability, so `len(results) < len(todo)` is unsatisfiable -- deleting it changed nothing
    # while deleting THIS one turned the run red. Two floors, one of them dead, is zero floors
    # plus one: the same lesson mission.ps1's tombstone records the same day.
    #
    if REQUIRE_PRODUCES and pstate == "unclaimed":
        out.append(("DRIFT",
                    f"{cid} PRODUCES: --require-produces is on and this entry declares no "
                    f"probe.produces, so its verdict is STRINGS ONLY. Everything that can be "
                    f"faked by a two-line script is all that was checked: name the file or glob "
                    f"the probe run leaves behind and this entry becomes falsifiable."))
    #
    # The verdict says only what was compared, and now also only what the FILE SYSTEM showed.
    # Four capabilities declare no `probe.expect_exit`, so for those "exit matched" would be a
    # claim about nothing; the text below is true for all of them either way.
    #
    # The two OK texts are the difference this whole change exists to make, so they must not be
    # collapsed into one lenient sentence. `pstate == "fresh"` means bytes were written by this
    # run and hashed into the evidence log; `unclaimed` means the entry never asked, and saying
    # so in the verdict is what stops the green from being read as stronger than it is.
    if not out:
        if pstate == "fresh":
            out.append(("OK", f"{cid}: every comparison this entry declares matched -- probe."
                              f"expect substring, control expect_exit, control expect_output -- "
                              f"AND probe.produces {produces_specs(probe)!r} matched a file this "
                              f"run WROTE, whose sha256 is in the evidence log beside the "
                              f"command. PROVEN: those strings were printed AND those bytes "
                              f"landed on disk during this run. NOT PROVEN: that the bytes are "
                              f"correct, that the number inside them is right, or that the "
                              f"instrument a caller reaches in anger is the one that ran here."))
        elif pstate == "stale":
            # Unreachable while check_produces emits its own DRIFT for "stale"; kept so that a
            # future edit to that function cannot silently turn a stale artifact into an OK.
            out.append(("OK", f"{cid}: string comparisons matched and the declared artifact "
                              f"exists, but this verdict proves nothing about the run."))
        else:
            out.append(("OK", f"{cid}: every comparison this entry declares matched -- probe."
                              f"expect substring, control expect_exit, control expect_output. "
                              f"NOT a claim that the instrument ran: this entry declares no "
                              f"probe.produces, so this checker matched STRINGS only, and a "
                              f"stub which prints them satisfies it. Name the artifact the probe "
                              f"leaves and this verdict becomes falsifiable."))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="capability ids; default = every safe one")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--list", action="store_true", help="show what would run, run nothing")
    ap.add_argument("--budget", type=int, default=0,
                    help="stop starting new entries after this many seconds and NAME every entry "
                         "that was not run. 0 means no budget. Nothing skipped is ever counted as "
                         "a pass.")
    ap.add_argument("--save-evidence", metavar="DIR", default=None,
                    help="write each probe's and control's REAL output to DIR/<id>.<kind>.log")
    ap.add_argument("--require-produces", action="store_true",
                    help="require every entry that runs to declare probe.produces, and to leave a "
                         "file this run wrote. Off by default: an entry without the field is "
                         "unaffected, it just gets the weaker OK verdict that admits it.")
    args = ap.parse_args()
    global EVIDENCE_DIR, REQUIRE_PRODUCES
    REQUIRE_PRODUCES = args.require_produces
    if args.save_evidence:
        EVIDENCE_DIR = Path(args.save_evidence)
        if not EVIDENCE_DIR.is_absolute():
            EVIDENCE_DIR = REPO / EVIDENCE_DIR

    caps = load()
    known = {c["id"] for c in caps}
    if args.ids:
        missing = set(args.ids) - known
        if missing:
            print(f"assert-probes: unknown id(s): {sorted(missing)}", file=sys.stderr)
            return 2

    if args.list:
        for c in caps:
            print(f"  {'SKIP ' if c['id'] in SKIP else 'run  '} {c['id']:<30} "
                  f"{(c.get('probe') or {}).get('command', '')[:58]}")
        return 0

    todo = [c for c in caps if not args.ids or c["id"] in args.ids]
    # ORDERED BY DECLARED COST, and that is two things at once. It makes a bounded sweep cover
    # more ground -- with declaration order a 150 s budget reached 13 of 27 entries and spent
    # most of itself on the first slow one it met -- and it gives `requires.wall_minutes` its
    # FIRST READER. A mutation sweep measured that field as decoration: set it to anything on all
    # 27 entries and the validator stayed clean. A field that decides what runs first is read.
    # Ties keep declaration order, so the ordering is deterministic.
    if not args.ids:
        todo.sort(key=lambda c: float((c.get("requires") or {}).get("wall_minutes") or 0))
    results: list[tuple[str, str]] = []
    # A TIME BUDGET, and the reason it exists. Until 2026-10-03 this script was the ONLY reader of
    # `probe.prepare`, `probe.expect` and `probe.expect_exit` -- and `verify-all.ps1` invoked it as
    # `--list`, which runs nothing. So the three fields the North Star depends on were executed
    # only when a human typed the command, while the entry point printed "VERIFY-ALL: every fast
    # check passed" and exited 0. A check the aggregate does not run is the same defect as a check
    # nobody wrote.
    #
    # The budget is honest about what it does NOT run: every skipped id is printed by name with
    # the reason, and the summary counts only what actually ran. A partial sweep that says so is
    # worth having; a partial sweep that reports a green whole is worse than no sweep.
    deferred: list[str] = []
    ran: list[tuple[str, float]] = []
    t_start = time.monotonic()
    deadline = t_start + args.budget if args.budget else None
    for c in todo:
        if deadline is not None and time.monotonic() >= deadline and c["id"] not in SKIP:
            deferred.append(c["id"])
            continue
        t0 = time.monotonic()
        results.extend(check(c, args.timeout))
        ran.append((c["id"], time.monotonic() - t0))
    elapsed = time.monotonic() - t_start
    if deferred:
        print(f"\nassert-probes: BUDGET SPENT. {len(ran)} of {len(todo)} entries ran in "
              f"{elapsed:.0f}s; {len(deferred)} were NOT RUN and are counted in NO number below.")
        print("  The budget stops STARTING new entries, so the last one that started can overrun it:")
        if ran:
            worst = max(ran, key=lambda r: r[1])
            print(f"    longest entry was {worst[0]} at {worst[1]:.0f}s")
        for cid in deferred:
            print(f"  NOT RUN  {cid}")
        print("  Re-run them by id:  python scripts/assert-probes.py " + " ".join(deferred))

    counts: dict[str, int] = {}
    for s, _ in results:
        counts[s] = counts.get(s, 0) + 1
    for s, m in results:
        print(f"  {s:<11} {m}")

    # THE COUNT IS WHAT RAN. The first version of --budget printed `len(todo)` here, so a run
    # that executed 15 of 27 entries announced "27 checked" -- the precise defect the budget was
    # added to prevent, committed by the fix itself. Caught by reading the output of my own
    # change, which is the only place it could have been caught.
    scope = (f"{len(ran)} of {len(todo)} entries ran in {elapsed:.0f}s"
             if deferred else f"{len(todo)} entries")
    print(f"\nassert-probes: {scope}; verdicts "
          + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + ".")
    if counts.get("TOOL-FAULT"):
        print("\nTOOL-FAULT is this script's problem, not the registry's: those commands never\n"
              "ran. Fix this script before reading anything else in this output.")
    if counts.get("PREREQ"):
        print("\nPREREQ is NOT a drift and NOT a pass: the probe had nothing to read. Build or\n"
              "install what the named path is, then re-run. Editing probe.expect in response to a\n"
              "PREREQ is the one repair guaranteed to be wrong -- it turns a missing prerequisite\n"
              "into a recorded claim that the missing thing was expected.")
    if counts.get("DRIFT"):
        print("\nA DRIFT is a finding, not an auto-fix: the instrument may have regressed, or the\n"
              "recorded string may never have been true. Those have opposite fixes, so read it.")
    # PREREQ does NOT set a non-zero exit on its own, and that is deliberate. A fresh clone without
    # the corpus or the third-party tools would otherwise be permanently red, and a permanently red
    # gate is a gate that gets switched off. It is printed, counted and named; DRIFT is what says
    # "do not trust this run".
    # DRIFT is the "do not trust this run" verdict. TOOL-FAULT joins it only when EVERY entry that
    # ran failed to start, because a sweep in which nothing executed has measured nothing and
    # reporting that as green is the failure this file was written to find. A few tool faults among
    # twenty good runs stay non-fatal and are named, since a permanently red gate gets switched off.
    measured = sum(1 for c in ran if True) if ran else 0
    faults = counts.get("TOOL-FAULT", 0)
    nothing_measured = measured > 0 and faults >= measured
    if nothing_measured:
        print(f"\nREFUSING TO PASS: all {faults} of {measured} entries that ran failed to start, so "
              f"nothing was measured. That is not a green run; it is no run.")
    return 1 if (counts.get("DRIFT") or nothing_measured) else 0


if __name__ == "__main__":
    sys.exit(main())