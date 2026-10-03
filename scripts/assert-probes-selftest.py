#!/usr/bin/env python3
"""assert-probes-selftest.py — the test of the test.

WHY THIS FILE EXISTS. `assert-probes.py` is the ONLY reader of `probe.prepare`,
`probe.expect` and `probe.expect_exit`, and it is the check `verify-all.ps1` runs
(`scripts/verify-all.ps1:45`, `Step 'assert-probes (bounded)'`). A checker with no test of
its own cannot be shown to still check anything: delete the mechanism, keep the suite green,
and nobody learns the mechanism was load-bearing. Every property below therefore has a PLANT
— a registry built so the property's absence produces a GREEN verdict that must not exist —
and a CONTROL — the same registry with the mechanism honoured, which must stay green. A
property with only a control proves nothing, because the control is also what you get when the
mechanism is missing.

THE SCRIPT UNDER TEST IS NEVER PATCHED. Each scenario copies `scripts/assert-probes.py`
byte-for-byte into a %TEMP% tree and runs THAT as a subprocess, with the copy's sha256 checked
against the repo file first. This is not a convenience: `assert-probes.py` derives its registry
path from `Path(__file__).resolve().parent.parent / "manifests" / "capabilities.json"`
(assert-probes.py:95-96) and writes its PowerShell wrapper to that same REPO
(assert-probes.py:328, `script = REPO / "_assert_probe_cmd.ps1"`). Driving it against a planted
registry therefore means running a copy rooted at a planted tree — and it is also why this
harness writes NOTHING into either repository. Checked, not assumed: after every run, the
scenario directory is listed and the repo `scripts/` directory is unchanged.

    python scripts/assert-probes-selftest.py          # every property, transcript per case
    python scripts/assert-probes-selftest.py -v       # add each subprocess's full stdout
    python scripts/assert-probes-selftest.py --strict # a known GAP also exits nonzero
    python scripts/assert-probes-selftest.py prepare brace   # property ids are positional

VERDICT VOCABULARY. Three words, and they mean different things on purpose:

  PROVEN  the script already holds this property: the plant went red and the control green.
  GAP     the script does NOT hold it. The measured behaviour is printed with its transcript,
          because "the tool is broken" is not a finding until you have seen it happen.
  BROKEN  the harness itself could not tell, e.g. the copy's hash moved under it. Never a pass.

A GAP exits 0 by default, and that is the one deliberate softness here, so read the next
paragraph before trusting the exit code. A GAP is asserted to STILL REPRODUCE: the harness
drives the broken shape and requires the broken verdict to come back. If a future edit FIXES a
gap, the harness goes red and says so, because a property nobody has promoted to an assertion is
a property nobody is testing. So exit 0 means "every gap in this file is still open and every
implemented property still holds" — it does NOT mean assert-probes.py is correct. `--strict`
collapses the two so a CI step can demand the gaps be closed.

WHAT THIS FILE DELIBERATELY DOES NOT DO. It does not fix `assert-probes.py`; the diffs for each
gap are in the report that accompanied this file and in GAP_NOTES below, so the fix can be
argued about before it is typed. It does not run the real registry's probes — 27 entries, real
tools, ~24 min, and `smoke-all.ps1` is parent-owned. It does not invoke `verify-all.ps1`. It
never imports `assert-probes.py`: the property under test is what the file does when executed,
and importing it would test a module in the harness's own address space instead.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SELF = Path(__file__).resolve()
REPO = SELF.parent.parent
SUT = REPO / "scripts" / "assert-probes.py"          # the script under test
VALIDATOR = REPO / "scripts" / "registry-verify.py"  # cross-checked, never patched

# The identity of the script under test for the whole run. Set once in main() before any case
# runs, re-checked by every Case against the copy it is about to execute, and re-checked once
# more at the end so an edit made mid-run cannot be reported as a verdict about the new file.
SUT_HASH: list[str] = []

# Interpreter used for the PLANTED probes. It is the same one running this harness, which is
# the point: a probe that works here must be one this box can actually start, or TOOL-FAULT
# would mask whatever the property is actually about.
PY = sys.executable
PYQ = f'& "{PY}"'

GAP_NOTES: dict[str, str] = {
    "brace-silent":
        "PowerShell reads a bare `{` in argument position as the start of a script block, "
        "re-enters itself and hands the child `-encodedCommand <base64> -inputFormat xml "
        "-outputFormat text` instead of the recorded value. Measured here with stderr EMPTY and "
        "exit 0 (assert-probes-selftest property `brace-silent`), so nothing about the mangling "
        "is visible unless a recorded expect string happens to contain the mangled token. "
        "registry-verify.py R26 (r26_bare_braces_survive_the_shell, registry-verify.py:1155, "
        "verdict emitted at :1214) refuses the registry at VALIDATION time, which is why this "
        "harness cross-checks against it rather than duplicating the scan: R26 fired on the "
        "planted registry and stayed silent on the quoted control. `assert-probes.py` has no "
        "equivalent, so a registry that reached this checker while skipping validation -- or one "
        "whose expect string does not mention the brace -- reports OK on a command that never "
        "ran the way it is written.",
    "toolfault":
        "A command that cannot start leaves $LASTEXITCODE UNSET, so the `exit $LASTEXITCODE` "
        "wrapper (assert-probes.py:336) propagates 0, and `tool_fault()` short-circuits on "
        "`if rc == 0 or secs >= TOOL_FAULT_SECS` (assert-probes.py:366) BEFORE scanning the "
        "FAULT_MARKERS list -- even though \"is not recognized\" is in that list "
        "(assert-probes.py:108-110) and is sitting in the captured blob. Measured: "
        "`selftest-no-such-binary-9f3a --run` returns rc=0 with the marker in stderr, and an "
        "entry declaring no probe.expect and no probe.expect_exit for it comes back "
        "`OK  selftest.toolfault.green` with a sweep exit code of 0. That is the floor "
        "violated from the other side: the file's own comments say \"The failure mode of a "
        "checking tool is to check nothing and look green.\"",
}


# --------------------------------------------------------------------------- harness plumbing

class Case:
    """One planted registry, one subprocess run of the unmodified script, one parsed verdict set."""

    def __init__(self, name: str, root: Path, caps: list[dict], ids: list[str],
                 extra: tuple[str, ...] = (), validator: bool = False) -> None:
        self.name = name
        self.root = root
        self.ids = ids
        self.validator = validator
        d = root / name
        (d / "manifests").mkdir(parents=True, exist_ok=True)
        (d / "scripts").mkdir(parents=True, exist_ok=True)
        # Re-hash the copy, not the source. "Never patched" is a claim about the bytes that ran,
        # and a copy is only that claim until something compares them.
        shutil.copyfile(SUT, d / "scripts" / "assert-probes.py")
        if hashlib.sha256((d / "scripts" / "assert-probes.py").read_bytes()).hexdigest() != SUT_HASH[0]:
            raise SystemExit(f"selftest: the copy in {d} is not the script under test; refusing "
                             f"to report verdicts about a file I cannot identify.")
        (d / "manifests" / "capabilities.json").write_text(
            json.dumps({"capabilities": caps}, indent=1), encoding="utf-8")
        # The interpreter leads argv: CreateProcess will not run a .py as an executable, and
        # `[script, ids]` without it fails with WinError 193 rather than a verdict.
        argv = [PY, str(d / "scripts" / "assert-probes.py"), *ids, "--timeout", "45", *extra]
        if validator:
            argv = [PY, str(VALIDATOR), "--registry", str(d / "manifests" / "capabilities.json")]
        t0 = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, cwd=str(d),
                           encoding="utf-8", errors="replace")
        self.rc = p.returncode
        self.secs = time.monotonic() - t0
        self.out = (p.stdout or "") + (p.stderr or "")
        self.registry = d / "manifests" / "capabilities.json"

    def verdicts(self, cid: str) -> list[tuple[str, str]]:
        """(STATUS, message) for one capability id, parsed from the script's own verdict lines.

        The script prints `  {status:<11} {message}` and every message begins with the id, so
        this reads the verdict table rather than grepping prose.
        """
        got: list[tuple[str, str]] = []
        for line in self.out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2 or not parts[0].isupper():
                continue
            if parts[1].startswith(cid):
                got.append((parts[0], parts[1]))
        return got

    def status_of(self, cid: str) -> str:
        v = self.verdicts(cid)
        return ",".join(sorted({s for s, _ in v})) if v else "NO-VERDICT"

    def transcript(self, keep: int = 4) -> str:
        lines = [ln for ln in self.out.splitlines() if ln.strip()]
        body = lines if len(lines) <= keep else lines[:keep] + [f"    ... (+{len(lines) - keep} lines)"]
        return (f"    exit={self.rc} in {self.secs:.1f}s | {self.name}\n"
                + "".join(f"    | {ln}\n" for ln in body))


def helper(root: Path, filename: str, body: str) -> str:
    """Write a planted probe script under %TEMP% and return a runnable PowerShell command.

    Two shapes of command here, and the difference is measured rather than assumed:
      `& "<exe>" "<script>"`  -- a QUOTED executable path in command position is a PARSER ERROR
                                  in PowerShell unless the call operator leads. Confirmed on
                                  this box: `ParserError ... UnexpectedToken`, which
                                  tool_fault() correctly names 'parsererror'.
      the registry's own idiom -- `node tool.mjs`, an unquoted bare name.
    """
    p = root / filename
    p.write_text(body, encoding="utf-8")
    return f'{PYQ} "{p}"'


# --------------------------------------------------------------------------- the properties

def build_properties(root: Path) -> list[dict]:
    """Every property, each with its plant, its control, and what the plant must produce."""
    art = root / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    stale = art / "stale.txt"
    stale.write_text("PRE-EXISTING BYTES\n", encoding="utf-8")
    corpus = root / "prep" / "corpus.txt"
    corpus.parent.mkdir(exist_ok=True)
    if corpus.exists():
        corpus.unlink()

    stub = helper(root, "stub.py", "print('READY-TO-SHIP')\n")
    fresh = helper(root, "fresh.py",
                   "import time\n"
                   f"open(r'{stale}', 'w').write('NEW BYTES ' + str(time.time()) + chr(10))\n"
                   "print('READY-TO-SHIP')\n")
    refuse = helper(root, "refuse.py", "import sys\nprint('REFUSED')\nsys.exit(2)\n")
    reader = helper(root, "reader.py",
                    "import sys\n"
                    f"p = r'{corpus}'\n"
                    "try:\n    d = open(p).read().strip()\n"
                    "except OSError:\n    print('MISSING CORPUS'); sys.exit(3)\n"
                    "print('CORPUS-OK:' + d)\n")
    gen = helper(root, "gen.py", f"open(r'{corpus}', 'w').write('PACKETS=5' + chr(10))\n")
    noop = helper(root, "noop.py", "print('prepare declared, did nothing')\n")
    badprep = helper(root, "badprep.py",
                     "import sys\nprint('cannot build the corpus')\nsys.exit(1)\n")
    banner = helper(root, "banner.py", "print('ANALYSIS-COMPLETE packets=5')\n")
    argvpy = helper(root, "argv.py",
                    "import sys\na = sys.argv[1:]\n"
                    "print('ARGV=' + '|'.join(a))\n"
                    "print('FLAG-OK' if '--flag' in a and a[a.index('--flag') + 1] == 'FLAG{abc}'"
                    " else 'FLAG-MANGLED')\n"
                    "sys.exit(0 if '--flag' in a and a[a.index('--flag') + 1] == 'FLAG{abc}' else 4)\n")
    trust = helper(root, "trust.py",
                   "import sys\nprint('ISOLATION HELD: 0 lab certs, proxy unset')\nsys.exit(0)\n")
    ghost = "selftest-no-such-binary-9f3a --run"

    def entry(cid: str, probe: dict, control: dict | None = None) -> dict:
        cap = {"id": cid, "probe": probe}
        if control is not None:
            cap["negative_control"] = control
        return cap

    def ctl() -> dict:
        return {"command": refuse, "expect_exit": 2, "expect_output": "REFUSED"}

    props: list[dict] = []

    # -- 1. probe.produces narrows a string verdict to a filesystem one ---------------
    # PLANT: the probe prints its recorded expect and writes NOTHING, but the registry declares
    # an artifact that already exists on disk with unchanged bytes. Existence must not be
    # mistaken for production, or a stub inherits the previous run's file forever.
    p = entry("selftest.stub",
              {"command": stub, "expect": "READY-TO-SHIP", "expect_exit": 0,
               "produces": str(stale)}, ctl())
    props.append(dict(
        key="produces-stale", why="a probe that prints its expect but writes no declared "
                                  "artifact must be DRIFT even though every string matched",
        plant=p, plant_want="DRIFT",
        plant_note="wants DRIFT naming the byte-identical verdict, NOT OK",
        control=entry("selftest.real",
                      {"command": fresh, "expect": "READY-TO-SHIP", "expect_exit": 0,
                       "produces": str(stale)}, ctl()),
        control_want="OK", extra=()))
    # CONTROL for the weaker verdict: the same stub with NO produces declared must still pass,
    # and the harness states plainly that this green is the known weaker one.
    props.append(dict(
        key="produces-unclaimed", why="without produces declared the entry passes, and the "
                                       "harness says that verdict is STRINGS ONLY rather than "
                                       "reporting it as equal to the filesystem one",
        plant=entry("selftest.stub.noproduces",
                    {"command": stub, "expect": "READY-TO-SHIP", "expect_exit": 0}, ctl()),
        plant_want="OK", plant_note="expected: the weaker OK, which the harness must label",
        control=None,
        must_say=[("NOT a claim that the instrument ran", "plant"),
                  ("STRINGS only", "plant")],
        mutation="remove the `pstate == \"fresh\"` branch at assert-probes.py:522 and this two-line "
                 "stub with no artifact is indistinguishable from an instrument"))

    # -- 2. probe.prepare is the only reader of itself -------------------------------
    # PLANT: prepare is a no-op, so the file the probe reads was never generated.
    props.append(dict(
        key="prepare", why="probe.prepare is what creates the input the probe reads; a no-op "
                           "prepare must not leave the entry green",
        plant=entry("selftest.prepare.noop",
                    {"prepare": noop, "command": reader,
                     "expect": "CORPUS-OK:PACKETS=5", "expect_exit": 0}, ctl()),
        plant_want="DRIFT", plant_note="wants DRIFT: the probe had no input to read",
        control=entry("selftest.prepare.ok",
                      {"prepare": gen, "command": reader,
                       "expect": "CORPUS-OK:PACKETS=5", "expect_exit": 0}, ctl()),
        control_want="OK",
        cleanup=[corpus],
        mutation="stop executing `prep` at assert-probes.py:401-406 and this entry's recorded "
                 "run is a claim about a corpus no code path created"))
    # Second half: a prepare that FAILS is named TOOL-FAULT and must not read as a passing probe.
    props.append(dict(
        key="prepare-fails", why="a prepare that exits nonzero is this entry's TOOL-FAULT; the "
                                 "probe never got its input and must not be scored on it",
        plant=entry("selftest.prepare.fails",
                    {"prepare": badprep, "command": reader,
                     "expect": "CORPUS-OK:PACKETS=5", "expect_exit": 0}, ctl()),
        plant_want="TOOL-FAULT", plant_note="wants TOOL-FAULT present and NO OK verdict",
        control=None, no_ok=True))

    # -- 3. a bare `{` in argument position ------------------------------------------
    # PLANT A: the recorded expect names the mangled value, so the damage is visible.
    props.append(dict(
        key="brace-visible", why="a bare `{` in argument position delivers a mangled token to "
                                  "the child; when the expect string names it, the run must go red",
        plant=entry("selftest.brace",
                    {"command": argvpy + " --flag FLAG{abc}",
                     "expect": "ARGV=--flag|FLAG{abc}", "expect_exit": 0}, ctl()),
        plant_want="DRIFT", plant_note="wants DRIFT",
        control=entry("selftest.brace.quoted",
                      {"command": argvpy + ' --flag "FLAG{abc}"',
                       "expect": "ARGV=--flag|FLAG{abc}", "expect_exit": 0}, ctl()),
        control_want="OK",
        validator_plant=True, validator_control=True,
        mutation="the mangled value reaches the child and nothing in assert-probes.py compares "
                 "the command against the shell's own rules"))
    # PLANT B: the expect string does not mention the brace, so the damage is INVISIBLE.
    props.append(dict(
        key="brace-silent", why="a bare `{` whose mangling no recorded string can see must not "
                                "come back OK -- this is the shape the R26 rule exists for",
        plant=entry("selftest.brace.silent",
                    {"command": banner + " --filter FLAG{abc}",
                     "expect": "ANALYSIS-COMPLETE", "expect_exit": 0}, ctl()),
        plant_want="NOT-OK", plant_note="wants a refusal; MEASURED: it reports OK",
        control=None, expected_gap="brace-silent", no_ok=True,
        mutation="the probe above exits 0, prints its expect, and had its `--filter` argument "
                 "replaced by `-encodedCommand <base64> -inputFormat xml -outputFormat text`"))

    # -- 4. isolation_check under its OWN polarity ------------------------------------
    iso = {"command": trust, "expect_exit": 0, "expect_output": "ISOLATION HELD",
           "polarity": "SUCCESS IS EXIT 0. Do not compare this to a negative control; it asserts "
                       "that the station is uncontaminated, and its failure is an emergency "
                       "rather than a finding."}
    props.append(dict(
        key="isolation", why="an isolation_check is judged under its OWN polarity; driving it "
                             "under control polarity must be shown to condemn a CLEAN station",
        plant=entry("selftest.iso",
                    {"command": banner, "expect": "ANALYSIS-COMPLETE", "expect_exit": 0},
                    {**ctl(), "isolation_check": iso}),
        plant_want="OK", plant_note="the station is clean and the verdict says so",
        control=entry("selftest.iso.controlpolarity",
                      {"command": banner, "expect": "ANALYSIS-COMPLETE", "expect_exit": 0},
                      {**ctl(), "isolation_check": {**iso, "expect_exit": 1}}),
        control_want="DRIFT",
        must_say=[("ISOLATION exit: expected 1, real=0", "control"),
                  ("treat this as an emergency", "control")],
        mutation="judge isolation_check with the negative control's polarity and the one moment "
                 "the project needs to hear from it -- a silent success -- is recorded as an "
                 "emergency"))

    # -- 5. TOOL-FAULT is not a pass ---------------------------------------------------
    props.append(dict(
        key="toolfault", why="a probe that cannot start must be TOOL-FAULT and must never be "
                              "counted as a pass",
        plant=entry("selftest.toolfault",
                    {"command": ghost, "expect": "ANALYSIS-COMPLETE", "expect_exit": 0}, ctl()),
        plant_want="TOOL-FAULT",
        plant_note="MEASURED: DRIFT instead -- the missing binary leaves $LASTEXITCODE unset, so "
                   "the wrapper propagates 0 and tool_fault() returns early on `rc == 0`",
        # The control is a shell failure this script DOES name: a quoted executable in command
        # position with no call operator, which PowerShell rejects in ~0.27s with a
        # ParserError. rc=1, under TOOL_FAULT_SECS, marker present -- so tool_fault() reaches its
        # scan and fires. That is what makes the plant a finding about the rc==0 GATE rather than
        # about TOOL-FAULT being unreachable or dead code. An earlier control here routed the
        # same missing binary through cmd.exe; it took 0.57-1.5s, tripped the other half of that
        # gate (`secs >= TOOL_FAULT_SECS`), and came back DRIFT -- a control that could not
        # distinguish the two mechanisms, which is no control at all.
        control=entry("selftest.toolfault.control",
                      {"command": '"' + PY.strip('"') + '" "' + str(root / "no-such-helper.py")
                       + '"', "expect": "ANALYSIS-COMPLETE", "expect_exit": 0}, ctl()),
        control_want="TOOL-FAULT",
        control_note="a quoted exe with no call operator: rc=1 in ~0.27s with ParserError, so "
                     "the marker scan runs and names it -- proving TOOL-FAULT is reachable and "
                     "that the plant's failure is the rc==0 gate",
        expected_gap="toolfault", no_ok=True,
        mutation="run the entry with no probe.expect and no probe.expect_exit at all and the "
                 "sweep prints `OK` and exits 0 for a command that never started"))
    props.append(dict(
        key="toolfault-green", why="the extreme case: a probe that cannot start AND declares "
                                    "nothing of its own must not be OK",
        plant=entry("selftest.toolfault.green", {"command": ghost}, ctl()),
        plant_want="NOT-OK", plant_note="wants a refusal; MEASURED: `OK`, sweep exit 0",
        control=None, expected_gap="toolfault", no_ok=True,
        mutation="delete `tool_fault()`'s marker scan and this sweep still exits 0"))
    return props


# --------------------------------------------------------------------------- the checks

def run_prop(prop: dict, root: Path, verbose: bool) -> dict:
    """Drive one property. Returns PROVEN / GAP / BROKEN with the transcript either way."""
    res: dict = {"key": prop["key"], "why": prop["why"], "notes": []}
    cases = [("plant", prop["plant"], prop["plant_want"], prop.get("plant_note", ""))]
    if prop.get("control"):
        cases.append(("control", prop["control"], prop["control_want"],
                      prop.get("control_note", "")))

    for label, cap, want, note in cases:
        for cleanup in prop.get("cleanup", []) or []:
            if cleanup.exists():
                cleanup.unlink()
        cid = cap["id"]
        case = Case(f"{prop['key']}-{label}", root, [cap], [cid])
        got_set = {s for s, _ in case.verdicts(cid)}
        got = ",".join(sorted(got_set)) if got_set else "NO-VERDICT"
        # An entry can earn SEVERAL verdicts -- a brace-mangled probe that also names a missing
        # path reports DRIFT *and* PREREQ -- and `want` names the one this property is about, not
        # the whole set. Exact string equality on a comma-joined list made this harness go BROKEN
        # the moment another verdict existed, which is a harness crying wolf about a working
        # script. So `want` is satisfied by MEMBERSHIP, and a plant additionally must NOT be OK.
        if want == "NOT-OK":
            ok = bool(got_set) and "OK" not in got_set
        else:
            ok = want in got_set
        res["notes"].append((label, want, got, ok, note, case, cap))

    # `must_say` names the transcript it belongs to. Defaulting to "the first passing case"
    # silently checked the wrong run and reported a real verdict as absent, which is the exact
    # shape of a checker that cries wolf.
    for phrase, on in prop.get("must_say", []):
        where = next(c for lb, _, _, _, _, c, _ in res["notes"] if lb == on)
        hit = phrase.lower() in where.out.lower()
        res["notes"].append((f"must_say[{on}]", phrase, "found" if hit else "ABSENT", hit,
                             "the verdict text has to carry this claim", where, None))

    # R26 cross-check for the brace property: the validator must refuse the planted registry
    # and accept the quoted control. Read, never patched.
    if prop.get("validator_plant"):
        for label, want in (("plant", "R26"), ("control", "NO-R26")):
            cap = prop[label]
            vcase = Case(f"{prop['key']}-{label}-validator", root, [cap], [cap["id"]],
                         validator=True)
            fired = [ln for ln in vcase.out.splitlines() if "R26 " in ln]
            hit = bool(fired) if want == "R26" else not fired
            res["notes"].append((f"R26-{label}", want,
                                 "R26 fired" if fired else "R26 silent", hit,
                                 "registry-verify.py is the static half of this property",
                                 vcase, None))

    gap = prop.get("expected_gap")
    if gap:
        # A gap's entire content is that its plant came back OK where it must not. If a future
        # edit fixes it, this harness says BROKEN rather than quietly folding it into PROVEN, so
        # a closed gap gets promoted to a real assertion instead of becoming a stale note.
        res["verdict"] = "GAP" if not all(n[3] for n in res["notes"]) else "BROKEN"
        res["gap_note"] = GAP_NOTES[gap] + (
            "" if res["verdict"] == "GAP" else
            "  MEASURED DIFFERENTLY THIS RUN: the plant no longer reproduces, so whatever this "
            "file called a gap has been fixed. Promote it to an assertion and drop this entry.")
    else:
        res["verdict"] = "PROVEN" if all(n[3] for n in res["notes"]) else "BROKEN"
    res["all_notes"] = res["notes"]
    return res


def repo_untouched(root: Path, preexisting: set[Path]) -> list[str]:
    """Refuse to claim 'nothing was written into either tree' without checking it.

    assert-probes.py writes a PowerShell wrapper to its own REPO (assert-probes.py:328,
    `script = REPO / "_assert_probe_cmd.ps1"`) and unlinks it in a `finally`. Because every case
    runs a COPY rooted at a %TEMP% tree, that wrapper must land in %TEMP% and never in the
    repo -- and the %TEMP% tree is where the proof is: run() creates that file for every single
    command it executes, so if the copy were rooted at the real repo this would be found.

    `preexisting` is the set of repo wrapper paths that existed BEFORE the suite started. This
    wrapper is TRANSIENT and shared: a concurrent `verify-all.ps1` on the same checkout creates
    the identical filename, so flagging it here would report another agent's run as this
    harness's escape. A path that was already there when the suite started is named and
    excluded rather than silently swallowed.
    """
    bad = [f"stray _assert_probe_cmd.ps1 left behind in the planted tree: {p}"
           for p in root.rglob("_assert_probe_cmd.ps1")]
    for stray in (REPO / "_assert_probe_cmd.ps1", REPO / "scripts" / "_assert_probe_cmd.ps1"):
        if stray.exists() and stray not in preexisting:
            bad.append(f"stray {stray.name} appeared in the REPO during this run: the script "
                       f"under test wrote outside %TEMP%")
        elif stray.exists():
            print(f"selftest: NOTE {stray} existed before this run (a concurrent verify-all, not "
                  f"this harness) and is excluded from the filesystem verdict.")
    return bad


def repo_wrappers() -> set[Path]:
    """Snapshot the shared wrapper paths in the repo, before any case runs."""
    return {p for p in (REPO / "_assert_probe_cmd.ps1", REPO / "scripts" / "_assert_probe_cmd.ps1")
            if p.exists()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="run only these property keys")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each run's full output")
    ap.add_argument("--strict", action="store_true", help="a known GAP exits nonzero too")
    ap.add_argument("--keep", action="store_true", help="keep the temp tree, print its path")
    a = ap.parse_args()

    if not SUT.exists():
        print(f"selftest: script under test not found: {SUT}", file=sys.stderr)
        return 2
    sut_hash = hashlib.sha256(SUT.read_bytes()).hexdigest()
    SUT_HASH.append(sut_hash)

    root = Path(tempfile.gettempdir()) / f"assert-probes-selftest-{os.getpid()}"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    preexisting = repo_wrappers()
    print(f"selftest: driving {SUT}")
    print(f"selftest:   sha256 {sut_hash} (each case re-checks this before it runs)")
    print(f"selftest:   registry copies and planted probes under {root}")
    print(f"selftest:   {len(props := build_properties(root))} properties\n")

    results = [run_prop(p, root, a.verbose) for p in props
               if not a.ids or p["key"] in a.ids]
    if a.ids:
        unknown = set(a.ids) - {p["key"] for p in props}
        if unknown:
            print(f"selftest: unknown property key(s): {sorted(unknown)}", file=sys.stderr)
            return 2

    width = max(len(r["key"]) for r in results)
    for r in results:
        print(f"  {r['verdict']:<7} {r['key']:<{width}}  {r['why']}")
        for label, want, got, ok, note, case, _cap in r["all_notes"]:
            mark = "  ok " if ok else "  ** "
            print(f"      {mark} {label:<14} want={want:<9} got={got}")
            if note:
                print(f"            {note}")
            if a.verbose or not ok:
                print(case.transcript(keep=99 if a.verbose else 5), end="")
        if r["verdict"] == "GAP":
            print(f"      GAP: {r['gap_note']}")
        print()

    stray = repo_untouched(root, preexisting)
    # The copy is what ran, so the copy is what has to still be the script under test. An
    # integrator editing assert-probes.py mid-run must invalidate this run, not silently
    # produce verdicts about a version that no longer exists.
    if hashlib.sha256(SUT.read_bytes()).hexdigest() != sut_hash:
        stray.append("scripts/assert-probes.py changed WHILE the suite ran; every verdict above "
                     "is about a version that no longer exists. Re-run.")
    for s in stray:
        print(f"  BROKEN  filesystem: {s}")

    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"\nselftest: {len(results)} properties; " + ", ".join(
        f"{v} {k}" for k, v in sorted(counts.items())) + ".")
    print("selftest: PROVEN = the script holds this property (plant red, control green).")
    print("selftest: GAP = measured, the script does NOT hold it; the diff is in the report.")
    print("selftest: a GAP is asserted to still reproduce -- if one goes green it was FIXED, "
          "which this harness reports as BROKEN so it gets promoted to an assertion.")

    if a.keep:
        print(f"selftest: tree kept at {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)

    if counts.get("BROKEN") or stray:
        return 2
    if a.strict and counts.get("GAP"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())