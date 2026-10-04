#!/usr/bin/env python
"""Read a PE's mitigation posture with rabin2 and emit it as JSON.

WHY THIS EXISTS. An audit found that radare2 6.2.2 has been installed, pinned in
manifests/tools.json, smoke-tested in scripts/smoke-tools.ps1 and present on disk at
Static-Reversing/radare2/ -- and that ZERO of the arsenal's capabilities mention radare2, rabin2
or rizin. It was paid for, callable, and unwired.

It is also the only instrument here that answers a question nothing else asks. native.pe.container
reads ASLR and native.pe.authenticode reads the certificate table; neither reports whether a binary
carries a stack canary, whether the image is marked as vulnerable to control-flow hijack, or whether
a checksum is present. Those are mitigation facts, and mitigation posture is what a reviewer asks
before deciding whether a crash is interesting.

It is a FOURTH instrument on the native axes and a genuinely different implementation again: pefile
reads the IMAGE structure in Python, rabin2 is a C tool with its own format layer. That matters
because the independence gate counts families, and a fourth reading from a different codebase is
worth more than another pefile wrapper.

Measured on c01-stringobf.exe: arch x86, baddr 0x140000000, class PE32+, bits 64, canary true,
injprot false, retguard false, crypto false, cmp.csum 0x00030d3e -- in 0.4 s, exit 0.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

# Added 2026-10-04 so this probe stops being a string match. `assert-probes.py` decides an entry
# is real by matching substrings in stdout, and prints its own weakness on every OK: "NOT a
# claim that the instrument ran: a stub which prints them satisfies it." 22 of 27 capabilities
# were in exactly that position. Writing the result to disk moves the verdict onto the
# filesystem, which a stub has to also write to fake. See scripts/probe_artifact.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from probe_artifact import write_artifact  # noqa: E402
# RESOLVED RELATIVE TO THIS FILE. Measured 2026-10-03 by an independent audit: this hardcoded the
# ORIGINAL station's absolute rabin2 path, so a clone at any other path silently measured with the
# original machine's binary and reported PASS. Passing number, wrong machine. RABIN2_ENV overrides.
_HERE = pathlib.Path(__file__).resolve().parent
_R2 = _HERE.parents[1] / "Static-Reversing" / "radare2"
def _newest_rabin2() -> str:
    """The HIGHEST version present, not the first one alphabetically.

    Measured 2026-10-03, and the first version of this fix got it wrong in a way worth writing
    down: `sorted(glob(...))[0]` picks radare2-6.2.0 over radare2-6.2.2, so the tool would have
    silently switched versions while every number it printed stayed plausible. Two copies of an
    instrument is two different instruments, and choosing between them by alphabetical accident
    is how a measurement becomes a claim about something else. Sorting by the parsed version and
    taking the max makes the choice explicit; RABIN2_EXE still overrides it entirely.
    """
    import re as _re
    best, best_key = None, None
    for cand in _R2.glob("radare2-*-w64/bin/rabin2.exe"):
        m = _re.search(r"radare2-(\d+)\.(\d+)\.(\d+)", str(cand))
        key = tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
        if best_key is None or key > best_key:
            best, best_key = cand, key
    return str(best) if best else str(_R2 / "bin" / "rabin2.exe")


DEFAULT_RABIN2 = os.environ.get("RABIN2_EXE") or _newest_rabin2()

# The fields this reports, and what each one is allowed to mean. `crypto` is the one that most
# needs the caveat: rabin2 sets it from the presence of a signature directory, which is exactly the
# signal native.pe.authenticode then has to check properly. It means "there is something here", not
# "this is trusted".
MITIGATION_FIELDS = ("canary", "injprot", "retguard", "nx", "pic", "relocs", "stripped", "crypto")


def refuse(code: int, error: str, **extra):
    out = {"ok": False, "exit": code, "error": error}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--rabin2", default=DEFAULT_RABIN2)
    args = ap.parse_args()

    if not os.path.isfile(args.rabin2):
        refuse(2, f"rabin2 not found at {args.rabin2}. The station ships a portable radare2; "
                  f"this path is the pinned 6.2.2 build and is not a PATH lookup.")

    p = subprocess.run([args.rabin2, "-I", args.binary], capture_output=True, text=True,
                       timeout=180)
    if p.returncode != 0:
        refuse(2, f"rabin2 exited {p.returncode}: {(p.stderr or p.stdout or '').strip()[:160]}")

    info: dict[str, str] = {}
    for line in (p.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            info[parts[0]] = parts[1].strip()

    if "arch" not in info or "bintype" not in info:
        refuse(2, "rabin2 ran but returned no recognisable info block; refusing rather than "
                  "reporting an empty mitigation profile as a clean one",
               parsed_keys=sorted(info)[:10])

    # A MANAGED PE has no native mitigation posture to report. Measured 2026-10-04 by an
    # independent experiment that built three managed PEs of different size and content:
    # rabin2 returned canary:"true" on ALL THREE, including a bare Console.WriteLine with no
    # buffer and no arguments, and none of them contains a cookie, a __security_check_cookie,
    # a LOAD_CONFIG directory, or a single native stack frame. rabin2 keys the flag off
    # arch=cil rather than off an actual cookie, so it is a CONSTANT on this population.
    #
    # That constant is more dangerous than a wrong flag on a native binary, because rabin2 IS
    # discriminating for native x86 -- so the two populations never overlap and nothing else
    # would ever have caught it. Passing it through would be reporting an instrument's habit
    # as a fact about the binary, which is the one thing this project exists to stop.
    managed = str(info.get("arch", "")).lower() in ("cil", "mono", "dotnet") or \
        str(info.get("lang", "")).lower() in ("cil", "csharp", "f#", "vb")
    if managed:
        result_managed = {
            "managed": True,
            "reason": ("this is a MANAGED assembly; the image has no native stack frames, so "
                       "native mitigation flags do not apply to it. rabin2 still reports them "
                       "and they are constants on this population, not readings."),
            "reported_by_rabin2_but_not_meaningful": {k: info.get(k) for k in MITIGATION_FIELDS},
            "what_to_read_instead": ("ask a MANAGED-lane capability (managed.il.decompile, or "
                                     "ilspycmd) about the IL. For hardening, the questions that "
                                     "matter are strong-naming and cross-assembly tampering, "
                                     "which are not native mitigations and are not in this file."),
        }
        print(json.dumps({
            "ok": True, "exit": 0, "binary": args.binary,
            "image": {k: info.get(k) for k in ("arch", "bits", "class", "bintype", "machine",
                                               "os", "subsys", "lang")},
            "mitigations": None,
            "managed": result_managed,
            "caveat": ("MITIGATIONS ARE NULL, NOT EMPTY, ON PURPOSE. An empty dict would read "
                       "as 'measured, nothing found'; null reads as 'this question does not "
                       "apply here, and here is why'. Do not fill it in from the rabin2 values "
                       "above -- they are the fabricated ones this check exists to catch."),
        }))
        write_artifact("hardening_probe", {"ok": True, "exit": 0, "binary": args.binary,
                                           "mitigations": None, "managed": result_managed})
        return 0

    mitigations = {k: info.get(k) for k in MITIGATION_FIELDS}
    result = {
        "ok": True, "exit": 0, "binary": args.binary,
        "image": {k: info.get(k) for k in
                  ("arch", "bits", "class", "bintype", "baddr", "binsz", "endian", "machine",
                   "os", "subsys", "compiler", "lang")},
        "mitigations": mitigations,
        "caveats": (
            "THESE ARE PRESENCE FLAGS FROM ONE IMPLEMENTATION, NOT A HARDENING ASSESSMENT. "
            "`canary true` means a stack-protection cookie symbol was found; it does not mean the "
            "buffer it protects is bounded. `nx` is reported by rabin2 but is NOT included in the "
            "mitigation dict above as a boolean because its value needs reading rather than "
            "trusting: a PE can carry the NX-compatible bit and still be marked executable. "
            "`crypto true` means a signature directory is PRESENT -- which is a trigger to ask "
            "native.pe.authenticode or native.signature.certverify, never a statement that anything "
            "is trusted."),
    }
    print(json.dumps(result))
    write_artifact("hardening_probe", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())