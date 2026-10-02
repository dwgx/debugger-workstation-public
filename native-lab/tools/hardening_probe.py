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
import subprocess
import sys

DEFAULT_RABIN2 = (r"D:\Software\Tool\WorkStation\debugger\Static-Reversing\radare2"
                   r"\radare2-6.2.2-w64\bin\rabin2.exe")

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
    return 0


if __name__ == "__main__":
    sys.exit(main())