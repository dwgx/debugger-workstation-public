#!/usr/bin/env python
"""Read a PE's load-relevant container facts and emit them as JSON.

WHY THIS EXISTS. `pe.aslr` is the fact BOTH frida entries rest on when they rebase at runtime:
dynamic.win.frida and dynamic.win.frida.intercept each read the module base from the live process
precisely because this header says the base is not guaranteed. Until now that fact was recorded in
the registry but no capability could EMIT it, so a mission chain could never carry the evidence
for the rule its own entries obey. This makes it callable.

STDOUT MUST BE PURE JSON, and stderr must stay silent by default. mission.ps1 runs a capability as
`& $runner @argList 2>&1 | Out-String`, which MERGES stderr into stdout -- a tool that decorates
stderr corrupts the JSON it declared. Learned from native.disasm.capstone, which failed its first
mission round for exactly that reason while working perfectly by hand.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

# ONE COPY OF THE TRUNCATION RULE, not two. Measured 2026-10-05 on this very tool: cutting the
# corpus binary to 50% and to 1 KB left pe_probe reporting `ok: true, sections: 6`, because a PE
# stores its headers FIRST and both pefile and this script read only headers. `sections: 6` on a
# 1 KB file enumerates section headers whose DATA is gone, which is the tell.
#
# The rule lives in the sibling because it was written and measured for this exact failure one
# tool earlier today, and the reasoning that makes it correct -- the discriminator is
# PointerToRawData, NOT SizeOfRawData, because an over-declaring linker never moves a
# PointerToRawData -- is the part a second copy here would be free to get wrong.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
try:
    from hardening_probe import _truncation_report
except ImportError as _e:
    _truncation_report = None
    _TRUNCATION_IMPORT_ERROR = f"{type(_e).__name__}: {_e}"
else:
    _TRUNCATION_IMPORT_ERROR = None

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DLLCHARACTERISTICS_DYNAMICBASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DIRECTORY_ENTRY_SECURITY = 4


def refuse(code: int, msg: str, **extra):
    out = {"ok": False, "exit": code, "error": msg}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def parse(raw: bytes):
    """Parse headers AND read the section table, or raise.

    Both halves live in here on purpose. Measured: guarding only `pefile.PE()` left a bare
    `IndexError: list index out of range` escaping for a 400-byte truncated PE, because pefile
    parses far enough to RETURN and then fails while the section table is read. That is the same
    defect as the null-dereference at mission.ps1:861 -- an unhandled crash where a refusal
    belongs, and the caller gets a stack trace instead of a name.
    """
    import pefile

    pe = pefile.PE(data=raw)
    oh = pe.OPTIONAL_HEADER
    sections = []
    for s in pe.sections:
        sections.append({
            "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "executable": bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE),
            "writable": bool(s.Characteristics & IMAGE_SCN_MEM_WRITE),
        })
    return pe, oh, sections


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    args = ap.parse_args()

    try:
        with open(args.binary, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        refuse(1, f"cannot read {args.binary}: {e}")

    # Checked here rather than left to pefile, because every downstream consumer of this entry
    # assumes a PE and pefile is lenient enough to yield a partial structure from one that is
    # not. A partial ImageBase is exactly the plausible wrong number this registry refuses.
    if len(raw) < 2 or raw[0] != 0x4D or raw[1] != 0x5A:
        head = raw[:2].hex() if len(raw) >= 2 else "too-short"
        refuse(2, f"not a PE: first two bytes are {head}, expected 4d5a ('MZ')", first_bytes=head)

    try:
        import pefile  # noqa: F401
    except ImportError:
        refuse(2, "pefile is not importable here")

    try:
        pe, oh, sections = parse(raw)
    except pefile.PEFormatError as e:
        refuse(1, f"not a PE: {e}")
    except Exception as e:
        refuse(1, f"PE headers are malformed or truncated: {type(e).__name__}: {e}",
               parsed_bytes=len(raw),
               note="pefile raises PEFormatError for a clean non-PE; a truncated one parses far "
                    "enough to RETURN and then fails reading the section table. Both are "
                    "refusals here, not crashes.")

    # IS THE FILE EVEN COMPLETE? This is the refusal hardening_probe added earlier today for the
    # same measured failure, and the rule is imported rather than rewritten so the two probes
    # cannot disagree about what "truncated" means.
    #
    # WHY REFUSE RATHER THAN "ACCEPT AND FLAG". A flag is only as good as the reader who looks at
    # it, and the field that makes this dangerous -- `sections: 6` -- is exactly the field a
    # caller reads. Every container fact here is true OF THE HEADER, and the header is the one
    # part a PE stores first, so a flag would sit beside a complete, confident, wrong picture of
    # a file that cannot execute. Exit 2 is the same class this probe already uses for "the
    # input is not the thing you said it is" (see the MZ check above), and it matches the
    # sibling's code for the identical condition.
    #
    # THE DISCRIMINATOR IS PointerToRawData, NOT SizeOfRawData. Both truncations leave a section
    # whose start lies past EOF: that section is not partly present, it is entirely absent.
    # Over-declaring SizeOfRawData never moves a PointerToRawData, so a linker that pads a
    # declared size is NOT called truncated. Measured in both directions; see the report.
    if _truncation_report is None:
        # Fail CLOSED. A probe that cannot check whether the file is whole has no business
        # reporting that it is a PE, and skipping the check quietly would restore the exact
        # defect this guard exists to remove.
        refuse(2, "cannot load the truncation rule from hardening_probe, so this probe cannot "
                  "honestly say the file is complete; refusing rather than reporting a "
                  "container picture it cannot stand behind",
               import_error=_TRUNCATION_IMPORT_ERROR,
               note="the rule is imported from the sibling deliberately, so there is one copy. "
                    "If it cannot be imported that is an environment fault, not a licence to "
                    "guess.")
    _t = _truncation_report(args.binary)
    if _t is not None:
        _declared_end, _file_size = _t
        refuse(2, f"the file is TRUNCATED, so its container facts would describe headers rather "
                  f"than the binary: the last section ends at 0x{_declared_end:x} but the file "
                  f"is only 0x{_file_size:x} bytes, and at least one section STARTS past the end "
                  f"of the file. A PE puts its headers first, so a half-file parses cleanly and "
                  f"pefile reads only headers -- this is not a corrupt-file signal, it is the "
                  f"ABSENCE of a whole-file signal. Nothing downstream may treat sections, "
                  f"aslr or entry_rva from this file as facts about a runnable image.",
               declared_end=_declared_end, file_size=_file_size,
               discriminator="a section's PointerToRawData lies past EOF. SizeOfRawData is NOT "
                             "the discriminator: a linker may over-declare a section size "
                             "without moving where that section starts, and such a file is "
                             "complete.")

    chars = oh.DllCharacteristics

    # The SECURITY directory is entry 4. A truncated PE can carry FEWER than five data-directory
    # entries, so indexing [4] raises IndexError -- and that is OUTSIDE the parse() guard, which
    # is why a SECOND bare traceback escaped after the first was fixed. Measured: the truncated
    # control still printed `IndexError: list index out of range` with the section table already
    # parsed cleanly. Indexing past the declared array is a refusal here.
    try:
        sec_dir = oh.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY]
        sec_entry = {"is_a": "FILE OFFSET (not an RVA)",
                     "offset": sec_dir.VirtualAddress, "size": sec_dir.Size}
    except Exception as e:
        refuse(1, f"PE data-directory array is too short to contain entry "
                  f"{IMAGE_DIRECTORY_ENTRY_SECURITY}: {type(e).__name__}: {e}",
               declared_entries=len(oh.DATA_DIRECTORY),
               note="a truncated PE can parse and yield a section table while carrying fewer "
                    "than five data-directory entries.")

    result = {
        "ok": True,
        "exit": 0,
        "binary": args.binary,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_64bit": oh.Magic == 0x20B,
        "image_base": hex(oh.ImageBase),
        "entry_rva": hex(oh.AddressOfEntryPoint),
        "dll_characteristics": hex(chars),
        "aslr": {
            "dynamic_base": bool(chars & IMAGE_DLLCHARACTERISTICS_DYNAMICBASE),
            "nx_compat": bool(chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
            "high_entropy_va": bool(chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
            "bit": "IMAGE_DLLCHARACTERISTICS_DYNAMICBASE 0x0040",
        },
        "sections": sections,
        "security_directory": sec_entry,
        "caveat": ("CONTAINER FACTS ONLY. No instruction is decoded and no code is interpreted. "
                   "aslr.dynamic_base is a HEADER CLAIM by whoever built the file: it is the "
                   "reason a runtime module base must be read rather than assumed, not proof "
                   "that the image is relocated on any particular run."),
    }
    print(json.dumps(result))
    # Written to disk so the verdict rests on a FILE. Added 2026-10-05: native.pe.container's
    # probe was a 200-character inline `python -c` that matched three hex strings and left
    # nothing, so it was verified by substring like the rest -- and this script already emits
    # every one of those facts as JSON. See scripts/probe_artifact.py.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
    from probe_artifact import write_artifact  # noqa: E402
    write_artifact("pe_probe", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())