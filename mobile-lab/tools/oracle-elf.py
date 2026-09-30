#!/usr/bin/env python
"""
oracle-elf.py — INDEPENDENT verification of a hand-built ELF shared object.

Why this exists
---------------
mobile-lab builds lib/<abi>/*.so byte-by-byte in JavaScript (there is no Android NDK on
this box). A file that its own author also inspects is not verified. This script re-reads
the same bytes with **pyelftools**, a separate ELF implementation written in Python by
other people, and asserts the same structural claims. If make-so.mjs and pyelftools
disagree about a symbol name, a section offset, or the machine type, the loop fails.

This is the loop's "independent second source" gate (analysis-loop invariant 3). It is an
ORACLE, not a dependency: the analyser in tools/analyze.mjs does not import pyelftools and
does not need it, but the loop refuses to call the build verified without this cross-check.

Usage:  python oracle-elf.py <path-to.so> [--expect-machine 183] [--expect-sym NAME]...
Exit:   0 = pyelftools agrees on every claim, 3 = disagreement (the interesting failure).
"""

import argparse
import json
import sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection
except ImportError:  # pragma: no cover
    print("pyelftools is not installed in this interpreter", file=sys.stderr)
    sys.exit(4)


def enum_value(value, table_name: str) -> int:
    """pyelftools returns ENUM fields as their *name* ('EM_AARCH64'), not their number.

    Comparing that straight to 183 silently fails, which looks like a corrupt ELF when the
    ELF is fine. Resolve the name through pyelftools' own enum tables so the oracle checks
    the value the spec defines rather than a string it happens to print.
    """
    import elftools.elf.enums as enums

    if not isinstance(value, str):
        return int(value)
    table = getattr(enums, table_name)
    if value not in table:
        raise KeyError(f"{table_name} has no entry named {value!r}")
    return table[value]

EM_AARCH64 = 183
ET_DYN = 3


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--expect-machine", type=int, default=EM_AARCH64)
    ap.add_argument("--expect-type", type=int, default=ET_DYN)
    ap.add_argument("--expect-sym", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    problems: list[str] = []
    report: dict = {"path": args.path}

    with open(args.path, "rb") as fh:
        elf = ELFFile(fh)

        report["class"] = elf.elfclass
        report["little_endian"] = elf.little_endian
        report["machine"] = enum_value(elf.header["e_machine"], "ENUM_E_MACHINE")
        report["type"] = enum_value(elf.header["e_type"], "ENUM_E_TYPE")

        if elf.elfclass != 64:
            problems.append(f"elfclass={elf.elfclass}, want 64")
        if not elf.little_endian:
            problems.append("big-endian ELF; want little-endian")
        if report["machine"] != args.expect_machine:
            problems.append(f"e_machine={report['machine']}, want {args.expect_machine}")
        if report["type"] != args.expect_type:
            problems.append(f"e_type={report['type']}, want {args.expect_type}")

        # --- sections ---
        names = [s.name for s in elf.iter_sections()]
        report["sections"] = names
        for req in (".text", ".rodata", ".dynstr", ".dynsym", ".dynamic", ".hash"):
            if req not in names:
                problems.append(f"missing section {req}")

        # --- segments ---
        segs = []
        for seg in elf.iter_segments():
            segs.append({"type": enum_value(seg.header.p_type, "ENUM_P_TYPE_BASE"),
                         "vaddr": hex(seg.header.p_vaddr), "filesz": seg.header.p_filesz})
        report["segments"] = segs
        if not any(s["type"] == 2 for s in segs):  # 2 == PT_DYNAMIC
            problems.append("no PT_DYNAMIC segment")

        # --- dynamic entries ---
        needed, soname, tags = [], None, []
        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                t = tag.entry.d_tag
                tags.append(t)
                if t == "DT_NEEDED":
                    needed.append(tag.needed)
                elif t == "DT_SONAME":
                    soname = tag.soname
        report["needed"] = needed
        report["soname"] = soname
        report["dynamic_tags"] = tags
        if not needed:
            problems.append("no DT_NEEDED")
        if not soname:
            problems.append("no DT_SONAME")
        if "DT_NULL" not in tags:
            problems.append("no DT_NULL terminator")

        # --- symbols ---
        defined, undefined = {}, {}
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if not sym.name or sym.entry.st_shndx == "SHN_UNDEF":
                    if sym.name:
                        undefined[sym.name] = sym.entry.st_info["type"]
                    continue
                defined[sym.name] = {
                    "type": sym.entry.st_info["type"],
                    "bind": sym.entry.st_info["bind"],
                    "value": hex(sym.entry.st_value),
                    "size": sym.entry.st_size,
                }
        report["defined_symbols"] = defined
        report["undefined_symbols"] = undefined

        if not defined:
            problems.append("no defined symbols")
        if not undefined:
            problems.append("no undefined symbols")
        for name in args.expect_sym:
            if name not in defined:
                problems.append(f"expected exported symbol missing: {name}")

        # --- rodata round-trip: the string the native pin table is supposed to hold ---
        rodata = elf.get_section_by_name(".rodata")
        if rodata is not None:
            data = rodata.data()
            pins = [s.decode() for s in data.split(b"\x00") if s.startswith(b"sha256/")]
            report["rodata_pins"] = pins
            report["rodata_size"] = len(data)
            if not pins:
                problems.append(".rodata contains no sha256/ pin strings")

    report["ok"] = not problems
    report["problems"] = problems

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"oracle: {args.path}")
        print(f"  class={report['class']} machine={report['machine']} type={report['type']}")
        print(f"  sections={len(report['sections'])} segments={len(report['segments'])}")
        print(f"  soname={report['soname']} needed={report['needed']}")
        print(f"  defined={len(report['defined_symbols'])} undefined={len(report['undefined_symbols'])}")
        print(f"  rodata_pins={len(report.get('rodata_pins', []))}")
        for p in problems:
            print(f"  PROBLEM: {p}")
        print("  VERDICT:", "AGREES with the hand-built layout" if not problems else "DISAGREES")

    return 0 if not problems else 3


if __name__ == "__main__":
    sys.exit(main())
