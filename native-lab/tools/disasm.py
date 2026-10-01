#!/usr/bin/env python
"""Disassemble a function at an RVA and resolve its RIP-relative operands.

WHY THIS EXISTS. Measured 2026-10-02 on crackme-corpus/out/c01-stringobf.exe, function `main`
at RVA 0x1080:

  * IDA Pro (Hex-Rays, a decompiler) inlined the XOR key constants as 18/11/90 and 26/5/51;
  * Ghidra (also a decompiler) left the last two as DAT_140017344 and DAT_140017342, with no
    width, which is dangerous -- read as the natural u32, DAT_140017342 is 734042;
  * capstone, which contains NO decompiler at all, emits
        movzx r9d, byte ptr [rip + 0x16259]     -> 0x140017342, byte = 90
        mov   r8d, dword ptr [rip + 0x16254]    -> 0x140017344, dword = 11
    which is the same value IDA propagated AND, crucially, the OPERAND WIDTH, because the
    `movzx` prefix says byte and the bare `mov` says dword.

So a disassembler is not merely a second opinion on structure here -- it is the only instrument
of the three that states the width, which is the exact fact whose absence made Ghidra's output
a trap rather than merely incomplete.

The RVA is mapped through the section table rather than used as a file offset. Disassembling at
file offset 0x1000 because .text has VirtualAddress 0x1000 yields ZERO instructions and looks
like a successful empty run; that mistake was made and is asserted against below.
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    import capstone
except ImportError:
    print(json.dumps({"ok": False, "exit": 2, "error": "capstone is not importable here"}))
    sys.exit(2)

try:
    import pefile
except ImportError:
    print(json.dumps({"ok": False, "exit": 2, "error": "pefile is not importable here"}))
    sys.exit(2)

X86_OP_MEM = capstone.x86.X86_OP_MEM
X86_REG_RIP = capstone.x86.X86_REG_RIP


def refuse(code: int, msg: str, **extra):
    out = {"ok": False, "exit": code, "error": msg}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--rva", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--count", type=int, default=48)
    ap.add_argument("--force", action="store_true",
                    help="disassemble even in a non-executable section (packed or self-modifying code)")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    try:
        pe = pefile.PE(args.binary)
    except pefile.PEFormatError as e:
        refuse(1, f"not a PE: {e}")

    # Resolve the RVA through the section table. This is the step whose absence produced a
    # silent zero-instruction run in the first draft of this script.
    try:
        off = pe.get_offset_from_rva(args.rva)
    except Exception as e:
        refuse(1, f"RVA 0x{args.rva:x} is not mapped by any section: {e}")

    base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__[off:off + 0x200]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True


    # EXECUTABLE-SECTION GATE, added after the probe caught this tool answering on non-code.
    # Measured: pointing --rva at .rdata (Characteristics 0x40000040, no IMAGE_SCN_MEM_EXECUTE)
    # returned ok:true with 8 decoded "instructions", the first being `sbb byte ptr [rip+2], dl`
    # -- decoded out of ASCII string bytes. That is worse than returning nothing, because the
    # caller sees a successful run and a plausible-looking instruction stream. The zero-
    # instruction refusal below is real but rare; garbage-decodes-from-data is the common case
    # and it sailed straight through.
    #
    # So the containing section must be executable before a single byte is handed to capstone.
    # --force exists for the legitimate case of a self-modifying or packed binary whose code
    # lives in a section not marked executable, and it is loud about what it is doing.
    section = None
    for s in pe.sections:
        lo, hi = s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if lo <= args.rva < hi:
            section = s
            break
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    if section is None:
        refuse(1, f"RVA 0x{args.rva:x} falls in no section")
    executable = bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    if not executable and not args.force:
        refuse(2,
               f"RVA 0x{args.rva:x} is in section "
               f"{section.Name.rstrip(bytes([0])).decode(errors='replace')!r} "
               f"(Characteristics 0x{section.Characteristics:08x}), which is NOT executable. "
               f"Decoding it yields plausible-looking instructions built out of data bytes; "
               f"pass --force only if you know that section really holds code.",
               section=section.Name.rstrip(bytes([0])).decode(errors="replace"),
               characteristics=hex(section.Characteristics))
    insns, operands = [], []
    for i in md.disasm(data, base + args.rva):
        insns.append({"addr": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str})
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = i.address + i.size + op.mem.disp
                rva_t = tgt - base
                try:
                    o = pe.get_offset_from_rva(rva_t)
                    raw = pe.__data__[o:o + 4]
                    operands.append({
                        "at": hex(i.address),
                        "text": f"{i.mnemonic} {i.op_str}",
                        "target": hex(tgt),
                        # The WIDTH is the whole point: `movzx ... byte ptr` is one byte and
                        # `mov ... dword ptr` is four. A reader that widens a byte load to a
                        # dword gets 734042 where the value is 90.
                        "width": "byte" if "byte ptr" in i.op_str else "dword",
                        "byte": raw[0],
                        "dword": int.from_bytes(raw, "little"),
                    })
                except Exception:
                    operands.append({"at": hex(i.address), "target": hex(tgt),
                                     "error": "target RVA not mapped"})
        if len(insns) >= args.count:
            break

    if not insns:
        # Loud, not silent. An empty result here is the exact failure mode this script exists
        # to prevent, so it REFUSES rather than reporting "0 instructions, ok".
        refuse(3, f"zero instructions decoded at RVA 0x{args.rva:x} (file offset 0x{off:x}); "
                   f"an empty disassembly is a mapping error, never an answer",
               file_offset=off)

    out = {
        "ok": True,
        "exit": 0,
        "binary": args.binary,
        "image_base": hex(base),
        "rva": hex(args.rva),
        "file_offset": hex(off),
        "count": len(insns),
        "insns": insns,
        "rip_operands": operands,
        "caveat": "A DISASSEMBLER IS NOT A DECOMPILER. These are instructions, not recovered "
                  "logic: no lifting, no type recovery, no control-flow reconstruction. It "
                  "corroborates structure and resolves operands the decompilers leave as "
                  "references, and it cannot tell you what the code MEANS.",
    }
    text = json.dumps(out, indent=1)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(json.dumps({k: out[k] for k in ("ok", "rva", "file_offset", "count")}))
    for op in operands:
        print(f"  RIP-REL {op.get('text',''):<44} -> {op.get('target','?')} "
              f"width={op.get('width','?'):<6} byte={op.get('byte','?')} dword={op.get('dword','?')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())