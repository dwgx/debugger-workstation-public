# IDA batch export (idat -A). No GUI. Hex-Rays when licensed.
# Args: idat -A -S"export_decompiled.py <outdir> [max_functions]" <sample>
import json
import os
import re
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_nalt
import ida_pro
import ida_segment
import idautils
import idc


def _outdir():
    args = []
    try:
        args = list(idc.ARGV)
    except Exception:
        args = []
    if len(args) > 1 and args[1]:
        return args[1], int(args[2]) if len(args) > 2 and str(args[2]).isdigit() else 10**9
    return os.path.join(os.environ.get("TEMP", "."), "ida-export"), 10**9


def _safe(name, ea):
    s = re.sub(r"[^A-Za-z0-9_.-]", "_", name or "func")
    if len(s) > 80:
        s = s[:80]
    return "%s_%X" % (s, ea)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(text if text else "")


def _imports():
    lines = []

    def cb(ea, name, ordinal):
        lines.append("%s ord=%s ea=0x%X" % (name or "ord%s" % ordinal, ordinal, ea))
        return True

    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod = ida_nalt.get_import_module_name(i) or "mod%d" % i
        lines.append("# %s" % mod)
        ida_nalt.enum_import_names(i, cb)
    return "\n".join(lines) + ("\n" if lines else "")


def _segments():
    lines = []
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if not seg:
            continue
        name = ida_segment.get_segm_name(seg) or ""
        lines.append("%s: 0x%X - 0x%X" % (name, seg.start_ea, seg.end_ea))
    return "\n".join(lines) + ("\n" if lines else "")


def _exports():
    lines = []
    for i, ordinal, ea, name in idautils.Entries():
        lines.append("%s ord=%s ea=0x%X" % (name or "entry", ordinal, ea))
    return "\n".join(lines) + ("\n" if lines else "")


def _disasm(fn):
    lines = []
    ea = fn.start_ea
    while ea < fn.end_ea and ea != idc.BADADDR:
        lines.append("0x%X: %s" % (ea, idc.generate_disasm_line(ea, 0) or ""))
        ea = idc.next_head(ea, fn.end_ea)
    return "\n".join(lines) + "\n"


def main():
    ida_auto.auto_wait()
    outdir, max_fn = _outdir()
    decomp_dir = os.path.join(outdir, "decompiled")
    os.makedirs(decomp_dir, exist_ok=True)
    hexrays = False
    try:
        hexrays = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays = False

    func_lines = []
    n = 0
    decompiled = 0
    for ea in idautils.Functions():
        if n >= max_fn:
            break
        fn = ida_funcs.get_func(ea)
        if not fn:
            continue
        name = ida_funcs.get_func_name(ea) or "sub_%X" % ea
        func_lines.append("%s @ 0x%X" % (name, ea))
        body = None
        if hexrays:
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc is not None:
                    body = str(cfunc)
                    decompiled += 1
            except Exception:
                body = None
        if not body:
            body = "// hexrays unavailable or failed; disassembly fallback\n" + _disasm(fn)
        _write(os.path.join(decomp_dir, _safe(name, ea) + ".c"), body)
        n += 1

    _write(os.path.join(outdir, "functions.txt"), "\n".join(func_lines) + ("\n" if func_lines else ""))
    _write(os.path.join(outdir, "imports.txt"), _imports())
    _write(os.path.join(outdir, "exports.txt"), _exports())
    _write(os.path.join(outdir, "segments.txt"), _segments())
    inf = ida_ida.inf_get_procname() if hasattr(ida_ida, "inf_get_procname") else ida_idp.get_idp_name()
    input_path = ida_nalt.get_input_file_path() or ""
    summary = {
        "ok": True,
        "tool": "ida",
        "program": os.path.basename(input_path),
        "processor": inf,
        "hexrays": hexrays,
        "functions": n,
        "decompiled": decompiled,
        "outdir": outdir.replace("\\", "/"),
    }
    _write(os.path.join(outdir, "summary.json"), json.dumps(summary, ensure_ascii=False) + "\n")
    print("EXPORT_DECOMPILE", outdir)
    print(json.dumps(summary, ensure_ascii=False))
    ida_pro.qexit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)
