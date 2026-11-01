"""labkit -- shared helpers for the crackme-corpus solvers.

Every solver in this corpus is a consumer of *tool output*, never of the
challenge source. The split is deliberate:

  * radare2 (rabin2/r2) supplies raw bytes at a virtual address, taken from the
    compiled artifact only.
  * Ghidra's headless export supplies the decompiled C, which is searched for
    the same constants the solver recovered from the bytes. Two tools, two
    independent derivations, and the artifact they must agree about.

Tool locations come from the station layout, overridable by env var so the
solver can be pointed at a different install root.
"""
import json
import os
import re
import subprocess
import sys

STATION = os.environ.get("CRACKME_STATION") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
R2_EXE = os.environ.get("CRACKME_R2", os.path.join(STATION, "Static-Reversing", "radare2", "radare2-6.2.2-w64", "bin", "radare2.exe"))
RABIN2_EXE = os.environ.get("CRACKME_RABIN2", os.path.join(STATION, "Static-Reversing", "radare2", "radare2-6.2.2-w64", "bin", "rabin2.exe"))


class ToolError(RuntimeError):
    pass


def _run(argv, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
    if p.returncode != 0:
        raise ToolError(f"{argv[0]} rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.stdout


def r2(*cmds, exe):
    """Run r2 non-interactively; returns stdout with tool warnings stripped."""
    argv = [R2_EXE, "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true"]
    for c in cmds:
        argv += ["-c", c]
    argv.append(exe)
    out = _run(argv)
    return "\n".join(l for l in out.splitlines() if not l.startswith("WARN"))


def read_va(exe, va, n):
    """Raw bytes at virtual address `va`, read through r2's loader."""
    out = r2(f"p8 {n} @ {va}", exe=exe)
    hexs = re.sub(r"[^0-9a-fA-F]", "", out)
    data = bytes.fromhex(hexs)
    if len(data) < n:
        raise ToolError(f"r2 returned {len(data)} of {n} bytes at {va:#x}")
    return data[:n]


def sections(exe):
    """[{name, vaddr, vsize, paddr, size, perm}, ...] from rabin2 -Sj."""
    doc = json.loads(_run([RABIN2_EXE, "-Sj", exe]))
    return doc["sections"] if isinstance(doc, dict) else doc


def read_u32(exe, va):
    return int.from_bytes(read_va(exe, va, 4), "little")


def read_u8(exe, va):
    return read_va(exe, va, 1)[0]


def section_bytes(exe, name):
    """Whole section content as bytes, via r2 (respects the loader's mapping)."""
    for s in sections(exe):
        if s["name"] == name:
            return read_va(exe, s["vaddr"], s["vsize"] or s["size"])
    raise ToolError(f"section {name} not present in {exe}")


def run_sample(exe, args=(), timeout=30):
    """Run the crackme itself. Ground truth: the artifact's own verdict."""
    p = subprocess.run([exe, *args], capture_output=True, text=True, errors="replace", timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def ghidra_files(outdir):
    """Decompiled .c files written by scripts/ghidra/ExportDecompile.java."""
    d = os.path.join(outdir, "decompiled")
    if not os.path.isdir(d):
        raise ToolError(f"no ghidra export at {d}")
    return [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".c")]


def ghidra_text(outdir):
    """Concatenated decompiled C for the whole program."""
    return "\n".join(open(f, encoding="utf-8", errors="replace").read() for f in ghidra_files(outdir))


def ghidra_func(outdir, name_hint):
    """Decompiled C of the first file whose name contains name_hint."""
    for f in ghidra_files(outdir):
        if name_hint.lower() in os.path.basename(f).lower():
            return open(f, encoding="utf-8", errors="replace").read()
    raise ToolError(f"no decompiled function matching {name_hint!r} in {outdir}")


def ghidra_main(outdir):
    """The decompiled `main` (Ghidra may name it `_main` / `FUN_...`); fall back
    to the file whose text looks like an entry point."""
    return ghidra_func(outdir, "main")


def printable(b):
    return all(32 <= c < 127 for c in b)


def fail(msg):
    print(f"FAIL {msg}")
    sys.exit(1)


def ok(msg):
    print(msg)


def banner(cid, technique):
    print(f"== {cid} :: {technique}")
