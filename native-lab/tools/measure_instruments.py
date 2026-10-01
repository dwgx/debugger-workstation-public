#!/usr/bin/env python
"""Measure the arms depot: wall time per instrument on ONE self-authored binary.

Every number printed here is produced by a command in this repository against
crackme-corpus/out/c01-stringobf.exe, which this repository authored. Nothing is
remembered and nothing is quoted from another session.

The point is not a benchmark table. It is that a PAIRING can only be chosen when the two
halves are timed on the same input, and until now this project compared tools described in
prose across different runs.

A row whose exit code is not the expected one is printed as FAILED and its timings are
excluded. A timing produced by an instrument that did not work is not a measurement, and
printing it in the same column as a working instrument's timing is the harness committing
the error it exists to detect.
"""
import pathlib
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
TARGET = REPO / "crackme-corpus" / "out" / "c01-stringobf.exe"
RUNS = 3


def timed(label, argv, expect_rc=0, cwd=REPO):
    """Run argv RUNS times. Returns (label, times, rc, stderr_tail)."""
    times, rc, err = [], None, ""
    for _ in range(RUNS):
        t0 = time.perf_counter()
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=900)
        times.append(round(time.perf_counter() - t0, 2))
        rc, err = p.returncode, p.stderr.strip()
    return label, times, rc, err


def main():
    if not TARGET.exists():
        print(f"target missing: {TARGET}")
        return 2

    rows = []

    # 1. pefile -- pure header parse, no instrument spawned beyond python itself.
    code = (
        "import pefile;pe=pefile.PE(r'%s');"
        "assert pe.OPTIONAL_HEADER.ImageBase==0x140000000;"
        "assert pe.OPTIONAL_HEADER.DllCharacteristics==0x8160" % TARGET
    )
    rows.append(timed("native.pe.container (pefile header parse)",
                      [sys.executable, "-c", code]))

    # 2. capstone -- disassembly of .text. NOTE the RVA-to-file-offset mapping: .text has
    #    VirtualAddress 0x1000 but PointerToRawData elsewhere, so disassembling at the file
    #    offset 0x1000 yields ZERO instructions and a silent success. Assert on the count so
    #    that mistake fails loudly instead of reporting a fast wrong answer.
    code2 = (
        "import pefile,capstone;"
        "pe=pefile.PE(r'%s');"
        "s=[x for x in pe.sections if x.Name.rstrip(b'\\x00')==b'.text'][0];"
        "off=s.PointerToRawData+(0x1080-s.VirtualAddress);"
        "data=pe.__data__[off:off+0x40];"
        "md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);"
        "ins=list(md.disasm(data,0x140001080));"
        "assert len(ins)>0, 'disassembled zero instructions';" % TARGET
    )
    rows.append(timed("capstone (disassemble main, RVA mapped)",
                      [sys.executable, "-c", code2]))

    # 5 and 6 -- the two wrappers written on 2026-10-02. Added here rather than measured ad hoc
    # so this table stays the ONE place instrument cost is quoted from.
    triage = REPO / "headless-lab" / "tools" / "triage-packer.ps1"
    if triage.exists():
        rows.append(timed("native.pe.packer (DiE unpack gate)",
                          ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", str(triage), "-Target", str(TARGET)]))

    matcher = REPO / "headless-lab" / "tools" / "match-functions.ps1"
    other = REPO / "crackme-corpus" / "out" / "c03_antidebug.exe"
    if matcher.exists() and other.exists():
        rows.append(timed("native.function.match (two Ghidra imports)",
                          ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", str(matcher), "-Source", str(TARGET),
                           "-Dest", str(other)]))

    # 3. IDA Pro through the station's own client.
    client = REPO / "native-lab" / "tools" / "list-funcs.mjs"
    if client.exists():
        rows.append(timed("native.ida.list_functions (IDA via idalib-mcp)",
                          ["node", str(client), str(TARGET)]))

    # 4. The frida recipe -- spawn-gate, load while suspended, resume, intercept.
    frida = REPO / "native-lab" / "tools" / "frida_spawn_gate.py"
    py = REPO / "Mobile-Android" / "objection" / ".venv" / "Scripts" / "python.exe"
    if frida.exists() and py.exists():
        tmpd = pathlib.Path(tempfile.gettempdir()) / "perf"
        tmpd.mkdir(exist_ok=True)
        t = tmpd / "target.exe"
        t.write_bytes(TARGET.read_bytes())
        rows.append(timed("dynamic.win.frida.intercept (spawn+intercept)",
                          [str(py), str(frida), str(t), "positive"]))

    print(f"target: {TARGET}")
    print(f"size:   {TARGET.stat().st_size} bytes")
    print(f"runs:   {RUNS} each, wall clock seconds\n")
    print(f"{'instrument':<46} {'min':>7} {'med':>7} {'max':>7}  rc")
    print("-" * 74)

    total, failed = 0.0, 0
    for label, times, rc, err in rows:
        if rc != 0:
            failed += 1
            tail = (err.splitlines() or [""])[-1][:38]
            print(f"{label:<46} {'FAILED':>21}  rc={rc}  {tail}")
            continue
        med = sorted(times)[len(times) // 2]
        total += med
        print(f"{label:<46} {min(times):>7.2f} {med:>7.2f} {max(times):>7.2f}  {rc}")

    print("-" * 74)
    print(f"{'sum of medians (working instruments only)':<46} {total:>7.2f}")
    print(f"{'instruments that did not run':<46} {failed:>7d}")

    print("\nReading this table:")
    print("  - Read the verdict, not the clock. A fast wrong answer is the worst kind.")
    print("  - The median is what a mission waits for; the min is a best case that will not repeat.")
    print("  - A pairing costs the SUM of its parts PLUS the hand-off between them, and the")
    print("    hand-off is not measured here. So this table is a FLOOR on the real cost, and a")
    print("    cheap pairing can still be the wrong one if the hand-off needs a human.")
    if failed:
        print(f"  - {failed} instrument(s) FAILED and are excluded from the total on purpose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())