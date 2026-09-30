#!/usr/bin/env python3
"""c01 solver -- string-table obfuscation (byte rotation + XOR mask).

Tool chain, in the order an analyst would run it:

  1. Ghidra headless (scripts/ghidra-headless.ps1 -> ExportDecompile.java)
     gives the decompiled program. From it the solver takes, per call site:
     the blob address, the blob length, and the *symbols* holding the rotation
     and the mask. It never reads the challenge source.
  2. radare2 reads the bytes: `p8 <n> @ <va>` at the blob address, a little-
     endian int32 at the rotation symbol, one byte at the mask symbol.
  3. The artifact itself is the judge: the recovered password is fed back to
     c01_stringobf.exe and it must answer ACCEPTED.

Exit 0 only when the recovered password is accepted by the binary AND the
recovered flag equals the expected one.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import labkit as lk  # noqa: E402

# <callee>(0x<blob VA>, 0x<len>, <rot ref>, <mask ref>, <dst>)
CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(\s*(0x[0-9a-fA-F]{6,})\s*,\s*(0x[0-9a-fA-F]+)\s*,"
    r"\s*([A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+)\s*,\s*([A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+)\s*,"
)


def sym(tok):
    """('imm', value) for a literal, ('mem', va) for a Ghidra data symbol."""
    if tok.lower().startswith("0x"):
        return "imm", int(tok, 16)
    m = re.search(r"_([0-9a-fA-F]{6,})$", tok)
    if not m:
        raise lk.ToolError(f"cannot resolve symbol {tok!r} to an address")
    return "mem", int(m.group(1), 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--ghidra-out", required=True)
    ap.add_argument("--expect-password", required=True)
    ap.add_argument("--expect-flag", required=True)
    a = ap.parse_args()

    lk.banner("c01", "string-table obfuscation (rotate + XOR)")
    text = lk.ghidra_text(a.ghidra_out)

    calls = CALL_RE.findall(text)
    if not calls:
        lk.fail("no (va, len, rot, mask) call site found in the Ghidra export")
    print(f"ghidra: {len(calls)} decoder call site(s) recovered from decompiled C")

    # Signature check: the callee really is a rotate+XOR loop.
    callee = calls[0][0]
    body = lk.ghidra_func(a.ghidra_out, callee)
    loop = [l.strip() for l in body.splitlines() if "for (" in l or "for(" in l]
    if "^" not in body or "%" not in body:
        lk.fail(f"callee {callee} does not look like a rotate+XOR loop")
    print(f"ghidra: callee {callee} -> {loop[0] if loop else '<no for-loop>'}")
    for l in body.splitlines():
        if "= *(byte *)(param_" in l:
            print(f"ghidra: body      -> {l.strip()}")

    blobs = []
    for callee, va_s, n_s, rot_tok, mask_tok in calls:
        va, n = int(va_s, 16), int(n_s, 16)
        rk, rv = sym(rot_tok)
        mk, mv = sym(mask_tok)
        rot = rv if rk == "imm" else lk.read_u32(a.exe, rv)
        mask = mv if mk == "imm" else lk.read_u8(a.exe, mv)
        raw = lk.read_va(a.exe, va, n)
        out = bytes(raw[(i + rot) % n] ^ mask for i in range(n))
        blobs.append((va, n, rot, mask, raw, out))
        print(f"r2:     {n} bytes @ {va:#x}  rot={rot} mask={mask:#04x}  -> {out.decode('latin-1')!r}")
        if not lk.printable(out):
            lk.fail(f"decode at {va:#x} is not printable (rot={rot} mask={mask:#04x})")

    # The artifact decides which decoded blob is the password.
    passwords = [b for b in blobs if lk.run_sample(a.exe, [b[5].decode()])[0] == 0]
    if len(passwords) != 1:
        lk.fail(f"expected exactly one decoded blob to be accepted, got {len(passwords)}")
    pw = passwords[0][5].decode()
    flags = [b[5].decode() for b in blobs if b is not passwords[0] and b[5].decode().startswith("FLAG{")]
    if len(flags) != 1:
        lk.fail(f"expected exactly one decoded FLAG{{..}} blob, got {flags}")

    rc, out, _ = lk.run_sample(a.exe, [pw])
    lines = [l for l in out.splitlines() if l.strip()]
    print(f"binary: rc={rc} {' | '.join(lines)}")
    if rc != 0 or "ACCEPTED" not in out:
        lk.fail("the binary rejected the recovered password")

    if pw != a.expect_password:
        lk.fail(f"password {pw!r} != expected {a.expect_password!r}")
    if flags[0] != a.expect_flag:
        lk.fail(f"flag {flags[0]!r} != expected {a.expect_flag!r}")

    print(f"PASS c01 password={pw!r} flag={flags[0]!r}")
    print("     decoy string in .rdata was NOT the answer (strings|grep FLAG is a trap)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
