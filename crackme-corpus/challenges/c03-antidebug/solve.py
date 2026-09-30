#!/usr/bin/env python3
"""c03 solver -- anti-debug awareness: never trust a result made under a debugger.

The whole point of this challenge is that the binary *lies* when it observes a
debugger, so the solve path has to do two opposite things and both have to hold:

  1. Recover the sealed key statically, from tool output only:
       - Ghidra headless decompiles the rolling-XOR unsealer and the FNV-1a
         integrity routine. The solver reads, from the decompiled C, the sealed
         blob address, its length, and the seed/step pair at each call site --
         it never reads the challenge source.
       - radare2 reads the sealed bytes at that address out of the compiled
         image. The rolling XOR is replayed here to get the candidate key.
       - Ghidra also yields the FNV-1a target constant and the address the
         checksum covers. Recomputing FNV-1a over the sealed bytes and matching
         that constant is what proves these bytes really are the table the
         program guards -- a decode that happens to be printable is not proof.
  2. Then run the artifact twice and demand the two answers differ:
       - a normal run must ACCEPT the recovered key and print the real flag;
       - the same run under `tools/dbg-presence.py` (a real Win32 debuggee,
         PEB->BeingDebugged set for the whole run) must ACCEPT *any* input and
         print the decoy. That is the guard working, not a bug.

Exit 0 only when the static recovery is right, the clean run accepts, and the
debugged run lies. A challenge whose only lesson is "use a debugger" would fail
the second half; a challenge that only works in a debugger would fail the first.
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import labkit as lk  # noqa: E402

# <callee>(0x<blob VA>, 0x<len>, 0x<seed>, '<step char>', <dst>)
CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(\s*(0x[0-9a-fA-F]{6,})\s*,\s*(0x[0-9a-fA-F]+)\s*,"
    r"\s*(0x[0-9a-fA-F]+)\s*,\s*('(\\?.|\\x[0-9a-fA-F]{2})')\s*,\s*\(?[A-Za-z_]"
)
# FNV-1a: h = 0x811c9dc5; loop h = (h ^ byte) * 0x1000193; return h == <target>
FNV_INIT_RE = re.compile(r"(?<![=!<>])\s*=\s*(0x[0-9a-fA-F]{6,})\s*;")
FNV_PRIME_RE = re.compile(r"\*\s*(0x[0-9a-fA-F]{6,})\s*;")
FNV_CMP_RE = re.compile(r"==\s*(0x[0-9a-fA-F]{6,})\s*;")
FNV_TABLE_RE = re.compile(r"\(&DAT_([0-9a-fA-F]{6,})\)\[local_\w+\]|\(&DAT_([0-9a-fA-F]{6,})\)\[(\w+)\]")
FNV_LEN_RE = re.compile(r"<\s*(0x[0-9a-fA-F]+|\d+)\s*;")


def unescape_char(tok):
    """Ghidra char literal: 'a', '\\r', '\\x0d' -> int."""
    body = tok[1:-1]
    if body.startswith("\\x"):
        return int(body[2:], 16)
    named = {"r": 13, "n": 10, "t": 9, "0": 0, "\\": 92, "'": 39}
    if body.startswith("\\") and body[1:] in named:
        return named[body[1:]]
    if body.startswith("\\"):
        return ord(body[1:])
    return ord(body)


def fnv1a(data, init, prime):
    h = init
    for b in data:
        h = ((h ^ b) * prime) & 0xFFFFFFFF
    return h


def find_unsealer(files):
    """The one decompiled function that is a rolling (seed-advancing) XOR loop."""
    found = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if "^" not in t or "for (" not in t:
            continue
        # A rolling mask advances by a parameter each iteration. A fixed-mask
        # XOR (c01) will not match, which is the point of the signature.
        if not re.search(r"\^\s*local_\w+\s*;\s*\n?\s*local_\w+\s*=\s*local_\w+\s*\+\s*param_\w+\s*;", t):
            continue
        found.append((f, t))
    if len(found) != 1:
        raise lk.ToolError(f"expected exactly one rolling-XOR unsealer, matched "
                           f"{[os.path.basename(f) for f, _ in found]}")
    return found[0]


def find_integrity(files):
    """The decompiled FNV-1a integrity check -> (init, prime, target, va, n)."""
    hits = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if "0x811c9dc5" not in t.lower():
            continue
        init = FNV_INIT_RE.findall(t)
        prime = FNV_PRIME_RE.findall(t)
        cmp_ = FNV_CMP_RE.findall(t)
        tab = FNV_TABLE_RE.search(t)
        ln = FNV_LEN_RE.findall(t)
        if not (init and prime and cmp_ and tab):
            continue
        va = int(tab.group(1) or tab.group(2), 16)
        hits.append((int(init[0], 16), int(prime[0], 16), int(cmp_[0], 16), va, int(ln[0], 0)))
    if len(hits) != 1:
        raise lk.ToolError(f"expected exactly one FNV-1a integrity check, matched {len(hits)}")
    return hits[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--ghidra-out", required=True)
    ap.add_argument("--expect-password", required=True)
    ap.add_argument("--expect-flag", required=True)
    a = ap.parse_args()

    lk.banner("c03", "anti-debug awareness (sealed key + integrity check + guard)")
    files = lk.ghidra_files(a.ghidra_out)

    # --- 1. the guard, from the decompiled C ---------------------------------
    guard = lk.ghidra_text(a.ghidra_out)
    for probe, label in ((r"IsDebuggerPresent", "IsDebuggerPresent() API check"),
                         (r"0x60", "direct PEB->BeingDebugged read (gs:[0x60])"),
                         (r"QueryPerformance", "QueryPerformanceCounter timing window")):
        if not re.search(probe, guard, re.I):
            lk.fail(f"guard not found in the decompile: {label}")
        print(f"ghidra: guard present -- {label}")
    if "FLAG{" not in guard:
        lk.fail("the decoy flag is not in the decompile; the trap is missing")
    print("ghidra: a decoy FLAG{...} literal is in the binary and is never the answer")

    # --- 2. the unsealer, from the decompiled C ------------------------------
    try:
        upath, ubody = find_unsealer(files)
    except lk.ToolError as e:
        lk.fail(str(e))
    print(f"ghidra: rolling-XOR unsealer = {os.path.basename(upath)}")
    for line in ubody.splitlines():
        if "^" in line or ("+" in line and "local_" in line and "param_" in line):
            print(f"ghidra: body  -> {line.strip()}")

    calls = CALL_RE.findall(guard)
    if not calls:
        lk.fail("no (va, len, seed, step) unseal call site found in the Ghidra export")
    print(f"ghidra: {len(calls)} unseal call site(s) recovered from decompiled C")

    blobs = []
    for callee, va_s, n_s, seed_s, step_tok, _inner in calls:
        if callee not in os.path.basename(upath):
            continue
        va, n, seed = int(va_s, 16), int(n_s, 16), int(seed_s, 16)
        step = unescape_char(step_tok)
        raw = lk.read_va(a.exe, va, n)
        k, out = seed, bytearray()
        for b in raw:
            out.append(b ^ k)
            k = (k + step) & 0xFF
        out = bytes(out)
        blobs.append((va, n, seed, step, raw, out))
        print(f"r2:     {n} bytes @ {va:#x}  seed={seed:#04x} step={step:#04x}  -> {out.decode('latin-1')!r}")
        if not lk.printable(out):
            lk.fail(f"unseal at {va:#x} is not printable (seed={seed:#04x} step={step:#04x})")
    if not blobs:
        lk.fail("the recovered unsealer has no call site in the decompile")

    # --- 3. the integrity check decides which blob is the guarded one --------
    init, prime, target, cva, cn = find_integrity(files)
    print(f"ghidra: FNV-1a init={init:#x} prime={prime:#x} target={target:#x} over {cn} bytes @ {cva:#x}")
    guarded = [b for b in blobs if b[0] == cva and b[1] == cn]
    if len(guarded) != 1:
        lk.fail(f"the checksummed table {cva:#x}+{cn} is not among the unsealed blobs")
    got = fnv1a(guarded[0][4], init, prime)
    print(f"r2:     FNV-1a over the sealed bytes = {got:#x}  (target {target:#x})")
    if got != target:
        lk.fail(f"integrity mismatch: computed {got:#x}, program expects {target:#x}")
    key = guarded[0][5].decode()
    flags = [b[5].decode() for b in blobs if b is not guarded[0] and b[5].decode().startswith("FLAG{")]
    if len(flags) != 1:
        lk.fail(f"expected exactly one unsealed FLAG{{..}} blob, got {flags}")
    flag = flags[0]
    if key != a.expect_password:
        lk.fail(f"password {key!r} != expected {a.expect_password!r}")
    if flag != a.expect_flag:
        lk.fail(f"flag {flag!r} != expected {a.expect_flag!r}")

    # --- 4. the artifact, clean run: must accept the recovered key -----------
    rc, out, _ = lk.run_sample(a.exe, [key])
    lines = [l for l in out.splitlines() if l.strip()]
    print(f"clean:  rc={rc} {' | '.join(lines)}")
    if rc != 0 or "ACCEPTED" not in out or flag not in out:
        lk.fail("the clean run did not accept the recovered key")

    # --- 5. the negative control: same binary, same key, real debugger -------
    here = os.path.dirname(os.path.abspath(__file__))
    dbg = os.path.join(here, "..", "..", "tools", "dbg-presence.py")
    p = subprocess.run([sys.executable, dbg, a.exe, key], capture_output=True, text=True, timeout=60)
    dbg_out = p.stdout
    print(f"debug:  rc={p.returncode} {' | '.join(l for l in dbg_out.splitlines() if l.strip())}")
    if "PEB->BeingDebugged was set for the whole run" not in dbg_out:
        lk.fail("dbg-presence did not actually run the sample as a debuggee")
    if "ACCEPTED" not in dbg_out or flag in dbg_out:
        lk.fail("the debugged run did not lie -- the anti-debug guard is not firing, "
                "so this challenge is not teaching what it claims")
    if "decoy" not in dbg_out:
        lk.fail("the debugged run accepted but printed no decoy")

    # A second, sharper control: the guard accepts a *wrong* key too.
    p2 = subprocess.run([sys.executable, dbg, a.exe, "definitely-not-the-key"],
                        capture_output=True, text=True, timeout=60)
    print(f"debug:  wrong key under the debugger -> rc={p2.returncode} "
          f"{' | '.join(l for l in p2.stdout.splitlines() if l.strip() and not l.startswith('dbg-presence'))}")
    if p2.returncode != 0 or "ACCEPTED" not in p2.stdout:
        lk.fail("a wrong key was rejected under the debugger; the trap is not total")

    print(f"PASS c03 password={key!r} flag={flag!r}")
    print("     the same binary under a debugger printed the decoy and accepted a wrong key:")
    print("     a flag captured with a debugger attached is not evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
