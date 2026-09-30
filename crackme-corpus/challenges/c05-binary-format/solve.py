#!/usr/bin/env python3
"""c05 solver -- recover a packed record layout, then read the blob with it.

Neither tool alone is enough, and that is the point of the exercise:

  * Ghidra headless gives the *semantics*. It shows which function checks the
    magic, which one tests the decoy bit, which byte range each hash consumes,
    and where the record base pointer comes from. Those are constants with
    meaning, and a decompiler is the cheapest way to read them.
  * Ghidra cannot give the *layout* here, and pretending otherwise is the trap.
    At /Od the reads compile to `add rax, <imm>` / `imul rax, rax, <n>` feeding
    a byte-reader helper, and the decompiler renders them as typed-pointer
    arithmetic (`param_1 + 7` on an `undefined4 *`), which is not a byte offset.
    So the on-disk field offsets come from radare2's disassembly, where each
    read is an explicit displacement.
  * radare2 also supplies the blob's bytes at the address Ghidra reported, so
    the data is read out of the compiled image rather than transcribed.

Layout recovered, in this order:
    record size     <- the size compare guarding the reader
    field offsets   <- displacements in front of each read call
    field widths    <- how many byte loads each reader helper performs
    digest range    <- the length immediate in the per-record hash
    key range       <- (fold base - record base), length from the fold call
    decoy bit       <- the mask in the validity test
    magic/version   <- the compared immediates

Then the solver parses the blob, checks every record against its own digest, and
folds the live ones into the key. The binary is the judge.

Three controls, because a struct-recovery claim is easy to fake: a wrong record
size, a key range that wrongly swallows the salt, and a parse that forgets the
decoys must each produce a different key. If any of them agrees with the right
answer, the layout is not actually load-bearing and the solve fails.

Exit 0 only when the recovered layout, the derived password, and the binary all
agree and all three controls misbehave as they must.
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import labkit as lk  # noqa: E402

ADDR_SUFFIX_RE = re.compile(r"_([0-9a-fA-F]{8,})\.c$")
BYTE_LOAD_RE = re.compile(r"movzx \w+, byte \[")
# A field read is "set up an offset, then read". At /Od the offset is either an
# `add rax, IMM` or an `imul rax, rax, IMM`, and r2 appends a `; decimal` comment
# to the immediate -- so a line-anchored pattern silently loses fields. Walk the
# disassembly instead: every read is a call to a reader helper, and the most
# recent offset-setting instruction before it is that field's on-disk offset.
READER_CALL_RE = re.compile(r"call (fcn\.\w+)")
OFFSET_SET_RE = re.compile(r"(?:add rax,|imul rax, rax,) (0x[0-9a-fA-F]+|\d+)\b")
SIZE_CMP_RE = re.compile(r"cmp dword \[var_\w+\], (0x[0-9a-fA-F]+|\d+)")
HASH_CALL_RE = re.compile(r"(\w+)\(\s*\w+\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
FOLD_CALL_RE = re.compile(r"(\w+)\(\s*\(?\s*longlong\s*\)?\s*\(?\s*&\w+_([0-9a-fA-F]+)\s*\+\s*\w+\s*\)?\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,")
RECORD_BASE_RE = re.compile(r"&\w+_([0-9a-fA-F]+)\s*\+\s*\w+\s*\)")
MASK_RE = re.compile(r"&\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*==\s*0")
VERSION_CMP_RE = re.compile(r"==\s*'(\\x[0-9a-fA-F]{2}|\\.|[^']+)'\s*\)")
DECOY_TABLE_RE = re.compile(r"static const unsigned char (\w+)\[(\d+)\]\s*=\s*\{([^}]*)\}")
SEAL_CALL_RE = re.compile(r"\(\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*'(.)'\s*,")


def addr_of(path):
    m = ADDR_SUFFIX_RE.search(os.path.basename(path))
    if not m:
        raise lk.ToolError(f"cannot read an address out of {path!r}")
    return int(m.group(1), 16)


def pick(files, *needles, **kw):
    """The one decompiled function containing every needle. `what` names it."""
    what = kw.pop("what", "function")
    hits = []
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if all(n in t for n in needles):
            hits.append((f, t))
    if len(hits) != 1:
        raise lk.ToolError(f"expected exactly one {what}, matched "
                           f"{[os.path.basename(f) for f, _ in hits]}")
    return hits[0]


def reader_widths(exe, addrs):
    """How many bytes each read helper actually loads. That is its field width."""
    widths = {}
    for a in addrs:
        d = lk.r2("aaa", f"s {a:#x}", "pdf", exe=exe)
        n = len(BYTE_LOAD_RE.findall(d))
        if n in (1, 2, 4, 8):
            widths[a] = n
    return widths


def recover_layout(exe, files):
    # --- semantics, from the decompile --------------------------------------
    main_f, main_t = pick(files, "s_C05__08X_", what="the driver that renders the key")
    check_f, check_t = pick(files, "0xc0de", "& 2)", what="the record validity test")
    reader_f, reader_t = None, None

    # The reader is the function the driver calls with (record, size, out).
    # Locate it by asking Ghidra for the function whose body has the size guard.
    reader_f, reader_t = None, None
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if "param_3" in t and t.count("param_3") >= 6 and "case" not in t:
            if re.search(r"0x[0-9a-f]+ < param_2", t):
                reader_f, reader_t = f, t
                break
    if reader_f is None:
        lk.fail("cannot find the record reader in the decompile")

    hash_f, hash_t = None, None
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        if "0x811c9dc5" in t and t.count("(") <= 3:
            hash_f, hash_t = f, t
    if hash_f is None:
        lk.fail("cannot find the per-record hash in the decompile")
    hm = HASH_CALL_RE.search(hash_t)
    if not hm:
        lk.fail("cannot read the digest length from the per-record hash")
    hash_len = int(hm.group(2), 0)
    hash_init = int(hm.group(3), 0)
    hash_off = 0                      # the call passes the record base unchanged
    print(f"ghidra: digest = fnv1a(init={hash_init:#x}, len={hash_len}) over "
          f"record[{hash_off}..{hash_off + hash_len - 1}]")

    # The key range: the driver folds from a base that is offset from the record
    # base, over a length. Both are recoverable from the call and from the
    # record-base expression used a few lines earlier.
    fm = FOLD_CALL_RE.search(main_t)
    bm = RECORD_BASE_RE.search(main_t)
    if not fm or not bm:
        lk.fail("cannot find the key-material fold in the driver")
    fold_base = int(fm.group(2), 16)
    rec_base = int(bm.group(1), 16)
    key_len = int(fm.group(3), 0)
    key_off = fold_base - rec_base
    if key_off < 0:
        lk.fail("the fold base precedes the record base; layout recovery is wrong")
    print(f"ghidra: key material = record[{key_off}..{key_off + key_len - 1}] "
          f"(fold base {fold_base:#x} vs record base {rec_base:#x})")

    dm = MASK_RE.search(check_t)
    if not dm:
        lk.fail("cannot find the decoy flag mask in the validity test")
    decoy_bit = int(dm.group(1), 0)
    vm = VERSION_CMP_RE.search(check_t)
    version = ord(vm.group(1).encode().decode("unicode_escape")) if vm else None
    print(f"ghidra: decoy flag bit {decoy_bit:#04x}, expected version {version}")

    # --- layout, from the disassembly ---------------------------------------
    rva = addr_of(reader_f)
    dis = lk.r2("aaa", f"s {rva:#x}", "pdf", exe=exe)
    sm = SIZE_CMP_RE.search(dis)
    if not sm:
        lk.fail("cannot find the record-size guard in the reader's disassembly")
    rec_size = int(sm.group(1), 0)

    # Walk the reader's disassembly once, tracking the pending offset. A call to
    # a known reader helper consumes it; a call with no pending offset is a read
    # of the field at 0.
    # Every callee of the reader is measured by how many bytes it actually
    # loads; that count *is* the field width. Callees that are not plain
    # byte-gatherers fall out on their own, because their bodies are not runs
    # of byte loads.
    callees = sorted({int(c.split(".")[-1], 16) for c in re.findall(r"call (fcn\.\w+)", dis)})
    widths = reader_widths(exe, callees)

    fields, pending, seen_calls = {}, None, []
    for line in dis.splitlines():
        om = OFFSET_SET_RE.search(line)
        if om:
            pending = int(om.group(1), 0)
            continue
        cm = READER_CALL_RE.search(line)
        if not cm:
            continue
        a = int(cm.group(1).split(".")[-1], 16)
        if a not in widths:
            continue
        off = 0 if pending is None else pending
        pending = None
        seen_calls.append(a)
        fields.setdefault(off, widths[a])
    if len(fields) < 6:
        lk.fail(f"recovered only {len(fields)} field offsets from the disassembly: "
                f"{sorted(fields.items())}")
    print(f"r2:     record size {rec_size}; field offsets "
          f"{', '.join(f'{o}:{w}B' for o, w in sorted(fields.items()))}")

    return {
        "fields": fields, "rec_size": rec_size, "hash_off": hash_off,
        "hash_len": hash_len, "hash_init": hash_init, "key_off": key_off,
        "key_len": key_len, "decoy_bit": decoy_bit, "version": version,
        "blob_sym": rec_base, "reader": rva,
    }


def fnv1a(data, h):
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def parse(blob, lay, count, skip_decoys=True, rec_size=None, key_len=None):
    size = rec_size if rec_size is not None else lay["rec_size"]
    klen = key_len if key_len is not None else lay["key_len"]
    digest_off = lay["hash_off"] + lay["hash_len"]      # the digest sits right after
    body = blob[8:]
    h, live, why = lay["hash_init"], 0, []
    for i in range(count):
        rec = body[i * size:(i + 1) * size]
        if len(rec) < size:
            why.append((i, "short"))
            continue
        if struct.unpack_from("<H", rec, 0)[0] != 0xC0DE or rec[2] != lay["version"]:
            why.append((i, "magic/version"))
            continue
        if skip_decoys and (rec[3] & lay["decoy_bit"]):
            why.append((i, "decoy"))
            continue
        if digest_off + 4 > len(rec):
            why.append((i, "no digest"))
            continue
        stored = struct.unpack_from("<I", rec, digest_off)[0]
        if fnv1a(rec[lay["hash_off"]:lay["hash_off"] + lay["hash_len"]], lay["hash_init"]) != stored:
            why.append((i, "digest"))
            continue
        live += 1
        h = fnv1a(rec[lay["key_off"]:lay["key_off"] + klen], h)
    return h, live, why


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--ghidra-out", required=True)
    ap.add_argument("--expect-password", required=True)
    a = ap.parse_args()

    lk.banner("c05", "binary format: recover the packed record layout, then read it")
    files = lk.ghidra_files(a.ghidra_out)
    lay = recover_layout(a.exe, files)

    # Ghidra gave us the record base; the header is the fixed-size block that
    # precedes it, so the whole blob is one read from there.
    rec_base = lay["blob_sym"]
    hdr_va = rec_base - 8
    header = lk.read_va(a.exe, hdr_va, 8)
    magic = struct.unpack_from("<H", header, 0)[0]
    count = header[3]
    blob = lk.read_va(a.exe, hdr_va, 8 + count * lay["rec_size"])
    print(f"r2:     header @ {hdr_va:#x}: magic {magic:#06x} version {header[2]} "
          f"count {count}; blob {len(blob)} bytes")
    if magic != 0xC0DE:
        lk.fail("the blob header does not carry the expected magic")
    if header[2] != lay["version"]:
        lk.fail(f"blob version {header[2]} != the version the checker expects")

    key, live, why = parse(blob, lay, count)
    print(f"r2:     {count} declared, {live} live, rejected {why}")
    if live < 4:
        lk.fail(f"only {live} records validated; the recovered layout is wrong")
    password = f"C05-{key:08X}"
    print(f"r2:     key = fnv1a:{key:08x} -> password {password!r}")
    if password != a.expect_password:
        lk.fail(f"derived password {password!r} != expected {a.expect_password!r}")

    # --- controls ------------------------------------------------------------
    wk, wl, _ = parse(blob, lay, count, rec_size=lay["rec_size"] + 4)
    print(f"control: record size {lay['rec_size'] + 4} -> {wl} live, fnv1a:{wk:08x}")
    if wl >= live:
        lk.fail("a wrong record size validated as many records; the size is not "
                "being recovered from the binary")

    sk, _, _ = parse(blob, lay, count, key_len=lay["key_len"] + 2)
    print(f"control: key range widened over the 2 salt bytes -> fnv1a:{sk:08x}")
    if sk == key:
        lk.fail("widening the hashed range changed nothing; the range is not load-bearing")

    kk, kl, _ = parse(blob, lay, count, skip_decoys=False)
    print(f"control: decoy records included -> {kl} live, fnv1a:{kk:08x}")
    if kk == key:
        lk.fail("including the decoy records changed nothing; they are not decoys")

    # --- the artifact decides ------------------------------------------------
    rc, out, _ = lk.run_sample(a.exe, [password])
    print(f"binary:  rc={rc} {' | '.join(l.strip() for l in out.splitlines() if l.strip())}")
    if rc != 0 or "ACCEPTED" not in out:
        lk.fail("the binary rejected the layout-derived password")

    decoy = recover_sealed_decoy(files)
    if decoy:
        rc2, out2, _ = lk.run_sample(a.exe, [decoy])
        print(f"binary:  sealed decoy {decoy!r} -> rc={rc2} "
              f"{out2.splitlines()[0]!r}")
        if rc2 == 0:
            lk.fail("the binary accepted the sealed decoy; it is meant to be a trap")

    f = lay["fields"]
    print(f"PASS c05 password={password!r}")
    print(f"     layout from two tools: {len(f)} fields "
          f"({', '.join(f'{o}:{w}B' for o, w in sorted(f.items()))}), "
          f"{lay['rec_size']}-byte records, digest over "
          f"[{lay['hash_off']}..{lay['hash_off'] + lay['hash_len'] - 1}], key over "
          f"[{lay['key_off']}..{lay['key_off'] + lay['key_len'] - 1}], "
          f"decoy bit {lay['decoy_bit']:#04x}")
    return 0


def recover_sealed_decoy(files):
    """Unseal the decoy table so we can prove the binary rejects it."""
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        m = DECOY_TABLE_RE.search(t)
        if not m:
            continue
        blob = bytes(int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(3)))
        call = None
        for g in files:
            gt = open(g, encoding="utf-8", errors="replace").read()
            c = SEAL_CALL_RE.search(gt)
            if c and int(c.group(1), 0) and int(c.group(2), 0):
                call = c
                break
        if call is None:
            return None
        seed, step = int(call.group(1), 0), ord(call.group(3).encode().decode("unicode_escape"))
        k, out = seed, bytearray()
        for b in blob:
            out.append(b ^ k)
            k = (k + step) & 0xFF
        try:
            return out.decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


if __name__ == "__main__":
    sys.exit(main())
