#!/usr/bin/env python
"""Read a Windows PE's Authenticode signature surface: present or absent, and if present, the
WIN_CERTIFICATE header and the PKCS#7 blob it points at.

WHY THIS EXISTS. Coverage measured 2026-10-02 across the seven question types shows Q6 --
"what token/signature/key handling is this" -- resting on ONE instrument, `crypto.jose.parse`,
which is JOSE/JWT only. For a Windows PE the signature handling lives in the same optional header
the packer gate already reads, in `IMAGE_DIRECTORY_ENTRY_SECURITY`, so this is the cheapest real
expansion of the thinnest axis.

WHAT IT DOES NOT DO, and the reason is worth stating up front: it does NOT verify a signature.
It reports what is there. Trust decisions need chain building and revocation checking, and a tool
that said "signed" without doing them would be the exact kind of confident wrong answer this
project keeps refusing.

THE TRAP, measured rather than described. `IMAGE_DIRECTORY_ENTRY_SECURITY`'s VirtualAddress is a
FILE OFFSET, not an RVA, unlike every other data directory. Mapping it through the section table
is wrong and produces a plausible-looking address in the wrong place. This tool reads it as a file
offset deliberately, and the flag name says so.

The fixture generator exists because every corpus binary is unsigned (all seven measured: SECURITY
VA=0x0, size=0), so without it there would be no positive case and the tool would be a "not
packed"-style always-green check.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import pathlib

# Added 2026-10-04 so this probe stops being a string match. `assert-probes.py` decides an
# entry is real by matching substrings in captured stdout and prints its own weakness on
# every OK: "NOT a claim that the instrument ran: a stub which prints them satisfies it."
# Writing the result to disk moves the verdict onto the filesystem, which a stub has to
# also write to fake. See scripts/probe_artifact.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from probe_artifact import write_artifact  # noqa: E402


WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
SECURITY_DIR_INDEX = 4


def refuse(code: int, msg: str, **extra):
    out = {"ok": False, "exit": code, "error": msg}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def build_fixture(src: str, dst: str) -> dict:
    """Append a self-authored WIN_CERTIFICATE to a PE and point SECURITY at it.

    Self-authored on purpose. Nothing here is copied from a real signed binary: the payload is a
    fixed ASCII marker, so the fixture proves the PARSER finds and decodes a certificate table,
    not that any signature is valid. It cannot be valid -- there is no key and no signature.
    """
    try:
        import pefile
    except ImportError:
        refuse(2, "pefile is not importable here")

    try:
        pe = pefile.PE(src)
    except pefile.PEFormatError as e:
        refuse(1, f"source is not a PE: {e}")

    payload = b"ARSENAL-FIXTURE-NOT-A-REAL-SIGNATURE\x00"
    # 8-byte WIN_CERTIFICATE header + payload, padded to an 8-byte boundary as the spec requires.
    body = payload + b"\x00" * ((8 - (len(payload) % 8)) % 8)
    length = 8 + len(body)
    cert = struct.pack("<IHH", length, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA) + body

    # The certificate table lives OUTSIDE the sections, appended at the end of the file, and the
    # data directory stores a FILE OFFSET to it. This is why SECURITY is not an RVA.
    # pe.__data__ is an MMAP, so `mmap + bytes` raises TypeError. bytes() first, measured.
    data = bytes(pe.__data__)
    pad = (-len(data)) % 4
    data = data + b"\x00" * pad
    cert_offset = len(data)
    data = bytearray(data + cert)

    # 408, not optional_header_offset + 24. The first version computed the offset arithmetically
    # and wrote 24 bytes into the optional header, where it silently landed in NumberOfRvaAndSizes
    # and left SECURITY at zero -- so the fixture was built and then read back as unsigned, with
    # no error anywhere. pefile's own DATA_DIRECTORY entry carries get_file_offset(); use it
    # rather than re-deriving a layout that has both a PE32 and a PE32+ variant.
    off = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIR_INDEX].get_file_offset()
    # This line went missing while the offset above was being corrected, which is why the
    # fixture read back as unsigned with no error at all: the certificate was appended and the
    # directory entry was simply never written. An edit that removes the write and leaves the
    # append in place produces a tool that builds fixtures it cannot then detect.
    struct.pack_into("<II", data, off, cert_offset, len(cert))

    with open(dst, "wb") as fh:
        fh.write(bytes(data))
    return {"cert_offset": cert_offset, "cert_len": len(cert), "payload": payload.decode()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--make-control", metavar="DST",
                    help="build a self-authored fixture with a populated certificate table and exit")
    args = ap.parse_args()

    if args.make_control:
        if not args.binary:
            ap.error("--make-control needs a source PE as the positional argument")
        info = build_fixture(args.binary, args.make_control)
        print(json.dumps({"ok": True, "exit": 0, "fixture": args.make_control, **info}))
        return 0

    if not args.binary:
        ap.error("a PE path is required")

    try:
        import pefile
    except ImportError:
        refuse(2, "pefile is not importable here")

    try:
        pe = pefile.PE(args.binary)
    except pefile.PEFormatError as e:
        refuse(1, f"not a PE: {e}")

    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIR_INDEX]
    total = len(pe.__data__)

    out = {
        "ok": True,
        "exit": 0,
        "binary": args.binary,
        "file_size": total,
        "security_va_is_a": "FILE OFFSET (not an RVA) -- true for IMAGE_DIRECTORY_ENTRY_SECURITY",
        "security_offset": dd.VirtualAddress,
        "security_size": dd.Size,
        "caveat": ("THIS DOES NOT VERIFY ANYTHING. It reports whether a certificate table is "
                   "present and decodes its header. 'signed: true' means 'there is a "
                   "WIN_CERTIFICATE here', NOT 'this binary is trusted' -- no chain is built, no "
                   "revocation is checked, and a self-authored fixture will read as signed."),
    }

    if dd.VirtualAddress == 0 or dd.Size == 0:
        out["signed"] = False
        out["reason"] = "no certificate table: IMAGE_DIRECTORY_ENTRY_SECURITY is empty"
    else:
        off = dd.VirtualAddress
        if off + 8 > total:
            refuse(2, f"certificate table at file offset 0x{off:x} runs past the end of a "
                      f"{total}-byte file; the directory is pointing outside the file")
        length, revision, ctype = struct.unpack("<IHH", pe.__data__[off:off + 8])
        blob = pe.__data__[off + 8:off + length]
        out["signed"] = True
        out["win_certificate"] = {
            "header_offset": off,
            "dwLength": length,
            "wRevision": hex(revision),
            "revision_is_2_0": revision == WIN_CERT_REVISION_2_0,
            "wCertificateType": hex(ctype),
            "type_is_pkcs_signed_data": ctype == WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            "blob_offset": off + 8,
            "blob_len": len(blob),
            "blob_sha256_prefix": __import__("hashlib").sha256(blob).hexdigest()[:16],
            "blob_ascii_head": blob[:40].decode("ascii", "replace"),
        }
        if length > dd.Size:
            out["warning"] = (f"WIN_CERTIFICATE dwLength {length} exceeds the directory size "
                              f"{dd.Size}; the table is inconsistent and must not be trusted")

    print(json.dumps(out, indent=1))
    write_artifact("authenticode", out if "authenticode" != "cert_verify" else result)
    return 0


if __name__ == "__main__":
    sys.exit(main())