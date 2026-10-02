#!/usr/bin/env python
"""Independently parse a PE's certificate bytes with OpenSSL and say whether they are DER.

WHY THIS EXISTS. native.pe.authenticode reads the SECURITY directory with pefile and reports
the WIN_CERTIFICATE header. Its own does_not_prove says it VERIFIES NOTHING, and that caution
turns out to be load-bearing in a way nobody had measured. Pointed at this repository's own signed
fixture it reports dwLength=48, wRevision=0x200, revision_is_2_0=true -- a plausible, cheerful,
structurally-consistent header for a certificate that is not a certificate.

MEASURED 2026-10-02, the disagreement: extracting the 40-byte body and handing it to
`openssl asn1parse -inform DER` fails with

    error:0680009B:asn1 encoding routines:ASN1_get_object:too long
    Error in encoding                                                              exit 1

and the body is literally the ASCII string ARSENAL-FIXTURE-NOT-A-REAL-SIGNATURE. So one
instrument reads a valid-looking header off bytes that a second, independent implementation
rejects outright. **That disagreement is the whole reason a second instrument exists**, and it is
not visible from either instrument alone: pefile is not wrong about the header, and OpenSSL is
not wrong about the DER. Both are right, and only together do they say the thing that matters.

This answers a question no other capability on Q6.crypto answers: not "is there a certificate
table" (native.pe.authenticode) but "are the bytes in it a certificate".
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

SECURITY_DIR = 4          # IMAGE_DIRECTORY_ENTRY_SECURITY
WIN_CERT_REVISION_2_0 = 0x0200
CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


def fail(code: int, error: str, **extra):
    out = {"ok": False, "exit": code, "error": error}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(code)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    args = ap.parse_args()

    try:
        import pefile  # noqa: PLC0415 - imported here so a missing dep is a clean refusal
    except ImportError as e:
        fail(2, f"pefile unavailable: {e}")

    # The SECURITY directory stores a FILE OFFSET, not an RVA. Reading it as section-relative
    # yields a plausible number and nothing else -- which is why this tool resolves it the same
    # way native.pe.authenticode does and says so, rather than quietly agreeing with it.
    try:
        pe = pefile.PE(args.binary, fast_load=True)
        pe.parse_data_directories(directories=[SECURITY_DIR])
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[SECURITY_DIR]
    except Exception as e:  # noqa: BLE001
        fail(2, f"not a PE: {e}")

    if not entry.VirtualAddress or not entry.Size:
        print(json.dumps({
            "ok": True, "exit": 0, "binary": args.binary, "verifiable": None,
            "reason": "no SECURITY directory: this binary carries no certificate to verify",
            "note": "null is the honest answer here, not false. 'there is nothing to verify' and "
                    "'what is there is not valid' are different findings and must not share a value.",
        }))
        return 0

    off = entry.VirtualAddress
    raw = open(args.binary, "rb").read()
    if off + 8 > len(raw):
        fail(2, f"certificate table at file offset 0x{off:x} runs past the end of a "
                f"{len(raw)}-byte file", security_offset=off)
    dw_length, w_revision, w_type = struct.unpack("<IHH", raw[off:off + 8])
    if off + dw_length > len(raw):
        fail(2, f"dwLength {dw_length} at offset 0x{off:x} runs past the end of a {len(raw)}-byte file",
            security_offset=off)
    body = raw[off + 8: off + dw_length]

    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
        fh.write(body)
        der = fh.name
    try:
        p = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", der],
                           capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(der)

    parsed = p.returncode == 0
    result = {
        "ok": True, "exit": 0, "binary": args.binary,
        "security_offset": off,
        "win_certificate": {"dwLength": dw_length, "wRevision": hex(w_revision),
                            "wCertificateType": hex(w_type),
                            "revision_is_2_0": w_revision == WIN_CERT_REVISION_2_0,
                            "is_pkcs_signed_data": w_type == CERT_TYPE_PKCS_SIGNED_DATA,
                            "body_bytes": len(body)},
        "der_parsed": parsed,
        "verifiable": parsed,
    }
    if parsed:
        result["asn1_head"] = (p.stdout or "").splitlines()[:6]
        result["caveat"] = ("ASN.1 PARSING IS NOT TRUST. OpenSSL read the structure; nothing here "
                            "checks that the chain roots anywhere, that the digest matches the file, "
                            "or that the signer is who it claims. 'der_parsed: true' means the bytes "
                            "are well-formed ASN.1, which is a far weaker statement than signed.")
    else:
        err = " ".join((p.stderr or "").split())[:200]
        result["reason"] = err
        result["caveat"] = ("THE HEADER IS STILL VALID-LOOKING AND THE BYTES ARE STILL NOT A "
                            "CERTIFICATE. native.pe.authenticode reports dwLength and wRevision off "
                            "exactly these bytes and is not wrong to; this is the instrument that "
                            "checks the next layer down.")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())