# OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/check.py
"""Hash-lock gate for the SYNTHETIC public learning kit.

ONE command (from this dir): python check.py
Read-only: opens files in 'rb'/'r' only, writes nothing, no network, no imports
outside the standard library, no real private paths, no credentials. The negative
control flips ONE byte IN MEMORY and requires the lock to reject it. The package
is proposed as a NEW public-repo subdirectory learning-kit/ (it never overwrites
an existing root file).
"""
import hashlib
import pathlib

BASE = pathlib.Path(__file__).resolve().parent
EX = BASE / "examples"


def fixture_names():
    """Denominator: every *.txt fixture present on disk, sorted for determinism."""
    return sorted(p.name for p in EX.glob("*.txt"))


def sidecar(name):
    """Recorded sha256 for one fixture (static text, ASCII hex)."""
    return (EX / (name + ".sha256")).read_text(encoding="ascii").strip()


def hash_lock(overrides=None):
    """Return (checked, matched, ok).

    overrides maps {filename: bytes} injected IN MEMORY only, never written.
    Recomputes sha256 from bytes for every fixture and compares to its sidecar.
    """
    overrides = overrides or {}
    checked = 0
    matched = 0
    for name in fixture_names():
        data = overrides.get(name)
        if data is None:
            data = (EX / name).read_bytes()
        got = hashlib.sha256(data).hexdigest()
        checked += 1
        if got == sidecar(name):
            matched += 1
    return checked, matched, (checked > 0 and checked == matched)


def main():
    checked, matched, ok = hash_lock()
    names = fixture_names()
    tamper_caught = 0
    if names:
        first = names[0]
        bad = bytearray((EX / first).read_bytes())
        bad[0] ^= 0x01  # one byte, in memory
        _, _, still_ok = hash_lock({first: bytes(bad)})
        tamper_caught = 0 if still_ok else 1
    print("checked=%d matched=%d hash_lock_ok=%d tamper_caught=%d"
          % (checked, matched, int(ok), tamper_caught))
    verdict = "GREEN" if (ok and tamper_caught == 1) else "RED"
    print("VERDICT=" + verdict)
    return 0 if verdict == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
