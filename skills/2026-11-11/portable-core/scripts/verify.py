# OWNER: SpecOptimizer | package/scripts/verify.py
"""Re-runnable verifier entry for harnesses that only load scripts/ (stdlib only).

Delegates to the package ONE ## Verify (package/verify.py -> package/tests/verify.py).
Exit code is the package verifier's exit code: 0 = PASS, 1 = FAIL, 2 = payload missing.
"""
import pathlib
import subprocess
import sys

PKG = pathlib.Path(__file__).resolve().parent.parent      # .../package
ROOT = PKG.parent                                         # workspace root
ENTRY = PKG / "verify.py"


def main():
    if not ENTRY.is_file():
        print("MISSING=%s" % ENTRY)
        return 2
    print("entry=%s (delegates to package/tests/verify.py)" % ENTRY.name)
    r = subprocess.run([sys.executable, "-X", "utf8", str(ENTRY)], cwd=str(ROOT))
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
