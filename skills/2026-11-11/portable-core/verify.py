# OWNER: parent (took over stalled PackageDesign slice) | package/verify.py
"""Package-level ONE ## Verify: delegates to tests/verify.py, run from ROOT."""
import subprocess, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent
r = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "tests/verify.py")],
                   cwd=str(ROOT), capture_output=False)
sys.exit(r.returncode)
