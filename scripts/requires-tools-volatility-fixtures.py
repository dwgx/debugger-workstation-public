"""Fixture builder for the volatility mutation proof. PROMOTED into the repository 2026-10-03.

Copies the REAL registry to %TEMP% and plants ONE tool entry of ONE capability, so the check can
be run against a registry that does not exist in the repo. Nothing here touches the git tree.

Every fixture uses a probe whose output REALLY changes between two invocations on this host. That
is the measurement, not a mock: the check claims to detect volatility, so the fixture has to have
some, produced by the OS or by a real counter file rather than by a hardcoded expectation.

  A  volatile-UNMARKED  expect quotes a stable span; the probe also prints a moving one beside it
                        -> must be VOLATILE
  B  stable-control     expect quotes a stable span of a probe that prints NOTHING volatile
                        -> must NOT be flagged (this is the false side)
  C  volatile-MARKED    the same moving span wrapped in {volatile:<why>} -> must PASS, and the
                        marker must be reported as measured-moving, so it is not a free pass
  D  lucky-first-run     the moving span is quoted as a LITERAL and the first run really does
                        match it while later runs do not. This is the exact real-world failure:
                        a substring check passes on the run the author copied from. -> VOLATILE
  E  unjustified-MARKER  {volatile:...} over a region that never moves -> VOLATILE-UNJUSTIFIED,
                        which is what stops the marker from becoming an excuse
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# PROMOTED 2026-10-03. The proof lived in %TEMP% and therefore in a transcript, which is the
# defect this file was written to catch: a mutation the next window cannot re-run is a story.
# REPO was a hardcoded absolute path; it is now derived, so the fixtures work in any clone.
REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "manifests" / "capabilities.json"
TMP = Path(os.environ["TEMP"])
HOST = "native.signature.certverify"        # state=observed, so its probes really execute

# A stable token, then a pid and a nanosecond clock that differ on every invocation.
MOVING_PROBE = "python -c \"import os,time;print('stable-token-abc123',os.getpid(),time.time_ns())\""
# A stable token and NOTHING else: no moving span exists to be found.
STATIC_PROBE = "python -c \"print('stable-token-abc123')\""
# `stable-token-abc123 <n>`, n incrementing per invocation through a counter file in TEMP.
COUNTER = TMP / "fx_counter.txt"
COUNTER_PROBE = (
    "python -c \"import pathlib;p=pathlib.Path(r'%s');"
    "n=int(p.read_text()) if p.exists() else 0;p.write_text(str(n+1));"
    "print('stable-token-abc123',n)\"" % COUNTER
)


def load_registry():
    """The integrator edits manifests/capabilities.json concurrently, so a transient
    JSONDecodeError here is THEIR write in flight, not a defect in this fixture. Retry, then fall
    back to git's index copy. Never edit the real registry to make a fixture work."""
    last = ""
    for _ in range(6):
        try:
            return json.load(open(SRC, encoding="utf-8"))["capabilities"]
        except json.JSONDecodeError as e:
            last = str(e)
            time.sleep(3)
    idx = subprocess.run(["git", "show", ":manifests/capabilities.json"], cwd=REPO,
                         capture_output=True, text=True, timeout=60)
    if idx.returncode == 0:
        print(f"NOTE: live registry unparseable ({last}); built from the git INDEX copy")
        return json.loads(idx.stdout)["capabilities"]
    raise SystemExit(f"fixture: registry unparseable and no index copy: {last}")


def plant(caps, expect, probe, which=0):
    """Point the `which`-th tool entry of HOST at this probe/expect, leaving its peers alone."""
    for c in caps:
        if c.get("id") != HOST:
            continue
        tools = (c.get("requires") or {}).get("tools") or []
        if len(tools) <= which:
            raise SystemExit(f"fixture: {HOST} has no tool entry #{which}")
        t = tools[which]
        t["probe"] = probe
        t["expect"] = expect
        for k in ("verify", "verify_note", "expect_exit", "expect_exit_note", "note"):
            t.pop(k, None)
        return t
    raise SystemExit(f"fixture: no capability {HOST}")


def write(name, caps):
    p = TMP / name
    p.write_text(json.dumps({"capabilities": caps}, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def build():
    base = load_registry()
    made = []

    a = json.loads(json.dumps(base))
    plant(a, "stable-token-abc123", MOVING_PROBE)
    made.append(("A volatile-UNMARKED", write("fx_A_unmarked.json", a)))

    b = json.loads(json.dumps(base))
    plant(b, "stable-token-abc123", STATIC_PROBE)
    made.append(("B stable-control", write("fx_B_stable.json", b)))

    c = json.loads(json.dumps(base))
    plant(c, "stable-token-abc123 {volatile:pid and ns clock differ every invocation}", MOVING_PROBE)
    made.append(("C volatile-MARKED", write("fx_C_marked.json", c)))

    # D: run the counter probe once so the expect can quote the value the FIRST run will print.
    COUNTER.unlink(missing_ok=True)
    first = subprocess.run(COUNTER_PROBE, shell=True, cwd=REPO, capture_output=True, text=True,
                           timeout=60).stdout.strip()
    if not first.endswith(" 0"):
        raise SystemExit(f"fixture D: first counter run was {first!r}, expected it to end in ' 0'")
    d = json.loads(json.dumps(base))
    plant(d, first, COUNTER_PROBE)
    made.append(("D lucky-first-run", write("fx_D_lucky.json", d)))

    e = json.loads(json.dumps(base))
    # No trailing space: the region after the last anchor is the tail of the line, and a trailing
    # space would only be an absent anchor (UNMATCHED), which would test nothing.
    plant(e, "stable-token-abc123{volatile:this region never actually moves}", STATIC_PROBE)
    made.append(("E unjustified-MARKER", write("fx_E_unjustified.json", e)))

    for label, path in made:
        print(f"{label:22s} -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(build())

# --- how to run the whole proof -------------------------------------------------
#   python scripts/requires-tools-volatility-fixtures.py --all
# builds every fixture under %TEMP% and prints the command to run each one. Nothing here
# touches the git tree; every registry it writes is a COPY under %TEMP%.
