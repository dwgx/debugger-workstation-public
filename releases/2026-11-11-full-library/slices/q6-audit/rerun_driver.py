# OWNER: researcher-q6 | setukou-20261111/v5/slices/q6-audit/rerun_driver.py
"""Q6 independent re-run driver (v2 — FIXED): re-run each ACCEPTED slice's exact
ONE ## Verify command from W. Commands are Python invocations with optional
timeout.exe prefix; we execute them DIRECTLY (no `cmd /c`, which swallowed the
command and produced a FALSE exit=0 banner). We enforce Q6's OWN bounded 90s
envelope via subprocess timeout. Capture stdout/stderr/exit/UTC into
receipts/<slice>-rerun.txt. READ-ONLY except Q6's own receipts dir.
"""
from __future__ import annotations
import datetime, pathlib, subprocess, sys

W = pathlib.Path("F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110")
V5 = W / "setukou-20261111/v5"
OUT = V5 / "slices/q6-audit/receipts"
OUT.mkdir(parents=True, exist_ok=True)
PY = sys.executable

# EXACT command strings copied verbatim from each slice REPORT.md ## Verify block.
CMDS = {
    "Q1": '"C:/Program Files/Git/usr/bin/timeout.exe" 120 python -X utf8 setukou-20261111/v5/slices/q1-completeness/verify.py',
    "Q3": 'python setukou-20261111/v5/slices/q3-missing/verify.py',
    "Q4": '"C:/Program Files/Git/usr/bin/timeout.exe" 30 python -X utf8 -B setukou-20261111/v5/slices/q4-wrappers/verify.py',
    "Q5": '"C:/Program Files/Git/usr/bin/timeout.exe" 120 python -X utf8 -B setukou-20261111/v5/slices/q5-absorption/verify.py',
}

def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def to_argv(cmd):
    """Translate a slice ## Verify line (shlex-like, Windows paths) into argv.
    The 'python' token maps to this interpreter; leading timeout.exe N is kept
    but Q6 ALSO wraps in its own subprocess timeout=90 (bounded envelope)."""
    import shlex
    toks = shlex.split(cmd, posix=False)
    # strip surrounding quotes shlex(posix=False) may keep on Windows paths
    toks = [t.strip('"') for t in toks]
    if toks and toks[0].lower().endswith("timeout.exe"):
        toks = toks[2:]  # drop timeout.exe + N; Q6 applies its own 90s bound
    if toks and toks[0] == "python":
        toks[0] = PY
    return toks

for name, cmd in CMDS.items():
    started = utc()
    argv = to_argv(cmd)
    try:
        p = subprocess.run(argv, cwd=str(W), capture_output=True, timeout=90)
        rc = p.returncode
        so = p.stdout.decode("utf-8", errors="replace")
        se = p.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        rc = 124
        so = (e.stdout or b"").decode("utf-8", errors="replace")
        se = (e.stderr or b"").decode("utf-8", errors="replace") + "\n[Q6 driver 90s HARD-TIMEOUT]"
    finished = utc()
    body = [
        "OWNER: researcher-q6 | setukou-20261111/v5/slices/q6-audit/receipts/",
        "Q6 independent re-run of " + name + " ONE ## Verify (DIFFERENT actor)",
        "started_utc      : " + started,
        "finished_utc     : " + finished,
        "cwd              : " + str(W),
        "command          : " + cmd,
        "executed_argv    : " + repr(argv),
        "q6_envelope      : subprocess timeout=90s (bounded); no cmd /c wrapper",
        "exit             : " + str(rc),
        "----- STDOUT -----",
        so.rstrip("\n"),
        "----- STDERR -----",
        se.rstrip("\n") if se.strip() else "(empty)",
        "----- END -----",
    ]
    (OUT / (name.lower() + "-rerun.txt")).write_text("\n".join(body) + "\n", encoding="utf-8")
    print(f"{name} exit={rc} stdout_lines={len(so.splitlines())} stderr_lines={len(se.splitlines())}")
