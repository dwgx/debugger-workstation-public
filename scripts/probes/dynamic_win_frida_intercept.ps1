# VERBATIM. Added 2026-10-05.
#
# This file exists so the capability's probe can leave an artifact. `assert-probes.py` writes a
# registry command byte-for-byte into a .ps1 and runs `powershell -File`, and its own docstring
# records that two earlier designs which sniffed for PowerShell markers and re-wrapped in
# `powershell -Command "..."` missed 8 commands and destroyed every command containing a double
# quote. So the one-liner was NOT re-quoted -- it was MOVED here unchanged, and the registry now
# names this file.
#
# The wrapper that invokes it (scripts/probe_wrapper.py) records the command, the exit code, the
# stdout, the stderr and the duration, and passes the child's exit code through, so adding it
# cannot turn a red into a green. It does not judge the output; that stays with assert-probes.

$py='.\Mobile-Android\objection\.venv\Scripts\python.exe'; $d=Join-Path $env:TEMP 'fridagate'; New-Item -ItemType Directory -Force -Path $d | Out-Null; Copy-Item '.\crackme-corpus\out\c01-stringobf.exe' (Join-Path $d 'target.exe'); & $py '.\native-lab\tools\frida_spawn_gate.py' (Join-Path $d 'target.exe') positive
