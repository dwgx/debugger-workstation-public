#!/bin/bash
# Full-station smoke: one command that runs every capability probe the registry claims.
# Read-only. Run from the repo root; this script deliberately does not cd.
#
# Interpreters are addressed by absolute path, not by PATH. Two reasons, both learned
# the hard way on this box:
#
#   1. The shell that launches this hands a spawned bash a Windows-formatted PATH --
#      semicolon-separated, D:\Software\... -- which bash reads as one enormous invalid
#      token, so node/python/powershell all resolve to "command not found" and every
#      probe reports rc=127.
#   2. Exporting a POSIX PATH inside the script is not enough on its own: this file goes
#      through CRLF conversion, so a trailing \r lands inside the value.
#
# A smoke test that fails 15/15 for a PATH reason is worse than no smoke test, because
# the red looks like real breakage. Resolve the binaries or do not report a verdict.

NODE="/d/Software/Developer/nodejs/node.exe"
PY="/d/Software/Developer/Python314/python.exe"
PS="/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

pass=0; fail=0; declare -a RESULTS

run() {
  local name="$1"; shift
  local cmd="$*"
  local out rc
  out=$(eval "$cmd" 2>&1); rc=$?
  local summary
  summary=$(printf '%s\n' "$out" | grep -oE 'JSON-SUMMARY .*|LOOP CLOSED|LANE CLOSED|ISOLATION HELD|CORPUS CLOSED|REGISTRY CLEAN' | tail -1)
  if [ "$rc" -eq 0 ]; then
    pass=$((pass+1)); RESULTS+=("PASS|$name|${summary:-exit 0}")
  else
    fail=$((fail+1)); RESULTS+=("FAIL|$name|rc=$rc ${summary:-$(printf '%s\n' "$out" | tail -1 | cut -c1-90)}")
  fi
  printf '%-26s rc=%-4s %s\n' "$name" "$rc" "${summary:-(no summary)}"
}

for b in "$NODE" "$PY" "$PS"; do
  if [ ! -f "$b" ]; then
    echo "ABORT: interpreter not found at $b -- this is a host problem, not a lab result."
    exit 2
  fi
done

echo "=============================================================="
echo "full-station smoke  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="

run "registry-selftest"   "\"$PY\" scripts/registry-verify.py --selftest"
run "registry-validate"   "\"$PY\" scripts/registry-verify.py"
run "ghidra-failopen"     "\"$PS\" -NoProfile -ExecutionPolicy Bypass -File scripts/ghidra-failopen-regress.ps1"
run "web-reverse"         "\"$NODE\" web-reverse/tools/loop.mjs"
run "web-reverse-ast"     "\"$NODE\" web-reverse/tools/loop2.mjs"
run "crypto-lab"          "\"$NODE\" crypto-lab/tools/loop.mjs"
run "net-reverse"         "\"$NODE\" net-reverse/tools/loop.mjs"
run "net-trustcheck"      "\"$NODE\" net-reverse/tools/trustcheck.mjs"
run "crackme-corpus"      "\"$PY\" crackme-corpus/tools/loop.py"
run "forensics-lab"       "\"$NODE\" forensics-lab/tools/loop.mjs"
run "managed-lab"         "\"$NODE\" managed-lab/tools/loop.mjs"
run "mobile-lab"          "\"$NODE\" mobile-lab/tools/loop.mjs"
run "native-lab-ida"      "\"$NODE\" native-lab/tools/loop.mjs"
run "agent-contract"      "\"$PY\" scripts/eval-agent-contract.py"
run "backend-consistency" "\"$PY\" scripts/check_backend_consistency.py"

echo
echo "=============================================================="
echo "SMOKE SUMMARY  pass=$pass fail=$fail"
echo "=============================================================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
echo "JSON-SUMMARY {\"total\":$((pass+fail)),\"pass\":$pass,\"fail\":$fail}"
[ "$fail" -eq 0 ] && exit 0 || exit 1
