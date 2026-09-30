#!/bin/bash
# Full-station smoke: one command that runs every capability probe the registry claims.
# Read-only. Prints JSON-SUMMARY per lab and a final verdict.
# no cd: cwd is supplied by the caller

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
  printf '%-26s rc=%-3s %s\n' "$name" "$rc" "${summary:-(no summary)}"
}

echo "=============================================================="
echo "full-station smoke  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="

run "registry-selftest"   "python scripts/registry-verify.py --selftest"
run "registry-validate"   "python scripts/registry-verify.py"
run "ghidra-failopen"     "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/ghidra-failopen-regress.ps1"
run "web-reverse"         "node web-reverse/tools/loop.mjs"
run "web-reverse-ast"     "node web-reverse/tools/loop2.mjs"
run "crypto-lab"          "node crypto-lab/tools/loop.mjs"
run "net-reverse"         "node net-reverse/tools/loop.mjs"
run "net-trustcheck"      "node net-reverse/tools/trustcheck.mjs"
run "crackme-corpus"      "python crackme-corpus/tools/loop.py"
run "forensics-lab"       "node forensics-lab/tools/loop.mjs"
run "managed-lab"         "node managed-lab/tools/loop.mjs"
run "mobile-lab"          "node mobile-lab/tools/loop.mjs"
run "native-lab-ida"      "node native-lab/tools/loop.mjs"
run "agent-contract"      "python scripts/eval-agent-contract.py"
run "backend-consistency" "python scripts/check_backend_consistency.py"

echo
echo "=============================================================="
echo "SMOKE SUMMARY  pass=$pass fail=$fail"
echo "=============================================================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
echo "JSON-SUMMARY {\"total\":$((pass+fail)),\"pass\":$pass,\"fail\":$fail}"
[ "$fail" -eq 0 ] && exit 0 || exit 1
