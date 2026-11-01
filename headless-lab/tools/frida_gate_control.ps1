# GENERATED FROM THE REGISTRY, and kept as a FILE on purpose.
# The control used to be recorded inline as several statements joined by ';'. That separates
# commands in PowerShell, and a PowerShell script run with -File returns 0 NO MATTER what the
# last command's exit code was -- proven: a script whose only statement is `python -c "import sys;
# sys.exit(2)"` returns 0. So every one of these controls was STRUCTURALLY INCAPABLE OF FAILING:
# its expect_exit was written down and never observed, and the registry reported CLEAN throughout.
# The trailing `exit $LASTEXITCODE` is the whole fix. A control that cannot fail is not a control.
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot); $py="$repo\Mobile-Android\objection\.venv\Scripts\python.exe";
$t=Join-Path $env:TEMP 'fridagate\target.exe';
& $py "$repo\native-lab\tools\frida_spawn_gate.py" $t neg-badaddr;
Write-Host "STAGE1_EXIT=$LASTEXITCODE";
& $py "$repo\native-lab\tools\frida_spawn_gate.py" $t neg-rebase
exit $LASTEXITCODE
