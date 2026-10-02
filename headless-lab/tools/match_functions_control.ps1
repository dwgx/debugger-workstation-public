# GENERATED FROM THE REGISTRY, and kept as a FILE on purpose.
# The control used to be recorded inline as several statements joined by ';'. That separates
# commands in PowerShell, and a PowerShell script run with -File returns 0 NO MATTER what the
# last command's exit code was -- proven: a script whose only statement is `python -c "import sys;
# sys.exit(2)"` returns 0. So every one of these controls was STRUCTURALLY INCAPABLE OF FAILING:
# its expect_exit was written down and never observed, and the registry reported CLEAN throughout.
# The trailing `exit $LASTEXITCODE` is the whole fix. A control that cannot fail is not a control.
Set-Content -Path $env:TEMP\nope.bin -Value 'not a pe' -NoNewline;
powershell -NoProfile -ExecutionPolicy Bypass -File headless-lab\tools\match-functions.ps1 -Source $env:TEMP\nope.bin -Dest crackme-corpus\out\c01-stringobf.exe
exit $LASTEXITCODE
