# WHY THIS IS A FILE. The control used to be recorded as three statements joined by ';'. That
# works in PowerShell and is a NO-OP in cmd.exe, where ';' is an ARGUMENT DELIMITER rather than
# a command separator -- so the whole thing reached authenticode.py as one invocation and died
# with "unrecognized arguments: python -c import sys;d=open(...)". scripts/assert-probes.py found
# it by running the string exactly as recorded; nothing static could have, because the string
# parses.
#
# Recorded verbatim, it had never been executed as written. It is now a file, so it is one
# command, has no nested quoting to get wrong, and cannot silently change meaning if somebody
# copies it into a different shell.
$ErrorActionPreference = 'Stop'

$signed = Join-Path $env:TEMP 'signed-fixture.exe'
$truncated = Join-Path $env:TEMP 'truncated-fixture.exe'

python headless-lab\tools\authenticode.py crackme-corpus\out\c01-stringobf.exe --make-control $signed
if ($LASTEXITCODE -ne 0) { Write-Error "could not build the signed fixture"; exit 1 }

# Chop 60 bytes off the end so the SECURITY directory's file offset points outside the file.
# The offset is a FILE OFFSET, not an RVA -- an entry that treats it as a section-relative
# address reads a plausible-looking value and verifies nothing.
python -c "import sys;d=open(r'$signed','rb').read();open(r'$truncated','wb').write(d[:len(d)-60])"

python headless-lab\tools\authenticode.py $truncated
exit $LASTEXITCODE