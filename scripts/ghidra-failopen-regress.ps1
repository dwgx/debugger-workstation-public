$repo = 'D:\Software\Tool\WorkStation\debugger'
Set-Location $repo

$wrapper = 'scripts\ghidra-headless.ps1'
$bad  = Join-Path $env:TEMP 'gh-regress-notabinary.txt'
$good = Join-Path (Join-Path $repo 'crackme-corpus\out') 'c01-stringobf.exe'
Set-Content -Path $bad -Value 'definitely not a PE'

$checks = @()
function Check($ok, $name, $detail) {
    $script:checks += [pscustomobject]@{ ok = $ok; name = $name; detail = $detail }
    Write-Output ("  " + $(if ($ok) { 'PASS' } else { 'FAIL' }) + "  " + $name.PadRight(56) + " " + $detail)
}

Write-Output ('=' * 96)
Write-Output 'ghidra-headless fail-open regression -- exit code must not be able to mean success'
Write-Output ('=' * 96)
Write-Output ''

# 1. NEGATIVE: a non-binary must NOT exit 0.
$outBad = Join-Path $env:TEMP 'gh-regress-bad'
& powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper `
    -Sample $bad -OutDir $outBad -TimeoutMs 240000 | Out-Null
$rcBad = $LASTEXITCODE
Check ($rcBad -ne 0) 'NEGATIVE: non-binary input exits non-zero' "exit=$rcBad"

# 2. NEGATIVE: no summary.json may be reported as ok.
$summaryBad = Test-Path (Join-Path $outBad 'summary.json')
Check (-not $summaryBad) 'NEGATIVE: no summary.json was produced for a bad input' "exists=$summaryBad"

# 3. POSITIVE: a real crackme must still exit 0 and produce the artifact.
$outGood = Join-Path $env:TEMP 'gh-regress-good'
if (Test-Path $outGood) { Remove-Item $outGood -Recurse -Force }
& powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper `
    -Sample $good -OutDir $outGood -TimeoutMs 420000 | Out-Null
$rcGood = $LASTEXITCODE
Check ($rcGood -eq 0) 'POSITIVE: a real binary still exits 0' "exit=$rcGood"
Check (Test-Path (Join-Path $outGood 'summary.json')) 'POSITIVE: summary.json is produced' "exists=$(Test-Path (Join-Path $outGood 'summary.json'))"

$failed = @($checks | Where-Object { -not $_.ok })
Write-Output ''
Write-Output ('=' * 96)
if ($failed.Count -eq 0) {
    Write-Output 'LOOP CLOSED: a failed import can no longer be reported as exit 0.'
} else {
    Write-Output ("LOOP OPEN: " + $failed.Count + " check(s) failed -- " + (($failed | ForEach-Object { $_.name }) -join '; '))
}
Write-Output ('JSON-SUMMARY ' + (@{ total = $checks.Count; pass = $checks.Count - $failed.Count; fail = $failed.Count } | ConvertTo-Json -Compress))
exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
