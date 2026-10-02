<#
.SYNOPSIS
    Is this Windows PE packed? A gate that REFUSES a non-PE instead of scoring it.

.DESCRIPTION
    WHY THIS WRAPPER EXISTS, measured not assumed. skills/debugger-workstation/references/
    triage.md tells the agent to run

        Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe -e <sample>

    and to treat "not packed" as the green light to decompile. Run that on a file that is NOT
    a PE and Die still answers, happily and with exit 0:

        diec.exe -e README.md
          Total 5.26547: not packed
          0|Data|0|7354|5.26547: not packed

    A markdown file scored "not packed". So Die cannot distinguish "a PE that is not packed"
    from "this is not a PE at all", and a triage step that trusts its verdict will wave a
    non-PE straight through to the decompiler. **That is a control which always passes**, which
    this project treats as worse than having no control.

    So the PE check happens FIRST and outside Die, using the DOS magic. Die is only asked about
    files that are genuinely PEs, and its "not packed" then means something.

    WHAT IT STILL CANNOT DO. "not packed" means no packer signature matched. It is not a
    guarantee the binary is unpacked: a custom or modified packer matches no signature, and a
    low score is not proof of absence. Treat a low score as a green light to LOOK, never as
    proof, and keep the entropy signal in the output.

.EXAMPLE
    .\triage-packer.ps1 -Target crackme-corpus\out\c01-stringobf.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Die,
    [double]$PackedAtOrAbove = 5.0
)

# NOT defaulted in the param block: $PSScriptRoot is empty there under `powershell -File`,
# which is exactly how the registry invokes a script. Measured -- it throws before any work.
if (-not $Die) {
    $Die = Join-Path $PSScriptRoot '..\..\Static-Reversing\die_win64_portable_3.21_x64\die\diec.exe'
}

function Refuse([int]$code, [string]$message, [hashtable]$extra) {
    $o = [ordered]@{ ok = $false; exit = $code; error = $message }
    if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
    $o | ConvertTo-Json -Compress | Write-Output
    exit $code
}

if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) { Refuse 1 "no such file: $Target" }
if (-not (Test-Path -LiteralPath $Die -PathType Leaf)) { Refuse 2 "diec.exe not found at $Die" }

$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Target).Path)

# The refusal, before any instrument is asked. 'MZ' is the DOS header magic every PE starts
# with; Die will happily score a file without it, which is the whole reason this line exists.
if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    $magic = if ($bytes.Length -ge 2) { '{0:X2}{1:X2}' -f $bytes[0], $bytes[1] } else { 'too-short' }
    # EXIT 3 MEANS "NOT MY SUBJECT", AND IT IS A NEW CODE FOR A REASON. This refusal used to be
    # exit 2 -- the same code as "diec.exe not found" and "diec produced no parseable output" --
    # three unrelated situations sharing one number. That mattered because mission.ps1 treats a
    # PRECONDITION's failure as "this target is gated shut, skip everything downstream", so a
    # mission aimed at an APK was told its target was unsafe to analyse when the truth was that a
    # PE packer gate had nothing to say about an APK. Measured: aimed at mobile-lab/artifacts/
    # mobilelab.apk this gate refused with exit 2 and the mission stopped after round 1, with
    # mobile.apk.static -- which analyses that APK perfectly well, verified exit 0 -- never run.
    #
    # 3 is safe to act on differently because it is unambiguous: a genuinely PACKED PE exits 0
    # with ok:false, and that path is untouched. Nothing about the packed case is relaxed; only
    # "I am not the right instrument for this file" is now distinguishable from "I could not run".
    Refuse 3 "not a PE: first two bytes are $magic, expected 4D5A ('MZ'). Die would have scored this anyway and said 'not packed'." @{ first_bytes = $magic; size = $bytes.Length; not_my_subject = $true }
}

# Die writes its result to stdout and its noise to stderr; a stderr line here is NOT a failure.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$out = & $Die -e $Target 2>$null
$ErrorActionPreference = $prev

$score = $null
$verdict = $null
foreach ($line in @($out)) {
    if ("$line" -match '^\s*Total\s+([0-9.]+):\s*(.+?)\s*$') { $score = [double]$Matches[1]; $verdict = $Matches[2] }
}
if ($null -eq $score) {
    Refuse 2 "diec.exe produced no parseable Total line; refusing rather than guessing 'not packed'" @{ raw_lines = @($out).Count }
}

[ordered]@{
    # `ok` IS THE PRECONDITION VERDICT, and that is a semantic change made on 2026-10-02. It was
    # hard-coded $true regardless of the verdict, which is right for an EVIDENCE round and wrong
    # for a PRECONDITION one: this entry now declares invoke.gate_role = "precondition", and the
    # loop skips every downstream round when a precondition's declared success fails. A packed
    # binary must therefore report ok:false, or "unpack first, do not decompile the stub" stays
    # advice instead of becoming a gate. Unpacked stays ok:true so normal work proceeds.
    ok         = (-not (($verdict -notmatch 'not\s+packed') -and ("$verdict" -match 'packed')))
    precondition = "PASS means it is safe to decompile. A packed target reports ok:false and the " +
                   "mission skips every downstream round rather than analysing a stub."
    target     = (Resolve-Path -LiteralPath $Target).Path
    size       = $bytes.Length
    die_score  = $score
    die_verdict = $verdict
    packed     = ($verdict -notmatch 'not\s+packed') -and ("$verdict" -match 'packed')
    caveat     = "DERIVED FROM DIE'S OWN VERDICT, NOT FROM A NUMERIC THRESHOLD. The first draft computed packed as ($score -ge $PackedAtOrAbove) with a hand-picked 5.0, and the very next probe proved that wrong: this binary is emphatically not packed -- Die says 'not packed' -- yet it scores 6.15091, so the threshold reported packed:true and would have BLOCKED EVERY DECOMPILATION in the arsenal. A gate that always says yes is as useless as one that always says no, and it is the same defect as a scanner scoring our own router 100/100 CRITICAL: a confident number with no denominator behind it. Die already decided; the score is reported as evidence but nothing branches on it. AND the limit that survives all of this: 'not packed' means no packer SIGNATURE matched, not that the binary is proven unpacked -- a custom or modified packer matches nothing. It is a green light to look, never proof."
    score_is_advisory = $true
} | ConvertTo-Json -Compress | Write-Output
exit 0