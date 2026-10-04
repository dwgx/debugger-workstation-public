<#
.SYNOPSIS
    Refuse arguments a script does not declare. Dot-source this, then call Assert-NoStrayArgs.

.DESCRIPTION
    WHY. Measured 2026-10-05: a sweep of the 32 PowerShell scripts in this tree that declare a
    `param()` block found that 22 of them silently swallow an argument. Concretely,
    `scripts/ghidra-failopen-regress.ps1 C:/nope/nothing.dll` printed `LOOP CLOSED`, four of four
    checks green, exit 0 -- having measured nothing the caller asked for.

    The mechanism is not a mistake in any one script; it is PowerShell's. A plain `param()` block
    is not strict: an unrecognised `-Name value` pair does not error, it lands in `$args`. Adding
    `[CmdletBinding()]` makes the engine refuse it, but that also changes every parameter's
    binding semantics and error behaviour, which is a far larger change than the defect warrants.

    So this is the explicit, uniform check instead. It is deliberately a FUNCTION LIBRARY with no
    top-level `param()`: dot-sourcing a script whose top-level param block is mandatory makes
    PowerShell bind those parameters to the dot-source itself, the script exits, and none of the
    functions load. Measured on this very project, in scripts/probe_artifact.ps1.

.NOTES
    It refuses rather than warns. A warning nobody reads is the same as no check, and the whole
    point is that the failure mode is SILENT.
#>

function Assert-NoStrayArgs {
    <#
        .SYNOPSIS
            Exit 2 if the calling script was handed arguments it does not declare.

        .PARAMETER ScriptName
            Used in the message so the reader knows WHICH script refused.

        .PARAMETER Allow
            Extra argv entries this script legitimately consumes and has already read. Pass
            the remainder if your script forwards arguments onward.

        .NOTES
            Call this AFTER your `param()` block, which is where PowerShell has finished binding
            and has already placed the leftovers in `$args`.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ScriptName,
        [string[]] $Allow = @()
    )

    if (-not $args -or $args.Count -eq 0) { return }

    $stray = @($args | Where-Object { $Allow -notcontains $_ })
    if ($stray.Count -eq 0) { return }

    [Console]::Error.WriteLine("$ScriptName`: refusing argument(s) it would otherwise IGNORE: $($stray -join ' ')")
    [Console]::Error.WriteLine("  A script that silently accepts an argument it cannot honour reports a pass")
    [Console]::Error.WriteLine('  for work nobody did. Check the spelling, or read the script''s param block.')
    exit 2
}
