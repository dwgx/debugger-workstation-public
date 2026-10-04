<#
.SYNOPSIS
    Write a probe's result to disk so the verdict rests on a FILE, not on a substring of stdout.

.DESCRIPTION
    This is the PowerShell member of a family: scripts/probe_artifact.py, its mirror
    scripts/probe_artifact.mjs, and this file. All three exist because
    `assert-probes.py` says so in its own OK verdict for an entry that declares no
    `probe.produces` —

        NOT a claim that the instrument ran: a stub which prints them satisfies it.

    — and every probe was verified by matching strings in captured stdout. A stub that
    prints the right sentences satisfies that. A stub does not write this file.

    Why a family rather than one implementation: the tree has three languages and the
    labs are deliberately independent of each other. A single cross-language helper is not
    available without one of the languages calling the others, which is worse than three
    small files that say the same thing.

.NOTES
    Two properties carried over from the Python member, both learned the hard way:

    * ONE FILE PER TOOL NAME. Several capabilities run the same script with different flags,
      and a single fixed path would let one tool's run satisfy another entry's declaration.
      That is the "a probe that cannot localise a fault is not much of a probe" failure.

    * NEVER DELETE ON FAILURE. A failed run writes ok = $false and its own error. "The
      artifact says this failed" is a fact a reader needs; the ABSENCE of a file is ambiguous
      between "never ran", "crashed before writing" and "wrote somewhere else".
#>
# THIS FILE HAS NO TOP-LEVEL `param()` BLOCK, and that is deliberate. Measured 2026-10-05:
# dot-sourcing a script whose top-level param block is mandatory makes PowerShell bind those
# parameters to THE DOT-SOURCE ITSELF; the script exits with a ParameterBindingException and none
# of the functions below get defined, so the first caller sees a `CommandNotFoundException` on a
# function that is visibly in the file. A helper library is dot-sourced; anything with a mandatory
# top-level param is an entry point. This is a library.

Set-StrictMode -Version Latest
function Get-ProbeArtifactPath {
    <#
        .SYNOPSIS
            Repo-relative path for this tool's artifact.

        .DESCRIPTION
            The tool name is slugified rather than trusted: it reaches here from a command
            line, and a name containing a path separator would otherwise write outside the
            output directory. That is a directory-traversal guard, not tidiness.

            $OutDir is a PARAMETER rather than read from the caller's scope. Reading it from
            scope would work only because PowerShell's dynamic lookup walks up the call stack --
            which is exactly the coupling that breaks when a caller passes an explicit directory.
    #>
    param(
        [Parameter(Mandatory)][string] $Name,
        [string] $OutDir = 'probe-artifacts'
    )

    $safe = ($Name -replace '[^A-Za-z0-9._-]', '_').Trim('._')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        throw "probe_artifact: unusable tool name '$Name'"
    }
    return (Join-Path $OutDir "last-run-$safe.json")
}

function Write-ProbeArtifact {
    <#
        .SYNOPSIS
            Write this run's payload to disk. Never throws.

        .DESCRIPTION
            A probe that fails because its bookkeeping failed has turned a measurement problem
            into an outage, and the exit code would then say nothing about the instrument. So
            a write error is reported and swallowed, and the caller carries on.

        .OUTPUTS
            The repo-relative path, or $null if the write failed.
    #>
    param(
        [Parameter(Mandatory)][string] $Tool,
        [Parameter(Mandatory)] $Payload,
        [string] $OutDir = 'probe-artifacts'
    )

    $rel = Get-ProbeArtifactPath -Name $Tool -OutDir $OutDir
    try {
        # NESTED Join-Path, not the three-argument form. Measured 2026-10-05: `Join-Path $a $b $c`
        # fails on Windows PowerShell 5.1 -- `-AdditionalChildPath` arrived in PowerShell 6 -- and
        # the failure surfaces as "A positional parameter cannot be found that accepts argument",
        # which reads like a problem with the CALLER rather than with the path. This tree runs
        # under both 5.1 and pwsh 7, so the portable form is the only one that works in both.
        $full = Join-Path (Join-Path $PSScriptRoot '..') $rel
        $dir = Split-Path -Parent $full
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $doc = [ordered]@{
            schema          = 'probe-artifact@1'
            artifact_version = 1
            tool            = $Tool
        }
        if ($Payload -is [System.Collections.IDictionary]) {
            foreach ($k in $Payload.Keys) { $doc[$k] = $Payload[$k] }
        } else {
            $doc['result'] = $Payload
        }

        # NO BOM. Measured 2026-10-05: `Set-Content -Encoding utf8` under Windows PowerShell 5.1
        # writes a UTF-8 BYTE ORDER MARK, and `json.load(..., encoding="utf-8")` in the harness
        # then dies with "Unexpected UTF-8 BOM". The artifact would exist, be non-empty, and be
        # unreadable by the only thing that has to read it -- the worst of both worlds.
        # `-Encoding utf8NoBOM` would fix it but arrived in PowerShell 6, so this tree needs the
        # explicit encoder, which works in 5.1 and in pwsh 7 alike.
        $json = $doc | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding $false))
        Write-Output "ARTIFACT $($rel -replace '\\','/')"
        return ($rel -replace '\\', '/')
    } catch {
        Write-Output "ARTIFACT WRITE FAILED: $($_.Exception.Message) -- the probe ran but left nothing checkable"
        return $null
    }
}
