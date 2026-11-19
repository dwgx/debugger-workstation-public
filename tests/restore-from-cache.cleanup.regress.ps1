#requires -Version 5.1
<#
.SYNOPSIS
  Verify that the candidate cleanup function never follows owned-stage reparse links.
.DESCRIPTION
  Loads only Remove-OwnedCacheStage from the target's parsed function definition.
  Creates controlled directories and junctions only inside a new -WorkDir.
  This is a focused cleanup test, separate from end-to-end archive restoration.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$WorkDir
)
$ErrorActionPreference = 'Stop'
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
if (Test-Path -LiteralPath $WorkDir) { throw "WorkDir must not exist: $WorkDir" }
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Target has parse errors.' }
$fn = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Remove-OwnedCacheStage'
}, $true)
if ($null -eq $fn) { throw 'Target has no Remove-OwnedCacheStage function.' }
. ([scriptblock]::Create($fn.Extent.Text))
New-Item -ItemType Directory -Path $WorkDir | Out-Null
$cases = @()
foreach ($kind in @('nested-junction', 'root-junction')) {
    $target = Join-Path $WorkDir ($kind + '-other-owner')
    New-Item -ItemType Directory -Path $target | Out-Null
    $sentinel = Join-Path $target 'sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'other owner bytes', (New-Object Text.UTF8Encoding($false)))
    $hashBefore = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
    $owned = Join-Path $WorkDir ($kind + '-owned')
    if ($kind -eq 'nested-junction') {
        New-Item -ItemType Directory -Path $owned | Out-Null
        [IO.File]::WriteAllText((Join-Path $owned 'owned.txt'), 'owned bytes')
        New-Item -ItemType Junction -Path (Join-Path $owned 'junction') -Target $target | Out-Null
    } else {
        New-Item -ItemType Junction -Path $owned -Target $target | Out-Null
    }
    Remove-OwnedCacheStage -Path $owned
    $targetExists = Test-Path -LiteralPath $sentinel
    $targetUnchanged = $false
    if ($targetExists) {
        $targetUnchanged = ((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -eq $hashBefore)
    }
    $ownedRemoved = -not (Test-Path -LiteralPath $owned)
    $cases += [pscustomobject]@{
        name = $kind
        ownedRemoved = $ownedRemoved
        externalTargetPreserved = $targetUnchanged
        pass = ($ownedRemoved -and $targetUnchanged)
    }
}
$failed = @($cases | Where-Object { -not $_.pass })
$result = [pscustomobject]@{
    scope = 'actual cleanup function, parsed from candidate; not archive extraction'
    source = $ScriptPath
    sourceSha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    shellVersion = $PSVersionTable.PSVersion.ToString()
    totalCases = 2
    totalAssertions = 4
    allPass = ($failed.Count -eq 0 -and $cases.Count -eq 2)
    cases = $cases
}
$json = $result | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $WorkDir 'results.json'), $json, (New-Object Text.UTF8Encoding($false)))
Write-Output $json
if (-not $result.allPass) { exit 1 }
exit 0
