#Requires -Version 5.1
<#
Read-only installation preflight. Paths are relative to the release root.
The manifest is a dependency declaration, not a product acceptance receipt.
#>

function Test-InstallRelativePath([object]$Value) {
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { return $false }
    # Manifest paths use slash separators, never wildcards, drives, ADS or traversal.
    if ($Value.StartsWith('/') -or $Value -match '[\\:*?"<>|]') { return $false }
    foreach ($part in $Value.Split('/')) {
        if ($part -in @('', '.', '..')) { return $false }
    }
    return $true
}

function Get-InstallationClosure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Mode
    )
    $manifestRel = 'manifests/installation-closure.v1.json'
    $manifestPath = Join-Path $RepoRoot $manifestRel
    $errors = New-Object 'System.Collections.Generic.List[object]'
    $manifest = $null
    $digest = $null
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $errors.Add([pscustomobject]@{ code = 'MISSING_REQUIRED'; path = $manifestRel })
    } else {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($null -eq $manifest -or $manifest.schema_version -ne 'installation-closure.1') {
                $errors.Add([pscustomobject]@{ code = 'INVALID_MANIFEST'; path = $manifestRel; detail = 'schema_version' })
            }
        } catch {
            $errors.Add([pscustomobject]@{ code = 'INVALID_MANIFEST'; path = $manifestRel; detail = 'unreadable_or_invalid_json' })
        }
    }
    $pathFields = @('copy_files', 'copy_trees', 'required_files')
    if ($errors.Count -eq 0) {
        foreach ($field in @('copy_files', 'copy_trees', 'required_files', 'exclude_directories', 'exclude_extensions')) {
            $value = $manifest.$field
            if ($value -isnot [System.Array] -or $value.Count -eq 0) {
                $errors.Add([pscustomobject]@{ code = 'INVALID_MANIFEST'; path = $manifestRel; detail = $field + '_must_be_nonempty_array' })
                continue
            }
            foreach ($item in $value) {
                if ($field -in $pathFields) {
                    $valid = Test-InstallRelativePath $item
                } else {
                    $valid = $item -is [string] -and -not [string]::IsNullOrWhiteSpace($item) -and $item -notmatch '[/\\:*?"<>|]'
                }
                if (-not $valid) {
                    $errors.Add([pscustomobject]@{ code = 'INVALID_MANIFEST'; path = $manifestRel; detail = $field + '_invalid_entry' })
                }
            }
        }
    }
    $required = @()
    if ($errors.Count -eq 0) {
        $required = @(@($manifest.copy_files) + @($manifest.required_files) + @($manifestRel, 'scripts/installation-closure.ps1') | Sort-Object -Unique)
        foreach ($rel in $required) {
            $path = Join-Path $RepoRoot $rel
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $errors.Add([pscustomobject]@{ code = 'MISSING_REQUIRED'; path = $rel })
            } else {
                try {
                    if ((Get-Item -LiteralPath $path).Length -eq 0) {
                        $errors.Add([pscustomobject]@{ code = 'EMPTY_REQUIRED'; path = $rel })
                    }
                } catch {
                    $errors.Add([pscustomobject]@{ code = 'UNREADABLE_REQUIRED'; path = $rel })
                }
            }
        }
        foreach ($rel in $manifest.copy_trees) {
            $path = Join-Path $RepoRoot $rel
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                $errors.Add([pscustomobject]@{ code = 'MISSING_REQUIRED'; path = $rel })
            } elseif (@(Get-ChildItem -LiteralPath $path -Force | Select-Object -First 1).Count -eq 0) {
                $errors.Add([pscustomobject]@{ code = 'EMPTY_REQUIRED'; path = $rel })
            }
        }
    }
    $status = if ($errors.Count -eq 0) { 'READY' } else { 'BLOCKED' }
    $report = [ordered]@{
        contract = 'installation-closure.1'
        status = $status
        mode = $Mode
        manifest_sha256 = $digest
        required_files = $required.Count
        errors = @($errors.ToArray())
    }
    return [pscustomobject]@{ Manifest = $manifest; Report = $report }
}

function Copy-InstallationTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)]$Closure
    )
    foreach ($entry in Get-ChildItem -LiteralPath $Source -Force) {
        if ($entry.PSIsContainer) {
            if ($entry.Name -in $Closure.exclude_directories) { continue }
            # Never traverse a junction/symlink into a cache or outside this release.
            if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
            Copy-InstallationTree -Source $entry.FullName -Destination (Join-Path $Destination $entry.Name) -Closure $Closure
        } else {
            if ($entry.Extension -in $Closure.exclude_extensions) { continue }
            if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
            [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
            Copy-Item -LiteralPath $entry.FullName -Destination (Join-Path $Destination $entry.Name) -Force
        }
    }
}
