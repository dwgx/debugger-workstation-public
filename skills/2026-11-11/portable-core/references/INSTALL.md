OWNER: repository maintainers | portable-core/references/INSTALL.md
# INSTALL — copy the package, then verify what the harness loads

## Supported identity

Install this whole package under the canonical directory and frontmatter name
`portable-core`. Renaming both is not a supported shortcut: the package validator
also enforces this canonical name. `debuggerstation-selfdeploy` is a historical
research alias, not an install target. Include `references/`, `scripts/`,
`FIX-KB/`, `tests/`, both READMEs and `LICENSE`, not only `SKILL.md`.

Use the current Owner's scope and root contract. Keep one active canonical copy
in the selected project discovery scope. Preserve old sources outside discovery
directories; do not delete history or alter user-global configuration to resolve
a project collision.

## OMP project copy (PowerShell)

Run from the reviewed repository or bootstrapped station root. The three packages
are `portable-core`, `debugger-workstation` and `debugger-review`. The two routers
need the station root; copying them does not install third-party tools. For a
different authorized project, change `$project` before running the copy.

```powershell
$sourceRoot = (Get-Location).Path
$project = $sourceRoot
$packages = [ordered]@{
    'portable-core' = 'skills/2026-11-11/portable-core'
    'debugger-workstation' = 'skills/2026-11-11/station-routers/debugger-workstation'
    'debugger-review' = 'skills/2026-11-11/station-routers/debugger-review'
}
# Check every destination before creating any package.
foreach ($name in $packages.Keys) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot ($packages[$name] + '/SKILL.md')))) { throw "Missing source: $name" }
    if (Test-Path -LiteralPath (Join-Path $project ".omp/skills/$name")) { throw "Existing install: compare and back up $name before updating." }
}
New-Item -ItemType Directory -Force -Path (Join-Path $project '.omp/skills') | Out-Null
foreach ($name in $packages.Keys) {
    $source = Join-Path $sourceRoot $packages[$name]
    $target = Join-Path $project ".omp/skills/$name"
    Copy-Item -LiteralPath $source -Destination $target -Recurse -ErrorAction Stop
    foreach ($file in Get-ChildItem -LiteralPath $source -File -Recurse) {
        $relative = $file.FullName.Substring($source.Length).TrimStart('\', '/')
        if ((Get-FileHash -LiteralPath $file.FullName).Hash -ne (Get-FileHash -LiteralPath (Join-Path $target $relative)).Hash) { throw "Copied bytes differ: $name/$relative" }
    }
}
Set-Location -LiteralPath $project
```

Use a clean release source to avoid copying generated caches. Keep the complete
portable-core package. An existing destination stops the first-install recipe;
updates need a reviewed comparison and a backup of that owned project copy.

For a bootstrapped station, OMP can also use the generated router-only config.
If `.omp/mcp.json` is absent, copy the station's `.mcp.json` there; otherwise merge
the selected `debugger-router` entry into the existing project file after review.
Ensure `mcp.enableProjectConfig` is enabled in this project's OMP settings. Inspect
the live MCP catalog before a task: existing user or plugin servers may also be
discovered. Do not copy the backend inventory or edit user-global configuration.

Other harnesses: use their documented discovery directory and registration
mechanism. The package does not assume a universal manifest or global skills path.

## Check the installed bytes

From the OMP project root:
```powershell
python -X utf8 -B .omp/skills/portable-core/verify.py
if ($LASTEXITCODE -ne 0) { throw 'Installed package check failed.' }
python -X utf8 -B .omp/skills/portable-core/tests/entry_checks.py
if ($LASTEXITCODE -ne 0) { throw 'Installed entry checks failed.' }
```
Require exit 0 and `VERDICT=PASS` from both; record the actual denominators.
Both use `tests/package_contract.py`. For another harness location, change into
its installed `portable-core` directory and run `verify.py` and
`tests/entry_checks.py` there. Optional `skills-ref validate ./portable-core`
checks the skill format from its parent directory; it does not prove discovery.

## Check OMP's actual loader source

From the same project root, with `$sourceRoot` and `$packages` still set:
```powershell
$catalog = omp skill list --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'OMP catalog failed.' }
$catalog.skills | Select-Object name, filePath, source
$catalog.warnings
foreach ($name in $packages.Keys) {
    $selected = @($catalog.skills | Where-Object { $_.name -eq $name })
    $expected = (Resolve-Path ".omp/skills/$name/SKILL.md").Path
    if ($selected.Count -ne 1) { throw "Expected one canonical $name entry." }
    if ($selected[0].source -ne 'native:project' -or $selected[0].filePath -ne $expected) { throw "Unexpected loader source: $name" }
    $source = Join-Path $sourceRoot $packages[$name]
    $reviewedHash = (Get-FileHash -LiteralPath (Join-Path $source 'SKILL.md') -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash -LiteralPath $selected[0].filePath -Algorithm SHA256).Hash
    "$name source=$reviewedHash installed=$installedHash"
    if ($reviewedHash -ne $installedHash) { throw "Loaded file differs: $name" }
    $readOutput = @(omp read "skill://$name")
    if ($LASTEXITCODE -ne 0) { throw "Canonical read failed: $name" }
    $readOutput
    if ($readOutput.Count -eq 0 -or $readOutput[0] -ne "[Skill file: $expected]") { throw "Unexpected read header: $name" }
}
```

Acceptance requires all five target identity checks: one exact bare name,
`source=native:project`, the expected `filePath`, SHA-256 equal to the reviewed
source, and a read output `[Skill file: ...]` header identifying that same path.
Keep the displayed warnings, catalog, read output and hashes with the receipt.
An older global copy exposed under a namespaced alias is diagnostic information;
it does not by itself fail this project install. A wrong selected path or different
bytes still fails the hard checks above; a mismatched read header fails acceptance.
For a new shell, restore `$sourceRoot` and `$packages` from the copy recipe before
comparison; do not compare an installed file only with itself. Start a new OMP
session after changing installed bytes so the next model task sees that version.

The 2026-11-19 synthetic controls showed why source identity matters: an alias-only
copy could not serve `skill://portable-core`; two same-name, different-byte copies
let an old directory occupy the bare name while the intended copy became
`native/portable-core`. A canonical name does not establish a canonical source.
These controls describe the tested OMP version and frozen inputs, not every
harness or a historical production incident. A new model-use acceptance run, if
needed, must record the exact changed Skill hashes separately from these checks.
