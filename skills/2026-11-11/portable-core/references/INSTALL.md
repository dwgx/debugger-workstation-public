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

Run from the reviewed repository root. This installs into that project. For a
different project, set `$project` to its known authorized root before the copy.
An existing destination stops this first-install command: compare and back up the
owned project copy before a scoped update instead of overwriting it blindly.

```powershell
$source = (Resolve-Path 'skills/2026-11-11/portable-core').Path
$project = (Get-Location).Path
$target = Join-Path $project '.omp/skills/portable-core'
if (Test-Path -LiteralPath $target) { throw 'Existing install: compare and back up before updating.' }
New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
Copy-Item -LiteralPath $source -Destination $target -Recurse -ErrorAction Stop
Set-Location -LiteralPath $project
```

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

From the same project root, with `$source` still set to the reviewed package:
```powershell
$catalog = omp skill list --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'OMP catalog failed.' }
$catalog.skills | Select-Object name, filePath, source
$catalog.warnings
$selected = @($catalog.skills | Where-Object { $_.name -eq 'portable-core' })
$expected = (Resolve-Path '.omp/skills/portable-core/SKILL.md').Path
if ($selected.Count -ne 1) { throw 'Expected one canonical portable-core entry.' }
if ($selected[0].source -ne 'native:project' -or $selected[0].filePath -ne $expected) { throw 'Unexpected loader source.' }
$reviewedHash = (Get-FileHash -LiteralPath (Join-Path $source 'SKILL.md') -Algorithm SHA256).Hash
$installedHash = (Get-FileHash -LiteralPath $selected[0].filePath -Algorithm SHA256).Hash
$reviewedHash; $installedHash
if ($reviewedHash -ne $installedHash) { throw 'Loaded file differs from the reviewed source.' }
omp read skill://portable-core
if ($LASTEXITCODE -ne 0) { throw 'Canonical skill read failed.' }
```

Acceptance requires all five target identity checks: one exact bare name,
`source=native:project`, the expected `filePath`, SHA-256 equal to the reviewed
source, and a read output `[Skill file: ...]` header identifying that same path.
Keep the displayed warnings, catalog, read output and hashes with the receipt.
An older global copy exposed under a namespaced alias is diagnostic information;
it does not by itself fail this project install. A wrong selected path or different
bytes still fails the hard checks above; a mismatched read header fails acceptance.
For a new shell, restore `$source` to the known reviewed package directory before
comparison; do not compare the installed file only with itself.

The 2026-11-19 synthetic controls showed why source identity matters: an alias-only
copy could not serve `skill://portable-core`; two same-name, different-byte copies
let an old directory occupy the bare name while the intended copy became
`native/portable-core`. A canonical name does not establish a canonical source.
These controls describe the tested OMP version and frozen inputs, not every
harness or a historical production incident. A new model-use acceptance run, if
needed, must record the exact changed Skill hashes separately from these checks.
