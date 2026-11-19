# Bootstrap layout

<!-- I18N:START -->
**English** · this file stays English (like `docs/EVAL.md`)
<!-- I18N:END -->

How `-Apply` turns this skeleton into a station. Dry-run is the default.
Read [`AGENTS.md`](../AGENTS.md) first; use the install root and scope already
agreed with the clone owner.

## First verified result (no third-party backend)

For a beginner, [run this one-command demo first](FIRST-SUCCESS.md). It uses an authored PCAP and the existing strict CLI product verifier, without installing the workstation or configuring an MCP backend. Its `PROFILE_PASS` covers only that parser fixture.

## Public quickstart

Use a Windows PowerShell 5.1 or PowerShell 7 prompt with Git and Python available.
The optional archive example below needs Python 3.12 or newer. OMP is needed only
for the OMP Skill/model route. Start with a fresh clone and an authorized, new
station directory; the example uses a directory under your own home.

```powershell
$ErrorActionPreference = 'Stop'
git clone https://github.com/dwgx/debugger-workstation-public.git
if ($LASTEXITCODE -ne 0) { throw 'Clone failed.' }
Set-Location debugger-workstation-public
$source = (Get-Location).Path
$sourceCommit = (git rev-parse HEAD).Trim()
$station = Join-Path $HOME 'Workstation-demo'
.\scripts\verify-all.ps1 -Scope Package
if ($LASTEXITCODE -ne 0) { throw 'Package checks failed.' }
.\scripts\bootstrap.ps1 -InstallRoot $station -SkipTools -UiLanguage en
# Review the dry run, then install the selected source package and router:
.\scripts\bootstrap.ps1 -InstallRoot $station -SkipTools -UiLanguage en -Apply
& (Join-Path $station 'MCP/debugger-router/.venv/Scripts/python.exe') -c 'import mcp'
if ($LASTEXITCODE -ne 0) { throw 'Router Python prerequisites are not ready.' }
Set-Location -LiteralPath $station
```

Stop on an error. The dry run does not install anything. `-Apply` creates the
router's isolated Python environment; inspect its installation output before
using MCP. This route does not use `-CloneMcp`: choose and install only the
backend required by your task. A rendered inventory is not an installed backend.

Now follow the single [Skill installation and loader verification guide](../skills/2026-11-11/portable-core/references/INSTALL.md)
from the installed station root. It installs the full `portable-core` package
and the two canonical station routers, checks copied bytes, and verifies each
OMP catalog path, source, digest and actual `skill://` read header. Configure the
project's generated router entry there before a model task. Do not install the
superseded undated Skill copies or assume a matching name proves matching bytes.

### Choose what to demonstrate

| Route | Additional dependency | What it establishes |
|---|---|---|
| [Installed package and Skill loader](../skills/2026-11-11/portable-core/references/INSTALL.md) | OMP for discovery/read checks | The copied package passes its validators and OMP resolves the reviewed project files. |
| [Bounded offline PCAP CLI profile](CURRENT-CLI-PROFILE.md) | Python; no downloaded backend | The generated, caller-authored PCAP is parsed through the frozen runner and independently verified. Use `$sourceCommit` as supplied source provenance and a new external run directory. |
| [Selected archive MCP example](#selected-archive-mcp-example) | `mcp7zop` and 7-Zip | A real Router/backend call lists and extracts an owned archive, while a malformed input retains its error. |

### Verification scopes

`verify-all.ps1 -Scope Package` checks installation source closure, the portable
package and its entry controls. It does not need a private wiki, corpus or tool
installation, and it does not accept station runtime or a release.

The default `-Scope Station` retains the station's runtime, semantic and
completeness gates. Missing selected runtime checks remain blocking. Wiki prose,
figure synchronization and wiki tree structure are `NOT_APPLICABLE` because no
paired integration is selected; their validator self-tests remain in the suite.
For a real paired wiki, use `-Scope Paired -PrivateTree <repository-root>`; that
root must contain `wiki/INDEX.md`. It adds the three integration checks and uses
the explicit wiki for provenance review. An absent/invalid pair is blocked,
never replaced by a placeholder wiki or counted as PASS. Read the reported scope
and each selected check's result.

## Selected archive MCP example

This optional Windows example was exercised with the public `mcp7zop` commit
`4856990e884e7c5a1d1cd353a3d7de3c234b6a3c` (0.8.14) and 7-Zip 26.06. From the
installed station root, create only this backend's environment:

```powershell
$station = (Get-Location).Path
$backend = Join-Path $station 'MCP/mcp7zop'
if (Test-Path -LiteralPath $backend) { throw 'Use a fresh backend destination or review the existing installation.' }
git clone https://github.com/zv-louis/mcp7zop.git $backend
if ($LASTEXITCODE -ne 0) { throw 'Backend clone failed.' }
git -C $backend checkout 4856990e884e7c5a1d1cd353a3d7de3c234b6a3c
if ($LASTEXITCODE -ne 0) { throw 'Backend source selection failed.' }
python -m venv (Join-Path $backend '.venv')
if ($LASTEXITCODE -ne 0) { throw 'Backend environment creation failed.' }
$backendPython = Join-Path $backend '.venv/Scripts/python.exe'
& $backendPython -m pip install $backend
if ($LASTEXITCODE -ne 0) { throw 'Backend dependencies failed.' }
& $backendPython -m pip freeze --all
```

Keep this environment separate from `MCP/debugger-router/.venv`; the provider's
upstream dependencies are not a Router SDK upgrade. Record the actual resolved
versions when you install. The measured 2026-11-19 provider environment used
FastMCP 4.2.2 / MCP 2.3.0 while the Router retained its pinned MCP 1.30.0; that is
one observed combination, not a promise about future unpinned resolutions.

From the [official 7-Zip download page](https://www.7-zip.org/download.html), obtain
`7zr.exe` and the Windows x64 installer `7z2606-x64.exe` into a new directory.
Set `$download` to that directory, then extract the installer as an archive;
the following command does not run the installer:

```powershell
$sevenzip = Join-Path $station 'Unpackers-Game/7-Zip-full'
if (Test-Path -LiteralPath (Join-Path $sevenzip '7z.exe')) { throw 'Review the existing 7-Zip installation before replacing it.' }
& (Join-Path $download '7zr.exe') x (Join-Path $download '7z2606-x64.exe') "-o$sevenzip" -y
if ($LASTEXITCODE -ne 0) { throw '7-Zip extraction failed.' }
& (Join-Path $sevenzip '7z.exe')
Get-FileHash -LiteralPath (Join-Path $sevenzip '7z.exe') -Algorithm SHA256
```

The existing `MCP/bin/7zip-mcp.cmd` prepends this station's 7-Zip directory and
launches the selected provider environment. The provider also supports a
user-level `~/.mcp7zop/config.json` binary override: inspect its effective choice
if present; do not silently change global configuration. Record the download asset's SHA-256 and the extracted executable's version and SHA-256.

Use only an archive you own. Start a fresh OMP session in this station after
installing its Skills and project router configuration. A concise task is:

> Load `skill://portable-core`, `skill://debugger-workstation` and
> `skill://debugger-review`. Through the debugger-router's sevenzip backend,
> inspect the files in my chosen input directory, list each archive and extract
> readable contents into a new report directory. Inspect the live tool schema,
> measure exact member paths, sizes and SHA-256, preserve any provider error,
> execute no extracted content, and close your own backend session. Report the
> actual loaded Skill paths and the limits of what you verified.

`list_backend_tools` can return descriptions without schemas; request
`include_schemas=true` when inspecting arguments. A Router call's outer transport
success does not erase an inner `is_error=true`. Check both and keep errors in
the report. Successful Skill discovery alone is not evidence that a model read
those Skills, and a single backend task does not establish all-backend readiness.

## Runtime inventory and client entry

| File | Who reads it | Contents |
|---|---|---|
| `MCP/.mcp.json` | `debugger-router` (`server.py`) | Rendered from [`mcp/.mcp.json.template`](../mcp/.mcp.json.template): 21 server entries = the router + 20 backend definitions. |
| `.mcp.json` and `.cursor/mcp.json` | Claude Code / Cursor **project** MCP | **Only** `debugger-router`. Template: [`mcp/client-mcp.json.template`](../mcp/client-mcp.json.template). |
| [`mcp/codex-mcp-config.example.toml`](../mcp/codex-mcp-config.example.toml) | A Codex configuration example for selective adoption | Router enabled, 20 backends disabled. Named profiles are commented examples; enable only the selected profile in the intended client configuration. |

Never copy the full inventory into a client or into user-global MCP. A configured
backend is not evidence of its installation, readiness or a successful real-tool
operation. The router starts a backend on demand and reuses its session until it
is closed or idles out.

### Why other documents have different counts

As read from this source on 2026-11-12:

| Denominator | Count | Meaning |
|---|---:|---|
| Runtime backend definitions | 20 | Entries other than `debugger-router` in the JSON and Codex templates. |
| Runtime server entries | 21 | One router plus those 20 backends. |
| `mcp-backends.json` third-party declarations | 18 | 17 clone-directory rows + one npm package declaration (REA), including an explicitly unwired extension among the clone rows. |
| Resolved upstream declarations | 4 | `resolved_upstream.entries`, including helper/component repositories. |
| Manifest component declarations | 24 | Two `self_developed` components + 18 third-party + 4 resolved upstream declarations. This is not a count of runnable backend sessions. |

Source: [`manifests/mcp-backends.json`](../manifests/mcp-backends.json). The 17 + 4 clone-directory rows give 21 upstream clone targets; REA has a separate npm package path.
The dated release's 295 inventory claims use another denominator; they are not
295 tools. See [`AI_ENTRY.md`](AI_ENTRY.md) for the separate evidence scopes.

## InstallRoot and the clone

Bootstrap copies the required manifests, skills, docs, scripts, templates and
root contract files so an agent opening the chosen install directory can still
follow the entry contract. Windows treats `mcp` and `MCP` as the same directory; self-copy
is skipped when the source and destination are the same folder.

`-Apply -CloneMcp` clones the declared third-party source repositories. Bootstrap
creates the router environment; each selected third-party backend still needs
its own documented build/runtime setup. Tools come separately from their
official sources; [`scripts/download-tools.ps1`](../scripts/download-tools.ps1)
is an optional downloader. A dry run does not establish that these dependencies
are installed.

The candidate strict CLI installation and its external plan/artifact directory
are described in [`CURRENT-CLI-PROFILE.md`](CURRENT-CLI-PROFILE.md). That bounded
offline profile and the MCP inventory have separate acceptance criteria.

## `local.json`

Always gitignored. `-Apply` writes `install_root`. `ui_language` is written only
with `-UiLanguage` or an explicit language environment hint, so an English
Windows UI cannot lock out a Chinese chat. `download-tools.ps1` reads
`install_root` when `-InstallRoot` is omitted.

The implementation still accepts `VRC_DCC_UI_LANG` as a legacy language hint
alongside `WORKSTATION_UI_LANG` / `DEBUGGER_UI_LANG`. That compatibility name
does not enable another station. `vrc-dcc` / `vrc-review` / `vrc-world` are retired;
this bootstrap guide provides no VRC setup or overlay path.
