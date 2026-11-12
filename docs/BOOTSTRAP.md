# Bootstrap layout

<!-- I18N:START -->
**English** · this file stays English (like `docs/EVAL.md`)
<!-- I18N:END -->

How `-Apply` turns this skeleton into a station. Dry-run is the default.
Read [`AGENTS.md`](../AGENTS.md) first; use the install root and scope already
agreed with the clone owner.

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
root contract files so an agent opening `D:\Tool\debugger` can still follow the
entry contract. Windows treats `mcp` and `MCP` as the same directory; self-copy
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
