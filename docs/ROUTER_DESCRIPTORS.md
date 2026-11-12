# Backend descriptors and environment policy

The Router reads `MCP/.mcp.json`, falling back to `mcp/.mcp.json.template`. These are Router backend descriptors, not a general-purpose implementation of every client's MCP configuration schema. Each entry accepts only `command`, `args`, `cwd`, `env`, and `env_inherit`; the `debugger-router` entry is excluded from backend loading.

## Explicit compatibility boundary

An entry containing **only `command`** keeps the existing `legacy-full` policy: no added argv, inherited caller cwd, and the full Router parent environment plus the Router's existing runtime defaults. It does **not** provide environment isolation. The checked template and local Windows inventory still use this form; this change does not silently migrate existing providers.

Adding **any** of `args`, `cwd`, `env`, or `env_inherit`, including an empty list/object, selects `platform-safe`. It uses the MCP SDK's documented-in-source platform environment baseline, individually requested parent variables, explicit backend overrides, and the Router runtime defaults. There is no wildcard inheritance and no separate `env_policy` input. Unknown fields are rejected rather than silently ignored.

This policy controls which parent environment values reach the child. It is not an OS sandbox: the child still runs under the same account and may read files, use the network, or launch descendants according to that account's permissions.

## Fields

| Field | Contract |
| --- | --- |
| `command` | Required nonempty string without NUL. Existing `{{DEBUGGER_ROOT}}` replacement and legacy root translation remain. A bare executable is resolved using PATH; strict Windows lookup uses the backend's selected PATH. Lists and shell command strings are not supported. |
| `args` | List of strings, preserving order, empty arguments, Unicode and whitespace. Values are literal: no template, environment or shell expansion is performed by the Router. Direct executable argv can contain quote and metacharacter literals. Windows batch files use the narrower subset below. |
| `cwd` | Nonempty existing directory string, optionally containing `{{DEBUGGER_ROOT}}`. Relative paths resolve from the installation root, not the Router caller's cwd. Omission preserves the inherited caller cwd. |
| `env` | Object of string values. Keys must be nonempty and contain neither `=` nor NUL; values cannot contain NUL. Values are literal. They override inherited values for this backend only. |
| `env_inherit` | List of exact parent environment names to add to the SDK baseline. Each requested name must exist. Duplicate names are refused. Empty list means no extra inherited names, not an empty environment. |

On Windows, environment names are case-insensitive: `Path` and `PATH` are the same key, and duplicate case variants within one `env` object or one inheritance list are rejected. On POSIX, distinct-case names remain distinct. No operation mutates `os.environ`.

The runtime defaults retain the existing behavior: `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, FastMCP banner/update/rich-logging settings, and the installation's `MCP/bin` prefix in PATH. These are applied after descriptor overrides. The SDK itself merges its baseline into the supplied environment; the Router uses that same public baseline rather than monkey-patching the SDK.

Observed SDK 1.29.0/1.29.1 baseline:

- Windows: `APPDATA`, `HOMEDRIVE`, `HOMEPATH`, `LOCALAPPDATA`, `PATH`, `PATHEXT`, `PROCESSOR_ARCHITECTURE`, `SYSTEMDRIVE`, `SYSTEMROOT`, `TEMP`, `USERNAME`, `USERPROFILE` when present and accepted by the SDK.
- POSIX: `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER` when present and accepted by the SDK.

These keys can expose user configuration directories. Do not describe `platform-safe` as zero-environment or credential-proof execution. The runtime requirement remains `mcp>=1.13,<2`; the actual baseline is supplied by the installed SDK, and a materially changed SDK baseline needs fresh review.

## Example

```json
{
  "mcpServers": {
    "analysis-local": {
      "command": "python",
      "args": ["-X", "utf8", "-B", "C:/owned/backend.py", "", "two words"],
      "cwd": "workspaces/analysis",
      "env": {"TOOL_MODE": "offline"},
      "env_inherit": ["TOOL_LICENSE_PATH"]
    }
  }
}
```

Create the owned working directory and provide the required parent variable before use. Do not place secret values in a tracked JSON file; prefer a narrowly named inherited variable supplied through the clone owner's existing secret mechanism. Adding `env_inherit: []` to an old command-only entry deliberately changes its policy and may remove variables that an unreviewed provider needs.

## Windows batch subset

Strict `.cmd`/`.bat` launches use the actual Windows command interpreter with AutoRun disabled and delayed expansion disabled. Command path and arguments may contain ordinary text, Unicode, whitespace and empty arguments. The Router refuses CR/LF, embedded double quotes, and `& | < > ^ % ! ( )` in the batch command path or arguments before spawning the backend. This avoids treating CRT argv quoting as a complete shell escaping algorithm. Use a direct executable with argv when those literals are needed.

A batch file's own content, quoting and text encoding remain its author's responsibility. If it forwards arguments, it must preserve them (for example `%*`); the Router cannot repair a wrapper that discards or expands its arguments. A batch script under an unsupported path can be replaced with a directly invoked executable descriptor. Existing command-only `.cmd` behavior remains legacy and does not gain the strict subset's guarantees.

Platform references: [Microsoft cmd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd) and [Microsoft call](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/call). These explain the shell parsing concerns; observed Windows acceptance results, not documentation alone, determine which adapter cases passed.

## Validation, catalog and warm sessions

Malformed descriptors raise an `INVALID_BACKEND_DESCRIPTOR` error identifying the backend/field/reason without serializing rejected argument or environment values. Descriptor parsing is fail-closed: an invalid configured backend blocks catalog/session acquisition until corrected. No backend is spawned for a rejected descriptor.

`list_backends` reports `command`, `args_count`, `cwd`, `env_policy`, `env_keys`, and `env_inherit`; it does not advertise argument values or environment override values.

A warm session pins its immutable descriptor. Changing command, args, cwd, overrides, inheritance or policy and then addressing the existing session ID returns `DESCRIPTOR_CHANGED`. Explicitly close that session or choose a new session ID. The Router does not automatically restart a stateful backend, replay requests, or reinterpret an unknown previous result.

## Reproducible acceptance

From a source checkout containing tests, using a new external output directory:

```text
python -X utf8 -B tests/router_descriptor/descriptor_probe.py --source mcp/debugger-router/server.py --out <new-external-evidence-directory>
```

The driver freezes its platform case set before execution, starts the real Router frontend, uses the real MCP SDK inside the Router, and observes an owned protocol fixture process. It retains raw frontend messages, startup argv/cwd/synthetic-env observations, structured failures and cleanup results. The same driver is run against the frozen old server for the OLD comparison. Direct executable quote/metacharacter literals and strict Windows batch restrictions are separate cases.

This tests descriptor behavior, not the correctness of a real debugger, GUI bridge, API provider, target generation or full product release. Provider migration needs a separately selected real-tool acceptance contract.
