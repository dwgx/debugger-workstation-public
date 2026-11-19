# Resource cleanup regression

Run these 11 cases with an installed Python and Node executable:

```text
python tests/resource_cleanup/run.py --source <repository-root> --output <new-evidence-directory> --node <installed-node-executable>
```

`--python` optionally selects the child Python; its default is the current interpreter. A Node command name found on PATH is accepted. The output must not already exist and must be outside the source root. No packages are installed.

Only these two source files are copied into the new output's `subject/` tree:

- `web-reverse/tools/cdp-nodes.mjs`
- `native-lab/tools/frida_runtime_facts.py`

The runner then places the three mock sibling modules beside those copies. It never imports a real Frida package, launches Chrome, executes the PE parser fixture, connects to a real browser, or attaches to/kills an OS PID. Real wrapper subprocesses exercise their normal argument checks and cleanup control flow. Mocks create only evidence-directory markers and emit JSONL events.

The five CDP cases cover success, evaluation failure, connection failure, non-loopback refusal and an unsupported external-PID argument. The six Frida cases cover success, attach failure, spawn failure, copy failure, caller-owned stage preservation, and an unsupported external-PID argument. Cleanup is checked against events and resource-marker existence; source fixture bytes, foreign markers and process exit codes are also checked.

`INPUTS.json` binds the original/copied wrappers, mocks, runner and executable files. `RESULTS.json` records every assertion, exact argv, exits and raw-log hashes. Each case retains `stdout.txt`, `stderr.txt`, `events.jsonl` when emitted, and `result.json`. Exit 0 means all 11 cases and input-identity checks passed; exit 2 means a recorded regression. Setup errors are nonzero. Source files are read only.

These tests establish mocked lifecycle behavior, not OS-level Chrome/Frida reclamation. Existing best-effort handling of real cleanup API failures remains outside their claim. The mock modules belong only in this test directory and generated `subject/`, never in the product's tool directories.
