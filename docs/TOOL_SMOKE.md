# Check what is installed

Run the inventory from a source checkout with Python 3.10 or later:

```sh
python scripts/smoke-tools.py --install-root /path/to/your/station --json
```

This reads every entry in `manifests/tools.json`. It starts no tool. `FILE_PRESENT`
and `DIRECTORY_PRESENT` report only filesystem presence; `MISSING` and `UNRESOLVED`
show what needs attention. An inventory exit of zero means the report was produced,
not that the station is installed or accepted.

To run the reviewed CLI version probes on your installed station:

```powershell
python scripts/smoke-tools.py --install-root 'D:/My Station' --probe --report './reports/tool-smoke-new.json'
```

Select a subset with repeated exact manifest names:

```powershell
python scripts/smoke-tools.py --install-root 'D:/My Station' --probe --tool '7-Zip full' --tool 'Wireshark' --json
```

The PowerShell entry remains available. It runs version probes by default; pass
`-InventoryOnly` to avoid starting tools. `-Python` can select an existing interpreter.

```powershell
./scripts/smoke-tools.ps1 -InstallRoot 'D:/My Station' -Tool '7-Zip full','Wireshark' -Json
```

The checked-in probe table covers twelve known CLI entries. It does not open GUI
windows, run installers/drivers, start services, execute target samples or arbitrary manifest commands.
Apktool requires Java on PATH. Unsupported entries retain their presence status and
an explicit reason; they do not become execution passes. A version is an observed
banner, not confirmation that the declared manifest pin or tool functionality is accepted.

`VERSION_VERIFIED` requires exit zero, a matching version, and successful bounded
cleanup. Nonzero exit with a plausible version, timeout, excess output, launch error
or cleanup error produces `PROBE_FAILED`. A missing prerequisite for a reviewed
probe produces `BLOCKED`. Exit codes in probe mode: 1 for a failed probe, otherwise
2 for blocked probes/input errors, otherwise 0. Reports include the full inventory
denominator, selected denominator and separate status counts.

Each process has closed stdin and a 20-second default deadline (adjust with
`--timeout`, up to 120 seconds). On Windows it is created suspended, assigned to an
owned Job, verified, then resumed; descendants are reclaimed on normal and timed-out
completion. Other systems use a dedicated process group. No process outside that
ownership scope is terminated. Both output streams and their hashes are recorded;
report text retains at most 64 KiB of input bytes per stream, with streaming hashes
for the complete files. Crossing a one-MiB combined output threshold fails the probe;
the 20-ms polling interval can allow overshoot, so this is not a hard disk cap. Temporary
capture files are removed on completion. `--report` refuses to overwrite an existing
file, so each run has a distinct output.

These checks are a preparation step for the tool demos and MCP semantic tests, not
their substitute. Run the portable regression with:

```sh
python -m unittest discover -s tests -p test_smoke_tools.py -v
```
