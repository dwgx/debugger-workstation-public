# Source releases and reusable acquisition recipes

The public product includes the station's tools, router, workflows, Skill
packages, lab sources, synthetic fixture generators and acceptance harnesses.
Third-party runtimes and applications are acquired separately. Start with the
[clean-clone installation and selected backend demo](BOOTSTRAP.md).

## Machine-readable inventory

| File | Contract |
|---|---|
| [publication.json](../manifests/publication.json) | Exactly 63 tool entries and 20 wired backend entries, with source, license evidence, acquisition method and unresolved gaps |
| [publication-files.json](../manifests/publication-files.json) | Exact reviewed source paths; no directory discovery or automatic additions |
| [download-recipes.json](../manifests/download-recipes.json) | Exact official release assets, byte counts and upstream SHA-256 assertions |
| [tools.json](../manifests/tools.json) | Current station declarations; recorded versions remain distinct from newer upstream observations |

The catalog was reviewed on **2026-11-19**. Its counts describe inventory
coverage. They do not mean that every application, provider or backend passed a
live capability test. [Current closeout](CURRENT-CLOSEOUT.md) states the actual
runtime evidence and its scope. The source catalog records an upstream license
file's URL, commit and content hash where available. GitHub's `NOASSERTION` is
not interpreted as an absence of license: mixed/custom terms are recorded for
radare2, x64dbg, UPX, 7-Zip and Volatility 3.

## Build an exact source bundle

Commit the reviewed candidate, including its updated explicit allowlist. From
the repository root, with Python 3.10+ and Git:

```powershell
python scripts/publication.py check --repo .
python scripts/publication.py build --repo . --revision HEAD --output ../station-source.zip
python scripts/publication.py verify --bundle ../station-source.zip --repo . --revision HEAD
```

The output ZIP must not already exist. The builder reads **Git blobs at the
selected commit**, includes the two repository licenses, and writes a per-file
SHA-256 receipt inside the archive. It does not copy the current workstation,
Git directory, ignored files, tool environments or installed applications.
Reading Git blobs also avoids checkout/archive end-of-line transformations
changing frozen fixture bytes. ZIP metadata and ordering are deterministic.

An unreviewed tracked file, missing allowlisted file, symlink, submodule,
credential-shaped content, forbidden runtime path or binary/capture payload
fails the build. A new source path needs an explicit reviewed allowlist entry.
The checker is a bounded guard, not a proof that arbitrary text contains no
private information. Maintainers still review newly included content.

`verify` without `--repo` checks internal membership and checksums; it cannot
authenticate an archive supplied by someone else. Use a trusted published
archive hash and `--repo --revision` to bind it to the selected source commit.

The focused packaging regression is:

```powershell
python tests/publication_regress.py --repo . --output ../publication-regress-new
```

It checks repeatable bytes, exact source coverage, refusal to overwrite an
existing output, tampering, missing members, extra private paths, traversal,
credential-shaped payloads and a backend coverage gap. No tool binary or
backend process is executed.

## Download one official tool without executing an installer

The acquisition helper prints a plan unless a new output directory is given:

```powershell
python scripts/fetch-official.py --recipe assetripper-assetripper-2.0.0
python scripts/fetch-official.py --recipe assetripper-assetripper-2.0.0 --output ../assetripper-download-new
```

It accepts only an explicitly selected recipe, requires the upstream SHA-256
and byte count, uses HTTPS with recorded official redirect hosts, and writes a
download receipt. Failed partials remain in that run's new directory for
diagnosis. Existing output directories are refused. The helper never extracts,
installs or runs the downloaded files; acquisition success is not runtime
acceptance. An asset marked `planned-release-asset` is not downloadable through this helper until
the maintainer confirms publication. The helper never executes an asset, regardless of status.

AssetRipper's official 2.0.0 Windows x64 asset is
[`AssetRipper_win_x64.zip`](https://github.com/AssetRipper/AssetRipper/releases/tag/2.0.0),
44,439,367 bytes, SHA-256
`9a7ef0e7c5c3ea5b90b4e6d855e2d98d5f7ec8c3f9e26fccbc194c6a7b01baf7`.
The expected entry is `AssetRipper.GUI.Free.exe`. The tagged build workflow uses
NativeAOT; its .NET build target alone is not evidence that a separate .NET
runtime must be installed. The maintainer's missing entry was restored at the
same version; version/HTTP smoke does not establish Unity asset conversion.

The 7-Zip 26.06 recipe is `ip7z-7zip-26.06`. Its tested, non-installer extraction
path and selected MCP demo are documented once in [BOOTSTRAP](BOOTSTRAP.md).
The other newer releases in the catalog are acquisition candidates. Ghidra,
ILSpy, capa and Detect It Easy updates still need the relevant provider,
runtime or output-format checks before becoming station upgrades. The IDA
bridge's recorded installed 2.0.0 label must not be downgraded just because
another release channel lists 1.4.0 or a 1.5.0 tag.

Some older official release assets have no publisher digest. They retain a
source URL and manual acquisition entry, but do not get a fabricated hash or a
verification-bypass flag. The legacy bulk downloader's existence checks are
not installation evidence: a directory can contain remnants while its actual
entry is missing.

## Twenty backends: wrappers, sources and actual prerequisites

The catalog maps each wired backend to its wrapper and every relevant upstream
component. A pinned source recipe uses `git clone --no-checkout`, followed by
`git checkout --detach <commit>` and a revision check. Dependencies and host
plugins remain separate steps; those recipes are not a claim that all 20
environments were freshly built here.

- Ghidra, JADX, x64dbg, ReClass, Cheat Engine and ImHex require their matching
  host/plugin setup. The x64dbg plugin and Python client use an upstream pairing
  codename; their version numbers need not be numerically equal.
- mcp7zop requires **Python >=3.12** according to its pinned `pyproject.toml`.
  Keep its environment isolated from the router environment.
- IDA is an owner-supplied licensed installation. No IDA download, activation
  file or commercial payload is included. The stdio/idalib wrapper and GUI
  plugin mode are separate paths.
- MobSF and VirusTotal need user-supplied service configuration. Only variable
  names belong in source; real tokens, captures and service data do not.
- The current Wireshark bridge/semantic-error patch and upstream 0.5.1 are
  different configurations. Compare real error behavior before changing the
  tested configuration. Offline analysis does not require installing Npcap.

## Precise publication exclusions

| Component | Public deliverable and reason |
|---|---|
| Private Owner/vault/conversation records and credentials | Excluded; product source and synthetic fixtures are published instead |
| `.venv`, `node_modules`, compiled outputs, dumps and captures | Recreated from source/recipes; they are not copied from the maintainer's workstation |
| IDA | Official product link and integration recipe; commercial installation remains owner-supplied |
| Npcap | Official acquisition link; ordinary free/demo redistribution is normally restricted, and the driver is never silently installed |
| Reqable and Sysinternals | Official download links; their terms do not grant this repository unrestricted binary republishing |
| MSVC | Official workload/edition instructions; no compiler installation is redistributed |
| dnspy-mcp, ReClass.NET-MCP, volatility3-mcp and the unwired dnSpy alternate | Wrapper/source locations remain visible, but no applicable bridge-wide redistribution license was established at the inspected commits; their source clones are excluded |
| Volatility 3 | Official framework source has a custom VSL license whose share-source terms expressly cover certain wrappers; `rules/LICENSE` in a bridge cannot be treated as that bridge's license |
| `.omp/skills` runtime mirrors | Canonical dated Skill packages are already published; machine loader copies are not a second source authority |

The official terms supporting the non-open application rows are
[Npcap](https://npcap.com/oem/redist.html),
[Reqable](https://reqable.com/en-US/policy/),
[Sysinternals](https://learn.microsoft.com/en-us/sysinternals/license-terms),
[Visual Studio](https://visualstudio.microsoft.com/license-terms/) and
[Hex-Rays](https://hex-rays.com/ida-pro). Per-source exact license evidence is in
the catalog. These exclusions do not remove the named tools from the inventory.

### Preserved YaraFlux source

The public origin returned 404, but the existing shallow Git checkout retains
an MIT-licensed revision. That is a recoverable source artifact, not evidence
that its license vanished. The separate source-only archive contains **116
exact Git blobs**, the original ThreatFlux license, a preservation notice and
an exact manifest. Four explicitly excluded paths are recorded: `.env` was
not read, and two binary documentation images plus a loose upstream fixture
are outside this source release.

See [the preserved-source notice and verification command](../source-releases/yaraflux/README.md).
The archive is a preserved local Git revision, not a new official upstream
release. Its Python AST and file hashes were checked; service compatibility
and dependency installation remain separate acceptance work.
