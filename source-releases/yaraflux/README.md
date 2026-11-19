# Preserved YaraFlux source, version 1.0.17

Original project: <https://github.com/ThreatFlux/YaraFlux>  
Preserved revision: `a4deb318d85cd2febe8b87695008444ee294dee7`  
License: [MIT, Copyright (c) 2025 ThreatFlux](LICENSE.upstream)

The original public endpoint returned 404 on 2026-11-19. A pre-existing shallow
Git checkout preserved this source. The archive includes 116 exact Git blobs,
`SOURCE-MANIFEST.json` and [PRESERVATION-NOTICE.txt](PRESERVATION-NOTICE.txt).
The manifest lists all selected paths and their SHA-256/Git object identity,
and the four excluded paths with reasons. No `.env` value was read or copied.

Expected asset: `YaraFlux-source-a4deb318d85c.zip`  
Size: **1,255,549 bytes**  
SHA-256: `61892545dfd874825a3575114906243bb8124e2d93c5e67fcc6394f3a9f3067a`

The [preservation release](https://github.com/dwgx/debugger-workstation-public/releases/tag/yaraflux-source-a4deb318d85c) is public. An anonymous download matched the digest, size and internal source manifest on 2026-11-19 UTC. Verify a downloaded copy from this repository:

```powershell
python scripts/publication.py verify-preserved --bundle <downloaded-zip> --manifest manifests/source-releases/yaraflux-a4deb318d85c.json
```

The exact file hashes, UTF-8 decoding and 72 Python ASTs were checked when the
source archive was made. No dependency, backend or service was run for those
checks. Python >=3.13 and the archived dependency locks are declared by this
revision. The archive's source/runtime claims, upstream defaults and global
client examples are historical upstream content, not new station defaults.
Use a separate environment, private credentials and explicit local storage /
loopback binding when evaluating it.
