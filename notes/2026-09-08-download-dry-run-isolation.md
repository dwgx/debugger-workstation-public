---
tags: [debugger,downloads,dry-run]
status: verified
source: agent-notes 2026-09-08
---

# download-dry-run-isolation

Verified on 2026-09-08: scripts/download-tools.ps1 must keep all filesystem writes behind -Apply. A dry-run may resolve release metadata, but it must not create _download-stage or destination parent directories. The regression check uses a fresh temporary install root and compares its child count after the command.
