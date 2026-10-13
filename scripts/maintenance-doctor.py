#!/usr/bin/env python3
"""Maintenance doctor: a report-only debt table for both trees. ALWAYS exits 0.

Why report-only: unpushed commits, dead weight and page size have no machine gate
anywhere in the estate -- that was the scorecard's gap 1/3/6, measured 2026-10-14.
A gate that fails on debt nobody can clear in the same window would be noise; a
report that prints the numbers on every verify-all run makes the debt visible
without blocking work. Exemptions are named on purpose (bypass-actor rule).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIKI = Path(r"<private-tree>")

MIB = 1024 * 1024
WARN = 50 * MIB          # GitHub warns at 50 MiB
REJECT = 100 * MIB       # GitHub hard-rejects at 100 MiB
PAGE_GATE = 500 * 1024   # check-added-large-files default (F16)


def git(path: Path, *args: str, timeout: int = 120) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=path, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else f"[exit {r.returncode}]"
    except Exception as exc:  # noqa: BLE001 - report the failure, do not die
        return f"[{type(exc).__name__}]"


def nlines(s: str) -> int:
    return len([ln for ln in s.splitlines() if ln.strip()])


def tree_block(name: str, path: Path) -> None:
    print(f"  {name}  ({path})")
    if not (path / ".git").exists():
        print("    [not a git tree]")
        return
    ahead = git(path, "rev-list", "--count", "@{u}..HEAD")
    if ahead.startswith("["):
        ahead = git(path, "rev-list", "--count", "HEAD", "--not", "--remotes")
    status = git(path, "status", "--porcelain")
    untracked_lines = sum(1 for ln in status.splitlines() if ln.startswith("??"))
    print(f"    ahead          : {ahead}")
    print(f"    tracked-mod    : {nlines(status) - untracked_lines}")
    print(f"    untracked      : {nlines(git(path, 'ls-files', '--others', '--exclude-standard'))}")
    print(f"    ignored        : {nlines(git(path, 'clean', '-n', '-X'))}")
    for ln in git(path, "count-objects", "-vH").splitlines():
        if ln.startswith(("size:", "size-pack:")):
            print(f"    dotgit {ln}")


def sized(paths: list[str], base: Path) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for rel in paths:
        fp = base / rel
        try:
            out.append((rel, fp.stat().st_size))
        except OSError:
            continue
    return sorted(out, key=lambda t: -t[1])


def show(sized_list: list[tuple[str, int]], limit: int = 8) -> None:
    for rel, sz in sized_list[:limit]:
        flag = "REJECT-LINE" if sz >= REJECT else ("warn" if sz >= WARN else "")
        print(f"    {sz / MIB:9.1f} MiB  {flag:<11s} {rel}")


def main() -> None:
    print("maintenance doctor (report only; exits 0 by design)")
    print("=" * 72)
    for name, path in (("station", ROOT), ("wiki", WIKI)):
        tree_block(name, path)

    wiki_pages = sized(
        [str(p.relative_to(WIKI / "wiki")) for p in (WIKI / "wiki").rglob("*.md")],
        WIKI / "wiki",
    )
    print("  top wiki pages by bytes:")
    for rel, sz in wiki_pages[:10]:
        mark = "  <= over 500 kB page gate" if sz >= PAGE_GATE else ""
        print(f"    {sz:9d}  wiki/{rel}{mark}")

    for name, path in (("station", ROOT), ("wiki", WIKI)):
        tracked = sized(git(path, "ls-files").splitlines(), path)
        over = [(rel, sz) for rel, sz in tracked if sz >= WARN]
        print(f"  {name} tracked files over 50 MiB: {len(over)}")
        show(over)
        if name == "station":
            others = sized(git(path, "ls-files", "--others", "--exclude-standard").splitlines(), path)
            print("  station untracked-not-ignored, top by size:")
            show(others)

    print("  exemptions (named): dead-weight deletion is Owner-gated; AgentRule .before-* backups")
    print("  are that layer's only rollback; redteam-*/ decompiled output is active experiment data")
    print("=" * 72)
    print("maintenance doctor: done (report only)")


if __name__ == "__main__":
    main()
