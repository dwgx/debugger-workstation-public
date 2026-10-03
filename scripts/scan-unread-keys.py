"""Which registry keys does NOTHING in scripts/ read by name?

WHY THIS EXISTS, and why it is a REPORT and not a rule.

Every rule added to this repository in the last day came from the same question: what does
`manifests/capabilities.json` claim that nothing will refuse on when it is false? The method
that kept producing answers was mechanical -- take one field, change it everywhere, run the real
validator, see whether anything moved. This script automates the first half of that method so the
question can be asked again after any change instead of only when someone thinks of it.

THE HONEST LIMIT, stated at the top because it is the reason this cannot be a rule. A name-based
search CANNOT see a generic reader. Measured on 2026-10-03: this scan reports `image_base`,
`aslr`, `sections`, `insns`, `cert_state` and eight more as unread, and every one of them is
wrong -- they are the SOURCE keys of `invoke.fact_map`, which mission.ps1 forwards by iterating
the dict rather than by naming each key. A rule built on this scan would refuse thirteen correct
entries on its first run, and a gate that cries wolf gets switched off. So this prints, and says
what it cannot see.

  python scripts/scan-unread-keys.py                 # report, exit 0
  python scripts/scan-unread-keys.py --fail-on-unread # non-zero if any key is unread
  python scripts/scan-unread-keys.py --json          # machine-readable

Writes nothing. Reads only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "manifests" / "capabilities.json"
SCAN_DIRS = ("scripts",)
SCAN_SUFFIXES = (".py", ".ps1", ".md")


def leaf_keys(node, out: set[str]) -> None:
    """Every dict KEY reachable in the capability list. Values are not keys: a `fact_map` source
    like `counts` is a key of that dict, while the stdout text a fact describes is a value."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                leaf_keys(v, out)
            else:
                out.add(k)
    elif isinstance(node, list):
        for v in node:
            leaf_keys(v, out)


def paths_for(key: str, caps: list) -> list[str]:
    """Where the key occurs, so a reader can judge it rather than count it."""
    hits: list[str] = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}.{k}"
                if k == key:
                    hits.append(p)
                if isinstance(v, (dict, list)):
                    walk(v, p)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    for c in caps:
        walk(c, c.get("id", "?"))
    return hits[:4]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", type=Path, default=REG)
    ap.add_argument("--fail-on-unread", action="store_true",
                    help="exit 1 when any key has zero name occurrences in scripts/. OFF by "
                         "default and it should stay off: the scan cannot see a generic reader, "
                         "so this exit code would be a false alarm, not a finding.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    doc = json.loads(args.registry.read_text(encoding="utf-8"))
    caps = doc.get("capabilities") or []
    keys: set[str] = set()
    leaf_keys(caps, keys)

    blob_parts: list[str] = []
    for d in SCAN_DIRS:
        for f in sorted((REPO / d).rglob("*")):
            if f.is_file() and f.suffix.lower() in SCAN_SUFFIXES:
                blob_parts.append(f.read_text(encoding="utf-8", errors="replace"))
    blob = "\n".join(blob_parts)

    unread = []
    for k in sorted(keys):
        pat = r"(?<![A-Za-z0-9_])" + re.escape(k) + r"(?![A-Za-z0-9_])"
        if not re.search(pat, blob):
            unread.append({"key": k, "paths": paths_for(k, caps)})

    if args.json:
        print(json.dumps({"leaf_keys": len(keys), "unread": len(unread), "items": unread},
                         indent=1, ensure_ascii=False))
        return 1 if (unread and args.fail_on_unread) else 0

    print(f"registry leaf keys      : {len(keys)}")
    print(f"scanned for name matches: {len(SCAN_DIRS)} dir(s), suffixes {SCAN_SUFFIXES}")
    print(f"zero name occurrences   : {len(unread)}")
    print()
    print("READ THIS BEFORE BELOW: a name search cannot see a GENERIC reader. `image_base`,")
    print("`aslr`, `sections`, `insns`, `cert_state`, `refs`, `dns_queries`, `win_certificate`,")
    print("`instrument_ordering`, `runtime_hook_hit`, `rip_operands`, `security_offset` and")
    print("`outdir` all appear below and all are FALSE POSITIVES: they are `invoke.fact_map`")
    print("SOURCE keys, forwarded by mission.ps1 by iterating the dict. Judging the rest needs a")
    print("human or a per-key argument, which is why this prints.")
    print()
    for item in unread:
        print(f"  {item['key']:<34} {', '.join(item['paths'])}")
    return 1 if (unread and args.fail_on_unread) else 0


if __name__ == "__main__":
    sys.exit(main())
