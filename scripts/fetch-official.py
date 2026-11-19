#!/usr/bin/env python3
"""Fetch one reviewed, hash-pinned recipe into a NEW directory; never install/run it.

Without --output, print the acquisition plan only. Hashes are upstream assertions
recorded in manifests/download-recipes.json; a successful download proves byte
identity, not publisher trust, license compliance, or runtime compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request


def get_recipe(manifest: Path, recipe_id: str) -> dict:
    catalog = json.loads(manifest.read_text(encoding="utf-8-sig"))
    if catalog.get("schema") != "workstation-download-recipes/v1":
        raise ValueError("unsupported recipe schema")
    matches = [row for row in catalog["recipes"] if row["id"] == recipe_id]
    if len(matches) != 1:
        raise ValueError("recipe must exist exactly once")
    recipe = matches[0]
    if recipe.get("mode") != "download-only" or not recipe.get("files"):
        raise ValueError("only reviewed download-only recipes are executable")
    seen = set()
    for row in recipe["files"]:
        name = row["name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name) or name.lower() in seen:
            raise ValueError("recipe filename is unsafe or duplicated")
        seen.add(name.lower())
        url = urllib.parse.urlsplit(row["url"])
        if url.scheme != "https" or url.username or url.password or url.query or url.fragment:
            raise ValueError("recipe must use an unambiguous official HTTPS URL")
        if url.hostname not in recipe["allowed_hosts"]:
            raise ValueError("recipe URL is outside its recorded official hosts")
        if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("recipe needs a pinned SHA-256; no skip-verification mode exists")
        if type(row["bytes"]) is not int or row["bytes"] <= 0:
            raise ValueError("recipe needs a positive expected byte count")
    return recipe


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or target.hostname not in self.allowed_hosts or target.username or target.password:
            raise ValueError("download redirected outside the recipe's official asset hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(recipe: dict, output: Path) -> dict:
    if recipe.get("status") == "planned-release-asset":
        raise ValueError("this source release asset is planned; publication has not been confirmed")
    output.mkdir(parents=False, exist_ok=False)
    # A new leaf owns this run's output. Failed partials stay here for diagnosis;
    # no shared cache, install destination, or pre-existing directory is changed.
    opener = urllib.request.build_opener(OfficialRedirects(set(recipe["allowed_hosts"])))
    receipt = {"schema": "workstation-download-receipt/v1", "recipe": recipe["id"], "ok": False, "files": [], "execution": "none"}
    try:
        for row in recipe["files"]:
            partial = output / (row["name"] + ".partial")
            actual_hash = hashlib.sha256()
            total = 0
            request = urllib.request.Request(row["url"], headers={"User-Agent": "debugger-workstation-source-recipes/1"})
            with opener.open(request, timeout=30) as response, partial.open("xb") as target:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > row["bytes"]:
                        raise ValueError(f"download exceeded expected byte count: {row['name']}")
                    actual_hash.update(chunk)
                    target.write(chunk)
            measured = {"name": row["name"], "bytes": total, "sha256": actual_hash.hexdigest()}
            receipt["files"].append(measured)
            if total != row["bytes"] or measured["sha256"] != row["sha256"]:
                raise ValueError(f"download size/hash mismatch: {row['name']}")
            # Exclusive output dir; leave verified bytes in place without extraction.
            partial.rename(output / row["name"])
        receipt["ok"] = True
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        with (output / "DOWNLOAD-RECEIPT.json").open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "manifests/download-recipes.json")
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--output", type=Path, help="new leaf directory; parent must already exist; omitting it only prints the plan")
    args = parser.parse_args()
    try:
        recipe = get_recipe(args.manifest, args.recipe)
        result = fetch(recipe, args.output) if args.output is not None else {"mode": "plan", "recipe": recipe}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
