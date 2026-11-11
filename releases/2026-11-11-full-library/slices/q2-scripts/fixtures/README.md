# OWNER: researcher-q2 | SYNTHETIC fixtures

syn-positive.json / syn-negative.json are SYNTHETIC capability registries (<=8KiB, sha256 sidecar).
They drive check-requires-tools.py --registry: positive -> OK/exit0; negative(UNMATCHED) -> exit1.
syn-wiki/ is an empty SYNTHETIC wiki dir for sync-wiki-figures.py --check (read-only).
