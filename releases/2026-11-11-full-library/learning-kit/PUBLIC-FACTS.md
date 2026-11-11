OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/RELEASE-CANDIDATE/PUBLIC-FACTS.md

# Public staging facts (sanitized, read-only, NO credentials)

These are the ONLY external facts this kit is allowed to cite. All were obtained
READ-ONLY by the parent; no value of any credential, token, or account name is
reproduced here. `as_of 2026-11-10T21:44:50Z` (Phase 0, disk wins) and
`2026-11-11` (parent baseline + rehearsal).

## Topology (Owner decision A)

- Keep TWO private trees + ONE public repo. NO new repo, NO nesting, NO rename,
  NO visibility change. Publish the sanitized package to the EXISTING public
  repo only after the v4 quality gate is GREEN.
- Dual licence: MIT(code) / CC BY-SA 4.0(docs). The public repo ALREADY has
  `LICENSE` + `LICENSE-docs` at root; this kit does NOT replace them.

## Target repo state (READ-ONLY)

- Public repo HEAD (read-only `git ls-remote`): `bc0747431a67cf9f46b4a02b95cf07b143da7d7a`. NO push.
- The public repo is NOT empty: 518 files, dual licence present, 4-language root
  docs, 8 lab dirs, 25 `_scratch_*` historical audit-noise paths, and 44 root
  entries. So the kit MUST be added as ONE new subdirectory `learning-kit/` and
  must not overwrite ANY root file. `token_like_files=0` (boolean scan; VALUES
  WITHHELD).
- Publication rehearsal (READ-ONLY on a temp clone, NO push): `git fetch` OK;
  `git log --oneline origin/main..HEAD` = EMPTY; `git diff --stat
  origin/main...HEAD` = EMPTY; branch `main`; temp clone porcelain = 0. So the
  target is clean and the commands work, but there is NOTHING to push until a
  scoped Worker copies ONLY `learning-kit/` in and makes ONE intended commit.
- Private trees (READ-ONLY, product trees stay that way): `11` dirty lines and
  `2` dirty lines respectively; must remain so after the wave. `gh_auth=YES`
  is a BOOLEAN only.

## Denominator / reproducibility rule

Every number above carries an `as_of` and the exact command that printed it;
numerator and denominator come from the SAME statistic. A number a command can
generate is never handwritten. Star counts and HEADs are instantaneous snapshots
that WILL drift — preserve `as_of`, never average.

## Red lines (NOT allowed, even though 真跑 is allowed on our own stuff)

online exploitation / bounty-target testing / third-party penetration / scanning
others' hosts / touching non-Owner accounts / credential VALUES in any output /
untrusted binary auto-exec / `gh` write on others' repos / visibility change /
force push / merge / deploy / release without the 5 conditions. `push_executed=NO`.
