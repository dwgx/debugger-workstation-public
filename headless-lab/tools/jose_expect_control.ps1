# WHY A FILE. This control mints a token and analyses it in two steps, and a two-step control has
# to live somewhere. Written inline it had to interpolate through PowerShell's own quoting, and the
# failure mode of that is a probe that no longer reaches the tool it is supposed to guard.
$ErrorActionPreference = 'Stop'
$tok = node crypto-lab/tools/mint_alg_none_token.mjs
if (-not $tok) { Write-Error 'token mint produced nothing'; exit 3 }
node crypto-lab/tools/analyze.mjs --token $tok --quiet --json --expect ALG_NONE
exit $LASTEXITCODE
