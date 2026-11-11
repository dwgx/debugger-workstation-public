OWNER: researcher-q3 | setukou-20261111/v5/slices/q3-missing/

# Q3 — 15 MISSING / 120 DECLARED 逐条重算（产品树只读）

`as_of 2026-11-11`。结论：15 条 `MISSING` 无一是「丢文件」；盘上重算
`REAL_MISSING=0 / LOGICAL_KEY=5 / PRESENT_BUT_UNVERIFIED=10`（CLAIM 视图，分母 15）。
父代 PRE-ACCEPTANCE 视图（分母 18 = 15 明细 + 3 桶汇总）= `1/6/11`，
其中 `REAL_MISSING=1` 只是空桶 SUMMARY 行，不是 claim。`PROMOTIONS=0`（诚实）。
`claims_total=295` 冻结，SATURATION.tsv 未编辑，`product_tree_writes=0`。

## 逐条结果（MISSING-RECHECK.tsv，15 明细 + 3 汇总 = 18 行）

| claim_id | new_classification | path | exists | file_count |
|---|---|---|---|---|
| TR:C-dynamic.device.frida | LOGICAL_KEY | capabilities.json#capabilities[9] | NA | 0 |
| TR:C-native.il2cpp.symbols | LOGICAL_KEY | scripts/il2cpp-probe.ps1 (NEGATIVE probe) | YES | 1 |
| TR:C-native.ghidra.emulate | LOGICAL_KEY | scripts/emulation-probe.ps1 (NEGATIVE probe) | YES | 1 |
| TR:T-static-reversing | PRESENT_BUT_UNVERIFIED | Static-Reversing/ | YES | 19295 |
| TR:T-debuggers | PRESENT_BUT_UNVERIFIED | Debuggers/ | YES | 627 |
| TR:T-mobile-android | PRESENT_BUT_UNVERIFIED | Mobile-Android/ | YES | 573 |
| TR:T-network-http | PRESENT_BUT_UNVERIFIED | Network-HTTP/ | YES | 1547 |
| TR:T-unpackers-game | PRESENT_BUT_UNVERIFIED | Unpackers-Game/ | YES | 501 |
| TR:T-system-forensics | PRESENT_BUT_UNVERIFIED | System-Forensics/ | YES | 295 |
| TR:T-web-reverse | PRESENT_BUT_UNVERIFIED | web-reverse/ | YES | 29 |
| TR:T-crypto-lab | PRESENT_BUT_UNVERIFIED | crypto-lab/ | YES | 18 |
| TR:T-forensics-lab | PRESENT_BUT_UNVERIFIED | forensics-lab/ | YES | 16 |
| TR:T-fuzz-lab | PRESENT_BUT_UNVERIFIED | fuzz-lab/ | YES | 406 |
| TR:T-ops | LOGICAL_KEY | (no debugger/ dir; external skillspector.exe) | NO | 0 |
| TR:T-build | LOGICAL_KEY | (no debugger/ dir; external vcvars64.bat) | NO | 0 |
| SUMMARY:REAL_MISSING | REAL_MISSING | (bucket summary) | NA | bucket_count=0 |
| SUMMARY:LOGICAL_KEY | LOGICAL_KEY | (bucket summary) | NA | bucket_count=5 |
| SUMMARY:PRESENT_BUT_UNVERIFIED | PRESENT_BUT_UNVERIFIED | (bucket summary) | NA | bucket_count=10 |

## 口径纠正

- brief 的「120 条 `TR:S-*` DECLARED」是 GLOBAL DECLARED 数误标；实测
  `TR:S` 总=64（DECLARED 57 + REAL 7）。Main IRC 2026-11-11 纠正为准。
- GLOBAL DECLARED（分母 120）= `path_resolves_real 86 / logical_not_a_file 34`
  （34 = 6 个目录行 + 28 个 v3 QA/SM 无 TOOL-REGISTER join 行）。
  `TR:S-*` DECLARED（分母 57）= `53 real / 4 not-a-file`。Q2 拥有执行权，Q3 只重分类、不执行。
- 产品树只读：WorkStation `7dfabdb`/11 porcelain、debugger `2c25f26`/2 porcelain（git 只读）。
- `PROMOTIONS.tsv` 空：目录存在 ≠ 能力可用；NEGATIVE 探针证明的是「没有」，
  均不满足 ROUND2-CONTRACT 的 REAL receipt 门槛。`real_verified` 仍为 9。

## Verify

ONE copy-pasteable W-relative command, run from W (no `W/` literal inside),
read-only, recomputes every number from disk, prints measured values +
`as_of` + denominator + both class-count views, and has a negative control
that can go RED (fake `exists=True` for a known-absent path is caught) plus a
positive control (Static-Reversing really exists). Parent re-runs THIS from W.

```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/build-weapon-library-20261110" && python setukou-20261111/v5/slices/q3-missing/verify.py
```

Observed run (2026-11-11, exit 0): `missing_rows=15 real_missing=0
logical_key=5 present_but_unverified=10` (CLAIM view, denom 15);
`recheck_rows_class_counts real_missing=1 logical_key=6
present_but_unverified=11 sum=18` (parent view, denom 18 incl 3 SUMMARY rows);
`declared_rows=120 path_resolves_real=86 logical_not_a_file=34`;
`trs_declared=57 trs_total=64 trs_real_verified=7 trs_path_resolves_real=53
trs_logical_not_a_file=4`; `scripts/ regular files=60`;
`recheck_rows=18 artifact_consistent=True`; `promotions=0`;
`product_tree_writes=0 | WorkStation HEAD=7dfabdb/11 | debugger HEAD=2c25f26/2`;
`claims_total_frozen_ok=YES | saturation_sha16=bc547e6756cff980`;
`negative_control caught=True (RED-capable) | positive_control_green=True`;
`VERDICT=OK`.
