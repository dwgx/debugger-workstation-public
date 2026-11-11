OWNER: researcher-q3 | research/Q3/ (REPORT.md, sources.tsv, claims.tsv) + setukou-20261111/v5/slices/q3-missing/

15 条 MISSING 没有一条是「丢了个文件」：盘上重算 REAL_MISSING=0 / LOGICAL_KEY=5 / PRESENT_BUT_UNVERIFIED=10，全部 15 条 MISSING 都是分类器口径错（把逻辑能力标签/目录判成缺文件）；其中 5 条能力确实不可用，但那是 capability 状态，不是文件缺失。

## Evidence

1. `v5/SATURATION.tsv` 现盘 295 行，status 桶 `{DECLARED_UNVERIFIED:120, RUNNABLE_REAL_VERIFIED:9, OWNER_GATED:151, MISSING:15}`。按 `claim_id` 前缀重算：15 MISSING = `TR:C` 3 + `TR:T` 12（不是别的切片）。[Q3-S01, Q3-S10]
2. 15 条在 `v2/tools/TOOL-REGISTER.tsv` 的 census verdict 全是 `UNVERIFIED` 且 `path_resolves=logical/not-a-file`——它们从一开始就不是文件路径，SATURATION 把 `absent`/`blocked` 升级成 `MISSING` 是口径升级错误。[Q3-S02]
3. 3 条 `TR:C-*` 是 `capabilities.json` 契约：`capabilities[9]`=absent、`[14]`=absent、`[15]`=blocked，`proves=[]`。`dynamic.device.frida` 无探针脚本（`adb devices` 期待 `no devices attached`）；`il2cpp-probe.ps1` / `emulation-probe.ps1` 两个脚本盘上存在，但是 NEGATIVE 探针（expect `IL2CPP ABSENT` / `PCODE EMULATION BLOCKED`），证明的是「没有」，不是能力可用。→ LOGICAL_KEY。[Q3-S03, Q3-S05]
4. 12 条 `TR:T-*` 中 10 条对应 `tools.json` 分类键在 `debugger/` 下有真实目录：`Static-Reversing`(19295 files)、`Debuggers`(627)、`Mobile-Android`(573)、`Network-HTTP`(1547)、`Unpackers-Game`(501)、`System-Forensics`(295)、`web-reverse`(29)、`crypto-lab`(18)、`forensics-lab`(16)、`fuzz-lab`(406)。→ PRESENT_BUT_UNVERIFIED（目录存在 ≠ 能力可用，Q3 未跑任何 REAL 命令，不可 promotion）。[Q3-S04, Q3-S05, Q3-S06, Q3-S09]
5. 另 2 条 `TR:T-ops` / `TR:T-build` 是纯逻辑键：`tools.json` 指向外部绝对路径（`%USERPROFILE%\.local\bin\skillspector.exe` / `vcvars64.bat`），`debugger/` 下无对应目录，也不是文件。→ LOGICAL_KEY。[Q3-S04, Q3-S05]
6. brief 的「120 条 `TR:S-*` DECLARED」是误标：120 是 GLOBAL DECLARED 数；实测 `TR:S` 总数=64（DECLARED 57 + REAL 7）。GLOBAL DECLARED(分母 120) 重算 = `path_resolves_real` 86 / `logical_not_a_file` 34（6 个目录行 + 28 个 v3 QA/SM 无 join 行）；`TR:S-*` DECLARED(分母 57) = 53 real / 4 not-a-file。Q2 拥有执行权，Q3 只重分类不执行。[Q3-S01, Q3-S02, Q3-S06, Q3-S09, Q3-S10]
7. `MISSING-RECHECK.tsv` = 18 行（15 明细 + 3 个桶汇总）；`PROMOTIONS.tsv` = 0 行（诚实：目录存在不是能力验证，0 条 MISSING→RUNNABLE_REAL_VERIFIED）。两套计数都在 `verify.py` 打印：CLAIM 视图(分母 15) = 0/5/10；父代 PRE-ACCEPTANCE 视图(分母 18，含 3 个 SUMMARY 行) = 1/6/11，其中那个 REAL_MISSING=1 是空桶汇总行，不是一条 claim。[Q3-S08, Q3-S11]
8. 产品树只读：`git rev-parse --short HEAD` + `status --porcelain` = WorkStation `7dfabdb`/11、debugger `2c25f26`/2，`product_tree_writes=0`；`claims_total=295` 冻结，SATURATION.tsv 的 sha16 = `bc547e6756cff980`，Q3 未编辑共享文件；126 条未指派 TR 子前缀（GAP G-004）保持冻结。[Q3-S05, Q3-S07, Q3-S08, Q3-S10]

## Confidence

**high**。15 条逐条从 `capabilities.json` / `tools.json` / `debugger/` 盘上目录 + `TOOL-REGISTER.tsv` 重算，非记忆非转述；`verify.py` 从 W 现跑 exit 0，`VERDICT=OK`，每个数字带 `as_of` + 分母 + 两条独立分母（15 claim 视图 / 18 行视图）；负例（对已知不存在路径伪造 `exists=True` 被抓 RED-capable）+ 正例（Static-Reversing 真存在 GREEN）都可复跑。`[INFERENCE]`：把「真缺/口径错」二分映射到 0 REAL_MISSING + 5 条确实不可用的能力，是语义解释（claims.tsv Q3-C11 标 medium）；盘上事实本身 high。

## What would falsify this answer

- 若 `debugger/` 下 10 个分类目录任一被删/为空且 `tools.json` 也无对应条目，则 PRESENT_BUT_UNVERIFIED 会变 REAL_MISSING，`verify.py` 的 `0/5/10` 与 `VERDICT=OK` 同时变 RED。
- 若 `capabilities[9/14/15]` 的 `state` 改为 `observed` 且 `proves` 非空、或出现 REAL 回执，则它们不再是 LOGICAL_KEY（但 Q3 仍不能 promotion：需 ROUND2-CONTRACT 的 REAL receipt）。
- 若 `SATURATION.tsv` 的 `claims_total` ≠ 295 或 sha 变化，则 `claims_total_frozen_ok=NO`，VERDICT FAIL。
- 若父代从 W 重跑 `verify.py` 得到不同数字（尤其 `scripts/` ≠ 60 或 TR:S ≠ 57/64），则本报告的分类分母被证伪。

## Real new subquestions / gaps

- **GAP G-004（父代已登记）**：6 个 TR 子前缀 `TR:X 36 / TR:N 32 / TR:MB 24 / TR:MC 21 / TR:L 11 / TR:K 2 = 126` 条未指派给任何 Round-2 切片，保持冻结，Q3 未触碰、未删除、未重分类。
- 10 条 PRESENT_BUT_UNVERIFIED 分类目录的「能力可用性」未验证：需要 Q2 式的 SYNTHETIC 靶场真跑（但归属 Q2 的 `TR:S-*` 执行域，Q3 不越界），或后续轮次单开。
- 2 条 NEGATIVE 探针（`il2cpp-probe.ps1` / `emulation-probe.ps1`）本轮未执行（PowerShell `-File`、bounded）——若后续轮次要证明「脚本能跑并诚实报 ABSENT」，需单独 REAL receipt；本轮保持 [UNVERIFIED]，不计入 real_verified。
