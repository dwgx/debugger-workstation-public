# 2026-10-15 — RE 工具包 v1：三态节表/FDE、描述符切片、Inno LZMA（站内持久化）

Status: verified（2026-10-15，lane P / board RETOOL；`python selftest.py` → `ALL 3 CHECKS PASSED`，exit 0）

## 交付

- 位置：`_re-work/re-toolkit-20261015/`（`_re-work/` 已 gitignore，不进仓库）。
- 内容：3 工具 + `README.md` + `selftest.py`；零第三方依赖（Python 标准库）；只读；有界（大小/解压上限）。
- 工具：
  1. `section_health_fde.py` — 三态节表体检（`healthy`/`lying`/`no-section-table-to-judge`）+ FDE 回退
     （`PT_GNU_EH_FRAME → .eh_frame_hdr → FDE`）；PE 扩展：Go `runtime.pclntab` 起点/名 + `.pdata` 统计。
  2. `fdp_slicer.py` — 描述符切片（字段号下降处切；首字段 = field 1 且 `.proto` 结尾）。
  3. `inno_lzma.py` — Inno LZMA 流定位 + 有界解码（`zlb` magic + props + dict；默认只解 1 MiB 头）。

## 事实（本轮实测）

1. **`derived/ls-candidate/ls.bin` 是 Go PE32+，不是 ELF**（`MZ` + PE32+、7 节；无 `PT_GNU_EH_FRAME`）。
   brief 原文「Go ELF」是错误前提，已更正。函数起点数走 Go `runtime.pclntab`：**121,658** 个
   （`.pdata` RUNTIME_FUNCTION 条目 103,168 个 —— unwind 区块，非 1:1 函数）。
2. **ls.bin 的 pclntab 存在确定性字段损坏（本日新发现）**：部分字段被后处理加
   `Δ = ((field_end + j) << 8j) mod 2^32`（j∈{1,2,3}；field_end = 字段结束文件偏移）。
   修复实测：funcoff 468、nameoff 1,895、entryoff 11（含 2 个 `+0xBB` low16 特例）；
   修复后名字解析 **121,645/121,658**（13 个边界例未解；计数不受影响）。
   修复判据：`_func.entryoff` 相符 / 名字位于 NUL 边界。**j 的选择规则未解（留痕）**。
3. **FDE 回退在合成损坏样本上跑通**：节表 `lying` 时仍解出 3 个起点；无 `PT_GNU_EH_FRAME` 时
   如实报「回退不可用」、**不报 0** —— 两者都有 selftest 断言（fixture 运行时生成）。
4. **描述符切片器复现 126/57**：`baseline-blobs/`（56 文件 = 55 blob + manifest）→ **126 切片 /
   57 distinct sha256**（与 J 车道 126/57 一致；旧口径 132/62 不再使用）。
5. **Inno LZMA 头 1 MiB 解出且校验通过**：`zlb`@0x11da00、props `0x5d`、dict `0x00800000`、
   PNG@0x4a6（后续 0x625 / 0x69c … 图标链同现）；`eof=False`（头模式，未全量解）。
6. 来源脚本：F 车道 4 个脚本**仍在盘**（`%TEMP%\methodsup-20261015\`：`ehfde.py`、`verify_starts.py`、
   `split_fdp.py`、`make_corrupt.mjs`）——工具 #1 的 ELF 部分按其为底稿重写（去掉 capstone 依赖）；
   D 车道 LZMA 读取器**未落盘**，按 `derived/FACTS.md` §A 参数重建（如实记录，非照抄）。

## 失效条件（诚实边界）

- 工具 #1：ELF32 未实现（如实报，不硬解）；无 `PT_GNU_EH_FRAME` → 「不可用」；13 个边界例未解（计数不含糊）。
- 工具 #2：package 为空/缺省的描述符切不出（原口径已知限制）；单文件 >512 MiB 拒。
- 工具 #3：只解头部（默认 1 MiB，上限 256 MiB；真实全流 1.18 GB 不做全量解）；Inno 6.4 文件表未解。

## 复现

- `python selftest.py`（任何 cwd；样本根可用环境变量 `RETOOL_STATION` 覆盖）。
- 样本：`derived/ls-candidate/ls.bin`（178,093,056 B）、`derived/ls-candidate/baseline-blobs/`、
  `originals/DevinUserSetup-x64-3.10.67.exe`（249,606,400 B）。
- 2026-10-15 实测：三条全过、exit 0（总耗时 <1 s）。
