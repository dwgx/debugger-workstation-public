---
tags: [debugger]
status: verified
source: windsurf-re wave-2 (2026-10-15/16, lanes INNO-MEMBERS / LS-GOSYM / RE-DEEPRES-2 / RE-VERIFY-W2)
---

# Devin 桌面 payload：成员级切片配方 + Chromium DataPack 错位陷阱

Case root: `D:/Software/Tool/WorkStation/debugger/Reports/private/windsurf-re-20261015/`（报告 = `<project>/WindsurfAPI/.agent/dispatches-20261015/*.report.md`）。

## 可复用配方（Inno 6.4 安装器 → 全成员）

1. 安装器 = PE32 stub + **raw LZMA1 流**（`zlb`+props `0x5d`+dict 8 MiB，有结束标记）→ Python `lzma.FORMAT_RAW` 可解（innounp 0.49 对 6.4.0.1 报 corrupted，勿再试；三个公开同型案例见 RE-DEEPRES-2 CITATIONS A 组）。
2. payload 头部 `0x0..0x4a6` **不是** Inno 成员表 —— 是 **Chromium DataPack v5**（`version=5/enc=1/entry=164/alias=47`）。**陷阱：`{u32 offset,u16 id}` 的「6B 记录」读法 = 错位 2 字节**；正确 = `{u16 id,u32 offset}` 自 `0x0c` 起（算术闭合：`0x0c+6×165+4×47=0x4a6`）。
3. 真正的 Inno 表在 payload 尾部的 setup header：**block2 = 12,128×87 B data entries**（= NumFileLocationEntries）+ **block1 [Files] 数组 = 12,129 条**（1 卸载器 + 12,128 文件，严格顺序）。按 data-entry 的 offset/size 全量切成员：**零间隙、零重叠、size 和 = payload 全长**（本例 1,178,497,215 B，逐字节自证）。
4. 产物形态：`INDEX.tsv`（id/offset/size/magic/class/sha256_16）+ 分类抽样目录；扩展名-魔数错配率应复核（本例 9,537 项零错配）。

## 本产物事实（Devin Desktop 3.10.67 安装器，as-of 2026-10-15）

- 应用 = **Electron 42.2.0 / Chromium 149.0.7827.22 / node 24.15.0**；内部版本 1.126.0（安装器号 3.10.67 = 另一套号）。
- **language server = `language_server_windows_x64.exe`**（payload @`0x0F6F5DBE`，178,093,056 B，Go 1.26.6，Bazel/gazelle，模块 `github.com/Exafunction/Exafunction`）。
- Go 符号恢复：**121,658 函数起点/名字全命名**（站内 re-toolkit 与 GoReSym 双路 0 差异；修复副本上 GoReSym 亦 121,658/121,658）。身份 = `codeium-language-server`（225 个 `exa/language_server/**` 源文件 + 174/174 LanguageServerService RPC 符号）。
- pak#0/#1 = `chrome_100/200_percent.pak`（各 164 资源 + 47 别名；与 Electron v39 官方 pak 首两条资源逐字节相同）。
- **独立复核抓到并修掉一个真缺陷**：functions.tsv 2/121,658 行 entryoff 非 32 对齐/破坏单调（修复副本覆盖了 `_func` 完好值）——已按 verifier 证据补修 + `PATCH-NOTE.md`。教训：**产物里的「已修」标记行正是分歧集中处**（2,370 条分歧全落在自标的 2,371 个已修行内）。

## 陷阱（下次直接省一小时）

- 「6B 记录」= 错位读法；任何表解析先用**算术闭合**（偏移+计数×宽度=下一区起点）自证。
- `package.json` 真偏移 = `0x84D8CF1`（前车道的 `0x84D8CD5` = 28 B 的 `node_modules.asar` stub——**同名锚点先验长度**）。
- V8 code cache（`.jsc`，`0xC0DE06CF`）在本产物 = **缺席**（1.52 GB 全扫 0；CodeCache 由运行时写 `<userData>/CachedData/<commit>`，不随包发行）——别把「应有 code cache」当预期。
