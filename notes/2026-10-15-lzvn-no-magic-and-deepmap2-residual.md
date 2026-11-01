# 2026-10-15 — 「未解残差」多数是定位启发式误判：deepmap2 586 条全解（LZVN 无 magic 流）

Status: verified（2026-10-15，AwesomeUI 波 au8-deepmap2-last；DONE WHEN `deepmap2-last-ok manifest 4921 residual 0`，rc=0；586/586 新 PNG 逐字节回环 + IHDR 尺寸 + IDAT 解压长 = manifest）

## 事实

1. Apple `.car` deepmap2 容器（macOS 26 全量 15,230 条）曾被启发式判「未解 586」（truncated 246 / short-raw 235 / planes 84 / raw<npx 20 / no-dmp2 1）。收口轮逐类重解：**586/586 全部解出，根因全部是容器定位启发式误判，不是数据损坏**。
2. 无 magic 的小负载 = **LZVN 流**：`[dmp2 头][u32 声明长=可用长][LZVN payload]`；mode4 在 LZVN 流后跟调色板段。判据：LZVN 结尾 `06 00 … 00` 模式 536/536 命中；输出长恰为 npx×bpp。
3. mode1 = **未压缩原始像素**（12B 头，像素 @o+12，bpp 随 pixel format）。
4. LZFSE 流（mode2 等）：magic 直接起于 o+16（旧启发式只看固定偏移，漏判致「truncated」误分类）；endp == 流长 42/42。
5. 复现：`ui-atlas/macos/deep/deepmap2/scripts/last_recover.py`（blob 库 `last_dump.py`）；manifest_close 4,335→**4,921**（+533 recovered-lzvn / +40 alpha-template / +8 raw / +5 lzfse）。

## 教训

- 「解不开」清单先过一遍**定位启发式**：无 magic 流、非固定偏移 magic、声明长==可用长（非截断）是三类高频误判。
- 交叉判据（同资产多尺度逐值一致 + 结构端点模式统计）比「像不像损坏」的目视更可靠。

## 失效条件

- 适用 Apple deepmap2 / LZVN/LZFSE 家族；其他容器格式需重新验证端点判据。
