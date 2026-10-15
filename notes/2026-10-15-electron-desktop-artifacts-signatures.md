# 2026-10-15 — Electron 桌面应用的字节级指纹（fuse wire / V8 code cache / asar 头）

Status: verified（2026-10-15，Claude Desktop 2.37337.1 / Electron 44.7.0 实测）

面向下一次 Electron/MSIX 桌面应用 RE，三条可直接复用的字节级指纹：

## 1. Electron fuse wire

- 位置：`claude.exe` @199,416,024（在 `.rdata` 尾部、紧贴 browser_init js2c bundle）。
- 结构：**32 字节 ASCII 前缀** `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX` + `01 09` + **N 个 ASCII 状态字符**（`0`/`1`，每 fuse 一字节）+ 结束符 `01 09`。
- 读法：前缀后第一个 `01 09` 之后就是状态串；`010011011`（9 fuse）= RunAsNode off / CookieEncryption on / NODE_OPTIONS off / --inspect off / Integrity on / OnlyLoadAppFromAsar on / V8Snapshot off / GrantFileProtocol on / WasmTrap on。
- 关联资源：INTEGRITY 资源里的 app.asar 头 SHA256 应与磁盘 asar 头字节一致（Electron 只校验**打包成员**；`unpacked:true` 成员的 integrity 与磁盘**本来就不符**——那是「签名前镜像」，不是包被动过）。

## 2. V8 code cache（`.jsc`，Electron compile-cache）

- 头 32 B：magic `CF 06 DE C0`（LE 0xC0DE06CF）；`@0x08` = **被包装后的源长度**（`Module.wrap` 包装 62 B + 4 B 尾）——**不是内容哈希**：`field == 源文件字节数 + 66`（3/3 精确成立）。
- `@0x14` = payload 长度（= 文件大小 − 32）；payload **非加密非压缩**（熵 4.3–6.0 bits/byte；本轮在 hub 的 .jsc 里直接明文可见 4 个白名单 URL + SRI）。
- 生成者可以是应用自身（Claude 用 `CLAUDE_GENERATE_COMPILE_CACHE` 机制在 `index.pre.js` 里生成），不限于 V8 运行时。

## 3. asar 头与校验

- 头布局：`u32le` header pickle 长度 / `u32le` header 字符串长度 / `u32le` header JSON 长度 / JSON（= pickle 内容）/ 1 B 填充 / 数据区。本轮实测 4/133648/133644/133639、data_start=133656。
- 独立交叉校验：MSIX 包内 `AppxBlockMap.xml` 可复算文件块哈希（本轮 3,511 文件 / 3,862 块 0 不符）。
- `unpacked:true` 成员 = 运行时按 `app.asar.unpacked/` 同名路径加载；其磁盘副本与 asar 内声明 integrity 不符是**签名剥离规则**（截断证书表 + CheckSum/目录项置零），可用「截断证书表 + CheckSum 置零」复现 5/6（第 6 个 msalruntime.dll 未穷尽）。

## 复现

`<project>/AwesomeUI/dissections/apps/claude-desktop/{native/core,native/claude-exe,vendored,bytes}/` 与 `reports/verify-claude-w4.md`（24 条独立复核含本三条的逐字节复现命令）。
