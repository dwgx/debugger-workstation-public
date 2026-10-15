# 2026-10-15 — Ghidra 处理 Go 1.25.x 与含空格路径（站内实测）

Status: verified（2026-10-15，Claude Desktop RE 轮，4 个二进制 + 1 个 13.7MB 服务实测）

## 事实

1. **含空格路径必失败**：`scripts/ghidra-headless.ps1 -Sample "C:\Program Files\...\x.exe"` 失败，`.err` = `The filename, directory name, or volume label syntax is incorrect.`（`cmd /c` 引号剥离）。**绕法**：复制到无空格路径（本轮约定 `<工单>/_input/`），复制件 md5 与原件一致后再跑。
2. **GolangSymbolAnalyzer 对 Go 1.25.14 抛 `InvocationTargetException`**（内部回退 1.25.0 解析失败），函数名全为 `FUN_*`。**绕法**：自写 `runtime.pclntab` 解析（Go 1.20+ pclntab 格式），把符号表喂回 Ghidra postScript 重命名 —— 本轮对齐率 **12,706/12,768 = 99.5%**（cowork-svc）。
3. **>10MB 二进制需要 `-TimeoutMs`**：默认 600 s 会在 chrome-native-host（26.6 min）和 cowork-svc（519 s 完成但边界）上超时/接近超时；`-TimeoutMs 3600000` 稳妥。
4. **`ExportDecompile.java`（30 s/函数）遇病理函数体退化**：`pcode error … Unable to resolve constructor`，3000 s 只前进 1 个地址区间。**自写 `ExportDecompileFast.java`（5 s/函数）** 在 2,563 s 内跑完 12,666 个函数（98.4% 成功）。大 .node/.exe 批量反编译建议默认用 fast 版。
5. **Go 二进制**：`go version -m` 不可用于 Linux ELF 载荷时，`GoReSym` 或自读 buildinfo（`\xff Go buildinf:` 魔数 + 版本串 + `path\t<module>`）可靠；本轮 `amaro`/`sdk-daemon` 等均由此拿到模块路径。

## 复现

- 含空格失败样本：任何 `C:\Program Files\**` 下 PE。
- pclntab 补偿：`artifacts/apps/claude-desktop/native/cowork-svc/`（解析脚本）与 `native/vm-daemon/`（同法）。
- fast 导出器：`artifacts/apps/claude-desktop/native/addon/ExportDecompileFast.java`。
