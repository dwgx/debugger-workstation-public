# 2026-10-15 — macOS dyld 共享缓存符号名：ipsw 工具链直接可得（「不可得」论断被推翻）

Status: verified（2026-10-15，AwesomeUI W7 au7-symnames；symtab 676,379 行；IMP 交叉 50/50 精确；全量 98.67%）

## 事实

1. 此前 W6 报告断言「符号名不可得」——W7 复盘取证推翻：**dyld 共享缓存的符号名提取有成熟公开工具**（ipsw / dyld-tools / dsc_fix），不必自研。
2. 实测（macOS 26.5.2 共享缓存）：ipsw v3.1.738 导出 **676,379 行** symtab；对 50 个 IMP 做交叉验证 50/50 精确命中；全量对齐率 98.67%。
3. 流程要点：共享缓存按 dylib 拆分为独立镜像 → 从镜像符号表（含导出 trie）导出地址↔名字；与 ObjC 运行时数据（classlist/methodlist）交叉即得方法名。
4. 落点：AwesomeUI `ui-atlas/macos/deep/symnames/symtab.tsv`（676,379 行）+ README（流程与误差口径）。

## 教训

- 对「不可得/做不到」的旧论断，收口轮必须做**先例检索**（公开工具/论文/开源项目），再决定自研或采用；本轮采用先例省下自研轮子（对照：W7 同时验证了「菜单栏/PreferencePanes 三代」等确无公开先例，属真领先）。
- 采用外部工具要记来源+版本+sha256。

## 失效条件

- 适用 dyld shared cache（macOS）；iOS 缓存同理但需对应版本工具；符号名覆盖率因缓存版本而异。
