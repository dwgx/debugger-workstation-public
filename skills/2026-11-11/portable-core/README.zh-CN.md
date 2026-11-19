OWNER: repository maintainers | portable-core/README.zh-CN.md
# portable-core — 可移植 skill 包

[English](README.md) · [简体中文](README.zh-CN.md)

随仓库交付的 AI / 人工接手包：复用 clone 或 archive、装入项目 harness、验证包的完整性，
并排查工具和环境故障。是否安装、是否发布分别需要实际回执，本介绍不预先宣称完成。

## 开始

1. 读 `SKILL.md`，再按 `SELF-DEPLOY.md` 选择已有 clone、archive 或新 clone；不要为了旧清单重复克隆。
2. 跑包级与入口检查。在本包目录执行：

```sh
python -X utf8 -B verify.py
python -X utf8 -B tests/entry_checks.py
```

3. 按 `references/INSTALL.md` 复制完整的 `portable-core` 目录。核对 harness 实际源路径、
   作用域及 SHA-256 与已审阅字节一致。失败时使用 `SELF-REPAIR.md` 与适用的、有日期的 FIX-KB 条目。

包级 PASS 只说明包契约通过，不代表全部工作站工具可用。`SKILL.md` 保留 2026-11-11 的
发布限制与已退役 VRC 家族边界；`references/VERIFY.md` 解释证据范围及历史输出。
按 Owner 当前授权范围执行，不继承旧的指定 Worker 限制或其他维护者的个人授权，保留审批与技术门。

支持的安装名是 **`portable-core`**。历史别名 `debuggerstation-selfdeploy` 不是安装目标。
凭据、私有语料和私有树内容不进入公开产物。包内 `LICENSE` 提供 MIT 文本；仓库文档条款见
根目录的 `LICENSE-docs`。
