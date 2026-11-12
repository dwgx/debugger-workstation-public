OWNER: parent (took over stalled PackageDesign slice) | package/README.zh-CN.md
# portable-core — 可移植 skill 包

[English](README.md) · [简体中文](README.zh-CN.md)

一份**本地可审阅的 skill 包**（没推、没装进任何产品树）。给「别人把 repo 发给 AI」时的白话入口。

## 是什么
一个入口（`SKILL.md` → `SELF-DEPLOY.md`）、一个 `tests/verify.py`、一个官方+社区修复知识库 `FIX-KB/`、一个 `SELF-REPAIR.md` 自修流程。AI 可以把它加到自己 harness、跑测试、自己排查工具/环境毛病。

## 不是什么
- 不是 `vrc-dcc` / `vrc-review` / `vrc-world`，不写 VRC overlay（2026-09-19 已停用，硬禁令）。
- 不是「全部能力可用」：`RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE`，295 条声明 / 27 条 REAL / 268 个 blockers，包内严格可解析回执 0/27。未验证 ≠ 可用。
- 不含凭据值 / 原始语料 / `.jsonl` / THINK / Hackerone KB 原文 / 私有树内容。
- 不是远程部署：push / Pages / 改设置 / 改 visibility 全是 `[NOT EXECUTED]`。

## AI 三步接手
1. 读 `SKILL.md`，再读 `SELF-DEPLOY.md`（带 `[NOT EXECUTED]` 横幅）。
2. 跑一条环境自检 + 一条 clone+verify；clone HEAD 只打印、不写死——期望验证器给出 `VERDICT=PASS`。
3. 跑 `tests/verify.py`，再跑 `tests/entry_checks.py`（安装契约）；失败就查 `SELF-REPAIR.md` + `FIX-KB/*.tsv`，先 dry-run、再改、再测，exit≠0 就回滚。

## 状态 / 许可
`RELEASE_GATE=RED`（295/27/268）。包内 `LICENSE` 已提供 MIT 文本：代码、配置和 agent contract 采用 MIT；仓库文档正文采用 CC BY-SA 4.0（`LICENSE-docs`）。已记录的 GitHub 仓库元数据仍显示 `NOASSERTION`，这是元数据识别滞后，不是另一份许可。上一波的图/入口属研究归档来源，不在本 clone 内：`public-repo-best-handoff-20261111/assets/`、`deploy/AGENT-ENTRY.md`、`i18n/README*.md`。

## 名称
规范安装名是 **`portable-core`**——frontmatter `name` 必须等于安装目录名。`debuggerstation-selfdeploy` 是 2026-11-11 研究轮的别名：只归档，永远不是安装目标，也永远不进活命令。

## Verify
在 clone 根目录（`repo_root` = 含 `skills/` 的那层）跑：
```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
```
