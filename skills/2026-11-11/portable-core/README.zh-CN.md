OWNER: parent (took over stalled PackageDesign slice) | package/README.zh-CN.md
# debuggerstation-selfdeploy — 可移植 skill 包

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
2. 跑一条环境自检 + 一条 clone+verify；期望 `PUSHED_SHA=875cd108… / VERDICT=PUBLISHED`。
3. 跑 `tests/verify.py`；失败就查 `SELF-REPAIR.md` + `FIX-KB/*.tsv`，先 dry-run、再改、再测，exit≠0 就回滚。

## 状态 / 许可
`RELEASE_GATE=RED`（295/27/268）。拟 MIT(代码)/CC BY-SA 4.0(文档) 双许可；远端目前 `NOASSERTION`，是已知缺口不是授权。上一波图/入口按指针引用、不复制：`public-repo-best-handoff-20261111/assets/`、`deploy/AGENT-ENTRY.md`、`i18n/README*.md`。

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111" && python -X utf8 package/verify.py
```
