# AI 入口 —— 先读这一页

`as_of 2026-11-11`。这一页只做一件事：告诉 AI（和它的人类）权威规则在哪、该跑什么、
什么话永远不能说。它不新增规则，只做路由。

## 1. 权威契约 —— 动手前先读

| 文件 | 作用 |
| --- | --- |
| [`AGENTS.zh-CN.md`](../AGENTS.zh-CN.md) | **中文权威入口**：初始化握手（先问后做）、克隆主人覆盖层、MCP 策略、红线。英文正文仍是 [`AGENTS.md`](../AGENTS.md)。 |
| [`docs/i18n/zh-CN/AI_USAGE_GUIDE.md`](i18n/zh-CN/AI_USAGE_GUIDE.md) | 阅读顺序、AI 可自行决定的事、必须确认的事。 |
| [`CLAUDE.md`](../CLAUDE.md) / [`GEMINI.md`](../GEMINI.md) / [`.github/copilot-instructions.md`](../.github/copilot-instructions.md) / [`.cursor/rules/`](../.cursor/rules/) | 各客户端入口，全部指回 `AGENTS.md`。 |
| [`templates/i18n/zh-CN/INIT_QUESTIONNAIRE.md`](../templates/i18n/zh-CN/INIT_QUESTIONNAIRE.md) | 驱动初始化的澄清问题清单。 |

客户端入口只是指针，不是第二份契约。它们和 `AGENTS.md` 冲突时，以 `AGENTS.md` 为准。

## 2. 2026-11-11 技能包

| 路径 | 内容 |
| --- | --- |
| [`skills/2026-11-11/portable-core/SKILL.md`](../skills/2026-11-11/portable-core/SKILL.md) | 便携核心技能：部署 / 加入 harness / 自测 / 自修 / 诊断。 |
| [`skills/2026-11-11/station-routers/`](../skills/2026-11-11/station-routers/) | 站点路由（`debugger-workstation`、`debugger-review`）。它们取代旧版 [`skills/debugger-workstation/SKILL.md`](../skills/debugger-workstation/SKILL.md) 与 [`skills/debugger-review/SKILL.md`](../skills/debugger-review/SKILL.md)；旧文件保留，文件头标 `SUPERSEDED`。 |
| [`releases/2026-11-11-full-library/README.md`](../releases/2026-11-11-full-library/README.md) | 已发布的证据 / 主张库。 |
| [`releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md) | 必须逐字引用的闸门结论。 |

## 3. 唯一自检命令

```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
```

exit 0 + `VERDICT=PASS` 才算包级检查通过。其它任何结果都是发现（finding），不是可以
就地抹掉的细节。

## 4. 不要让 AI 靠踩坑学会的规矩

- **先问后做。** 只读探索 → 提澄清问题 → 给计划 → 你确认后才跑 `scripts/bootstrap.ps1`。
- **本仓库不分发任何第三方工具二进制。** 工具靠 `manifests/` +
  `scripts/bootstrap.ps1` / `scripts/download-tools.ps1` 从官方源拉取。
- **绝不静默安装。** 驱动、服务、Npcap、Defender / 注册表 / 启动项、可疑样本：先写
  后果与回滚，确认后再执行。
- **RED 就报 RED。** `RELEASE_GATE=RED`、`COMPLETENESS_VERDICT=NOT_COMPLETE`、
  **268 个结构性阻塞**（295 条主张：27 REAL / 102 DECLARED / 151 OWNER_GATED /
  15 MISSING）。发布不改变这两个事实。未验证的主张永远不能当能力引用。
- **HARD BAN —— vrc 家族。** `vrc-dcc` / `vrc-review` / `vrc-world` /
  `overlays/vrc-dcc` 已于 2026-09-19 退役。永不恢复，永不写 VRC overlay。
- **不写凭据值、不搬原始语料。** 报告、提交、笔记都不行。
- 对话用中文；git 提交说明保持英文；契约改在 git 里，不改在聊天里。

## 5. 其余入口

- [`docs/INDEX.md`](INDEX.md) —— `.agent/`、`evidence/`、`docs/` 的分类索引。
- [`docs/i18n/zh-CN/MAINTAIN.md`](i18n/zh-CN/MAINTAIN.md) —— 维护这个 clone。
- [`docs/i18n/zh-CN/I18N.md`](i18n/zh-CN/I18N.md) —— 语言选择与初始化。
- [`docs/WORKSTATION_RULES.md`](WORKSTATION_RULES.md) —— 部署后的操作规则。
