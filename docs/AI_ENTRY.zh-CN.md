# AI 入口 —— 先读这一页

`as_of 2026-11-12`。这一页只做一件事：告诉 AI（和它的人类）权威规则在哪、该跑什么、
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
| [`releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md) | 历史发布闸门；保留原文，引用时带上日期与分母。 |

## 3. 分开报告的验证范围

| 范围 | 能说明什么 | 入口 |
| --- | --- | --- |
| 便携技能包 | 必需文件与安装契约一致。 | 下方 `portable-core/verify.py` 与 `tests/entry_checks.py`。 |
| 候选 CLI profile | 一次预先固定计划的离线 PCAP 执行满足语义 oracle 与清理契约。 | [`CURRENT-CLI-PROFILE.md`](CURRENT-CLI-PROFILE.md)。 |
| MCP 运行配置 | router + 20 个配置后端；安装就绪和真实 provider 操作另需证据。 | [`BOOTSTRAP.md`](BOOTSTRAP.md)。 |
| 历史证据发布 | 2026-11-11 的结论与 295 行台账分类保持原样。 | [`RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)。 |

295 行混有脚本、技能、笔记、元数据等主张，不等于 295 个可运行工具。
有限 profile 通过不替换历史闸门，也不等于全产品完成。候选代码的本地状态、
采用记录与公开发布分别核验。

### 包级命令

```sh
python -X utf8 skills/2026-11-11/portable-core/verify.py
```

exit 0 + `VERDICT=PASS` 才算包级检查通过。其它任何结果都是发现（finding），不是可以
就地抹掉的细节。

**从当前 clone 接手——最短路径。** `repo_root` = 你刚 clone 下来、含 `skills/` 的那一层；
下面所有路径都不依赖研究归档、私有 wiki 或写死的发布 SHA。

1. 读 [`skills/2026-11-11/portable-core/SKILL.md`](../skills/2026-11-11/portable-core/SKILL.md)
   ——部署 / 加入 harness / 自测 / 自修 / 诊断。
2. 跑上面的包级自检，再跑安装契约：
   `python -X utf8 skills/2026-11-11/portable-core/tests/entry_checks.py`。
   两者都调用同一个校验器——`skills/2026-11-11/portable-core/tests/package_contract.py`。
   缺必需文件时输出 `MISSING_REQUIRED=<path>` 并 exit 1（不再抛 traceback）；
   必需闭包包含 `LICENSE` 与各 reference 文件。
3. 读 [`releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md`](../releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)
   并逐字引用。验证器变绿也不改变 `RELEASE_GATE=RED`。

**规范技能名。** 安装目录名必须等于 frontmatter 的 `name`：`portable-core`。
`debuggerstation-selfdeploy` 是 2026-11-11 研究轮的别名——只归档，永远不是安装目标，
也永远不进活命令。

**实际 CLI 的有限验收。** 候选 runner 将运行前计划、真实子进程、保留产物与语义 oracle 绑定；具体入口见 [`CURRENT-CLI-PROFILE.md`](CURRENT-CLI-PROFILE.md)。该结果与包级自检、历史发布闸门分别报告。

## 4. 不要让 AI 靠踩坑学会的规矩

- **先问后做。** 只读探索 → 提澄清问题 → 给计划 → 你确认后才跑 `scripts/bootstrap.ps1`。
- **本仓库不分发任何第三方工具二进制。** 工具靠 `manifests/` +
  `scripts/bootstrap.ps1` / `scripts/download-tools.ps1` 从官方源拉取。
- **绝不静默安装。** 驱动、服务、Npcap、Defender / 注册表 / 启动项、可疑样本：先写
  后果与回滚，确认后再执行。
- **RED 就报 RED，结论带上范围与日期。** 2026-11-11 发布记录为 `RELEASE_GATE=RED`、
  `COMPLETENESS_VERDICT=NOT_COMPLETE`、**268 个结构性阻塞**（295 条清单主张：
  27 REAL / 102 DECLARED / 151 OWNER_GATED / 15 MISSING）。保留历史分类，
  新验收另行报告；未验证的主张永远不能当能力引用。
- **HARD BAN —— vrc 家族。** `vrc-dcc` / `vrc-review` / `vrc-world` /
  `overlays/vrc-dcc` 已于 2026-09-19 退役。永不恢复，永不写 VRC overlay。
- **不写凭据值、不搬原始语料。** 报告、提交、笔记都不行。
- 对话用中文；git 提交说明保持英文；契约改在 git 里，不改在聊天里。

## 5. 其余入口

- [`docs/INDEX.md`](INDEX.md) —— `.agent/`、`evidence/`、`docs/` 的分类索引。
- [`docs/i18n/zh-CN/MAINTAIN.md`](i18n/zh-CN/MAINTAIN.md) —— 维护这个 clone。
- [`docs/i18n/zh-CN/I18N.md`](i18n/zh-CN/I18N.md) —— 语言选择与初始化。
- [`docs/WORKSTATION_RULES.md`](WORKSTATION_RULES.md) —— 部署后的操作规则。
