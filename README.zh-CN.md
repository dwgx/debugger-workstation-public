# debugger-workstation

<!-- I18N:START -->
[English](README.md) · **简体中文** · [日本語](README.ja.md) · [한국어](README.ko.md)
<!-- I18N:END -->

## 从这里开始

1. **先 clone**，再读 [`AGENTS.zh-CN.md`](AGENTS.zh-CN.md)（英文权威版 [`AGENTS.md`](AGENTS.md)）——AI 的权威契约：先问后做、红线。
2. **只跑 dry-run：** `pwsh scripts/bootstrap.ps1 -InstallRoot "D:\Tool\debugger"`——只打印计划，不写盘、不下载。
3. **2026-11-11 证据发布：** [`releases/2026-11-11-full-library/README.md`](releases/2026-11-11-full-library/README.md) 与 [`RELEASE-GATE-STATUS.md`](releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)——`RELEASE_GATE=RED`、`COMPLETENESS_VERDICT=NOT_COMPLETE`、**历史分类中的 268 个结构性阻塞**；发布不改变该结论。295 条是清单主张，不等于 295 个可运行工具。
4. **技能包：** [`skills/2026-11-11/`](skills/2026-11-11/)——portable core + 站点路由。规范技能名与安装目录是 **`portable-core`**（frontmatter `name` = 目录名）；`debuggerstation-selfdeploy` 是 2026-11-11 研究轮的归档别名，永远不是安装目标。自检在当前 clone 内完成、不依赖研究目录：`python -X utf8 skills/2026-11-11/portable-core/verify.py`（安装契约：`tests/entry_checks.py`）。
5. **AI 单一入口：** [`docs/AI_ENTRY.zh-CN.md`](docs/AI_ENTRY.zh-CN.md) · 改了什么：[`CHANGELOG.md`](CHANGELOG.md) · 发布页：[`RELEASE.md`](RELEASE.md)。

6. **静态首页：** 仓库根的 [`index.html`](index.html) 是当前中英双语源码；[`docs/site/index.html`](docs/site/index.html) 保留为 2026-11-11 的历史首页快照。部署状态与实际站点 URL 须另外核验。
7. **有限 CLI 验收：** [`docs/CURRENT-CLI-PROFILE.md`](docs/CURRENT-CLI-PROFILE.md) 给出候选 runner 与离线 PCAP profile 的入口；它与包级检查、真实 MCP provider 验收、全产品发布分别报告。

便携式逆向 / 安全分析 / 调试 / 解包 / 移动端分析 / 网络抓包 / 系统巡检 / MCP 自动化工作站的 **骨架仓库**。

任何 AI agent(Claude / Codex / Gemini / Cursor / Copilot / Grok)或人类 clone 后,按 [docs/i18n/zh-CN/I18N.md](docs/i18n/zh-CN/I18N.md) 选定界面语言,走 [AGENTS.zh-CN.md](AGENTS.zh-CN.md) 握手,即可在自己机器上还原一个**可被 AI 最高效调用**的工具站。本树是**参考骨架**：主人保留自己的工具和提示词（`OWNER.example.md` → gitignore 的 `OWNER.md`）。主人要求时 agent 可以**改这个 clone**；聊天不能取消红线（[docs/i18n/zh-CN/MAINTAIN.md](docs/i18n/zh-CN/MAINTAIN.md)）。对话用中文；git 提交说明保持英文。

> ⚠️ **本仓库不分发任何第三方工具二进制。** 工具靠 `manifests/` + `scripts/bootstrap.ps1` 从各官方源拉取。详见 [DISCLAIMER.zh-CN.md](DISCLAIMER.zh-CN.md)。

---

## 这个仓库里有什么

| 路径 | 内容 |
| --- | --- |
| `AGENTS.zh-CN.md` | 中文权威入口:初始化握手(先问后做)、克隆主人覆盖层、MCP 策略、红线。见 [docs/i18n/zh-CN/I18N.md](docs/i18n/zh-CN/I18N.md) 与 [docs/i18n/zh-CN/MAINTAIN.md](docs/i18n/zh-CN/MAINTAIN.md)。 |
| `OWNER.example.md` | gitignore 的 `OWNER.md` 模板。 |
| `docs/EVAL.md` | 静态合同测评（英文，像测试一样）。 |
| `CLAUDE.md` / `GEMINI.md` / `.github/copilot-instructions.md` / `.cursor/rules/` | 各客户端入口,均指向 `AGENTS.md`。 |
| `templates/INIT_QUESTIONNAIRE.md` | 驱动动态初始化的澄清问题清单。 |
| `docs/` | 给人/AI 的文档。任务结束后的进化：`docs/AGENT_EVOLUTION.md`。 |
| `skills/2026-11-11/station-routers/debugger-review/` | 双轴审查 + 把教训写回笔记/手册。 |
| `notes/` | 可入库短笔记（无样本、无密钥）。 |
| `docs/extensions/INDEX.md` | curated 的 MCP server / AI skill 扩展资源索引。 |
| `manifests/tools.json` | 工具清单:名称、版本、官方下载源、放置路径。 |
| `manifests/mcp-backends.json` | 第三方 MCP backend 上游清单 + 自研核心。 |
| `mcp/debugger-router/server.py` | **自研**轻量 MCP 路由(按需启动后端,默认唯一启用)。 |
| `mcp/bin/*.cmd` | **自研**后端 MCP 包装脚本(相对路径,可移植)。 |
| `mcp/.mcp.json.template` | MCP 配置模板,bootstrap 替换 `{{DEBUGGER_ROOT}}`。 |
| `scripts/download-tools.ps1` | 确认后从官方源拉便携包(`-Apply`)。Npcap 只下安装包,不静默装驱动。 |
| `templates/i18n/zh-CN/INIT_QUESTIONNAIRE.md` | 中文初始化问卷。 |

**不包含**(由 `.gitignore` 硬排除):工具二进制、`.env`/凭据、`.venv`/`node_modules`/运行时、样本/pcap/dump、临时工作区、本机 git 历史。

## 快速开始

```powershell
# 1. dry-run:只看计划,不写盘不下载
pwsh scripts\bootstrap.ps1 -InstallRoot "D:\Tool\debugger"

# 2. 确认无误后执行:部署自研 MCP + 生成本机配置 + clone 第三方 MCP
pwsh scripts\bootstrap.ps1 -Apply -CloneMcp -InstallRoot "D:\Tool\debugger"

# 3. 确认所需工具后，可用下载脚本从官方源获取便携包
powershell -File scripts\download-tools.ps1 -Apply

# 4. 重建所选第三方 MCP 的 .venv / dotnet / node 依赖，再逐项 smoke test
```

> Windows PowerShell 5.1 也可运行(脚本为 UTF-8 BOM)。优先用 PowerShell 7 (`pwsh`)。

## AI 接手请先读

任何 AI clone 本仓库后,**先按界面语言读 [AGENTS.zh-CN.md](AGENTS.zh-CN.md)**(英文正文仍是 [AGENTS.md](AGENTS.md))。各客户端入口:Claude→`CLAUDE.md`、Gemini→`GEMINI.md`、Cursor→`.cursor/rules/`、Copilot→`.github/copilot-instructions.md`。

核心理念:当被要求搭建工作站时,AI **不会直接动手**。它先只读探索 → 提澄清问题(安装根目录、范围、哪些 MCP、是否下载二进制、AI 客户端、系统级组件)→ 给出计划 → 经你确认后才执行 `bootstrap.ps1`。

延伸阅读:
1. [AGENTS.zh-CN.md](AGENTS.zh-CN.md) — **中文权威入口**。
2. [templates/i18n/zh-CN/INIT_QUESTIONNAIRE.md](templates/i18n/zh-CN/INIT_QUESTIONNAIRE.md) — 初始化提问清单。
3. [docs/i18n/zh-CN/I18N.md](docs/i18n/zh-CN/I18N.md) — 语言与初始化。
4. [docs/i18n/zh-CN/AI_USAGE_GUIDE.md](docs/i18n/zh-CN/AI_USAGE_GUIDE.md) — 阅读顺序。
5. [docs/WORKSTATION_RULES.md](docs/WORKSTATION_RULES.md) — 部署后中文操作规则。
6. [manifests/](manifests/) — 工具与 MCP 清单。

## MCP 策略

默认只启用 `debugger-router` 一个轻量 MCP,它按需临时启动 20 个后端中需要的那个,该后端进程跨调用保活(每个 `session_id` 一个进程),空闲超时或主动关闭后才回收。不要默认一次性加载全部后端。需要直连时，按 [`mcp/codex-mcp-config.example.toml`](mcp/codex-mcp-config.example.toml) 选择 profile（`mcp-mobile` / `mcp-re` / `mcp-net` / `mcp-ce` / `mcp-intel` / `mcp-all`）；其中 profile 是注释示例，尚须按需启用。运行配置与上游清单的数量定义见 [`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md)。

## 安全姿态

工具集含调试器、注入器、Hook、Frida、抓包、内存分析工具,可能触发杀软/EDR。执行高风险操作(安装驱动/服务/Npcap、修改注册表/Defender/启动项、在宿主机运行可疑样本)前,AI 会简要说明后果与回滚方式,用户确认后按意图执行——不会无声操作,也不会拒绝。面向安全测试、CTF、逆向工程、研究和教育用途。

## 许可

许可按文件类型分成两套:

- **代码与配置 — MIT**([LICENSE](LICENSE))。涵盖 `mcp/debugger-router`、`mcp/bin`、`scripts`、`manifests`、`skills`、`templates`、代理契约(`AGENTS*.md`、`CLAUDE.md`、`GEMINI.md`)以及所有非 Markdown 文件。fork 后可以闭源。
- **文档散文 — CC BY-SA 4.0**([LICENSE-docs](LICENSE-docs))。涵盖 `docs/`(含 `docs/i18n/`)、`README*.md`、`DISCLAIMER*.md`、`notes/` 等散文。署名后可复用,但派生文档须沿用同一许可。
- 第三方工具与第三方 MCP 的版权和许可归各上游所有,本仓库不再分发其代码或二进制。详见 [DISCLAIMER.zh-CN.md](DISCLAIMER.zh-CN.md)。

## 贡献与安全

- 欢迎贡献,见 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 报告安全问题见 [SECURITY.md](SECURITY.md)。
- 请遵守[行为准则](CODE_OF_CONDUCT.md)。
