OWNER: parent (main line) | F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111/CUSTOMIZATION-NOTES.md

# 定制化依据 — 学 butler + 当前 AgentRule 体系后的落位决策（2026-11-11）

Owner 本波原话：「你自己做 测试dispatch加载 然后学习butler和现在的agentrule体系别乱坐 最好的定制化 以及我们skill是公开 以前跟你说了那么多全部做到最优秀好么」。Q1 表单答案 = `B`（两个都恢复 + 规范装修 + 加新测试）。本页是「别乱坐」的只读取证结论，**父代只读产品树**，实际写入交有 scope Worker。

## 1. 只读读了什么（每条带 locator + 日期）
| 源 | locator | 关键结论 |
|---|---|---|
| `butler-os` skill | `skill://butler-os` 全文，2026-11-11 | 单一入口 `ops/BUTLER-OS.md`、六表分母不混、DONE 需 artifact+本会话命令、远程/网络/harness config 改动要停问、两读法差很远要问 |
| `AgentRule/README.md` | `AR-IDX-README` :15, :43-49, 2026-11-04 | 路由按 frontmatter `id`、文件名只是容器、不整目录预载；**四触发**才动规则书；改共享文件 = board open 占位 + stat/sha256 快照 + `*.before-*` 备份 + 最小 edit + diff 重算 |
| `AgentRule/skills.md` | `AR-IDX-SKILLS` :28, :46-50, 2026-11-04 | **项目专用 skill 放 `<项目>/.omp/skills/`；`~/.omp/agent/skills/` 只放跨项目通用**；动 skills 想到 `cache-hygiene`；`git -C` 只用盘符 `D:/...` |
| `AgentRule/硬地板.md` | `AR-POLICY-HARDFLOOR` :25, :30-31, :43-44, :53-55, :64, 2026-11-04 | push 三条自检后直接推但 commit/push 交 Worker；**hackerone 与 debugger 是 Owner 自管树、不用逐事报备**；board open+briefcheck+close 是门；远程改动必须附①回滚命令②本机演练记录；检查红了改代码不许改检查 |
| `AgentRule/回答形状.md` | `AR-POLICY-OWNER-REPLY` :21-27, :33-43, 2026-11-04 | Owner 答复首行结论、≤5 条；英文材料进 skill 要「意思+语气+言外之意」翻译、术语用既有译法（板/门/派发/brief/硬地板） |
| `AgentRule/specialist/README.md` | `AR-IDX-SPECIALIST` :23-26, 2026-11-04 | **omp/codex 的 skill 目录接到站的 `debugger-workstation`/`debugger-review`**；官方 Claude Code 已摘除；MCP 到站才挂 `debugger-router`、不并进用户全局 |
| `D:/Software/Tool/WorkStation/debugger/AGENTS.md` | :74-80, :168-172, :194-206, :210-212, 2026-11-11 | 「Self-maintain this repo」= Owner 要改 skills 时 explore/plan/patch + **dual-axis review (`skills/debugger-review`)**、commit 英文、不另立 constitution；layout 明写 `skills/` = 2 个 debugger skill；Owner 2026-10-12 常驻授权「军火库全开」改文件不用逐事报备但技术要求照旧；material job 后读 `docs/AGENT_EVOLUTION.md` + `debugger-review/SKILL.md` |
| `AgentRule/干活.md` | `AR-HOWTO-WORK` :22-29, :38-49, 2026-11-04 | 完成条件=能跑命令/看非空文件、强=测试先红后绿；最小写入；生成完打开产物搜内容；等法唯一=`wait` 阻塞、读 `agent://<id>`；等待有上界；检查必须报分母且分母 0 算失败 |
| 官方 Agent Skills spec | https://agentskills.io/specification.md（父侧 2026-11-11 实读） | name 1-64 小写/数字/连字符+须与父目录一致、description 1-1024 含 what+when+keywords、metadata string→string、license/compatibility 可选、body <500 行、references/scripts/assets 一级、渐进披露 |

## 2. 「别乱坐」的落位决策（本波定制化的核心）
1. **恢复位置 = 原位 `D:/Software/Tool/WorkStation/debugger/skills/<name>/SKILL.md`**，不改目录名、不迁移。依据：`debugger/AGENTS.md:200` layout + `specialist/README.md:26` 接线现状 + 官方 spec「name 须与父目录名一致」。
2. **绝不塞进 `~/.omp/agent/skills/`**。依据：`skills.md:48` 项目隔离（这 2 个是站点专用 router，不是跨项目通用）+ 上一波盘上 20 个通用 skill 不动。Owner 说的「测试 dispatch 加载」= **验证 specialist 路由重新发现这 2 个恢复后的 skill**（读 skill 目录 → frontmatter 触发 → 站点契约），不是往全局加第 21 个。
3. **装修范围严格按 Q1=B**：只按官方 spec 修这 2 个 SKILL.md 的 frontmatter / description 触发关键词 / 一级引用；**保留站点 router 本质**（`.agent/*`、`docs/AGENT_EVOLUTION.md`、`debugger-router` 默认、`bootstrap.ps1 dry-run→-Apply`、高风险 consequence+rollback 不静默装驱动、dual-axis `debugger-review` 收尾）。不改 MCP 配置、不改 manifests、不改 AGENTS.md、不动二进制、不动 `vrc-dcc`（2026-09-19 硬禁令）。
4. **新测试 = 每个 skill 各 1 个可复跑 `## Verify`**（本地脚本，放研究区 `restore-test/`，不污染产品树）：断言 frontmatter 合规、站点指针存在、HARD BAN、0 凭据形状、description 含触发关键词、commit 英文；负例（如把 `vrc-dcc` 标 RESTORED 或删掉 RED 诚实行）必须 RED。按 `干活.md:22` 强完成 = 先红后绿。
5. **公开标准**：Owner 说「我们 skill 是公开」→ 恢复后的 2 个 SKILL.md 必须 0 凭据值 / 0 邮箱 / 0 私有树绝对路径以外内容 / 0 语料正文 / 0 `.jsonl`；licence 与站点 `LICENSE` 一致（MIT/CC BY-SA 4.0 双许可），站点 AGENTS.md:78 commit 英文。
6. **远程发布（push）单独一步**：`butler-os` + 硬地板 :55 要求远程改动附①可粘贴回滚命令②本机演练记录；`AR-HOWTO-WORK:29` 要求先留回滚点。所以先本地闭环（恢复→装修→新测试→加载冒烟→父侧验收），**再**跑 5 条件门 + 写回滚 + 本地演练，然后由 scoped Worker 单 commit 单 push。若门红 → 停并报，不硬推。
7. **体系纪律**：board open 四参占位 → briefcheck → 有 scope Worker → 父侧 collect/重跑/验收（completed≠accepted）→ close `--verdict ok --verify "<真跑过的>"`。改前 `stat` mtime+sha256 快照 + `*.before-*` 备份（README:49）；改动最小、diff 全文复核。

## 3. 本波不做（边界，非遗漏）
- 不改规则书本身（四触发未满足：不是重复犯错/审计抓到/重复纠正/新同事上下文）——`README.md:45`。
- 不恢复 `vrc-dcc` / `vrc-review` / `vrc-world` / overlays（硬禁令 `AGENTS.md:19` + retired note 2026-09-19）。
- 不改 4 个 PRIVATE 树 visibility、不改 MCP 注册、不装 always-on 插件、不加更贵模型档、不把 jsonl 进仓。
- 不整目录预载 AgentRule、不写第二份 constitution、不另立 recovery 板。

## Verify
```sh
cd "F:/GENESIS-ARCHIVE/10-STORE/12-RESEARCH-RUNS/debuggerstation-skill-revival-ai-selfdeploy-20261111" && python -X utf8 -B -c "import pathlib; t=pathlib.Path('CUSTOMIZATION-NOTES.md').read_text(encoding='utf-8'); print('sections',sum(1 for l in t.splitlines() if l.startswith('## ')),'locators',t.count('2026-11'))"
```
Parent ran: `sections 4` (含 Verify) with dated locators.
