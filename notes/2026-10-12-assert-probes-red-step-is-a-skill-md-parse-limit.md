---
tags: [debugger]
status: observed
source: agent-notes 2026-10-12
---

# assert-probes-red-step-is-a-skill-md-parse-limit

2026-10-12 实测：verify-all.ps1 第 70 步 assert-probes（--budget 420 --timeout 300 --require-complete --skip-slow）exit 1，唯一 DRIFT = ops.skill.security：登记 probe.expect 为 Recommendation  SAFE，实跑为 CAUTION / Status partial / Coverage 83.3%。根因不是仪器也不是产物：站自己的 skills/debugger-workstation/SKILL.md 工作区未提交改动里，§6 新增的那一行引用块带一个行内代码 span（il2cpp-probe.ps1），顶爆 SkillSpector v2.12.0 受限静态解析器的 span 上限，该文件只被部分检查（static_parse_limit ledger 异常 + static_patterns_tool_misuse degraded），按设计降级为 CAUTION。二分实测：HEAD 版本 SAFE/100.0%；工作区 front matter + HEAD 正文 SAFE；工作区正文 CAUTION；四行里只有带反引号那行触发；该行去掉反引号后 SAFE/100.0%（真实文件副本 + 探针同一命令行，exit 0）。修复 = 去掉那对反引号，一行，需 skills/ 写权，本 lane 无。另：28 条能力里 27 条声明 produces，本轮 21 条可跑条目全部 fresh 产物，artifact-bound 缺口不存在；skill §4 的 25 of 27 与 probe_artifact.py 一次调用一个探针均过期或错误（该脚本是库，无 CLI，真入口是 probe_wrapper.py --tool）。native.yara.triage 被 --skip-slow 排除且 verify-all.ps1 无任何步骤按名跑它，等于该能力在入口链上一次都不执行。
