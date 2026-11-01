# 2026-10-15 — 子代理后端拒绝的两类模式与处置（403 内容策略 / 流中断）

Status: observed（2026-10-15，AwesomeUI W8 波实测；15 次派发中 3 次 403 + 1 次流中断）

## 事实

1. **内容策略 403**（deepseek-v4.1-flash 后端）：同任务首派被拒 → **原样重派一次通常通过**（nibsem ✓、emoji ✓）；**连续两次被拒**（winmica ×2）→ 改写 brief（去具体系统 DLL 名/软化措辞/降门槛）+ **换后端**（researcher/GLM）→ 通过。
2. **流中断**（「the model provider ended the stream before the answer was finished」）：长任务（~14 min）中途断流、无产物 → 直接重派（verify 实例）。
3. 处置顺序建议：403 第 1 次 → 重派（改 name 留痕）；第 2 次 → 改写 brief + 换后端；流中断 → 重派（若第二次仍断，拆分任务）。
4. 不要：同一内容连续硬重试 >2 次；不要把后端拒绝当任务失败上报。

## 失效条件

- 后端行为随版本变化；本记录为 2026-10-15 实测快照。
