# 2026-10-12 — verify-all 快扫间歇性 FLAKY（三跑一现，条目名未捕获）

**观测**（2026-10-12，station `scripts/verify-all.ps1` 链内与单跑）：
同一入口 `assert-probes --budget 420 --timeout 300 --require-complete --skip-slow` 当天三跑：

| 跑 | 结果 | 墙钟 |
|---|---|---|
| 1（verify-all 链内，bg_23） | 22 OK / 3 SKIP | — |
| 2（verify-all 链内，bg_24） | **1 FLAKY** / 21 OK / 3 SKIP | — |
| 3（单跑，bg_25） | 22 OK / 3 SKIP | 312 s |

**含义**（按 R14 纪律）：FLAKY 不是通过也不是回归，是「本轮无法裁决」。三跑里出现一次
且不可复现，**符合负载敏感特征**——但这是推断，不是测量。条目的具体名字在两次链内跑的
尾部输出里没有保留（grep 过滤后没抓到 per-entry 行）。

**下一步（未做）**：
- 复现实验：在**空载**机器上连跑两次同一命令，把完整输出（不只 tail）落盘，抓 FLAKY 条目名。
- 抓到名字后：读该条目的 `runtime_note`——它要么解释噪声（记录即可），要么说明是缺陷（修）。
- 已知嫌疑：`fuzz.differential.parse` 有历史 FLAKY 记录且自带 load-sensitive 注记，但它被
  `--skip-slow` 排除在外，所以**这次的 FLAKY 另有其条**——不要默认是它。

**教训（可复用）**：链内跑的快扫输出要**全量落盘**再 tail；只留 tail 的跑法会把
FLAKY 的条目名丢掉，导致下一次只能重跑而不能直接读证据。这与「报告先落盘」同源：
证据在管道里被截断 = 没留证据。
