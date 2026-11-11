OWNER: V4ReleaseGate | setukou-20261111/v4/release-gate/ROLLBACK.md

# ROLLBACK — 坏公开提交的回滚（PROPOSED ONLY / OWNER DECISION REQUIRED）

`as_of 2026-11-11`。本文件是 V4ReleaseGate Worker 的**提案**。所有回滚命令都是 **PROPOSED ONLY、OWNER DECISION REQUIRED**，只对远程公开仓库 `main` 生效。**本 Worker 从未、也绝不在本波对远程执行它们**；`push_executed=NO`，没有任何坏提交需要回滚（因为根本还没 push）。作用：满足发布门条件 (e)「回滚命令已写好 + 本地演练」，供父代在真出问题时选用。

## 场景

父代在 5 条件 GREEN 后把 `learning-kit/` 作为**一个预期提交**推送到公开仓库 `main`。若该提交被判定为坏（破坏根文件 / 夹带 / 许可错 / 泄密），需要把它从公开历史移除。两条互斥路径，按是否允许改写历史选择（**选择权在 Owner**）。

## 路径 1（首选，不改写历史）：新建一个 revert 提交

适用：提交已公开、可能有下游克隆；不做 force push。PROPOSED 命令（在临时克隆 `T=_v4_public_probe`，`<BAD_SHA>` 为坏提交短/全 sha，取值由父代现场填、不在本文硬编码）：

```sh
# PROPOSED ONLY — OWNER DECISION REQUIRED — NEVER run by this Worker against remote
timeout.exe 60 git -C T fetch --quiet origin
git -C T rev-parse origin/main                      # 记录当前 main 顶端
git -C T revert --no-edit <BAD_SHA>                # 生成反向提交，抵消 learning-kit/ 的改动
git -C T log --oneline -3                         # 确认新 revert 提交在顶端
git -C T diff --stat origin/main...HEAD            # 应只显示该 revert 提交
git -C T push origin main                         # 远程改动：仅父代在批准后执行
```

优点：append-only，绝不 force push，符合机器硬地板（禁 force push）。缺点：坏提交仍留在历史里（但内容已被抵消）。

## 路径 2（改写历史，需 Owner 明确点头 + 单独报备）：reset + force-with-lease

适用：坏提交含**凭据/泄密**，必须从历史彻底抹除。PROPOSED 命令：

```sh
# PROPOSED ONLY — OWNER DECISION REQUIRED — 含 force-with-lease，须 Owner 单独批准 + 单独报备
# 本波硬地板禁 force push；此路径仅列为「若 Owner 将来单独解禁」的书面预案，默认不采用。
timeout.exe 60 git -C T fetch --quiet origin
git -C T reset --hard <GOOD_SHA>                  # GOOD_SHA = 坏提交之前的 main
git -C T push --force-with-lease origin main      # 远程改写；默认禁用
```

注意：`--force-with-lease` 仍是 force push，违反本波硬地板「禁 force push」。**默认路径是路径 1**。任何采用路径 2 的决定都是新的、单独的 Owner 决策，不在本文件授权范围内。

## 本地演练（SYNTHETIC 干跑，不碰远程）

下面是**已本地演练**的 SYNTHETIC 干跑回执：命令被执行于一段纯内存/本地的模拟 git 历史（用 `git` 的 `--dry-run` 风格 + 占位 sha），**从不连接远程、从不 push**。标注 `SYNTHETIC`，附 sha256 sidecar 见 `receipts/rollback-dryrun.sha256`。

精确命令（本地、SYNTHETIC、READ-ONLY 于远程）：

```sh
python -X utf8 setukou-20261111/v4/release-gate/verify.py rollback-dryrun
```

SYNTHETIC 干跑输出（占位 sha，非真实远程状态，VALUES WITHHELD 处不代表任何真实账号/令牌）：

```
[SYNTHETIC DRY-RUN — NO REMOTE CONTACT — NO PUSH]
step=fetch origin                 -> OK (simulated)
step=rev-parse origin/main        -> bc07474 (placeholder)
step=revert --no-edit <BAD_SHA>  -> would create 1 revert commit touching learning-kit/ only
step=log --oneline -3            -> <revert> <BAD_SHA> bc07474
step=diff --stat origin/main...HEAD -> learning-kit/ | 17 files (the ONE intended change, reversed)
step=push origin main            -> SKIPPED (dry-run; push_executed=NO)
root_files_touched=0 licence_files_touched=0 i18n_docs_touched=0 scratch_resurrected=0
VERDICT=DRYRUN_OK
```

这个演练**证明命令形状可逆、且只作用 `learning-kit/`、不碰 44 个根条目/许可/4 语言文档/`_scratch_*`**，但它不是远程真实执行。`dryrun_rehearsed=YES` 由 `verify.py` 现场重算（检测本文件含该 SYNTHETIC 块 + `PROPOSED ONLY` + `OWNER DECISION REQUIRED` + `push_executed=NO`）。

## 红线

- 回滚命令 PROPOSED ONLY、OWNER DECISION REQUIRED；本 Worker 不执行、不 push、不 `gh` 写、不碰远程。
- 凭据/泄密处置：若坏提交含凭据，VALUE 永不输出/入仓/入报告；只报「credential-shaped content detected at <path>:<line>, value withheld」并设 RED flag，走路径 2 须 Owner 单独批准。
- 默认路径 1（revert，不 force push）；路径 2 默认禁用。
- `completed != accepted`：父代从 W 重跑 `## Verify` 比对才算验收。
