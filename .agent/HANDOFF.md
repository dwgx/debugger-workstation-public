# HANDOFF — reverse workstation (debugger station)

**交接时间 2026-10-02 17:40 · 基线 `101cf57` · tracked-uncommitted 0 · 两仓库均已 push**

本文替代此前那一版。那一版记的是"八 agent 深审发现验证层没在验证自己"，**已被本文取代**：
那个阶段的洞全部修完，之后又发生了六个阶段的工作，见下。

---

## 0. 三十分钟上手

```bash
cd "D:/Software/Tool/WorkStation/debugger"

powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-all.ps1   # 一条命令跑完整套快检
python scripts/reachability-report.py                                       # 什么真的产出过 fact
python scripts/assert-probes.py --list                                     # 手工跑真实 probe（~15min 全量）
python scripts/arsenal_mcp_server.py                                       # MCP 面（stdio）
```

**`verify-all.ps1` 是入口。** 它跑：registry-verify / registry --selftest / requires-tools /
doc-facts / gate selftest / mission selftest / mission ablate / reachability / assert-probes --list。
`assert-probes` 不在默认链里（它真跑工具、耗时），要跑请显式。

---

## 1. 这一阶段实际做了什么（按天序）

| 阶段 | 结果 |
|---|---|
| 独立 verifier 审计注册表 | 8 条发现，含 fact_map 指向未声明键（R20）、**13/24 负控制是散文**（R21） |
| 写 `assert-probes.py` | 把"你真的跑过吗"变成命令；自曝 21/24 假 DRIFT（PowerShell 喂给 cmd.exe）、**把所有控制报成通过**（`-File` 吞退出码）、**超时报成 drift** |
| 写 `reachability-report.py` | 把 `ok:true` 且零 facts 算成 worked——**我这一轮报给你的每个数字都是上界** |
| capa 登记 / 修正 | `grep capa` 命中全部条目，因为 "capa" 在 "capabilit**y**" 里 |
| 证书二次意见 | OpenSSL 推翻 pefile 对自家 fixture 的"证书头有效"读数 |
| Q6/Q4 点亮 | **黑轴 3/7 → 1/7**；`native.pe.hardening`（radare2 早就装了、0 条引用） |
| **安全洞** | precondition 只声明 Q1，**加壳目标在打包器门从未被咨询的情况下被反编译** |
| 造轮子 | `check-requires-tools.py`、`arsenal_mcp_server.py`、注册表 plan 绑定 |
| 两轮 subagents | registry/tools/gates 审计 + 联网挖掘三轮 |

**规模**：session 基线 15 能力 / 3 可调用 / 10 规则 → 现在 **27 / 16 / 22**。

---

## 2. 当前实测状态（不是声明）

```
27 capabilities: 23 observed · 2 absent · 1 planned · 1 blocked
16 declare an invoke · 16 evidence families · 7 question axes
registry-verify            REGISTRY CLEAN（22 规则，59 自测用例全触发）
check-requires-tools       27 条 probe：20 ok · 0 wrong · 0 tool-fault · 3 skipped
doc-facts                  17 条活声明 OK
gate selftest              24 refusals/grants behaved
mission selftest           51 controls（N4 仍 unresolved —— 这是对的）
mission ablate             7 + 6 load-bearing，0 unproved
reachability               1 of 7 轴从未产出 fact；3 of 16 可调用从未产出 fact
```

### 按轴（**这是该引用的数字，不是"可调用 16/24"**）

```
Q1.identify 6/8   Q2.locate 5/5   Q3.behaviour 4/4   Q4.data 2/4
Q6.crypto   2/3   Q7.origin  3/5   Q5.vuln-shape 0/0   ← 唯一黑轴
```

**`可调用` 是注册表的属性，`成功过` 是历史的属性。只有历史能回答你拥有哪一个。**

---

## 3. 唯一需要 Owner 决定的一条

**授权能被凭空造出。** 实测：

```powershell
gate.ps1 -Action New -Target <我自己拷到 temp 的文件>
  -OwnerWord "do absolutely anything you want to this machine"
  -Provenance "the user asked for this in the previous turn of THIS conversation"
# → {"ok":true,"allowed_count":18,"attested":true}   MINT_EXIT=0
```

`Test-SelfAsserted` 那 9 条正则过滤**措辞不是权限**；24 条 selftest 全在测"已铸的授权被改盘"，
**没有一条问 Owner 那句话是不是真的**。

**这是设计缺口不是 bug** —— 门无法验证人话。修法在授权层（Owner nonce / 具名目标 / 会签记录），
**不在 `gate.ps1` 里**。**不要为了让指标好看去翻 `requires_verdict`。**

---

## 4. 已知不足，按严重度

1. **授权缺口**（上）。
2. **7 个家族各只有 1 条可调用能力**：`artefact-parser` `capture-analysis` `certificate-verifier`
   `dynamic-instrumentation` `format-reader` `package-inspection` `packet-reader`。
   **它们在 independence 门里贡献为零**；Q4 够两个是运气不是设计。
3. **`assert-probes` 认字符串不认仪器** —— 2 行假脚本能让它绿灯。
4. **10 条能力还没有可运行的负控制**（`kind: plan`，附书面理由，设计是真的，命令还没有）。
5. **知识库门仍窄** —— 已从 16 条扩到 17 条 + 跨行，但散文计数、表格裸数字、
   `.agent/` 与 `literature/` 整目录仍跳过。
6. **`net.pcap.selfparse` 类型写错**：`capture: pcap`，但 **pcap 就是一条路径**，应为 `path_ref`。
   与当初 `forensics` 把 `lab_workdir` 写成 `image` 同类，方向相反。**下一步该修它。**
7. **MCP 面只被一个测试 client 跑过**，没有被任何真实客户端用过。
8. **20 个已装工具仍无能力**：ImHex · ReClass.NET · YARA-X · sigcheck · x64dbg · ScyllaHide 等。
   T1 已判定：**最好的三个候选都是被"它们怎么报告"淘汰的**——
   **YARA-X 命中和未命中都 exit 0**（只能读 stdout 字节数）、FLOSS 在它存在的意义那个用例上
   **exit 0 且输出为空**、sigcheck 对 Signed/Unsigned 都 exit 0。**"能跑且退出 0"不是一个结果。**

---

## 5. 环境陷阱（每次都会踩的）

- **bash 是 WSL2，看不到 `D:`。** PowerShell 用**单引号**：`powershell -NoProfile -Command '...'`
  （双引号会让外层吃掉 `$`）
- **`EXIT=$?` 在管道后读的是最后一个命令的**，不是目标的。用 `cmd >/dev/null 2>&1; echo $?`
- **`%TEMP%` 在 PowerShell 不展开**，用 `$env:TEMP`。这一条已经害我产生过一次假 DRIFT
- **相对路径跑 .exe 会失败**（exit 127 / "command not found"），用绝对路径
- **PowerShell 里带引号的路径是字符串表达式不是调用**，要加调用符 `&`
- **`Get-FileHash` 在这里不存在**（CommandNotFoundException）——用
  `[System.Security.Cryptography.SHA256]::Create()`，`gate.ps1:173-176` 有记录
- **`spawn 出去的进程会继承文件描述符** —— server 持有的 JSON-RPC 管道会被子进程继承并挂死，
  必须 `stdin=subprocess.DEVNULL`
- **not on PATH**：`tshark`(portable Wireshark 4.6.8) · `diec` · `upx`(5.2.1) · `rabin2`(6.2.2) · Frida(仅 objection venv)
- **IDA 走 `idalib-mcp` MCP device，不是 CLI**
- **端口冲突**：`crypto-lab` 硬编码 8791，而 `<project>\homework` 的 `atlas_server.py` 占着它
  ——**那是 Owner 另一个项目，不要碰**；probe 已写 `CRYPTO_LAB_PORT=8799` 绕过
- **成本**：capa ~33s · Ghidra pair ~32s · fuzz loop ~634s · assert-probes 全量 ~15min
- **不要跑** `smoke-all.ps1` / 任何 lab loop / 任何 fuzz run（父进程所有，昂贵）

---

## 6. 目录地图

```
manifests/capabilities.json     唯一事实源，27 条，22 规则由 registry-verify.py 校验
scripts/verify-all.ps1          一条命令跑全套
scripts/gate.ps1                授权：New / Check / Escalate / Selftest
scripts/mission.ps1             编排：Run / Selftest / Ablate；-SeedFact；precondition 按 invoke.gates 跟随
scripts/registry-verify.py      静态校验 + 59 自测
scripts/check-requires-tools.py 执行 requires.tools[].expect（27 条）
scripts/assert-probes.py        真跑 probe/control，比对 expect
scripts/reachability-report.py  按 mission 历史算"真的成功过"
scripts/doc-facts.py            wiki 数字漂移，跨行匹配
scripts/arsenal_mcp_server.py   MCP 面，16 个可调用能力
native-lab/ headless-lab/ net-reverse/ crypto-lab/ forensics-lab/ fuzz-lab/
managed-lab/ mobile-lab/ web-reverse/ crackme-corpus/     各自 self-authored、零下载
Static-Reversing/ Mobile-Android/ Network-HTTP/ Debuggers/
System-Forensics/ Unpackers-Game/                          第三方工具（tools.json 登记 38 个）
E:/missions/                    143 个 mission case，每个含 artifact.json / trace.jsonl / plan.json
```

**`E:` 放运行时数据；仓库留 `D:`。**

---

## 7. 工作流程（这个项目实际遵守的）

1. **先测后写。** 每一个"已验证"都必须有真跑过的命令和真实输出。
2. **先量再修。** "这条路走不通"要区分**三个**不同原因：不在 PATH / 跑不起来 / 没有新问题。
3. **拒绝优于伪造。** `native.crosscompare.ghidra` 从 `observed` 降到 `planned`，因为没有可运行命令
   做过它声称的比较。**没有命令的 probe 是 schema 条目，不是能力。**
4. **每个新规则必须能被控制证伪**，且 **fixture 必须是合法注册表**（本项目四次栽在这：
   control command 字面写着 `"false"`）。
5. **删除要切换不要抹除**：散文负控制移到 `control_plan` 并附理由；过时数字划掉不删。
6. **subagent 派发**：`board.py open --scope` 占坑 → brief 必须有 `# Non-Conflict` + `DONE WHEN`
   → **结果先落盘再报状态**（上下文压缩会静默杀掉没落盘的 worker）
   → `close --verdict ok --verify "<真跑过的>"`
   **注意：本环境的 worker 没有文件写权限**（write 只接受 `xd://`），**必须让它在最终消息里全量交付**，
   由父进程落盘。

---

## 8. 与 <private-tree> 仓库的同步

- `<project>/<private-tree>` 的 `wiki/` 是本军火库**唯一**的解释层。
- `doc-facts.py` 跨仓库校验 wiki 数字。**改注册表数字后必须修 wiki**，否则它会红。
- 本阶段写入：`wiki/CHARTER-ARSENAL.md`（方法论沉淀）、`wiki/methods/arsenal-upgrade-plan.md`
  （升级计划 + 未接线工具审计 + MCP + plan 绑定）、`wiki/INDEX.md`（计数）。
- 两仓库 commit 均已 push，uncommitted 均为 0。

---

## 9. 下一步建议（按性价比）

1. **`net.pcap.selfparse` 的 `capture: pcap` → `path_ref`** —— 2 分钟，且它其实可路由
2. **剩 10 条 plan 负控制** —— 审计给了 NEEDS-A-TOOL-CHANGE 清单
3. **MCP 面接一个真实客户端**（Claude Code 等）跑一遍，而不是只有测试 client
4. **研究已采纳未建**：Kubernetes dry-run **枚举**（`none|client|server`）+
   **答不出就 fail closed**——现成失败案例是 `kubectl --dry-run=client` 接受非法资源类型。
   这里权威是 `gate.ps1`，**客户端侧 dry-run 什么也验证不了**
5. **授权缺口** —— 只有 Owner 能定

---

## 10. 这一阶段最有价值的一条（别丢）

> **一个"看起来像契约"但没人执行的字段，比没有这个字段更危险。**
>
> `requires.tools[].expect` 读了几个月、写着 `tshark --version`（在本机**根本跑不了**），
> 而**全项目没有任何东西执行过它**。直到 `check-requires-tools.py` 去跑，10 条错声明当场暴露。
>
> 同类还有：`probe.expect` 认字符串不认仪器 · `reachability` 把"没报错"当成"学到了" ·
> **`Test-SelfAsserted` 过滤措辞当作权限**。
>
> **绿是写入顺序的函数，不是正确性的函数。**