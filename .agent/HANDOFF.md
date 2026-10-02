# HANDOFF — reverse workstation (debugger station)

**交接时间 2026-10-03 · 基线 `77142aa`（本文写作时 HEAD）· 两仓库均已 push · tracked-uncommitted 0**

2026-10-03 那一轮做了什么：**把三处「看起来像契约却没人执行」的字段变成会拒绝的东西**，
外加一处会让任务静默消失的死代码。全部先写控制、看它变红，再改实现看它变绿；
每个数字都由 `verify-all.ps1` 当场跑出来。逐条见 §2a。

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

## 2. 当前实测状态（2026-10-03 实跑，不是抄上一版）

```
27 capabilities: 23 observed · 2 absent · 1 planned · 1 blocked
16 declare an invoke · 16 evidence families · 7 question axes
registry-verify            REGISTRY CLEAN（**24 规则**，**66** 自测用例全触发）
gate selftest              **33** refusals/grants behaved（2026-10-03 独立验收后；原 24）
mission selftest           51 controls（N4 仍 unresolved —— 这是对的）
mission ablate             7 + 6 load-bearing，0 unproved
reachability               1 of 7 轴从未产出 fact；3 of 16 可调用从未产出 fact
verify-all                 **55.3 s** 全绿

### 按轴（**这是该引用的数字，不是"可调用 16/24"**）

```
Q1.identify 7/9   Q2.locate 5/5   Q3.behaviour 4/4   Q4.data 2/4
Q6.crypto   2/3   Q7.origin  3/5   Q5.vuln-shape 0/0   ← 唯一黑轴
```

**`可调用` 是注册表的属性，`成功过` 是历史的属性。只有历史能回答你拥有哪一个。**

### 2a. 2026-10-03 修掉的五处（每处都先量出红，再改绿）

| commit | 洞 | 量出来的样子 |
|---|---|---|
| `dd0511e` | `consumes.inputs[].type` 没有词汇表 | 41 个输入里 34 个没有 `from` 边，R4 只在有边时比对类型 → 这个字段**没有任何规则读**。三处声明本身是错的：`net.pcap.analyse`/`net.pcap.selfparse` 的 `capture: pcap`、`mobile.apk.static` 的 `apk: apk`，按 `fact_types` 自己的定义那是「已解析的记录集」，而它们是磁盘上的路径。加 `schema.input_types` + 新规则 **R24**，三处改 `path_ref` |
| `dd0511e` | `escalation_class` 的理由键有两个拼法，且都没人读 | `escalation_why`（2 条）与 `escalation_reason`（1 条），7 条非 `none` 里 4 条没有任何理由。加规则 **R23**：类别高于 `none` 就必须有 `escalation_reason`，旧拼法本身违规 |
| `99c1d21` | **门可以被调用方换掉注册表** | `-Registry` 在**铸造**时也被接受：手写一份 `capabilities.json` 多塞一条能力，就能铸出全绿授权——`grant.escalation` 同理，`-EscalationClass 'TOTALLY_MADE_UP_CLASS'` 返回 exit 0、写进授权、DPAPI 重新封存，之后 Check 仍 ok:true。三个入口现在全部拒绝；只有 selftest 内部的 `$script:RegistryOverride` 还能改道，且有控制钉住它仍然有效，防止以后有人删掉它顺便把状态过滤器的测试弄成空转 |
| `a0bdcaf` | mission.ps1 里一段孤儿 `skip_exits` | 循环外、无 `if`、以裸 `continue` 结尾，而 `artifact.json` 和退出码都写在它后面 → 一旦命中就**无产物、无trace、无消息、退出码 0**。今天是死代码，但触发条件是注册表数据。墓碑留在原地 |
| `77142aa` | MCP 面声称自己不过门 | 文件头写着「Every call still goes through the same gate invocation」，而全文 `gate`/`grant`/`OwnerWord` 只出现 4 次，**全是那句话**。16 条可调用能力对任何 MCP 客户端、任何本机路径开放，没有 Owner word、没有 containment。现在每个工具必填 `case_dir`，执行前跑 `gate.ps1 -Action Check`。顺带修：argv 里残留的 `{input.function}` 之类占位符会**拒绝并点名**，不再把字面量塞进子进程 |

四份 commit 全部先在真注册表上看到规则变红（R23/R24 报 11 条违规），再改数据。

### 2b. 独立验收（2026-10-03，opus `verifier`）

结论 **ACCEPT WITH FINDINGS**：每个数字被独立重新推导，每个新控制被变异测试（删掉被测机制，
看控制是否变红）。**它抓到我 5 处错，已全部修正**（`38e87df`）：

1. **HIGH · 我写的注释断言了假的安全属性**。`Get-RegistryPath` 曾说 `$script:RegistryOverride`
   是「nothing outside this file can reach」。实测为假：PowerShell **点源**把被调方跑进**调用方**
   的作用域，所以那里的 `$script:` 变量就是调用方的变量，`$script:RegistryOverride=<evil>;
   . gate.ps1 -Action New ...` 铸出了全绿授权。**任何 script 级变量都挡不住点源。**
   注释改成窄的真话，并加了一条**独立进程**的控制，钉住真正活下来的性质：伪造的授权活不过铸出它的进程。
2. **MEDIUM · 一道永远不会触发的地板**：`assert-probes` 的 `len(results) < len(todo)` 在
   `check()` 保证每条能力至少一条裁决的前提下不可满足。删掉它输出不变，删掉 `check()` 那道才变红。
   死的那道已删——**两处地板、一处是死的 = 零处加一**，与今天 mission.ps1 的墓碑是同一条教训。
3. **LOW · 墓碑两个行号写错**：应为 `:1218` / `:1234`。
4. **LOW · 裁决文案说得比做到的多**：OK 文本原写「exit 也匹配」，而 4 条能力没声明 `expect_exit`。
5. **INFO · R23 对一次改名报两条**。

变异测试还抓到我**第二个自己的错误**：新控制第一版问 `RULE.THE.WORLD`（真注册表里不存在），
于是它靠「能力未知」通过，删掉被测机制仍然绿。改成问 `native.ida.decompile`、并要求指名
digest 拒绝之后，红/绿两向都测过。**「控制要以错误的原因通过为敌人」——只有变异测试抓得到。**

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

1. **授权缺口**（上）。今天的门已经不能被调用方换掉注册表、不能被写进一个不认识的升级类别，
   但**「Owner 那句话是不是真的」仍然无法验证** —— 这是设计缺口，只能在授权层修。
2. **7 个家族各只有 1 条可调用能力**：`artefact-parser` `capture-analysis` `certificate-verifier`
   `dynamic-instrumentation` `format-reader` `package-inspection` `packet-reader`。
   **它们在 independence 门里贡献为零**；Q4 够两个是运气不是设计。
3. **`assert-probes` 认字符串不认仪器**。今天补了「每条能力必须给出裁决，否则不让 exit 0」的地板，
   所以「什么都没检查」不再伪装成绿灯；**但两行假脚本仍然能通过**，因为它比的是字符串。
   真正的修法是让每个 probe 产出「字符串伪造不出来」的东西（一次运行的产物哈希 / trace 行），
   今天没做，记在这里而不是假装做了。
4. **10 条能力还没有可运行的负控制**（`kind: plan`，附书面理由）。2026-10-03 重建了清单：
   `plan_reason` 是注册表里**唯一没有任何代码读的字段**，所以「理由是假的」不可能被发现。
   两条旧理由已被证伪（`native.ida.decompile` 的「没有 CLI 接受地址」——`decompile.mjs` 接受；
   `mobile.apk.static` 的「没装第二个 AXML 解码器」——Apktool 3.0.3 在）。
5. **知识库门仍窄** —— 现在 19 条活声明，散文计数、表格裸数字、`.agent/` 与 `literature/` 整目录仍跳过。
6. ~~**`net.pcap.selfparse` 类型写错**~~ —— **2026-10-03 已修**，但板上写「一条」，实测是**三条**
   （还有 `net.pcap.analyse` 和 `mobile.apk.static`），而且真正的问题是**没有词汇表**，所以补了
   `schema.input_types` + R24。三条旧声明是错的，不只是措辞不统一。
7. **MCP 面**：今天把「声称过门但没有门」变成真的过门（`case_dir` 必填 + 执行前 Check），
   并且修掉了 `{input.*}` 占位符被当字面量塞进子进程。**仍然只被一个测试 client 跑过**；
   而且 `case_dir` 是破坏性改动，接真实客户端之前要先决定它怎么拿 case dir。
8. **20 个已装工具仍无能力**：ImHex · ReClass.NET · YARA-X · sigcheck · x64dbg · ScyllaHide 等。
   T1 已判定：**最好的三个候选都是被"它们怎么报告"淘汰的**——
   **YARA-X 命中和未命中都 exit 0**（只能读 stdout 字节数）、FLOSS 在它存在的意义那个用例上
   **exit 0 且输出为空**、sigcheck 对 Signed/Unsigned 都 exit 0。**"能跑且退出 0"不是一个结果。**
9. **4 条可调用能力在 MCP 面上不可用**：`native.ida.decompile` / `native.disasm.capstone` /
   `native.ghidra.decompile` / `crypto.jose.parse` 的 argv 里有 `{input.*}` 占位符，
   由上游 fact 供给，MCP 客户端给不了。今天改成明确拒绝并点名，而不是把字面量塞进去。
10. **`mission.ps1` 的 `MaxRounds` 其实是 `MaxSteps`**：路线只算一次，循环里不重排，
    所以 `Get-Termination` 的 CONTINUE 分支在实践中不可达。这会让「预算耗尽」和「步骤走完」
    在报告里长得一样。

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
- 2026-10-03 两侧都 push；<private-tree> 侧另修了 `arsenal-inventory.md:51` 被从句中截断的句子，
  以及两处「measured 2026-10-02 19:5x」这种带 `x` 的假时间戳。

---

## 9. 下一步建议（2026-10-03 重排，按性价比）

1. **让 `assert-probes` 认仪器不认字符串** —— 这是现在唯一还开着的「假绿灯」。
   地基已经有了（今天补的地板保证「没检查」不会伪装成通过），剩下的是让每个 probe 交出
   一次运行的产物（输出哈希 / trace 行），比一个字符串难伪造。**没有它，`--list` 之外的那条
   命令就只是把注册表的自我描述重打一遍。**
2. **`native.ghidra.decompile` 的 `{input.outdir}` 是永久 skip** —— `ghidra-headless.ps1:30`
   本来就在 `-OutDir` 为空时回落到 `%TEMP%`，所以这个占位符什么也没换来，只会让这一轮永远
   `skipped_unmet_input`。约 20 分钟，能把一条「可调用但永远跑不了」的能力变成真能跑。
3. **剩 10 条 plan 负控制** —— 清单今天重建了（见 §4.4），但**它现在只存在于本文里**，
   该落成注册表能读的东西，否则下一轮又会丢。
4. **`mission.ps1` 的 `MaxRounds` 其实是 `MaxSteps`**（§4.10）—— 影响的是「预算耗尽」这个
   结论能不能被区分，不是性能问题，但它让一份 artifact 的终止原因变得不可读。
5. **MCP 面接一个真实客户端** —— 但先定 `case_dir` 怎么来（每个 case 一个？还是按会话一个？）。
   破坏性改动已经在 main 上，接客户端之前应该有一次真实握手。
6. **研究已采纳未建**：Kubernetes dry-run **枚举**（`none|client|server`）+
   **答不出就 fail closed**——现成失败案例是 `kubectl --dry-run=client` 接受非法资源类型。
   这里权威是 `gate.ps1`，**客户端侧 dry-run 什么也验证不了**。
7. **授权缺口** —— 只有 Owner 能定。

**已经从清单上划掉的**：`net.pcap.selfparse` 的类型（2026-10-03 修完，且发现是三条不是一条）；
板的第 ⑤ 条指向的 `NEEDS-A-TOOL-CHANGE` 清单**从来就不存在**——全树 grep 只命中
`.agent/HANDOFF.md:184` 那一句本身。

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