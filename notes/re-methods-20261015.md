---
tags: [methods, re, inventory, upgrade, elf, descriptors, dap, emulation]
status: verified
source: agent-notes 2026-10-15 (WindsurfAPI F-lane / board METHODSUP)
---

# re-methods-20261015 — 现役 RE 办法清单 + 可升级项

**两个读者**：下一个窗口（照抄 §1 的命令）+ Owner（只看 §4 的投资判断）。
**证据标记**：`[实测]` = 本轮在这台机器上跑过并读到输出；`[记录]` = 前人写下的测量、本轮未复现
（给原件路径）；`[未实测]` = 没跑过。**命令默认在站根跑**：`cd <repo>`。
**本轮的原始命令与输出在 §7**；我的临时脚本在 `%TEMP%\methodsup-20261015\`——**临时目录会丢**，
所以 §6 给的是可以直接落地的版本。

---

## 0. 分母（每个数字从哪来）

| 数字 | 值 | 怎么来的 |
|---|---|---|
| 能力条目 | 28 | `manifests/capabilities.json` 里 `capabilities[]` 的长度；25 observed · 2 absent · 1 blocked `[实测 2026-10-15]` |
| 站内自检的分母 | 23 bound / 2 unverified / 27 runnable controls / 1 declared plan | `python scripts/doc-facts.py` 自己的输出，退出 0 `[实测]` |
| assert-probes 的 SKIP | 28 行里 3 行 | `python scripts/assert-probes.py --list` `[实测]` |
| 本轮真跑的 lab | 9 条 | §7 的命令表；每条都读到了它自己的 `LOOP CLOSED` / `JSON-SUMMARY` `[实测]` |
| 描述符 | **55 个 blob → 132 个切片 → 62 个不同 descriptor** | 我重跑提取 + 自己写切分器，sha256 去重 `[实测]`，见 §5.2 |
| 技能档案自述 | 182 条 / 229 URL（2026-10-14 计数） | `wiki/methods/arsenal-skill-archive.md:146-150` 的**自述**，本轮**没有**重数 `[记录]` |
| 模型目录（项目侧） | 123 条，`_calibratedAt` 2026-07-08 | `src/data/devin-catalog-snapshot.json` `[实测]` |

**一条读法**：`state=observed` 说的是「这条的探针跑过」，不是「这个能力现在可用」；反过来
`SKIP` 说的是「没跑」，不是「不可用」——§3 把两者分开。

---

## 1. 现役办法清单

每行 = 目的 / 逐字命令 / 证据形状 / **失效条件（会给你错答案的场合）** / 标记。
时间是本轮实测的墙钟。

### 1.1 PE 原生

| 目的 | 命令 | 证据形状 | 失效条件 |
|---|---|---|---|
| 先摸底 | `powershell -File headless-lab\tools\triage-packer.ps1 -Target FILE.exe` | `packed` 布尔（来自 DiE 的读数） | 不是 PE（对 ELF/APK 会瞎报） |
| 行为特征 | `python native-lab\tools\capa_probe.py FILE.exe` | capa 特征 JSON | **加壳样本**——capa 自己说会漏 |
| 缓解措施 | `python native-lab\tools\hardening_probe.py FILE.exe` | 每项 flag：`nx` `pic` `relocs` `crypto`… | **没有 `CFG` 键**，别报它 |
| 某地址的指令 | `python native-lab\tools\disasm.py FILE.exe --rva 0x1080 --count 20` | Capstone 反汇编 | RVA≠地址；`--rva` 要的是 RVA |
| 真 C 代码 | `node native-lab/tools/loop.mjs --only=decompile` | `JSON-SUMMARY {"total":15,"pass":15,"fail":0}` + `LOOP CLOSED`，**2.98 s** `[实测]` | **IDA 的 `isError:false` 会撒谎**——wrapper 必须查 `error` 且要求 `code` 非空 |
| 函数表 | `node native-lab/tools/loop.mjs --only=list_funcs` | `{"total":6,"pass":6,"fail":0}`，**2.77 s** `[实测]` | 同上 |
| 跨版本找同一函数 | `powershell -File headless-lab\tools\match-functions.ps1 -Source OLD.exe -Dest NEW.exe` | 函数匹配表 | 两个路径都必填（「同一函数」需要两个 build） |
| 签名存在性 vs 有效性 | `python headless-lab\tools\authenticode.py F.exe` / `python native-lab\tools\cert_verify.py F.exe` | `WIN_CERTIFICATE` 头 / 链判定 | **两个不同问题**；后者只对有签名的 fixture 有意义 |
| 四个能力一次跑 | `python scripts/assert-probes.py native.pe.container native.disasm.capstone native.pe.hardening native.behaviour.capa --budget 240 --timeout 120 --save-evidence DIR` | `4 entries; verdicts 4 OK`，**48.0 s** `[实测]`；OK 的含义是「字符串印出来了 **且** 声明的产物本轮真写盘了（带 sha256）」 | 别把 `OK` 读成「产物内容正确」——探针自己的话是 NOT PROVEN |

### 1.2 .NET 程序集

```
node managed-lab/tools/loop.mjs
```
`JSON-SUMMARY {"total":27,"pass":27,"fail":0}` + `LOOP CLOSED`，**16.8 s** `[实测]`。
它的总结行是重点：*every sample was recovered from its decompilation alone*。
**失效**：目标其实不是 .NET → jar 会被它忽略（静默）；混淆样本用 `ilspycmd` 或
`powershell -File scripts\dnspy-console.ps1`，**`de4dot` 没装**（exit 127），别让人跑它。

### 1.3 APK

```
node mobile-lab/tools/loop.mjs
```
`LOOP CLOSED`，**8.1 s** `[实测]`——从源码构建**真 APK**，native 库与独立 ELF 实现交叉核对，
JADX 与 Apktool 用各自的解码器复现同一批发现。
**失效**：没有设备 → 不 attach（lab 自己印 `NOT PROVEN (no device on this box)`）；
**SKIP 不是 PASS**。单个 `.class` 走 `powershell -File scripts/jadx-decompile.ps1 -InputPath X.class`
（2026-10-05 测过四种压力输入，但**不是 registry 能力**，别当能力引用）。

### 1.4 pcap / 网络

```
node net-reverse/tools/loop.mjs          # LANE CLOSED + ISOLATION HELD，12.3 s [实测]
python net-reverse\tools\pcap_reader.py FILE.pcap   # 直接读一个 pcap
```
**失效**：每次都要读 isolation 行——它是「没碰机器真实证书库/系统代理」的证明，行没了结论就没了。

### 1.5 内存镜像 / 取证

```
node forensics-lab/tools/loop.mjs        # LOOP CLOSED，10.4 s [实测]
```
**失效**：符号不匹配的镜像；**负结果之前先跑 `windows.info`**——十二个插件各返回一张空表
读起来和一台干净机器一模一样。

### 1.6 协议描述符提取（ELF，无 protoc / 无 grpcio）

```bash
python extract-fdp2.py <binary> <outdir>      # 站在 re-samples 目录里跑
node   dump-fields.mjs <outdir> [protoFilter] [messageFilter]
```
**锚点必须是 `.proto` 路径字符串**（`exa/codeium_common_pb/codeium_common.proto`），
**不能**锚 ASCII `"descriptor"`——后者 0 命中（第一版的失败原因）。
`[实测]` 重跑：184,880,320 B 的 `language_server_linux_x64` → **1.58 s**、55 个 blob、
与 2026-10-01 记录的 manifest **55/55 逐字节相同**（sha256 全等）。零依赖（只用 Python 标准库）。
**失效条件（本轮新发现，很重要）**：**55 个 blob ≠ 55 个描述符**，见 §5.2。

### 1.7 模型目录 / 字符串提取

| 目的 | 命令 | 证据形状 | 失效条件 |
|---|---|---|---|
| 模型枚举表 | 有界扫描 `MODEL_[A-Z0-9_]+` | **646 个不同 token**（LS v1.8.1）`[实测]` | 只是「存在」；不能证明某个 uid 服务端有效 |
| RPC 名单 | **用描述符**（§1.6）而不是扫字符串 | 62 个 descriptor → 17 个 service / 622 个 method `[实测]` | — |
| 字符串扫 RPC | `python rpcinv.py <binary>`（有界 8 MiB 分块） | 松匹配 809、紧匹配 559 个「不同路径」`[实测]` | **上界，不是名单**：这个二进制的字符串块是**拼接**的，`/exa.api_server_pb.ApiServerService/PingAccountOwnershipNotificationVerification` 就是一个命中——`Notification` 与 `Verification` 是两条串。负控制：同一个正则打 c01 PE → **0** 命中 `[实测]` |

### 1.8 损坏容器的处理（ELF）

```
python ehfde.py FILE          # 节表健康信号 + program header 路线的 FDE 计数
python verify_starts.py FILE  # 用 capstone/段属性反证这些起点是不是真的
```
`[实测]` 在 184 MB 的 LS ELF 上：`PT_GNU_EH_FRAME` → `.eh_frame_hdr`（`fde_count=9749`）→
解出 **9,749 个函数起点**，与「按名字找 section」路线指向**同一个偏移**（`0x6a055b0`），
全部落在可执行 `PT_LOAD` 内，抽样 200 个起点 **196 个**首指令是合理序言（其余 4 个是
`ret`/`prefetcht0`/`xorps`/`movzx`，仍是合法指令边界）。
`[实测]` 合成损坏样本：把站内 `make-so.mjs` 造的 ELF 的节表改成
`sh_name=0xDEADBEEF`、`sh_type=0x70000000`（**devin 二进制报告里的那个形状**）后：
- `readelf.py -S` → **exit 0**，9 行里 8 行名字印成 `<unknown>`（**静默撒谎**，不是报错）
- 站内 `verifySo()` → `ok:false` 并逐条点名 `missing section .text/.rodata/.dynstr/.dynsym/.dynamic/.hash` + 3 条 `sh_link` 错
- 我的检测器 → `sh_name_oob: 8`

**失效条件**：`0x70000000` **本身不是损坏证据**——它是 `SHT_LOPROC` 起点，是合法值；
判据是「`sh_name` 落在 `.shstrtab` 之外」+「期望的名字在原始字节里但没有任何 section 认领它」。
没有 `PT_GNU_EH_FRAME` 的文件（部分静态/加壳产物）**回退路线不可用**，要如实报这一句，别报 0。
**Go 目标另说**：`.eh_frame_hdr` 只给地址，Go 产物应走 `runtime.pclntab`（给名字）——见 §4 U9 与 §8。

### 1.9 动态

| 目的 | 命令 | 证据形状 | 失效条件 |
|---|---|---|---|
| Windows 目标注入 | `& '.\Mobile-Android\objection\.venv\Scripts\frida.exe' -f "$env:TEMP\fridaprobe\target.exe" -q -e 'Java.perform(...)'` | 真进程被插桩 | **`-q` 必须有**（否则掉进 REPL 不退出）；**frida 17.17.0 拒绝 `--no-pause`**；别粘贴带 `...` 的版本——有人因此对着一个叫 `target.exe ...` 的文件跑出 exit 0 |
| 原生 GUI 动态 | `Debuggers\x64dbg`（在盘）、`Debuggers\Cheat Engine` | 人工会话 | 没有 CLI 门；产物不可复现 |
| JS/浏览器 | `node web-reverse/tools/loop.mjs` → `LOOP CLOSED`，**4.4 s** `[实测]`；单独条目 `python scripts/assert-probes.py web.js.cdp` → **OK，7.8 s** `[实测]` | 签名算法恢复 + 浏览器外造请求 | 只覆盖 CDP 能看的层 |
| 语言级 DAP | **本机没有可用 adapter**，见 §2.2 | — | — |

### 1.10 站内自检（改完东西跑哪个）

| 命令 | 回答 | 本轮实测 |
|---|---|---|
| `python scripts/assert-probes.py --list` | 28 条能力里哪些会跑、哪些 SKIP | 28 行、3 行 SKIP `[实测]` |
| `python scripts/assert-probes.py --budget N --timeout T --require-complete [--skip-slow]` | 真跑并**拒绝在没跑全时通过** | 见 §7 `[实测]` |
| `python scripts/doc-facts.py` | wiki 里的数字 vs registry | `OK, every live numeric claim matches the registry`，扫描 144 个 wiki 文件、44 条活数字声明，exit 0 `[实测]` |
| `python scripts/registry-verify.py` | registry 自己的规则 | 本轮未跑 `[未实测]` |
| `powershell -File scripts/verify-all.ps1` / `smoke-all.ps1` | 两棵树快检 / 每个 lab 自跑 | 本轮未跑（由别的车道/收尾跑）`[未实测]` |

---

## 2. 四件专项评估（brief 点名的四件）

### 2.1 符号执行（angr 类）——**先别装 angr，本机已经有 unicorn**

实测本机 Python 环境 `[实测]`：

| 库 | 状态 | 证据 |
|---|---|---|
| `unicorn` | **2.1.4，可用** | 跑 `mov rax,42; add rax,8; ret`：3 步、`RAX=50`（第一次忘了映射栈 → `UC_ERR_READ_UNMAPPED`，补上 RSP 后通过） |
| `capstone` | 5.0.7 | 见 §1.8 的 196/200 |
| `pefile` | 2024.8.26 | — |
| `pyelftools`(elftools) | 0.33 | 全文的 ELF 解析都靠它 |
| `angr` / `claripy` / `z3` / `miasm` / `triton` / `qiling` / `pwntools` | **全缺** | `importlib.import_module` 逐个试 |

**结论**：具体（concrete）模拟现在就能做，用 unicorn；**符号**执行（要解约束）才需要 angr。
angr 的落地成本不是零：它拖 z3 + claripy（数百 MB），而且**本机站规不做网络安装**——
要么 Owner 点头，要么走离线 wheel。wiki 侧已把它记成最大的未覆盖能力类：
`wiki/methods/arsenal-skill-index.md:210`（§2 头条：四个真空洞 = kernel/WinDbg、emulation、
symbolic execution、source-level DAP）与 `:221`（§2 第 8 条 `angr.mcp`）。
`arsenal-how-to-use.md` §9 也写着「`angr` is surveyed, not installed」。

### 2.2 DAP 调试适配——**客户端在，适配器一个都没有**

`[实测]` 本机：

| 角色 | 现状 |
|---|---|
| DAP **客户端** | 有。omp 的 `xd://debug` 设备，`adapter` 可填 `gdb` / `lldb-dap` / `debugpy` / `dlv` / `rdbg` / 自建 `dap.json` |
| `gdb` | 在（w64devkit，GNU gdb 17.2），**但这个 build 不支持 DAP**：`gdb --interpreter=dap` → `Interpreter 'dap' unrecognized`；且 `Python scripting is not supported in this copy of GDB` |
| `lldb-dap` / `lldb` | 缺 |
| `debugpy` | 缺（`pdb` 在，但它不是 DAP adapter） |
| `dlv` / `rdbg` | 缺（`go` 在，所以 dlv 可以 `go install`——但那也是网络安装） |
| `cdb`（WinDbg/SDK） | 缺 |
| `~/.omp/agent` 下的 `dap.json` | **没有**，即没有任何 adapter 被配置 |

**结论**：DAP 这条线是**「装一个 adapter」的问题，不是「搭一套调试器」的问题**。最便宜的一步是
`debugpy`（Python 车道立刻可用）；native 车道本轮**不值得**为 DAP 投资——站内已有的原生动态是
x64dbg（GUI）+ frida + IDA/Ghidra，DAP 在这里换不来新信息。参考：`arsenal-skill-index.md:220`
（§2 第 7 条 `debugmcp/mcp-debugger`，DAP 无头驱动）。

### 2.3 Ghidra 模拟器（registry 里 blocked 的那条）——**successor 核实完毕，且可构建**

`[实测]` 直接开装好的 Ghidra 12.1.3 的 jar 与源码 zip 看：

- `Static-Reversing/Ghidra/ghidra_12.1.3_PUBLIC/Ghidra/Framework/Emulation/lib/Emulation.jar`
  = **1,271,831 B**（与 `docs/research/ghidra-capability-spec.md:225-232` 记的字节数一致）
- jar 里 `ghidra/pcode/emu/` 有 **315 个 class**（含 `PcodeEmulator.class`），
  同时 `ghidra/app/emulator/` 仍有 **19 个**（旧的 `EmulatorHelper`/`DefaultEmulator`）
- 同一个 lib 目录里就有 `Emulation-src.zip`，`ghidra/pcode/emu/PcodeEmulator.java` 的 javadoc 逐字包含探针头引用的那句：
  `IMPORTANT: The inject must also return control to the calling function, usually by replicating the conventions of the target platform.`
- 构建条件在盘：`java`/`javac` = **Temurin 21.0.12.1**（`D:\Software\Developer\jdk\21`）

**所以「successor identified, buildable」核实为真**，并且 brief 里那个「前作说」可以更精确：
被弃用的是 `ghidra.app.emulator.*`（javac 报 deprecated-and-marked-for-removal），
替代是 `ghidra.pcode.emu.PcodeEmulator`。**blocked 的原因不是 API 没了**，是
「scratch stack 没映射，参数/返回地址写不进去 → 回到 PC=0、输出缓冲 48 B 全零」——
**是我们自己的 bug**（`scripts/emulation-probe.ps1` 头里写得很清楚），加上一个 Owner 决策：
目标 Ghidra 大版本（旧 API 会被删）。

### 2.4 损坏节表的通用处理——**能做成一个脚本，零新依赖**

可以，而且判据是测出来的（§1.8）：一个脚本两件事——**先判节表能不能信**，再**用不依赖节表的路线取数据**。
检测信号（任一命中就别信节表）：

1. 有任何 section 的 `sh_name` ≥ `.shstrtab` 的 `sh_size`
2. `e_shstrndx` 越界 / `e_shoff` 为 0
3. **期望的名字在文件原始字节里存在，但没有任何 section 认领它**（本轮合成样本正是这个形状：
   `.shstrtab` 内容还在，节表却全指到界外）
4. 某个 `PT_*` 指向的偏移没有任何 section 覆盖（交叉核对，不是单点判断）

回退路线：`ELF header → program header → PT_GNU_EH_FRAME → .eh_frame_hdr → FDE 表`（§1.8 实测 9,749 条）。
**注意**：`sh_type=0x70000000` **不是**判据（`SHT_LOPROC` 起点，合法值）；
**没有 `PT_GNU_EH_FRAME` 时要输出「回退不可用」，不能输出 0**。
落地成本：约 2 小时（站内已有 `mobile-lab/lab/build/make-so.mjs` 的 `verifySo()` 可以做它的自检对偶，
别再写第二套）。风险：对「本来就没节表」的产物（部分加壳/静态）会误报——所以输出必须是三态
（`healthy` / `lying` / `no-section-table-to-judge`），不是布尔。

---

## 3. `assert-probes.py --list` 的真实输出与解释

**先纠一句 brief 里的前提**：`--list` **只印 SKIP 标记，不印原因**。
`--list` 分支（`scripts/assert-probes.py:787`）是
`print(f"  {'SKIP ' if c['id'] in SKIP else 'run  '} {c['id']:<30} {cmd[:58]}")`——
只有 id 和命令前 58 字符。**原因要真跑那条才印**（`SKIP` dict 在 `:121-146`，原因在 `:553-554` 输出）。
两个都实测了：

```
$ python scripts/assert-probes.py --list        # 28 行，3 行 SKIP
  SKIP  dynamic.device.frida           adb devices
  SKIP  native.il2cpp.symbols          powershell -File scripts\il2cpp-probe.ps1
  SKIP  native.ghidra.emulate          powershell -File scripts\emulation-probe.ps1
  （其余 25 行都是 run）

$ python scripts/assert-probes.py native.ghidra.emulate dynamic.device.frida native.il2cpp.symbols
  SKIP  dynamic.device.frida: state=absent; needs an attached device. VERIFIED 2026-10-05: frida 17.17.0 is present
        and runs; its -U channel prints 'Waiting for USB device to appear...'. The tool is fine, the hardware is absent.
  SKIP  native.il2cpp.symbols: state=absent; needs an extracted IL2CPP metadata dump. MEASURED 2026-10-05: its probe
        DOES run and pass -- scripts/il2cpp-probe.ps1 exits 0 and prints the recorded 'IL2CPP ABSENT'.
  SKIP  native.ghidra.emulate: state=blocked; needs a runtime the registry does not have. MEASURED 2026-10-05: its
        probe DOES run and pass -- scripts/emulation-probe.ps1 exits 0 and prints the recorded 'PCODE EMULATION BLOCKED'.
assert-probes: 3 entries; verdicts 3 SKIP.
```

**逐条判读（哪些是真不可用、哪些只是没绑定产物）**：

| SKIP 条目 | 真不可用？ | 判读 |
|---|---|---|
| `dynamic.device.frida` | **真不可用（硬件）** | 工具在（frida 17.17.0 能跑），设备不在。换机器/插设备才有意义，**没有技术解** |
| `native.il2cpp.symbols` | **真不可用（缺产物 + 运行时）** | 探针能跑且通过，但通过的内容是「我拒绝」；本机 `global-metadata.dat` 只存在于第三方商业软件里（来源门过不了）。两个阻塞都不是技术：一个是 .NET 6 运行时，一个是 Owner 点名 |
| `native.ghidra.emulate` | **不是「不可用」，是「没做完」** | 探针跑通并印出 `PCODE EMULATION BLOCKED`；API 可达、编过、跑了 15 步 p-code。**blocked 的是我们的输入构造**（§2.3） |
| `native.crosscompare.ghidra` | **不在 SKIP 里**（会跑） | 它 `state=observed`，只是**没有绑产物**：`probe.run_log`/`sha256` 都空 → 被 `doc-facts.py` 算成「未绑定」的两个之一 |
| `native.yara.triage` | **不在 SKIP 里**（会跑） | 有 `run_log` 但**没有 `sha256`** → 按 `doc-facts.py` 的判据（run_log **且** sha256）不算 bound。这是「没绑定」的另一个样本，不是「不可用」 |
| `web.js.cdp` | **不 SKIP** | `arsenal-how-to-use.md` §5 说「预计出现第五个 SKIP（无负控制）」。**本轮实测这条已经不会了**：命名跑 → `OK`，控制项 `expect_exit`/`expect_output` 都匹配。那句是旧的 |
| `arsenal-how-to-use.md` §5 的「四条被跳过」表 | **旧了** | 表里第 4 条 `native.crosscompare.ghidra` 标 `planned`；现在 registry 里是 `observed`。今天的真值是 **3 条 SKIP**（上表前三行） |

**一句话**：`SKIP` = 没跑（三种原因：硬件、产物、自己没做完）；**「没绑定」是另一个轴**
（`crosscompare` 与 `yara.triage`），这两个会跑、只是没人留产物哈希。把两个轴混起来就会得出
「四个能力不可用」这种既对又错的句子。

---

## 4. 升级建议（每条：更强/更省 + 出处 + 成本 + 状态）

按「落地成本 ÷ 收益」排。

### U1. 把「损坏节表检测 + program header 回退」做成站内脚本 —— **最便宜，收益最大**
- **内容**：§2.4 的三态检测器 + `PT_GNU_EH_FRAME → .eh_frame_hdr → FDE` 回退（代码骨架在 §6）。
- **省什么**：这次如果不做，下一个窗口还得重写一遍（前作的 FDE 索引就死在 `%TEMP%` 里，见 §5.1）。
- **出处**：本轮实测（§1.8 / §7）；前作测量在 `%USERPROFILE%\.omp\extra-hands\RESEARCH\windsurfapi-verification-ledger-2026-10-01.md:95-101`。
- **成本**：~2 h，**零新依赖**（pyelftools 0.33 已在）。风险：三态输出必须写死，别退化成布尔。
- **状态**：`[实测]` 方法已跑通（脚本在 `%TEMP%`，§6 是可落地版本）。

### U2. 修描述符提取器的 blob 边界，并把它固化 —— **一个已知缺陷，修一次省一辈子**
- **内容**：`extract-fdp2.py` 的 blob 延长步**在遇到第二个顶层 field-1 (`name`) 时就停**；
  再加一个切分器（§6 的 `split_fdp.py` 逻辑），manifest 里记「blob 含 N 个描述符」。
- **省什么**：任何「用 manifest 数描述符」的结论都会错（本轮实测 55 blob → **62 个不同描述符**，§5.2）。
- **出处**：`re-samples/extract-fdp2.py` 的文件头（自述「byte-exact」）+ 本轮实测。
- **成本**：~1 h，零依赖。风险：切分规则对「没有 package 字段的描述符」会少切一刀（本轮 132 个切片里 6 个无 package 字段，但**没有**一个还残留第二个 name 字段，所以在本产物上是完整的）。
- **状态**：`[实测]`（切分器与计数都跑过）。

### U3. RPC/方法名单走描述符，字符串扫描降级为「上界 + 负控制」
- **内容**：名单只从 §1.6 的描述符出；字符串扫只在没有描述符时用，且必须带负控制。
- **省什么**：本轮的松正则给出 809 条「路径」，其中绝大多数是拼接噪声（§1.7）。
- **出处**：本轮实测；`arsenal-skill-index.md` §2 第 14 条（LIEF 类工具「nothing here beats radare2 + Ghidra」）。
- **成本**：0（改用已有产物）。风险：描述符只覆盖它自己声明的服务——**没声明的服务不会出现在名单里**，要写清楚这是「下界」。
- **状态**：`[实测]`。

### U4. 符号执行：先用 unicorn，angr 等 Owner 决策
- **内容**：把 `unicorn` 记成「站内已有」；angr 只在出现**约束求解类问题**时再提。
- **省什么**：省掉一次数百 MB 的安装 + z3 依赖链。
- **出处**：本轮实测（unicorn 2.1.4 跑通 3 步）；`arsenal-skill-index.md:210`、`:221`（§2 第 8 条 angr.mcp）；`arsenal-how-to-use.md` §9。
- **成本**：0（已装）。angr 的路线成本：网络安装（站规不允许，需 Owner 点头）+ 磁盘 + 与 unicorn 的功能重叠。
- **状态**：unicorn `[实测]`；angr `[未实测]`。

### U5. DAP：先装 `debugpy` 一条，别铺开
- **内容**：Python 车道用 `debugpy` 接 `xd://debug`；native 车道继续 x64dbg + frida。
- **省什么**：省掉「为 DAP 换调试器」的大工程——本机没有任何 adapter，问题不在客户端。
- **出处**：本轮实测（§2.2）；`arsenal-skill-index.md:220`（§2 第 7 条）。
- **成本**：`debugpy` 是一次 pip 安装（**网络安装，按站规要 Owner 点头**）；`lldb` 是整套 LLVM；`cdb` 是 Windows SDK。
- **状态**：现状 `[实测]`（gdb 不支持 DAP、其余全缺）；装完后的效果 `[未实测]`。

### U6. Ghidra 模拟器：直接写在 `PcodeEmulator` 上，别修旧 API
- **内容**：按 §2.3 的结论，新的 `EmulateDecode.java` 用 `ghidra.pcode.emu.PcodeEmulator`，
  自己映射 scratch stack（按目标平台调用约定），用 `checkLoad`/`checkStore` 断言写入合法。
- **省什么**：省掉在「Ghidra 打算删掉的 API」上白建一次。
- **出处**：`scripts/emulation-probe.ps1` 头（它自己已经写了这条答案）；`docs/research/ghidra-capability-spec.md:225-232`；本轮实测 jar/javadoc。
- **成本**：Ghidra 脚本 + JDK 21（都在盘）。**前置决策**：目标 Ghidra 大版本（旧 API 会被删）。
- **状态**：前提 `[实测]`（jar/类/javadoc/JDK）；改写本身 `[未实测]`。

### U7. PE 识别步换 `diec --json`
- **内容**：摸底那一步用 DiE 自己的 JSON，而不是包一层 PowerShell 再解析。
- **出处**：`arsenal-how-to-use.md` §0（「skill index §3M entry 1 (Detect It Easy, diec --json) 是这个问题更强的版本，值得装」）。
- **成本**：装 DiE CLI；现在 `triage-packer.ps1` 已经在用 DiE 的读数，只是包了一层。
- **状态**：`[未实测]`（本轮没装没跑）。

### U8. 内核对 / WinDbg 那个洞 —— 明确不做，除非有目标
- **内容**：`arsenal-how-to-use.md` §9 与 `arsenal-skill-index.md:210` 都把它列成真空洞；
  最便宜的路是 `cdb -z DUMP.dmp -c "..."`，但**本机没有 `cdb`**（`[实测]`，Windows SDK 未装）。
- **成本**：装 Windows SDK/WinDbg；**没有内核目标时是纯负债**。
- **状态**：`[实测]`（缺 cdb）；能力本身 `[未实测]`。

### U9. Go 目标：用 `pclntab` 而不是 `.eh_frame_hdr`（更强，且给名字）
- **内容**：函数起点/函数名从 `runtime.pclntab` 自解析（Go 1.20+ 格式），或 `GoReSym`；
  自读 buildinfo（`\xff Go buildinf:` 魔数）拿模块路径。
- **比什么更强**：`.eh_frame_hdr` 只给**地址**，`pclntab` 给**名字**；且 `GolangSymbolAnalyzer` 在
  Go 1.25.x 上会抛异常（函数名全 `FUN_*`）。
- **出处**：同目录今日实测 `notes/2026-10-15-ghidra-go-symbols-and-space-paths.md`（verified，
  对齐率 12,706/12,768 = 99.5%）。本轮我用的 LS 二进制正是 Go 产物（`.note.go.buildid`）。
- **成本**：解析脚本（那条车道已写过一版）；零新依赖。
- **状态**：`[记录]`（同目录另一车道的 verified 记录，本轮未复跑）。

### U10. Ghidra headless 的四个坑，写进 `debugger-workstation` 的 trap 表
- **内容**：(1) **路径含空格必失败**（`cmd /c` 引号剥离）→ 先复制到 `_input/` 并核对 md5；
  (2) >10 MB 要显式 `-TimeoutMs`；(3) `ExportDecompile.java` 遇病理函数 30 s/函数 → 用 fast 版（5 s/函数）；
  (4) Go 1.25.x 符号分析器抛异常（见 U9）。
- **出处**：`notes/2026-10-15-ghidra-go-symbols-and-space-paths.md`（verified，2026-10-15）。
- **成本**：0（只是把已有记录挂到 skill 的 trap 表）。风险：改动 skill 文件要走站内门。
- **状态**：`[记录]`；引用前按站规复跑一次。

---

## 5. 本轮复核发现的既有记载不准（三处，全部留痕）

### 5.1 「189,293 个函数起点」是**记录**，不是本轮复现——而且那个二进制已经不在盘上了
- 记录在 `%USERPROFILE%\.omp\extra-hands\RESEARCH\windsurfapi-verification-ledger-2026-10-01.md:95-101`
  与 `...\windsurfapi-audit-session-2026-09-30-to-10-01.md:145-150`（两份都写「重建产物在 `re/mr1/idx.pkl`，
  临时目录，**会丢**」）。
- 本轮 `[实测]`：全盘搜 150–250 MB 的新文件**找不到** `devin` CLI（记的是 194,950,824 B、sha256 `5a8649d9…`），
  所以这个数字**无法复现**，只能引用。**方法**本身已在本轮用另一个真实 ELF 复现（§1.8，9,749 条）。
- 教训与项目已有的那条一致：**产物落在 `%TEMP%` 等于没落**。这是 U1 的理由。

### 5.2 「55 份 FileDescriptorProto」——**55 是 blob 数，不是描述符数；真值 62**
- 提取器（`re-samples/extract-fdp2.py`）会把 blob 向后延长到「解析不再干净」为止。
  protobuf 顶层是自定界的，**两个描述符拼在一起照样 round-trip 成功**，所以它自称的
  byte-exact 检查抓不到这件事。
- 本轮 `[实测]`：55 个 blob 切成 **132 个切片（全部以 `0x0A` 开头且解析成功）**，
  按 sha256 去重 = **62 个不同描述符**；`exa/codeium_common_pb/codeium_common.proto` 一个人出现在 **12 个** blob 里，
  `exa/cortex_pb/cortex.proto` 11 个，`exa/language_server_pb/language_server.proto` 10 个。
- **受害面**：任何「把 manifest 当描述符清单」的下游都会把同一个 message 数很多遍。
  本轮我自己第一版解析器就中招——它把 blob 当一个描述符，于是「package」字段印成一串拼接的包名，
  并把同一个 service 每个文件数一遍（56 个 service / 4,659 个 method 就是这么来的，**这个数不能引用**）。
  去重后的正确数是 **17 个不同 service / 622 个不同 method**。
- **没有受害的**：2026-10-01 的 20/20 字段核对用的是 `fdp_034.proto`（`codeium_common.proto`），
  我核了它**只含 1 个 name 字段**（干净单描述符），所以那个结论不受影响。
  交叉印证：二进制里的字符串 `exa.auth_pb.AuthService/GetUserJwt` 与描述符里
  `AuthService` 恰好 1 个方法（`GetUserJwt`）一致。

### 5.3 「23 bound / 2 unverified」数字对，**括号里的解释过期了**
- `python scripts/doc-facts.py`（站内自己的门，本轮 exit 0）印：
  `28 capabilities (25 observed) … 23 bound to a retained artifact, 2 unverified`。
- 但 `wiki/ROUTER.md` §4 把这 2 条写成 `native.ida.*`（MCP 驱动，无物可哈希）。
  **实测**：按 `doc-facts.py:171-180` 的判据（`probe.run_log` **且** `probe.sha256`），
  25 个 observed 里未绑定的是 **`native.crosscompare.ghidra`** 与 **`native.yara.triage`**；
  两个 IDA 条目**现在都有 run_log + sha256**（2026-10-04/05 那次修正把绑定从 21/27 提到 23/27，
  `wiki/methods/dwgxhacker-HANDOFF.md:41`），只是它们的 `evidence_binding.status` 仍写着 `unverified`——
  这两个字段回答的是不同问题，混用就会写错句子。

### 5.4 「四条被跳过」+「预计第五个 SKIP」也过期了（见 §3）
- 实测：`--list` 里 **3 条 SKIP**；`native.crosscompare.ghidra` 是 `observed` 且会跑；
  `web.js.cdp` 命名跑 → `OK`（它的负控制现在是可执行的）。
- 出处：`wiki/methods/arsenal-how-to-use.md` §5 的表与 §1 的注。

### 5.5 一个措辞级的更正：`sh_type=0x70000000` 不是损坏证据
它落在 `SHT_LOPROC`（0x70000000）起点的处理器自定义区间里，**是合法值**。
本轮合成样本实测：把节表打成 `sh_name=0xDEADBEEF` + `sh_type=0x70000000` 之后，
**能站住的判据是「`sh_name` 越出 `.shstrtab`」**（检测器 `sh_name_oob: 8`），
以及「名字在原始字节里但没人认领」。写案例时把 `sh_type` 当主证据，下一个读者会误判正常产物。

---

## 6. 可以落地的脚本（`%TEMP%` 里那两个会丢，这里留本体）

### 6.1 `scripts/elf-section-health.py`（建议落地路径）
三态检测 + FDE 回退，只用标准库 + pyelftools（两者都在盘）。核心（已跑通的那版见 §7）：

```python
PT_GNU_EH_FRAME = 0x6474E550
def section_health(data):
    """-> 'healthy' | 'lying' | 'no-section-table-to-judge'"""
    e_shoff, = struct.unpack_from('<Q', data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
    if not e_shoff or not e_shnum:
        return 'no-section-table-to-judge'
    if e_shstrndx >= e_shnum:
        return 'lying'
    o = e_shoff + e_shstrndx * e_shentsize
    str_off, = struct.unpack_from('<Q', data, o + 0x18)
    str_sz,  = struct.unpack_from('<Q', data, o + 0x20)
    shstr = data[str_off:str_off + str_sz]
    oob = 0
    for i in range(e_shnum):
        nm, = struct.unpack_from('<I', data, e_shoff + i * e_shentsize)
        if nm >= len(shstr):
            oob += 1
    if oob:
        return 'lying'
    # 交叉核对：PT_* 指向的偏移有没有 section 认领（用 program header 走一遍）
    return 'healthy'

def fde_starts(data):
    """program header -> PT_GNU_EH_FRAME -> .eh_frame_hdr -> 函数起点表。
    返回 (count, starts)；找不到就返回 (None, 'fallback-unavailable')，不要返回 0。"""
    ...
```

### 6.2 `split_fdp.py` 的切分规则（描述符 blob 里其实有几个描述符）
顶层遍历；**遇到「field 1 (`name`) 且前面已经出现过 field 2 (`package`)」就是下一个描述符的起点**。
实测在 55 个 blob 上：132 个切片、0 个切片残留第二个 `name` 字段。
限制（要写进注释）：**package 字段为空/缺省的描述符切不出来**（本轮 132 个切片里有 6 个无 package 字段）。

---

## 7. 本轮实测的原始命令与输出形状（`[实测]` 的证据本体）

站根 = `<repo>`。时间 = 墙钟。

| # | 命令 | 输出形状 | 时间 |
|---|---|---|---|
| 1 | `python scripts/assert-probes.py --list` | 28 行；`SKIP` 3 行（frida / il2cpp / ghidra.emulate），其余 `run` | <1 s |
| 2 | `python scripts/assert-probes.py native.ghidra.emulate dynamic.device.frida native.il2cpp.symbols` | 3 条 SKIP + 各自原因；`assert-probes: 3 entries; verdicts 3 SKIP.` | <1 s |
| 3 | `python scripts/assert-probes.py native.pe.container native.disasm.capstone native.pe.hardening native.behaviour.capa --budget 240 --timeout 120 --save-evidence <TEMP>\evidence` | `4 entries; verdicts 4 OK`，每条注明「产物本轮真写盘 + sha256 在证据日志里」 | **48.0 s** |
| 4 | `python scripts/assert-probes.py web.js.cdp` | `1 entries; verdicts 1 OK` | **7.8 s** |
| 5 | `python scripts/doc-facts.py` | `28 capabilities (25 observed, 7 typed edges)` / `23 bound to a retained artifact, 2 unverified, 27 runnable controls, 1 declared plans` / `scanned 144 wiki files, 44 live numeric claims checked` / `OK…` exit 0 | ~2 s |
| 6 | `node net-reverse/tools/loop.mjs` | `LANE CLOSED: …` + `ISOLATION HELD` | **12.3 s** |
| 7 | `node forensics-lab/tools/loop.mjs` | `LOOP CLOSED: …` | **10.4 s** |
| 8 | `node crypto-lab/tools/loop.mjs` | `JSON-SUMMARY {"total":17,"pass":17,"fail":0}` + `LOOP CLOSED` | **4.9 s** |
| 9 | `node managed-lab/tools/loop.mjs` | `JSON-SUMMARY {"total":27,"pass":27,"fail":0}` + `LOOP CLOSED` | **16.8 s** |
| 10 | `node mobile-lab/tools/loop.mjs` | `LOOP CLOSED` + `NOT PROVEN (no device on this box)` | **8.1 s** |
| 11 | `node web-reverse/tools/loop.mjs` | `LOOP CLOSED: signature captured…` | **4.4 s** |
| 12 | `node native-lab/tools/loop.mjs --only=decompile` | `JSON-SUMMARY {"total":15,"pass":15,"fail":0}` + `LOOP CLOSED: IDA 9.2 is present and licensed…` | **2.98 s** |
| 13 | `node native-lab/tools/loop.mjs --only=list_funcs` | `JSON-SUMMARY {"total":6,"pass":6,"fail":0}` | **2.77 s** |
| 14 | `python extract-fdp2.py language_server_linux_x64 <TEMP>\fdp_rerun` | `wrote 55 to …`；逐条 `fdp_NNN.proto <bytes> <proto_name>` | **1.58 s** |
| 15 | 上一步产物 vs 记录 manifest（55 条 sha256 比对） | `recorded 55 re-extracted 55` / `byte-identical: 55 / 55` | ~1 s |
| 16 | `python split_fdp.py fdp_rerun` | `blobs 55 slices 132 parse-ok 132 distinct descriptors 62` / `service definitions 56 methods 4659`（含重复；去重后 17 / 622） | ~1 s |
| 17 | `python ehfde.py language_server_linux_x64` | `PT_GNU_EH_FRAME off=0x6a055b0 size=78004` / `section health {'sh_name_oob': 0, …}` / `fde_count=9749` / `function starts recovered: 9749` | ~3 s |
| 18 | `python verify_starts.py language_server_linux_x64` | `route A (section name) -> 0x6a055b0` == `route B (PT_GNU_EH_FRAME) -> 0x6a055b0` / `monotonic: True` / `starts outside an executable PT_LOAD: 0` / `capstone sample 200: plausible prologue 196/200` | ~4 s |
| 19 | `node make_corrupt.mjs`（站内 `make-so.mjs` 造 ELF 后打坏节表） | `built 1896 B…` / `verifySo(healthy): {"ok":true,…}` / `verifySo(corrupt): {"ok":false,"problems":["missing section .text",…]}` / `bytes differ: true same length: true` | ~1 s |
| 20 | `python <pyelftools>/readelf.py -S corrupt-shdr.so`（+ healthy 对照） | `healthy: exit=0 rows=9 unknown-named=0` / `corrupt: exit=0 rows=9 unknown-named=8` | ~1 s |
| 21 | `python rpcinv.py language_server_linux_x64`；负控制打 c01 PE | `distinct RPC paths 559`（紧正则）/ 控制 `distinct RPC paths 0` | 5.1 s / <1 s |
| 22 | 有界扫 `MODEL_[A-Z0-9_]+` | `distinct MODEL_* tokens: 646` | ~4 s |
| 23 | unicorn 微测试（`mov rax,42; add rax,8; ret`） | `unicorn 2.1.4 steps 3 RAX 50` | <1 s |
| 24 | `gdb --interpreter=dap` | `Interpreter 'dap' unrecognized`；`gdb -q -ex "python print('py ok')"` → `Python scripting is not supported in this copy of GDB.` | <1 s |
| 25 | 列 `Emulation.jar` / 读 `Emulation-src.zip` | `ghidra/pcode/emu/` 315 个 class（含 `PcodeEmulator.class`）；`ghidra/app/emulator/` 19 个；javadoc 命中 `IMPORTANT: The inject must also return control…` | ~2 s |

**我在这两棵树里写过的东西（透明起见）**：
- `notes/re-methods-20261015.md`（本文件，唯一一处站内写入）
- `%TEMP%\methodsup-20261015\`：`ehfde.py`、`verify_starts.py`、`rpcinv.py`、`split_fdp.py`、`make_corrupt.mjs`、`healthy.so`、`corrupt-shdr.so`、`fdp_rerun/`、`evidence/`（探针日志）
- 站内 lab 的**产物目录**（`native-lab/out/last-run-*.json` 等）是各探针自己声明的 `produces`，不是我手写的；
  `git status` 里看不到它们（已被忽略）。**没有改任何既有脚本、清单或 wiki 页**。

---

## 8. 同目录今日另外两条车道的相邻发现（会影响上面的判据）

这两份是**同一天、同一 `notes/` 目录**里的实测记录（不是我做的），跟 §1.1 / §1.8 / §4 直接相关，
所以在这里挂上指针，免得下一个窗口只读到本文件：

- `notes/2026-10-15-ghidra-go-symbols-and-space-paths.md`（verified）：
  1. **含空格路径的 Ghidra headless 必失败**（`cmd /c` 引号剥离）→ 先复制到无空格路径再跑；
  2. **Go 1.25.x 上 `GolangSymbolAnalyzer` 抛 `InvocationTargetException`**，函数名全 `FUN_*`
     → 自解析 `runtime.pclntab` 喂回重命名，对齐率 **12,706/12,768 = 99.5%**；
  3. **>10 MB 二进制要 `-TimeoutMs`**（默认 600 s 会超时）；
  4. `ExportDecompile.java` 30 s/函数 vs 自写 fast 版 5 s/函数。
  ⇒ **对 Go 目标，`pclntab` 比 `.eh_frame_hdr` 更强**：前者给**名字**，后者只给地址。
  我这轮用的 `language_server_linux_x64` 正是 Go 产物（`.note.go.buildid`），所以 §1.8 的 9,749 条
  是「地址下界」；要名字就走上表第 2 条。
- `notes/2026-10-15-electron-desktop-artifacts-signatures.md`（verified）：
  Electron fuse wire / `.jsc` V8 code cache / **asar 头布局**；其中一条与「损坏容器」直接同构：
  **`unpacked:true` 成员的 integrity 与磁盘不符是签名剥离的预期结果，不是被篡改**。
  这正是 §2.4 要的那种「先分类再判损坏」——数字对不上不等于容器坏了。

---

## 9. 本轮没做（缺口，明确列出）

- **没跑** `registry-verify.py` / `verify-all.ps1` / `smoke-all.ps1`（本轮由别的车道或收尾跑；§1.10 已标 `[未实测]`）。
- **没复现** 189,293 这个数字（二进制不在盘上，§5.1）。
- **没复现** 2026-10-01 的 20/20 字段逐条核对（只核了承载它的 blob 是干净单描述符，§5.2）。
- **没做** kernel/driver RE（无 `cdb`，无目标）、APK 设备侧（无设备）、IL2CPP（无授权产物）。
- **没装任何东西**：本轮零安装、零网络安装。§4 里带「网络安装」的项都停在建议层。
- **没重数** `arsenal-skill-archive.md` 的 182 条 / 229 URL（那是 wiki 侧的自述，引用时带日期与出处）。

---

## 10. 交货后的两处登记（**不在本车道的写权限内，必须由别人补**）

本车道只许写两个文件，所以下面两条**没做**，而其中第二条会让站内门变红：

1. **站内 `notes/INDEX.md` 缺本文件的一行**。同一天另外两条车道已经给自己加了行
   （`notes/INDEX.md` 现在是 `M` 状态），本文件还没有行。协议见 `docs/AGENT_EVOLUTION.md`。
2. **wiki 侧 `wiki/methods/re-method-upgrades-2026-10-15.md` 从 `INDEX.md` 不可达**
   → `python scripts/arsenal-two-tree-check.py` **退出 1**（实测）：
   ```
   arsenal-two-tree-check: 190 wiki pages, 189 reachable from INDEX.md
     UNREACHABLE  methods/re-method-upgrades-2026-10-15.md  -- on disk, linked from nowhere; INDEX.md:3 requires a row
   ```
   修法是一行（`wiki/INDEX.md` 的 methods 表里，紧跟 `adversarial-verdict-patterns.md` 那行之后）：
   ```
   | [methods/re-method-upgrades-2026-10-15.md](methods/re-method-upgrades-2026-10-15.md) | **RE 方法升级建议（2026-10-15 station 实测）** — 损坏节表三态检测 + FDE 回退；描述符 blob 边界缺陷（55 blob → 62 个描述符）；Ghidra `PcodeEmulator` 核实；DAP / 符号执行现状 |
   ```
   补完后 `doc-facts.py` 与 `arsenal-two-tree-check.py` 都应回到 exit 0
   （`doc-facts.py` 在本页存在的情况下已经实测 exit 0）。





