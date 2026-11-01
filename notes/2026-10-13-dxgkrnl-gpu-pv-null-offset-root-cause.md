---
tags: [debugger, dxgkrnl, gpu-pv, root-cause, verified]
status: verified
verification: >-
  Independently falsified-and-confirmed 2026-10-13 by a separate verifier agent that re-derived
  every instruction from the binary, swept all 110 call sites of the constructor, and parsed the
  PDB. Verdict `claim_holds`. It refuted 4 supporting claims, all corrected below.
source: static analysis 2026-10-13 against dxgkrnl.sys (Windows 11 26H2, build 26300)
---

# dxgkrnl GPU-PV 0x3B 根因：`lea` 从空指针算偏移，绕过被调函数的 NULL 检查

**一句话**：`DXGK_VIRTUAL_GPU_PARAV::VirtualGpuDriverEscape` 在 `+0x1f1` 读
`this->field_0x68`（一个 `DXGVIRTUALMACHINE*`，出生为 NULL，只有 `SetVirtualGpuVmBus` 赋非零值），
**不检查 NULL** 就用 `lea rdx, [rbx+0x60]` 算出成员地址。`rbx == 0` 时结果是 `0x60`——
**非零、无效**。被调构造函数里 `test rdx,rdx` 的 NULL 检查因此形同虚设，
`mov rdx,[rdx+8]` 去读 `0x68`，蓝屏。

## 崩溃链（逐条反汇编核实）

```
DXGK_VIRTUAL_GPU_PARAV::VirtualGpuDriverEscape      RVA 0x22e900, size 0x59c
  +0x0025  mov  rbx, rcx              ; rbx = this
  ...
  +0x01db  mov  rcx, rbx
  +0x01de  call SuspendDevices        ; RVA 0x22e81c
  +0x01e3  lea  rcx, [rbx + 0xb0]
  +0x01ea  xor  edx, edx
  +0x01ec  call 0x140235eac
  +0x01f1  mov  rbx, [rbx + 0x68]     ; rbx = this->field_0x68   ← 值为 NULL
  +0x01f5  lea  rcx, [rbp - 0x20]     ; rcx = &stack_obj
  +0x01f9  lea  rdx, [rbx + 0x60]     ; rdx = NULL + 0x60 = 0x60  ← 无 NULL 检查
  +0x01fd  call DXGAUTOPUSHLOCKSHARED ctor   ; RVA 0xca10

DXGAUTOPUSHLOCKSHARED::DXGAUTOPUSHLOCKSHARED        RVA 0xca10, size 0xa8
  +0x06    and   dword ptr [rcx+0x10], 0   ; this->Flags = 0
  +0x0a    mov   rbx, rcx
  +0x0d    mov   [rcx+8], rdx              ; this->pLock = 0x60
  +0x11    test  rdx, rdx                  ; 0x60 != 0
  +0x14    je    +0x28                     ; 不跳 —— NULL 检查被绕过
  +0x16    mov   rdx, [rdx+8]              ; 读 [0x68]   ←←← ACCESS VIOLATION
  +0x1a    mov   rax, gs:[0x188]           ; KeGetCurrentThread()
  +0x23    cmp   rdx, rax
  +0x26    je    +0x3a                     ; 相等 → 记断言
  +0x28    call  DXGAUTOPUSHLOCK::AcquireShared   ; RVA 0xb610
```

## `field_0x68` 的完整生命周期（全部访问点，穷举）

**类型：`DXGVIRTUALMACHINE*`** —— 它作为 `this` 传给 `DXGVIRTUALMACHINE::RemoveVirtualGpu`
（`DestroyVirtualGpu+0xd9`）和 `DXGVIRTUALMACHINE::ResetVirtualGpu`（`ResetVirtualFunction+0x166`）。
**不是「VmBus 对象」**（早期版本写错，2026-10-13 由独立 verifier 指出并经反汇编确认）。

| 函数 | RVA | 指令 | 动作 |
|---|---|---|---|
| `DXGK_VIRTUAL_GPU::DXGK_VIRTUAL_GPU`（基类构造，`??0DXGK_VIRTUAL_GPU@@QEAA@PEAVADAPTER_RENDER@@E@Z`） | `0x223ef0+0x3c` | `mov [rcx+0x68], rdx` | **出生置 NULL**（`+0x19 xor edx,edx`） |
| `DXGK_VIRTUAL_GPU_PARAV::SetVirtualGpuVmBus` | `0x22e400+0x2ce` | `mov [rsi+0x68], rcx` | **唯一非零赋值**（`rcx = [[rsi+0x60]+0x250]`） |
| `DXGK_VIRTUAL_GPU_PARAV::ResetVirtualFunction` | `0x22e130+0x1a6` | `mov [rbx+0x68], rbp` | **清零**（`+0x29 xor ebp,ebp`，`+0x31 mov rbx,rcx`） |
| `DXGK_VIRTUAL_GPU_PARAV::DestroyVirtualGpu` | `0x22db60+0x22` | `cmp [rcx+0x68], 0` | NULL 检查 |
| `DXGK_VIRTUAL_GPU_PARAV::DestroyVirtualGpu` | `0x22db60+0xce` | `mov rcx, [rbx+0x68]` | 取用 |
| `DXGK_VIRTUAL_GPU_PARAV::DestroyVirtualGpu` | `0x22db60+0xde` | `and [rbx+0x68], 0` | **清零** |
| **`DXGK_VIRTUAL_GPU_PARAV::VirtualGpuDriverEscape`** | **`0x22e900+0x1f1`** | `mov rbx, [rbx+0x68]` | **无检查取用 —— suspend 路径，崩溃点** |
| **`DXGK_VIRTUAL_GPU_PARAV::VirtualGpuDriverEscape`** | **`0x22e900+0x155`** | `mov rcx, [rbx+0x68]` | **无检查取用 —— resume 路径** |
| **`VmBusProcessPacket`** | **`0x3c6e70+0x209`** | `mov rax,[r8+0x68]` → `+0x218 mov eax,[rax+0x188]` | **无检查取用 —— VmBus 包路径** |

**共 9 处访问：4 写 + 1 检查 + 4 读。三处未检查使用，三个不同故障地址。**

> **⚠️ 2026-10-13 第三次更正（SubmissionValidity）**：此前记「8 处 / 3 读」仍**漏了 `VmBusProcessPacket`**。
> 三处未检查使用的故障点各不相同：
> - suspend → 构造函数 `+0x16`，崩在 `[0x68]`
> - resume → `ResumeChannel+0x6`，崩在 `[0xb8]`
> - VmBus 包 → `+0x218`，崩在 `[0x188]`
>
> **→「每次都在同一条指令崩」是错的**：同一个缺失的检查，三个入口，三个地址。本机只抓到第一个。
> 三处均已由我自己的反汇编独立复核。

**→ 3 个「查表可达」的 NULL 窗口 + 1 个仅竞态**：
1. `SetVirtualGpuVmBus` 成功前（**对象在创建时就进 manager 的链表，此时字段仍为 NULL**）
2. `SetVirtualGpuVmBus` 在写入前失败
3. `ResetVirtualFunction` 之后
4. ~~`DestroyVirtualGpu` 之后~~ —— **仅竞态**：manager 在清零**之前**已把对象从链表摘除，
   查表找不到它。列出仅为完整，**不声称可达**。

### ✅ 可达性已验证（FalsifyGpuPv，2026-10-13）

```
IOCTL 0x226460 → DpiFdoDispatchIoctl+0xadb → DxgkDdiVirtualGpuDriverEscape (0x1983e4，单调用者)
→ FindVirtualGpuByLuid（走 manager+0x68 链表，按 LUID 匹配 obj+0x1c/+0x20）
→ vtable[+0x28] = 0x22e900
```

**这条链上没有任何一步查 `this+0x68` 的状态。** 对象在 `CreateVirtualGpu`（`0x22d620`，
分配 `0x188` tag `DxgK`，ctor `0x22d4ec` @ `0x22d910`，`InsertHeadList` @ `+0x81..+0xa5`）
时就进了链表，**那时 `+0x68` 还是 NULL**。→ **窗口 1/2/3 真实可达，不是理论。**

### 对照证据：`DestroyVirtualGpu` 的 NULL 检查

```asm
DXGK_VIRTUAL_GPU_PARAV::DestroyVirtualGpu   RVA 0x22db60
  +0x14  48 83 79 60 00       cmp qword ptr [rcx + 0x60], 0    ; 检查 field_0x60
  +0x19  48 8b d9             mov rbx, rcx                     ; rbx = this
  +0x1c  0f 84 cf 00 00 00    je  0x22dc51                     ; → 函数内 +0xf1（field-0x60 清理路径）
  +0x22  48 83 79 68 00       cmp qword ptr [rcx + 0x68], 0    ; 检查 field_0x68  ← 同一个字段
  +0x27  0f 84 b6 00 00 00    je  0x22dc43                     ; → 函数内 +0xe3（跳过 field-0x68 清理块）
```

**注意**：`+0x27` 跳的是 **field-0x68 teardown 块**（落在 `+0xe3` 的 field-0x60 清理上），
**不是函数返回**。早期版本写成「提前返回」不准确。

**微软在同一驱动的另一个函数里，对同一个字段做了 NULL 检查并跳过清理块。
`VirtualGpuDriverEscape` 里没有这个检查 —— 这就是「缺一个分支」的直接对照。**

## 这不只是单点疏忽：是类级模式（独立 verifier 发现）

`DXGAUTOPUSHLOCKSHARED` 构造函数（RVA `0xca10`）在本映像里**有 110 个直接调用点**。
其中大量调用点**先取成员地址、不检查基指针**：

- **63 处**传 `[rcx+0x50] + 0xf8`
- **29 处**传 `ADAPTER_RENDER::GetVirtualGpuManager()` 的返回值 `+ 0x28`
- 若干单项：`+0x68` / `+0x48` / `+0x10` / `+0x190` 等

构造函数里的 `test rdx,rdx` **只能拦住精确的 NULL**，所以**每一个这样的调用点都是这个 bug 的潜伏形态**——
只在「基指针为 NULL **且** 成员偏移小到落在未映射页」时才可见。本次崩溃里偏移恰好是 `0x60`。

**110 个调用点里只有 3 个能在 NULL 基址上恰好得出 `0x60`**（`0x801e6` / `0x22eafd` / `0x3f45dd`），
而只有 `0x22eafd` 的基址是 NULL 初始化的字段，且转储栈帧独立地把调用者钉死在 `VirtualGpuDriverEscape+0x202`。
**→ 归因不受影响，但「其他 109 个点是否可达」未经追查（本轮未做，别当成已排除）。**

**派生类构造函数 `0x22d4ec` 不写这个字段**（它写的 `[rcx+0x68]` 里 `rcx = this+0xb0`，
即 `this+0x118`，是另一个对象）。

## 因此

`VirtualGpuDriverEscape` 在**字段仍是 NULL** 的窗口里被调用就会崩。四种进入该窗口的可能：

1. `SetVirtualGpuVmBus` **尚未成功执行**（IOCTL 先于 VmBus 建立到达）
2. `SetVirtualGpuVmBus` **失败**（该路径不写字段）
3. `ResetVirtualFunction` **已清零**（`+0x1a6`）
4. `DestroyVirtualGpu` **已清零**（teardown）

**缺陷本身是确定性的：缺一个 NULL 检查，不是野指针、不是内存损坏。**
所以跨 OEM、跨 CPU/GPU 厂商（NVIDIA/Intel/AMD）、跨构建都报出**逐字相同**的签名。
（**哪**一个窗口在实际崩溃时生效可能取决于时序——那一点静态数据定不了；
确定的是**任何一个窗口都会崩在同一条指令**。）

## 三处独立数据吻合

| 来源 | 值 | 对应 |
|---|---|---|
| `!analyze -v`（2026-10-06 0x3B） | `rdx = 0x60` | = `[this+0x68]`(0) + 0x60 ✓ |
| 同上 | `mov rdx,[rdx+8]`，故障地址 `0x68` | = `+0x16`，`0x60+8` ✓ |
| 同上 | `rcx = fffff909991ee880` | = `lea rcx,[rbp-0x20]` 的栈地址 ✓ |
| 符号 | `DXGAUTOPUSHLOCKSHARED::DXGAUTOPUSHLOCKSHARED+0x16` | = RVA `0xca10+0x16 = 0xca26` ✓ |
| 转储基址 `fffff8020b330000` | 崩溃地址 `fffff8020b33ca26` | −基址 = `0xca26` ✓ |

## 附带发现：断言字符串也没兜住

构造函数里有一条断言消息（`+0x6e` `lea rax,[rip+0xa633b]` 引用，行号常量 `1512`）：

```
"bAllowAcquireRecursive || pPushLock == NULL || !m_pPushLock->IsExclusiveOwner()"
```

它检查 `pPushLock == NULL`，而传进来的 `0x60` **不是 NULL**，所以断言同样放行。
`+0x23 cmp rdx,rax` 比较的是 `[0x60+8]` 的值（已经崩了）——断言在崩溃之后才可能触发。

## 建议修法

`VirtualGpuDriverEscape` `+0x1f1` 之后、`+0x1f9` 之前加：

```asm
test rbx, rbx
jz   <skip the DXGAUTOPUSHLOCKSHARED scope>
```

或把 `+0x1f9` 的裸 `lea` 换成显式判空的路径。**`DestroyVirtualGpu` 已有同款检查，
照抄即可。**

**但考虑到这是类级模式（110 个调用点里大量同形），更根本的修法是重新定义
`DXGAUTOPUSHLOCKSHARED` 构造函数的契约**：它既然会解引用那个指针，调用方就不该传「从可能为 NULL
的基指针算出来的成员地址」。要么构造函数容忍，要么调用方判空——两者必须选一个。

## 复现

```powershell
# 站内工具；IDA 打不开 System32 下的原件（要在旁边建数据库，System32 不可写）
# 先拷到可写目录，PDB 放同名文件
node native-lab/tools/decompile.mjs <dxgkrnl.sys 副本> 0x14000ca10
```

自写脚本调 `list_funcs` + `queries:[{filter:'名字片段'}]` 最稳；
`list-funcs.mjs` 的 `count` 上限在 100~500 之间（2000 返回空）。

**本轮全部断言的一键复算**（34 项，exit 0/1）：

```bash
python "<repo>\_re-work\recheck-dxgkrnl-14033.py"
```

**注意**：该脚本只覆盖本文件**已经写下的**断言——它是回归检查，不是独立验证。
独立验证由 verifier 子代理做过一次（见上），结论与 4 处修正都已并入。

## 独立验证（2026-10-13）

由**独立 verifier 子代理**执行，任务是**证伪**而非确认。它从二进制重新推导了每一条指令、
扫了全部 **110 个** `0xca10` 调用点、手工解析了 PDB 的 16,714 条 `S_PUB32` 记录。

**判定：`claim_holds`。** 但它**证伪了 4 条支撑性声明**，全部已在本文件修正：

| # | 被证伪的声明 | 修正 |
|---|---|---|
| 1 | 「生命周期表穷举」 | **漏了 `ResetVirtualFunction+0x1a6`** —— 是第 4 个写入点/第 4 个 NULL 窗口 |
| 2 | 「`[this+0x68]` 是 VmBus 对象」 | **是 `DXGVIRTUALMACHINE*`**（作为 `this` 传给 `RemoveVirtualGpu` / `ResetVirtualGpu`）；`[this+0x60]` 是 `DXGPROCESS*` |
| 3 | 「`DestroyVirtualGpu` 提前返回」 | `+0x27` 跳的是 **field-0x68 teardown 块**（落在 `+0xe3` 的 field-0x60 清理），**不是函数返回** |
| 4 | （未声称但值得记） | 同款模式在 **110 个调用点里大量存在**（63× `[rcx+0x50]+0xf8`、29× `GetVirtualGpuManager()+0x28`）→ 是**类级模式**，反而加强论点 |

**独立复算的关键等式**（verifier 自己推的，不是抄本文件的）：
`[this+0x68] + 0x60 = 0x60` ⟹ `[this+0x68] = 0`，且 `+0x1f1` 与 `+0x1f9` 之间没有任何指令写 `rbx`/`rdx`。

## 未解（不影响结论）

- **四个 NULL 窗口里实际触发的是哪一个** —— 需要运行时状态；转储里该帧内存已回收。
  （缺陷本身是确定性的，这一点不影响。）
- **另外 109 个调用点是否可达** —— 未追查。110 个点里只有 3 个能在 NULL 基址上得出恰好 `0x60`
  （`0x801e6` / `0x22eafd` / `0x3f45dd`），只有 `0x22eafd` 的基址是 NULL 初始化字段，
  且栈帧把调用者钉死在 `VirtualGpuDriverEscape+0x202` —— **归因不受影响，但「其他点不可达」未证明**。
- **无法静态排除**「某个未被找到的写入者清零了该字段」—— 无证据，且转储不需要这种解释。
- **跨厂商/跨构建「逐字相同签名」的断言** —— 单个二进制测不了（依据是社区报告）。
- **`dxgkrnl.pdb` 自身 age 字段不一致**（PDB-info stream age=3 vs RSDS/DBI age=1），
  dbghelp 拒绝加载（`SymFromAddr` err=87）。符号名靠手工 MSF/`S_PUB32` 解析 +
  与反汇编/vtable 的精确 RVA 交叉验证，**地址正确性已建立**，但 age 不一致本身未解释。
- `[[this+0x60]+0x250]` 那个对象的确切类型（`[this+0x60]` 已确认是 `DXGPROCESS*`）。
