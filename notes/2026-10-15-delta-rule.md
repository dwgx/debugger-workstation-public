# delta-rule：ls.bin pclntab 字段「Δ」规则求解（车道 DELTA-RULE）

日期：2026-10-15 · 状态：verified · board：DELTA-RULE
对象：`Reports/private/windsurf-re-20261015/derived/ls-candidate/ls.bin`（178,093,056 B，Go 1.26.6 PE32+；未执行，仅静态解析）
交付：`_re-work/delta-rule-20261015/delta_solve.py`（零依赖 / 只读 / 有界）

## 结论一句话

**真值含 0xE8/0xE9（x86 CALL/JMP 操作码）→ `j = 首个命中字节位置 + 1`，存值 = 真值 + `((field_end+j) << 8j)`（mod 2³²）；否则走 b2op：`字节0 += (field_end>>16)&0xFF`，且真字节0 ≥ 0x80 时 `字节1 ^= 0xFF`（字节2、3 不动）。**

## 规则全文（两个族）

设字段起点 S、字段末 `E = S+4`、`b2 = (E>>16)&0xFF`、真值 V。

- **fam 族**（V 含 0xE8/0xE9）：k = V 里第一个 ∈{0xE8,0xE9} 的字节位（0..3），`j = k+1`；
  `stored = (V + ((E + j) << 8j)) mod 2³²`。
  物理含义：X = S+k 处的字节被当作 x86 `CALL`(0xE8)/`JMP`(0xE9)，`X+5` = 下一条指令偏移，该偏移左移 j 字节后加回字段。
  仅 0xE8/0xE9 触发（0xEA、0xE0–0xE7 已用「更早出现的干扰字节」对照，均不触发）。
- **b2op 族**（V 不含 0xE8/0xE9）：
  `stored_b0 = (V_b0 + b2) mod 256`；`stored_b1 = V_b1 ^ 0xFF`（若 V_b0 ≥ 0x80，否则 V_b1）；`stored_b2/b3 = V_b2/b3`。
- **触发配对（pair）**：X 处触发字节除改写本字段（fam）外，还会以 b2op 改写**下一个 4 字节字段**（操作数窗口 X+1..X+4 的后半）：
  - j=2 实测 561 例：e2→noff 9/9、e→f 4/4、pcln→npcdata 548/548（npcdata 548 另有 size 链独立复核）；
  - j=1 触发**无** B 侧改写（pcln-j1 6/6、startLine-j1 抽样 5/5 均无）。

## 求解路径（121,645 → 121,658）

1. 基线（工具包 P/RETOOL）：121,645/121,658，13 例未解析。
2. 13 例逐字段拆解发现第二族 b2op：其 noff 的模型逆在 funcnametab 解出合法名字（如 55657 → `…ServerStreamForClient[…].ResponseHeader`）。
3. b2op 逆解出 9 例；另 4 例（77416、104080–82）noff 本无损坏，坏在 e/f——f 走 b2op 逆、e 走 fam2 逆后按 size 链定位记录，名字照常解出。
4. 全量扫描（`scan29.py`）：121,658 条 × 全部字段做「clean / fam1..3 / b2op 逆 + 前向验证（真值首 0xE8/0xE9 位 == j-1 且前向模型 == 存值）」，得完整分类。

## 计数（`scan29.py` 实测，2026-10-15）

| 字段 | clean | fam1 | fam2 | fam3 | b2op | 备注 |
|---|---|---|---|---|---|---|
| e2（_func +0） | 121,649 | 0 | 9 | 0 | 0 | 9 例即 13 例中的 9 例；`e2==e` 交叉验证 0 失败 |
| e（functab entryoff） | 121,652 | 0 | 4 | 0 | 2 | fam2 4 例 = 77416/104080–82；b2op 2 例 = 7610/7611（其 b2=0xBB，即工具包「+0xBB 特例」） |
| f（functab funcoff） | 121,186 | 468 | 0 | 0 | 4 | 468 = 466×j1 + 2×j2，与工具包 funcoff=468 对齐；b2op 4 例 = 77416/104080–82 |
| noff（_func +4） | 119,754 | 35 | 938 | 922 | 9 | fam 合计 1,895，与工具包 nameoff=1,895 对齐 |
| npcdata（+28） | 121,110 | — | — | — | 548 | 由 size 链独立复核（b2op 族） |
| pcsp / pcfile / pcln | 121,642 / 121,651 / 121,104 | 13 / 5 / 6 | 3 / 2 / 548 | 0 / 0 / 0 | 0 | pcln fam2 548 = npcdata b2op 548 的来源 |
| startLine（+36） | 121,240 | 418 | 0 | 0 | 0 | 全 j=1 |
| args（+8） | 121,642 | 16 | 0 | 0 | 0 | 全 j=1 |
| cuOffset（+32） | 121,656 | 2 | 0 | 0 | 0 | |
| deferreturn（+12） | 121,658 | 0 | 0 | 0 | 0 | 全净（b2op 落在此处不可检出，见下） |
| funcdata 数组 | 1,322,994 | 1,050 | 483 | 0 | 355 | b2op 仅「值可检出」部分（0xFFFFFFFF 哨兵等） |
| **fam 触发合计** | — | **1,545** | **1,987** | **922** | — | _func 内 4,454 + functab f 468 = **4,922** |

- 名字解析：**121,658/121,658（0 未解析）**。
- 结构校验：size 链 121,658 条全走通；每条记录 `f` 与模型逆一致（0 失败）；`e2==e`（候选交集）0 失败。
- 与工具包计数全对齐：funcoff 468 ✓、nameoff 1,895 ✓、entryoff 11 = e2-fam 9 + e-b2op 2 ✓（工具包 13 例未解析 = 本车道 13 边界例）。

## 13 个边界例分类表（全部解出）

| idx | F | e2 | e | f | noff | 名字 |
|---|---|---|---|---|---|---|
| 8910 | 0x5d57780 | fam2 | clean | clean | b2op | net/http.(*http2clientConnReadLoop).endStream |
| 42792 | 0x6033fe0 | fam2 | clean | clean | b2op | connectrpc.com/connect.(*BidiStreamForClient[…]).ResponseTrailer |
| 55657 | 0x6149e20 | fam2 | clean | clean | b2op | connectrpc.com/connect.(*ServerStreamForClient[…]).ResponseHeader |
| 55658 | 0x6149e78 | fam2 | clean | clean | b2op | 同上 .Err |
| 55659 | 0x6149ed0 | fam2 | clean | clean | b2op | 同上 .Msg |
| 55660 | 0x6149f28 | fam2 | clean | clean | b2op | 同上 .Receive |
| 71097 | 0x6295e48 | fam2 | clean | clean | b2op | golang.org/x/image/vp8l.(*hTree).build |
| 77416 | 0x631cfa0 | clean | fam2 | b2op | clean | google.golang.org/protobuf/types/dynamicpb.(*Message).Range |
| 85867 | 0x63d33b0 | fam2 | clean | clean | b2op | github.com/bufbuild/protovalidate-go/cel.library.CompileOptions.func11 |
| 85868 | 0x63d3410 | fam2 | clean | clean | b2op | 同上 func12 |
| 104080 | 0x655d078 | clean | fam2 | b2op | clean | connectrpc.com/connect.(*Client[…]).CallServerStream.func1 |
| 104081 | 0x655d0d0 | clean | fam2 | b2op | clean | 同上 .CallClientStream |
| 104082 | 0x655d128 | clean | fam2 | b2op | clean | 同上 .CallUnary |

（4 例「clean noff」说明其 noff 从未损坏：工具包未解它们是因为 f 候选被 `%8` 过滤拒掉、记录定位不到。）

## 复现命令（debugger 仓库根执行）

```
python _re-work/delta-rule-20261015/delta_solve.py            # → names resolved: 121658/121658
python _re-work/delta-rule-20261015/delta_solve.py --explain  # 规则 + 各族命中统计 + 修复清单
python _re-work/delta-rule-20261015/scan29.py                 # 全字段分类计数
```

## 已知边界 / 未解部分（诚实清单）

- **触发选择子集未全解**：落在记录内的 0xE8/0xE9 字节共 15,064 个，仅 4,922 个真的触发（≈33%）。已验证「触发集 ⊆ 贪心不重叠 5 字节步进扫描集」（12,715 个含触发字节的记录全过），但步进的 skip 细节未复原——工具大概率是线性 x86 解码/重定位扫描，具体状态机未定位（ls.bin 内未见其代码）。
- **小值字段的 b2op 不可检出**：b2op 落在小值字段（如 fd2 真值≈0）时存值仍「像干净」，只能由 pair 规则推断（j≥2 成立处）；对名字解析与 size 链无影响。
- **23 个值歧义字段**（e2 14、fd 9）：存值与某个 fam 逆同时可信；e2 的 14 例由 `e2==e` 全部判为 clean；fd 9 例无独立判据（不影响交付）。
- **未用字符串对账**：funcnametab 143,797 条串中 121,658 条被引用（全部不同 noff）；未用 22,139 = 上一车道口径 22,152 − 13，与本车道恰好多解出的 13 例严格对账一致。未用串中 12,964 条形似限定函数名（疑似 Go 链接器为裁剪函数/泛型实例保留），未逐条追查；37 个名字被 2 条目共用（ABI 包装器，正常）。
- 未执行 ls.bin；未改工具包；未碰 `derived/ls-candidate/`。
