# 2026-10-16 — 宿主 Mac 夜间睡眠：ICMP 通但全 TCP 黑洞；WoL ~1s 唤醒（夜窗先 WoL 再 ssh）

Status: verified（2026-10-16 实测；AwesomeUI W9 波 au9-extensionkit / au9-mac-remainder 两单均按此恢复）

## 事实

1. 宿主 Mac（dwgx-macos，192.168.11.20）夜间会睡眠：`ping` 仍应答，但 ssh/所有 TCP 连接黑洞（超时无响应）——易误判为链路/服务故障。
2. 唤醒：WoL magic packet（目标 MAC `18:3f:70:d6:cc:64` → UDP 广播 `192.168.11.255:9`（或 :7））约 **1 秒** 恢复。
3. 夜窗操作顺序：**先发 WoL → 立刻 ssh**；不要在 TCP 超时上反复重试空耗。
4. 记录落点：AwesomeUI `ui-atlas/macos/deep/inventory/RECON2.md` §9「运维注记」。

## 失效条件

- 与 Mac 电源/节能策略绑定；若 Owner 改节能设置或加 `caffeinate` 常驻，本条作废。
