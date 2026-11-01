# EAC 206 patch feasibility — durable facts (2026-10-17)

status: observed

- **Driver 3.2.0**: `<project>/Romantic/work/l184/guest-out/service-eos/EasyAntiCheat_EOS.sys`, 44,478,104 B, sha256 `3845b1ea31adcd9667dff556eaac50fa837aa46870a9d4963a181ab5b02a9e19`.
- **Module (decoded `.eac`)**: `<project>/Romantic/work/l191/decoded-cdn-module.dll`, 33,507,768 B, sha256 `565b88d7ac14319fa61017281b9e5b786d7e7e82bdcede05be7291a536199a27`.
- **Bootstrapper 1.9.4**: `D:\Steam\...\start_protected_game.exe`, 3,993,896 B, sha256 `46d2552552ac95c436389a2c9f1aba6fda37ab998acf9b9ee026f3262dd70c53`.
- **206 chain**: driver `0x14179781d` `41 c7 00 16 00 00 00` (`mov dword [r8],0x16`, `r8=[r12+0x178]`); module predicate `0x15122 cmp [resp],0` / `je 0x15252`; dispatcher `0x7d990 cmp ebp,0x16` → `0x7d999` → `error_virtual`.
- **Patch points**: module P1 `0x15124` 1 B `00→16`; P2 `0x15130` 2 B `8B 00→31 C0`; P3 `0x7d999` 10 B `31 ED E9 A3 15 00 00`; bootstrapper P1 `0x14003136b` 12 B.
- **Response crypto**: XXTEA n=142 (568 B), q=6, Δ=`0x9e3779b9`; key = `{lo32(bufVA)^0x5a621d44, hi32(bufVA)^0x836a8e36, PID^0x8313a412, 0x844ecdf6}`; no IV/MAC.
- **(d2′) baseline**: user-mode zero-write at `0x1511d`; P1 3/3 + P2 2/2; 30 min; cross-boot 2/2.
- **SBX IP trap**: `sbx.ps1 ip` returned stale `172.22.99.55`; live IP via elevated `Get-VMNetworkAdapter -VMName DWGXSBWIN` = `172.27.98.96` (2026-10-17). Always read the IP from Hyper-V.
- **EAC service as-found**: STOPPED before game launch (2026-10-17).
- **Feasibility verdicts**: T1 proven; T3 feasible (not live); T2 conditional; T4 undetermined/high-risk; T7/T8/T9 infeasible; T10 unknown.

## Step 2b result (2026-10-17, verified in guest)

- Checkpoint `PATCHVM-pre-20261017` (Standard, with memory); as-found: EAC service STOPPED (1077), no EOSSys, no target process.
- P0 same-value write → still 206 (write channel clean).
- **P3 = `module+0x7d999` 7 B (`31 ED E9 A3 15 00 00`) applied at `module_init_call`: 3/3 `success_continuation ebp=0`, `VRChat.exe` 3/3, launcher 21 lines ending 200, no 206 / no new rejection.**
- Long run 43m55s: launcher/EAC service/EOSSys/VRChat present; no Error/Critical; no CodeIntegrity 3033/3077; no stop lines.
- Harness defect: `t60` census RPC hang (auto closeout skipped; manual sample at 43m55s).
- VM kept as-found + checkpoint (not rolled back).
- Report: `research/eac206-patch-2026-10-17/18-step2-result.md`.

