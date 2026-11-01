# verify-all 2026-10-14（omp 线：桌面应用拆包工序前站健康检查）

- 触发：Owner 指示对两应用（Codex Desktop / Claude Desktop，MSIX+Electron）做拆包与前端机制蒸馏；按 debugger-workstation skill 先跑站健康检查。
- 结果：VERIFY-ALL wall clock 42:02。probes 24/25 跑了：21 OK + 3 SKIP（均为文档化状态：dynamic.device.frida 无设备 / native.il2cpp.symbols 无工件 / native.ghidra.emulate 上游 API blocked）。
- 唯一 FAILED 项 = `assert-probes (bounded, completeness required)`：**预算耗尽把 `mobile.apk.static` 整个 defer**（非能力失败；脚本自己写「REFUSING TO PASS … NEVER MEASURED」）。
- 处置：按脚本提示按 id 重跑 `python scripts/assert-probes.py mobile.apk.static --save-evidence evidence/probes` → **OK，10.72s**（产出 `mobile-lab/out/last-run-mobile-lab.json`，sha256 已入 evidence 日志）。
- 结论：站健康，无待修项。下次全量 verify-all 若要避免该 FAILED：提高 `--budget` 或接受「deferral=FAILED」语义并按 id 补跑。
- 旁证（同轮应用工序用到/没用到的）：codegraph 1.6.0 CLI（`~/.local/bin/codegraph-mcp.cmd` 指向的 `codegraph.cmd`）本工序大量使用（94+ 仓索引）；应用拆包用 `npx @electron/asar` + 自带 python 探针，未用站内二进制；7z/x64dbg/System Informer 未动用。
