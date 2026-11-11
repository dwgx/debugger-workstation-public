# OWNER: researcher-q4 | setukou-20261111/v5/slices/q4-wrappers/receipt_tools/find_targets.py
"""Q4 LOCAL-CHECK-3: bounded, READ-ONLY presence probe for wrapper-referenced targets.

Runs under `timeout.exe 30`. For each of the 23 wrappers, resolve the concrete
jar/exe/script path it launches (when determinable from the .cmd text) and report
whether that path exists ON THIS BOX. A path existing is static evidence only —
it does NOT prove the backend process starts or that an MCP session connects.
No wrapper, java, exe, node, npx, r2pm, or python module is ever executed.
"""
from __future__ import annotations
import pathlib
import sys

ROOT = pathlib.Path("D:/Software/Tool/WorkStation/debugger")
BIN = ROOT / "mcp" / "bin"

# (wrapper, target relative to debugger/, or None when the launcher is a
#  runtime-resolved PATH command / npx / r2pm with no static path to probe)
TARGETS: dict[str, str | None] = {
    "7zip-mcp.cmd": "MCP/mcp7zop/.venv/Scripts/python.exe",
    "apktool-mcp.cmd": "MCP/apktool-mcp-server/.venv/Scripts/python.exe",
    "apktool.cmd": "Mobile-Android/Apktool/apktool.jar",
    "cheatengine-mcp.cmd": "MCP/cheatengine-mcp-bridge/MCP_Server/.venv/Scripts/python.exe",
    "debugger-router-mcp.cmd": "MCP/debugger-router/server.py",
    "dnspy-mcp.cmd": "MCP/dnspy-mcp/publish/win-x64/DnSpyMcpServer.exe",
    "frida-mcp.cmd": "MCP/frida-mcp/.venv/Scripts/frida-mcp.exe",
    "ghidra-mcp.cmd": "MCP/GhidraMCP/.venv/Scripts/python.exe",
    "ida-pro-mcp.cmd": "MCP/ida-pro-mcp/.venv/Scripts/idalib-mcp.exe",
    "ilspy-mcp.cmd": "MCP/ILSpy-Mcp/publish/ILSpy.Mcp.exe",
    "imhex-mcp.cmd": "MCP/imhexMCP/mcp-server/.venv/Scripts/python.exe",
    "jadx-mcp.cmd": "MCP/jadx-mcp-server/.venv/Scripts/python.exe",
    "mobsf-mcp.cmd": "MCP/mobsf-mcp-server/node_modules/.bin/tsx.cmd",
    "radare2-mcp.cmd": "Static-Reversing/radare2/radare2-6.2.2-w64/bin/r2pm.exe",
    "rea-mcp.cmd": None,  # `where rea` / npx -y  -> PATH-resolved, no static path
    "reclass-mcp.cmd": "MCP/ReClass.NET-MCP/ReClassMCP.Server/.venv/Scripts/python.exe",
    "reqable-mcp-local.cmd": "MCP/reqable-mcp/.venv/Scripts/python.exe",
    "virustotal-mcp.cmd": "MCP/mcp-virustotal/build/index.js",
    "volatility3-mcp.cmd": "MCP/volatility3-mcp/.venv/Scripts/python.exe",
    "wireshark-mcp.cmd": "MCP/mcp-wireshark/.venv/Scripts/mcp-wireshark.exe",
    "x64dbg-mcp.cmd": "MCP/x64dbg-automate-pyclient/.venv/Scripts/x64dbg-automate-mcp.exe",
    "yaraflux-http.cmd": "MCP/YaraFlux/.venv/Scripts/yaraflux-mcp-server.exe",
    "yaraflux-mcp.cmd": "MCP/YaraFlux/.venv/Scripts/python.exe",
}

wrappers = sorted((p for p in BIN.glob("*.cmd") if p.is_file()), key=lambda p: p.name)
print(f"root={ROOT}")
print(f"wrappers_seen={len(wrappers)}")
present = absent = unprobeable = 0
for p in wrappers:
    rel = TARGETS.get(p.name, "__MISSING_FROM_MAP__")
    if rel is None:
        unprobeable += 1
        print(f"target|{p.name}|PATH_RESOLVED|exists=UNKNOWN|launcher=where/npx (no static path)")
    elif rel == "__MISSING_FROM_MAP__":
        unprobeable += 1
        print(f"target|{p.name}|NO_MAP|exists=UNKNOWN")
    else:
        t = ROOT / rel
        ex = t.exists()
        present += 1 if ex else 0
        absent += 0 if ex else 1
        print(f"target|{p.name}|{rel}|exists={ex}")
print(f"static_path_present={present} static_path_absent={absent} unprobeable={unprobeable}")
print("NOTE: path existence = static evidence only; backend_usable UNVERIFIED (no session run)")
sys.exit(0)
