@echo off
REM radare2 official MCP (r2mcp). Start via r2pm, do not run r2mcp.exe directly.
set "PYTHONIOENCODING=utf-8"
set "PATH=%~dp0..\..\Static-Reversing\radare2\radare2-6.2.2-w64\bin;%PATH%"
r2pm -r r2mcp
