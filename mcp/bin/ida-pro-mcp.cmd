@echo off
REM Headless IDA via idalib (already on this PC). GUI 13337 is optional when IDA is open.
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
cd /d "%~dp0..\..\MCP\ida-pro-mcp"
if exist ".venv\Scripts\idalib-mcp.exe" (
  ".venv\Scripts\idalib-mcp.exe" --stdio
) else (
  "D:\Software\Developer\Python314\Scripts\idalib-mcp.exe" --stdio
)
