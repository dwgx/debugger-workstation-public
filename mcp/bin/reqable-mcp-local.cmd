@echo off
set "PYTHONIOENCODING=utf-8"
if not defined REQABLE_DATA_DIR set "REQABLE_DATA_DIR=%~dp0..\..\MCP\workspaces\reqable"
cd /d "%~dp0..\..\MCP\reqable-mcp"
".venv\Scripts\python.exe" -m reqable_mcp
