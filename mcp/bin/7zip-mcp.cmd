@echo off
set "PYTHONIOENCODING=utf-8"
set "PATH=%~dp0..\..\Unpackers-Game\7-Zip-full;%PATH%"
cd /d "%~dp0..\..\MCP\mcp7zop"
".venv\Scripts\python.exe" -m mcp7zop --mcp-server
