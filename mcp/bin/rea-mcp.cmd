@echo off
REM REA (morluto/rea) — "Reverse Engineer Anything" MCP backend.
REM Upstream: https://github.com/morluto/rea · npm package: rea-agents (pinned 6.4.0, 2026-10-12).
REM Install: npm install --global rea-agents@6.4.0   (Node 22.19+/24.11+ required; this box: v24.21.0)
REM Starts REA's local MCP server on stdio. Falls back to npx if the global shim is absent.
set "PYTHONIOENCODING=utf-8"
where rea >nul 2>nul
if %errorlevel%==0 (
  rea mcp
) else (
  npx -y rea-agents@6.4.0 mcp
)
