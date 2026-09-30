@echo off
REM Builds the self-authored lab payload PE with MSVC. /Brepro makes the output
REM byte-reproducible, which is what lets the image be deterministic.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
cl /nologo /LD /O1 /Brepro d12payload.c /link /OUT:d12payload.dll
exit /b %ERRORLEVEL%
