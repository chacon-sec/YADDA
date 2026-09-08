@echo off
rem build.cmd — build the napi addon with MSVC (x64). Run from the repo root:  native\build.cmd
setlocal
if not defined VSCMD_VER call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul


rem headers: native\include\node (fetched from nodejs.org headers tarball;
rem the Windows MSI doesn't ship them). Falls back to a system Node install.
if exist "%~dp0include\node\node_api.h" (set NAPI_INC=%~dp0include\node) else (set NAPI_INC=C:\Program Files\nodejs\include\node)

rem host-portable build: NO node.lib (runtime-resolved napi — see coffloader.c
rem header), STATIC CRT (/MT) so we never bind the host's bundled VC runtime DLLs.
rem Result: one .node for node.exe AND any Electron host (slack.exe, ...).
cl /nologo /O2 /W3 /LD /MT /D_CRT_SECURE_NO_WARNINGS ^
   /I "%NAPI_INC%" ^
   native\coffloader.c ^
   /Fe:native\coffloader.node ^
   /link advapi32.lib /EXPORT:napi_register_module_v1
if errorlevel 1 (echo ADDON BUILD FAILED & exit /b 1)
echo OK: native\coffloader.node
