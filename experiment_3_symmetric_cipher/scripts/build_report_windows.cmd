@echo off
setlocal

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "MSYS_BASH=C:\msys64\usr\bin\bash.exe"
set "MIKTEX_BIN=%LOCALAPPDATA%\Programs\MiKTeX\miktex\bin\x64"
set "MIKTEX_USERINSTALL=%LOCALAPPDATA%\Programs\MiKTeX"
set "MIKTEX_USERCONFIG=%APPDATA%\MiKTeX"
set "MIKTEX_USERDATA=%LOCALAPPDATA%\MiKTeX"
set "MIKTEX_USERSTARTUPFILE=%APPDATA%\MiKTeX\miktex\config\miktexstartup.ini"

if not exist "%MSYS_BASH%" (
  echo FAIL: MSYS2 bash not found
  exit /b 2
)
if not exist "%MIKTEX_BIN%\xelatex.exe" (
  echo FAIL: MiKTeX XeLaTeX not found
  exit /b 2
)

if not exist "%ROOT%\build" mkdir "%ROOT%\build"
if not exist "%ROOT%\build\tmp" mkdir "%ROOT%\build\tmp"
del /q "%ROOT%\build\report-build.status" 2>nul

"%MSYS_BASH%" -lc "root=$(cygpath -u \"$ROOT\"); miktex=$(cygpath -u \"$MIKTEX_BIN\"); export PATH=\"$miktex:/ucrt64/bin:/usr/bin:$PATH\"; export TMPDIR=\"$root/build/tmp\"; export TMP=\"$TMPDIR\"; export TEMP=\"$TMPDIR\"; cd \"$root\"; make report" > "%ROOT%\build\report-build.log" 2>&1
set "RESULT=%ERRORLEVEL%"
(echo %RESULT%)> "%ROOT%\build\report-build.status"
exit /b %RESULT%
