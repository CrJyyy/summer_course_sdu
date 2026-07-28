@echo off
setlocal

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "CLANG=C:\Program Files\LLVM\bin\clang.exe"
set "ASAN_DIR=C:\Program Files\LLVM\lib\clang\22\lib\windows"

if not exist "%VCVARS%" (
  echo FAIL: Visual Studio vcvars64.bat not found 1>&2
  exit /b 2
)
if not exist "%CLANG%" (
  echo FAIL: official LLVM clang.exe not found 1>&2
  exit /b 2
)

call "%VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%

cd /d "%ROOT%"
if not exist build\sanitize mkdir build\sanitize
if not exist build\tmp mkdir build\tmp
set "TMP=%ROOT%\build\tmp"
set "TEMP=%ROOT%\build\tmp"

set "SOURCES=src\util.c src\aes.c src\sm4.c src\sm4_aes_assist.c src\gift64.c src\twine.c src\dispatch.c src\modes.c src\arm64\aes_arm64.c src\arm64\shuffle_arm64.c src\arm64\ghash_pmull.c src\x86\gfni_model.c src\x86\sm4_gfni_x86.c src\x86\ghash_pclmul.c src\x86\shuffle_x86.c src\x86\aes_vaes.c src\arm64\sm4_hw_arm64.c src\x86\sm4_hw_x86.c"

if "%~1"=="generic" (
  set "TEST=tests\test_symcrypto.c"
  set "OUTPUT=build\sanitize\test_symcrypto_msvc.exe"
) else if "%~1"=="x86" (
  set "TEST=tests\test_x86_backends.c"
  set "OUTPUT=build\sanitize\test_x86_backends_msvc.exe"
) else (
  echo usage: sanitize_windows.cmd generic^|x86 1>&2
  exit /b 2
)

"%CLANG%" -Iinclude -D_CRT_SECURE_NO_WARNINGS -std=c11 -O1 -g ^
  -Wall -Wextra -Wpedantic -Werror ^
  -fsanitize=address,undefined -fno-omit-frame-pointer ^
  %SOURCES% %TEST% -o "%OUTPUT%"
if errorlevel 1 exit /b %errorlevel%

set "PATH=%ASAN_DIR%;C:\Program Files\LLVM\bin;%PATH%"
set "ASAN_OPTIONS=detect_leaks=0"
"%OUTPUT%"
exit /b %errorlevel%
