@echo off
setlocal

:: Find VS installation
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere not found. Install Visual Studio 2022+.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
    echo ERROR: No Visual Studio installation found.
    exit /b 1
)

call "%VSDIR%\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1

if /i "%~1"=="clean" (
    echo Cleaning RemoraHook...
    msbuild RemoraHook.sln /t:Clean /p:Configuration=Debug /p:Platform=x64 /verbosity:minimal >nul 2>&1
    msbuild RemoraHook.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /verbosity:minimal >nul 2>&1
    if exist "bin\Debug" rmdir /s /q "bin\Debug"
    if exist "bin\Release" rmdir /s /q "bin\Release"
    echo Clean complete.
    exit /b 0
)

set "CONFIG=Debug"
if /i "%~1"=="release" set "CONFIG=Release"

echo Building RemoraHook solution (%CONFIG%)...
msbuild RemoraHook.sln /p:Configuration=%CONFIG% /p:Platform=x64 /verbosity:minimal

if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCEEDED
echo Output: bin\%CONFIG%\remora_hook.exe
echo         bin\%CONFIG%\hookdll.dll
