@echo off
SETLOCAL EnableDelayedExpansion

pushd "%~dp0.."

echo [*] Hypervisor Launcher Test Suite
echo [*] Finding Visual Studio...

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" (
    echo [!] vswhere.exe not found.
    popd
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -property installationPath`) do set "VS_PATH=%%i"
if "!VS_PATH!"=="" (
    echo [!] Visual Studio installation not found.
    popd
    exit /b 1
)

set "VCVARSALL=!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "!VCVARSALL!" (
    echo [!] vcvarsall.bat not found.
    popd
    exit /b 1
)

echo [*] Initializing MSVC environment (x64)...
call "!VCVARSALL!" x64 >nul
if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: Failed to initialize MSVC environment.
    popd
    exit /b 1
)

set "TEST_OBJ=%TEMP%\hvlauncher_test.obj"
set "TEST_EXE=%TEMP%\hvlauncher_test.exe"

echo [*] Compiling C++ unit tests...
cl /utf-8 /permissive- /EHsc /W4 /WX /std:c++17 /nologo /Fo"!TEST_OBJ!" tests\test_launcher.cpp /link /SUBSYSTEM:CONSOLE /OUT:"!TEST_EXE!"
if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: C++ test compilation failed.
    if exist "!TEST_OBJ!" del /f /q "!TEST_OBJ!"
    if exist "!TEST_EXE!" del /f /q "!TEST_EXE!"
    popd
    exit /b 1
)

echo [*] Executing C++ unit tests...
"!TEST_EXE!"
set "CPP_RC=%ERRORLEVEL%"
if exist "!TEST_OBJ!" del /f /q "!TEST_OBJ!"
if exist "!TEST_EXE!" del /f /q "!TEST_EXE!"
if !CPP_RC! NEQ 0 (
    echo [-] ERROR: C++ unit tests failed ^(exit !CPP_RC!^).
    popd
    exit /b !CPP_RC!
)

echo [*] Executing PowerShell tests...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\test_hv_readiness.ps1
set "PS_RC=%ERRORLEVEL%"
if !PS_RC! NEQ 0 (
    echo [-] ERROR: PowerShell tests failed ^(exit !PS_RC!^).
    popd
    exit /b !PS_RC!
)

echo [+] ALL TESTS PASSED
popd
exit /b 0
