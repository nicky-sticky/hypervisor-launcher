@echo off
SETLOCAL EnableDelayedExpansion

:: Path Normalization
pushd "%~dp0"
set "PROJECT_ROOT=%CD%"
popd

echo [*] Hypervisor Launcher Build System
echo [*] Finding Visual Studio...

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" (
    echo [!] vswhere.exe not found.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -property installationPath`) do set "VS_PATH=%%i"
if "!VS_PATH!"=="" (
    echo [!] Visual Studio installation not found.
    exit /b 1
)

set "VCVARSALL=!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "!VCVARSALL!" (
    echo [!] vcvarsall.bat not found.
    exit /b 1
)

echo [*] Initializing MSVC environment (x64)...
call "!VCVARSALL!" x64 >nul

:: Create output directory
if not exist "release" mkdir "release"

echo [*] Compiling Resources...
rc /fo source\resource.res source\resource.rc >nul

echo [*] Compiling Launcher...
cl /EHsc /O2 /W4 /std:c++17 /nologo source\launcher.cpp source\resource.res /link /SUBSYSTEM:CONSOLE Advapi32.lib Shell32.lib /OUT:release\hvlauncher.exe

if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: Build failed.
    exit /b 1
)

:: Clean up build artifacts
if exist source\resource.res del source\resource.res
if exist launcher.obj del launcher.obj

:: Copy source tools
if not exist "release\tools" mkdir "release\tools"
if exist "source\tools" (
    copy /y "source\tools\*" "release\tools\" >nul
)

:: Copy hvlauncher.ini template
if exist "source\hvlauncher.ini" (
    copy /y "source\hvlauncher.ini" "release\hvlauncher.ini" >nul
)

:: Copy standard hypervisor drivers (single source of truth)
for %%D in (driver_amd driver_intel) do (
    if exist "source\%%D" (
        if not exist "release\%%D" mkdir "release\%%D"
        copy /y "source\%%D\*" "release\%%D\" >nul
    )
)

echo [+] SUCCESS: Build and Packaging Complete!
echo [+] Binary located at: release\hvlauncher.exe
exit /b 0
