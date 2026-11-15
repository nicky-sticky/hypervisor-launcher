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
if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: Failed to initialize MSVC environment.
    exit /b 1
)

:: Create output directory
if not exist "release" mkdir "release"

echo [*] Compiling Resources...
rc /fo source\resource.res source\resource.rc >nul
if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: Resource compilation failed.
    exit /b 1
)

echo [*] Compiling Launcher...
cl /utf-8 /permissive- /EHsc /O2 /W4 /std:c++17 /guard:cf /nologo source\launcher.cpp source\resource.res /link /SUBSYSTEM:CONSOLE Advapi32.lib Shell32.lib /OUT:release\hvlauncher.exe

if %ERRORLEVEL% NEQ 0 (
    echo [-] ERROR: Build failed.
    exit /b 1
)

:: Clean up build artifacts
if exist source\resource.res del source\resource.res
if exist launcher.obj del launcher.obj

:: Copy source tools (excluding archives)
if not exist "release\tools" mkdir "release\tools"
if exist "release\tools\kvc.7z" del /q "release\tools\kvc.7z"
if exist "source\tools" (
    for %%F in ("source\tools\*") do (
        if /i not "%%~xF"==".7z" (
            copy /y "%%~F" "release\tools\" >nul
            if !ERRORLEVEL! NEQ 0 (
                echo [-] ERROR: Failed to copy tool %%~nxF
                exit /b 1
            )
        )
    )
)

:: Copy hvlauncher.ini template
if exist "source\hvlauncher.ini" (
    copy /y "source\hvlauncher.ini" "release\hvlauncher.ini" >nul
    if %ERRORLEVEL% NEQ 0 (
        echo [-] ERROR: Failed to copy hvlauncher.ini
        exit /b 1
    )
)

:: Copy standard hypervisor drivers (single source of truth)
for %%D in (driver_amd driver_intel) do (
    if exist "source\%%D" (
        if not exist "release\%%D" mkdir "release\%%D"
        copy /y "source\%%D\*" "release\%%D\" >nul
        if !ERRORLEVEL! NEQ 0 (
            echo [-] ERROR: Failed to copy %%D files
            exit /b 1
        )
    )
)

echo [+] SUCCESS: Build and Packaging Complete!
echo [+] Binary located at: release\hvlauncher.exe
exit /b 0
