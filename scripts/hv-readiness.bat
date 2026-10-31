@echo off

fltmc >nul 2>&1
if %errorLevel%==0 (
    goto is_admin
)

set "ELEVATED=0"
for %%a in (%*) do if "%%~a"=="-elevated" set "ELEVATED=1"

if "%ELEVATED%"=="1" (
    echo Elevation failed. UAC is likely disabled or restricted in Safe Mode.
    pause
    exit /b 1
)

echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k \"\"%~f0\" %* -elevated\"' -Verb RunAs"
exit /b 2

:is_admin
pushd "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0hv-readiness.ps1" %*
popd
