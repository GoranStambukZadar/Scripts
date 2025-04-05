@echo off
Title GPerf && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Prep environment 
cd /d %~dp0
cd Bin
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Execute PowerShell (.ps1) files alphabetically
for /f "tokens=*" %%P in ('dir /b /o:n *.ps1') do (
    powershell -ExecutionPolicy Bypass -File "%%P"
)

:: Step 4: Execute Registry (.reg) files alphabetically
for /f "tokens=*" %%R in ('dir /b /o:n *.reg') do (
    reg import "%%R"
)

:: Step 5: Execute CMD (.cmd) files alphabetically
for /f "tokens=*" %%C in ('dir /b /o:n *.cmd') do (
    call "%%C"
)
