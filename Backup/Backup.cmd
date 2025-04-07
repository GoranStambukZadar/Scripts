@echo off
setlocal enabledelayedexpansion

:: Check if F: drive exists
if not exist "F:\" (
    echo F: drive not found. Please connect it or check the drive letter.
    pause
    exit /b
)

:: Create media folder if it doesn't exist
if not exist "F:\media" (
    mkdir "F:\media"
    if errorlevel 1 (
        echo Failed to create F:\media
        pause
        exit /b
    )
)

:: Log file to track copied files
set "LOGFILE=F:\media\copied_files.txt"
if not exist "%LOGFILE%" type nul > "%LOGFILE%"

:: Main loop
:loop
for %%F in (jpg mp4 3gp mov gif) do (
    for /r "%USERPROFILE%" %%A in (*%%F) do (
        findstr /x /c:"%%~fA" "%LOGFILE%" >nul
        if errorlevel 1 (
            echo Copying: %%~fA
            copy /y "%%~fA" "F:\media\" >nul
            echo %%~fA>>"%LOGFILE%"
        )
    )
)

:: Wait before scanning again
timeout /t 10 >nul
goto loop
