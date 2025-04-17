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

:: Log files
set "LOGFILE=F:\media\robocopy_log.txt"
set "ERRORLOG=F:\media\error_log.txt"

:: Main loop
:loop
:: Clear error log for this iteration
if exist "%ERRORLOG%" del "%ERRORLOG%"

:: Use robocopy to copy files by extension
for %%F in (jpg mp4 3gp mov gif) do (
    robocopy "%USERPROFILE%" "F:\media" "*.%%F" /s /r:1 /w:1 /njh /njs /ndl /nc /ns /np /log+:"%LOGFILE%" /tee
    if !errorlevel! geq 8 (
        echo Failed to copy some %%F files. Check %LOGFILE% for details.>>"%ERRORLOG%"
    )
)

:: Check if F: drive is still available
if not exist "F:\" (
    echo F: drive disconnected. Stopping script.
    pause
    exit /b
)

:: Wait before scanning again
timeout /t 30 >nul
goto loop