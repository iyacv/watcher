@echo off
title NYK-FIL NYKfilF5Log360Watcher - Setup
echo ============================================
echo  NYK-FIL Maritime E Training Inc.
echo  Security Monitoring System - Setup
echo ============================================
echo.

:: ── Check Python ─────────────────────────────────────────────────────────────
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.10 or later from https://www.python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
echo       Python found.
echo.

:: ── Install dependencies ──────────────────────────────────────────────────────
echo [2/5] Installing required packages...
pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo ERROR: Failed to install packages. Check your internet connection.
    pause
    exit /b 1
)
echo       Packages installed.
echo.

:: ── Create folders ────────────────────────────────────────────────────────────
echo [3/5] Creating inbox, processed, and failed folders...
if not exist "%~dp0inbox"     mkdir "%~dp0inbox"
if not exist "%~dp0processed" mkdir "%~dp0processed"
if not exist "%~dp0failed"    mkdir "%~dp0failed"
echo       Folders ready.
echo.

:: ── Create .env if missing ────────────────────────────────────────────────────
echo [4/5] Checking environment config...
if not exist "%~dp0.env" (
    echo DB_HOST=localhost> "%~dp0.env"
    echo DB_PORT=3306>> "%~dp0.env"
    echo DB_NAME=capstone_security>> "%~dp0.env"
    echo DB_USER=root>> "%~dp0.env"
    echo DB_PASSWORD=>> "%~dp0.env"
    echo.
    echo       .env file created.
    echo       IMPORTANT: Open .env and fill in your MySQL password before continuing.
    echo       Press any key after you have updated the .env file...
    pause >nul
) else (
    echo       .env already exists.
)
echo.

:: ── Register Task Scheduler ───────────────────────────────────────────────────
echo [5/5] Registering auto-start task in Windows Task Scheduler...

:: Find pythonw.exe path
for /f "delims=" %%i in ('where pythonw 2^>nul') do set PYTHONW=%%i

if "%PYTHONW%"=="" (
    set PYTHONW=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python314\pythonw.exe
)

:: Delete existing task if present
schtasks /delete /tn "NYKFilWatcherforF5Log360" /f >nul 2>&1

:: Create the task
schtasks /create ^
  /tn "NYKFilWatcherforF5Log360" ^
  /tr "\"%PYTHONW%\" \"%~dp0watcher.py\"" ^
  /sc onstart ^
  /ru "%USERNAME%" ^
  /rl highest ^
  /f >nul

if %errorlevel% neq 0 (
    echo ERROR: Could not register Task Scheduler task.
    echo Please run this script as Administrator.
    pause
    exit /b 1
)
echo       Auto-start task registered.
echo.

:: ── Start the watcher now ─────────────────────────────────────────────────────
echo Starting the watcher now...
schtasks /run /tn "NYKFilWatcherforF5Log360" >nul
echo.
echo ============================================
echo  Setup complete.
echo.
echo  The NYK-FIL F5 Log360 watcher is now running in the background.
echo  It will start automatically every time this
echo  computer is turned on 
echo.
echo  Drop F5 or Log360 export files into:
echo  %~dp0inbox\
echo.
echo  Open Grafana at: http://localhost:3000
echo ============================================
echo.
pause
