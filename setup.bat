@echo off
title NYK-FIL NYKfilF5Log360Watcher - Setup
echo ============================================
echo  NYK-FIL Maritime E Training Inc.
echo  Security Monitoring System - Setup
echo ============================================
echo.

:: ── Check Python ─────────────────────────────────────────────────────────────
echo [1/6] Checking Python installation...
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
echo [2/6] Installing required packages...
pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo ERROR: Failed to install packages. Check your internet connection.
    pause
    exit /b 1
)
echo       Packages installed.
echo.

:: ── Create folders ────────────────────────────────────────────────────────────
echo [3/6] Creating inbox, processed, and failed folders...
if not exist "%~dp0inbox"     mkdir "%~dp0inbox"
if not exist "%~dp0processed" mkdir "%~dp0processed"
if not exist "%~dp0failed"    mkdir "%~dp0failed"
echo       Folders ready.
echo.

:: ── Create SQLite database ────────────────────────────────────────────────────
echo [4/6] Creating SQLite database...
python "%~dp0storage\init_db.py"
if %errorlevel% neq 0 (
    echo ERROR: Failed to create SQLite database.
    pause
    exit /b 1
)
echo.

:: ── Install + provision Grafana SQLite data source ───────────────────────────
echo [5/6] Configuring Grafana SQLite data source...
where grafana-cli >nul 2>&1
if %errorlevel% neq 0 (
    echo       WARNING: grafana-cli not found in PATH.
    echo       After installing Grafana, run these commands manually:
    echo         grafana-cli plugins install frser-sqlite-datasource
    echo         python "%~dp0grafana\provision.py"
    echo       Then restart the Grafana service.
) else (
    grafana-cli plugins install frser-sqlite-datasource
    python "%~dp0grafana\provision.py"
    echo       Restarting Grafana service...
    net stop "Grafana" >nul 2>&1
    net start "Grafana" >nul 2>&1
    if %errorlevel% neq 0 (
        echo       NOTE: could not restart Grafana automatically.
        echo       If Grafana is not installed as a Windows service, restart it manually.
    )
)
echo.

:: ── Register Task Scheduler ───────────────────────────────────────────────────
echo [6/6] Registering auto-start task in Windows Task Scheduler...

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
echo  It will start automatically every time this computer is turned on.
echo.
echo  Drop F5 or Log360 export files into:
echo    %~dp0inbox\
echo.
echo  Database file:
echo    %~dp0capstone.db
echo.
echo  Open Grafana at: http://localhost:3000
echo  The "Capstone SQLite" data source is provisioned automatically.
echo ============================================
echo.
pause
