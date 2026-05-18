@echo off
title NYK-FIL Maritime - Security Monitoring Watcher Setup
setlocal EnableDelayedExpansion

echo ============================================
echo  NYK-FIL Maritime E Training Inc.
echo  Security Monitoring Watcher - Setup
echo ============================================
echo.

set "ROOT=%~dp0"
set "BUNDLED_PY=%ROOT%python\python.exe"
set "BUNDLED_PYW=%ROOT%python\pythonw.exe"

:: ── Mode detection: bundled (client ZIP) vs system (dev) ────────────────────
if exist "%BUNDLED_PY%" (
    set "PYTHON=%BUNDLED_PY%"
    set "PYTHONW=%BUNDLED_PYW%"
    set "MODE=bundled"
) else (
    set "PYTHON=python"
    set "PYTHONW=pythonw"
    set "MODE=system"
)
echo Mode: %MODE%
echo.

:: ── 1. Python check (system mode only) ──────────────────────────────────────
if /I "%MODE%"=="system" (
    echo [1/5] Checking Python installation...
    "%PYTHON%" --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python not found. Install Python 3.10+ from https://www.python.org
        pause & exit /b 1
    )
    echo       Python found.

    echo [2/5] Installing Python packages...
    "%PYTHON%" -m pip install -r "%ROOT%requirements.txt" --quiet
    if errorlevel 1 ( echo ERROR: pip install failed. & pause & exit /b 1 )
    echo       Packages installed.
) else (
    echo [1/5] Bundled Python detected — skipping system Python check.
    echo [2/5] Bundled dependencies — skipping pip install.
)
echo.

:: ── 3. Folders ──────────────────────────────────────────────────────────────
echo [3/5] Creating inbox / processed / failed folders...
if not exist "%ROOT%inbox"     mkdir "%ROOT%inbox"
if not exist "%ROOT%processed" mkdir "%ROOT%processed"
if not exist "%ROOT%failed"    mkdir "%ROOT%failed"
echo       Folders ready.
echo.

:: ── 4. Database connection (.env) ───────────────────────────────────────────
echo [4/5] Checking database configuration...
if exist "%ROOT%.env" (
    findstr /b /c:"DATABASE_URL=postgres" "%ROOT%.env" >nul 2>&1
    if not errorlevel 1 (
        echo       .env already configured — skipping prompt.
        goto :env_done
    )
)

:prompt_url
echo.
echo       This watcher uploads logs to a shared Supabase database.
echo       Your administrator should have sent you a DATABASE_URL.
echo.
echo       It looks like:
echo         postgresql://postgres.xxxx:PASSWORD@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres
echo.
set "DBURL="
set /p "DBURL=       Paste DATABASE_URL here and press Enter: "

if "!DBURL!"=="" (
    echo       ERROR: No URL entered. Try again or close this window to cancel.
    goto :prompt_url
)

:: Light validation — must start with postgresql:// or postgres://
echo !DBURL! | findstr /b /r "postgres" >nul 2>&1
if errorlevel 1 (
    echo       ERROR: That doesn't look like a Postgres URL.
    echo       It should start with 'postgresql://' or 'postgres://'.
    goto :prompt_url
)

:: Write a fresh .env with the pasted URL
> "%ROOT%.env" echo DATABASE_URL=!DBURL!
>> "%ROOT%.env" echo KEEP_PROCESSED=false
echo       Saved connection to .env

:env_done
echo.

:: ── 5. Register watcher auto-start (Task Scheduler, runs on user logon) ─────
echo [5/5] Registering watcher auto-start (Task Scheduler, on user logon)...
schtasks /delete /tn "NYKFilWatcher" /f >nul 2>&1
:: Use cmd /c to set the working directory before launching pythonw, so the
:: watcher's `import config` (sibling file) resolves correctly.
set "ROOT_NOSLASH=%ROOT:~0,-1%"
schtasks /create /tn "NYKFilWatcher" ^
    /tr "cmd /c cd /d \"%ROOT_NOSLASH%\" && \"%PYTHONW%\" \"%ROOT%watcher.py\"" ^
    /sc onlogon /f >nul
if errorlevel 1 (
    echo       WARNING: could not register watcher auto-start.
    echo       You can still run watcher.py manually.
) else (
    echo       Watcher auto-start registered.
)
echo.

:: ── Start the watcher now ───────────────────────────────────────────────────
echo Starting watcher in the background...
schtasks /run /tn "NYKFilWatcher" >nul 2>&1
echo.

echo ============================================
echo  Setup complete.
echo.
echo  HOW TO USE:
echo    Drop F5 / Log360 export files (.xml .xlsx .json) into:
echo      %ROOT%inbox\
echo.
echo    The watcher picks them up automatically and uploads
echo    them to the shared Supabase database.
echo.
echo  DASHBOARD:
echo    View the live dashboard in your browser at the
echo    Grafana Cloud URL provided by your administrator.
echo.
echo  TO STOP THE WATCHER:
echo    schtasks /end /tn "NYKFilWatcher"
echo.
echo  TO UNINSTALL:
echo    schtasks /delete /tn "NYKFilWatcher" /f
echo    Then delete this folder.
echo ============================================
echo.

pause
