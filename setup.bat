@echo off
title NYK-FIL Maritime - Security Monitoring System Setup
setlocal EnableDelayedExpansion

echo ============================================
echo  NYK-FIL Maritime E Training Inc.
echo  Security Monitoring System - Setup
echo ============================================
echo.

set "ROOT=%~dp0"
set "BUNDLED_PY=%ROOT%python\python.exe"
set "BUNDLED_PYW=%ROOT%python\pythonw.exe"
set "BUNDLED_GFS=%ROOT%grafana\bin\grafana-server.exe"

:: ── Mode detection: bundled (portable) vs system (dev) ──────────────────────
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
    echo [1/6] Checking Python installation...
    "%PYTHON%" --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python not found. Install Python 3.10+ from https://www.python.org
        pause & exit /b 1
    )
    echo       Python found.

    echo [2/6] Installing Python packages...
    "%PYTHON%" -m pip install -r "%ROOT%requirements.txt" --quiet
    if errorlevel 1 ( echo ERROR: pip install failed. & pause & exit /b 1 )
    echo       Packages installed.
) else (
    echo [1/6] Bundled Python detected — skipping system Python check.
    echo [2/6] Bundled dependencies — skipping pip install.
)
echo.

:: ── 3. Folders ──────────────────────────────────────────────────────────────
echo [3/6] Creating inbox / processed / failed folders...
if not exist "%ROOT%inbox"     mkdir "%ROOT%inbox"
if not exist "%ROOT%processed" mkdir "%ROOT%processed"
if not exist "%ROOT%failed"    mkdir "%ROOT%failed"
echo       Folders ready.
echo.

:: ── 4. SQLite database ──────────────────────────────────────────────────────
echo [4/6] Initializing SQLite database...
"%PYTHON%" "%ROOT%storage\init_db.py"
if errorlevel 1 ( echo ERROR: DB init failed. & pause & exit /b 1 )
echo.

:: ── 5. Provision Grafana datasource + dashboard ─────────────────────────────
echo [5/6] Provisioning Grafana data source and dashboard...
"%PYTHON%" "%ROOT%grafana\provision.py"
if errorlevel 1 (
    echo       NOTE: provisioning failed. If using system Grafana, install it,
    echo             ensure grafana-cli is on PATH, then run provision.py manually.
)
echo.

:: ── 6. Register auto-start tasks (no admin required, runs on user logon) ───
echo [6/6] Registering auto-start (Task Scheduler, on user logon)...

if /I "%MODE%"=="bundled" (
    schtasks /delete /tn "NYKFilGrafana" /f >nul 2>&1
    schtasks /create /tn "NYKFilGrafana" ^
        /tr "\"%BUNDLED_GFS%\" --homepath \"%ROOT%grafana\"" ^
        /sc onlogon /f >nul
    if errorlevel 1 (
        echo       WARNING: could not register Grafana auto-start.
    ) else (
        echo       Grafana auto-start registered.
    )
)

schtasks /delete /tn "NYKFilWatcher" /f >nul 2>&1
schtasks /create /tn "NYKFilWatcher" ^
    /tr "\"%PYTHONW%\" \"%ROOT%watcher.py\"" ^
    /sc onlogon /f >nul
if errorlevel 1 (
    echo       WARNING: could not register watcher auto-start.
) else (
    echo       Watcher auto-start registered.
)
echo.

:: ── 6b. Firewall rule so other PCs on the LAN can reach Grafana ────────────
echo Opening Windows Firewall for port 3000 (LAN dashboard access)...
netsh advfirewall firewall delete rule name="NYKFil Grafana Dashboard" >nul 2>&1
netsh advfirewall firewall add rule name="NYKFil Grafana Dashboard" ^
    dir=in action=allow protocol=TCP localport=3000 profile=private,domain >nul 2>&1
if errorlevel 1 (
    echo       NOTE: could not add firewall rule automatically.
    echo             If staff cannot reach the dashboard from other PCs,
    echo             re-run this setup.bat as Administrator.
) else (
    echo       Firewall rule added (private/domain networks).
)
echo.

:: ── Start now ───────────────────────────────────────────────────────────────
echo Starting services...
if /I "%MODE%"=="bundled" (
    schtasks /run /tn "NYKFilGrafana" >nul 2>&1
    timeout /t 4 /nobreak >nul
)
schtasks /run /tn "NYKFilWatcher" >nul 2>&1
echo.

:: ── Detect this PC's LAN IP so staff know what URL to use ─────────────────
set "HOST_IP="
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    if not defined HOST_IP set "HOST_IP=%%a"
)
set "HOST_IP=%HOST_IP: =%"

echo ============================================
echo  Setup complete.
echo.
echo  Drop F5 / Log360 export files into:
echo    %ROOT%inbox\
echo.
echo  Database file (all data is stored here):
echo    %ROOT%capstone.db
echo.
echo  Dashboard URLs:
echo    On this PC          : http://localhost:3000
if defined HOST_IP (
echo    From other staff PCs: http://%HOST_IP%:3000
) else (
echo    From other staff PCs: http://^<this-pc-ip^>:3000  (run 'ipconfig' to find it)
)
echo.
echo  First login: admin / admin   (you will be asked to set a new password)
echo  Then create accounts for staff under:
echo    Administration -^> Users and access -^> Users -^> New user
echo    (default role = Viewer, which is read-only)
echo ============================================
echo.

start "" "http://localhost:3000"
pause
