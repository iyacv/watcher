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

:: ── 4. Database connection (.env) ───────────────────────────────────────────
echo [4/6] Checking database configuration...
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
echo [5/6] Registering watcher auto-start (Task Scheduler, on user logon)...
schtasks /delete /tn "NYKFilWatcher" /f >nul 2>&1
set "ROOT_NOSLASH=%ROOT:~0,-1%"

:: Task Scheduler's <Command> needs a real path — a bare name like "pythonw"
:: (system mode) is not PATH-resolved the way a shell would. Resolve it now.
set "PYTHONW_ABS=%PYTHONW%"
if /I "%MODE%"=="system" (
    for /f "delims=" %%P in ('where pythonw 2^>nul') do (
        if not defined PYTHONW_RESOLVED (
            set "PYTHONW_ABS=%%P"
            set "PYTHONW_RESOLVED=1"
        )
    )
)

:: Register via an XML definition rather than the /tr short form. The short
:: form forced a `cmd /c cd ... && pythonw` wrapper; Task Scheduler reaps the
:: cmd host on return and kills pythonw with it (observed Last Result
:: 0xC000013A). The XML sets <WorkingDirectory> directly so `import config`
:: resolves with no wrapper process, and clears the defaults that otherwise
:: stop the watcher (battery, idle, 72h execution limit).
set "TASKXML=%TEMP%\nykfilwatcher_task.xml"
> "%TASKXML%" echo ^<?xml version="1.0" encoding="UTF-16"?^>
>>"%TASKXML%" echo ^<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"^>
>>"%TASKXML%" echo   ^<RegistrationInfo^>^<Description^>NYK-FIL Security Monitoring Watcher^</Description^>^</RegistrationInfo^>
>>"%TASKXML%" echo   ^<Triggers^>^<LogonTrigger^>^<Enabled^>true^</Enabled^>^<UserId^>%USERDOMAIN%\%USERNAME%^</UserId^>^</LogonTrigger^>^</Triggers^>
>>"%TASKXML%" echo   ^<Principals^>^<Principal id="Author"^>^<UserId^>%USERDOMAIN%\%USERNAME%^</UserId^>^<LogonType^>InteractiveToken^</LogonType^>^<RunLevel^>LeastPrivilege^</RunLevel^>^</Principal^>^</Principals^>
>>"%TASKXML%" echo   ^<Settings^>
>>"%TASKXML%" echo     ^<MultipleInstancesPolicy^>IgnoreNew^</MultipleInstancesPolicy^>
>>"%TASKXML%" echo     ^<DisallowStartIfOnBatteries^>false^</DisallowStartIfOnBatteries^>
>>"%TASKXML%" echo     ^<StopIfGoingOnBatteries^>false^</StopIfGoingOnBatteries^>
>>"%TASKXML%" echo     ^<AllowHardTerminate^>false^</AllowHardTerminate^>
>>"%TASKXML%" echo     ^<StartWhenAvailable^>true^</StartWhenAvailable^>
>>"%TASKXML%" echo     ^<RunOnlyIfIdle^>false^</RunOnlyIfIdle^>
>>"%TASKXML%" echo     ^<IdleSettings^>^<StopOnIdleEnd^>false^</StopOnIdleEnd^>^<RestartOnIdle^>false^</RestartOnIdle^>^</IdleSettings^>
>>"%TASKXML%" echo     ^<ExecutionTimeLimit^>PT0S^</ExecutionTimeLimit^>
>>"%TASKXML%" echo     ^<Enabled^>true^</Enabled^>
>>"%TASKXML%" echo   ^</Settings^>
>>"%TASKXML%" echo   ^<Actions Context="Author"^>
>>"%TASKXML%" echo     ^<Exec^>
>>"%TASKXML%" echo       ^<Command^>%PYTHONW_ABS%^</Command^>
>>"%TASKXML%" echo       ^<Arguments^>"%ROOT%watcher.py"^</Arguments^>
>>"%TASKXML%" echo       ^<WorkingDirectory^>%ROOT_NOSLASH%^</WorkingDirectory^>
>>"%TASKXML%" echo     ^</Exec^>
>>"%TASKXML%" echo   ^</Actions^>
>>"%TASKXML%" echo ^</Task^>

schtasks /create /tn "NYKFilWatcher" /xml "%TASKXML%" /f >nul
if errorlevel 1 (
    echo       WARNING: could not register watcher auto-start.
    echo       You can still run watcher.py manually.
) else (
    echo       Watcher auto-start registered.
)
del "%TASKXML%" >nul 2>&1
echo.

:: ── Start the watcher now ───────────────────────────────────────────────────
echo Starting watcher in the background...
schtasks /run /tn "NYKFilWatcher" >nul 2>&1
echo.

:: ── 6. Self-test: confirm unsupported files are rejected ────────────────────
echo [6/6] Self-test: dropping a junk file to confirm it is rejected...
set "TESTNAME=_setup_selftest.txt"
set "TESTFILE=%ROOT%inbox\%TESTNAME%"
set "TESTNOTE=%ROOT%failed\%TESTNAME%.error.txt"

:: Clean any leftovers from a previous run
del "%TESTFILE%"                >nul 2>&1
del "%ROOT%failed\%TESTNAME%"   >nul 2>&1
del "%TESTNOTE%"                >nul 2>&1

> "%TESTFILE%" echo this is not an F5 or Log360 export - it must be rejected

:: Give the running watcher time to detect, reject, and move the file.
:: We sleep FIRST each iteration, then check — the watcher itself waits ~0.5s
:: for the file to finish writing before it processes, so an immediate check
:: would always miss on the first pass. Budget: ~20 x 2s = up to 40s, which
:: comfortably covers a freshly-started watcher on a slow machine.
:: NOTE: delayed expansion (!OK!) is required — %OK% would be frozen at the
:: value it had when the loop was parsed, so the flag would never update.
set "OK="
for /L %%i in (1,1,20) do (
    if not defined OK (
        ping -n 3 127.0.0.1 >nul
        if exist "%TESTNOTE%" set "OK=1"
    )
)

if defined OK (
    echo       PASS - junk file was rejected to the failed\ folder.
    echo       Rejection note written:
    echo         %TESTNOTE%
    :: tidy up the test artifacts so failed\ stays clean
    del "%TESTNOTE%"              >nul 2>&1
    del "%ROOT%failed\%TESTNAME%" >nul 2>&1
) else (
    echo       WARNING - test file was not rejected within 40 seconds.
    echo       The watcher may still be starting. Check manually:
    echo         - inbox\  should NOT contain %TESTNAME%
    echo         - failed\ SHOULD contain %TESTNAME% and its .error.txt
    echo       Leaving the test file in place for inspection.
)
echo.

echo ============================================
echo  Setup complete.
echo.
echo  HOW TO USE:
echo    Drop export files into:
echo      %ROOT%inbox\
echo.
echo    Accepted file types:
echo      .xml   - F5 vulnerability scans
echo      .xlsx  - Log360 event reports
echo.
echo    Any other file (.txt .png .pdf .json .xlsm etc.) is
echo    rejected and moved to the failed\ folder with a
echo    .error.txt note explaining why.
echo.
echo    The watcher picks up accepted files automatically and
echo    uploads them to the shared Supabase database.
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
