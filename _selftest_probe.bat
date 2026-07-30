@echo off
setlocal EnableDelayedExpansion
set "ROOT=%~1"
set "TESTNAME=_setup_selftest.txt"
set "TESTFILE=%ROOT%inbox\%TESTNAME%"
set "TESTNOTE=%ROOT%failed\%TESTNAME%.error.txt"
del "%TESTFILE%" >nul 2>&1
del "%ROOT%failed\%TESTNAME%" >nul 2>&1
del "%TESTNOTE%" >nul 2>&1
> "%TESTFILE%" echo this is not an F5 or Log360 export - it must be rejected
set "OK="
for /L %%i in (1,1,20) do (
    if not defined OK (
        ping -n 3 127.0.0.1 >nul
        if exist "%TESTNOTE%" set "OK=1"
    )
)
if defined OK ( echo SELFTEST=PASS ) else ( echo SELFTEST=FAIL )
