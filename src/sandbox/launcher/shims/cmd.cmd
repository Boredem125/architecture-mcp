@echo off
REM cmd.exe interception shim — catches attempts to use cmd /c for elevation
REM Only intercepts when running inside a sandbox jail

setlocal enabledelayedexpansion

set "FULL_CMD=%*"
set "BROKER_URL=%SANDBOX_BROKER_URL%"
set "SESSION_ID=%SANDBOX_SESSION_ID%"
set "RUN_ID=%SANDBOX_RUN_ID%"
set "JAIL_DIR=%SANDBOX_JAIL_DIR%"

if "%BROKER_URL%"=="" (
    echo [SANDBOX] ERROR: No broker URL configured. cmd access denied.
    exit /b 1
)

curl -s -X POST "%BROKER_URL%/request" ^
    -H "Content-Type: application/json" ^
    -H "Authorization: Bearer %SANDBOX_AGENT_TOKEN%" ^
    -d "{\"session_id\":\"%SESSION_ID%\",\"run_id\":\"%RUN_ID%\",\"command\":\"cmd %FULL_CMD%\",\"jail_dir\":\"%JAIL_DIR%\"}" ^
    > "%TEMP%\broker_response.json" 2>nul

if %ERRORLEVEL% neq 0 (
    echo [SANDBOX] ERROR: Failed to contact privilege broker. cmd access denied.
    exit /b 1
)

for /f "tokens=2 delims=:," %%a in ('type "%TEMP%\broker_response.json" ^| findstr "request_id"') do (
    set "REQ_ID=%%~a"
    set "REQ_ID=!REQ_ID: =!"
    set "REQ_ID=!REQ_ID:"=!"
)

if "%REQ_ID%"=="" (
    echo [SANDBOX] ERROR: Invalid broker response. cmd access denied.
    exit /b 1
)

echo [SANDBOX] cmd access requested. Waiting for human approval...
echo [SANDBOX] Request ID: %REQ_ID%

set "OUTPUT_FILE=%JAIL_DIR%\broker_out\%REQ_ID%.txt"
set /a WAIT=0
set /a MAX_WAIT=300

:poll_loop
if %WAIT% geq %MAX_WAIT% (
    echo [SANDBOX] TIMEOUT: Denied.
    exit /b 1
)

if exist "%OUTPUT_FILE%" (
    type "%OUTPUT_FILE%"
    findstr /c:"STATUS: DENIED" "%OUTPUT_FILE%" >nul 2>nul
    if !ERRORLEVEL! equ 0 exit /b 1
    findstr /c:"STATUS: TIMEOUT" "%OUTPUT_FILE%" >nul 2>nul
    if !ERRORLEVEL! equ 0 exit /b 1
    exit /b 0
)

timeout /t 2 /nobreak >nul
set /a WAIT+=2
goto poll_loop
