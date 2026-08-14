@echo off
REM Drag-and-drop an .eml/.msg file onto this file to analyze it.
REM Reports (JSON + HTML) are written next to this script, in reports\.

setlocal
set SCRIPT_DIR=%~dp0
set VENV_PY=%SCRIPT_DIR%.venv\Scripts\python.exe

if "%~1"=="" (
    echo Usage: drag an .eml or .msg file onto this .bat, or run:
    echo   analyze.bat path\to\email.eml
    pause
    exit /b 1
)

if not exist "%VENV_PY%" (
    echo Virtual environment not found. Run setup.ps1 first ^(right-click it and "Run with PowerShell"^).
    pause
    exit /b 1
)

REM phishanalyzer isn't pip-installed as a package (only its dependencies
REM are) — "python -m phishanalyzer" only finds it if the working directory
REM is this folder. Force that explicitly so this works no matter how the
REM .bat was launched (typed from elsewhere, a Desktop shortcut with a
REM different "Start in" path, dropped onto directly, etc).
set EMAIL_FILE=%~1
cd /d "%SCRIPT_DIR%"

"%VENV_PY%" -m phishanalyzer "%EMAIL_FILE%" --format all

echo.
echo Report saved to: %SCRIPT_DIR%reports
pause
