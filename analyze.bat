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

"%VENV_PY%" -m phishanalyzer "%~1" --format all --output-dir "%SCRIPT_DIR%reports"

echo.
echo Report saved to: %SCRIPT_DIR%reports
pause
