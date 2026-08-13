# PhishAnalyzer setup for Windows.
# Creates a local virtual environment and installs dependencies.
# Run from PowerShell in the repo folder:  .\setup.ps1

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$pythonCmd = Get-Command py -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $pythonCmd) {
    Write-Error "Python was not found on PATH. Install Python 3.10+ from https://www.python.org/downloads/ (check 'Add python.exe to PATH' during install), then re-run this script."
    exit 1
}

Write-Host "Using: $($pythonCmd.Source)"

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment (.venv)..."
    & $pythonCmd.Source -m venv .venv
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

Write-Host "Installing dependencies..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r requirements.txt

Write-Host ""
Write-Host "Done. To analyze an email:" -ForegroundColor Green
Write-Host "  .\.venv\Scripts\python.exe -m phishanalyzer path\to\email.eml"
Write-Host ""
Write-Host "Or just drag an .eml/.msg file onto analyze.bat." -ForegroundColor Green
Write-Host ""
Write-Host "Optional: to enable the AI-written summary, set an API key for this session:" -ForegroundColor Yellow
Write-Host '  $env:ANTHROPIC_API_KEY = "sk-ant-..."'
