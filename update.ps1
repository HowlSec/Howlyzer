# PhishAnalyzer updater for Windows.
# Pulls the latest version from GitHub and refreshes dependencies in the
# existing .venv. Run from PowerShell in the repo folder:  .\update.ps1

$ErrorActionPreference = "Stop"

# $MyInvocation.MyCommand.Path is null if this file's contents were pasted
# directly into an interactive prompt instead of being run as .\update.ps1 -
# fall back to the current directory so that still works.
if ($MyInvocation.MyCommand.Path) {
    $repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $repoRoot = (Get-Location).Path
}
Set-Location $repoRoot

if (-not (Test-Path ".git")) {
    Write-Error "This folder isn't a git clone (no .git found) - update.ps1 only works if you cloned the repo with 'git clone'. If you downloaded a ZIP, download the latest ZIP again instead."
    exit 1
}

$dirty = git status --porcelain
if ($dirty) {
    Write-Error "You have local changes (e.g. a customized indicators.json). Commit or 'git stash' them first, then re-run .\update.ps1."
    exit 1
}

$branch = git rev-parse --abbrev-ref HEAD

Write-Host "Fetching latest changes..."
git fetch origin
if ($LASTEXITCODE -ne 0) {
    Write-Error "git fetch failed - check your network connection and try again."
    exit 1
}

git merge --ff-only "origin/$branch"
if ($LASTEXITCODE -ne 0) {
    # Working tree is already confirmed clean above, so this can only discard
    # local *commits* that aren't upstream (e.g. the maintainer rewrote
    # history) - never uncommitted work.
    Write-Host ""
    Write-Host "Local history doesn't match origin/$branch (probably rewritten upstream) - resyncing to origin/$branch..." -ForegroundColor Yellow
    git reset --hard "origin/$branch"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not sync with origin/$branch - see above."
        exit 1
    }
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    Write-Host "Refreshing dependencies..."
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -r requirements.txt
} else {
    Write-Host "No .venv found - running setup.ps1 instead..."
    & (Join-Path $repoRoot "setup.ps1")
}

Write-Host ""
Write-Host "Up to date." -ForegroundColor Green
