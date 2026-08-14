#!/usr/bin/env bash
# PhishAnalyzer updater for macOS and Linux.
# Pulls the latest version from GitHub and refreshes dependencies in the
# existing .venv. Run from a terminal in the repo folder:  ./update.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"
cd "$repo_root"

if [ ! -d ".git" ]; then
    echo "error: this folder isn't a git clone (no .git found) - update.sh only works if you cloned the repo with 'git clone'. If you downloaded a tarball/zip, download the latest one again instead." >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "error: you have local changes (e.g. a customized indicators.json). Commit or 'git stash' them first, then re-run ./update.sh." >&2
    exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD)"

echo "Fetching latest changes..."
if ! git fetch origin; then
    echo "error: git fetch failed - check your network connection and try again." >&2
    exit 1
fi

if ! git merge --ff-only "origin/$branch"; then
    # Working tree is already confirmed clean above, so this can only discard
    # local *commits* that aren't upstream (e.g. the maintainer rewrote
    # history) - never uncommitted work.
    echo ""
    echo "Local history doesn't match origin/$branch (probably rewritten upstream) - resyncing to origin/$branch..."
    if ! git reset --hard "origin/$branch"; then
        echo "error: could not sync with origin/$branch - see above." >&2
        exit 1
    fi
fi

venv_python="$repo_root/.venv/bin/python"
if [ -x "$venv_python" ]; then
    echo "Refreshing dependencies..."
    "$venv_python" -m pip install --upgrade pip --quiet
    "$venv_python" -m pip install -r requirements.txt
else
    echo "No .venv found - running setup.sh instead..."
    "$repo_root/setup.sh"
fi

echo ""
echo "Up to date."
