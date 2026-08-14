#!/usr/bin/env bash
# PhishAnalyzer setup for macOS and Linux.
# Creates a local virtual environment and installs dependencies.
# Run from a terminal in the repo folder:  ./setup.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

python_cmd=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        python_cmd="$candidate"
        break
    fi
done

if [ -z "$python_cmd" ]; then
    echo "error: Python was not found on PATH. Install Python 3.10+ (macOS: 'brew install python3', or https://www.python.org/downloads/; Linux: use your distro's package manager), then re-run this script." >&2
    exit 1
fi

echo "Using: $(command -v "$python_cmd")"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    "$python_cmd" -m venv .venv
fi

venv_python="$repo_root/.venv/bin/python"

echo "Installing dependencies..."
"$venv_python" -m pip install --upgrade pip --quiet
"$venv_python" -m pip install -r requirements.txt

echo ""
echo "Done. To analyze an email:"
echo "  ./.venv/bin/python -m phishanalyzer path/to/email.eml"
echo ""
echo "Or run:  ./analyze.sh path/to/email.eml"
echo ""
echo "Optional: to enable the AI-written summary, set an API key for this session:"
echo '  export ANTHROPIC_API_KEY="sk-ant-..."'
