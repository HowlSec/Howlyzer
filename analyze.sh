#!/usr/bin/env bash
# Analyze an .eml/.msg file on macOS/Linux.
# Reports (JSON + HTML) are written next to this script, in reports/.
#
# Usage:
#   ./analyze.sh path/to/email.eml

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_py="$script_dir/.venv/bin/python"

if [ $# -eq 0 ]; then
    echo "Usage: ./analyze.sh path/to/email.eml"
    exit 1
fi

if [ ! -x "$venv_py" ]; then
    echo "Virtual environment not found. Run ./setup.sh first." >&2
    exit 1
fi

email_file="$1"

# phishanalyzer isn't pip-installed as a package (only its dependencies
# are) — "python -m phishanalyzer" only finds it if the working directory
# is this folder. Force that explicitly so this works no matter where
# the script was invoked from.
cd "$script_dir"

"$venv_py" -m phishanalyzer "$email_file" --format all --output-dir "$script_dir/reports"

echo ""
echo "Report saved to: $script_dir/reports"
