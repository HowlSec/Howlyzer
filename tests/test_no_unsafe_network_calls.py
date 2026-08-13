"""Locks in PhishAnalyzer's core safety guarantee: this tool never fetches a
URL, resolves a domain, opens a browser, or executes an external program —
static analysis only, always. If this test ever fails, someone introduced a
code path that could act on attacker-controlled email content (a link, an
attachment, a domain) instead of just describing it, and that needs a
deliberate security review before merging, not a quiet regression.

The only network activity this tool ever performs is the *optional* Claude
API call in llm.py, which the SDK makes to api.anthropic.com — never to
anything derived from the email being analyzed. That call is exempted by
name below; everything else in the package must stay clean.
"""

from __future__ import annotations

import pathlib
import re

from conftest import ROOT

PACKAGE_DIR = ROOT / "phishanalyzer"

# Each pattern is something that could open a URL/file externally, shell out,
# or otherwise act on data instead of just reading/describing it.
FORBIDDEN_PATTERNS = [
    r"\bwebbrowser\b",
    r"\bos\.startfile\b",
    r"\bsubprocess\b",
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\burllib\.request\b",
    r"\burlopen\b",
    r"\brequests\.(get|post|put|delete|head|patch)\b",
    r"\bhttpx\.(get|post|put|delete|head|patch|Client|AsyncClient)\b",
    r"\bsocket\.\b",
    r"\bsmtplib\b",
    r"\bftplib\b",
    r"\beval\(",
    r"\bexec\(",
    r"\bpickle\.(load|loads)\b",
]

# The one legitimate, non-email-derived network call in the whole package.
ALLOWED_FILE = "llm.py"
ALLOWED_PATTERN = r"\bimport anthropic\b|\banthropic\.Anthropic\b"


def test_no_forbidden_calls_outside_the_one_allowed_llm_client():
    violations = []
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            for match in re.finditer(pattern, text):
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(ROOT)}:{line_no}: matched {pattern!r}")

    assert not violations, (
        "Found code paths that could act on external data instead of just "
        "analyzing it statically:\n" + "\n".join(violations)
    )


def test_llm_module_only_talks_to_anthropic_directly():
    """The one allowed exception (the optional AI summary) must stay scoped
    to the anthropic SDK — not grow a raw HTTP client of its own."""
    llm_path = PACKAGE_DIR / ALLOWED_FILE
    text = llm_path.read_text(encoding="utf-8")
    assert re.search(ALLOWED_PATTERN, text), (
        f"{ALLOWED_FILE} no longer references the anthropic SDK the way this "
        "test expects — update this test if the integration changed intentionally."
    )
