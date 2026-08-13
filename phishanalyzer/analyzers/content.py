"""Social-engineering / content heuristics: urgency language, generic
greetings, BEC-style financial requests, and HTML tricks used to hide text
from the reader while keeping it in the DOM for filter evasion."""

from __future__ import annotations

import re

from ..models import Category, Finding, ParsedEmail, Severity

_ZERO_WIDTH_CHARS = "​‌‍﻿⁠"

_HIDDEN_STYLE_RE = re.compile(
    r"(?is)"
    r"(?:color\s*:\s*(?:#fff(?:fff)?|white)\s*;[^\"'>]*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))"
    r"|(?:font-size\s*:\s*0(?:px|pt)?)"
    r"|(?:display\s*:\s*none)"
    r"|(?:visibility\s*:\s*hidden)"
)


def _count_matches(haystack: str, needles: list[str]) -> list[str]:
    haystack_lower = haystack.lower()
    return [n for n in needles if n.lower() in haystack_lower]


def analyze(parsed: ParsedEmail, indicators: dict) -> list[Finding]:
    findings: list[Finding] = []
    text = f"{parsed.subject}\n{parsed.body_text}"

    urgency_hits = _count_matches(text, indicators.get("urgency_keywords", []))
    if urgency_hits:
        severity = Severity.HIGH if len(urgency_hits) >= 3 else Severity.MEDIUM
        findings.append(
            Finding(
                category=Category.CONTENT,
                severity=severity,
                title="Urgency / pressure language",
                detail=(
                    f"Found {len(urgency_hits)} urgency phrase(s) commonly used to rush "
                    "recipients into acting without verifying: " + ", ".join(f"'{h}'" for h in urgency_hits[:8])
                ),
                evidence=", ".join(urgency_hits),
                mitre="T1566",
                # Urgency copy alone is just as common in aggressive marketing
                # spam as in phishing. It's real signal for "worth a look" but
                # shouldn't by itself push the phishing/spam split — that job
                # belongs to findings tied to an actual credential/malware/fraud
                # mechanism (URL, attachment, BEC keywords, impersonation).
                phishing_signal=False,
            )
        )

    greeting_hits = _count_matches(text, indicators.get("generic_greetings", []))
    if greeting_hits:
        findings.append(
            Finding(
                category=Category.CONTENT,
                severity=Severity.LOW,
                title="Generic, non-personalized greeting",
                detail="Uses a generic greeting instead of the recipient's name — common in "
                "both mass phishing and legitimate bulk/marketing mail, so weak on its own.",
                evidence=", ".join(greeting_hits),
                phishing_signal=False,
            )
        )

    bec_hits = _count_matches(text, indicators.get("financial_bec_keywords", []))
    if bec_hits:
        findings.append(
            Finding(
                category=Category.CONTENT,
                severity=Severity.HIGH,
                title="Financial request language (possible BEC)",
                detail=(
                    "Contains phrasing associated with Business Email Compromise / invoice "
                    "fraud: " + ", ".join(f"'{h}'" for h in bec_hits[:8]) + ". Verify any "
                    "payment or banking-detail change through a separate, known-good channel "
                    "before acting."
                ),
                evidence=", ".join(bec_hits),
                mitre="T1566.002",
            )
        )

    if parsed.body_html:
        zero_width_count = sum(parsed.body_html.count(c) for c in _ZERO_WIDTH_CHARS)
        if zero_width_count > 0:
            findings.append(
                Finding(
                    category=Category.CONTENT,
                    severity=Severity.MEDIUM,
                    title="Zero-width / invisible Unicode characters in HTML body",
                    detail=(
                        f"Found {zero_width_count} zero-width character(s). These are "
                        "invisible to the reader but can break up keywords to evade "
                        "text-based spam/phishing filters."
                    ),
                )
            )

        hidden_style_hits = _HIDDEN_STYLE_RE.findall(parsed.body_html)
        if hidden_style_hits:
            findings.append(
                Finding(
                    category=Category.CONTENT,
                    severity=Severity.MEDIUM,
                    title="Hidden text in HTML body",
                    detail=(
                        f"Found {len(hidden_style_hits)} instance(s) of CSS commonly used to "
                        "hide text from the reader (white-on-white, zero font size, display:none) "
                        "while keeping it machine-readable — used both for filter evasion and "
                        "to stuff invisible keywords."
                    ),
                )
            )

    return findings
