"""Aggregates analyzer findings into a verdict.

Two running totals are kept: an overall score (every finding) and a
phishing score (only findings with phishing_signal=True — i.e. credential
theft, malware delivery, targeted fraud, active impersonation). A message
can score moderately overall while being driven almost entirely by
bulk/marketing-style signals; that pattern is labeled Spam, not Phishing,
which is the distinction this tool exists to make.
"""

from __future__ import annotations

from .models import SEVERITY_WEIGHT, Finding, Severity, Verdict

# Verdict thresholds, in points (see README for the full table + rationale).
_LEGITIMATE_MAX = 14
_SPAM_MIN = 15
_PHISHING_MIN = 40
_MALICIOUS_MIN = 80
_SUSPICIOUS_PHISHING_SHARE = 0.4


def score_findings(findings: list[Finding]) -> tuple[int, int]:
    total = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    phishing = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.phishing_signal)
    return total, phishing


def _confidence(findings: list[Finding], total: int) -> str:
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    if has_critical or total >= _MALICIOUS_MIN:
        return "high"
    if total >= _PHISHING_MIN or len(findings) >= 4:
        return "medium"
    return "low"


def _label(total: int, phishing: int, findings: list[Finding]) -> str:
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)

    if total <= _LEGITIMATE_MAX:
        return "Likely Legitimate"

    if has_critical or phishing >= _MALICIOUS_MIN:
        return "Malicious — High Confidence"

    if phishing >= _PHISHING_MIN:
        return "Phishing"

    phishing_share = phishing / total if total else 0
    if phishing >= _SPAM_MIN and phishing_share >= _SUSPICIOUS_PHISHING_SHARE:
        return "Suspicious"

    if total >= _SPAM_MIN:
        return "Spam / Unwanted"

    return "Likely Legitimate"


def _fallback_summary(label: str, findings: list[Finding]) -> str:
    if not findings:
        return "No notable indicators found in this message."

    ranked = sorted(findings, key=lambda f: SEVERITY_WEIGHT[f.severity], reverse=True)
    top = ranked[:4]
    bullet_lines = "\n".join(f"- {f.title}: {f.detail}" for f in top)
    return f"Verdict: {label}.\n\nTop indicators:\n{bullet_lines}"


def build_verdict(findings: list[Finding]) -> Verdict:
    total, phishing = score_findings(findings)
    label = _label(total, phishing, findings)
    confidence = _confidence(findings, total)
    summary = _fallback_summary(label, findings)
    return Verdict(label=label, score=total, phishing_score=phishing, confidence=confidence, summary=summary)
