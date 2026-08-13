"""Static analyzers. Each module exposes analyze(parsed, indicators) -> list[Finding]."""

from __future__ import annotations

from ..indicators import load_indicators
from ..models import Finding, ParsedEmail
from . import attachments, content, headers, urls


def run_all(parsed: ParsedEmail, indicators: dict | None = None) -> list[Finding]:
    ind = indicators if indicators is not None else load_indicators()
    findings: list[Finding] = []
    findings.extend(headers.analyze(parsed, ind))
    findings.extend(urls.analyze(parsed, ind))
    findings.extend(attachments.analyze(parsed, ind))
    findings.extend(content.analyze(parsed, ind))
    return findings
