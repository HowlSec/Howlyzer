"""Shared data structures used across PhishAnalyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Category(Enum):
    AUTH = "authentication"
    SPOOFING = "spoofing"
    URL = "url"
    ATTACHMENT = "attachment"
    CONTENT = "content"


@dataclass
class Finding:
    """One observation from an analyzer."""

    category: Category
    severity: Severity
    title: str
    detail: str
    evidence: str = ""
    mitre: Optional[str] = None
    # True when this finding points toward credential theft / malware delivery
    # / targeted fraud (phishing). False when it points toward bulk/unwanted
    # mail with no phishing-specific payload (spam). Used by scoring.py to
    # tell the two apart instead of lumping everything into one score.
    phishing_signal: bool = True

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "mitre": self.mitre,
            "phishing_signal": self.phishing_signal,
        }


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    # Raw bytes kept only transiently in memory for the current analysis run
    # (e.g. to peek at zip flags) - never included in to_dict()/report output.
    raw: bytes = field(default=b"", repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass
class ExtractedLink:
    url: str
    anchor_text: str = ""  # visible text, only set for HTML <a> tags


@dataclass
class ParsedEmail:
    source_path: str
    headers: dict[str, str] = field(default_factory=dict)
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    links: list[ExtractedLink] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def urls(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for link in self.links:
            if link.url not in seen:
                seen.add(link.url)
                out.append(link.url)
        return out


@dataclass
class Verdict:
    label: str
    score: int
    phishing_score: int
    confidence: str
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "score": self.score,
            "phishing_score": self.phishing_score,
            "confidence": self.confidence,
            "summary": self.summary,
        }


@dataclass
class Report:
    parsed: ParsedEmail
    findings: list[Finding]
    verdict: Verdict
    iocs: dict[str, Any]
    ai_summary: Optional[str] = None
