"""Authentication (SPF/DKIM/DMARC) and sender-alignment / impersonation checks."""

from __future__ import annotations

import re

from ..models import Category, Finding, ParsedEmail, Severity

_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def _registrable_domain(domain: str) -> str:
    """Best-effort eTLD+1 without a public-suffix-list dependency.

    Good enough to compare "mail.paypal.com" vs "paypal.com" as related, and
    "paypal.com" vs "paypal-secure.com" as unrelated. Not perfect for
    multi-part ccTLDs (co.uk etc.) - those are treated slightly too
    coarsely, which only makes this check more conservative, not less.
    """
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def _check_auth_results(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    raw = parsed.headers.get("Authentication-Results", "")
    if not raw:
        findings.append(
            Finding(
                category=Category.AUTH,
                severity=Severity.LOW,
                title="No Authentication-Results header",
                detail=(
                    "The message has no Authentication-Results header, so SPF/DKIM/DMARC "
                    "could not be verified from this file. This is common for internally "
                    "relayed or exported mail and is not itself proof of spoofing."
                ),
            )
        )
        return findings

    results: dict[str, str] = {}
    for match in _AUTH_RESULT_RE.finditer(raw):
        mech, verdict = match.group(1).lower(), match.group(2).lower()
        # Keep the first (outermost / most relevant) result per mechanism.
        results.setdefault(mech, verdict)

    for mech in ("spf", "dkim", "dmarc"):
        verdict = results.get(mech)
        if verdict is None:
            continue
        if verdict in ("pass",):
            continue
        if verdict in ("fail", "hardfail"):
            findings.append(
                Finding(
                    category=Category.AUTH,
                    severity=Severity.HIGH,
                    title=f"{mech.upper()} check failed",
                    detail=f"The receiving mail server reported {mech.upper()}={verdict}, "
                    "meaning the sending server was not authorized to send as this domain, "
                    "or the message was altered in transit.",
                    evidence=f"{mech}={verdict}",
                    mitre="T1656",
                )
            )
        elif verdict in ("softfail", "neutral", "none", "temperror", "permerror"):
            findings.append(
                Finding(
                    category=Category.AUTH,
                    severity=Severity.MEDIUM,
                    title=f"{mech.upper()} check did not pass cleanly",
                    detail=f"{mech.upper()}={verdict} - weaker than a clean pass. "
                    "Common with legitimate mailing-list or forwarded mail, but also with spoofing.",
                    evidence=f"{mech}={verdict}",
                    phishing_signal=verdict not in ("none",),
                )
            )
    return findings


def _check_alignment(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = _registrable_domain(parsed.from_addr.rsplit("@", 1)[-1]) if "@" in parsed.from_addr else ""
    if not from_domain:
        return findings

    if parsed.reply_to_addr and "@" in parsed.reply_to_addr:
        reply_domain = _registrable_domain(parsed.reply_to_addr.rsplit("@", 1)[-1])
        if reply_domain and reply_domain != from_domain:
            findings.append(
                Finding(
                    category=Category.SPOOFING,
                    severity=Severity.MEDIUM,
                    title="Reply-To domain differs from From domain",
                    detail=(
                        f"Replies are routed to '{reply_domain}' instead of the sending domain "
                        f"'{from_domain}'. A common pattern for redirecting victim replies to an "
                        "attacker-controlled mailbox while the From address looks legitimate."
                    ),
                    evidence=f"From: {from_domain}  Reply-To: {reply_domain}",
                    mitre="T1656",
                )
            )

    if parsed.return_path_addr and "@" in parsed.return_path_addr:
        rp_domain = _registrable_domain(parsed.return_path_addr.rsplit("@", 1)[-1])
        if rp_domain and rp_domain != from_domain:
            findings.append(
                Finding(
                    category=Category.SPOOFING,
                    severity=Severity.LOW,
                    title="Return-Path domain differs from From domain",
                    detail=(
                        f"Bounces go to '{rp_domain}', not the sending domain '{from_domain}'. "
                        "Sometimes legitimate (bulk-mail platforms), also common in spoofed mail."
                    ),
                    evidence=f"From: {from_domain}  Return-Path: {rp_domain}",
                )
            )
    return findings


def _check_brand_impersonation(parsed: ParsedEmail, indicators: dict) -> list[Finding]:
    findings: list[Finding] = []
    brands: dict[str, list[str]] = indicators.get("impersonated_brands", {})
    free_webmail: list[str] = indicators.get("free_webmail_domains", [])

    display = (parsed.from_display or "").lower()
    from_domain = _registrable_domain(parsed.from_addr.rsplit("@", 1)[-1]) if "@" in parsed.from_addr else ""

    for brand, real_domains in brands.items():
        if brand.lower() not in display:
            continue
        real_domains_lower = [_registrable_domain(d) for d in real_domains]
        if from_domain and from_domain not in real_domains_lower:
            findings.append(
                Finding(
                    category=Category.SPOOFING,
                    severity=Severity.CRITICAL,
                    title=f"Display name claims to be '{brand}' but domain does not match",
                    detail=(
                        f"The sender display name references '{brand}', but the message "
                        f"actually comes from '{from_domain}', which is not one of {brand}'s "
                        f"known domains ({', '.join(real_domains)}). Classic brand impersonation."
                    ),
                    evidence=f"From: \"{parsed.from_display}\" <{parsed.from_addr}>",
                    mitre="T1656",
                )
            )

    if from_domain and from_domain in free_webmail:
        looks_corporate = any(
            kw in display for kw in ("support", "security", "billing", "helpdesk", "it department", "admin", "accounts")
        )
        if looks_corporate:
            findings.append(
                Finding(
                    category=Category.SPOOFING,
                    severity=Severity.MEDIUM,
                    title="Corporate-sounding sender name from a free webmail domain",
                    detail=(
                        f"Display name '{parsed.from_display}' implies an official/support role, "
                        f"but the message was sent from a free webmail domain ({from_domain}), "
                        "not a corporate mail system."
                    ),
                    evidence=f"From: \"{parsed.from_display}\" <{parsed.from_addr}>",
                )
            )

    return findings


_SIGNOFF_WORDS = {
    "regards", "thanks", "thank you", "best", "best regards", "warm regards",
    "sincerely", "cheers", "appreciated", "kind regards", "many thanks",
    "respectfully", "yours truly", "yours sincerely", "warmly",
}
_NAME_LINE_RE = re.compile(r"^[A-Z][a-zA-Z'’.-]+(?:\s+[A-Z][a-zA-Z'’.-]+){1,2}$")
_DATE_LIKE_DISPLAY_RE = re.compile(
    r"^\d{1,2}[-/\s]+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[-/\s]+\d{2,4}$"
    r"|^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$",
    re.IGNORECASE,
)


def _looks_like_signoff(line: str) -> bool:
    return line.strip().lower().rstrip(",.!:") in _SIGNOFF_WORDS


def _extract_signed_name(body_text: str) -> str | None:
    """Find a name-shaped line right after a sign-off word ('Regards, <Name>')."""
    lines = [line.strip() for line in (body_text or "").splitlines() if line.strip()]
    for i, line in enumerate(lines):
        if _looks_like_signoff(line):
            for candidate in lines[i + 1 : i + 3]:
                if _NAME_LINE_RE.match(candidate):
                    return candidate
    return None


def _name_overlaps(name: str, *haystacks: str) -> bool:
    tokens = {t.lower() for t in re.findall(r"[a-zA-Z']+", name) if len(t) > 1}
    if not tokens:
        return False
    return any(tok in (haystack or "").lower() for haystack in haystacks for tok in tokens)


def _check_signature_mismatch(parsed: ParsedEmail) -> list[Finding]:
    """Body signed by a name that has nothing to do with who actually sent it.

    A classic pretexting pattern precisely *because* it leaves the technical
    headers (SPF/DKIM/DMARC, From domain) completely clean — the account
    sending the mail is real, it just isn't the person the message claims to
    be from. Keyword/domain checks alone can't see this; only comparing what
    the message signs itself as against who actually sent it can.
    """
    findings: list[Finding] = []
    signed_name = _extract_signed_name(parsed.body_text)
    if signed_name and not _name_overlaps(signed_name, parsed.from_display, parsed.from_addr):
        findings.append(
            Finding(
                category=Category.SPOOFING,
                severity=Severity.MEDIUM,
                title="Message is signed by a name that doesn't match the sender",
                detail=(
                    f"The email body is signed '{signed_name}', but the actual sending "
                    f"identity is \"{parsed.from_display}\" <{parsed.from_addr}> - nothing "
                    "ties the two together. A common pretexting pattern: sign as a real, "
                    "trusted person while actually sending from an unrelated account, "
                    "often to build rapport before a follow-up ask (e.g. 'what's your "
                    "phone number', then a fraud attempt by phone or a later email)."
                ),
                evidence=f"Signed as: {signed_name}  |  Actually from: \"{parsed.from_display}\" <{parsed.from_addr}>",
                mitre="T1656",
            )
        )
    return findings


def _check_date_like_display_name(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    display = (parsed.from_display or "").strip()
    if display and _DATE_LIKE_DISPLAY_RE.match(display):
        findings.append(
            Finding(
                category=Category.SPOOFING,
                severity=Severity.LOW,
                title="Sender display name looks like a date, not a person/organization",
                detail=(
                    f"The From display name is '{display}' - a date-shaped string rather "
                    "than an actual name. Sometimes a leftover artifact of bulk-registered "
                    "or automation-driven accounts used for outreach campaigns, rather than "
                    "a real personal or corporate identity."
                ),
                evidence=f"From display name: {display}",
            )
        )
    return findings


def analyze(parsed: ParsedEmail, indicators: dict) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_auth_results(parsed))
    findings.extend(_check_alignment(parsed))
    findings.extend(_check_brand_impersonation(parsed, indicators))
    findings.extend(_check_signature_mismatch(parsed))
    findings.extend(_check_date_like_display_name(parsed))
    return findings
