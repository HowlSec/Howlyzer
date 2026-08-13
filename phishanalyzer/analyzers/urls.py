"""Static URL/link analysis. Never fetches, resolves, or connects to anything -
every check here works purely off the URL string as written in the email."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..models import Category, Finding, ParsedEmail, Severity

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize(url: str) -> str:
    return re.sub(r"^hxxp", "http", url.strip(), flags=re.IGNORECASE)


def _hostname(url: str) -> str:
    try:
        parsed = urlparse(_normalize(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _registrable_domain(host: str) -> str:
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _is_ip_literal(host: str) -> bool:
    if _IPV4_RE.match(host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    return host.startswith("[") and host.endswith("]")  # IPv6 literal in a URL


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _looks_like_lookalike(domain: str, real_domain: str) -> bool:
    """Cheap, high-signal typosquat check: same length ballpark, 1-2 edits away."""
    if domain == real_domain:
        return False
    base = real_domain.split(".")[0]
    candidate = domain.split(".")[0]
    if abs(len(candidate) - len(base)) > 2:
        return False
    distance = _levenshtein(candidate, base)
    return 0 < distance <= 2


def _dedupe_links(links: list) -> list:
    """Collapse the same URL appearing in both the text/plain and text/html
    parts of a multipart/alternative message (the normal case for almost
    every HTML email) into one entry, preferring whichever copy carries
    anchor text (only HTML <a> tags have it)."""
    by_url: dict[str, object] = {}
    order: list[str] = []
    for link in links:
        existing = by_url.get(link.url)
        if existing is None:
            by_url[link.url] = link
            order.append(link.url)
        elif not existing.anchor_text and link.anchor_text:
            by_url[link.url] = link
    return [by_url[u] for u in order]


def analyze(parsed: ParsedEmail, indicators: dict) -> list[Finding]:
    findings: list[Finding] = []
    shorteners = set(indicators.get("url_shorteners", []))
    suspicious_tlds = tuple(indicators.get("suspicious_tlds", []))
    cred_paths = tuple(p.lower() for p in indicators.get("credential_harvest_paths", []))
    brands: dict[str, list[str]] = indicators.get("impersonated_brands", {})
    real_domains = {
        _registrable_domain(d) for domains in brands.values() for d in domains
    }

    seen_hosts: set[str] = set()

    for link in _dedupe_links(parsed.links):
        host = _hostname(link.url)
        if not host:
            continue

        reg_domain = _registrable_domain(host)
        parsed_url = urlparse(_normalize(link.url))
        path = (parsed_url.path or "").lower()

        if _is_ip_literal(host):
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.HIGH,
                    title="Link points directly to an IP address",
                    detail="Legitimate services essentially never link using a bare IP "
                    "address instead of a domain name. Strong phishing/malware-delivery signal.",
                    evidence=link.url,
                    mitre="T1566.002",
                )
            )

        if host in shorteners:
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.MEDIUM,
                    title="Link uses a URL shortener",
                    detail=f"'{host}' hides the real destination. Shorteners are widely used "
                    "in phishing to disguise malicious links and bypass keyword filters.",
                    evidence=link.url,
                )
            )

        if "@" in (parsed_url.netloc or ""):
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.HIGH,
                    title="URL uses the userinfo '@' trick",
                    detail="Everything before '@' in a URL's authority section is ignored by "
                    "browsers - text made to look like a trusted domain can precede '@' while "
                    "the real destination follows it.",
                    evidence=link.url,
                    mitre="T1566.002",
                )
            )

        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.HIGH,
                    title="Punycode (IDN) domain - possible homograph attack",
                    detail=f"'{host}' contains an xn-- encoded label. This is how lookalike "
                    "domains using non-Latin characters that visually resemble a trusted "
                    "brand's domain are represented under the hood.",
                    evidence=link.url,
                    mitre="T1566.002",
                )
            )

        if suspicious_tlds and host.endswith(suspicious_tlds):
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.LOW,
                    title="Link uses a high-abuse TLD",
                    detail=f"'{host}' uses a top-level domain that is disproportionately "
                    "represented in phishing/spam campaigns due to low registration cost "
                    "and weak vetting. Not proof of malice on its own.",
                    evidence=link.url,
                    phishing_signal=False,
                )
            )

        label_count = host.count(".")
        if label_count >= 4:
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.MEDIUM,
                    title="Unusually deep subdomain nesting",
                    detail=f"'{host}' has {label_count + 1} labels. A common trick is burying "
                    "a trusted brand name in a subdomain of an attacker-owned domain, e.g. "
                    "'paypal.com.verify-account.example.xyz'.",
                    evidence=link.url,
                )
            )

        if reg_domain not in real_domains and any(cred_path in path for cred_path in cred_paths):
            findings.append(
                Finding(
                    category=Category.URL,
                    severity=Severity.MEDIUM,
                    title="Link path suggests a credential-harvesting page",
                    detail=f"The URL path ('{path}') matches patterns commonly used by "
                    "fake login/verification pages.",
                    evidence=link.url,
                    mitre="T1566.002",
                )
            )

        # Brand impersonation via hostname: brand name appears in the host but
        # the registrable domain isn't actually the brand's real domain.
        for brand, domains in brands.items():
            brand_token = brand.lower().replace(" ", "")
            host_norm = host.replace("-", "").replace(".", "")
            brand_real_domains = {_registrable_domain(d) for d in domains}
            if brand_token in host_norm and reg_domain not in brand_real_domains:
                findings.append(
                    Finding(
                        category=Category.URL,
                        severity=Severity.CRITICAL,
                        title=f"Link references '{brand}' but is not hosted on {brand}'s domain",
                        detail=f"'{host}' contains '{brand}' but resolves to registrable domain "
                        f"'{reg_domain}', not one of {brand}'s real domains ({', '.join(domains)}).",
                        evidence=link.url,
                        mitre="T1566.002",
                    )
                )
                break

        # Lookalike / typosquat check against known brand domains (edit distance).
        if reg_domain not in seen_hosts:
            seen_hosts.add(reg_domain)
            for real in real_domains:
                if _looks_like_lookalike(reg_domain, real):
                    findings.append(
                        Finding(
                            category=Category.URL,
                            severity=Severity.CRITICAL,
                            title="Lookalike domain (likely typosquat)",
                            detail=f"'{reg_domain}' is only a couple of characters different "
                            f"from the known legitimate domain '{real}'. Classic typosquatting.",
                            evidence=link.url,
                            mitre="T1566.002",
                        )
                    )

        # Anchor text vs actual destination mismatch (HTML links only).
        if link.anchor_text:
            text_host = _hostname(link.anchor_text) or (
                link.anchor_text.strip().lower() if "." in link.anchor_text and " " not in link.anchor_text.strip() else ""
            )
            if text_host and _registrable_domain(text_host) not in ("", reg_domain):
                findings.append(
                    Finding(
                        category=Category.URL,
                        severity=Severity.HIGH,
                        title="Visible link text does not match the real destination",
                        detail=f"The link displays as '{link.anchor_text.strip()}' but actually "
                        f"points to '{host}'. Displaying one domain while linking to another is "
                        "a deliberate deception technique.",
                        evidence=f"shown: {link.anchor_text.strip()!r}  actual: {link.url}",
                        mitre="T1566.002",
                    )
                )

    return findings
