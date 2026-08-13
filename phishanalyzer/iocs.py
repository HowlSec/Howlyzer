"""Extracts a flat, shareable list of indicators of compromise from a ParsedEmail."""

from __future__ import annotations

from urllib.parse import urlparse

from .models import ParsedEmail


def extract_iocs(parsed: ParsedEmail) -> dict:
    domains: set[str] = set()
    urls: list[str] = []

    for link in parsed.links:
        urls.append(link.url)
        try:
            host = urlparse(link.url.replace("hxxp", "http", 1)).hostname
        except Exception:
            host = None
        if host:
            domains.add(host.lower())

    for addr in (parsed.from_addr, parsed.reply_to_addr, parsed.return_path_addr):
        if addr and "@" in addr:
            domains.add(addr.rsplit("@", 1)[-1].lower())

    hashes = [
        {"filename": a.filename, "sha256": a.sha256}
        for a in parsed.attachments
        if a.sha256
    ]

    return {
        "domains": sorted(domains),
        "urls": urls,
        "attachment_hashes": hashes,
        "sender_addresses": sorted(
            {a for a in (parsed.from_addr, parsed.reply_to_addr, parsed.return_path_addr) if a}
        ),
    }


def defang(value: str) -> str:
    """Make a URL/domain safe to paste into chat/ticketing tools without it being clickable."""
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )
