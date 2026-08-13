"""Loads .eml and .msg files into a normalized ParsedEmail.

Static parsing only: nothing here ever opens a network connection, resolves
a domain, or executes attachment content. Attachments are hashed as raw
bytes and otherwise left alone.
"""

from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.message import Message
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path

from .models import Attachment, ExtractedLink, ParsedEmail

# A reported phishing email is realistically a few KB to a few MB. 50 MB is
# generous enough for legitimate large attachments while still refusing to
# load an arbitrarily huge (possibly malicious, memory-exhaustion-intended)
# file fully into memory just because someone pointed the tool at it.
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024


class FileTooLargeError(ValueError):
    """Raised when an input file exceeds MAX_FILE_SIZE_BYTES."""


_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|hxxps?://|www\.)
    [^\s<>"'\]\)]+
    """
)


class _AnchorExtractor(HTMLParser):
    """Pulls (href, visible text) pairs out of HTML without rendering anything."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[ExtractedLink] = []
        self._in_a = False
        self._href = ""
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = next((v for k, v in attrs if k.lower() == "href" and v), "")
            if href:
                self._in_a = True
                self._href = href
                self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_a:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._in_a:
            text = "".join(self._text_parts).strip()
            self.links.append(ExtractedLink(url=self._href.strip(), anchor_text=text))
            self._in_a = False
            self._href = ""
            self._text_parts = []


def _extract_html_links(html_body: str) -> list[ExtractedLink]:
    parser = _AnchorExtractor()
    try:
        parser.feed(html_body)
    except Exception:
        pass
    return parser.links


def _extract_bare_urls(text: str) -> list[ExtractedLink]:
    return [ExtractedLink(url=m.group(0).rstrip(".,;:)]\"'")) for m in _URL_RE.finditer(text or "")]


def _addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _first_addr(header_value: str) -> str:
    parsed = getaddresses([header_value]) if header_value else []
    return parsed[0][1].lower() if parsed else ""


def _walk_parts(msg: Message) -> tuple[str, str, list[Attachment]]:
    """Return (body_text, body_html, attachments) for a parsed email.Message."""
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[Attachment] = []

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        is_attachment = disposition == "attachment" or (filename and disposition != "inline")

        if is_attachment or (filename and content_type not in ("text/plain", "text/html")):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest() if payload else "",
                    raw=payload,
                )
            )
            continue

        if content_type == "text/plain":
            try:
                body_text_parts.append(part.get_content())
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                body_html_parts.append(part.get_content())
            except Exception:
                pass

    return "\n".join(body_text_parts), "\n".join(body_html_parts), attachments


def _flatten_headers(msg: Message) -> dict[str, str]:
    """Collapse email.Message headers into a plain dict without losing repeats.

    Headers like Authentication-Results and Received legitimately appear once
    per hop. A naive dict comprehension keeps only the last occurrence; join
    repeats instead so analyzers can see the full picture.
    """
    headers: dict[str, str] = {}
    for k, v in msg.items():
        sv = str(v)
        if k in headers:
            headers[k] = f"{headers[k]}\n---\n{sv}"
        else:
            headers[k] = sv
    return headers


def _parse_eml_bytes(raw: bytes, source_path: str) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.default)

    headers = _flatten_headers(msg)
    body_text, body_html, attachments = _walk_parts(msg)

    links = _extract_html_links(body_html) + _extract_bare_urls(body_text)

    from_display = ""
    from_addr = ""
    from_header = headers.get("From", "")
    if from_header:
        addresses = getaddresses([from_header])
        if addresses:
            from_display, from_addr = addresses[0]
            from_addr = from_addr.lower()

    return ParsedEmail(
        source_path=source_path,
        headers=headers,
        subject=headers.get("Subject", ""),
        from_display=from_display,
        from_addr=from_addr,
        reply_to_addr=_first_addr(headers.get("Reply-To", "")),
        return_path_addr=_first_addr(headers.get("Return-Path", "")),
        to_addrs=[a for _, a in getaddresses([headers.get("To", "")])],
        date=headers.get("Date", ""),
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
    )


def _parse_msg_file(path: Path) -> ParsedEmail:
    try:
        import extract_msg
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "Reading .msg (Outlook) files requires the optional 'extract-msg' "
            "package. Install it with: pip install extract-msg"
        ) from exc

    msg = extract_msg.Message(str(path))
    try:
        headers = dict(msg.header.items()) if msg.header else {}
        body_text = msg.body or ""
        body_html = msg.htmlBody.decode("utf-8", "ignore") if isinstance(msg.htmlBody, bytes) else (msg.htmlBody or "")

        links = _extract_html_links(body_html) + _extract_bare_urls(body_text)

        attachments: list[Attachment] = []
        for att in msg.attachments:
            try:
                data = att.data or b""
            except Exception:
                data = b""
            attachments.append(
                Attachment(
                    filename=getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "(unnamed)",
                    content_type=getattr(att, "mimetype", "") or "application/octet-stream",
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest() if data else "",
                    raw=data,
                )
            )

        from_display = msg.sender or ""
        from_addr = (_extract_addr_from_display(msg.sender) or getattr(msg, "senderEmailAddress", "") or "").lower()

        return ParsedEmail(
            source_path=str(path),
            headers=headers,
            subject=msg.subject or "",
            from_display=from_display,
            from_addr=from_addr,
            reply_to_addr=(getattr(msg, "replyTo", "") or "").lower(),
            return_path_addr=(headers.get("Return-Path", "") or "").strip("<>").lower(),
            to_addrs=[a.strip() for a in (msg.to or "").split(";") if a.strip()],
            date=str(getattr(msg, "date", "") or ""),
            body_text=body_text,
            body_html=body_html,
            links=links,
            attachments=attachments,
        )
    finally:
        try:
            msg.close()
        except Exception:
            pass


def _extract_addr_from_display(display: str | None) -> str:
    if not display:
        return ""
    addresses = getaddresses([display])
    return addresses[0][1] if addresses else ""


def load_email(path: str | Path) -> ParsedEmail:
    """Load a .eml or .msg file into a normalized ParsedEmail.

    Files without a recognized extension are treated as .eml (most
    "forwarded/saved phishing report" files are RFC822 text even when
    saved with a generic name).
    """
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"{path} is {size / 1_048_576:.1f} MB, over the {MAX_FILE_SIZE_BYTES / 1_048_576:.0f} MB "
            "limit for a reported email. Refusing to load it fully into memory."
        )

    suffix = path.suffix.lower()

    if suffix == ".msg":
        return _parse_msg_file(path)

    raw = path.read_bytes()
    return _parse_eml_bytes(raw, str(path))
