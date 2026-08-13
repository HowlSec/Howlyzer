import pytest
from conftest import SAMPLES

import phishanalyzer.parser as parser_module
from phishanalyzer.parser import FileTooLargeError, load_email


def test_parses_headers_and_addresses():
    parsed = load_email(SAMPLES / "sample_phish.eml")
    assert parsed.subject.startswith("Urgent:")
    assert parsed.from_addr == "security@paypa1-verify.tk"
    assert parsed.from_display == "PayPal Security"
    assert parsed.reply_to_addr == "paypal-support@totally-unrelated-domain.xyz"


def test_extracts_body_and_links():
    parsed = load_email(SAMPLES / "sample_phish.eml")
    assert "unusual activity" in parsed.body_text.lower() + parsed.body_html.lower()
    urls = parsed.urls
    assert any("paypa1-verify.tk" in u for u in urls)
    # The HTML link's visible text is a different (legitimate-looking) URL than its href.
    mismatched = [l for l in parsed.links if l.anchor_text and "paypal.com" in l.anchor_text]
    assert mismatched
    assert "paypa1-verify.tk" in mismatched[0].url


def test_extracts_attachment_with_hash():
    parsed = load_email(SAMPLES / "sample_phish.eml")
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Invoice.pdf.exe"
    assert len(att.sha256) == 64


def test_authentication_results_multi_line_preserved():
    parsed = load_email(SAMPLES / "sample_phish.eml")
    auth = parsed.headers.get("Authentication-Results", "")
    assert "spf=fail" in auth
    assert "dmarc=fail" in auth


def test_oversized_file_is_rejected_without_being_read(monkeypatch):
    # Force the limit far below the real sample's size so this test doesn't
    # need to actually create a 50 MB fixture file.
    monkeypatch.setattr(parser_module, "MAX_FILE_SIZE_BYTES", 10)
    with pytest.raises(FileTooLargeError):
        load_email(SAMPLES / "sample_phish.eml")
