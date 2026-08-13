from conftest import SAMPLES

from phishanalyzer.analyzers.headers import (
    _check_date_like_display_name,
    _check_signature_mismatch,
    _extract_signed_name,
    _name_overlaps,
)
from phishanalyzer.parser import load_email


def test_extracts_signed_name_after_signoff_word():
    body = "Hi,\n\nSome message.\n\nAppreciated!\nGiles Whiting"
    assert _extract_signed_name(body) == "Giles Whiting"


def test_no_signed_name_when_body_has_no_signoff():
    body = "Hi,\n\nJust a plain message with no closing signature at all."
    assert _extract_signed_name(body) is None


def test_name_overlap_detection():
    assert _name_overlaps("Giles Whiting", "Giles Whiting", "gwhiting@example.com")
    assert not _name_overlaps("Giles Whiting", "12-Aug-26", "boardallocation56@gmail.com")


def test_pretext_sample_flags_signature_mismatch_and_date_display_name():
    parsed = load_email(SAMPLES / "sample_pretext.eml")

    sig_findings = _check_signature_mismatch(parsed)
    assert len(sig_findings) == 1
    assert "Giles Whiting" in sig_findings[0].evidence
    assert "boardallocation56@gmail.com" in sig_findings[0].evidence

    date_findings = _check_date_like_display_name(parsed)
    assert len(date_findings) == 1
    assert "12-Aug-26" in date_findings[0].evidence


def test_phish_sample_signature_matches_display_name_no_false_positive():
    # sample_phish.eml signs off "PayPal Security Team" and its From display
    # name is "PayPal Security" - these overlap, so this check must NOT also
    # fire (the existing brand-impersonation check already covers the real
    # issue there; this check is specifically for *unrelated* signed names).
    parsed = load_email(SAMPLES / "sample_phish.eml")
    assert _check_signature_mismatch(parsed) == []
