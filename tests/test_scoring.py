from conftest import SAMPLES

from phishanalyzer import analyzers, scoring
from phishanalyzer.indicators import load_indicators
from phishanalyzer.parser import load_email


def _verdict_for(filename):
    parsed = load_email(SAMPLES / filename)
    findings = analyzers.run_all(parsed, load_indicators())
    return scoring.build_verdict(findings), findings


def test_phishing_sample_scores_as_phishing_or_worse():
    verdict, findings = _verdict_for("sample_phish.eml")
    assert verdict.label in ("Phishing", "Malicious — High Confidence")
    titles = {f.title for f in findings}
    assert any("does not match" in t or "Lookalike" in t or "credential-harvesting" in t for t in titles)


def test_legitimate_sample_scores_low():
    verdict, findings = _verdict_for("sample_legitimate.eml")
    assert verdict.label == "Likely Legitimate"


def test_spam_sample_is_labeled_spam_not_phishing():
    verdict, findings = _verdict_for("sample_spam.eml")
    assert verdict.label == "Spam / Unwanted"
    assert verdict.phishing_score == 0
