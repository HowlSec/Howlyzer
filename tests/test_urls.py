from phishanalyzer.analyzers.urls import _hostname, _is_ip_literal, _levenshtein, _looks_like_lookalike, _registrable_domain


def test_hostname_extraction():
    assert _hostname("https://mail.example.com/path?q=1") == "mail.example.com"
    assert _hostname("hxxp://evil.tk/login") == "evil.tk"


def test_registrable_domain():
    assert _registrable_domain("mail.example.com") == "example.com"
    assert _registrable_domain("example.com") == "example.com"


def test_ip_literal_detection():
    assert _is_ip_literal("203.0.113.5") is True
    assert _is_ip_literal("example.com") is False
    assert _is_ip_literal("999.999.999.999") is False


def test_levenshtein_distance():
    assert _levenshtein("paypal", "paypal") == 0
    assert _levenshtein("paypal", "paypa1") == 1
    assert _levenshtein("paypal", "amazon") > 2


def test_lookalike_domain_detection():
    assert _looks_like_lookalike("paypa1.com", "paypal.com") is True
    assert _looks_like_lookalike("arnazon.com", "amazon.com") is True
    assert _looks_like_lookalike("paypal.com", "paypal.com") is False
    assert _looks_like_lookalike("totally-unrelated.com", "paypal.com") is False
