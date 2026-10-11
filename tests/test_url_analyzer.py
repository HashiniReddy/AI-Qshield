from src.url_engine.url_analyzer import analyze_url


def test_normal_url():
    result = analyze_url("https://example.com/about")

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["indicators"] == []


def test_ip_address_host():
    result = analyze_url("http://192.0.2.10/login")

    assert result["success"] is True
    assert "IP_ADDRESS_HOST" in result["indicators"]


def test_empty_url():
    result = analyze_url("")

    assert result["success"] is False


def test_invalid_scheme():
    result = analyze_url("javascript:alert(1)")

    assert result["success"] is False


def test_sensitive_keyword():
    result = analyze_url("https://example.com/verify")

    assert result["success"] is True
    assert "SENSITIVE_KEYWORD" in result["indicators"]

def test_url_shortener():
    result = analyze_url("https://bit.ly/example")

    assert result["success"] is True
    assert "URL_SHORTENER" in result["indicators"]
    assert result["review_recommended"] is True


def test_unicode_domain():
    result = analyze_url("https://пример.рф/login")

    assert result["success"] is True
    assert "UNICODE_DOMAIN" in result["indicators"]
