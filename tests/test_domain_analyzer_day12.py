from src.domain_engine.domain_analyzer import analyze_domain


def test_punycode_hostname():
    result = analyze_domain("xn--e1afmkfd.com")

    assert result["success"] is True
    assert "PUNYCODE_HOSTNAME" in result["indicators"]


def test_many_subdomains():
    result = analyze_domain("a.b.c.example.com")

    assert result["success"] is True
    assert "MANY_SUBDOMAINS" in result["indicators"]


def test_hyphenated_domain():
    result = analyze_domain("secure-example.com")

    assert result["success"] is True
    assert "HYPHENATED_DOMAIN" in result["indicators"]


def test_normal_domain_has_no_indicators():
    result = analyze_domain("example.com")

    assert result["success"] is True
    assert result["indicators"] == []


def test_ip_address_indicator():
    result = analyze_domain("192.0.2.10")

    assert result["success"] is True
    assert "IP_ADDRESS_HOST" in result["indicators"]
