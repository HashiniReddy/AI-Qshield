from src.domain_engine.domain_analyzer import analyze_domain


def test_simple_domain():
    result = analyze_domain("example.com")

    assert result["success"] is True
    assert result["registrable_domain"] == "example.com"
    assert result["subdomain"] is None


def test_subdomain():
    result = analyze_domain("login.example.com")

    assert result["success"] is True
    assert result["subdomain"] == "login"
    assert result["registrable_domain"] == "example.com"


def test_multi_part_public_suffix():
    result = analyze_domain("login.example.co.uk")

    assert result["success"] is True
    assert result["subdomain"] == "login"
    assert result["registrable_domain"] == "example.co.uk"


def test_ipv4_address():
    result = analyze_domain("192.0.2.10")

    assert result["success"] is True
    assert result["is_ip_address"] is True
    assert result["ip_version"] == 4


def test_empty_hostname():
    result = analyze_domain("")

    assert result["success"] is False
