from src.url_engine.url_analyzer import (
    analyze_url,
    is_hostname_well_formed,
)


def test_valid_hostname():
    assert is_hostname_well_formed("example.com")


def test_hostname_with_invalid_hyphen():
    assert not is_hostname_well_formed("-example.com")


def test_hostname_with_empty_label():
    assert not is_hostname_well_formed("example..com")


def test_percent_encoding_detected():
    result = analyze_url("https://example.com/%2Faccount")

    assert result["success"] is True
    assert "PERCENT_ENCODING_PRESENT" in result["indicators"]
    assert "ENCODED_URL_DELIMITER" in result["indicators"]


def test_encoded_at_symbol_detected():
    result = analyze_url("https://example.com/%40user")

    assert result["success"] is True
    assert "ENCODED_URL_DELIMITER" in result["indicators"]


def test_normal_url_still_works():
    result = analyze_url("https://example.com/about")

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["indicators"] == []

