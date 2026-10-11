
import pytest

from src.risk_engine.url_risk_scorer import score_url_risk


def test_clean_url_has_minimal_risk():
    result = score_url_risk([])

    assert result["score"] == 0
    assert result["risk_level"] == "MINIMAL"
    assert result["review_recommended"] is False


def test_single_indicator():
    result = score_url_risk(["URL_SHORTENER"])

    assert result["score"] == 10
    assert result["risk_level"] == "LOW"
    assert result["review_recommended"] is True


def test_multiple_indicators_add_up():
    result = score_url_risk(
        ["IP_ADDRESS_HOST", "SENSITIVE_KEYWORD"]
    )

    assert result["score"] == 30
    assert result["risk_level"] == "LOW"


def test_duplicate_indicators_count_once():
    result = score_url_risk(
        ["URL_SHORTENER", "URL_SHORTENER"]
    )

    assert result["score"] == 10


def test_score_is_capped_at_100():
    result = score_url_risk(
        [
            "MALFORMED_HOSTNAME",
            "IP_ADDRESS_HOST",
            "AT_SYMBOL_IN_AUTHORITY",
            "ENCODED_URL_DELIMITER",
            "UNICODE_DOMAIN",
            "URL_SHORTENER",
        ]
    )

    assert result["score"] == 100
    assert result["risk_level"] == "HIGH"


def test_unknown_indicators_are_ignored():
    result = score_url_risk(["UNKNOWN_INDICATOR"])

    assert result["score"] == 0
    assert result["matched_indicators"] == []


def test_invalid_input_raises_type_error():
    with pytest.raises(TypeError):
        score_url_risk("URL_SHORTENER")

def test_url_indicator_has_human_readable_explanation():
    result = score_url_risk(["URL_SHORTENER"])

    finding = result["explanations"][0]

    assert finding["indicator"] == "URL_SHORTENER"
    assert finding["explanation"] == (
        "The URL uses a shortening service that may hide "
        "the final destination."
    )


def test_raw_score_matches_score_when_below_cap():
    result = score_url_risk(
        ["URL_SHORTENER", "IP_ADDRESS_HOST"]
    )

    assert result["raw_score"] == 30
    assert result["score"] == 30


def test_raw_score_preserves_total_before_cap():
    result = score_url_risk(
        [
            "MALFORMED_HOSTNAME",
            "IP_ADDRESS_HOST",
            "AT_SYMBOL_IN_AUTHORITY",
            "ENCODED_URL_DELIMITER",
            "UNICODE_DOMAIN",
            "URL_SHORTENER",
        ]
    )

    assert result["raw_score"] == 105
    assert result["score"] == 100
