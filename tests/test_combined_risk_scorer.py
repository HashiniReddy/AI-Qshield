
import pytest

from src.risk_engine.url_risk_scorer import score_combined_risk


def test_clean_url_has_minimal_combined_risk():
    result = score_combined_risk([])

    assert result["score"] == 0
    assert result["risk_level"] == "MINIMAL"
    assert result["review_recommended"] is False


def test_url_and_redirect_findings_are_combined():
    result = score_combined_risk(
        ["URL_SHORTENER"],
        {
            "success": True,
            "indicators": ["HTTPS_DOWNGRADE", "FINAL_HOST_DIFFERS"],
        },
    )

    assert result["score"] == 45
    assert result["risk_level"] == "MEDIUM"
    assert len(result["explanations"]) == 3


def test_score_is_capped_at_100():
    result = score_combined_risk(
        ["MALFORMED_HOSTNAME", "IP_ADDRESS_HOST"],
        {
            "success": True,
            "indicators": [
                "HTTPS_DOWNGRADE",
                "REDIRECT_LOOP",
                "NON_PUBLIC_IP_DESTINATION",
                "LOCALHOST_DESTINATION",
            ],
        },
    )

    assert result["score"] == 100
    assert result["risk_level"] == "HIGH"


def test_unknown_indicators_are_ignored():
    result = score_combined_risk(
        ["UNKNOWN_URL_INDICATOR"],
        {"success": True, "indicators": ["UNKNOWN_REDIRECT_INDICATOR"]},
    )

    assert result["score"] == 0
    assert result["matched_indicators"] == []


def test_invalid_url_indicators_raise_type_error():
    with pytest.raises(TypeError):
        score_combined_risk("URL_SHORTENER")


def test_invalid_redirect_analysis_raises_type_error():
    with pytest.raises(TypeError):
        score_combined_risk([], redirect_analysis="invalid")
