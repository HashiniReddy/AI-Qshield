
import pytest

from src.threat_intel.threat_intel_client import (
    build_intelligence_result,
)


def test_successful_intelligence_result():
    result = build_intelligence_result(
        hostname="Example.COM.",
        provider="TestProvider",
        available=True,
        malicious_count=2,
        suspicious_count=1,
    )

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["malicious_count"] == 2
    assert result["suspicious_count"] == 1


def test_unavailable_provider_returns_safe_result():
    result = build_intelligence_result(
        hostname="example.com",
        provider="TestProvider",
        available=False,
        error="Service unavailable",
    )

    assert result["success"] is False
    assert result["available"] is False
    assert result["malicious_count"] is None
    assert result["error"] == "Service unavailable"


def test_empty_hostname_is_rejected():
    with pytest.raises(ValueError):
        build_intelligence_result(
            hostname=" ",
            provider="TestProvider",
            available=True,
            malicious_count=0,
            suspicious_count=0,
        )


def test_invalid_availability_type_is_rejected():
    with pytest.raises(TypeError):
        build_intelligence_result(
            hostname="example.com",
            provider="TestProvider",
            available="yes",
        )


@pytest.mark.parametrize("count", [-1, 1.5, True, None])
def test_invalid_malicious_count_is_rejected(count):
    with pytest.raises(ValueError):
        build_intelligence_result(
            hostname="example.com",
            provider="TestProvider",
            available=True,
            malicious_count=count,
            suspicious_count=0,
        )

from unittest.mock import Mock, patch

import requests

from src.threat_intel.threat_intel_client import lookup_domain_reputation


@patch("src.threat_intel.threat_intel_client.requests.get")
def test_virustotal_success(mock_get):
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 5,
                }
            }
        }
    }
    mock_get.return_value = response

    result = lookup_domain_reputation(
        "example.com",
        api_key="test-key",
    )

    assert result["success"] is True
    assert result["hostname"] == "example.com"
    assert result["malicious_count"] == 3
    assert result["suspicious_count"] == 2
    mock_get.assert_called_once()


@patch("src.threat_intel.threat_intel_client.requests.get")
def test_virustotal_rate_limit(mock_get):
    response = Mock()
    response.status_code = 429
    mock_get.return_value = response

    result = lookup_domain_reputation(
        "example.com",
        api_key="test-key",
    )

    assert result["success"] is False
    assert "rate limit" in result["error"].lower()


@patch("src.threat_intel.threat_intel_client.requests.get")
def test_virustotal_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    result = lookup_domain_reputation(
        "example.com",
        api_key="test-key",
    )

    assert result["success"] is False
    assert "timed out" in result["error"].lower()


def test_virustotal_rejects_full_url():
    import pytest

    with pytest.raises(ValueError):
        lookup_domain_reputation(
            "https://example.com/path",
            api_key="test-key",
        )


@patch("src.threat_intel.threat_intel_client.requests.get")
def test_virustotal_missing_api_key(mock_get):
    result = lookup_domain_reputation(
        "example.com",
        api_key="",
    )

    assert result["success"] is False
    assert "API key" in result["error"]
    mock_get.assert_not_called()
