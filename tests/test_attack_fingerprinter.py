
from src.attack_fingerprint.attack_fingerprinter import (
    identify_attack_fingerprints,
)


def test_clean_evidence_returns_no_fingerprints():
    result = identify_attack_fingerprints(
        url_analysis={"indicators": []},
        redirect_analysis=None,
        threat_intelligence=None,
    )

    assert result == []


def test_suspicious_url_creates_url_fingerprint():
    result = identify_attack_fingerprints(
        url_analysis={"indicators": ["URL_SHORTENER"]},
    )

    assert len(result) == 1
    assert result[0]["fingerprint_id"] == "QR-URL-001"
    assert result[0]["matched_indicators"] == ["URL_SHORTENER"]


def test_risky_redirect_creates_redirect_fingerprint():
    result = identify_attack_fingerprints(
        redirect_analysis={
            "success": True,
            "indicators": ["HTTPS_DOWNGRADE"],
        },
    )

    assert len(result) == 1
    assert result[0]["fingerprint_id"] == "QR-REDIRECT-001"


def test_malicious_reputation_creates_threat_fingerprint():
    result = identify_attack_fingerprints(
        threat_intelligence={
            "available": True,
            "malicious_count": 2,
        },
    )

    assert len(result) == 1
    assert result[0]["fingerprint_id"] == "QR-THREAT-001"


def test_unavailable_threat_intelligence_is_not_a_match():
    result = identify_attack_fingerprints(
        threat_intelligence={
            "available": False,
            "malicious_count": None,
        },
    )

    assert result == []


def test_multiple_evidence_sources_can_match():
    result = identify_attack_fingerprints(
        url_analysis={"indicators": ["IP_ADDRESS_HOST"]},
        redirect_analysis={
            "success": True,
            "indicators": ["REDIRECT_LOOP"],
        },
        threat_intelligence={
            "available": True,
            "malicious_count": 1,
        },
    )

    assert len(result) == 3
    assert {
        item["fingerprint_id"] for item in result
    } == {
        "QR-URL-001",
        "QR-REDIRECT-001",
        "QR-THREAT-001",
    }
