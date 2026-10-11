
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

from src.attack_fingerprint.attack_fingerprinter import (
    correlate_attack_evidence,
)


def test_no_fingerprints_returns_no_evidence():
    result = correlate_attack_evidence([])

    assert result["evidence_level"] == "NO_EVIDENCE"
    assert result["source_count"] == 0


def test_one_source_returns_single_source():
    result = correlate_attack_evidence([
        {
            "fingerprint_id": "QR-URL-001",
            "source": "url_analysis",
        }
    ])

    assert result["evidence_level"] == "SINGLE_SOURCE"
    assert result["source_count"] == 1


def test_two_sources_return_corroborated():
    result = correlate_attack_evidence([
        {
            "fingerprint_id": "QR-URL-001",
            "source": "url_analysis",
        },
        {
            "fingerprint_id": "QR-REDIRECT-001",
            "source": "redirect_analysis",
        },
    ])

    assert result["evidence_level"] == "CORROBORATED"
    assert result["source_count"] == 2


def test_three_sources_return_multi_source():
    result = correlate_attack_evidence([
        {"source": "url_analysis"},
        {"source": "redirect_analysis"},
        {"source": "threat_intelligence"},
    ])

    assert result["evidence_level"] == "MULTI_SOURCE"
    assert result["source_count"] == 3


def test_duplicate_sources_are_counted_once():
    result = correlate_attack_evidence([
        {"source": "url_analysis"},
        {"source": "url_analysis"},
    ])

    assert result["source_count"] == 1
    assert result["fingerprint_count"] == 2


def test_malformed_input_is_handled():
    result = correlate_attack_evidence([
        None,
        "invalid",
        {"source": "unknown_source"},
    ])

    assert result["evidence_level"] == "NO_EVIDENCE"
    assert result["source_count"] == 0
