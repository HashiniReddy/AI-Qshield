
import pytest

from src.report_engine.risk_report import build_risk_report


def sample_analysis():
    return {
        "success": True,
        "decoding": {"content": "https://example.com"},
        "url_analysis": {"success": True, "indicators": []},
        "redirect_analysis": None,
        "risk_assessment": {
            "score": 35,
            "risk_level": "MEDIUM",
            "matched_indicators": [
                "URL_SHORTENER",
                "HTTPS_DOWNGRADE",
            ],
            "explanations": [
                {
                    "indicator": "URL_SHORTENER",
                    "source": "url_analysis",
                    "weight": 10,
                    "explanation": "A URL shortener was detected.",
                },
                {
                    "indicator": "HTTPS_DOWNGRADE",
                    "source": "redirect_analysis",
                    "weight": 25,
                    "explanation": "HTTPS was downgraded.",
                },
            ],
            "review_recommended": True,
            "scoring_note": "Heuristic score, not proof of maliciousness.",
        },
    }


def test_report_separates_findings_by_source():
    report = build_risk_report(sample_analysis())

    assert len(report["url_findings"]) == 1
    assert len(report["redirect_findings"]) == 1


def test_report_includes_risk_summary():
    report = build_risk_report(sample_analysis())

    assert report["risk_score"] == 35
    assert report["risk_level"] == "MEDIUM"
    assert report["decoded_content"] == "https://example.com"


def test_report_marks_redirect_analysis_not_performed():
    report = build_risk_report(sample_analysis())

    assert report["redirect_status"] == "Not performed"


def test_report_recommends_review_when_indicators_exist():
    report = build_risk_report(sample_analysis())

    assert report["recommendation"].startswith("Review the detected")


def test_report_handles_failed_qr_analysis():
    report = build_risk_report({
        "success": False,
        "error": "QR code could not be decoded",
    })

    assert report["success"] is False
    assert report["error"] == "QR code could not be decoded"


def test_report_handles_missing_risk_assessment():
    report = build_risk_report({
        "success": True,
        "risk_assessment": None,
    })

    assert report["success"] is False
    assert report["error"] == "Risk assessment is unavailable"


def test_report_rejects_invalid_input():
    with pytest.raises(TypeError):
        build_risk_report("invalid")

def test_report_rejects_invalid_risk_score():
    analysis = sample_analysis()
    analysis["risk_assessment"]["score"] = 150

    report = build_risk_report(analysis)

    assert report["success"] is False
    assert report["error"] == "Risk score is missing or invalid"


def test_report_handles_malformed_findings():
    analysis = sample_analysis()
    analysis["risk_assessment"]["explanations"] = [
        None,
        "invalid finding",
        {
            "indicator": "URL_SHORTENER",
            "source": "url_analysis",
            "weight": 10,
            "explanation": "A URL shortener was detected.",
        },
    ]

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert len(report["url_findings"]) == 1
    assert report["redirect_findings"] == []


def test_report_handles_missing_decoding_data():
    analysis = sample_analysis()
    analysis.pop("decoding")

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["decoded_content"] is None


def test_report_recommends_review_for_positive_score():
    analysis = sample_analysis()
    analysis["risk_assessment"]["score"] = 10
    analysis["risk_assessment"]["review_recommended"] = False
    analysis["risk_assessment"]["explanations"] = []

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert "Review" in report["recommendation"]
def test_report_includes_severity_guidance():
    analysis = {
        "success": True,
        "risk_assessment": {
            "score": 80,
            "risk_level": "HIGH",
            "explanations": [],
            "review_recommended": True,
        },
        "decoding": {"content": "https://example.com"},
    }

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["severity_summary"]
    assert report["recommended_action"]
    assert "high" in report["severity_summary"].lower()

def test_report_includes_available_threat_intelligence():
    analysis = sample_analysis() 
    analysis["threat_intelligence"] = {
        "success": True,
        "hostname": "example.com",
        "provider": "VirusTotal",
        "available": True,
        "malicious_count": 2,
        "suspicious_count": 1,
        "error": None,
    }

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["threat_intelligence"]["status"] == "Completed"
    assert report["threat_intelligence"]["provider"] == "VirusTotal"
    assert report["threat_intelligence"]["hostname"] == "example.com"
    assert report["threat_intelligence"]["malicious_count"] == 2
    assert report["threat_intelligence"]["suspicious_count"] == 1


def test_report_handles_unavailable_threat_intelligence():
    analysis = sample_analysis()
    analysis["threat_intelligence"] = {
        "success": False,
        "hostname": "example.com",
        "provider": "VirusTotal",
        "available": False,
        "malicious_count": None,
        "suspicious_count": None,
        "error": "VirusTotal rate limit reached",
    }

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["threat_intelligence"]["status"] == "Unavailable"
    assert report["threat_intelligence"]["malicious_count"] is None
    assert report["threat_intelligence"]["suspicious_count"] is None
    assert report["threat_intelligence"]["error"] == (
        "VirusTotal rate limit reached"
    )

def test_report_includes_score_breakdown():
    report = build_risk_report(sample_analysis())

    assert report["success"] is True
    assert report["raw_risk_score"] == 35
    assert report["score_cap_applied"] is False
    assert len(report["score_breakdown"]) == 2

    first = report["score_breakdown"][0]
    assert first["indicator"] == "URL_SHORTENER"
    assert first["source"] == "url_analysis"
    assert first["weight"] == 10
    assert first["explanation"] == (
        "A URL shortener was detected."
    )


def test_report_uses_score_when_raw_score_is_missing():
    report = build_risk_report(sample_analysis())

    assert report["raw_risk_score"] == 35
    assert report["score_cap_applied"] is False


def test_report_handles_raw_score_above_cap():
    analysis = sample_analysis()
    analysis["risk_assessment"]["score"] = 100
    analysis["risk_assessment"]["raw_score"] = 125

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["risk_score"] == 100
    assert report["raw_risk_score"] == 125
    assert report["score_cap_applied"] is True
def test_report_includes_attack_fingerprints():
    analysis = sample_analysis()
    analysis["attack_fingerprints"] = [
        {
            "fingerprint_id": "QR-URL-001",
            "name": "Suspicious URL Structure",
            "matched_indicators": ["URL_SHORTENER"],
            "source": "url_analysis",
            "explanation": "The URL has a structural indicator.",
            "recommended_action": "Inspect the destination.",
        }
    ]

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert len(report["attack_fingerprints"]) == 1
    assert (
        report["attack_fingerprints"][0]["fingerprint_id"]
        == "QR-URL-001"
    )


def test_report_handles_malformed_attack_fingerprints():
    analysis = sample_analysis()
    analysis["attack_fingerprints"] = [
        None,
        "invalid",
        {"fingerprint_id": "QR-URL-001"},
    ]

    report = build_risk_report(analysis)

    assert report["success"] is True
    assert report["attack_fingerprints"] == [
        {"fingerprint_id": "QR-URL-001"}
    ]
def test_report_includes_evidence_correlation():
    analysis = sample_analysis()
    analysis["evidence_correlation"] = {
        "evidence_level": "CORROBORATED",
        "fingerprint_count": 2,
        "source_count": 2,
        "sources": ["url_analysis", "redirect_analysis"],
        "explanation": "Findings appear across two evidence sources.",
    }

    report = build_risk_report(analysis)

    assert report["evidence_correlation"]["evidence_level"] == (
        "CORROBORATED"
    )
    assert report["evidence_correlation"]["fingerprint_count"] == 2
    assert report["evidence_correlation"]["source_count"] == 2


def test_report_handles_missing_evidence_correlation():
    report = build_risk_report(sample_analysis())

    assert report["evidence_correlation"]["evidence_level"] == (
        "NO_EVIDENCE"
    )
    assert report["evidence_correlation"]["source_count"] == 0
