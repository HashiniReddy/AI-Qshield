
"""Format AI-QShield analysis into an investigator-friendly report."""

from src.risk_engine.severity_guidance import get_severity_guidance


DEFAULT_SCORING_NOTE = (
    "Risk scores are heuristic review signals, "
    "not proof of maliciousness."
)


def build_risk_report(analysis):
    """Build a validated, readable report from pipeline output."""

    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dictionary")

    if not analysis.get("success"):
        return {
            "success": False,
            "error": analysis.get("error") or "QR analysis failed",
        }

    risk = analysis.get("risk_assessment")

    if not isinstance(risk, dict):
        return {
            "success": False,
            "error": "Risk assessment is unavailable",
        }

    # Validate the score instead of trusting arbitrary input.
    score = risk.get("score")
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not 0 <= score <= 100
    ):
        return {
            "success": False,
            "error": "Risk score is missing or invalid",
        }

    risk_level = risk.get("risk_level")
    if not isinstance(risk_level, str) or not risk_level.strip():
        risk_level = "UNKNOWN"
    else:
        risk_level = risk_level.strip().upper()

    # Get an explanation and recommended action for the risk level.
    guidance = get_severity_guidance(risk_level)

    # Ignore malformed explanation entries safely.
    findings = risk.get("explanations", [])
    if not isinstance(findings, list):
        findings = []

    valid_findings = [
        item for item in findings
        if isinstance(item, dict)
    ]


    # Build a readable score breakdown from recognized findings.
    score_breakdown = []

    for item in valid_findings:
        weight = item.get("weight", 0)

        # Avoid displaying invalid weights.
        if (
            not isinstance(weight, (int, float))
            or isinstance(weight, bool)
        ):
            weight = 0

        score_breakdown.append({
            "indicator": item.get("indicator", "UNKNOWN"),
            "source": item.get("source", "unknown"),
            "weight": weight,
            "explanation": item.get(
                "explanation",
                "No explanation available.",
            ),
        })

    # Older results may not contain raw_score.
    raw_score = risk.get("raw_score", score)

    if (
        not isinstance(raw_score, (int, float))
        or isinstance(raw_score, bool)
        or raw_score < score
    ):
        raw_score = score

    score_cap_applied = raw_score > 100


    url_findings = [
        item for item in valid_findings
        if item.get("source") == "url_analysis"
    ]

    redirect_findings = [
        item for item in valid_findings
        if item.get("source") == "redirect_analysis"
    ]

    redirect_analysis = analysis.get("redirect_analysis")

    if redirect_analysis is None:
        redirect_status = "Not performed"
    elif (
        isinstance(redirect_analysis, dict)
        and redirect_analysis.get("success") is True
    ):
        redirect_status = "Completed"
    else:
        redirect_status = "Unavailable or unsuccessful"

    # Use either the explicit recommendation flag or detected findings.
    review_recommended = (
        risk.get("review_recommended") is True
        or bool(valid_findings)
        or score > 0
    )

    if review_recommended:
        recommendation = (
            "Review the detected indicators and destination "
            "before trusting this QR code."
        )
    else:
        recommendation = (
            "No configured risk indicators were detected. "
            "This does not guarantee the QR code is safe."
        )

    decoding = analysis.get("decoding")
    if not isinstance(decoding, dict):
        decoding = {}

    scoring_note = risk.get("scoring_note")
    if not isinstance(scoring_note, str) or not scoring_note.strip():
        scoring_note = DEFAULT_SCORING_NOTE
    # Extract threat-intelligence results safely.
    threat_intel = analysis.get("threat_intelligence")

    if not isinstance(threat_intel, dict):
        threat_intel = None

    if threat_intel is None:
        threat_intel_report = {
            "status": "Not performed",
            "provider": None,
            "hostname": None,
            "malicious_count": None,
            "suspicious_count": None,
            "error": None,
        }
    else:
        available = threat_intel.get("available") is True
        threat_intel_report = {
            "status": "Completed" if available else "Unavailable",
            "provider": threat_intel.get("provider"),
            "hostname": threat_intel.get("hostname"),
            "malicious_count": (
                threat_intel.get("malicious_count")
                if available else None
            ),
            "suspicious_count": (
                threat_intel.get("suspicious_count")
                if available else None
            ),
            "error": threat_intel.get("error"),
        }

    return {
        "success": True,
        "risk_score": score,
        "risk_level": risk_level,
        "threat_intelligence": threat_intel_report,
        "severity_summary": guidance["summary"],
        "recommended_action": guidance["recommended_action"],
        "decoded_content": decoding.get("content"),
        "url_findings": url_findings,
        "redirect_findings": redirect_findings,
        "redirect_status": redirect_status,
        "recommendation": recommendation,
        "scoring_note": scoring_note,
        "raw_risk_score": raw_score,
        "score_cap_applied": score_cap_applied,
        "score_breakdown": score_breakdown,
    }
