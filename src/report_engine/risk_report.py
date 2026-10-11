
"""Format AI-QShield analysis into an investigator-friendly report."""


def build_risk_report(analysis):
    """Build a readable report from the QR analysis pipeline output."""

    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dictionary")

    risk = analysis.get("risk_assessment")
    url_analysis = analysis.get("url_analysis")
    redirect_analysis = analysis.get("redirect_analysis")

    if not analysis.get("success"):
        return {
            "success": False,
            "error": analysis.get("error", "QR analysis failed"),
        }

    if not isinstance(risk, dict):
        return {
            "success": False,
            "error": "Risk assessment is unavailable",
        }

    findings = risk.get("explanations", [])

    url_findings = [
        item for item in findings
        if item.get("source") == "url_analysis"
    ]

    redirect_findings = [
        item for item in findings
        if item.get("source") == "redirect_analysis"
    ]

    if redirect_analysis is None:
        redirect_status = "Not performed"
    elif redirect_analysis.get("success"):
        redirect_status = "Completed"
    else:
        redirect_status = "Unavailable or unsuccessful"

    if risk.get("review_recommended"):
        recommendation = (
            "Review the detected indicators before trusting this QR code."
        )
    else:
        recommendation = (
            "No configured risk indicators were detected. "
            "This does not guarantee the QR code is safe."
        )

    return {
        "success": True,
        "risk_score": risk.get("score", 0),
        "risk_level": risk.get("risk_level", "UNKNOWN"),
        "decoded_content": (
            analysis.get("decoding", {}).get("content")
        ),
        "url_findings": url_findings,
        "redirect_findings": redirect_findings,
        "redirect_status": redirect_status,
        "recommendation": recommendation,
        "scoring_note": risk.get(
            "scoring_note",
            "Risk scores are heuristic review signals, not proof of maliciousness.",
        ),
    }
