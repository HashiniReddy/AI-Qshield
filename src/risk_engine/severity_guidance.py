
"""Provide analyst guidance for AI-QShield risk levels."""


SEVERITY_GUIDANCE = {
    "MINIMAL": {
        "summary": (
            "No configured risk indicators were detected."
        ),
        "recommended_action": (
            "Continue to use caution. Verify the destination "
            "before entering sensitive information."
        ),
    },
    "LOW": {
        "summary": (
            "A small number of risk indicators were detected."
        ),
        "recommended_action": (
            "Review the indicators and verify the destination "
            "before proceeding."
        ),
    },
    "MEDIUM": {
        "summary": (
            "Multiple or higher-weight indicators warrant investigation."
        ),
        "recommended_action": (
            "Investigate the flagged indicators and destination "
            "before opening the link or sharing information."
        ),
    },
    "HIGH": {
        "summary": (
            "The configured risk score is high and needs priority review."
        ),
        "recommended_action": (
            "Avoid trusting the destination until it has been "
            "independently verified by a trusted source."
        ),
    },
}


def get_severity_guidance(risk_level):
    """Return analyst guidance for a known risk level."""

    if not isinstance(risk_level, str):
        raise TypeError("risk_level must be a string")

    level = risk_level.strip().upper()

    if level not in SEVERITY_GUIDANCE:
        return {
            "summary": "Risk level is unknown or unsupported.",
            "recommended_action": (
                "Review the analysis results and verify the destination "
                "before trusting it."
            ),
        }

    return SEVERITY_GUIDANCE[level].copy()
