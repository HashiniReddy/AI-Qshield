
"""Explainable risk scoring for QR destination URLs."""

INDICATOR_WEIGHTS = {
    "URL_SHORTENER": 10,
    "IP_ADDRESS_HOST": 20,
    "SENSITIVE_KEYWORD": 10,
    "ENCODED_URL_DELIMITER": 15,
    "UNICODE_DOMAIN": 15,
    "MALFORMED_HOSTNAME": 25,
    "MANY_DOMAIN_LABELS": 10,
    "AT_SYMBOL_IN_AUTHORITY": 20,
    "PERCENT_ENCODING_PRESENT": 5,
}


def score_url_risk(indicators):
    """Return an explainable risk score from URL warning indicators."""

    if not isinstance(indicators, (list, tuple, set)):
        raise TypeError("indicators must be a list, tuple, or set")

    # Count each recognized indicator only once.
    unique_indicators = set(indicators)

    matched = [
        indicator
        for indicator in INDICATOR_WEIGHTS
        if indicator in unique_indicators
    ]

    score = min(
        100,
        sum(INDICATOR_WEIGHTS[indicator] for indicator in matched),
    )

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "MINIMAL"

    explanations = [
        {
            "indicator": indicator,
            "weight": INDICATOR_WEIGHTS[indicator],
            "explanation": (
                f"{indicator.replace('_', ' ').lower().capitalize()} "
                "was detected and contributes to the review score."
            ),
        }
        for indicator in matched
    ]

    return {
        "score": score,
        "risk_level": level,
        "matched_indicators": matched,
        "explanations": explanations,
        "review_recommended": score > 0,
        "scoring_note": (
            "Heuristic score for prioritizing review; "
            "not a probability or proof of maliciousness."
        ),
    }
