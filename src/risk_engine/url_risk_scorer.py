
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

REDIRECT_INDICATOR_WEIGHTS = {
    "HTTPS_DOWNGRADE": 25,
    "REDIRECT_LOOP": 25,
    "REDIRECT_LIMIT_REACHED": 15,
    "FINAL_HOST_DIFFERS": 10,
    "NON_PUBLIC_IP_DESTINATION": 30,
    "LOCALHOST_DESTINATION": 30,
    "INVALID_DESTINATION": 25,
    "UNSAFE_REDIRECT_SCHEME": 30,
}


def score_combined_risk(url_indicators, redirect_analysis=None):
    """Score URL and redirect findings with explanations."""

    if not isinstance(url_indicators, (list, tuple, set)):
        raise TypeError("url_indicators must be a list, tuple, or set")

    if redirect_analysis is not None and not isinstance(
        redirect_analysis, dict
    ):
        raise TypeError("redirect_analysis must be a dictionary or None")

    url_findings = set(url_indicators)
    redirect_findings = set()

    if redirect_analysis is not None:
        indicators = redirect_analysis.get("indicators", [])

        if not isinstance(indicators, (list, tuple, set)):
            raise TypeError("redirect indicators must be a list, tuple, or set")

        redirect_findings = set(indicators)

    matched_url = [
        item for item in INDICATOR_WEIGHTS if item in url_findings
    ]
    matched_redirect = [
        item
        for item in REDIRECT_INDICATOR_WEIGHTS
        if item in redirect_findings
    ]

    explanations = []

    for item in matched_url:
        explanations.append({
            "indicator": item,
            "source": "url_analysis",
            "weight": INDICATOR_WEIGHTS[item],
            "explanation": (
                f"URL indicator {item} was detected."
            ),
        })

    for item in matched_redirect:
        explanations.append({
            "indicator": item,
            "source": "redirect_analysis",
            "weight": REDIRECT_INDICATOR_WEIGHTS[item],
            "explanation": (
                f"Redirect indicator {item} was detected."
            ),
        })

    raw_score = sum(item["weight"] for item in explanations)
    score = min(100, raw_score)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "MINIMAL"

    return {
        "score": score,
        "risk_level": level,
        "matched_indicators": [
            item["indicator"] for item in explanations
        ],
        "explanations": explanations,
        "review_recommended": score > 0,
        "scoring_note": (
            "Combined heuristic score for prioritizing review; "
            "not a probability or proof of maliciousness."
        ),
    }
