
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

URL_INDICATOR_EXPLANATIONS = {
    "URL_SHORTENER": (
        "The URL uses a shortening service that may hide "
        "the final destination."
    ),
    "IP_ADDRESS_HOST": (
        "The destination uses an IP address instead of a "
        "domain name. Verify that the address is trusted."
    ),
    "SENSITIVE_KEYWORD": (
        "The URL contains a keyword associated with sensitive "
        "actions. Check the destination and context."
    ),
    "ENCODED_URL_DELIMITER": (
        "Encoded URL delimiters may make the destination "
        "harder to interpret."
    ),
    "UNICODE_DOMAIN": (
        "The domain contains Unicode characters. Check for "
        "characters that resemble letters from other scripts."
    ),
    "MALFORMED_HOSTNAME": (
        "The hostname has an unusual or invalid structure "
        "that should be reviewed."
    ),
    "MANY_DOMAIN_LABELS": (
        "The hostname contains many domain labels. Verify "
        "which domain actually controls the destination."
    ),
    "AT_SYMBOL_IN_AUTHORITY": (
        "The URL contains an @ symbol in its authority "
        "section, which can obscure the actual hostname."
    ),
    "PERCENT_ENCODING_PRESENT": (
        "The URL contains percent-encoded characters. "
        "Inspect the decoded destination for unexpected content."
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

REDIRECT_INDICATOR_EXPLANATIONS = {
    "HTTPS_DOWNGRADE": (
        "A redirect changes the connection from HTTPS to HTTP, "
        "reducing transport protection."
    ),
    "REDIRECT_LOOP": (
        "The redirect chain appears to loop instead of "
        "reaching a final destination."
    ),
    "REDIRECT_LIMIT_REACHED": (
        "The redirect limit was reached before the chain "
        "could be fully inspected."
    ),
    "FINAL_HOST_DIFFERS": (
        "The final hostname differs from the original hostname. "
        "Verify whether the destination change is expected."
    ),
    "NON_PUBLIC_IP_DESTINATION": (
        "A redirect points to a non-public IP address. "
        "Review it carefully before following the destination."
    ),
    "LOCALHOST_DESTINATION": (
        "A redirect points to the local machine. This can be "
        "dangerous if an application follows it automatically."
    ),
    "INVALID_DESTINATION": (
        "A redirect destination could not be validated."
    ),
    "UNSAFE_REDIRECT_SCHEME": (
        "A redirect uses a scheme other than an accepted "
        "HTTP or HTTPS destination."
    ),
}


def _get_risk_level(score):
    """Convert a numeric score into a risk level."""

    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def score_url_risk(indicators):
    """Return an explainable risk score from URL indicators."""

    if not isinstance(indicators, (list, tuple, set)):
        raise TypeError("indicators must be a list, tuple, or set")

    # Count each recognized indicator only once.
    unique_indicators = set(indicators)

    matched = [
        indicator
        for indicator in INDICATOR_WEIGHTS
        if indicator in unique_indicators
    ]

    raw_score = sum(
        INDICATOR_WEIGHTS[indicator] for indicator in matched
    )
    score = min(100, raw_score)

    explanations = [
        {
            "indicator": indicator,
            "source": "url_analysis",
            "weight": INDICATOR_WEIGHTS[indicator],
            "explanation": URL_INDICATOR_EXPLANATIONS[indicator],
        }
        for indicator in matched
    ]

    return {
        "score": score,
        "risk_level": _get_risk_level(score),
        "matched_indicators": matched,
        "explanations": explanations,
        "review_recommended": score > 0,
        "raw_score": raw_score,
        "scoring_note": (
            "Heuristic score for prioritizing review; "
            "not a probability or proof of maliciousness."
        ),
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
            raise TypeError(
                "redirect indicators must be a list, tuple, or set"
            )

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
            "explanation": URL_INDICATOR_EXPLANATIONS[item],
        })

    for item in matched_redirect:
        explanations.append({
            "indicator": item,
            "source": "redirect_analysis",
            "weight": REDIRECT_INDICATOR_WEIGHTS[item],
            "explanation": REDIRECT_INDICATOR_EXPLANATIONS[item],
        })

    raw_score = sum(item["weight"] for item in explanations)
    score = min(100, raw_score)

    return {
        "score": score,
        "risk_level": _get_risk_level(score),
        "matched_indicators": [
            item["indicator"] for item in explanations
        ],
        "explanations": explanations,
        "review_recommended": score > 0,
        "raw_score": raw_score,
        "scoring_note": (
            "Combined heuristic score for prioritizing review; "
            "not a probability or proof of maliciousness."
        ),
    }
