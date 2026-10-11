
"""Identify explainable QR-related risk patterns from collected evidence."""

REDIRECT_RULES = {
    "HTTPS_DOWNGRADE",
    "REDIRECT_LOOP",
    "NON_PUBLIC_IP_DESTINATION",
    "LOCALHOST_DESTINATION",
    "INVALID_DESTINATION",
    "UNSAFE_REDIRECT_SCHEME",
}

URL_RULES = {
    "URL_SHORTENER",
    "IP_ADDRESS_HOST",
    "SENSITIVE_KEYWORD",
    "ENCODED_URL_DELIMITER",
    "UNICODE_DOMAIN",
    "MALFORMED_HOSTNAME",
    "MANY_DOMAIN_LABELS",
    "AT_SYMBOL_IN_AUTHORITY",
}


def identify_attack_fingerprints(
    url_analysis=None,
    redirect_analysis=None,
    threat_intelligence=None,
):
    """Return potential patterns supported by observed indicators."""

    fingerprints = []

    if not isinstance(url_analysis, dict):
        url_analysis = {}

    if not isinstance(redirect_analysis, dict):
        redirect_analysis = {}

    if not isinstance(threat_intelligence, dict):
        threat_intelligence = {}

    url_indicators = set(url_analysis.get("indicators", []))
    redirect_indicators = set(redirect_analysis.get("indicators", []))

    # Pattern 1: URL contains indicators that warrant closer inspection.
    matched_url = sorted(url_indicators & URL_RULES)

    if matched_url:
        fingerprints.append({
            "fingerprint_id": "QR-URL-001",
            "name": "Suspicious URL Structure",
            "matched_indicators": matched_url,
            "source": "url_analysis",
            "explanation": (
                "The URL contains structural indicators that "
                "warrant further investigation."
            ),
            "recommended_action": (
                "Inspect the URL and verify the destination "
                "before opening it."
            ),
        })

    # Pattern 2: Redirect analysis found a risky redirect behavior.
    matched_redirects = sorted(
        redirect_indicators & REDIRECT_RULES
    )

    if matched_redirects:
        fingerprints.append({
            "fingerprint_id": "QR-REDIRECT-001",
            "name": "Suspicious Redirect Behavior",
            "matched_indicators": matched_redirects,
            "source": "redirect_analysis",
            "explanation": (
                "Redirect analysis identified behavior that "
                "may lead to an unsafe or unexpected destination."
            ),
            "recommended_action": (
                "Review the redirect chain and verify each "
                "destination before trusting the QR code."
            ),
        })

    # Pattern 3: External threat intelligence reports malicious detections.
    malicious_count = threat_intelligence.get("malicious_count", 0)

    if (
        threat_intelligence.get("available") is True
        and isinstance(malicious_count, int)
        and not isinstance(malicious_count, bool)
        and malicious_count > 0
    ):
        fingerprints.append({
            "fingerprint_id": "QR-THREAT-001",
            "name": "External Malicious Reputation",
            "matched_indicators": ["THREAT_INTEL_MALICIOUS"],
            "source": "threat_intelligence",
            "explanation": (
                "The configured threat-intelligence provider "
                "reported one or more malicious detections."
            ),
            "recommended_action": (
                "Avoid opening the destination and investigate "
                "the provider's reputation results."
            ),
        })

    return fingerprints

def correlate_attack_evidence(fingerprints):
    """Summarize findings across distinct evidence sources."""

    if not isinstance(fingerprints, list):
        fingerprints = []

    valid_fingerprints = [
        item for item in fingerprints
        if isinstance(item, dict)
    ]

    source_names = {
        "url_analysis",
        "redirect_analysis",
        "threat_intelligence",
    }

    sources = sorted({
        item.get("source")
        for item in valid_fingerprints
        if item.get("source") in source_names
    })

    source_count = len(sources)
    fingerprint_count = len(valid_fingerprints)

    if source_count == 0:
        evidence_level = "NO_EVIDENCE"
        explanation = (
            "No recognized evidence sources support a finding."
        )
    elif source_count == 1:
        evidence_level = "SINGLE_SOURCE"
        explanation = (
            "Findings come from one evidence source. "
            "Additional verification is recommended."
        )
    elif source_count == 2:
        evidence_level = "CORROBORATED"
        explanation = (
            "Findings appear across two evidence sources. "
            "Review the underlying evidence before deciding."
        )
    else:
        evidence_level = "MULTI_SOURCE"
        explanation = (
            "Findings appear across three evidence sources. "
            "Review each result because this does not prove "
            "that the QR code is malicious."
        )

    return {
        "evidence_level": evidence_level,
        "fingerprint_count": fingerprint_count,
        "source_count": source_count,
        "sources": sources,
        "explanation": explanation,
    }