from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
]


def analyze_url(url):
    """Inspect a URL and return explainable warning indicators."""

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "error": "URL must be a non-empty string",
            "indicators": [],
        }

    url = url.strip()

    # Require a valid HTTP or HTTPS URL structure.
    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError

        if not parsed.hostname:
            raise ValueError

        # Accessing port can raise ValueError for malformed ports.
        _ = parsed.port

    except ValueError:
        return {
            "success": False,
            "error": "Invalid HTTP or HTTPS URL",
            "indicators": [],
        }

    indicators = []
    hostname = parsed.hostname.lower()

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        indicators.append("IP_ADDRESS_HOST")
    except ValueError:
        pass

    # Check for an unusual number of subdomains.
    if len(hostname.split(".")) >= 5:
        indicators.append("MANY_DOMAIN_LABELS")

    # Check for an '@' symbol in the URL authority.
    if "@" in parsed.netloc:
        indicators.append("AT_SYMBOL_IN_AUTHORITY")

    # Check for suspicious-looking words in the URL.
    if re.search(
        r"(?:^|[^a-z0-9])(?:"
        + "|".join(SUSPICIOUS_KEYWORDS)
        + r")(?:[^a-z0-9]|$)",
        url,
        re.IGNORECASE,
    ):
        indicators.append("SENSITIVE_KEYWORD")

    return {
        "success": True,
        "error": None,
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "indicators": indicators,
        "review_recommended": bool(indicators),
    }
