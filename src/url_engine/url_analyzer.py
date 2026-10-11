
from urllib.parse import urlparse, unquote
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

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "shorturl.at",
}


def is_hostname_well_formed(hostname):
    """Perform basic structural checks on a hostname."""

    if not hostname or len(hostname) > 253:
        return False

    # Accept IP addresses separately.
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    labels = hostname.rstrip(".").split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
        ):
            return False

    return True


def is_url_shortener(hostname):
    """Check whether a hostname matches a known URL shortener."""

    hostname = hostname.lower().rstrip(".")

    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in URL_SHORTENER_DOMAINS
    )


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

    # Check basic hostname structure.
    if not is_hostname_well_formed(hostname):
        indicators.append("MALFORMED_HOSTNAME")

    # Identify percent-encoded characters.
    if re.search(r"%[0-9a-fA-F]{2}", url):
        indicators.append("PERCENT_ENCODING_PRESENT")

    # Flag encoded URL delimiters for closer inspection.
    decoded_url = unquote(url)

    if decoded_url != url and re.search(r"[@/\\?#]", decoded_url):
        if re.search(r"%(?:2f|5c|3f|23|40)", url, re.IGNORECASE):
            indicators.append("ENCODED_URL_DELIMITER")

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        indicators.append("IP_ADDRESS_HOST")
    except ValueError:
        pass

    # Check for an unusual number of domain labels.
    if len(hostname.rstrip(".").split(".")) >= 5:
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

    # Flag known URL-shortening services.
    if is_url_shortener(hostname):
        indicators.append("URL_SHORTENER")

    # Flag Unicode hostnames for closer inspection.
    if not hostname.isascii():
        indicators.append("UNICODE_DOMAIN")

    return {
        "success": True,
        "error": None,
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "indicators": indicators,
        "review_recommended": bool(indicators),
    }
