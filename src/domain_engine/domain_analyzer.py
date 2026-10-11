import ipaddress
import re
import tldextract


def analyze_domain(hostname):
    """Extract domain structure and identify review indicators."""

    if not isinstance(hostname, str) or not hostname.strip():
        return {
            "success": False,
            "error": "Hostname must be a non-empty string",
            "indicators": [],
        }

    hostname = hostname.strip().lower().rstrip(".")

    # Handle IP addresses separately.
    try:
        address = ipaddress.ip_address(hostname)

        return {
            "success": True,
            "hostname": hostname,
            "is_ip_address": True,
            "ip_version": address.version,
            "subdomain": None,
            "registrable_domain": None,
            "public_suffix": None,
            "indicators": ["IP_ADDRESS_HOST"],
            "error": None,
        }
    except ValueError:
        pass

    # Extract the domain using the local Public Suffix List snapshot.
    extractor = tldextract.TLDExtract(suffix_list_urls=())
    extracted = extractor(hostname)

    if not extracted.domain or not extracted.suffix:
        return {
            "success": False,
            "error": "Unable to identify a registrable domain",
            "indicators": [],
        }

    registrable_domain = (
        f"{extracted.domain}.{extracted.suffix}"
    )
    subdomain = extracted.subdomain or None
    indicators = []

    # Detect internationalized-domain labels represented in punycode.
    if any(
        label.startswith("xn--")
        for label in hostname.split(".")
    ):
        indicators.append("PUNYCODE_HOSTNAME")

    # Flag hostnames with many subdomain labels.
    if subdomain and len(subdomain.split(".")) >= 3:
        indicators.append("MANY_SUBDOMAINS")

    # Flag hyphens in the registrable domain name.
    if "-" in extracted.domain:
        indicators.append("HYPHENATED_DOMAIN")

    return {
        "success": True,
        "hostname": hostname,
        "is_ip_address": False,
        "ip_version": None,
        "subdomain": subdomain,
        "registrable_domain": registrable_domain,
        "public_suffix": extracted.suffix,
        "indicators": indicators,
        "review_recommended": bool(indicators),
        "error": None,
    }
