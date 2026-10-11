import ipaddress
import tldextract


def analyze_domain(hostname):
    """Extract domain structure for QR destination analysis."""

    if not isinstance(hostname, str) or not hostname.strip():
        return {
            "success": False,
            "error": "Hostname must be a non-empty string",
        }

    hostname = hostname.strip().lower().rstrip(".")

    # IP addresses do not have registrable domains.
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
            "error": None,
        }
    except ValueError:
        pass

    # Disable network fetching of the Public Suffix List.
    # Use the local snapshot provided by tldextract.
    extractor = tldextract.TLDExtract(suffix_list_urls=())

    extracted = extractor(hostname)

    if not extracted.domain or not extracted.suffix:
        return {
            "success": False,
            "error": "Unable to identify a registrable domain",
        }

    registrable_domain = (
        f"{extracted.domain}.{extracted.suffix}"
    )

    return {
        "success": True,
        "hostname": hostname,
        "is_ip_address": False,
        "ip_version": None,
        "subdomain": extracted.subdomain or None,
        "registrable_domain": registrable_domain,
        "public_suffix": extracted.suffix,
        "error": None,
    }
