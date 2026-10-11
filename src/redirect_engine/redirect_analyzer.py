
from urllib.parse import urlparse
import ipaddress
import requests


MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)


def validate_destination(url):
    """Reject malformed URLs and obvious local/private destinations."""

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False, "UNSAFE_REDIRECT_SCHEME"

        if not parsed.hostname or parsed.username is not None:
            return False, "INVALID_DESTINATION"

        # Reject malformed ports.
        _ = parsed.port

        hostname = parsed.hostname.lower().rstrip(".")

        # Block localhost names.
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False, "LOCALHOST_DESTINATION"

        # Block non-public IP addresses.
        try:
            address = ipaddress.ip_address(hostname)

            if not address.is_global:
                return False, "NON_PUBLIC_IP_DESTINATION"

        except ValueError:
            # Hostname is not an IP literal.
            pass

        return True, None

    except (ValueError, TypeError, AttributeError):
        return False, "INVALID_DESTINATION"


def analyze_redirects(url):
    """Inspect HTTP redirects with basic destination checks."""

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "error": "URL must be a non-empty string",
            "redirect_chain": [],
            "indicators": [],
        }

    url = url.strip()
    safe, reason = validate_destination(url)

    if not safe:
        return {
            "success": False,
            "error": reason,
            "redirect_chain": [],
            "indicators": [reason],
        }

    chain = [url]
    indicators = []

    try:
        with requests.Session() as session:
            for _ in range(MAX_REDIRECTS):
                current = chain[-1]

                response = session.get(
                    current,
                    allow_redirects=False,
                    timeout=TIMEOUT_SECONDS,
                    stream=True,
                )

                try:
                    if response.status_code not in REDIRECT_CODES:
                        break

                    location = response.headers.get("Location")

                    if not location:
                        break

                    next_url = requests.compat.urljoin(current, location)
                    safe, reason = validate_destination(next_url)

                    if not safe:
                        indicators.append(reason)
                        break

                    current_scheme = urlparse(current).scheme.lower()
                    next_scheme = urlparse(next_url).scheme.lower()

                    if current_scheme == "https" and next_scheme == "http":
                        indicators.append("HTTPS_DOWNGRADE")

                    if next_url in chain:
                        indicators.append("REDIRECT_LOOP")
                        break

                    chain.append(next_url)

                finally:
                    response.close()

            else:
                indicators.append("REDIRECT_LIMIT_REACHED")

    except requests.RequestException as exc:
        return {
            "success": False,
            "error": f"Redirect request failed: {type(exc).__name__}",
            "redirect_chain": chain,
            "indicators": indicators,
        }

    first_host = urlparse(chain[0]).hostname
    final_host = urlparse(chain[-1]).hostname

    if first_host and final_host and first_host.lower() != final_host.lower():
        indicators.append("FINAL_HOST_DIFFERS")

    return {
        "success": True,
        "error": None,
        "original_url": chain[0],
        "final_url": chain[-1],
        "redirect_count": len(chain) - 1,
        "redirect_chain": chain,
        "indicators": indicators,
    }
