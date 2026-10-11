from urllib.parse import urlparse
import requests


MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 5


def analyze_redirects(url):
    """Inspect an HTTP redirect chain with basic safety limits."""

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "error": "URL must be a non-empty string",
            "redirect_chain": [],
            "indicators": [],
        }

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return {
            "success": False,
            "error": "A valid HTTP or HTTPS URL is required",
            "redirect_chain": [],
            "indicators": [],
        }

    chain = [url]
    indicators = []

    try:
        # Disable automatic redirects so each hop can be inspected.
        with requests.Session() as session:
            session.max_redirects = MAX_REDIRECTS

            for _ in range(MAX_REDIRECTS):
                current = chain[-1]
                response = session.get(
                    current,
                    allow_redirects=False,
                    timeout=TIMEOUT_SECONDS,
                    stream=True,
                )

                try:
                    if response.status_code not in (301, 302, 303, 307, 308):
                        break

                    location = response.headers.get("Location")

                    if not location:
                        break

                    next_url = requests.compat.urljoin(current, location)
                    next_parsed = urlparse(next_url)

                    if (
                        next_parsed.scheme.lower() not in ("http", "https")
                        or not next_parsed.hostname
                    ):
                        indicators.append("UNSAFE_REDIRECT_SCHEME")
                        break

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

    # Compare the first and last hostnames.
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
