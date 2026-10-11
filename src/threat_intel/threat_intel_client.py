
"""Safe, provider-independent threat-intelligence result handling."""

import ipaddress
import os
import re

import requests
from dotenv import load_dotenv


VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"
REQUEST_TIMEOUT = 8


def build_intelligence_result(
    hostname,
    provider,
    available,
    malicious_count=None,
    suspicious_count=None,
    error=None,
):
    """Build a normalized threat-intelligence result."""

    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")

    if not isinstance(provider, str) or not provider.strip():
        raise ValueError("provider must be a non-empty string")

    if not isinstance(available, bool):
        raise TypeError("available must be a boolean")

    normalized_hostname = hostname.strip().lower().rstrip(".")

    if not available:
        return {
            "success": False,
            "hostname": normalized_hostname,
            "provider": provider.strip(),
            "available": False,
            "malicious_count": None,
            "suspicious_count": None,
            "error": error or "Threat intelligence is unavailable",
        }

    for name, count in (
        ("malicious_count", malicious_count),
        ("suspicious_count", suspicious_count),
    ):
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise ValueError(f"{name} must be a non-negative integer")

    return {
        "success": True,
        "hostname": normalized_hostname,
        "provider": provider.strip(),
        "available": True,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "error": None,
    }


def _validate_hostname(hostname):
    """Accept a domain name, not a URL, IP address, or malformed hostname."""

    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")

    hostname = hostname.strip().lower().rstrip(".")

    if len(hostname) > 253 or "/" in hostname or "://" in hostname:
        raise ValueError("Provide a valid domain name, not a URL")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported by this domain lookup")

    labels = hostname.split(".")

    if len(labels) < 2:
        raise ValueError("Provide a fully qualified domain name")

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain name")

    return hostname


def lookup_domain_reputation(hostname, api_key=None, timeout=REQUEST_TIMEOUT):
    """Look up domain reputation using VirusTotal's domain API.

    No API key is included in the URL or returned result.
    """

    hostname = _validate_hostname(hostname)

    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number")

    if api_key is None:
        load_dotenv()
        api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not isinstance(api_key, str) or not api_key.strip():
        return build_intelligence_result(
            hostname, "VirusTotal", False,
            error="VirusTotal API key is not configured",
        )

    try:
        response = requests.get(
            f"{VIRUSTOTAL_DOMAIN_URL}/{hostname}",
            headers={"x-apikey": api_key.strip()},
            timeout=timeout,
        )

        if response.status_code != 200:
            messages = {
                401: "VirusTotal rejected the API key",
                403: "VirusTotal denied access to this resource",
                404: "Domain was not found in VirusTotal",
                429: "VirusTotal rate limit reached",
            }
            return build_intelligence_result(
                hostname,
                "VirusTotal",
                False,
                error=messages.get(
                    response.status_code,
                    f"VirusTotal returned HTTP {response.status_code}",
                ),
            )

        payload = response.json()
        stats = payload["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        return build_intelligence_result(
            hostname,
            "VirusTotal",
            True,
            malicious_count=malicious,
            suspicious_count=suspicious,
        )

    except requests.Timeout:
        error = "VirusTotal request timed out"
    except requests.RequestException:
        error = "Could not connect to VirusTotal"
    except (ValueError, KeyError, TypeError):
        error = "VirusTotal returned an invalid response"

    return build_intelligence_result(
        hostname, "VirusTotal", False, error=error
    )
