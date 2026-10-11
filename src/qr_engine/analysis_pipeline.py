
"""Coordinate QR decoding, forensics, URL analysis, and risk scoring."""

from pathlib import Path
from urllib.parse import urlsplit

import cv2

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.forensics_report import analyze_qr_forensics
from src.redirect_engine.redirect_analyzer import analyze_redirects
from src.url_engine.url_analyzer import analyze_url
from src.risk_engine.url_risk_scorer import score_combined_risk
from src.report_engine.risk_report import build_risk_report
from src.threat_intel.threat_intel_client import (
    lookup_domain_reputation,
)


class QRAnalysisPipeline:
    """Coordinate QR decoding, forensics, URL analysis, and risk scoring."""

    def __init__(self):
        self.decoder = QRDecoder()

    def analyze(
        self,
        image_path,
        check_redirects=False,
        check_threat_intel=False,
    ):
        image_path = Path(image_path)

        # Step 1: Decode the QR image.
        decoded = self.decoder.decode(image_path)

        if not decoded["success"]:
            return {
                "success": False,
                "error": decoded["error"],
                "decoding": decoded,
                "forensics": None,
                "url_analysis": None,
                "risk_assessment": None,
                "redirect_analysis": None,
                "threat_intelligence": None,
                "risk_report": None,
            }

        content = decoded.get("content", "")

        # Step 2: Load the image for forensic analysis.
        image = cv2.imread(str(image_path))

        # Step 3: Analyze QR finder regions.
        points = self.decoder.detector.detect(image)[1]
        forensics = analyze_qr_forensics(image, points)

        # Step 4: Analyze the decoded URL.
        url_analysis = analyze_url(content)

        # Step 4a: Check domain reputation only when explicitly requested.
        threat_intelligence = None

        if check_threat_intel:
            if url_analysis["success"]:
                hostname = urlsplit(content).hostname

                if hostname:
                    try:
                        threat_intelligence = lookup_domain_reputation(
                            hostname
                        )
                    except Exception:
                        # Keep optional threat intelligence fault-tolerant.
                        threat_intelligence = {
                            "success": False,
                            "hostname": hostname,
                            "provider": "VirusTotal",
                            "available": False,
                            "malicious_count": None,
                            "suspicious_count": None,
                            "error": "Threat-intelligence lookup failed",
                        }
                else:
                    threat_intelligence = {
                        "success": False,
                        "hostname": None,
                        "provider": "VirusTotal",
                        "available": False,
                        "malicious_count": None,
                        "suspicious_count": None,
                        "error": "URL hostname is unavailable",
                    }
            else:
                threat_intelligence = {
                    "success": False,
                    "hostname": None,
                    "provider": "VirusTotal",
                    "available": False,
                    "malicious_count": None,
                    "suspicious_count": None,
                    "error": "Decoded content is not a valid URL",
                }

        # Step 5: Redirect analysis remains opt-in.
        redirect_analysis = None

        if check_redirects:
            if url_analysis["success"]:
                redirect_analysis = analyze_redirects(content)
            else:
                redirect_analysis = {
                    "success": False,
                    "error": (
                        "Decoded content is not a valid HTTP/HTTPS URL"
                    ),
                    "redirect_chain": [],
                    "indicators": [],
                }

        # Step 6: Calculate explainable combined risk.
        risk_assessment = None

        if url_analysis["success"]:
            risk_assessment = score_combined_risk(
                url_analysis["indicators"],
                redirect_analysis=redirect_analysis,
            )

        # Step 7: Build the complete analysis result.
        result = {
            "success": True,
            "error": None,
            "decoding": decoded,
            "forensics": forensics,
            "url_analysis": url_analysis,
            "risk_assessment": risk_assessment,
            "redirect_analysis": redirect_analysis,
            "threat_intelligence": threat_intelligence,
            "risk_report": None,
        }

        # Step 8: Create the readable investigator report.
        result["risk_report"] = build_risk_report(result)

        return result
