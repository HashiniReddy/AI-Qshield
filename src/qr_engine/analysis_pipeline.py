
from pathlib import Path

import cv2

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.forensics_report import analyze_qr_forensics
from src.redirect_engine.redirect_analyzer import analyze_redirects
from src.url_engine.url_analyzer import analyze_url
from src.risk_engine.url_risk_scorer import score_combined_risk


class QRAnalysisPipeline:
    """Coordinate QR decoding, forensics, URL analysis, and risk scoring."""

    def __init__(self):
        self.decoder = QRDecoder()

    def analyze(self, image_path, check_redirects=False):
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
            }

        content = decoded.get("content", "")

        # Step 2: Load the image for forensic analysis.
        image = cv2.imread(str(image_path))

        # Step 3: Analyze QR finder regions.
        points = self.decoder.detector.detect(image)[1]
        forensics = analyze_qr_forensics(image, points)

        # Step 4: Analyze the decoded URL.
        url_analysis = analyze_url(content)
        redirect_analysis = None

        # Step 5: Redirect analysis remains opt-in.
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

        # Step 7: Return the combined report.
        return {
            "success": True,
            "error": None,
            "decoding": decoded,
            "forensics": forensics,
            "url_analysis": url_analysis,
            "risk_assessment": risk_assessment,
            "redirect_analysis": redirect_analysis,
        }
