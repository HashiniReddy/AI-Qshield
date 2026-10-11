
from pathlib import Path
from urllib.parse import urlparse

import cv2

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.forensics_report import analyze_qr_forensics
from src.redirect_engine.redirect_analyzer import analyze_redirects


class QRAnalysisPipeline:
    """Coordinate QR decoding, forensics, and optional redirect analysis."""

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
                "redirect_analysis": None,
            }

        # Step 2: Load the image for forensic analysis.
        image = cv2.imread(str(image_path))

        # Step 3: Analyze QR finder regions.
        points = self.decoder.detector.detect(image)[1]
        forensics = analyze_qr_forensics(image, points)

        # Step 4: Redirect analysis is opt-in.
        redirect_analysis = None

        if check_redirects:
            content = decoded.get("content", "")
            parsed = urlparse(content)

            if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
                redirect_analysis = analyze_redirects(content)
            else:
                redirect_analysis = {
                    "success": False,
                    "error": "Decoded content is not a valid HTTP/HTTPS URL",
                    "redirect_chain": [],
                    "indicators": [],
                }

        # Step 5: Return the combined report.
        return {
            "success": True,
            "error": None,
            "decoding": decoded,
            "forensics": forensics,
            "redirect_analysis": redirect_analysis,
        }
