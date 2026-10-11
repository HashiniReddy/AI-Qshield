
from pathlib import Path

import cv2

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.forensics_report import analyze_qr_forensics


class QRAnalysisPipeline:
    """Coordinate QR decoding and image-forensics analysis."""

    def __init__(self):
        self.decoder = QRDecoder()

    def analyze(self, image_path):
        image_path = Path(image_path)

        # Decode the QR image.
        decoded = self.decoder.decode(image_path)

        # Stop if the image cannot be decoded.
        if not decoded["success"]:
            return {
                "success": False,
                "error": decoded["error"],
                "decoding": decoded,
                "forensics": None,
            }

        # Load the image for forensic analysis.
        image = cv2.imread(str(image_path))

        # Get the QR corner points for finder-region analysis.
        points = self.decoder.detector.detect(image)[1]

        # Combine the available forensic measurements.
        forensics = analyze_qr_forensics(image, points)

        return {
            "success": True,
            "error": None,
            "decoding": decoded,
            "forensics": forensics,
        }
