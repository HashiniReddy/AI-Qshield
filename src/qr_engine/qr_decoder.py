"""
AI-QShield - QR Intelligence Engine

Day 2 module.

Responsibilities:
    1. Load a QR image safely.
    2. Detect and decode QR content.
    3. Validate decoded content.
    4. Determine whether the content is a URL or plain text.
    5. Return a structured result.

Important security principle:
    This module DOES NOT determine whether a URL is malicious.

    Its responsibility ends after extracting and classifying
    the QR content as URL or TEXT.

    Malicious URL analysis will be handled by the
    URL Intelligence Engine.
"""

from altair import value
import cv2
from pathlib import Path
from urllib.parse import urlparse


class QRDecoder:
    """
    QR Intelligence Engine.

    Uses OpenCV's QRCodeDetector to detect and decode
    QR codes from image files.
    """

    def __init__(self):
        """
        Initialize the QR detector.
        """

        self.detector = cv2.QRCodeDetector()

    def decode(self, image_path):
        """
        Detect and decode a QR code from an image.

        Parameters
        ----------
        image_path : str or Path
            Path to the QR image.

        Returns
        -------
        dict
            Structured result containing:

            success
                Whether decoding was successful.

            error
                Error message if decoding failed.

            content
                Decoded QR content.

            content_type
                Either URL or TEXT.

            is_url
                True if the decoded content is an HTTP/HTTPS URL.
        """

        # ---------------------------------------------------------
        # STEP 1: Convert input path into a Path object
        # ---------------------------------------------------------

        image_path = Path(image_path)

        # ---------------------------------------------------------
        # STEP 2: Check whether the image exists
        # ---------------------------------------------------------

        if not image_path.exists():
            return {
                "success": False,
                "error": "Image file not found",
                "content": None,
                "content_type": None,
                "is_url": False
            }

        # ---------------------------------------------------------
        # STEP 3: Load the image
        # ---------------------------------------------------------

        image = cv2.imread(str(image_path))
        print("Image Shape:", image.shape)

        # ---------------------------------------------------------
        # STEP 4: Check whether OpenCV successfully loaded it
        # ---------------------------------------------------------

        if image is None:
            return {
                "success": False,
                "error": "Unable to read image",
                "content": None,
                "content_type": None,
                "is_url": False
            }
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        print("Gray Image Shape:", gray.shape)
        middle_row = gray[165]

        row = middle_row[35:90]

        binary_row = ["B" if pixel < 128 else "W" for pixel in row]
        runs = []

        current = binary_row[0]
        count = 1

        for value in binary_row[1:]:
          if value == current:
              count += 1
          else:
             runs.append((current, count))
             current = value
             count = 1

        runs.append((current, count))

        print("Runs:", runs)

        print("QR Row Binary:", binary_row)

        # ---------------------------------------------------------
        # STEP 5: Detect and decode the QR code
        # ---------------------------------------------------------

        content, points, _ = self.detector.detectAndDecode(image)

        print("QR Points:", points)

        geometry = self.get_geometry(points, image.shape)
        print("QR Geometry:", geometry)

        # ---------------------------------------------------------
        # STEP 6: Check whether a QR code was detected
        # ---------------------------------------------------------

        if not content:
            return {
                "success": False,
                "error": "No QR code detected",
                "content": None,
                "content_type": None,
                "is_url": False
            }

        # ---------------------------------------------------------
        # STEP 7: Clean the decoded content
        # ---------------------------------------------------------

        content = content.strip()

        # ---------------------------------------------------------
        # STEP 8: Determine whether the content is a URL
        # ---------------------------------------------------------

        if self.is_url(content):
            content_type = "URL"
            is_url = True

        else:
            content_type = "TEXT"
            is_url = False

        # ---------------------------------------------------------
        # STEP 9: Return structured result
        # ---------------------------------------------------------

        return {
            "success": True,
            "error": None,
            "content": content,
            "content_type": content_type,
            "is_url": is_url
        }

    @staticmethod
    def get_geometry(points, image_shape):
        """
        Calculate the detected QR bounding-box dimensions.
        """

        if points is None:
            return None

        points = points[0]

        x_min = points[:, 0].min()
        x_max = points[:, 0].max()

        y_min = points[:, 1].min()
        y_max = points[:, 1].max()

        width = x_max - x_min
        height = y_max - y_min
        image_height, image_width = image_shape[:2]

        left_margin = x_min
        top_margin = y_min
        right_margin = image_width - x_max
        bottom_margin = image_height - y_max
        margins = [
            left_margin,
            top_margin,
            right_margin,
            bottom_margin
        ]

        margin_difference = max(margins) - min(margins)
        quiet_zone_consistent = margin_difference <= 5

        return {
            "x_min": float(x_min),
            "y_min": float(y_min),
            "x_max": float(x_max),
            "y_max": float(y_max),
            "width": float(width),
            "height": float(height),
            "left_margin": float(left_margin),
            "top_margin": float(top_margin),
            "right_margin": float(right_margin),
            "bottom_margin": float(bottom_margin),
            "margin_difference": float(margin_difference),
        "quiet_zone_consistent": bool(quiet_zone_consistent)
}
        

    @staticmethod
    def is_url(content):
        """
        Perform basic URL structure validation.

        This function checks whether the content uses
        HTTP or HTTPS and contains a network location.

        IMPORTANT:
            A valid URL is NOT necessarily a safe URL.

        Example:

            https://example.com
                ↓
            Structurally valid URL

        But that does NOT mean:
                ↓
            SAFE

        Security analysis will happen later.
        """

        try:

            # Parse the URL
            parsed = urlparse(content)

            # Check for HTTP/HTTPS scheme
            valid_scheme = parsed.scheme in ("http", "https")

            # Check that a domain/network location exists
            valid_domain = bool(parsed.netloc)

            return valid_scheme and valid_domain

        except Exception:
            return False