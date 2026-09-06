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

        # ---------------------------------------------------------
        # STEP 5: Detect and decode the QR code
        # ---------------------------------------------------------

        content, points, _ = self.detector.detectAndDecode(image)

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