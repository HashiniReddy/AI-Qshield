
"""
AI-QShield - QR Intelligence Engine

Day 2 module.

Responsibilities:
    1. Load a QR image safely.
    2. Detect and decode QR content.
    3. Validate decoded content.
    4. Classify content as URL or TEXT.
    5. Calculate QR image geometry.
    6. Return a structured result.

Important:
    This module does not determine whether a URL is malicious.
"""

import cv2
from pathlib import Path
from urllib.parse import urlparse


class QRDecoder:
    """Decode QR codes and calculate basic image geometry."""

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def decode(self, image_path):
        """Decode a QR image and return structured results."""

        # Step 1: Convert the path
        image_path = Path(image_path)

        # Step 2: Check whether the file exists
        if not image_path.exists():
            return {
                "success": False,
                "error": "Image file not found",
                "content": None,
                "content_type": None,
                "is_url": False,
                "geometry": None
            }

        # Step 3: Load the image
        image = cv2.imread(str(image_path))

        # Step 4: Handle unreadable images safely
        if image is None:
            return {
                "success": False,
                "error": "Unable to read image",
                "content": None,
                "content_type": None,
                "is_url": False,
                "geometry": None
            }

        print("Image Shape:", image.shape)

        # Step 5: Create a grayscale image for pixel analysis
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        print("Gray Image Shape:", gray.shape)

        # Temporary learning experiment:
        # Examine a row in the existing 330x330 test image.
        if gray.shape[0] > 165 and gray.shape[1] >= 90:
            middle_row = gray[165]
            row = middle_row[35:90]

            binary_row = [
                "B" if pixel < 128 else "W"
                for pixel in row
            ]

            runs = []
            if binary_row:
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

        # Step 6: Detect and decode the QR code
        content, points, _ = self.detector.detectAndDecode(image)

        print("QR Points:", points)

        # Step 7: Calculate geometry when points are available
        geometry = self.get_geometry(points, image.shape)
        print("QR Geometry:", geometry)

        # Step 8: Handle images without a decodable QR code
        if not content:
            return {
                "success": False,
                "error": "No QR code detected",
                "content": None,
                "content_type": None,
                "is_url": False,
                "geometry": geometry
            }

        # Step 9: Clean the decoded content
        content = content.strip()

        # Step 10: Classify the content
        is_url = self.is_url(content)
        content_type = "URL" if is_url else "TEXT"

        # Step 11: Return the complete result
        return {
            "success": True,
            "error": None,
            "content": content,
            "content_type": content_type,
            "is_url": is_url,
            "geometry": geometry
        }

    @staticmethod
    def get_geometry(points, image_shape):
        """Calculate QR bounding-box dimensions and image margins."""

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

        # This checks margin similarity only.
        # It does not certify a standards-compliant quiet zone.
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
        Check basic HTTP/HTTPS URL structure.

        A structurally valid URL is not necessarily safe.
        """

        try:
            parsed = urlparse(content)

            valid_scheme = parsed.scheme in ("http", "https")
            valid_domain = bool(parsed.netloc)

            return valid_scheme and valid_domain

        except (ValueError, TypeError):
            return False
