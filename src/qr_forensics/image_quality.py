
import cv2
import numpy as np


def analyze_image_quality(image):
    """
    Measure basic QR image quality.

    These measurements describe image quality.
    They do not determine whether a QR code is malicious.
    """

    # Validate the input image.
    if (
        image is None
        or not isinstance(image, np.ndarray)
        or image.size == 0
        or image.ndim not in (2, 3)
    ):
        return {
            "success": False,
            "error": "Invalid or empty image"
        }

    # Convert the image to grayscale.
    if image.ndim == 2:
        gray = image
    elif image.shape[2] == 3:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    elif image.shape[2] == 4:
        gray = cv2.cvtColor(image, cv2.COLOR_BGRA2GRAY)
    else:
        return {
            "success": False,
            "error": "Unsupported image format"
        }

    # Measure image dimensions.
    height, width = gray.shape

    # Measure sharpness using the Laplacian variance.
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    sharpness = float(laplacian.var())

    # Measure contrast using standard deviation.
    contrast = float(gray.std())

    return {
        "success": True,
        "error": None,
        "width": int(width),
        "height": int(height),
        "sharpness_score": round(sharpness, 2),
        "contrast_score": round(contrast, 2)
    }

def classify_image_quality(result):
    """
    Convert image-quality measurements into review findings.

    These findings describe image quality, not maliciousness.
    Thresholds are preliminary and need further calibration.
    """

    if not isinstance(result, dict) or not result.get("success"):
        return {
            "success": False,
            "findings": [],
            "error": "Valid image-quality results are required"
        }

    sharpness = result.get("sharpness_score")
    contrast = result.get("contrast_score")

    if not isinstance(sharpness, (int, float)) or not np.isfinite(sharpness):
        return {
            "success": False,
            "findings": [],
            "error": "Invalid sharpness score"
        }

    if not isinstance(contrast, (int, float)) or not np.isfinite(contrast):
        return {
            "success": False,
            "findings": [],
            "error": "Invalid contrast score"
        }

    findings = []

    # Preliminary thresholds for experimentation only.
    if sharpness < 150:
        findings.append("LOW_SHARPNESS")

    if contrast < 40:
        findings.append("LOW_CONTRAST")

    if findings:
        findings.append("IMAGE_QUALITY_REVIEW")

    return {
        "success": True,
        "findings": findings,
        "error": None
    }
