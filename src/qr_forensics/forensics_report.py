
from src.qr_forensics.image_quality import (
    analyze_image_quality,
    classify_image_quality,
)
from src.qr_forensics.finder_analysis import analyze_finder_regions


def analyze_qr_forensics(image, points=None):
    """
    Combine image-quality measurements and finder-region
    measurements into one forensic report.

    This report describes image evidence; it does not
    determine whether a QR code is malicious.
    """

    quality = analyze_image_quality(image)

    if not quality["success"]:
        return {
            "success": False,
            "error": quality["error"],
            "image_quality": quality,
            "finder_analysis": None,
        }

    quality_findings = classify_image_quality(quality)

    finder_results = None

    if points is not None:
        finder_results = analyze_finder_regions(image, points)

    return {
        "success": True,
        "error": None,
        "image_quality": quality,
        "quality_findings": quality_findings,
        "finder_analysis": finder_results,
    }
