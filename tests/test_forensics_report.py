
import numpy as np

from src.qr_forensics.forensics_report import analyze_qr_forensics


def test_forensics_report_with_valid_image_and_points():
    image = np.zeros((100, 100, 3), dtype=np.uint8)
    points = np.array(
        [[[10, 10], [90, 10], [90, 90], [10, 90]]],
        dtype=np.float32,
    )

    result = analyze_qr_forensics(image, points)

    assert result["success"] is True
    assert result["image_quality"]["width"] == 100
    assert result["image_quality"]["height"] == 100
    assert result["quality_findings"]["success"] is True
    assert result["finder_analysis"]["success"] is True


def test_forensics_report_without_corner_points():
    image = np.zeros((100, 100, 3), dtype=np.uint8)

    result = analyze_qr_forensics(image)

    assert result["success"] is True
    assert result["image_quality"]["success"] is True
    assert result["quality_findings"]["success"] is True
    assert result["finder_analysis"] is None


def test_forensics_report_rejects_empty_image():
    image = np.array([], dtype=np.uint8)

    result = analyze_qr_forensics(image)

    assert result["success"] is False
    assert result["error"] == "Invalid or empty image"
