import numpy as np

from src.qr_forensics.finder_analysis import analyze_finder_regions


def test_missing_image():
    result = analyze_finder_regions(None, None)

    assert result["success"] is False


def test_missing_points():
    image = np.zeros((100, 100, 3), dtype=np.uint8)

    result = analyze_finder_regions(image, None)

    assert result["success"] is False


def test_finder_regions_detected():
    image = np.zeros((100, 100, 3), dtype=np.uint8)

    points = np.array(
        [[[10, 10], [90, 10], [90, 90], [10, 90]]],
        dtype=np.float32
    )

    result = analyze_finder_regions(image, points)

    assert result["success"] is True
    assert len(result["regions"]) == 3