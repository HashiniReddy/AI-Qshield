
import numpy as np

from src.qr_forensics.finder_analysis import analyze_finder_regions


def test_missing_image():
    result = analyze_finder_regions(None, None)

    assert result["success"] is False
    assert result["error"] == "Image or QR corner points unavailable"


def test_missing_qr_points():
    image = np.zeros((100, 100, 3), dtype=np.uint8)

    result = analyze_finder_regions(image, None)

    assert result["success"] is False
    assert result["regions"] == {}


def test_finder_regions_returned():
    image = np.zeros((330, 330, 3), dtype=np.uint8)

    points = np.array([[
        [40.0, 40.0],
        [289.0, 40.0],
        [289.0, 289.0],
        [40.0, 289.0]
    ]], dtype=np.float32)

    result = analyze_finder_regions(image, points)

    assert result["success"] is True
    assert set(result["regions"].keys()) == {
        "top_left",
        "top_right",
        "bottom_left"
    }

    for region in result["regions"].values():
        assert 0.0 <= region["dark_pixel_density"] <= 1.0
