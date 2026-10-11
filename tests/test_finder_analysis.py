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


def test_empty_image():
    import numpy as np

    image = np.array([], dtype=np.uint8)

    result = analyze_finder_regions(image, None)

    assert result["success"] is False
    assert result["error"] == "Invalid or empty image"


def test_malformed_corner_points():
    import numpy as np

    image = np.zeros((100, 100, 3), dtype=np.uint8)
    points = np.array([[10, 10], [90, 90]], dtype=np.float32)

    result = analyze_finder_regions(image, points)

    assert result["success"] is False
    assert result["error"] == "Invalid QR corner points"


def test_non_finite_corner_points():
    import numpy as np

    image = np.zeros((100, 100, 3), dtype=np.uint8)
    points = np.array(
        [[[10, 10], [90, 10], [90, float("nan")], [10, 90]]],
        dtype=np.float32
    )

    result = analyze_finder_regions(image, points)

    assert result["success"] is False
    assert result["error"] == "Invalid QR corner points"


def test_zero_size_qr_geometry():
    import numpy as np

    image = np.zeros((100, 100, 3), dtype=np.uint8)
    points = np.array(
        [[[20, 20], [20, 20], [20, 20], [20, 20]]],
        dtype=np.float32
    )

    result = analyze_finder_regions(image, points)

    assert result["success"] is False
    assert result["error"] == "Invalid QR geometry"
