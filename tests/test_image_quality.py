
import numpy as np

from src.qr_forensics.image_quality import analyze_image_quality


def test_valid_image():
    image = np.zeros((100, 100, 3), dtype=np.uint8)

    result = analyze_image_quality(image)

    assert result["success"] is True
    assert result["width"] == 100
    assert result["height"] == 100
    assert "sharpness_score" in result
    assert "contrast_score" in result


def test_empty_image():
    image = np.array([], dtype=np.uint8)

    result = analyze_image_quality(image)

    assert result["success"] is False
    assert result["error"] == "Invalid or empty image"


def test_grayscale_image():
    image = np.zeros((80, 120), dtype=np.uint8)

    result = analyze_image_quality(image)

    assert result["success"] is True
    assert result["width"] == 120
    assert result["height"] == 80

