
from src.qr_forensics.image_quality import classify_image_quality


def test_blurry_image_gets_review_finding():
    result = {
        "success": True,
        "sharpness_score": 107.07,
        "contrast_score": 100.72
    }

    output = classify_image_quality(result)

    assert output["success"] is True
    assert "LOW_SHARPNESS" in output["findings"]
    assert "IMAGE_QUALITY_REVIEW" in output["findings"]


def test_good_quality_measurements_get_no_findings():
    result = {
        "success": True,
        "sharpness_score": 8213.81,
        "contrast_score": 116.05
    }

    output = classify_image_quality(result)

    assert output["success"] is True
    assert output["findings"] == []


def test_invalid_measurements_are_rejected():
    result = {
        "success": True,
        "sharpness_score": float("nan"),
        "contrast_score": 100.0
    }

    output = classify_image_quality(result)

    assert output["success"] is False
    assert output["findings"] == []
