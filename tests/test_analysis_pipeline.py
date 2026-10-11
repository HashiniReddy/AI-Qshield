
import cv2
import numpy as np
from unittest.mock import patch

from src.qr_engine.analysis_pipeline import QRAnalysisPipeline


def test_pipeline_decodes_valid_qr():
    pipeline = QRAnalysisPipeline()

    result = pipeline.analyze("dataset/test_qr.png")

    assert result["success"] is True
    assert result["decoding"]["success"] is True
    assert result["decoding"]["content"] == "https://example.com"
    assert result["forensics"]["success"] is True
    assert result["redirect_analysis"] is None


def test_pipeline_handles_image_without_qr(tmp_path):
    pipeline = QRAnalysisPipeline()

    image_path = tmp_path / "blank.png"
    blank_image = np.full((100, 100, 3), 255, dtype=np.uint8)
    cv2.imwrite(str(image_path), blank_image)

    result = pipeline.analyze(image_path)

    assert result["success"] is False
    assert result["error"] == "No QR code detected"
    assert result["forensics"] is None
    assert result["redirect_analysis"] is None


def test_pipeline_handles_missing_image(tmp_path):
    pipeline = QRAnalysisPipeline()

    image_path = tmp_path / "missing.png"
    result = pipeline.analyze(image_path)

    assert result["success"] is False
    assert result["error"] == "Image file not found"
    assert result["forensics"] is None
    assert result["redirect_analysis"] is None


@patch("src.qr_engine.analysis_pipeline.analyze_redirects")
def test_pipeline_runs_optional_redirect_analysis(mock_redirects):
    mock_redirects.return_value = {
        "success": True,
        "error": None,
        "original_url": "https://example.com",
        "final_url": "https://example.org",
        "redirect_count": 1,
        "redirect_chain": [
            "https://example.com",
            "https://example.org",
        ],
        "indicators": ["FINAL_HOST_DIFFERS"],
    }

    pipeline = QRAnalysisPipeline()
    result = pipeline.analyze(
        "dataset/test_qr.png",
        check_redirects=True,
    )

    assert result["success"] is True
    assert result["redirect_analysis"]["success"] is True
    assert result["redirect_analysis"]["redirect_count"] == 1
    assert "FINAL_HOST_DIFFERS" in result["redirect_analysis"]["indicators"]
    mock_redirects.assert_called_once_with("https://example.com")
