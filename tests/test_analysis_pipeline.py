
import numpy as np

from src.qr_engine.analysis_pipeline import QRAnalysisPipeline


def test_pipeline_decodes_valid_qr():
    pipeline = QRAnalysisPipeline()

    result = pipeline.analyze("dataset/test_qr.png")

    assert result["success"] is True
    assert result["decoding"]["success"] is True
    assert result["decoding"]["content"] == "https://example.com"
    assert result["forensics"]["success"] is True


def test_pipeline_handles_image_without_qr(tmp_path):
    pipeline = QRAnalysisPipeline()

    image_path = tmp_path / "blank.png"
    blank_image = np.full((100, 100, 3), 255, dtype=np.uint8)

    import cv2
    cv2.imwrite(str(image_path), blank_image)

    result = pipeline.analyze(image_path)

    assert result["success"] is False
    assert result["error"] == "No QR code detected"
    assert result["forensics"] is None


def test_pipeline_handles_missing_image(tmp_path):
    pipeline = QRAnalysisPipeline()

    image_path = tmp_path / "missing.png"
    result = pipeline.analyze(image_path)

    assert result["success"] is False
    assert result["error"] == "Image file not found"
    assert result["forensics"] is None
