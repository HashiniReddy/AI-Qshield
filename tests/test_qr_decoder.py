"""
Tests for the AI-QShield QR Intelligence Engine.

Day 2 tests verify:

1. Missing image handling
2. Basic URL detection
3. Plain-text detection
4. Invalid URL detection
"""


from src.qr_engine.qr_decoder import QRDecoder


def test_invalid_image_path():
    """
    Verify that the decoder handles a missing image safely.
    """

    decoder = QRDecoder()

    result = decoder.decode("does_not_exist.png")

    assert result["success"] is False
    assert result["is_url"] is False
    assert result["error"] == "Image file not found"


def test_url_detection():
    """
    Verify that a normal HTTP/HTTPS URL is recognized.
    """

    assert QRDecoder.is_url("https://example.com") is True


def test_http_url_detection():
    """
    Verify that HTTP URLs are also recognized.
    """

    assert QRDecoder.is_url("http://example.com") is True


def test_non_url_detection():
    """
    Verify that normal text is not treated as a URL.
    """

    assert QRDecoder.is_url("Hello AI-QShield") is False


def test_invalid_url():
    """
    Verify that a domain without HTTP/HTTPS is not
    treated as a valid URL by our basic validator.
    """

    assert QRDecoder.is_url("example.com") is False


def test_invalid_scheme():
    """
    Verify that unsupported schemes are rejected.
    """

    assert QRDecoder.is_url("ftp://example.com") is False


def test_empty_content():
    """
    Verify that empty content is rejected.
    """

    assert QRDecoder.is_url("") is False