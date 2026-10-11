from unittest.mock import patch, Mock

from src.redirect_engine.redirect_analyzer import analyze_redirects


def make_response(status_code, location=None):
    response = Mock()
    response.status_code = status_code
    response.headers = {}

    if location:
        response.headers["Location"] = location

    return response


@patch("src.redirect_engine.redirect_analyzer.requests.Session")
def test_no_redirect(mock_session_class):
    session = mock_session_class.return_value.__enter__.return_value
    session.get.return_value = make_response(200)

    result = analyze_redirects("https://example.com")

    assert result["success"] is True
    assert result["redirect_count"] == 0
    assert result["final_url"] == "https://example.com"


@patch("src.redirect_engine.redirect_analyzer.requests.Session")
def test_redirect_to_another_host(mock_session_class):
    session = mock_session_class.return_value.__enter__.return_value
    session.get.side_effect = [
        make_response(302, "https://example.org/page"),
        make_response(200),
    ]

    result = analyze_redirects("https://example.com")

    assert result["success"] is True
    assert result["redirect_count"] == 1
    assert result["final_url"] == "https://example.org/page"
    assert "FINAL_HOST_DIFFERS" in result["indicators"]


def test_invalid_scheme():
    result = analyze_redirects("javascript:alert(1)")

    assert result["success"] is False
    assert result["redirect_chain"] == []


def test_empty_url():
    result = analyze_redirects("")

    assert result["success"] is False
