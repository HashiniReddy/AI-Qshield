
import pytest

from src.risk_engine.severity_guidance import get_severity_guidance


@pytest.mark.parametrize("level", ["MINIMAL", "LOW", "MEDIUM", "HIGH"])
def test_known_levels_have_guidance(level):
    guidance = get_severity_guidance(level)

    assert guidance["summary"]
    assert guidance["recommended_action"]


def test_level_is_case_insensitive_and_trimmed():
    assert get_severity_guidance(" high ") == get_severity_guidance("HIGH")


def test_unknown_level_returns_safe_guidance():
    guidance = get_severity_guidance("EXTREME")

    assert "unknown" in guidance["summary"].lower()
    assert guidance["recommended_action"]


@pytest.mark.parametrize("level", [None, 10, [], {}])
def test_invalid_level_raises_type_error(level):
    with pytest.raises(TypeError):
        get_severity_guidance(level)
