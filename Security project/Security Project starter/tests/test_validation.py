"""
Property 3: Input Validation
Feature: prompt-injection-detector, Property 3: Input Validation
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.detector.engine import DetectionEngine
from tests.conftest import oversized_st, valid_prompt_st, whitespace_only_st

_ENGINE = DetectionEngine()


# ---------------------------------------------------------------------------
# Property 3 — Hypothesis (module-level engine avoids fixture health check)
# ---------------------------------------------------------------------------

@given(prompt=valid_prompt_st)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property3_valid_prompts_are_accepted(prompt):
    """Any non-empty, non-whitespace-only prompt <= 10 000 chars is accepted."""
    result = _ENGINE.analyze(prompt)
    assert result is not None


@given(text=whitespace_only_st)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property3_whitespace_only_rejected(text):
    """Whitespace-only strings must raise ValueError."""
    with pytest.raises(ValueError, match="1 and 10,000"):
        _ENGINE.analyze(text)


@given(text=oversized_st)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property3_oversized_rejected(text):
    """Strings > 10 000 chars must raise ValueError."""
    with pytest.raises(ValueError, match="1 and 10,000"):
        _ENGINE.analyze(text)


# ---------------------------------------------------------------------------
# Unit tests — boundary cases
# ---------------------------------------------------------------------------

def test_exactly_1_char_accepted():
    assert _ENGINE.analyze("x") is not None


def test_exactly_10000_chars_accepted():
    assert _ENGINE.analyze("a" * 10_000) is not None


def test_10001_chars_rejected():
    with pytest.raises(ValueError):
        _ENGINE.analyze("a" * 10_001)


def test_empty_string_rejected():
    with pytest.raises(ValueError):
        _ENGINE.analyze("")


def test_single_space_rejected():
    with pytest.raises(ValueError):
        _ENGINE.analyze("   ")


def test_tabs_and_newlines_rejected():
    with pytest.raises(ValueError):
        _ENGINE.analyze("\t\n\r")
