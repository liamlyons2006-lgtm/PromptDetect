"""
Properties 1, 2, 10: Output Consistency, Confidence Score Range,
                     Confidence Level Classification
Feature: prompt-injection-detector
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.detector.engine import DetectionEngine
from app.detector.scoring import ScoreAggregator
from app.models.schemas import AnalyzerScore
from tests.conftest import confidence_score_st, valid_prompt_st

# Module-level singletons — safe for Hypothesis (stateless)
_ENGINE = DetectionEngine()
_AGG = ScoreAggregator()


def make_score(s: float) -> AnalyzerScore:
    return AnalyzerScore(score=round(s, 2), matched_patterns=[])


# ---------------------------------------------------------------------------
# Property 1: Output Consistency
# Feature: prompt-injection-detector, Property 1: Output Consistency
# ---------------------------------------------------------------------------

@given(prompt=valid_prompt_st)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property1_output_consistency(prompt):
    """Classification is 'safe'|'malicious'; threat_type consistent."""
    result = _ENGINE.analyze(prompt)
    assert result.classification in ("safe", "malicious")
    if result.classification == "malicious":
        assert result.threat_type in ("jailbreak", "indirect_injection")
    else:
        assert result.threat_type == "none"


# ---------------------------------------------------------------------------
# Property 2: Confidence Score Range
# Feature: prompt-injection-detector, Property 2: Confidence Score Range
# ---------------------------------------------------------------------------

@given(prompt=valid_prompt_st)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property2_confidence_score_range(prompt):
    """confidence_score is in [0.0, 1.0] and rounded to 2 decimal places."""
    result = _ENGINE.analyze(prompt)
    assert 0.0 <= result.confidence_score <= 1.0
    assert round(result.confidence_score, 2) == result.confidence_score


# ---------------------------------------------------------------------------
# Property 10: Confidence Level Classification
# Feature: prompt-injection-detector, Property 10: Confidence Level Classification
# ---------------------------------------------------------------------------

@given(score=confidence_score_st)
def test_property10_confidence_level(score):
    """Confidence level labels map correctly for all scores in [0.0, 1.0]."""
    from app.models.schemas import AnalysisResult, Classification, ThreatType

    rounded = round(score, 2)
    result = AnalysisResult(
        prompt="test",
        classification=Classification.SAFE,
        confidence_score=rounded,
        threat_type=ThreatType.NONE,
    )
    level = result.confidence_level
    # Use rounded value for boundary checks (matches engine behaviour)
    if rounded > 0.8:
        assert "High" in level.value
    elif rounded >= 0.5:
        assert "Medium" in level.value
    else:
        assert "Low" in level.value


# ---------------------------------------------------------------------------
# ScoreAggregator unit tests (use module-level _AGG)
# ---------------------------------------------------------------------------

def test_aggregator_safe_when_both_low():
    cls, conf, threat = _AGG.classify(make_score(0.1), make_score(0.2))
    assert cls == "safe"
    assert threat == "none"
    assert 0.0 <= conf <= 1.0


def test_aggregator_malicious_jailbreak_wins():
    cls, conf, threat = _AGG.classify(make_score(0.9), make_score(0.3))
    assert cls == "malicious"
    assert threat == "jailbreak"
    assert conf == 0.9


def test_aggregator_malicious_indirect_wins():
    cls, conf, threat = _AGG.classify(make_score(0.3), make_score(0.8))
    assert cls == "malicious"
    assert threat == "indirect_injection"
    assert conf == 0.8


def test_aggregator_tie_goes_to_jailbreak():
    cls, conf, threat = _AGG.classify(make_score(0.7), make_score(0.7))
    assert cls == "malicious"
    assert threat == "jailbreak"


def test_aggregator_exactly_0_5_is_malicious():
    cls, _, _ = _AGG.classify(make_score(0.5), make_score(0.0))
    assert cls == "malicious"


def test_aggregator_below_0_5_is_safe():
    cls, _, _ = _AGG.classify(make_score(0.49), make_score(0.49))
    assert cls == "safe"


def test_aggregator_safe_confidence_is_complement():
    """Safe confidence = 1.0 - max_score, rounded to 2dp."""
    max_s = 0.3
    cls, conf, _ = _AGG.classify(make_score(max_s), make_score(0.1))
    assert cls == "safe"
    assert conf == round(1.0 - max_s, 2)


@given(jb=confidence_score_st, ii=confidence_score_st)
def test_property1_aggregator_always_valid(jb, ii):
    """Aggregator always returns valid classification/threat_type combos."""
    cls, conf, threat = _AGG.classify(make_score(jb), make_score(ii))
    assert cls in ("safe", "malicious")
    assert 0.0 <= conf <= 1.0
    if cls == "malicious":
        assert threat in ("jailbreak", "indirect_injection")
    else:
        assert threat == "none"
