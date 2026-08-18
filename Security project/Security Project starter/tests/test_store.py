"""
Properties 7, 8, 9: Summary Count Invariant, Prompt Truncation, Result Ordering
Feature: prompt-injection-detector
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.models.schemas import AnalysisResult, Classification, ThreatType
from app.store.memory import PromptStore
from tests.conftest import truncation_boundary_st


def _make_result(
    classification: str = "safe",
    prompt: str = "test prompt",
    submitted_at: datetime | None = None,
) -> AnalysisResult:
    kwargs = dict(
        prompt=prompt,
        classification=classification,
        confidence_score=0.95 if classification == "safe" else 0.85,
        threat_type="none" if classification == "safe" else "jailbreak",
    )
    if submitted_at is not None:
        kwargs["submitted_at"] = submitted_at
    return AnalysisResult(**kwargs)


# ---------------------------------------------------------------------------
# Property 7: Summary Count Invariant
# Feature: prompt-injection-detector, Property 7: Summary Count Invariant
# ---------------------------------------------------------------------------

@given(
    classifications=st.lists(
        st.sampled_from(["safe", "malicious"]),
        min_size=0,
        max_size=50,
    )
)
def test_property7_summary_count_invariant(classifications):
    """total == safe + malicious at all times."""
    store = PromptStore()
    for cls in classifications:
        store.add(_make_result(classification=cls))
    summary = store.get_summary()
    assert summary.total == summary.safe + summary.malicious
    assert summary.total == len(classifications)
    assert summary.safe == classifications.count("safe")
    assert summary.malicious == classifications.count("malicious")


def test_empty_store_summary():
    store = PromptStore()
    s = store.get_summary()
    assert s.total == 0
    assert s.safe == 0
    assert s.malicious == 0


def test_summary_increments_correctly():
    store = PromptStore()
    store.add(_make_result("safe"))
    store.add(_make_result("malicious"))
    store.add(_make_result("safe"))
    s = store.get_summary()
    assert s.total == 3
    assert s.safe == 2
    assert s.malicious == 1


# ---------------------------------------------------------------------------
# Property 8: Prompt Truncation
# Feature: prompt-injection-detector, Property 8: Prompt Truncation
# ---------------------------------------------------------------------------

@given(prompt=truncation_boundary_st)
def test_property8_truncation(prompt):
    """
    truncated_prompt == full prompt if len <= 200,
    else first 200 chars + ellipsis.
    """
    result = _make_result(prompt=prompt)
    if len(prompt) <= 200:
        assert result.truncated_prompt == prompt
    else:
        assert result.truncated_prompt == prompt[:200] + "\u2026"
        assert len(result.truncated_prompt) == 201  # 200 chars + ellipsis


def test_truncation_at_boundary_200():
    prompt = "x" * 200
    result = _make_result(prompt=prompt)
    assert result.truncated_prompt == prompt
    assert "\u2026" not in result.truncated_prompt


def test_truncation_at_201():
    prompt = "x" * 201
    result = _make_result(prompt=prompt)
    assert result.truncated_prompt.endswith("\u2026")
    # The visible text is 200 chars + 1 ellipsis char
    assert len(result.truncated_prompt) == 201


# ---------------------------------------------------------------------------
# Property 9: Result Ordering
# Feature: prompt-injection-detector, Property 9: Result Ordering
# ---------------------------------------------------------------------------

@given(
    n=st.integers(min_value=1, max_value=30),
)
def test_property9_results_sorted_newest_first(n):
    """get_all() returns results sorted by submitted_at descending."""
    store = PromptStore()
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    # Insert in chronological order
    for i in range(n):
        r = _make_result(submitted_at=base + timedelta(seconds=i))
        store.add(r)
    results = store.get_all()
    assert len(results) == n
    for i in range(len(results) - 1):
        assert results[i].submitted_at >= results[i + 1].submitted_at


def test_ordering_with_same_timestamp():
    """Results with identical timestamps don't raise errors."""
    store = PromptStore()
    ts = datetime(2025, 6, 1, tzinfo=timezone.utc)
    for _ in range(5):
        store.add(_make_result(submitted_at=ts))
    results = store.get_all()
    assert len(results) == 5


def test_clear_resets_store():
    store = PromptStore()
    store.add(_make_result())
    store.clear()
    assert store.get_all() == []
    assert store.get_summary().total == 0
