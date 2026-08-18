"""
Property 6: Benign Content Safety
Feature: prompt-injection-detector
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.detector.engine import DetectionEngine

_ENGINE = DetectionEngine()

BENIGN_PROMPTS = [
    "Can you role-play as a medieval knight for a creative writing exercise?",
    "Write a short story where the hero is a time-travelling scientist.",
    "I'm writing a fantasy novel. Can you play the villain for a dialogue?",
    'Translate "Guten Morgen, wie geht es Ihnen?" from German to English.',
    'The report states: "Revenue increased 12% in Q3."',
    "What are the key differences between microservices and monolithic architecture?",
    "Help me write a professional email announcing the Q3 planning meeting.",
    "What are best practices for code reviews in a fast-moving startup team?",
    "Summarize the main points from our last sprint retrospective.",
    "Explain how transformer models work in simple terms.",
    "What is the OWASP Top 10 for LLM applications?",
    "How do I set up a Python virtual environment?",
    "The base64 for 'Hello' is SGVsbG8=. Can you decode it?",
]


@pytest.mark.parametrize("prompt", BENIGN_PROMPTS)
def test_benign_prompt_classified_safe(prompt):
    result = _ENGINE.analyze(prompt)
    assert result.classification == "safe", (
        f"Expected 'safe', got '{result.classification}' "
        f"(confidence {result.confidence_score}) for:\n{prompt}"
    )
    assert result.threat_type == "none"


_BENIGN_WORDS = [
    "the", "quick", "brown", "fox", "hello", "world", "python", "code",
    "review", "meeting", "email", "report", "sprint", "agile", "team",
    "document", "summary", "translate", "write", "explain", "help",
    "question", "answer", "data", "analysis", "chart", "graph",
]

_benign_sentence_st = st.lists(
    st.sampled_from(_BENIGN_WORDS), min_size=5, max_size=20
).map(lambda words: " ".join(words))


@given(sentence=_benign_sentence_st)
def test_property6_benign_sentences_classified_safe(sentence):
    """
    Feature: prompt-injection-detector, Property 6: Benign Content Safety
    Random sentences composed of benign words must be classified safe.
    """
    result = _ENGINE.analyze(sentence)
    assert result.classification == "safe", (
        f"False positive: '{sentence}' classified as {result.classification}"
    )
