"""Shared fixtures and Hypothesis profiles for the test suite."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Hypothesis profiles
# ---------------------------------------------------------------------------

settings.register_profile(
    "ci",
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "dev",
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("dev")


# ---------------------------------------------------------------------------
# Re-usable Hypothesis strategies
# ---------------------------------------------------------------------------

# Valid prompt: 1–10 000 Unicode characters, not all whitespace
valid_prompt_st = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),  # no surrogates
    min_size=1,
    max_size=10_000,
).filter(lambda s: s.strip() != "")

# Whitespace-only strings
whitespace_only_st = st.text(
    alphabet=st.sampled_from(" \t\n\r\f\v"),
    min_size=1,
    max_size=500,
)

# Oversized strings (> 10 000 chars) — use fixed oversized string to avoid
# Hypothesis text() max_size limits
oversized_st = st.just("a" * 10_001) | st.just("x" * 15_000) | st.just("z" * 10_002)

# Confidence scores in [0.0, 1.0]
confidence_score_st = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)

# Strings spanning the 200-character truncation boundary
truncation_boundary_st = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=1,
    max_size=500,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    from app.detector.engine import DetectionEngine
    return DetectionEngine()


@pytest.fixture()
def store():
    from app.store.memory import PromptStore
    return PromptStore()


@pytest.fixture()
def jailbreak_analyzer():
    from app.detector.jailbreak import JailbreakAnalyzer
    return JailbreakAnalyzer()


@pytest.fixture()
def indirect_analyzer():
    from app.detector.indirect_injection import IndirectInjectionAnalyzer
    return IndirectInjectionAnalyzer()


@pytest.fixture()
def aggregator():
    from app.detector.scoring import ScoreAggregator
    return ScoreAggregator()


@pytest.fixture()
def scenario_provider():
    from app.samples.provider import ScenarioProvider
    return ScenarioProvider()


@pytest.fixture()
def http_client():
    """Synchronous test client for FastAPI using Starlette's TestClient."""
    import os

    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from starlette.testclient import TestClient

    from app.api.routes import router
    from app.models.schemas import state

    # Reset shared state between tests
    state.store.clear()
    state.demo_in_progress = False

    test_app = FastAPI()
    test_app.include_router(router)

    static_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "static")
    )
    if os.path.isdir(static_dir):
        test_app.mount("/static", StaticFiles(directory=static_dir), name="static")

    with TestClient(test_app, raise_server_exceptions=True) as client:
        yield client
